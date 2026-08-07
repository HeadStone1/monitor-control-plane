from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
import yaml
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import server.monitor_server.app as monitor_server_app
import agent.monitor_agent.client as monitor_agent_client
from agent.monitor_agent.client import (
    AgentAuthenticationError,
    AgentProtocolError,
    CollectionInProgressError,
    CollectionTimeoutError,
    MonitorAgent,
)
from agent.monitor_agent.config import AgentConfig, DockerConfig, ReconnectConfig, load_agent_config
from agent.monitor_agent.collectors.docker_collector import DockerCollector
from server.monitor_server.app import _handle_agent_message, _run_metrics_maintenance, create_app
from server.monitor_server.config import (
    AgentCredential,
    AlertNotificationConfig,
    AlertWebhookConfig,
    ApiTokenConfig,
    ServerConfig,
    UserConfig,
    load_server_config,
)
from server.monitor_server.db import Database
from server.monitor_server.doctor import format_doctor_report, run_config_doctor
from server.monitor_server.hub import ConnectionHub
from server.monitor_server.init_config import write_init_config_files
from server.monitor_server.notifications import AlertNotifier
from server.monitor_server.security import hash_secret, verify_secret


LEGACY_PBKDF2_DEV_ADMIN_HASH = (
    "pbkdf2_sha256$310000$bW9uaXRvci1kZXYtYWRtaW4tc2FsdA$"
    "-82Brrs8OuexgSIZ36iHB783tRwRnYOKUUwHR3QBp5A"
)


class FakeAgentWebSocket:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []

    async def send(self, raw: str) -> None:
        self.messages.append(json.loads(raw))


class FakeAgentAuthWebSocket(FakeAgentWebSocket):
    def __init__(self, response: dict[str, object]) -> None:
        super().__init__()
        self.response = response

    async def recv(self) -> str:
        return json.dumps(self.response)


class FakeHubWebSocket:
    def __init__(self, *, hang: bool = False, fail: bool = False) -> None:
        self.hang = hang
        self.fail = fail
        self.messages: list[dict[str, object]] = []
        self.closed = False

    async def send_json(self, message: dict[str, object]) -> None:
        if self.hang:
            await asyncio.Event().wait()
        if self.fail:
            raise RuntimeError("websocket is closed")
        self.messages.append(message)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        _ = (code, reason)
        self.closed = True


class FakeDocker:
    def __init__(self) -> None:
        self.executed: tuple[str, str] | None = None

    def execute(self, action: str, container_id: str) -> tuple[bool, str]:
        self.executed = (action, container_id)
        return True, "done"

    def inventory(self) -> list[dict[str, object]]:
        return []

    def inventory_snapshot(self) -> dict[str, object]:
        return {"ok": True, "containers": self.inventory(), "error": None}


class FakeDockerContainer:
    def __init__(self, labels: dict[str, str] | None = None) -> None:
        self.attrs = {"Config": {"Labels": labels or {}}}
        self.started = False

    def start(self) -> None:
        self.started = True

    def stop(self, timeout: int = 10) -> None:
        _ = timeout

    def restart(self, timeout: int = 10) -> None:
        _ = timeout


class FakeDockerClient:
    def __init__(self, container: FakeDockerContainer) -> None:
        self.containers = SimpleNamespace(get=lambda _container_id: container)


def config(tmp_path: Path, **overrides: object) -> ServerConfig:
    base = ServerConfig(
        database_path=tmp_path / "monitor.db",
        allowed_hosts=["testserver", "127.0.0.1", "localhost"],
        admin_token="dev-admin-token",
        admin_username="admin",
        admin_password_hash=hash_secret("admin-password"),
        session_secret="x" * 32,
        agents=[
            AgentCredential(
                node_id="agent-a",
                name="agent-a",
                token_hash=hash_secret("agent-token-a"),
            ),
            AgentCredential(
                node_id="agent-b",
                name="agent-b",
                token_hash=hash_secret("agent-token-b"),
            ),
        ],
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def write_server_config(
    path: Path,
    db_path: Path,
    *,
    admin_hash: str,
    agent_hash: str,
    agent_enabled: bool = True,
) -> None:
    path.write_text(
        "\n".join(
            [
                "host: 127.0.0.1",
                "port: 8000",
                "environment: development",
                "allowed_hosts:",
                "  - testserver",
                f"database_path: '{str(db_path).replace(chr(92), '/')}'",
                "admin_token: ''",
                "admin_username: admin",
                f"admin_password_hash: '{admin_hash}'",
                "session_secret: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
                "agents:",
                "  - node_id: agent-a",
                "    name: agent-a",
                "    token_id: token-a",
                f"    token_hash: '{agent_hash}'",
                f"    enabled: {'true' if agent_enabled else 'false'}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def login(client: TestClient, username: str = "admin", password: str = "admin-password") -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def _write_private_agent_config(path: Path, content: str) -> None:
    """Write an agent config file with POSIX-restrictive permissions.

    ``load_agent_config`` refuses config files readable by group/others on
    non-Windows platforms. Helper tests that materialise ``agent.yaml`` in a
    tmp_path must therefore tighten permissions, otherwise the call fails on
    Linux (umask 022 -> 0644) but passes on Windows where the check is skipped.
    """
    path.write_text(content, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def test_hash_secret_generates_argon2id_and_rejects_legacy_pbkdf2() -> None:
    encoded = hash_secret("admin-password")

    assert encoded.startswith("$argon2id$")
    assert verify_secret("admin-password", encoded) is True
    assert verify_secret("dev-admin-password", LEGACY_PBKDF2_DEV_ADMIN_HASH) is False
    assert verify_secret("wrong-password", LEGACY_PBKDF2_DEV_ADMIN_HASH) is False


def test_plaintext_admin_password_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "server.yaml"
    path.write_text("admin_password: plaintext\n", encoding="utf-8")

    with pytest.raises(ValueError, match="admin_password"):
        load_server_config(str(path))


def test_plaintext_user_password_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "server.yaml"
    path.write_text(
        "users:\n"
        "  - username: admin\n"
        "    password: plaintext\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"users\[\]\.password"):
        load_server_config(str(path))


def test_plaintext_admin_password_env_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MONITOR_ADMIN_PASSWORD", "plaintext")

    with pytest.raises(ValueError, match="MONITOR_ADMIN_PASSWORD"):
        load_server_config(None)


def test_plaintext_agent_token_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "server.yaml"
    path.write_text(
        "agents:\n"
        "  - node_id: agent-a\n"
        "    token: plaintext-agent-token\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"agents\[\]\.token"):
        load_server_config(str(path))


def test_legacy_agent_tokens_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "server.yaml"
    path.write_text("agent_tokens:\n  - plaintext-agent-token\n", encoding="utf-8")

    with pytest.raises(ValueError, match="agent_tokens"):
        load_server_config(str(path))


def test_legacy_agent_tokens_env_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MONITOR_AGENT_TOKENS", "plaintext-agent-token")

    with pytest.raises(ValueError, match="MONITOR_AGENT_TOKENS"):
        load_server_config(None)


def test_admin_token_disabled_in_production(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        environment="production",
        admin_token="a" * 32,
        secure_cookies=True,
        require_secure_transport=True,
    )
    app = create_app(cfg)

    with pytest.raises(RuntimeError, match="admin_token is disabled"):
        with TestClient(app):
            pass


def test_legacy_pbkdf2_hash_rejected_at_startup(tmp_path: Path) -> None:
    cfg = config(tmp_path, admin_password_hash=LEGACY_PBKDF2_DEV_ADMIN_HASH)
    app = create_app(cfg)

    with pytest.raises(RuntimeError, match="invalid_admin_password_hash"):
        with TestClient(app):
            pass


@pytest.mark.parametrize(
    ("body", "pattern"),
    [
        (f"admin_password_hash: '{LEGACY_PBKDF2_DEV_ADMIN_HASH}'\n", "admin_password_hash"),
        (
            "users:\n"
            "  - username: admin\n"
            f"    password_hash: '{LEGACY_PBKDF2_DEV_ADMIN_HASH}'\n",
            r"users\[\]\.password_hash",
        ),
        (
            "agents:\n"
            "  - node_id: agent-a\n"
            f"    token_hash: '{LEGACY_PBKDF2_DEV_ADMIN_HASH}'\n",
            r"agents\[\]\.token_hash",
        ),
        (
            "api_tokens:\n"
            "  - name: automation\n"
            f"    token_hash: '{LEGACY_PBKDF2_DEV_ADMIN_HASH}'\n"
            "    scopes:\n"
            "      - nodes:read\n",
            r"api_tokens\[\]\.token_hash",
        ),
    ],
)
def test_non_argon2id_hashes_rejected_at_config_load(tmp_path: Path, body: str, pattern: str) -> None:
    path = tmp_path / "server.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError, match=pattern):
        load_server_config(str(path))


def test_non_argon2id_admin_password_hash_env_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MONITOR_ADMIN_PASSWORD_HASH", LEGACY_PBKDF2_DEV_ADMIN_HASH)

    with pytest.raises(ValueError, match="admin_password_hash"):
        load_server_config(None)


def test_csrf_required_for_cookie_mutation(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    app = create_app(cfg)

    with TestClient(app) as client:
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin-password"},
        )
        assert response.status_code == 200
        csrf_token = response.json()["csrf_token"]

        forbidden = client.post("/api/auth/logout")
        assert forbidden.status_code == 403

        ok = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_token})
        assert ok.status_code == 200


def test_threshold_settings_are_persisted_and_viewer_is_read_only(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        users=[
            UserConfig(username="admin", password_hash=hash_secret("admin-password"), role="admin"),
            UserConfig(username="viewer", password_hash=hash_secret("viewer-password"), role="viewer"),
        ],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        viewer_csrf = login(client, username="viewer", password="viewer-password")
        response = client.get("/api/auth/me")
        assert response.status_code == 200
        assert response.json()["role"] == "viewer"
        assert "nodes:read" in response.json()["scopes"]
        assert "commands:create" not in response.json()["scopes"]

        response = client.get("/api/settings/thresholds")
        assert response.status_code == 200
        assert response.json()["configured"] is False

        response = client.put(
            "/api/settings/thresholds",
            headers={"X-CSRF-Token": viewer_csrf},
            json={"cpu": 70, "memory": 80, "disk": 90},
        )
        assert response.status_code == 403

    app = create_app(config(tmp_path))
    with TestClient(app) as client:
        admin_csrf = login(client)
        response = client.put(
            "/api/settings/thresholds",
            headers={"X-CSRF-Token": admin_csrf},
            json={"cpu": 70, "memory": None, "disk": 95},
        )
        assert response.status_code == 200
        assert response.json()["thresholds"] == {"cpu": 70.0, "memory": None, "disk": 95.0}

        response = client.get("/api/settings/thresholds")
        assert response.status_code == 200
        assert response.json()["configured"] is True
        assert response.json()["thresholds"]["cpu"] == 70.0


def test_metrics_create_and_resolve_threshold_alerts(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    db.set_thresholds({"cpu": 50, "memory": None, "disk": None})
    app = SimpleNamespace(state=SimpleNamespace(config=cfg, db=db, hub=ConnectionHub()))

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {"type": "metrics", "data": {"cpu_percent": 90, "memory_percent": 10, "disk_percent": 10}},
        )
    )

    active = db.list_alerts(status="active")
    assert len(active) == 1
    assert active[0]["metric"] == "cpu"
    assert active[0]["value"] == 90.0

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {"type": "metrics", "data": {"cpu_percent": 20, "memory_percent": 10, "disk_percent": 10}},
        )
    )

    assert db.list_alerts(status="active") == []
    resolved = db.list_alerts(status="resolved")
    assert len(resolved) == 1
    assert resolved[0]["metric"] == "cpu"
    assert resolved[0]["value"] == 20.0
    logs = db.list_audit_logs(limit=10)
    assert any(item["event_type"] == "alert_created" for item in logs)
    assert any(item["event_type"] == "alert_resolved" for item in logs)


def test_prometheus_metrics_requires_metrics_read_and_exports_latest_nodes(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        api_tokens=[
            ApiTokenConfig(
                name="metrics-token",
                token_hash=hash_secret("metrics-token"),
                scopes=["metrics:read"],
            ),
            ApiTokenConfig(
                name="nodes-token",
                token_hash=hash_secret("nodes-token"),
                scopes=["nodes:read"],
            ),
        ],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        db: Database = app.state.db
        db.ensure_node("agent-a", name='agent "A"')
        db.update_host_info(
            "agent-a",
            {
                "agent_name": 'agent "A"',
                "hostname": "host-a",
                "ip": "10.0.0.10",
                "os": "Linux",
                "arch": "x86_64",
                "agent_version": "dev",
                "docker": {"available": True, "version": "25.0"},
            },
        )
        db.save_metrics("agent-a", {"cpu_percent": 42.5, "memory_percent": 33, "disk_percent": 12})

        unauthorized = client.get("/metrics")
        assert unauthorized.status_code == 401

        forbidden = client.get("/metrics", headers={"Authorization": "Bearer nodes-token"})
        assert forbidden.status_code == 403

        response = client.get("/metrics", headers={"Authorization": "Bearer metrics-token"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        body = response.text
        assert "# TYPE monitor_node_cpu_percent gauge" in body
        assert 'node_id="agent-a"' in body
        assert 'name="agent \\"A\\""' in body
        assert "monitor_node_cpu_percent" in body
        assert "42.5" in body
        assert "monitor_node_docker_available" in body


def test_metric_series_falls_back_to_raw_before_rollup(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    captured_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
    db.save_metrics(
        "agent-a",
        {"captured_at": captured_at, "cpu_percent": 42, "memory_percent": 30, "disk_percent": 20},
    )

    payload = db.list_metric_series("agent-a", "7d")

    assert payload["source"] == "raw"
    assert payload["bucket"] == "hour"
    assert payload["points"][0]["cpu_avg"] == 42.0


def test_metric_series_supports_dashboard_time_ranges(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")

    expected_buckets = {
        "1h": "raw",
        "24h": "hour",
        "7d": "hour",
        "15d": "hour",
        "30d": "day",
        "60d": "day",
        "90d": "day",
    }
    for range_name, bucket in expected_buckets.items():
        payload = db.list_metric_series("agent-a", range_name)
        assert payload["range"] == range_name
        assert payload["bucket"] == bucket


def test_metric_rollup_populates_hourly_and_daily_series(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    base = (datetime.now(timezone.utc) - timedelta(days=1)).replace(minute=5, second=0, microsecond=0)
    db.save_metrics(
        "agent-a",
        {
            "captured_at": base.isoformat(timespec="seconds"),
            "cpu_percent": 20,
            "memory_percent": 40,
            "disk_percent": 60,
        },
    )
    db.save_metrics(
        "agent-a",
        {
            "captured_at": (base + timedelta(minutes=10)).isoformat(timespec="seconds"),
            "cpu_percent": 40,
            "memory_percent": 80,
            "disk_percent": 90,
        },
    )

    counts = db.rollup_metrics()
    hourly = db.list_metric_series("agent-a", "7d")
    daily = db.list_metric_series("agent-a", "30d")

    assert counts["hourly"] >= 1
    assert counts["daily"] >= 1
    assert hourly["source"] == "rollup"
    assert hourly["points"][0]["sample_count"] == 2
    assert hourly["points"][0]["cpu_avg"] == 30.0
    assert hourly["points"][0]["cpu_max"] == 40.0
    assert hourly["summary"]["cpu"]["avg"] == 30.0
    assert daily["source"] == "rollup"
    assert daily["points"][0]["disk_max"] == 90.0


def test_metric_rollup_only_reprocesses_recent_buckets(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    old = datetime.now(timezone.utc) - timedelta(days=5)
    recent = datetime.now(timezone.utc).replace(minute=5, second=0, microsecond=0)
    db.save_metrics("agent-a", {"captured_at": old.isoformat(timespec="seconds"), "cpu_percent": 10})
    db.save_metrics("agent-a", {"captured_at": recent.isoformat(timespec="seconds"), "cpu_percent": 20})

    first = db.rollup_metrics()
    db.save_metrics(
        "agent-a",
        {"captured_at": (recent + timedelta(minutes=5)).isoformat(timespec="seconds"), "cpu_percent": 40},
    )
    second = db.rollup_metrics()

    assert first["hourly_source_rows"] == 2
    assert first["daily_source_rows"] == 2
    assert second["hourly_source_rows"] == 2
    assert second["daily_source_rows"] == 2
    recent_point = db.list_metric_series("agent-a", "7d")["points"][-1]
    assert recent_point["sample_count"] == 2
    assert recent_point["cpu_avg"] == 30.0


def test_metrics_maintenance_prunes_in_bounded_batches(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    old = datetime.now(timezone.utc) - timedelta(days=30)
    for offset in range(5):
        db.save_metrics(
            "agent-a",
            {"captured_at": (old + timedelta(minutes=offset)).isoformat(timespec="seconds"), "cpu_percent": 10},
        )

    result = _run_metrics_maintenance(
        db,
        include_rollup=False,
        raw_metrics_days=7,
        hourly_rollup_days=90,
        daily_rollup_days=365,
        batch_size=2,
    )

    assert result["rollup_ran"] is False
    assert result["pruned_raw"] == 2
    assert len(db.list_metrics("agent-a")) == 3


def test_status_watcher_recovers_after_cycle_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app(config(tmp_path))
    app.state.db.init()
    attempts = 0

    async def run() -> None:
        nonlocal attempts
        recovered = asyncio.Event()

        async def flaky_cycle(_: object) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("temporary watcher failure")
            recovered.set()

        monkeypatch.setattr(monitor_server_app, "_status_watcher_cycle", flaky_cycle)
        task = asyncio.create_task(
            monitor_server_app._status_watcher(app, interval_seconds=0.01, max_retry_seconds=0.02)
        )
        await asyncio.wait_for(recovered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(run())
        status = app.state.status_watcher_health
        assert attempts >= 2
        assert status["cycles_completed"] >= 1
        assert status["total_failures"] == 1
        assert status["consecutive_failures"] == 0
        assert status["last_error"] is None
        assert status["last_failure_error"] == "temporary watcher failure"
        assert any(
            item["event_type"] == "status_watcher_failed" for item in app.state.db.list_audit_logs(limit=20)
        )
    finally:
        app.state.db.close()


def test_config_reload_disables_agent_and_disconnects_websocket(tmp_path: Path) -> None:
    path = tmp_path / "server.yaml"
    admin_hash = hash_secret("admin-password")
    agent_hash = hash_secret("agent-token-a")
    write_server_config(
        path,
        tmp_path / "monitor.db",
        admin_hash=admin_hash,
        agent_hash=agent_hash,
    )
    cfg = load_server_config(str(path))
    app = create_app(cfg)

    with TestClient(app) as client:
        csrf_token = login(client)
        with client.websocket_connect("/agent/ws") as websocket:
            websocket.send_json({"type": "auth", "agent_id": "agent-a", "token": "agent-token-a"})
            assert websocket.receive_json()["type"] == "auth_ok"

            write_server_config(
                path,
                tmp_path / "monitor.db",
                admin_hash=admin_hash,
                agent_hash=agent_hash,
                agent_enabled=False,
            )
            response = client.post(
                "/api/admin/config/reload",
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            assert response.json()["disconnected_agents"] == ["agent-a"]
            assert cfg.agents[0].enabled is False
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_json()

        logs = app.state.db.list_audit_logs(limit=20)
        assert any(item["event_type"] == "config_reloaded" for item in logs)
        assert any(item["event_type"] == "agent_disconnected_after_config_reload" for item in logs)


def test_revoke_agent_requires_admin_permission(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        users=[
            UserConfig(username="admin", password_hash=hash_secret("admin-password"), role="admin"),
            UserConfig(username="viewer", password_hash=hash_secret("viewer-password"), role="viewer"),
        ],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        csrf_token = login(client, username="viewer", password="viewer-password")
        response = client.post(
            "/api/admin/agents/agent-a/revoke",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 403
        assert cfg.agents[0].enabled is True


def test_revoke_agent_disables_runtime_credential_and_audits(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    app = create_app(cfg)

    with TestClient(app) as client:
        csrf_token = login(client)
        response = client.post(
            "/api/admin/agents/agent-a/revoke",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert response.json()["node_id"] == "agent-a"
        assert response.json()["revoked"] is True
        assert response.json()["revocations_persisted"] == 1
        assert cfg.agents[0].enabled is False
        assert app.state.db.health_summary(public=False)["revoked_agent_tokens"] == 1

        logs = app.state.db.list_audit_logs(limit=10)
        assert any(item["event_type"] == "agent_token_revoked" for item in logs)


def test_revoked_agent_token_stays_rejected_after_restart_and_rotation_is_allowed(tmp_path: Path) -> None:
    database_path = tmp_path / "monitor.db"
    original = AgentCredential(
        node_id="agent-a",
        name="agent-a",
        token_hash=hash_secret("agent-token-a"),
        token_id="token-old",
    )
    first_config = config(tmp_path, agents=[original])
    first_app = create_app(first_config)

    with TestClient(first_app) as client:
        csrf_token = login(client)
        response = client.post(
            "/api/admin/agents/agent-a/revoke",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert response.status_code == 200
        assert response.json()["revocations_persisted"] == 1

    assert b"agent-token-a" not in database_path.read_bytes()

    restarted_config = config(
        tmp_path,
        database_path=database_path,
        agents=[
            AgentCredential(
                node_id="agent-a",
                name="agent-a",
                token_hash=original.token_hash,
                token_id="renamed-old-token",
            )
        ],
    )
    restarted_app = create_app(restarted_config)
    with TestClient(restarted_app) as client:
        with client.websocket_connect("/agent/ws") as websocket:
            websocket.send_json(
                {
                    "type": "auth",
                    "agent_id": "agent-a",
                    "token": "agent-token-a",
                    "protocol_version": "1",
                }
            )
            assert websocket.receive_json()["error"] == "revoked_credentials"
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_json()
        assert any(
            item["event_type"] == "agent_revoked_credential_rejected"
            for item in restarted_app.state.db.list_audit_logs(limit=20)
        )

    reused_identity_config = config(
        tmp_path,
        database_path=database_path,
        agents=[
            AgentCredential(
                node_id="agent-a",
                name="agent-a",
                token_hash=hash_secret("agent-token-new"),
                token_id="token-old",
            )
        ],
    )
    reused_identity_app = create_app(reused_identity_config)
    with TestClient(reused_identity_app) as client:
        with client.websocket_connect("/agent/ws") as websocket:
            websocket.send_json(
                {
                    "type": "auth",
                    "agent_id": "agent-a",
                    "token": "agent-token-new",
                    "protocol_version": "1",
                }
            )
            assert websocket.receive_json()["error"] == "revoked_credentials"

    rotated_config = config(
        tmp_path,
        database_path=database_path,
        agents=[
            AgentCredential(
                node_id="agent-a",
                name="agent-a",
                token_hash=hash_secret("agent-token-new"),
                token_id="token-new",
            )
        ],
    )
    rotated_app = create_app(rotated_config)
    with TestClient(rotated_app) as client:
        with client.websocket_connect("/agent/ws") as websocket:
            websocket.send_json(
                {
                    "type": "auth",
                    "agent_id": "agent-a",
                    "token": "agent-token-new",
                    "protocol_version": "1",
                }
            )
            response = websocket.receive_json()
            assert response["type"] == "auth_ok"
            assert response["node_id"] == "agent-a"


def test_agent_cannot_mark_other_node_command_result(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    db.ensure_node("agent-b")
    command = db.create_command("agent-a", "container.restart", {"container_id": "a" * 64}, "admin")

    assert db.mark_command_result(command["id"], "agent-b", "success", "spoofed") is None
    unchanged = db.get_command(command["id"])
    assert unchanged is not None
    assert unchanged["status"] == "pending"

    updated = db.mark_command_result(command["id"], "agent-a", "success", "done")
    assert updated is not None
    assert updated["status"] == "success"


def test_command_ack_and_running_are_bound_to_node(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    db.ensure_node("agent-b")
    command = db.create_command("agent-a", "container.restart", {"container_id": "a" * 64}, "admin")
    db.mark_command_sent(command["id"])

    assert db.mark_command_acknowledged(command["id"], "agent-b") is None
    acknowledged = db.mark_command_acknowledged(command["id"], "agent-a")
    assert acknowledged is not None
    assert acknowledged["status"] == "acknowledged"
    assert acknowledged["acknowledged_at"] is not None

    assert db.mark_command_running(command["id"], "agent-b") is None
    running = db.mark_command_running(command["id"], "agent-a")
    assert running is not None
    assert running["status"] == "running"
    assert running["running_at"] is not None


def test_agent_command_ack_and_running_messages_update_server_state(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    command = db.create_command("agent-a", "container.restart", {"container_id": "a" * 64}, "admin")
    db.mark_command_sent(command["id"])
    app = SimpleNamespace(state=SimpleNamespace(config=cfg, db=db, hub=ConnectionHub()))

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {"type": "command_ack", "data": {"command_id": command["id"], "status": "received"}},
        )
    )
    assert db.get_command(command["id"])["status"] == "acknowledged"

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {"type": "command_running", "data": {"command_id": command["id"], "status": "running"}},
        )
    )
    assert db.get_command(command["id"])["status"] == "running"


def test_sqlite_wal_enabled(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    try:
        journal_mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
        synchronous = db._conn.execute("PRAGMA synchronous").fetchone()[0]
    finally:
        db.close()

    assert str(journal_mode).lower() == "wal"
    assert synchronous == 1


def test_health_reports_public_and_admin_operational_details(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    app = create_app(cfg)

    with TestClient(app) as client:
        public = client.get("/health")
        assert public.status_code == 200
        assert public.json()["status"] == "ok"
        assert public.json()["database"] == "ok"
        assert public.json()["wal"] is True
        assert "database_path" not in public.json()
        assert "path" not in public.json()

        unauthorized = client.get("/api/admin/health")
        assert unauthorized.status_code == 401

        login(client)
        admin = client.get("/api/admin/health")
        assert admin.status_code == 200
        payload = admin.json()
        assert payload["database"]["journal_mode"] == "wal"
        assert payload["database"]["path"].endswith("monitor.db")
        assert payload["background"]["status_watcher"] is True
        assert payload["background"]["status_watcher_health"]["total_failures"] == 0
        assert "next_retry_seconds" in payload["background"]["status_watcher_health"]
        assert payload["background"]["metrics_maintenance"]["running"] is False
        assert "last_duration_ms" in payload["background"]["metrics_maintenance"]
        assert payload["config"]["command_timeout_seconds"] == cfg.command.timeout_seconds
        assert payload["config"]["maintenance_batch_size"] == cfg.retention.maintenance_batch_size


def test_config_doctor_reports_ok_for_hardened_config(tmp_path: Path) -> None:
    cfg = config(tmp_path, admin_token="", session_secret="not-a-default-session-secret")

    report = run_config_doctor(cfg)
    text = format_doctor_report(report)

    assert report["status"] == "ok"
    assert "Config doctor: ok" in text
    assert "[ok] admin_password_hash" in text


def test_config_doctor_reports_runtime_config_errors(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        admin_password_hash="not-a-valid-hash",
        users=[UserConfig(username="viewer", password_hash="bad-hash", role="missing")],
        agents=[AgentCredential(node_id="agent-a", name="agent-a", token_hash="bad-hash")],
    )

    report = run_config_doctor(cfg)
    error_names = {check["name"] for check in report["checks"] if check["status"] == "error"}

    assert report["status"] == "error"
    assert {"admin_password_hash", "users", "agents", "roles"} <= error_names


def test_init_config_wizard_writes_hardened_server_and_agent_configs(tmp_path: Path) -> None:
    server_path = tmp_path / "server.yaml"
    agent_path = tmp_path / "agent.yaml"

    result = write_init_config_files(
        server_config_path=server_path,
        agent_config_path=agent_path,
        admin_username="admin",
        admin_password="admin-password",
        agent_id="dev-agent",
        agent_token="agent-token",
    )

    assert result.server_config_path == server_path
    assert result.agent_config_path == agent_path

    server_text = server_path.read_text(encoding="utf-8")
    assert "admin-password" not in server_text
    assert "agent-token" not in server_text
    assert "admin_password:" not in server_text
    assert "admin_password_hash:" in server_text
    assert "token_hash:" in server_text

    cfg = load_server_config(str(server_path))
    assert verify_secret("admin-password", cfg.admin_password_hash)
    assert verify_secret("agent-token", cfg.agents[0].token_hash)
    assert cfg.admin_token == ""

    agent_cfg = load_agent_config(str(agent_path))
    assert agent_cfg.server_url == "ws://127.0.0.1:8000/agent/ws"
    assert agent_cfg.agent_id == "dev-agent"
    assert agent_cfg.token == "agent-token"
    assert agent_cfg.docker.api_timeout_seconds == 10
    assert agent_cfg.docker.collection_timeout_seconds == 15
    assert agent_cfg.docker.collection_workers == 3
    assert agent_cfg.docker.allowed_labels == {"monitor.control-plane.allow": "true"}
    assert agent_cfg.reconnect == ReconnectConfig(1, 30, 60, 20, 5)
    assert cfg.command.send_timeout_seconds == 5

    with pytest.raises(FileExistsError):
        write_init_config_files(
            server_config_path=server_path,
            agent_config_path=agent_path,
            admin_username="admin",
            admin_password="admin-password",
            agent_id="dev-agent",
        )


def test_duplicate_agent_registration_rejected() -> None:
    async def run() -> None:
        hub = ConnectionHub()
        first = object()
        second = object()
        assert await hub.register_agent("agent-a", first) is True
        assert await hub.register_agent("agent-a", second) is False

    asyncio.run(run())


def test_agent_websocket_rejects_unsupported_protocol(tmp_path: Path) -> None:
    app = create_app(config(tmp_path))

    with TestClient(app) as client:
        with client.websocket_connect("/agent/ws") as websocket:
            websocket.send_json(
                {
                    "type": "auth",
                    "agent_id": "agent-a",
                    "token": "agent-token-a",
                    "protocol_version": "99",
                }
            )
            response = websocket.receive_json()
            assert response == {
                "type": "auth_error",
                "error": "unsupported_protocol",
                "protocol_version": "1",
            }
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_json()

        assert any(
            item["event_type"] == "agent_protocol_rejected"
            for item in app.state.db.list_audit_logs(limit=20)
        )


def test_agent_command_send_timeout_removes_stale_connection() -> None:
    async def run() -> None:
        hub = ConnectionHub(send_timeout_seconds=0.01)
        websocket = FakeHubWebSocket(hang=True)
        assert await hub.register_agent("agent-a", websocket) is True

        sent = await hub.send_command(
            "agent-a",
            {
                "id": "cmd-timeout",
                "action": "container.restart",
                "payload": {"container_id": "a" * 64},
            },
            timeout_seconds=60,
        )

        assert sent is False
        assert await hub.is_agent_connected("agent-a") is False
        assert websocket.closed is True

    asyncio.run(run())


def test_ui_broadcast_timeout_does_not_block_healthy_clients() -> None:
    async def run() -> None:
        hub = ConnectionHub(send_timeout_seconds=0.01)
        slow = FakeHubWebSocket(hang=True)
        healthy = FakeHubWebSocket()
        await hub.register_ui(slow)
        await hub.register_ui(healthy)

        await hub.broadcast_ui({"type": "node_updated", "node_id": "agent-a"})

        assert healthy.messages == [{"type": "node_updated", "node_id": "agent-a"}]
        assert await hub.connected_ui_count() == 1
        assert slow.closed is True

    asyncio.run(run())


def test_offline_command_is_marked_send_failed_and_audited(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    app = create_app(cfg)

    with TestClient(app) as client:
        csrf_token = login(client)
        app.state.db.ensure_node("agent-a")
        app.state.db.replace_inventory("agent-a", [{"id": "a" * 64, "ports": {}}])

        response = client.post(
            "/api/nodes/agent-a/commands",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "action": "container.restart",
                "payload": {"container_id": "a" * 64},
            },
        )

        assert response.status_code == 200
        command = response.json()
        assert command["status"] == "send_failed"
        assert command["result_message"] == "agent is not connected or command delivery failed"
        logs = app.state.db.list_audit_logs(limit=20)
        assert any(item["event_type"] == "command_delivery_failed" for item in logs)
        assert any(item["result"] == "send_failed" for item in logs)


def test_invalid_metrics_payload_is_rejected(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    app = SimpleNamespace(state=SimpleNamespace(config=cfg, db=db, hub=ConnectionHub()))

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {"type": "metrics", "data": {"cpu_percent": -1, "memory_percent": 10}},
        )
    )

    assert db.list_metrics("agent-a") == []
    logs = db.list_audit_logs()
    assert logs[0]["event_type"] == "agent_payload_invalid"


def test_failed_docker_inventory_preserves_last_successful_snapshot(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    db.replace_inventory(
        "agent-a",
        [
            {
                "id": "a" * 64,
                "name": "important-service",
                "image": "example/service:latest",
                "status": "running",
                "ports": {},
            }
        ],
    )
    app = SimpleNamespace(state=SimpleNamespace(config=cfg, db=db, hub=ConnectionHub()))

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {
                "type": "docker_inventory",
                "data": {
                    "ok": False,
                    "containers": [],
                    "error": "docker daemon temporarily unavailable",
                },
            },
        )
    )

    containers = db.list_containers("agent-a")
    node = db.list_nodes()[0]
    assert len(containers) == 1
    assert containers[0]["name"] == "important-service"
    assert node["docker_inventory_status"] == "stale"
    assert node["docker_inventory_error"] == "docker daemon temporarily unavailable"
    assert node["docker_inventory_last_success_at"] is not None
    logs = db.list_audit_logs(limit=10)
    assert any(item["event_type"] == "docker_inventory_collection_failed" for item in logs)


def test_successful_empty_docker_inventory_clears_previous_snapshot(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    db.replace_inventory("agent-a", [{"id": "a" * 64, "ports": {}}])
    app = SimpleNamespace(state=SimpleNamespace(config=cfg, db=db, hub=ConnectionHub()))

    asyncio.run(
        _handle_agent_message(
            app,
            "agent-a",
            {"type": "docker_inventory", "data": {"ok": True, "containers": [], "error": None}},
        )
    )

    node = db.list_nodes()[0]
    assert db.list_containers("agent-a") == []
    assert node["docker_inventory_status"] == "current"
    assert node["docker_inventory_error"] is None
    assert node["docker_inventory_last_success_at"] is not None


def test_docker_inventory_snapshot_reports_collection_failure() -> None:
    collector = object.__new__(DockerCollector)
    collector.enabled = False
    collector.allowed_labels = {"monitor.control-plane.allow": "true"}
    collector.client = None
    collector.error = "disabled"
    collector.api_timeout_seconds = 10
    collector._connect_lock = threading.Lock()

    snapshot = collector.inventory_snapshot()

    assert snapshot == {"ok": False, "containers": [], "error": "disabled"}


def test_blocking_collection_does_not_block_event_loop_or_duplicate_after_timeout() -> None:
    async def run() -> None:
        agent = MonitorAgent(
            AgentConfig(
                docker=DockerConfig(
                    enabled=False,
                    collection_timeout_seconds=1,
                    collection_workers=1,
                )
            )
        )
        started = threading.Event()
        release = threading.Event()

        def blocking_collection() -> str:
            started.set()
            release.wait(timeout=2)
            return "finished"

        try:
            collection = asyncio.create_task(
                agent._run_blocking_collection("slow", blocking_collection, timeout_seconds=0.5)
            )
            assert await asyncio.to_thread(started.wait, 1) is True
            await asyncio.sleep(0)
            assert collection.done() is False
            with pytest.raises(CollectionTimeoutError):
                await collection
            with pytest.raises(CollectionInProgressError):
                await agent._run_blocking_collection("slow", blocking_collection, timeout_seconds=1)

            release.set()
            for _ in range(100):
                if "slow" not in agent._collector_futures:
                    break
                await asyncio.sleep(0.01)
            assert "slow" not in agent._collector_futures
            assert await agent._run_blocking_collection("slow", lambda: "next", timeout_seconds=1) == "next"
        finally:
            release.set()
            agent.close()

    asyncio.run(run())


def test_agent_docker_timeout_config_is_bounded(tmp_path: Path) -> None:
    config_path = tmp_path / "agent.yaml"
    _write_private_agent_config(
        config_path,
        "\n".join(
            [
                "docker:",
                "  api_timeout_seconds: 12",
                "  collection_timeout_seconds: 20",
                "  collection_workers: 4",
            ]
        ),
    )

    loaded = load_agent_config(str(config_path))
    assert loaded.docker.api_timeout_seconds == 12
    assert loaded.docker.collection_timeout_seconds == 20
    assert loaded.docker.collection_workers == 4

    _write_private_agent_config(config_path, "docker:\n  collection_workers: 0\n")
    with pytest.raises(ValueError, match="between 1 and 8"):
        load_agent_config(str(config_path))


def test_agent_reconnect_config_is_bounded(tmp_path: Path) -> None:
    config_path = tmp_path / "agent.yaml"
    _write_private_agent_config(
        config_path,
        "\n".join(
            [
                "reconnect:",
                "  initial_seconds: 2",
                "  max_seconds: 45",
                "  stable_reset_seconds: 90",
                "  jitter_percent: 25",
                "  auth_timeout_seconds: 8",
            ]
        ),
    )

    loaded = load_agent_config(str(config_path))
    assert loaded.reconnect == ReconnectConfig(2, 45, 90, 25, 8)

    _write_private_agent_config(config_path, "reconnect:\n  initial_seconds: 10\n  max_seconds: 5\n")
    with pytest.raises(ValueError, match="max_seconds"):
        load_agent_config(str(config_path))


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only permission check")
def test_agent_config_requires_strict_permissions(tmp_path: Path) -> None:
    config_path = tmp_path / "agent.yaml"
    config_path.write_text("reconnect:\n  initial_seconds: 1\n", encoding="utf-8")
    config_path.chmod(0o644)
    with pytest.raises(RuntimeError, match="chmod 600"):
        load_agent_config(str(config_path))


def test_agent_waits_for_auth_ok_and_validates_protocol() -> None:
    async def run() -> None:
        agent = MonitorAgent(AgentConfig())
        accepted = FakeAgentAuthWebSocket(
            {"type": "auth_ok", "node_id": "dev-agent", "protocol_version": "1"}
        )
        try:
            await agent._authenticate(accepted)
            assert accepted.messages[0]["type"] == "auth"
            assert accepted.messages[0]["protocol_version"] == "1"
            assert agent._connected_at is not None

            rejected = FakeAgentAuthWebSocket(
                {"type": "auth_error", "error": "invalid_credentials", "protocol_version": "1"}
            )
            with pytest.raises(AgentAuthenticationError, match="invalid_credentials"):
                await agent._authenticate(rejected)

            incompatible = FakeAgentAuthWebSocket(
                {"type": "auth_ok", "node_id": "dev-agent", "protocol_version": "2"}
            )
            with pytest.raises(AgentProtocolError, match="expected 1"):
                await agent._authenticate(incompatible)
        finally:
            agent.close()

    asyncio.run(run())


def test_agent_reconnect_delay_has_jitter_and_resets_after_stable_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = MonitorAgent(
        AgentConfig(
            reconnect=ReconnectConfig(
                initial_seconds=2,
                max_seconds=30,
                stable_reset_seconds=60,
                jitter_percent=20,
                auth_timeout_seconds=5,
            )
        )
    )
    try:
        monkeypatch.setattr(monitor_agent_client.random, "uniform", lambda _low, high: high)
        assert agent._jittered_reconnect_delay(10) == 12
        agent._connected_at = time.monotonic() - 61
        assert agent._backoff_after_disconnect(30) == 2
        assert agent._connected_at is None
    finally:
        agent.close()


def test_stale_commands_timeout(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    db.create_command("agent-a", "container.restart", {"container_id": "a" * 64}, "admin")

    expired = db.expire_stale_commands(timeout_seconds=0)

    assert len(expired) == 1
    assert expired[0]["status"] == "timeout"
    assert expired[0]["result_message"] == "agent did not acknowledge in time"


def test_audit_logs_can_be_filtered(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.add_security_event(event_type="login_success", actor="admin", node_id=None, result="accepted")
    db.add_security_event(event_type="agent_connected", actor="agent-a", node_id="agent-a", result="accepted")
    db.add_security_event(event_type="agent_connected", actor="agent-b", node_id="agent-b", result="accepted")

    by_node = db.list_audit_logs(node_id="agent-a")
    by_action = db.list_audit_logs(action="login_success")
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds")
    by_time = db.list_audit_logs(from_time=future)

    assert len(by_node) == 1
    assert by_node[0]["node_id"] == "agent-a"
    assert len(by_action) == 1
    assert by_action[0]["event_type"] == "login_success"
    assert by_time == []


def test_stale_acknowledged_command_timeout_reports_unfinished(tmp_path: Path) -> None:
    db = Database(tmp_path / "monitor.db")
    db.init()
    db.ensure_node("agent-a")
    command = db.create_command("agent-a", "container.restart", {"container_id": "a" * 64}, "admin")
    db.mark_command_sent(command["id"])
    db.mark_command_acknowledged(command["id"], "agent-a")

    expired = db.expire_stale_commands(timeout_seconds=0)

    assert len(expired) == 1
    assert expired[0]["status"] == "timeout"
    assert expired[0]["result_message"] == "agent did not finish in time"


def test_agent_sends_ack_running_and_result_for_command() -> None:
    agent = MonitorAgent(AgentConfig())
    docker = FakeDocker()
    agent.docker = docker
    websocket = FakeAgentWebSocket()

    asyncio.run(
        agent._handle_command(
            websocket,
            {
                "type": "command",
                "request_id": "cmd_123",
                "command_id": "cmd_123",
                "action": "container.restart",
                "payload": {"container_id": "a" * 64},
            },
        )
    )

    message_types = [message["type"] for message in websocket.messages]
    assert message_types[:3] == ["command_ack", "command_running", "command_result"]
    assert websocket.messages[0]["data"]["status"] == "received"
    assert websocket.messages[1]["data"]["status"] == "running"
    assert websocket.messages[2]["data"]["status"] == "success"
    assert docker.executed == ("container.restart", "a" * 64)


def test_docker_execute_requires_allowed_label() -> None:
    denied_container = FakeDockerContainer()
    collector = object.__new__(DockerCollector)
    collector.enabled = True
    collector.allowed_labels = {"monitor.control-plane.allow": "true"}
    collector.error = None
    collector.client = FakeDockerClient(denied_container)

    ok, message = collector.execute("container.start", "a" * 64)

    assert ok is False
    assert "not labeled" in message
    assert denied_container.started is False

    allowed_container = FakeDockerContainer({"monitor.control-plane.allow": "true"})
    collector.client = FakeDockerClient(allowed_container)
    ok, message = collector.execute("container.start", "a" * 64)

    assert ok is True
    assert message == "container started"
    assert allowed_container.started is True


def test_frontend_logout_preserves_csrf_for_request() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    assert "const csrfToken = state.csrfToken;" in script
    assert 'headers: csrfHeaders("POST", csrfToken),' in script


def test_frontend_uses_custom_command_confirmation_dialog() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")

    assert "window.confirm" not in script
    assert "confirmCommand(action, containerId)" in script
    assert 'id="command-dialog"' in markup
    assert 'id="command-dialog-confirm"' in markup


def test_frontend_has_node_overview_dashboard_cards() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="node-overview"' in markup
    assert "renderNodeOverview()" in script
    assert "createMetricRing" in script
    assert "node-overview-card" in styles
    assert "conic-gradient" in styles


def test_frontend_supports_collapsible_sidebar_navigation() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="sidebar-toggle"' in markup
    assert 'id="mobile-nav-toggle"' in markup
    assert 'id="sidebar-scrim"' in markup
    assert "monitor.sidebarCollapsed" in script
    assert "toggleSidebar" in script
    assert "toggleMobileSidebar" in script
    assert "closeMobileSidebar" in script
    assert "isCompactNavigation" in script
    assert "applySidebarState" in script
    assert 'stored === "false"' in script
    assert "sidebar-collapsed" in styles
    assert ".app-shell.sidebar-collapsed" in styles
    assert "translateX(-100%)" in styles
    assert "content: attr(data-label)" in styles
    assert "dataset.label" in script
    assert ".mobile-nav-toggle" in styles
    assert ".sidebar-scrim" in styles


def test_frontend_navigation_switches_independent_pages() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'data-page-link="overview"' in markup
    assert 'data-page="containers"' in markup
    assert 'data-page="commands"' in markup
    assert 'data-page="audit"' in markup
    assert 'data-page="admin"' in markup
    assert "currentPage: loadPage()" in script
    assert "changePage" in script
    assert "applyPage" in script
    assert "hashchange" in script
    assert "monitor.currentPage" in script
    assert ".app-page" in styles
    assert "grid-template-columns: minmax(0, 1fr)" in styles


def test_frontend_has_admin_health_page_and_reload_control() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'data-page-link="admin"' in markup
    assert "data-admin-only" in markup
    assert 'id="admin-reload-config"' in markup
    assert 'id="admin-db-details"' in markup
    assert 'id="admin-config-details"' in markup
    assert 'id="admin-pending-commands"' in markup
    assert "/api/admin/health" in script
    assert "/api/admin/config/reload" in script
    assert "renderAdminHealth" in script
    assert "status_watcher_health" in script
    assert "watcherFailures" in script
    assert "reloadConfig" in script
    assert "syncAdminVisibility" in script
    assert "hasScope(\"*\") ? api(\"/api/admin/health\")" in script
    assert ".admin-grid" in styles
    assert ".detail-list" in styles


def test_frontend_pages_have_operational_insight_cards() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="containers-running-count"' in markup
    assert 'id="containers-memory-total"' in markup
    assert 'id="commands-active-count"' in markup
    assert 'id="commands-problem-count"' in markup
    assert 'id="audit-security-count"' in markup
    assert 'id="audit-source-count"' in markup
    assert "renderPageInsights" in script
    assert "renderContainerInsights" in script
    assert "renderCommandInsights" in script
    assert "renderAuditInsights" in script
    assert ".page-insights" in styles
    assert ".insight-card" in styles


def test_frontend_supports_language_switching() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="language-select"' in markup
    assert 'data-i18n="header.title"' in markup
    assert 'data-i18n-placeholder="containers.search"' in markup
    assert "const translations" in script
    assert "monitor.language" in script
    assert "applyLanguage" in script
    assert "changeLanguage" in script
    assert "language-select" in styles
    assert "中文" in markup


def test_frontend_has_container_search_and_status_filters() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="container-search"' in markup
    assert 'id="container-status-filter"' in markup
    assert "updateContainerFilters" in script
    assert "containerMatchesFilters" in script
    assert "No containers match the current filters." in script
    assert ".container-controls" in styles
    assert "setTableCellLabel" in script
    assert "content: attr(data-label)" in styles
    assert "table-empty-row" in styles


def test_frontend_has_loading_error_and_empty_states() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert "hasLoaded: false" in script
    assert "isLoading: false" in script
    assert "refreshError" in script
    assert "createDataEmptyState" in script
    assert "createEmptyState" in script
    assert 't("empty.retry")' in script
    assert ".empty-state" in styles
    assert ".empty-state.loading" in styles
    assert ".empty-state.error" in styles


def test_frontend_marks_stale_docker_inventory() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")

    assert '"docker.inventoryStale"' in script
    assert 'node.docker_inventory_status === "stale"' in script
    assert "node.docker_inventory_error" in script
    assert "dockerStatusText" in script


def test_frontend_websocket_reconnect_is_bounded_and_cancelable() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")

    assert "wsReconnectTimer: null" in script
    assert "wsReconnectAttempts: 0" in script
    assert "function scheduleWsReconnect" in script
    assert "Math.min(30000" in script
    assert "Math.random()" in script
    assert "clearTimeout(state.wsReconnectTimer)" in script
    assert "if (state.ws !== ws) return" in script


def test_frontend_treats_send_failed_as_a_problem_command() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")

    assert 'new Set(["failed", "send_failed", "timeout"])' in script
    assert '=== "send_failed") return "failed"' in script


def test_frontend_respects_rbac_scopes_for_mutating_controls() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert "applyAuthProfile" in script
    assert "hasScope(\"commands:create\")" in script
    assert "createContainerActions" in script
    assert "read only" in script
    assert "hasScope(\"*\")" in script
    assert "input.disabled = !canManageThresholds" in script
    assert "button:disabled" in styles


def test_frontend_supports_dark_theme_for_ui_and_chart() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="theme-toggle"' in markup
    assert "loadTheme()" in script
    assert "toggleTheme" in script
    assert "applyTheme" in script
    assert "monitor.theme" in script
    assert "chartColors()" in script
    assert ':root[data-theme="dark"]' in styles
    assert "--chart-bg" in styles


def test_frontend_supports_chart_drag_zoom() -> None:
    script = Path("web/app.js").read_text(encoding="utf-8")
    markup = Path("web/index.html").read_text(encoding="utf-8")
    styles = Path("web/styles.css").read_text(encoding="utf-8")

    assert 'id="chart-zoom-reset"' in markup
    assert "startChartSelection" in script
    assert "finishChartSelection" in script
    assert "metricsForChart()" in script
    assert "summarizeMetrics(metricsForChart())" in script
    assert "state.metricZoom" in script
    assert "--chart-selection" in styles
    assert "touch-action: none" in styles


def test_deployment_artifacts_are_hardened_by_default() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    server_unit = Path("deploy/systemd/monitor-server.service").read_text(encoding="utf-8")
    agent_unit = Path("deploy/systemd/monitor-agent.service").read_text(encoding="utf-8")
    backup_timer = Path("deploy/systemd/monitor-db-backup.timer").read_text(encoding="utf-8")
    backup_script = Path("scripts/backup_sqlite.sh").read_text(encoding="utf-8")

    assert "USER monitor" in dockerfile
    assert "127.0.0.1:8000:8000" in compose
    assert "MONITOR_HOST: 0.0.0.0" in compose
    assert "MONITOR_DATABASE_PATH: /app/data/monitor.db" in compose
    assert "profiles:" in compose
    assert "/var/run/docker.sock:/var/run/docker.sock" in compose
    assert "no-new-privileges:true" in compose
    assert "ExecReload=/bin/kill -HUP $MAINPID" in server_unit
    assert "NoNewPrivileges=true" in server_unit
    assert "SupplementaryGroups=docker" in agent_unit
    assert "OnCalendar=daily" in backup_timer
    assert ".backup" in backup_script
    assert "PRAGMA integrity_check" in backup_script


def test_ui_smoke_check_script_exercises_real_browser_flow() -> None:
    wrapper = Path("scripts/ui_smoke_check.ps1").read_text(encoding="utf-8")
    script = Path("scripts/ui_smoke_check.mjs").read_text(encoding="utf-8")

    assert "Get-Command npx" in wrapper
    assert "--package" in wrapper
    assert "playwright" in wrapper
    assert "chromium.launch" in script
    assert "#login-username" in script
    assert "#login-password" in script
    assert "data-page-link" in script
    assert "language-select" in script
    assert "theme-toggle" in script
    assert 'clickPage(page, "admin")' in script
    assert "setViewportSize" in script
    assert '#mobile-nav-toggle' in script
    assert "#app-view.sidebar-collapsed" in script


def test_yaml_artifacts_parse() -> None:
    for path in [
        ".github/workflows/security.yml",
        ".github/dependabot.yml",
        "docker-compose.yml",
        "server.example.yaml",
        "agent.example.yaml",
    ]:
        assert yaml.safe_load(Path(path).read_text(encoding="utf-8")) is not None


def test_ui_websocket_rejects_api_token(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        api_tokens=[
            ApiTokenConfig(
                name="read-token",
                token_hash=hash_secret("api-token"),
                scopes=["nodes:read"],
            )
        ],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/ui") as websocket:
                websocket.send_json({"type": "auth", "token": "api-token"})
                websocket.receive_json()


def test_login_rejects_invalid_payload_shape(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    app = create_app(cfg)

    with TestClient(app) as client:
        response = client.post("/api/auth/login", json=["admin", "admin-password"])
        assert response.status_code == 400

        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "x" * 5000},
        )
        assert response.status_code == 400


def test_alert_webhook_config_rejects_plaintext_secret_and_insecure_production_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "server.yaml"
    path.write_text(
        """
environment: development
alert_notifications:
  enabled: false
  webhooks:
    - name: local
      url: http://127.0.0.1:9000/alerts
      secret: plaintext-secret
      secret_env: MONITOR_TEST_ALERT_SECRET
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Plaintext alert_notifications"):
        load_server_config(str(path))

    monkeypatch.setenv("MONITOR_TEST_ALERT_SECRET", "s" * 32)
    path.write_text(
        """
environment: production
alert_notifications:
  enabled: true
  webhooks:
    - name: operations
      url: http://alerts.example.com/monitor
      secret_env: MONITOR_TEST_ALERT_SECRET
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must use HTTPS"):
        load_server_config(str(path))


def test_alert_webhook_config_resolves_secret_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "server.yaml"
    monkeypatch.setenv("MONITOR_TEST_ALERT_SECRET", "s" * 32)
    path.write_text(
        """
environment: development
alert_notifications:
  enabled: true
  queue_size: 12
  worker_count: 1
  webhooks:
    - name: local
      url: http://127.0.0.1:9000/alerts
      secret_env: MONITOR_TEST_ALERT_SECRET
      enabled: true
""".strip(),
        encoding="utf-8",
    )

    loaded = load_server_config(str(path))

    assert loaded.alert_notifications.enabled is True
    assert loaded.alert_notifications.queue_size == 12
    assert loaded.alert_notifications.webhooks[0].secret == "s" * 32
    assert "s" * 32 not in repr(loaded.alert_notifications.webhooks[0])


def test_alert_notifier_signs_retries_and_audits_delivery() -> None:
    requests: list[httpx.Request] = []
    audits: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(503 if len(requests) == 1 else 204)

    notification_config = AlertNotificationConfig(
        enabled=True,
        queue_size=10,
        worker_count=1,
        request_timeout_seconds=1,
        max_attempts=2,
        retry_base_seconds=0,
        webhooks=[
            AlertWebhookConfig(
                name="operations",
                url="https://alerts.example.com/monitor",
                secret_env="MONITOR_TEST_ALERT_SECRET",
                secret="s" * 32,
            )
        ],
    )
    notifier = AlertNotifier(
        notification_config,
        lambda **event: audits.append(event),
        transport=httpx.MockTransport(handler),
    )
    alert_event = {
        "type": "alert_created",
        "alert": {"id": "alert-1", "node_id": "agent-a", "metric": "cpu", "value": 95},
    }

    async def exercise() -> dict[str, object]:
        await notifier.start()
        assert notifier.enqueue(alert_event) == 1
        await asyncio.wait_for(notifier.join(), timeout=1)
        status = notifier.status()
        await notifier.stop()
        return status

    status = asyncio.run(exercise())

    assert len(requests) == 2
    body = requests[-1].content
    timestamp = requests[-1].headers["X-Monitor-Timestamp"]
    expected = hmac.new(
        b"s" * 32,
        timestamp.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    assert requests[-1].headers["X-Monitor-Signature"] == f"sha256={expected}"
    assert json.loads(body)["alert"]["id"] == "alert-1"
    assert status["delivered"] == 1
    assert status["failed"] == 0
    assert any(event["event_type"] == "alert_notification_delivered" for event in audits)


def test_alert_notifier_does_not_follow_redirects_or_retry_client_errors() -> None:
    requests: list[httpx.Request] = []
    audits: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/internal"})

    notification_config = AlertNotificationConfig(
        enabled=True,
        worker_count=1,
        max_attempts=3,
        retry_base_seconds=0,
        webhooks=[
            AlertWebhookConfig(
                name="operations",
                url="https://alerts.example.com/monitor",
                secret_env="MONITOR_TEST_ALERT_SECRET",
                secret="s" * 32,
            )
        ],
    )
    notifier = AlertNotifier(
        notification_config,
        lambda **event: audits.append(event),
        transport=httpx.MockTransport(handler),
    )

    async def exercise() -> None:
        await notifier.start()
        notifier.enqueue({"type": "alert_resolved", "alert": {"id": "alert-1"}})
        await asyncio.wait_for(notifier.join(), timeout=1)
        await notifier.stop()

    asyncio.run(exercise())

    assert len(requests) == 1
    failure = next(event for event in audits if event["event_type"] == "alert_notification_failed")
    assert failure["detail"]["status_code"] == 302
    assert failure["detail"]["attempts"] == 1
