from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent.monitor_agent.client import MonitorAgent
from agent.monitor_agent.config import AgentConfig
from agent.monitor_agent.collectors.docker_collector import DockerCollector
from server.monitor_server.app import _handle_agent_message, create_app
from server.monitor_server.config import AgentCredential, ApiTokenConfig, ServerConfig, UserConfig, load_server_config
from server.monitor_server.db import Database
from server.monitor_server.doctor import format_doctor_report, run_config_doctor
from server.monitor_server.hub import ConnectionHub
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


class FakeDocker:
    def __init__(self) -> None:
        self.executed: tuple[str, str] | None = None

    def execute(self, action: str, container_id: str) -> tuple[bool, str]:
        self.executed = (action, container_id)
        return True, "done"

    def inventory(self) -> list[dict[str, object]]:
        return []


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
        assert cfg.agents[0].enabled is False

        logs = app.state.db.list_audit_logs(limit=10)
        assert any(item["event_type"] == "agent_token_revoked" for item in logs)


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
        assert payload["config"]["command_timeout_seconds"] == cfg.command.timeout_seconds


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


def test_duplicate_agent_registration_rejected() -> None:
    async def run() -> None:
        hub = ConnectionHub()
        first = object()
        second = object()
        assert await hub.register_agent("agent-a", first) is True
        assert await hub.register_agent("agent-a", second) is False

    asyncio.run(run())


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
