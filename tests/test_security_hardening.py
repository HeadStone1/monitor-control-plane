from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from server.monitor_server.app import _handle_agent_message, create_app
from server.monitor_server.config import AgentCredential, ServerConfig
from server.monitor_server.db import Database
from server.monitor_server.hub import ConnectionHub
from server.monitor_server.security import hash_secret


def config(tmp_path: Path, **overrides: object) -> ServerConfig:
    base = ServerConfig(
        database_path=tmp_path / "monitor.db",
        allowed_hosts=["testserver", "127.0.0.1", "localhost"],
        admin_token="dev-admin-token",
        admin_username="admin",
        admin_password_hash=hash_secret("admin-password"),
        admin_password="",
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
