from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import hmac

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from .config import ServerConfig
from .db import Database
from .hub import ConnectionHub
from .security import create_session_token, require_admin_token, verify_admin_token


ALLOWED_COMMANDS = {
    "container.start",
    "container.stop",
    "container.restart",
}


def create_app(config: ServerConfig) -> FastAPI:
    app = FastAPI(title="Monitor Server", version="0.1.0")
    app.state.config = config
    app.state.db = Database(config.database_path)
    app.state.hub = ConnectionHub()
    app.state.status_task = None

    @app.on_event("startup")
    async def startup() -> None:
        app.state.db.init()
        app.state.status_task = asyncio.create_task(_status_watcher(app))

    @app.on_event("shutdown")
    async def shutdown() -> None:
        task = app.state.status_task
        if task:
            task.cancel()
        app.state.db.close()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/login")
    async def login(request: Request) -> dict[str, Any]:
        body = await request.json()
        username = str(body.get("username") or "")
        password = str(body.get("password") or "")
        username_ok = hmac.compare_digest(username, config.admin_username)
        password_ok = hmac.compare_digest(password, config.admin_password)

        if not username_ok or not password_ok:
            raise HTTPException(status_code=401, detail="invalid username or password")

        token, expires_at = create_session_token(config, username)
        return {
            "token": token,
            "token_type": "bearer",
            "expires_at": expires_at,
            "username": username,
        }

    @app.get("/api/auth/me")
    async def me(user: str = Depends(require_admin_token)) -> dict[str, str]:
        return {"username": user}

    @app.get("/api/nodes")
    async def list_nodes(_: str = Depends(require_admin_token)) -> list[dict[str, Any]]:
        return app.state.db.list_nodes()

    @app.get("/api/nodes/{node_id}/metrics")
    async def list_metrics(
        node_id: str,
        limit: int = 120,
        _: str = Depends(require_admin_token),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_metrics(node_id, limit=max(1, min(limit, 1000)))

    @app.get("/api/containers")
    async def list_containers(
        node_id: str | None = None,
        _: str = Depends(require_admin_token),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_containers(node_id)

    @app.get("/api/commands")
    async def list_commands(
        limit: int = 100,
        _: str = Depends(require_admin_token),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_commands(limit=max(1, min(limit, 500)))

    @app.get("/api/audit-logs")
    async def list_audit_logs(
        limit: int = 100,
        _: str = Depends(require_admin_token),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_audit_logs(limit=max(1, min(limit, 500)))

    @app.post("/api/nodes/{node_id}/commands")
    async def create_command(
        node_id: str,
        request: Request,
        user: str = Depends(require_admin_token),
    ) -> dict[str, Any]:
        body = await request.json()
        action = str(body.get("action") or "")
        payload = body.get("payload") or {}

        if action not in ALLOWED_COMMANDS:
            raise HTTPException(status_code=400, detail="unsupported command action")
        if not isinstance(payload, dict) or not payload.get("container_id"):
            raise HTTPException(status_code=400, detail="payload.container_id is required")

        command = app.state.db.create_command(node_id, action, payload, created_by=user)
        app.state.db.add_audit_log(
            user=user,
            action=action,
            target=str(payload.get("container_id")),
            node_id=node_id,
            result="created",
        )

        sent = await app.state.hub.send_command(node_id, command)
        if sent:
            app.state.db.mark_command_sent(command["id"])
            command = app.state.db.get_command(command["id"])

        await app.state.hub.broadcast_ui({"type": "command_updated", "command": command})
        return command

    @app.websocket("/agent/ws")
    async def agent_ws(websocket: WebSocket) -> None:
        token = websocket.query_params.get("token")
        node_id = websocket.query_params.get("agent_id") or websocket.query_params.get("node_id")
        agent_name = websocket.query_params.get("agent_name") or node_id

        if token not in config.agent_tokens or not node_id:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        app.state.db.ensure_node(node_id, agent_name)
        app.state.db.mark_seen(node_id)
        await app.state.hub.register_agent(node_id, websocket)
        await app.state.hub.broadcast_ui({"type": "node_connected", "node_id": node_id})
        await websocket.send_json({"type": "welcome", "node_id": node_id})

        try:
            while True:
                message = await websocket.receive_json()
                await _handle_agent_message(app, node_id, message)
        except WebSocketDisconnect:
            pass
        finally:
            await app.state.hub.unregister_agent(node_id, websocket)

    @app.websocket("/ws/ui")
    async def ui_ws(websocket: WebSocket) -> None:
        token = websocket.query_params.get("token")
        if not verify_admin_token(config, token):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        await app.state.hub.register_ui(websocket)
        await websocket.send_json({"type": "snapshot_hint"})
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await app.state.hub.unregister_ui(websocket)

    web_dir = Path(__file__).resolve().parents[2] / "web"
    app.mount("/", StaticFiles(directory=web_dir, html=True, check_dir=False), name="web")
    return app


async def _handle_agent_message(app: FastAPI, node_id: str, message: dict[str, Any]) -> None:
    db: Database = app.state.db
    hub: ConnectionHub = app.state.hub
    message_type = message.get("type")
    data = message.get("data") or {}

    db.mark_seen(node_id)

    if message_type in {"hello", "host_info"}:
        db.update_host_info(node_id, data)
        await hub.broadcast_ui({"type": "node_updated", "node_id": node_id})
        return

    if message_type == "heartbeat":
        await hub.broadcast_ui({"type": "heartbeat", "node_id": node_id})
        return

    if message_type == "metrics":
        db.save_metrics(node_id, data)
        await hub.broadcast_ui({"type": "metrics_updated", "node_id": node_id})
        return

    if message_type == "docker_inventory":
        containers = data.get("containers") or []
        if isinstance(containers, list):
            db.replace_inventory(node_id, containers)
            await hub.broadcast_ui({"type": "containers_updated", "node_id": node_id})
        return

    if message_type == "docker_stats":
        stats = data.get("containers") or []
        if isinstance(stats, list):
            db.update_container_stats(node_id, stats)
            await hub.broadcast_ui({"type": "containers_updated", "node_id": node_id})
        return

    if message_type == "command_result":
        command_id = str(data.get("command_id") or message.get("command_id") or "")
        status = str(data.get("status") or "failed")
        result_message = data.get("message")
        command = db.mark_command_result(command_id, status, result_message)
        if command:
            db.add_audit_log(
                user="agent",
                action=command["action"],
                target=str(command["payload"].get("container_id")),
                node_id=node_id,
                result=status,
            )
            await hub.broadcast_ui({"type": "command_updated", "command": command})
        return


async def _status_watcher(app: FastAPI) -> None:
    config: ServerConfig = app.state.config
    while True:
        await asyncio.sleep(5)
        changes = app.state.db.update_stale_node_statuses(
            warning_after_seconds=config.heartbeat.warning_after_seconds,
            offline_after_seconds=config.heartbeat.offline_after_seconds,
        )
        for change in changes:
            await app.state.hub.broadcast_ui({"type": "node_status_changed", **change})
