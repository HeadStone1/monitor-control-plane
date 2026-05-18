from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import DEV_ADMIN_PASSWORD_HASH, DEV_AGENT_TOKEN_HASH, ServerConfig
from .db import Database
from .hub import ConnectionHub
from .security import (
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    create_session_token,
    require_admin_token,
    set_session_cookie,
    is_secret_hash,
    verify_admin_token,
    verify_admin_password,
    verify_agent_credentials,
)


ALLOWED_COMMANDS = {
    "container.start",
    "container.stop",
    "container.restart",
}

LOGGER = logging.getLogger("monitor.server")


class FailureRateLimiter:
    def __init__(self, window_seconds: int, max_failures: int) -> None:
        self.window_seconds = max(1, window_seconds)
        self.max_failures = max(1, max_failures)
        self._failures: dict[str, list[float]] = {}

    def can_attempt(self, key: str) -> bool:
        now = time.monotonic()
        failures = self._recent_failures(key, now)
        return len(failures) < self.max_failures

    def add_failure(self, key: str) -> None:
        now = time.monotonic()
        failures = self._recent_failures(key, now)
        failures.append(now)
        self._failures[key] = failures

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)

    def _recent_failures(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        failures = [item for item in self._failures.get(key, []) if item >= cutoff]
        self._failures[key] = failures
        return failures


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        config: ServerConfig = request.app.state.config
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if _request_is_secure(request, config) or config.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class SecureTransportMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, config: ServerConfig) -> None:
        super().__init__(app)
        self.config = config

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if self.config.require_secure_transport and not _request_is_secure(request, self.config):
            return JSONResponse(
                {"detail": "secure transport is required"},
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)


def create_app(config: ServerConfig) -> FastAPI:
    app = FastAPI(title="Monitor Server", version="0.1.0")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.allowed_hosts)
    app.add_middleware(SecureTransportMiddleware, config=config)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.config = config
    app.state.db = Database(config.database_path)
    app.state.hub = ConnectionHub()
    app.state.status_task = None
    app.state.login_limiter = FailureRateLimiter(
        config.auth_rate_limit.window_seconds,
        config.auth_rate_limit.login_max_failures,
    )
    app.state.ws_limiter = FailureRateLimiter(
        config.auth_rate_limit.window_seconds,
        config.auth_rate_limit.ws_max_failures,
    )

    @app.on_event("startup")
    async def startup() -> None:
        _validate_startup_security(config)
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
    async def login(request: Request, response: Response) -> dict[str, Any]:
        body = await request.json()
        username = str(body.get("username") or "")
        password = str(body.get("password") or "")
        limiter: FailureRateLimiter = app.state.login_limiter
        rate_key = f"login:{_client_host(request)}:{username}"

        if not limiter.can_attempt(rate_key):
            raise HTTPException(status_code=429, detail="too many failed login attempts")

        if not verify_admin_password(config, username, password):
            limiter.add_failure(rate_key)
            raise HTTPException(status_code=401, detail="invalid username or password")

        limiter.reset(rate_key)
        token, expires_at = create_session_token(config, username)
        set_session_cookie(
            response,
            token,
            max_age_seconds=config.session_ttl_hours * 3600,
            secure=config.secure_cookies or _request_is_secure(request, config),
        )
        return {
            "expires_at": expires_at,
            "username": username,
        }

    @app.post("/api/auth/logout")
    async def logout(response: Response) -> dict[str, str]:
        clear_session_cookie(response)
        return {"status": "signed_out"}

    @app.get("/api/auth/me")
    async def me(user: str = Depends(require_admin_token)) -> dict[str, str]:
        return {"username": user}

    @app.get("/api/nodes")
    async def list_nodes(_: str = Depends(require_admin_token)) -> list[dict[str, Any]]:
        return app.state.db.list_nodes()

    @app.get("/api/nodes/{node_id}/metrics")
    async def list_metrics(
        node_id: str,
        metric_range: str = Query("1h", alias="range"),
        _: str = Depends(require_admin_token),
    ) -> dict[str, Any]:
        if metric_range not in {"1h", "7d", "30d"}:
            raise HTTPException(status_code=400, detail="unsupported metric range")
        return app.state.db.list_metric_series(node_id, range_name=metric_range)

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
        container_id = str(payload.get("container_id"))
        if not app.state.db.container_exists(node_id, container_id):
            raise HTTPException(status_code=404, detail="container is not known on this node")
        payload["container_id"] = container_id

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
        await websocket.accept()
        if config.require_secure_transport and websocket.url.scheme != "wss":
            await websocket.close(code=1008)
            return

        limiter: FailureRateLimiter = app.state.ws_limiter
        rate_key = f"agent-ws:{_ws_client_host(websocket)}"
        if not limiter.can_attempt(rate_key):
            await websocket.close(code=1008)
            return

        auth = await _receive_ws_auth(websocket)
        if not auth:
            limiter.add_failure(rate_key)
            await websocket.close(code=1008)
            return

        token = str(auth.get("token") or "")
        node_id = str(auth.get("agent_id") or auth.get("node_id") or "")
        credential = verify_agent_credentials(config, node_id, token)

        if credential is None:
            limiter.add_failure(rate_key)
            await websocket.close(code=1008)
            return

        limiter.reset(rate_key)
        agent_name = credential.name or str(auth.get("agent_name") or node_id)
        app.state.db.ensure_node(node_id, agent_name)
        app.state.db.mark_seen(node_id)
        await app.state.hub.register_agent(node_id, websocket)
        await app.state.hub.broadcast_ui({"type": "node_connected", "node_id": node_id})
        await websocket.send_json({"type": "auth_ok", "node_id": node_id})

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
        await websocket.accept()
        if config.require_secure_transport and websocket.url.scheme != "wss":
            await websocket.close(code=1008)
            return

        limiter: FailureRateLimiter = app.state.ws_limiter
        rate_key = f"ui-ws:{_ws_client_host(websocket)}"
        if not limiter.can_attempt(rate_key):
            await websocket.close(code=1008)
            return

        auth = await _receive_ws_auth(websocket)
        token = str((auth or {}).get("token") or "") or websocket.cookies.get(SESSION_COOKIE_NAME)
        if not verify_admin_token(config, token):
            limiter.add_failure(rate_key)
            await websocket.close(code=1008)
            return
        limiter.reset(rate_key)
        await app.state.hub.register_ui(websocket)
        await websocket.send_json({"type": "auth_ok"})
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


async def _receive_ws_auth(websocket: WebSocket) -> dict[str, Any] | None:
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except (asyncio.TimeoutError, ValueError, RuntimeError):
        return None
    if not isinstance(message, dict) or message.get("type") != "auth":
        return None
    return message


def _validate_startup_security(config: ServerConfig) -> None:
    weak_values = {
        "admin_token": "dev-admin-token",
        "session_secret": "dev-session-secret-change-me",
    }
    strict_mode = config.environment.lower() == "production" or not _is_loopback_host(config.host)
    weak: list[str] = []
    for key, weak_value in weak_values.items():
        if getattr(config, key) == weak_value:
            weak.append(key)
    if config.admin_password == "dev-admin-password" or config.admin_password_hash == DEV_ADMIN_PASSWORD_HASH:
        weak.append("admin_password_hash")
    if not config.admin_password_hash and not config.admin_password:
        weak.append("admin_password_missing")
    if config.admin_password_hash and not is_secret_hash(config.admin_password_hash):
        weak.append("invalid_admin_password_hash")
    if any(agent.token == "dev-agent-token" or agent.token_hash == DEV_AGENT_TOKEN_HASH for agent in config.agents):
        weak.append("agents")
    if not config.agents:
        weak.append("agents_missing")
    if any(not agent.token and not agent.token_hash for agent in config.agents):
        weak.append("agent_token_missing")
    if any(agent.token_hash and not is_secret_hash(agent.token_hash) for agent in config.agents):
        weak.append("invalid_agent_token_hash")
    if config.admin_password:
        weak.append("plaintext_admin_password")
    if any(agent.token for agent in config.agents):
        weak.append("plaintext_agent_token")
    for key in ("admin_token", "session_secret"):
        value = str(getattr(config, key) or "")
        if _looks_placeholder(value) or len(value) < 24:
            weak.append(key)
    if any(_looks_placeholder(agent.token) for agent in config.agents):
        weak.append("plaintext_agent_token")

    if weak and strict_mode:
        joined = ", ".join(sorted(set(weak)))
        raise RuntimeError(f"Refusing to start with development security defaults: {joined}")
    for key in sorted(set(weak)):
        LOGGER.warning("Using development default %s. Replace it before network exposure.", key)

    if config.environment.lower() == "production" and not config.secure_cookies:
        raise RuntimeError("Production mode requires secure_cookies=true")
    if config.environment.lower() == "production" and not config.require_secure_transport:
        raise RuntimeError("Production mode requires require_secure_transport=true")


async def _handle_agent_message(app: FastAPI, node_id: str, message: dict[str, Any]) -> None:
    if not isinstance(message, dict):
        return

    config: ServerConfig = app.state.config
    db: Database = app.state.db
    hub: ConnectionHub = app.state.hub
    message_type = message.get("type")
    data = message.get("data") or {}
    if not isinstance(data, dict):
        data = {}

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
        containers = _bounded_list(
            data.get("containers") or [],
            config.agent_payload_limits.max_containers,
            node_id,
            "docker_inventory",
        )
        if isinstance(containers, list):
            db.replace_inventory(node_id, containers)
            await hub.broadcast_ui({"type": "containers_updated", "node_id": node_id})
        return

    if message_type == "docker_stats":
        stats = _bounded_list(
            data.get("containers") or [],
            config.agent_payload_limits.max_containers,
            node_id,
            "docker_stats",
        )
        if isinstance(stats, list):
            db.update_container_stats(node_id, stats)
            await hub.broadcast_ui({"type": "containers_updated", "node_id": node_id})
        return

    if message_type == "command_result":
        command_id = str(data.get("command_id") or message.get("command_id") or "")
        status = str(data.get("status") or "failed")
        result_message = _bounded_text(data.get("message"), config.agent_payload_limits.max_result_message_bytes)
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


def _bounded_list(value: Any, limit: int, node_id: str, message_type: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    if len(value) > limit:
        LOGGER.warning(
            "Truncating %s from node %s: %s items exceeds limit %s",
            message_type,
            node_id,
            len(value),
            limit,
        )
    return [item for item in value[:limit] if isinstance(item, dict)]


def _bounded_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text.encode("utf-8")) <= limit:
        return text
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def _request_is_secure(request: Request, config: ServerConfig) -> bool:
    if request.url.scheme == "https":
        return True
    if not config.trust_proxy_headers:
        return False
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return forwarded_proto.split(",", 1)[0].strip().lower() == "https"


def _client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _ws_client_host(websocket: WebSocket) -> str:
    return websocket.client.host if websocket.client else "unknown"


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def _looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith("change-me") or lowered.startswith("replace-with")
