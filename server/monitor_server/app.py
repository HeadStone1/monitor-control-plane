from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
import signal
import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import (
    AgentCredential,
    DEV_ADMIN_PASSWORD_HASH,
    DEV_AGENT_TOKEN_HASH,
    ServerConfig,
    load_server_config,
    validate_alert_notification_config,
)
from .db import Database, SUPPORTED_METRIC_RANGES
from .hub import ConnectionHub
from .notifications import AlertNotifier
from .security import (
    AuthContext,
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    create_session_token,
    extract_csrf_token,
    require_permission,
    set_session_cookie,
    is_secret_hash,
    verify_admin_password,
    verify_agent_credentials,
    verify_auth_context,
)


ALLOWED_COMMANDS = {
    "container.start",
    "container.stop",
    "container.restart",
}
AGENT_PROTOCOL_VERSION = "1"

LOGGER = logging.getLogger("monitor.server")
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class MetricsPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    captured_at: str | None = Field(default=None, max_length=64)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    disk_percent: float | None = Field(default=None, ge=0, le=100)
    load1: float | None = Field(default=None, ge=0)
    load5: float | None = Field(default=None, ge=0)
    load15: float | None = Field(default=None, ge=0)
    net_rx: int | None = Field(default=None, ge=0)
    net_tx: int | None = Field(default=None, ge=0)


class DockerContainerPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(pattern=r"^[a-fA-F0-9]{12,128}$")
    short_id: str | None = Field(default=None, max_length=128)
    name: str | None = Field(default=None, max_length=128)
    image: str | None = Field(default=None, max_length=256)
    status: str | None = Field(default=None, max_length=64)
    ports: dict[str, Any] = Field(default_factory=dict)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_usage: int | None = Field(default=None, ge=0)
    memory_limit: int | None = Field(default=None, ge=0)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 64:
            raise ValueError("too many ports")
        return value


class DockerStatsPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(pattern=r"^[a-fA-F0-9]{12,128}$")
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_usage: int | None = Field(default=None, ge=0)
    memory_limit: int | None = Field(default=None, ge=0)


class DockerInventoryEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ok: bool = Field(default=True, strict=True)
    error: str | None = Field(default=None, max_length=512)


class CommandResultPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    command_id: str = Field(min_length=1, max_length=80)
    status: str = Field(pattern=r"^(success|failed)$")
    message: str | None = Field(default=None, max_length=4096)


class CommandStatePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    command_id: str = Field(min_length=1, max_length=80)
    message: str | None = Field(default=None, max_length=4096)


class ThresholdSettingsPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu: float | None = Field(default=None, ge=0, le=100)
    memory: float | None = Field(default=None, ge=0, le=100)
    disk: float | None = Field(default=None, ge=0, le=100)


class LoginPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=4096)


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
            "connect-src 'self'; "
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


@asynccontextmanager
async def _lifespan(app: FastAPI) -> Any:
    config: ServerConfig = app.state.config
    _validate_startup_security(config)
    app.state.db.init()
    await app.state.alert_notifier.start()
    app.state.status_task = asyncio.create_task(_status_watcher(app))
    _install_sighup_reload(app)
    try:
        yield
    finally:
        task = app.state.status_task
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await app.state.alert_notifier.stop()
        app.state.db.close()


def create_app(config: ServerConfig) -> FastAPI:
    app = FastAPI(title="Monitor Server", version="0.1.0", lifespan=_lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.allowed_hosts)
    app.add_middleware(SecureTransportMiddleware, config=config)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.config = config
    app.state.db = Database(config.database_path)
    app.state.hub = ConnectionHub(send_timeout_seconds=config.command.send_timeout_seconds)
    app.state.alert_notifier = AlertNotifier(config.alert_notifications, app.state.db.add_security_event)
    app.state.status_task = None
    app.state.reload_lock = asyncio.Lock()
    app.state.last_rollup_at = 0.0
    app.state.metrics_maintenance = {
        "running": False,
        "last_started_at": None,
        "last_completed_at": None,
        "last_duration_ms": None,
        "last_error": None,
        "last_result": {},
    }
    app.state.status_watcher_health = {
        "cycle_running": False,
        "cycles_completed": 0,
        "total_failures": 0,
        "consecutive_failures": 0,
        "last_started_at": None,
        "last_success_at": None,
        "last_failure_at": None,
        "last_duration_ms": None,
        "last_error": None,
        "last_failure_error": None,
        "next_retry_seconds": 5.0,
    }
    app.state.login_limiter = FailureRateLimiter(
        config.auth_rate_limit.window_seconds,
        config.auth_rate_limit.login_max_failures,
    )
    app.state.ws_limiter = FailureRateLimiter(
        config.auth_rate_limit.window_seconds,
        config.auth_rate_limit.ws_max_failures,
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        database = app.state.db.health_summary(public=True)
        watcher_running = app.state.status_task is not None and not app.state.status_task.done()
        return {
            "status": "ok" if watcher_running else "degraded",
            "version": app.version,
            "database": "ok",
            "wal": database["journal_mode"] == "wal",
            "background": "ok" if watcher_running else "stopped",
        }

    @app.get("/api/admin/health")
    async def admin_health(_: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
        watcher_running = app.state.status_task is not None and not app.state.status_task.done()
        return {
            "status": "ok" if watcher_running else "degraded",
            "version": app.version,
            "database": app.state.db.health_summary(public=False),
            "background": {
                "status_watcher": watcher_running,
                "status_watcher_health": dict(app.state.status_watcher_health),
                "metrics_maintenance": dict(app.state.metrics_maintenance),
                "alert_notifications": app.state.alert_notifier.status(),
            },
            "config": {
                "environment": config.environment,
                "config_path": str(config.config_path) if config.config_path else "",
                "command_timeout_seconds": config.command.timeout_seconds,
                "command_send_timeout_seconds": config.command.send_timeout_seconds,
                "raw_metrics_days": config.retention.raw_metrics_days,
                "rollup_interval_seconds": config.retention.rollup_interval_seconds,
                "maintenance_batch_size": config.retention.maintenance_batch_size,
                "alert_notifications_enabled": config.alert_notifications.enabled,
                "alert_webhooks": len(
                    [webhook for webhook in config.alert_notifications.webhooks if webhook.enabled]
                ),
            },
        }

    @app.post("/api/auth/login")
    async def login(request: Request, response: Response) -> dict[str, Any]:
        try:
            body = await request.json()
            login_payload = LoginPayload.model_validate(body)
        except (ValueError, ValidationError):
            app.state.db.add_security_event(
                event_type="login_invalid_payload",
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                result="rejected",
            )
            raise HTTPException(status_code=400, detail="invalid login payload")

        username = login_payload.username
        password = login_payload.password
        limiter: FailureRateLimiter = app.state.login_limiter
        rate_key = f"login:{_client_host(request)}:{username}"

        if not limiter.can_attempt(rate_key):
            app.state.db.add_security_event(
                event_type="login_rate_limited",
                actor=username,
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                result="rejected",
            )
            raise HTTPException(status_code=429, detail="too many failed login attempts")

        if not verify_admin_password(config, username, password):
            limiter.add_failure(rate_key)
            app.state.db.add_security_event(
                event_type="login_failed",
                actor=username,
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                result="rejected",
            )
            raise HTTPException(status_code=401, detail="invalid username or password")

        limiter.reset(rate_key)
        token, expires_at = create_session_token(config, username)
        csrf_token = extract_csrf_token(config, token)
        context = verify_auth_context(config, token, allow_static_admin_token=False)
        set_session_cookie(
            response,
            token,
            max_age_seconds=config.session_ttl_hours * 3600,
            secure=config.secure_cookies or _request_is_secure(request, config),
        )
        app.state.db.add_security_event(
            event_type="login_success",
            actor=username,
            client_ip=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            result="accepted",
        )
        return {
            "csrf_token": csrf_token,
            "expires_at": expires_at,
            "username": username,
            "role": context.role if context else "",
            "scopes": context.scopes if context else [],
        }

    @app.post("/api/auth/logout")
    async def logout(response: Response, _: AuthContext = Depends(require_permission("authenticated"))) -> dict[str, str]:
        clear_session_cookie(response)
        return {"status": "signed_out"}

    @app.get("/api/auth/me")
    async def me(request: Request, auth: AuthContext = Depends(require_permission("nodes:read"))) -> dict[str, Any]:
        csrf_token = extract_csrf_token(config, request.cookies.get(SESSION_COOKIE_NAME))
        return {"username": auth.actor, "role": auth.role, "scopes": auth.scopes, "csrf_token": csrf_token or ""}

    @app.get("/api/nodes")
    async def list_nodes(_: AuthContext = Depends(require_permission("nodes:read"))) -> list[dict[str, Any]]:
        return app.state.db.list_nodes()

    @app.get("/api/nodes/{node_id}/metrics")
    async def list_metrics(
        node_id: str,
        metric_range: str = Query("1h", alias="range"),
        _: AuthContext = Depends(require_permission("metrics:read")),
    ) -> dict[str, Any]:
        if metric_range not in SUPPORTED_METRIC_RANGES:
            raise HTTPException(status_code=400, detail="unsupported metric range")
        return app.state.db.list_metric_series(node_id, range_name=metric_range)

    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics(_: AuthContext = Depends(require_permission("metrics:read"))) -> PlainTextResponse:
        return PlainTextResponse(
            _prometheus_metrics(app.state.db.list_nodes()),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/api/settings/thresholds")
    async def get_thresholds(_: AuthContext = Depends(require_permission("metrics:read"))) -> dict[str, Any]:
        thresholds, configured = app.state.db.get_thresholds()
        return {"thresholds": thresholds, "configured": configured}

    @app.put("/api/settings/thresholds")
    async def put_thresholds(
        request: Request,
        auth: AuthContext = Depends(require_permission("*")),
    ) -> dict[str, Any]:
        try:
            payload = ThresholdSettingsPayload.model_validate(await request.json())
        except (ValueError, ValidationError):
            raise HTTPException(status_code=400, detail="invalid threshold payload")
        thresholds = app.state.db.set_thresholds(payload.model_dump())
        app.state.db.add_security_event(
            event_type="thresholds_updated",
            actor=auth.actor,
            client_ip=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            result="accepted",
            detail={"thresholds": thresholds},
        )
        await app.state.hub.broadcast_ui({"type": "thresholds_updated", "thresholds": thresholds})
        return {"thresholds": thresholds}

    @app.get("/api/alerts")
    async def list_alerts(
        limit: int = 100,
        status_filter: str | None = Query(None, alias="status"),
        node_id: str | None = None,
        _: AuthContext = Depends(require_permission("metrics:read")),
    ) -> list[dict[str, Any]]:
        if status_filter and status_filter not in {"active", "resolved"}:
            raise HTTPException(status_code=400, detail="unsupported alert status")
        return app.state.db.list_alerts(limit=max(1, min(limit, 500)), status=status_filter, node_id=node_id)

    @app.get("/api/containers")
    async def list_containers(
        node_id: str | None = None,
        _: AuthContext = Depends(require_permission("containers:read")),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_containers(node_id)

    @app.get("/api/commands")
    async def list_commands(
        limit: int = 100,
        _: AuthContext = Depends(require_permission("commands:read")),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_commands(limit=max(1, min(limit, 500)))

    @app.get("/api/audit-logs")
    async def list_audit_logs(
        limit: int = 100,
        node_id: str | None = None,
        action: str | None = None,
        from_time: str | None = Query(None, alias="from"),
        to_time: str | None = Query(None, alias="to"),
        _: AuthContext = Depends(require_permission("audit:read")),
    ) -> list[dict[str, Any]]:
        return app.state.db.list_audit_logs(
            limit=max(1, min(limit, 500)),
            node_id=node_id or None,
            action=action or None,
            from_time=from_time or None,
            to_time=to_time or None,
        )

    @app.post("/api/admin/config/reload")
    async def reload_config(
        request: Request,
        auth: AuthContext = Depends(require_permission("*")),
    ) -> dict[str, Any]:
        try:
            return await _reload_runtime_config(
                app,
                actor=auth.actor,
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
            )
        except (RuntimeError, ValueError) as exc:
            app.state.db.add_security_event(
                event_type="config_reload_failed",
                actor=auth.actor,
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                result="rejected",
                detail={"error": str(exc)},
            )
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/admin/agents/{node_id}/revoke")
    async def revoke_agent(
        node_id: str,
        request: Request,
        auth: AuthContext = Depends(require_permission("*")),
    ) -> dict[str, Any]:
        result = await _revoke_agent_runtime(
            app,
            node_id,
            actor=auth.actor,
            client_ip=_client_host(request),
            user_agent=request.headers.get("user-agent"),
        )
        if result is None:
            app.state.db.add_security_event(
                event_type="agent_token_revoke_failed",
                actor=auth.actor,
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                node_id=node_id,
                result="not_found",
            )
            raise HTTPException(status_code=404, detail="agent credential not found")
        return result

    @app.post("/api/nodes/{node_id}/commands")
    async def create_command(
        node_id: str,
        request: Request,
        auth: AuthContext = Depends(require_permission("commands:create")),
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

        command = app.state.db.create_command(node_id, action, payload, created_by=auth.actor)
        app.state.db.add_audit_log(
            user=auth.actor,
            action=action,
            target=str(payload.get("container_id")),
            node_id=node_id,
            result="created",
        )

        sent = await app.state.hub.send_command(node_id, command, timeout_seconds=config.command.timeout_seconds)
        if sent:
            app.state.db.mark_command_sent(command["id"])
            command = app.state.db.get_command(command["id"])
        else:
            message = "agent is not connected or command delivery failed"
            command = app.state.db.mark_command_send_failed(command["id"], message) or command
            app.state.db.add_audit_log(
                user=auth.actor,
                action=action,
                target=container_id,
                node_id=node_id,
                result="send_failed",
            )
            app.state.db.add_security_event(
                event_type="command_delivery_failed",
                actor=auth.actor,
                client_ip=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                node_id=node_id,
                target=command["id"],
                result="send_failed",
                detail={"action": action, "container_id": container_id},
            )

        await app.state.hub.broadcast_ui({"type": "command_updated", "command": command})
        return command

    @app.websocket("/agent/ws")
    async def agent_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        if config.require_secure_transport and not _websocket_is_secure(websocket, config):
            app.state.db.add_security_event(
                event_type="agent_ws_rejected",
                client_ip=_ws_client_host(websocket),
                result="insecure_transport",
            )
            await _reject_agent_websocket(websocket, "insecure_transport")
            return

        limiter: FailureRateLimiter = app.state.ws_limiter
        rate_key = f"agent-ws:{_ws_client_host(websocket)}"
        if not limiter.can_attempt(rate_key):
            app.state.db.add_security_event(
                event_type="agent_ws_rate_limited",
                client_ip=_ws_client_host(websocket),
                result="rejected",
            )
            await _reject_agent_websocket(websocket, "rate_limited")
            return

        auth = await _receive_ws_auth(websocket)
        if not auth:
            limiter.add_failure(rate_key)
            app.state.db.add_security_event(
                event_type="agent_auth_failed",
                client_ip=_ws_client_host(websocket),
                result="missing_auth",
            )
            await _reject_agent_websocket(websocket, "authentication_required")
            return

        token = str(auth.get("token") or "")
        node_id = str(auth.get("agent_id") or auth.get("node_id") or "")
        protocol_version = str(auth.get("protocol_version") or AGENT_PROTOCOL_VERSION)
        if protocol_version != AGENT_PROTOCOL_VERSION:
            limiter.add_failure(rate_key)
            app.state.db.add_security_event(
                event_type="agent_protocol_rejected",
                actor=node_id or None,
                client_ip=_ws_client_host(websocket),
                node_id=node_id or None,
                result="unsupported_protocol",
                detail={"received": protocol_version, "supported": AGENT_PROTOCOL_VERSION},
            )
            await _reject_agent_websocket(websocket, "unsupported_protocol")
            return
        credential = verify_agent_credentials(config, node_id, token)

        if credential is None:
            limiter.add_failure(rate_key)
            app.state.db.add_security_event(
                event_type="agent_auth_failed",
                actor=node_id,
                client_ip=_ws_client_host(websocket),
                node_id=node_id or None,
                result="invalid_credentials",
            )
            await _reject_agent_websocket(websocket, "invalid_credentials")
            return

        credential_fingerprint = _agent_credential_fingerprint(credential)
        if app.state.db.is_agent_credential_revoked(
            node_id,
            credential_fingerprint,
            credential.token_id,
        ):
            limiter.add_failure(rate_key)
            app.state.db.add_security_event(
                event_type="agent_revoked_credential_rejected",
                actor=node_id,
                client_ip=_ws_client_host(websocket),
                node_id=node_id,
                result="revoked_credentials",
                detail={"token_id": credential.token_id},
            )
            await _reject_agent_websocket(websocket, "revoked_credentials")
            return

        limiter.reset(rate_key)
        agent_name = credential.name or str(auth.get("agent_name") or node_id)
        registered = await app.state.hub.register_agent(
            node_id,
            websocket,
            credential_fingerprint=credential_fingerprint,
        )
        if not registered:
            app.state.db.add_security_event(
                event_type="agent_duplicate_connection",
                actor=node_id,
                client_ip=_ws_client_host(websocket),
                node_id=node_id,
                result="rejected",
            )
            await _reject_agent_websocket(websocket, "duplicate_node_connection")
            return
        app.state.db.ensure_node(node_id, agent_name)
        app.state.db.mark_seen(node_id)
        app.state.db.add_security_event(
            event_type="agent_connected",
            actor=node_id,
            client_ip=_ws_client_host(websocket),
            node_id=node_id,
            result="accepted",
            detail={"token_id": credential.token_id},
        )
        await app.state.hub.broadcast_ui({"type": "node_connected", "node_id": node_id})
        await websocket.send_json(
            {"type": "auth_ok", "node_id": node_id, "protocol_version": AGENT_PROTOCOL_VERSION}
        )

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
        if config.require_secure_transport and not _websocket_is_secure(websocket, config):
            app.state.db.add_security_event(
                event_type="ui_ws_rejected",
                client_ip=_ws_client_host(websocket),
                result="insecure_transport",
            )
            await websocket.close(code=1008)
            return

        limiter: FailureRateLimiter = app.state.ws_limiter
        rate_key = f"ui-ws:{_ws_client_host(websocket)}"
        if not limiter.can_attempt(rate_key):
            app.state.db.add_security_event(
                event_type="ui_ws_rate_limited",
                client_ip=_ws_client_host(websocket),
                result="rejected",
            )
            await websocket.close(code=1008)
            return

        auth = await _receive_ws_auth(websocket)
        token = str((auth or {}).get("token") or "") or websocket.cookies.get(SESSION_COOKIE_NAME)
        context = verify_auth_context(config, token, allow_static_admin_token=True)
        if (
            not context
            or context.source != "session"
            or ("*" not in context.scopes and "nodes:read" not in context.scopes)
        ):
            limiter.add_failure(rate_key)
            app.state.db.add_security_event(
                event_type="ui_ws_auth_failed",
                client_ip=_ws_client_host(websocket),
                result="invalid_credentials",
            )
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


async def _reject_agent_websocket(websocket: WebSocket, error: str) -> None:
    try:
        await websocket.send_json(
            {
                "type": "auth_error",
                "error": error,
                "protocol_version": AGENT_PROTOCOL_VERSION,
            }
        )
    except Exception:
        LOGGER.debug("Could not send Agent authentication error", exc_info=True)
    await websocket.close(code=1008)


async def _receive_ws_auth(websocket: WebSocket) -> dict[str, Any] | None:
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except (asyncio.TimeoutError, ValueError, RuntimeError):
        return None
    if not isinstance(message, dict) or message.get("type") != "auth":
        return None
    return message


def _validate_startup_security(config: ServerConfig) -> None:
    try:
        validate_alert_notification_config(config.alert_notifications, config.environment)
    except ValueError as exc:
        raise RuntimeError(f"Invalid alert notification configuration: {exc}") from exc

    weak_values = {
        "admin_token": "dev-admin-token",
        "session_secret": "dev-session-secret-change-me",
    }
    strict_mode = config.environment.lower() == "production" or not _is_loopback_host(config.host)
    weak: list[str] = []
    invalid_hashes: list[str] = []
    for key, weak_value in weak_values.items():
        if getattr(config, key) == weak_value:
            weak.append(key)
    if config.admin_password_hash == DEV_ADMIN_PASSWORD_HASH:
        weak.append("admin_password_hash")
    has_user_password = any(user.enabled and user.password_hash for user in config.users)
    if not config.admin_password_hash and not has_user_password:
        weak.append("admin_password_missing")
    if config.admin_password_hash and not is_secret_hash(config.admin_password_hash):
        invalid_hashes.append("invalid_admin_password_hash")
    if any(agent.token_hash == DEV_AGENT_TOKEN_HASH for agent in config.agents):
        weak.append("agents")
    if not config.agents:
        weak.append("agents_missing")
    if any(not agent.token_hash for agent in config.agents):
        weak.append("agent_token_missing")
    if any(agent.token_hash and not is_secret_hash(agent.token_hash) for agent in config.agents):
        invalid_hashes.append("invalid_agent_token_hash")
    if any(user.password_hash and not is_secret_hash(user.password_hash) for user in config.users):
        invalid_hashes.append("invalid_user_password_hash")
    for key in ("admin_token", "session_secret"):
        value = str(getattr(config, key) or "")
        if key == "admin_token" and not value:
            continue
        if _looks_placeholder(value) or len(value) < 24:
            weak.append(key)

    if any(token.enabled and token.token_hash and not is_secret_hash(token.token_hash) for token in config.api_tokens):
        invalid_hashes.append("invalid_api_token_hash")
    if invalid_hashes:
        joined = ", ".join(sorted(set(invalid_hashes)))
        raise RuntimeError(f"Invalid security hash configuration: {joined}")

    if weak and strict_mode:
        joined = ", ".join(sorted(set(weak)))
        raise RuntimeError(f"Refusing to start with development security defaults: {joined}")
    for key in sorted(set(weak)):
        LOGGER.warning("Using development default %s. Replace it before network exposure.", key)

    if config.environment.lower() == "production" and not config.secure_cookies:
        raise RuntimeError("Production mode requires secure_cookies=true")
    if config.environment.lower() == "production" and not config.require_secure_transport:
        raise RuntimeError("Production mode requires require_secure_transport=true")
    if config.environment.lower() == "production" and config.admin_token:
        raise RuntimeError("admin_token is disabled in production")


def _install_sighup_reload(app: FastAPI) -> None:
    if not hasattr(signal, "SIGHUP"):
        return
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(
            signal.SIGHUP,
            lambda: asyncio.create_task(_reload_runtime_config_from_signal(app)),
        )
    except (NotImplementedError, RuntimeError, ValueError):
        return


async def _reload_runtime_config_from_signal(app: FastAPI) -> None:
    try:
        await _reload_runtime_config(app, actor="signal")
    except Exception as exc:  # pragma: no cover - defensive signal callback guard
        LOGGER.exception("Failed to reload monitor config from SIGHUP")
        if hasattr(app.state, "db"):
            app.state.db.add_security_event(
                event_type="config_reload_failed",
                actor="signal",
                result="rejected",
                detail={"error": str(exc)},
            )


def _prometheus_metrics(nodes: list[dict[str, Any]]) -> str:
    lines = [
        "# HELP monitor_node_online Whether the monitor node is online.",
        "# TYPE monitor_node_online gauge",
        "# HELP monitor_node_cpu_percent Latest node CPU utilization percent.",
        "# TYPE monitor_node_cpu_percent gauge",
        "# HELP monitor_node_memory_percent Latest node memory utilization percent.",
        "# TYPE monitor_node_memory_percent gauge",
        "# HELP monitor_node_disk_percent Latest node disk utilization percent.",
        "# TYPE monitor_node_disk_percent gauge",
        "# HELP monitor_node_docker_available Whether Docker is available on the node.",
        "# TYPE monitor_node_docker_available gauge",
        "# HELP monitor_node_last_seen_timestamp_seconds Last agent heartbeat time as a Unix timestamp.",
        "# TYPE monitor_node_last_seen_timestamp_seconds gauge",
        "# HELP monitor_node_latest_metric_timestamp_seconds Latest metric capture time as a Unix timestamp.",
        "# TYPE monitor_node_latest_metric_timestamp_seconds gauge",
        "# HELP monitor_node_info Node metadata labels with a constant value of 1.",
        "# TYPE monitor_node_info gauge",
    ]

    for node in nodes:
        labels = _prometheus_labels(
            {
                "node_id": node.get("id"),
                "name": node.get("name"),
                "hostname": node.get("hostname"),
            }
        )
        info_labels = _prometheus_labels(
            {
                "node_id": node.get("id"),
                "name": node.get("name"),
                "hostname": node.get("hostname"),
                "ip": node.get("ip"),
                "os": node.get("os"),
                "arch": node.get("arch"),
                "agent_version": node.get("agent_version"),
                "docker_version": node.get("docker_version"),
            }
        )
        lines.append(f"monitor_node_online{{{labels}}} {1 if node.get('status') == 'online' else 0}")
        lines.append(f"monitor_node_info{{{info_labels}}} 1")
        _append_prometheus_gauge(lines, "monitor_node_cpu_percent", labels, node.get("latest_cpu_percent"))
        _append_prometheus_gauge(lines, "monitor_node_memory_percent", labels, node.get("latest_memory_percent"))
        _append_prometheus_gauge(lines, "monitor_node_disk_percent", labels, node.get("latest_disk_percent"))
        _append_prometheus_gauge(
            lines,
            "monitor_node_docker_available",
            labels,
            1 if node.get("docker_available") else 0,
        )
        _append_prometheus_gauge(
            lines,
            "monitor_node_last_seen_timestamp_seconds",
            labels,
            _timestamp_seconds(node.get("last_seen")),
        )
        _append_prometheus_gauge(
            lines,
            "monitor_node_latest_metric_timestamp_seconds",
            labels,
            _timestamp_seconds(node.get("latest_metric_at")),
        )

    return "\n".join(lines) + "\n"


def _append_prometheus_gauge(lines: list[str], name: str, labels: str, value: Any) -> None:
    if value is None:
        return
    try:
        number = float(value)
    except (TypeError, ValueError):
        return
    lines.append(f"{name}{{{labels}}} {number:g}")


def _prometheus_labels(values: dict[str, Any]) -> str:
    return ",".join(f'{key}="{_prometheus_label_value(value)}"' for key, value in values.items())


def _prometheus_label_value(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _timestamp_seconds(value: Any) -> float | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


async def _reload_runtime_config(
    app: FastAPI,
    actor: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    async with app.state.reload_lock:
        current: ServerConfig = app.state.config
        if current.config_path is None:
            raise RuntimeError("config reload requires a config file path")

        loaded = load_server_config(str(current.config_path))
        _validate_startup_security(loaded)
        replacement_notifier = AlertNotifier(loaded.alert_notifications, app.state.db.add_security_event)
        await replacement_notifier.start()
        _apply_runtime_config(current, loaded)
        previous_notifier = app.state.alert_notifier
        app.state.alert_notifier = replacement_notifier
        await previous_notifier.stop(reason="config_reload")
        app.state.hub.set_send_timeout_seconds(current.command.send_timeout_seconds)
        disconnected = await _disconnect_agents_with_stale_credentials(app)

        app.state.db.add_security_event(
            event_type="config_reloaded",
            actor=actor,
            client_ip=client_ip,
            user_agent=user_agent,
            result="accepted",
            detail={
                "config_path": str(current.config_path),
                "agents": len(current.agents),
                "api_tokens": len(current.api_tokens),
                "users": len(current.users),
                "roles": sorted(current.roles),
                "alert_webhooks": len(
                    [webhook for webhook in current.alert_notifications.webhooks if webhook.enabled]
                ),
                "disconnected_agents": disconnected,
            },
        )
        await app.state.hub.broadcast_ui({"type": "config_reloaded", "disconnected_agents": disconnected})
        return {
            "status": "reloaded",
            "agents": len(current.agents),
            "api_tokens": len(current.api_tokens),
            "users": len(current.users),
            "roles": sorted(current.roles),
            "alert_webhooks": len(
                [webhook for webhook in current.alert_notifications.webhooks if webhook.enabled]
            ),
            "disconnected_agents": disconnected,
        }


def _apply_runtime_config(current: ServerConfig, loaded: ServerConfig) -> None:
    current.config_path = loaded.config_path
    current.admin_username = loaded.admin_username
    current.admin_password_hash = loaded.admin_password_hash
    current.users = loaded.users
    current.roles = loaded.roles
    current.api_tokens = loaded.api_tokens
    current.agents = loaded.agents
    current.command = loaded.command
    current.retention = loaded.retention
    current.alert_notifications = loaded.alert_notifications


async def _disconnect_agents_with_stale_credentials(app: FastAPI) -> list[str]:
    disconnected: list[str] = []
    config: ServerConfig = app.state.config
    hub: ConnectionHub = app.state.hub
    for node_id in await hub.connected_agent_ids():
        fingerprint = await hub.agent_credential_fingerprint(node_id)
        if (
            fingerprint
            and fingerprint in _enabled_agent_fingerprints(config, node_id)
            and not app.state.db.is_agent_credential_revoked(node_id, fingerprint)
        ):
            continue
        if await hub.disconnect_agent(node_id, code=1008, reason="agent credential changed"):
            disconnected.append(node_id)
            app.state.db.add_security_event(
                event_type="agent_disconnected_after_config_reload",
                actor="system",
                node_id=node_id,
                result="disconnected",
            )
    return disconnected


async def _revoke_agent_runtime(
    app: FastAPI,
    node_id: str,
    actor: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any] | None:
    config: ServerConfig = app.state.config
    credentials = [
        credential
        for credential in config.agents
        if credential.node_id == node_id and credential.enabled
    ]
    if not credentials:
        return None

    persisted = app.state.db.revoke_agent_credentials(
        node_id,
        [(_agent_credential_fingerprint(credential), credential.token_id) for credential in credentials],
        revoked_by=actor,
        client_ip=client_ip,
    )
    for credential in credentials:
        credential.enabled = False
    revoked = len(credentials)

    disconnected = await app.state.hub.disconnect_agent(node_id, code=1008, reason="agent token revoked")
    app.state.db.add_security_event(
        event_type="agent_token_revoked",
        actor=actor,
        client_ip=client_ip,
        user_agent=user_agent,
        node_id=node_id,
        result="accepted",
        detail={
            "credentials_revoked": revoked,
            "revocations_persisted": persisted,
            "disconnected": disconnected,
        },
    )
    await app.state.hub.broadcast_ui(
        {"type": "agent_token_revoked", "node_id": node_id, "disconnected": disconnected}
    )
    return {
        "node_id": node_id,
        "revoked": True,
        "credentials_revoked": revoked,
        "revocations_persisted": persisted,
        "disconnected": disconnected,
    }


def _enabled_agent_fingerprints(config: ServerConfig, node_id: str) -> set[str]:
    return {
        _agent_credential_fingerprint(credential)
        for credential in config.agents
        if credential.enabled and credential.node_id == node_id
    }


def _agent_credential_fingerprint(credential: AgentCredential) -> str:
    material = credential.token_hash
    if not material:
        return ""
    return hashlib.sha256(f"{credential.node_id}:{material}".encode("utf-8")).hexdigest()


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
        try:
            payload = MetricsPayload.model_validate(data).model_dump(exclude_none=True)
        except ValidationError as exc:
            db.add_security_event(
                event_type="agent_payload_invalid",
                actor=node_id,
                node_id=node_id,
                result="rejected",
                detail={"message_type": message_type, "errors": exc.errors()},
            )
            return
        db.save_metrics(node_id, payload)
        thresholds, _ = db.get_thresholds()
        for event in db.evaluate_metric_alerts(node_id, payload, thresholds):
            alert = event["alert"]
            db.add_security_event(
                event_type=event["type"],
                actor="system",
                node_id=node_id,
                target=str(alert.get("metric") or ""),
                result=str(alert.get("status") or ""),
                detail={"alert_id": alert.get("id"), "threshold": alert.get("threshold"), "value": alert.get("value")},
            )
            await hub.broadcast_ui(event)
            notifier = getattr(app.state, "alert_notifier", None)
            if notifier is not None:
                notifier.enqueue(event)
        await hub.broadcast_ui({"type": "metrics_updated", "node_id": node_id})
        return

    if message_type == "docker_inventory":
        try:
            collection = DockerInventoryEnvelope.model_validate(data)
        except ValidationError as exc:
            db.add_security_event(
                event_type="agent_payload_invalid",
                actor=node_id,
                node_id=node_id,
                result="rejected",
                detail={"message_type": message_type, "errors": exc.errors()},
            )
            return
        if not collection.ok:
            error = collection.error or "docker inventory collection failed"
            db.mark_inventory_failed(node_id, error)
            db.add_security_event(
                event_type="docker_inventory_collection_failed",
                actor=node_id,
                node_id=node_id,
                result="stale",
                detail={"error": error},
            )
            await hub.broadcast_ui(
                {
                    "type": "docker_inventory_stale",
                    "node_id": node_id,
                    "error": error,
                }
            )
            return
        containers = _bounded_list(
            data.get("containers") or [],
            config.agent_payload_limits.max_containers,
            node_id,
            "docker_inventory",
        )
        if isinstance(containers, list):
            try:
                payloads = [
                    DockerContainerPayload.model_validate(item).model_dump(exclude_none=True)
                    for item in containers
                ]
            except ValidationError as exc:
                db.add_security_event(
                    event_type="agent_payload_invalid",
                    actor=node_id,
                    node_id=node_id,
                    result="rejected",
                    detail={"message_type": message_type, "errors": exc.errors()},
                )
                return
            db.replace_inventory(node_id, payloads)
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
            try:
                payloads = [
                    DockerStatsPayload.model_validate(item).model_dump(exclude_none=True)
                    for item in stats
                ]
            except ValidationError as exc:
                db.add_security_event(
                    event_type="agent_payload_invalid",
                    actor=node_id,
                    node_id=node_id,
                    result="rejected",
                    detail={"message_type": message_type, "errors": exc.errors()},
                )
                return
            db.update_container_stats(node_id, payloads)
            await hub.broadcast_ui({"type": "containers_updated", "node_id": node_id})
        return

    if message_type == "command_ack":
        ack_data = dict(data)
        if "command_id" not in ack_data and message.get("command_id"):
            ack_data["command_id"] = message.get("command_id")
        try:
            payload = CommandStatePayload.model_validate(ack_data)
        except ValidationError as exc:
            db.add_security_event(
                event_type="agent_payload_invalid",
                actor=node_id,
                node_id=node_id,
                result="rejected",
                detail={"message_type": message_type, "errors": exc.errors()},
            )
            return
        command = db.mark_command_acknowledged(payload.command_id, node_id)
        if command:
            await hub.broadcast_ui({"type": "command_updated", "command": command})
        else:
            db.add_security_event(
                event_type="command_ack_node_mismatch",
                actor=node_id,
                node_id=node_id,
                target=payload.command_id,
                result="rejected",
            )
        return

    if message_type == "command_running":
        running_data = dict(data)
        if "command_id" not in running_data and message.get("command_id"):
            running_data["command_id"] = message.get("command_id")
        try:
            payload = CommandStatePayload.model_validate(running_data)
        except ValidationError as exc:
            db.add_security_event(
                event_type="agent_payload_invalid",
                actor=node_id,
                node_id=node_id,
                result="rejected",
                detail={"message_type": message_type, "errors": exc.errors()},
            )
            return
        command = db.mark_command_running(payload.command_id, node_id)
        if command:
            await hub.broadcast_ui({"type": "command_updated", "command": command})
        else:
            db.add_security_event(
                event_type="command_running_node_mismatch",
                actor=node_id,
                node_id=node_id,
                target=payload.command_id,
                result="rejected",
            )
        return

    if message_type == "command_result":
        result_data = dict(data)
        if "command_id" not in result_data and message.get("command_id"):
            result_data["command_id"] = message.get("command_id")
        try:
            payload = CommandResultPayload.model_validate(result_data)
        except ValidationError as exc:
            db.add_security_event(
                event_type="agent_payload_invalid",
                actor=node_id,
                node_id=node_id,
                result="rejected",
                detail={"message_type": message_type, "errors": exc.errors()},
            )
            return
        result_message = _bounded_text(payload.message, config.agent_payload_limits.max_result_message_bytes)
        command = db.mark_command_result(payload.command_id, node_id, payload.status, result_message)
        if command:
            db.add_audit_log(
                user="agent",
                action=command["action"],
                target=str(command["payload"].get("container_id")),
                node_id=node_id,
                result=payload.status,
            )
            await hub.broadcast_ui({"type": "command_updated", "command": command})
        else:
            db.add_security_event(
                event_type="command_result_node_mismatch",
                actor=node_id,
                node_id=node_id,
                target=payload.command_id,
                result="rejected",
            )
        return


def _run_metrics_maintenance(
    db: Database,
    *,
    include_rollup: bool,
    raw_metrics_days: int,
    hourly_rollup_days: int,
    daily_rollup_days: int,
    batch_size: int,
) -> dict[str, Any]:
    maintenance_db = Database(db.path)
    try:
        rollups = {"hourly": 0, "daily": 0, "hourly_source_rows": 0, "daily_source_rows": 0}
        pruned_rollups = {"hourly": 0, "daily": 0}
        if include_rollup:
            rollups = maintenance_db.rollup_metrics()
            pruned_rollups = maintenance_db.prune_rollups(
                hourly_days=hourly_rollup_days,
                daily_days=daily_rollup_days,
                batch_size=batch_size,
            )
        pruned_raw = maintenance_db.prune_metrics(raw_metrics_days, batch_size=batch_size)
        return {
            "rollup_ran": include_rollup,
            "rollups": rollups,
            "pruned_rollups": pruned_rollups,
            "pruned_raw": pruned_raw,
        }
    finally:
        maintenance_db.close()


async def _maintain_metrics(app: FastAPI, include_rollup: bool) -> None:
    config: ServerConfig = app.state.config
    status = app.state.metrics_maintenance
    started = time.perf_counter()
    status.update(
        {
            "running": True,
            "last_started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "last_error": None,
        }
    )
    try:
        worker = asyncio.create_task(
            asyncio.to_thread(
                _run_metrics_maintenance,
                app.state.db,
                include_rollup=include_rollup,
                raw_metrics_days=config.retention.raw_metrics_days,
                hourly_rollup_days=config.retention.hourly_rollup_days,
                daily_rollup_days=config.retention.daily_rollup_days,
                batch_size=config.retention.maintenance_batch_size,
            )
        )
        try:
            result = await asyncio.shield(worker)
        except asyncio.CancelledError:
            await worker
            raise
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        status.update(
            {
                "last_completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "last_duration_ms": duration_ms,
                "last_result": result,
            }
        )
        if include_rollup and (
            result["rollups"]["hourly"]
            or result["rollups"]["daily"]
            or any(result["pruned_rollups"].values())
        ):
            app.state.db.add_security_event(
                event_type="metrics_rollup_completed",
                actor="system",
                result="success",
                detail={**result, "duration_ms": duration_ms},
            )
        if result["pruned_raw"]:
            app.state.db.add_security_event(
                event_type="metrics_retention_pruned",
                actor="system",
                result="success",
                detail={"rows": result["pruned_raw"], "duration_ms": duration_ms},
            )
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        status.update(
            {
                "last_completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "last_duration_ms": duration_ms,
                "last_error": str(exc),
            }
        )
        LOGGER.exception("Metrics maintenance failed")
        app.state.db.add_security_event(
            event_type="metrics_maintenance_failed",
            actor="system",
            result="failed",
            detail={"error": str(exc), "duration_ms": duration_ms},
        )
    finally:
        status["running"] = False


async def _status_watcher_cycle(app: FastAPI) -> None:
    config: ServerConfig = app.state.config
    changes = app.state.db.update_stale_node_statuses(
        warning_after_seconds=config.heartbeat.warning_after_seconds,
        offline_after_seconds=config.heartbeat.offline_after_seconds,
    )
    for change in changes:
        await app.state.hub.broadcast_ui({"type": "node_status_changed", **change})
    for command in app.state.db.expire_stale_commands(config.command.timeout_seconds):
        app.state.db.add_audit_log(
            user="system",
            action=command["action"],
            target=str(command["payload"].get("container_id")),
            node_id=command["node_id"],
            result="timeout",
        )
        await app.state.hub.broadcast_ui({"type": "command_updated", "command": command})
    now = time.monotonic()
    include_rollup = now - app.state.last_rollup_at >= config.retention.rollup_interval_seconds
    if include_rollup:
        app.state.last_rollup_at = now
    await _maintain_metrics(app, include_rollup)


def _record_status_watcher_failure(app: FastAPI, error: Exception, failures: int, duration_ms: float) -> None:
    if failures != 1 and failures % 12 != 0:
        return
    try:
        app.state.db.add_security_event(
            event_type="status_watcher_failed",
            actor="system",
            result="failed",
            detail={
                "error": str(error),
                "consecutive_failures": failures,
                "duration_ms": duration_ms,
            },
        )
    except Exception:
        LOGGER.exception("Could not persist status watcher failure audit event")


async def _status_watcher(
    app: FastAPI,
    interval_seconds: float = 5.0,
    max_retry_seconds: float = 30.0,
) -> None:
    retry_seconds = max(0.01, interval_seconds)
    while True:
        app.state.status_watcher_health["next_retry_seconds"] = retry_seconds
        await asyncio.sleep(retry_seconds)
        status = app.state.status_watcher_health
        started = time.perf_counter()
        status.update(
            {
                "cycle_running": True,
                "last_started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )
        try:
            await _status_watcher_cycle(app)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            failures = int(status["consecutive_failures"]) + 1
            retry_seconds = min(max_retry_seconds, max(interval_seconds, interval_seconds * (2**failures)))
            failure_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            status.update(
                {
                    "total_failures": int(status["total_failures"]) + 1,
                    "consecutive_failures": failures,
                    "last_failure_at": failure_at,
                    "last_duration_ms": duration_ms,
                    "last_error": str(exc),
                    "last_failure_error": str(exc),
                    "next_retry_seconds": retry_seconds,
                }
            )
            LOGGER.exception("Status watcher cycle failed; retrying in %.2f seconds", retry_seconds)
            _record_status_watcher_failure(app, exc, failures, duration_ms)
        else:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            retry_seconds = max(0.01, interval_seconds)
            status.update(
                {
                    "cycles_completed": int(status["cycles_completed"]) + 1,
                    "consecutive_failures": 0,
                    "last_success_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "last_duration_ms": duration_ms,
                    "last_error": None,
                    "next_retry_seconds": retry_seconds,
                }
            )
        finally:
            status["cycle_running"] = False


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


def _websocket_is_secure(websocket: WebSocket, config: ServerConfig) -> bool:
    if websocket.url.scheme == "wss":
        return True
    if not config.trust_proxy_headers:
        return False
    forwarded_proto = websocket.headers.get("x-forwarded-proto", "")
    return forwarded_proto.split(",", 1)[0].strip().lower() in {"https", "wss"}


def _client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _ws_client_host(websocket: WebSocket) -> str:
    return websocket.client.host if websocket.client else "unknown"


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def _looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith("change-me") or lowered.startswith("replace-with")
