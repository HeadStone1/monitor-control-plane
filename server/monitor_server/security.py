from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request, Response, status

from .config import AgentCredential, ApiTokenConfig, ServerConfig, UserConfig


TOKEN_PREFIX = "monitor"
SESSION_COOKIE_NAME = "monitor_session"
ARGON2_HASH_PREFIX = "$argon2id$"
CSRF_HEADER_NAME = "x-csrf-token"

_ARGON2_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


@dataclass(slots=True)
class AuthContext:
    actor: str
    scopes: list[str]
    source: str
    role: str = ""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_secret(secret: str) -> str:
    return _ARGON2_HASHER.hash(secret)


def is_secret_hash(encoded: str) -> bool:
    if not encoded.startswith(ARGON2_HASH_PREFIX):
        return False
    try:
        _ARGON2_HASHER.check_needs_rehash(encoded)
    except (InvalidHashError, VerificationError, ValueError, TypeError):
        return False
    return True


def verify_secret(secret: str, encoded: str) -> bool:
    if not encoded.startswith(ARGON2_HASH_PREFIX):
        return False
    try:
        return _ARGON2_HASHER.verify(encoded, secret)
    except (InvalidHashError, VerificationError, VerifyMismatchError, ValueError, TypeError):
        return False


def extract_bearer_token(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return value.strip()


def create_session_token(config: ServerConfig, username: str) -> tuple[str, int]:
    expires_at = int(time.time() + config.session_ttl_hours * 3600)
    csrf_token = secrets.token_urlsafe(32)
    payload = {
        "sub": username,
        "exp": expires_at,
        "csrf": csrf_token,
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _sign(config, body)
    return f"{TOKEN_PREFIX}.{body}.{signature}", expires_at


def extract_csrf_token(config: ServerConfig, token: str | None) -> str | None:
    payload = decode_session_payload(config, token)
    if not payload:
        return None
    csrf = payload.get("csrf")
    return csrf if isinstance(csrf, str) and csrf else None


def verify_admin_password(config: ServerConfig, username: str, password: str) -> bool:
    user = find_user(config, username)
    if not user:
        return False
    if user.password_hash:
        return verify_secret(password, user.password_hash)
    return False


def find_user(config: ServerConfig, username: str) -> UserConfig | None:
    for user in config.users:
        if user.enabled and hmac.compare_digest(username, user.username):
            return user
    if hmac.compare_digest(username, config.admin_username) and config.admin_password_hash:
        return UserConfig(
            username=config.admin_username,
            password_hash=config.admin_password_hash,
            role="admin",
        )
    return None


def verify_agent_credentials(config: ServerConfig, node_id: str, token: str) -> AgentCredential | None:
    if not node_id or not token:
        return None

    for agent in config.agents:
        if not agent.enabled or not hmac.compare_digest(node_id, agent.node_id):
            continue
        if agent.token_hash and verify_secret(token, agent.token_hash):
            return agent
    return None


def verify_admin_token(config: ServerConfig, token: str | None) -> str | None:
    context = verify_auth_context(config, token, allow_static_admin_token=True)
    return context.actor if context else None


def verify_auth_context(
    config: ServerConfig,
    token: str | None,
    *,
    allow_static_admin_token: bool,
) -> AuthContext | None:
    if not token:
        return None

    if allow_static_admin_token and config.admin_token and hmac.compare_digest(token, config.admin_token):
        if config.environment.lower() == "production":
            return None
        return AuthContext(
            actor=config.admin_username,
            scopes=["*"],
            source="admin_token",
            role="admin",
        )

    api_token = verify_api_token(config, token)
    if api_token:
        return AuthContext(
            actor=api_token.name,
            scopes=api_token.scopes,
            source="api_token",
        )

    payload = decode_session_payload(config, token)
    if not payload:
        return None

    username = payload.get("sub")
    if not isinstance(username, str) or not username:
        return None
    user = find_user(config, username)
    if not user:
        return None
    return AuthContext(
        actor=username,
        scopes=config.roles.get(user.role, []),
        source="session",
        role=user.role,
    )


def verify_api_token(config: ServerConfig, token: str) -> ApiTokenConfig | None:
    now = datetime.now(timezone.utc)
    for item in config.api_tokens:
        if not item.enabled:
            continue
        if item.expires_at:
            try:
                expires_at = datetime.fromisoformat(item.expires_at.replace("Z", "+00:00"))
            except ValueError:
                continue
            if expires_at.astimezone(timezone.utc) <= now:
                continue
        if verify_secret(token, item.token_hash):
            return item
    return None


def decode_session_payload(config: ServerConfig, token: str | None) -> dict[str, object] | None:
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None

    _, body, signature = parts
    expected = _sign(config, body)
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        payload = json.loads(_b64decode(body).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    if int(payload.get("exp", 0)) < int(time.time()):
        return None

    return payload


def _sign(config: ServerConfig, body: str) -> str:
    digest = hmac.new(
        config.session_secret.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64encode(digest)


def require_admin_token(request: Request) -> str:
    return require_permission("*")(request).actor


def require_permission(scope: str):
    def dependency(request: Request) -> AuthContext:
        return _require_auth_context(request, scope)

    return dependency


def _require_auth_context(request: Request, scope: str) -> AuthContext:
    config: ServerConfig = request.app.state.config
    token = extract_bearer_token(request.headers.get("authorization"))
    token = token or request.headers.get("x-admin-token")
    token = token or request.cookies.get(SESSION_COOKIE_NAME)

    context = verify_auth_context(config, token, allow_static_admin_token=True)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired credentials",
        )
    if scope != "authenticated" and "*" not in context.scopes and scope not in context.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient permissions")
    _verify_csrf_for_cookie_session(request, config, token, context)
    if context.source == "admin_token" and hasattr(request.app.state, "db"):
        request.app.state.db.add_security_event(
            event_type="admin_token_used",
            actor=context.actor,
            client_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent"),
            result="accepted",
            detail={"path": request.url.path, "method": request.method},
        )
    return context


def _verify_csrf_for_cookie_session(
    request: Request,
    config: ServerConfig,
    token: str | None,
    context: AuthContext,
) -> None:
    if context.source != "session":
        return
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie_token or not token or not hmac.compare_digest(cookie_token, token):
        return
    expected = extract_csrf_token(config, token)
    supplied = request.headers.get(CSRF_HEADER_NAME)
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        if hasattr(request.app.state, "db"):
            request.app.state.db.add_security_event(
                event_type="csrf_failed",
                actor=context.actor,
                client_ip=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent"),
                result="rejected",
                detail={"path": request.url.path, "method": request.method},
            )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid csrf token")


def set_session_cookie(response: Response, token: str, max_age_seconds: int, secure: bool) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age_seconds,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/", samesite="strict")
