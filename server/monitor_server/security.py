from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi import HTTPException, Request, Response, status

from .config import AgentCredential, ServerConfig


TOKEN_PREFIX = "monitor"
SESSION_COOKIE_NAME = "monitor_session"
SECRET_HASH_PREFIX = "pbkdf2_sha256"
DEFAULT_SECRET_HASH_ITERATIONS = 310_000


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_secret(secret: str, *, iterations: int = DEFAULT_SECRET_HASH_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iterations)
    return f"{SECRET_HASH_PREFIX}${iterations}${_b64encode(salt)}${_b64encode(digest)}"


def is_secret_hash(encoded: str) -> bool:
    parts = encoded.split("$")
    if len(parts) != 4 or parts[0] != SECRET_HASH_PREFIX:
        return False
    try:
        int(parts[1])
        _b64decode(parts[2])
        _b64decode(parts[3])
    except (ValueError, TypeError):
        return False
    return True


def verify_secret(secret: str, encoded: str) -> bool:
    if not is_secret_hash(encoded):
        return False
    parts = encoded.split("$")
    try:
        iterations = int(parts[1])
        salt = _b64decode(parts[2])
        expected = _b64decode(parts[3])
    except (ValueError, TypeError):
        return False

    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def extract_bearer_token(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return value.strip()


def create_session_token(config: ServerConfig, username: str) -> tuple[str, int]:
    expires_at = int(time.time() + config.session_ttl_hours * 3600)
    payload = {
        "sub": username,
        "exp": expires_at,
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _sign(config, body)
    return f"{TOKEN_PREFIX}.{body}.{signature}", expires_at


def verify_admin_password(config: ServerConfig, username: str, password: str) -> bool:
    if not hmac.compare_digest(username, config.admin_username):
        return False
    if config.admin_password_hash:
        return verify_secret(password, config.admin_password_hash)
    if config.admin_password:
        return hmac.compare_digest(password, config.admin_password)
    return False


def verify_agent_credentials(config: ServerConfig, node_id: str, token: str) -> AgentCredential | None:
    if not node_id or not token:
        return None

    for agent in config.agents:
        if not agent.enabled or not hmac.compare_digest(node_id, agent.node_id):
            continue
        if agent.token_hash and verify_secret(token, agent.token_hash):
            return agent
        if agent.token and hmac.compare_digest(token, agent.token):
            return agent
    return None


def verify_admin_token(config: ServerConfig, token: str | None) -> str | None:
    if not token:
        return None

    if hmac.compare_digest(token, config.admin_token):
        return config.admin_username

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

    if int(payload.get("exp", 0)) < int(time.time()):
        return None

    username = payload.get("sub")
    if not isinstance(username, str) or not username:
        return None
    return username


def _sign(config: ServerConfig, body: str) -> str:
    digest = hmac.new(
        config.session_secret.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64encode(digest)


def require_admin_token(request: Request) -> str:
    config: ServerConfig = request.app.state.config
    token = extract_bearer_token(request.headers.get("authorization"))
    token = token or request.headers.get("x-admin-token")
    token = token or request.cookies.get(SESSION_COOKIE_NAME)

    username = verify_admin_token(config, token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired admin token",
        )
    return username


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
