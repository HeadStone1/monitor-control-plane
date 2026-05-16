from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi import HTTPException, Request, status

from .config import ServerConfig


TOKEN_PREFIX = "monitor"


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


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

    username = verify_admin_token(config, token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired admin token",
        )
    return username
