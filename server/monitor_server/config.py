from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class HeartbeatConfig:
    warning_after_seconds: int = 30
    offline_after_seconds: int = 60


@dataclass(slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    database_path: Path = Path("data/monitor.db")
    admin_token: str = "dev-admin-token"
    admin_username: str = "admin"
    admin_password: str = "dev-admin-password"
    session_secret: str = "dev-session-secret-change-me"
    session_ttl_hours: int = 12
    agent_tokens: list[str] = field(default_factory=lambda: ["dev-agent-token"])
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)


def _resolve_path(value: str | Path, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return base_dir / path


def _env(name: str, fallback: Any) -> Any:
    value = os.getenv(name)
    return fallback if value is None or value == "" else value


def _env_list(name: str, fallback: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return fallback
    return [item.strip() for item in value.split(",") if item.strip()]


def load_server_config(path: str | None) -> ServerConfig:
    config_path = Path(path).resolve() if path else None
    base_dir = config_path.parent if config_path else Path.cwd()
    raw: dict[str, Any] = {}

    if config_path and config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            raw = yaml.safe_load(file) or {}

    heartbeat_raw = raw.get("heartbeat") or {}
    agent_tokens = [str(item) for item in raw.get("agent_tokens", ["dev-agent-token"])]
    allowed_hosts = [str(item) for item in raw.get("allowed_hosts", ["127.0.0.1", "localhost"])]
    return ServerConfig(
        host=str(_env("MONITOR_HOST", raw.get("host", "127.0.0.1"))),
        port=int(_env("MONITOR_PORT", raw.get("port", 8000))),
        allowed_hosts=_env_list("MONITOR_ALLOWED_HOSTS", allowed_hosts),
        database_path=_resolve_path(
            _env("MONITOR_DATABASE_PATH", raw.get("database_path", "data/monitor.db")),
            base_dir,
        ),
        admin_token=str(_env("MONITOR_ADMIN_TOKEN", raw.get("admin_token", "dev-admin-token"))),
        admin_username=str(_env("MONITOR_ADMIN_USERNAME", raw.get("admin_username", "admin"))),
        admin_password=str(_env("MONITOR_ADMIN_PASSWORD", raw.get("admin_password", "dev-admin-password"))),
        session_secret=str(_env("MONITOR_SESSION_SECRET", raw.get("session_secret", "dev-session-secret-change-me"))),
        session_ttl_hours=int(_env("MONITOR_SESSION_TTL_HOURS", raw.get("session_ttl_hours", 12))),
        agent_tokens=_env_list("MONITOR_AGENT_TOKENS", agent_tokens),
        heartbeat=HeartbeatConfig(
            warning_after_seconds=int(heartbeat_raw.get("warning_after_seconds", 30)),
            offline_after_seconds=int(heartbeat_raw.get("offline_after_seconds", 60)),
        ),
    )
