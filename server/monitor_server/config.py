from __future__ import annotations

from dataclasses import dataclass, field
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


def load_server_config(path: str | None) -> ServerConfig:
    config_path = Path(path).resolve() if path else None
    base_dir = config_path.parent if config_path else Path.cwd()
    raw: dict[str, Any] = {}

    if config_path and config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            raw = yaml.safe_load(file) or {}

    heartbeat_raw = raw.get("heartbeat") or {}
    return ServerConfig(
        host=str(raw.get("host", "127.0.0.1")),
        port=int(raw.get("port", 8000)),
        database_path=_resolve_path(raw.get("database_path", "data/monitor.db"), base_dir),
        admin_token=str(raw.get("admin_token", "dev-admin-token")),
        admin_username=str(raw.get("admin_username", "admin")),
        admin_password=str(raw.get("admin_password", "dev-admin-password")),
        session_secret=str(raw.get("session_secret", "dev-session-secret-change-me")),
        session_ttl_hours=int(raw.get("session_ttl_hours", 12)),
        agent_tokens=[str(item) for item in raw.get("agent_tokens", ["dev-agent-token"])],
        heartbeat=HeartbeatConfig(
            warning_after_seconds=int(heartbeat_raw.get("warning_after_seconds", 30)),
            offline_after_seconds=int(heartbeat_raw.get("offline_after_seconds", 60)),
        ),
    )
