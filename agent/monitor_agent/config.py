from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import stat
from typing import Any

import yaml


LOGGER = logging.getLogger("monitor.agent.config")


@dataclass(slots=True)
class IntervalConfig:
    heartbeat: int = 10
    metrics: int = 5
    docker_stats: int = 5
    docker_inventory: int = 30
    host_info: int = 60


@dataclass(slots=True)
class DockerConfig:
    enabled: bool = True
    api_timeout_seconds: int = 10
    collection_timeout_seconds: int = 15
    collection_workers: int = 3
    allowed_labels: dict[str, str] = field(default_factory=lambda: {"monitor.control-plane.allow": "true"})


@dataclass(slots=True)
class ReconnectConfig:
    initial_seconds: int = 1
    max_seconds: int = 30
    stable_reset_seconds: int = 60
    jitter_percent: int = 20
    auth_timeout_seconds: int = 5


@dataclass(slots=True)
class AgentConfig:
    server_url: str = "ws://127.0.0.1:8000/agent/ws"
    agent_id: str = "dev-agent"
    agent_name: str = "dev-agent"
    token: str = "dev-agent-token"
    tls_verify: bool = True
    allow_insecure_transport: bool = False
    intervals: IntervalConfig = field(default_factory=IntervalConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)
    reconnect: ReconnectConfig = field(default_factory=ReconnectConfig)


def _load_reconnect_config(raw: dict[str, Any]) -> ReconnectConfig:
    reconnect = ReconnectConfig(
        initial_seconds=_bounded_int(raw.get("initial_seconds"), 1, 1, 60),
        max_seconds=_bounded_int(raw.get("max_seconds"), 30, 1, 600),
        stable_reset_seconds=_bounded_int(raw.get("stable_reset_seconds"), 60, 1, 3600),
        jitter_percent=_bounded_int(raw.get("jitter_percent"), 20, 0, 50),
        auth_timeout_seconds=_bounded_int(raw.get("auth_timeout_seconds"), 5, 1, 60),
    )
    if reconnect.max_seconds < reconnect.initial_seconds:
        raise ValueError("reconnect.max_seconds must be greater than or equal to reconnect.initial_seconds")
    return reconnect


def load_agent_config(path: str | None) -> AgentConfig:
    config_path = Path(path).resolve() if path else None
    raw: dict[str, Any] = {}
    if config_path and config_path.exists():
        _check_config_permissions(config_path)
        with config_path.open("r", encoding="utf-8") as file:
            raw = yaml.safe_load(file) or {}

    intervals_raw = raw.get("intervals") or {}
    docker_raw = raw.get("docker") or {}
    reconnect_raw = raw.get("reconnect") or {}
    agent_id = str(raw.get("agent_id", "dev-agent"))

    return AgentConfig(
        server_url=str(raw.get("server_url", "ws://127.0.0.1:8000/agent/ws")),
        agent_id=agent_id,
        agent_name=str(raw.get("agent_name", agent_id)),
        token=str(raw.get("token", "dev-agent-token")),
        tls_verify=bool(raw.get("tls_verify", True)),
        allow_insecure_transport=bool(raw.get("allow_insecure_transport", False)),
        intervals=IntervalConfig(
            heartbeat=int(intervals_raw.get("heartbeat", 10)),
            metrics=int(intervals_raw.get("metrics", 5)),
            docker_stats=int(intervals_raw.get("docker_stats", 5)),
            docker_inventory=int(intervals_raw.get("docker_inventory", 30)),
            host_info=int(intervals_raw.get("host_info", 60)),
        ),
        docker=DockerConfig(
            enabled=bool(docker_raw.get("enabled", True)),
            api_timeout_seconds=_bounded_int(docker_raw.get("api_timeout_seconds"), 10, 1, 120),
            collection_timeout_seconds=_bounded_int(
                docker_raw.get("collection_timeout_seconds"), 15, 1, 300
            ),
            collection_workers=_bounded_int(docker_raw.get("collection_workers"), 3, 1, 8),
            allowed_labels={
                str(key): str(value)
                for key, value in (docker_raw.get("allowed_labels") or {"monitor.control-plane.allow": "true"}).items()
            },
        ),
        reconnect=_load_reconnect_config(reconnect_raw),
    )


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"expected an integer between {minimum} and {maximum}") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"expected an integer between {minimum} and {maximum}")
    return parsed


def _check_config_permissions(config_path: Path) -> None:
    if os.name == "nt":
        parts = {part.lower() for part in config_path.parts}
        if "public" in parts:
            LOGGER.warning("agent config is in a public path; keep token-bearing config files private")
        return

    mode = stat.S_IMODE(config_path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError("agent config is readable or writable by group/others; run chmod 600 agent.yaml")
