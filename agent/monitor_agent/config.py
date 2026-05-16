from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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


@dataclass(slots=True)
class AgentConfig:
    server_url: str = "ws://127.0.0.1:8000/agent/ws"
    agent_id: str = "dev-agent"
    agent_name: str = "dev-agent"
    token: str = "dev-agent-token"
    tls_verify: bool = True
    intervals: IntervalConfig = field(default_factory=IntervalConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)


def load_agent_config(path: str | None) -> AgentConfig:
    config_path = Path(path).resolve() if path else None
    raw: dict[str, Any] = {}
    if config_path and config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            raw = yaml.safe_load(file) or {}

    intervals_raw = raw.get("intervals") or {}
    docker_raw = raw.get("docker") or {}
    agent_id = str(raw.get("agent_id", "dev-agent"))

    return AgentConfig(
        server_url=str(raw.get("server_url", "ws://127.0.0.1:8000/agent/ws")),
        agent_id=agent_id,
        agent_name=str(raw.get("agent_name", agent_id)),
        token=str(raw.get("token", "dev-agent-token")),
        tls_verify=bool(raw.get("tls_verify", True)),
        intervals=IntervalConfig(
            heartbeat=int(intervals_raw.get("heartbeat", 10)),
            metrics=int(intervals_raw.get("metrics", 5)),
            docker_stats=int(intervals_raw.get("docker_stats", 5)),
            docker_inventory=int(intervals_raw.get("docker_inventory", 30)),
            host_info=int(intervals_raw.get("host_info", 60)),
        ),
        docker=DockerConfig(enabled=bool(docker_raw.get("enabled", True))),
    )

