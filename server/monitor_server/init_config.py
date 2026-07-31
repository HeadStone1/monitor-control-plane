from __future__ import annotations

from dataclasses import dataclass
from getpass import getpass
import os
from pathlib import Path
import secrets

import yaml

from .security import hash_secret


@dataclass(slots=True)
class InitConfigResult:
    server_config_path: Path
    agent_config_path: Path
    admin_username: str
    agent_id: str
    server_url: str


def build_init_config_payloads(
    *,
    admin_username: str,
    admin_password: str,
    agent_id: str,
    agent_name: str | None = None,
    agent_token: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
    database_path: str = "data/monitor.db",
    environment: str = "development",
) -> tuple[dict[str, object], dict[str, object], str]:
    admin_username = admin_username.strip() or "admin"
    agent_id = agent_id.strip() or "dev-agent"
    agent_name = (agent_name or agent_id).strip() or agent_id
    agent_token = agent_token or secrets.token_urlsafe(32)
    session_secret = secrets.token_urlsafe(48)

    admin_hash = hash_secret(admin_password)
    agent_hash = hash_secret(agent_token)
    server_url = f"ws://{host}:{port}/agent/ws"

    server_payload: dict[str, object] = {
        "host": host,
        "port": port,
        "environment": environment,
        "allowed_hosts": ["127.0.0.1", "localhost"],
        "database_path": database_path,
        "secure_cookies": False,
        "trust_proxy_headers": False,
        "require_secure_transport": False,
        "admin_token": "",
        "admin_username": admin_username,
        "admin_password_hash": admin_hash,
        "session_secret": session_secret,
        "session_ttl_hours": 12,
        "users": [
            {
                "username": admin_username,
                "password_hash": admin_hash,
                "role": "admin",
                "enabled": True,
            }
        ],
        "roles": {
            "viewer": ["nodes:read", "containers:read", "metrics:read", "commands:read", "audit:read"],
            "operator": [
                "nodes:read",
                "containers:read",
                "metrics:read",
                "commands:read",
                "commands:create",
                "audit:read",
            ],
            "admin": ["*"],
        },
        "api_tokens": [],
        "agents": [
            {
                "node_id": agent_id,
                "name": agent_name,
                "token_id": "initial-token",
                "token_hash": agent_hash,
                "enabled": True,
            }
        ],
        "auth_rate_limit": {
            "window_seconds": 60,
            "login_max_failures": 8,
            "ws_max_failures": 20,
        },
        "agent_payload_limits": {
            "max_containers": 1000,
            "max_result_message_bytes": 4096,
            "max_string_length": 256,
            "max_ports_entries": 64,
        },
        "command": {"timeout_seconds": 60},
        "retention": {
            "raw_metrics_days": 7,
            "hourly_rollup_days": 90,
            "daily_rollup_days": 365,
            "rollup_interval_seconds": 3600,
        },
        "heartbeat": {
            "warning_after_seconds": 30,
            "offline_after_seconds": 60,
        },
    }

    agent_payload: dict[str, object] = {
        "server_url": server_url,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "token": agent_token,
        "tls_verify": True,
        "allow_insecure_transport": False,
        "intervals": {
            "heartbeat": 10,
            "metrics": 5,
            "docker_stats": 5,
            "docker_inventory": 30,
            "host_info": 60,
        },
        "docker": {
            "enabled": True,
            "allowed_labels": {
                "monitor.control-plane.allow": "true",
            },
        },
    }
    return server_payload, agent_payload, agent_token


def write_init_config_files(
    *,
    server_config_path: str | Path,
    agent_config_path: str | Path,
    admin_username: str,
    admin_password: str,
    agent_id: str,
    agent_name: str | None = None,
    agent_token: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
    overwrite: bool = False,
) -> InitConfigResult:
    if not admin_password:
        raise ValueError("admin password is required")

    server_path = Path(server_config_path)
    agent_path = Path(agent_config_path)
    existing = [path for path in (server_path, agent_path) if path.exists()]
    if existing and not overwrite:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(f"refusing to overwrite existing config file(s): {names}")

    server_payload, agent_payload, _agent_token = build_init_config_payloads(
        admin_username=admin_username,
        admin_password=admin_password,
        agent_id=agent_id,
        agent_name=agent_name,
        agent_token=agent_token,
        host=host,
        port=port,
    )

    _write_yaml(server_path, server_payload)
    _write_yaml(agent_path, agent_payload)
    _restrict_permissions(agent_path)

    return InitConfigResult(
        server_config_path=server_path,
        agent_config_path=agent_path,
        admin_username=str(server_payload["admin_username"]),
        agent_id=str(agent_payload["agent_id"]),
        server_url=str(agent_payload["server_url"]),
    )


def run_init_config(args: object) -> None:
    server_path = Path(str(getattr(args, "config", "server.yaml")))
    agent_path = Path(str(getattr(args, "agent_config", "agent.yaml")))
    admin_username = str(getattr(args, "admin_username", "admin") or "admin")
    agent_id = str(getattr(args, "agent_id", "dev-agent") or "dev-agent")
    agent_name = str(getattr(args, "agent_name", "") or agent_id)
    host = str(getattr(args, "host", "") or "127.0.0.1")
    port = int(getattr(args, "port", 0) or 8000)
    overwrite = bool(getattr(args, "force", False))

    admin_password = getpass("Admin password: ")
    confirm_password = getpass("Confirm admin password: ")
    if admin_password != confirm_password:
        raise SystemExit("Admin passwords did not match.")
    agent_token = secrets.token_urlsafe(32)

    try:
        result = write_init_config_files(
            server_config_path=server_path,
            agent_config_path=agent_path,
            admin_username=admin_username,
            admin_password=admin_password,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_token=agent_token,
            host=host,
            port=port,
            overwrite=overwrite,
        )
    except (FileExistsError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    print("Initialized Monitor config.")
    print(f"  Server config: {result.server_config_path}")
    print(f"  Agent config:  {result.agent_config_path}")
    print(f"  WebUI:         http://{host}:{port}")
    print(f"  Agent URL:     {result.server_url}")
    print(f"  Admin user:    {result.admin_username}")
    print(f"  Agent ID:      {result.agent_id}")
    print("The generated Agent token is stored in the agent config file; keep it private.")


def _write_yaml(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _restrict_permissions(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(0o600)
    except OSError:
        pass
