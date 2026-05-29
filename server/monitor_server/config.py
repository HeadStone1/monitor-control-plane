from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any

import yaml


ARGON2_HASH_PREFIX = "$argon2id$"
DEV_ADMIN_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=2$i2Ya6cFy/RyasiIt5G0rYg$"
    "SXc3BGbPeBlcXe7hhqBuAg9AG3FgPvgnJBb4l5dHWP8"
)
DEV_AGENT_TOKEN_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=2$fzC/vKa3DtBEDACUlhKrvg$"
    "3zGHBTY1zqdy7xCDWP61nGuckSvrqfBOSVwt/RIRdy4"
)


@dataclass(slots=True)
class HeartbeatConfig:
    warning_after_seconds: int = 30
    offline_after_seconds: int = 60


@dataclass(slots=True)
class AgentCredential:
    node_id: str
    name: str
    token_hash: str = ""
    token_id: str = ""
    created_at: str = ""
    enabled: bool = True


@dataclass(slots=True)
class ApiTokenConfig:
    name: str
    token_hash: str
    scopes: list[str]
    expires_at: str = ""
    enabled: bool = True


@dataclass(slots=True)
class UserConfig:
    username: str
    password_hash: str = ""
    role: str = "viewer"
    enabled: bool = True


@dataclass(slots=True)
class AuthRateLimitConfig:
    window_seconds: int = 60
    login_max_failures: int = 8
    ws_max_failures: int = 20


@dataclass(slots=True)
class AgentPayloadLimitConfig:
    max_containers: int = 1000
    max_result_message_bytes: int = 4096
    max_string_length: int = 256
    max_ports_entries: int = 64


@dataclass(slots=True)
class CommandConfig:
    timeout_seconds: int = 60


@dataclass(slots=True)
class RetentionConfig:
    raw_metrics_days: int = 7
    hourly_rollup_days: int = 90
    daily_rollup_days: int = 365
    rollup_interval_seconds: int = 3600


@dataclass(slots=True)
class ServerConfig:
    config_path: Path | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    environment: str = "development"
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    database_path: Path = Path("data/monitor.db")
    admin_token: str = "dev-admin-token"
    admin_username: str = "admin"
    admin_password_hash: str = DEV_ADMIN_PASSWORD_HASH
    users: list[UserConfig] = field(default_factory=list)
    roles: dict[str, list[str]] = field(
        default_factory=lambda: {
            "viewer": ["nodes:read", "containers:read", "metrics:read", "commands:read", "audit:read"],
            "operator": ["nodes:read", "containers:read", "metrics:read", "commands:read", "commands:create", "audit:read"],
            "admin": ["*"],
        }
    )
    api_tokens: list[ApiTokenConfig] = field(default_factory=list)
    session_secret: str = "dev-session-secret-change-me"
    session_ttl_hours: int = 12
    secure_cookies: bool = False
    trust_proxy_headers: bool = False
    require_secure_transport: bool = False
    agents: list[AgentCredential] = field(
        default_factory=lambda: [
            AgentCredential(
                node_id="dev-agent",
                name="dev-agent",
                token_hash=DEV_AGENT_TOKEN_HASH,
            )
        ]
    )
    auth_rate_limit: AuthRateLimitConfig = field(default_factory=AuthRateLimitConfig)
    agent_payload_limits: AgentPayloadLimitConfig = field(default_factory=AgentPayloadLimitConfig)
    command: CommandConfig = field(default_factory=CommandConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)


def _resolve_path(value: str | Path, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return base_dir / path


def _env(name: str, fallback: Any) -> Any:
    value = os.getenv(name)
    return fallback if value is None or value == "" else value


def _env_bool(name: str, fallback: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return fallback
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, fallback: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return fallback
    return [item.strip() for item in value.split(",") if item.strip()]


def _reject_plaintext_passwords(raw: dict[str, Any]) -> None:
    if str(raw.get("admin_password") or "").strip():
        raise ValueError("Plaintext admin_password is not supported; use admin_password_hash")
    if str(os.getenv("MONITOR_ADMIN_PASSWORD") or "").strip():
        raise ValueError("MONITOR_ADMIN_PASSWORD is not supported; use MONITOR_ADMIN_PASSWORD_HASH")
    if raw.get("agent_tokens"):
        raise ValueError("Plaintext agent_tokens is not supported; use agents[].token_hash")
    if str(os.getenv("MONITOR_AGENT_TOKENS") or "").strip():
        raise ValueError("MONITOR_AGENT_TOKENS is not supported; use agents[].token_hash")

    users_raw = raw.get("users")
    if isinstance(users_raw, list):
        for item in users_raw:
            if isinstance(item, dict) and str(item.get("password") or "").strip():
                raise ValueError("Plaintext users[].password is not supported; use users[].password_hash")

    agents_raw = raw.get("agents")
    if isinstance(agents_raw, list):
        for item in agents_raw:
            if isinstance(item, dict) and str(item.get("token") or "").strip():
                raise ValueError("Plaintext agents[].token is not supported; use agents[].token_hash")


def _require_argon2id_hash(label: str, encoded: str) -> None:
    if encoded and not encoded.startswith(ARGON2_HASH_PREFIX):
        raise ValueError(f"{label} must be an Argon2id hash generated with --hash-secret")


def _load_agents(raw: dict[str, Any]) -> list[AgentCredential]:
    agents_raw = raw.get("agents")
    if isinstance(agents_raw, list) and agents_raw:
        agents: list[AgentCredential] = []
        for item in agents_raw:
            if not isinstance(item, dict):
                continue
            node_id = str(item.get("node_id") or item.get("agent_id") or "").strip()
            if not node_id:
                continue
            token_hash = str(item.get("token_hash") or "")
            _require_argon2id_hash("agents[].token_hash", token_hash)
            agents.append(
                AgentCredential(
                    node_id=node_id,
                    name=str(item.get("name") or item.get("agent_name") or node_id),
                    token_hash=token_hash,
                    token_id=str(item.get("token_id") or item.get("id") or ""),
                    created_at=str(item.get("created_at") or ""),
                    enabled=bool(item.get("enabled", True)),
                )
            )
        if agents:
            return agents

    return [
        AgentCredential(
            node_id="dev-agent",
            name="dev-agent",
            token_hash=DEV_AGENT_TOKEN_HASH,
        )
    ]


def _load_users(raw: dict[str, Any], admin_username: str, admin_password_hash: str) -> list[UserConfig]:
    users_raw = raw.get("users")
    if isinstance(users_raw, list) and users_raw:
        users: list[UserConfig] = []
        for item in users_raw:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username") or "").strip()
            if not username:
                continue
            password_hash = str(item.get("password_hash") or "")
            _require_argon2id_hash("users[].password_hash", password_hash)
            users.append(
                UserConfig(
                    username=username,
                    password_hash=password_hash,
                    role=str(item.get("role") or "viewer"),
                    enabled=bool(item.get("enabled", True)),
                )
            )
        if users:
            return users

    return [
        UserConfig(
            username=admin_username,
            password_hash=admin_password_hash,
            role="admin",
        )
    ]


def _load_roles(raw: dict[str, Any]) -> dict[str, list[str]]:
    default_roles = {
        "viewer": ["nodes:read", "containers:read", "metrics:read", "commands:read", "audit:read"],
        "operator": ["nodes:read", "containers:read", "metrics:read", "commands:read", "commands:create", "audit:read"],
        "admin": ["*"],
    }
    roles_raw = raw.get("roles")
    if not isinstance(roles_raw, dict):
        return default_roles
    roles = default_roles.copy()
    for name, scopes in roles_raw.items():
        if isinstance(scopes, list):
            roles[str(name)] = [str(scope) for scope in scopes]
    return roles


def _load_api_tokens(raw: dict[str, Any]) -> list[ApiTokenConfig]:
    tokens_raw = raw.get("api_tokens")
    if not isinstance(tokens_raw, list):
        return []
    tokens: list[ApiTokenConfig] = []
    for item in tokens_raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        token_hash = str(item.get("token_hash") or "")
        scopes_raw = item.get("scopes") or []
        if not name or not token_hash or not isinstance(scopes_raw, list):
            continue
        _require_argon2id_hash("api_tokens[].token_hash", token_hash)
        tokens.append(
            ApiTokenConfig(
                name=name,
                token_hash=token_hash,
                scopes=[str(scope) for scope in scopes_raw],
                expires_at=str(item.get("expires_at") or ""),
                enabled=bool(item.get("enabled", True)),
            )
        )
    return tokens


def load_server_config(path: str | None) -> ServerConfig:
    config_path = Path(path).resolve() if path else None
    base_dir = config_path.parent if config_path else Path.cwd()
    raw: dict[str, Any] = {}

    if config_path and config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            raw = yaml.safe_load(file) or {}

    _reject_plaintext_passwords(raw)

    heartbeat_raw = raw.get("heartbeat") or {}
    rate_limit_raw = raw.get("auth_rate_limit") or {}
    payload_limit_raw = raw.get("agent_payload_limits") or {}
    command_raw = raw.get("command") or {}
    retention_raw = raw.get("retention") or {}
    admin_password_hash_default = raw.get("admin_password_hash")
    if admin_password_hash_default is None:
        admin_password_hash_default = "" if "users" in raw else DEV_ADMIN_PASSWORD_HASH
    allowed_hosts = [str(item) for item in raw.get("allowed_hosts", ["127.0.0.1", "localhost"])]
    admin_username = str(_env("MONITOR_ADMIN_USERNAME", raw.get("admin_username", "admin")))
    admin_password_hash = str(_env("MONITOR_ADMIN_PASSWORD_HASH", admin_password_hash_default))
    _require_argon2id_hash("admin_password_hash", admin_password_hash)
    return ServerConfig(
        config_path=config_path,
        host=str(_env("MONITOR_HOST", raw.get("host", "127.0.0.1"))),
        port=int(_env("MONITOR_PORT", raw.get("port", 8000))),
        environment=str(_env("MONITOR_ENV", raw.get("environment", "development"))),
        allowed_hosts=_env_list("MONITOR_ALLOWED_HOSTS", allowed_hosts),
        database_path=_resolve_path(
            _env("MONITOR_DATABASE_PATH", raw.get("database_path", "data/monitor.db")),
            base_dir,
        ),
        admin_token=str(_env("MONITOR_ADMIN_TOKEN", raw.get("admin_token", "dev-admin-token"))),
        admin_username=admin_username,
        admin_password_hash=admin_password_hash,
        users=_load_users(raw, admin_username, admin_password_hash),
        roles=_load_roles(raw),
        api_tokens=_load_api_tokens(raw),
        session_secret=str(_env("MONITOR_SESSION_SECRET", raw.get("session_secret", "dev-session-secret-change-me"))),
        session_ttl_hours=int(_env("MONITOR_SESSION_TTL_HOURS", raw.get("session_ttl_hours", 12))),
        secure_cookies=_env_bool("MONITOR_SECURE_COOKIES", bool(raw.get("secure_cookies", False))),
        trust_proxy_headers=_env_bool("MONITOR_TRUST_PROXY_HEADERS", bool(raw.get("trust_proxy_headers", False))),
        require_secure_transport=_env_bool(
            "MONITOR_REQUIRE_SECURE_TRANSPORT",
            bool(raw.get("require_secure_transport", False)),
        ),
        agents=_load_agents(raw),
        auth_rate_limit=AuthRateLimitConfig(
            window_seconds=int(rate_limit_raw.get("window_seconds", 60)),
            login_max_failures=int(rate_limit_raw.get("login_max_failures", 8)),
            ws_max_failures=int(rate_limit_raw.get("ws_max_failures", 20)),
        ),
        agent_payload_limits=AgentPayloadLimitConfig(
            max_containers=int(payload_limit_raw.get("max_containers", 1000)),
            max_result_message_bytes=int(payload_limit_raw.get("max_result_message_bytes", 4096)),
            max_string_length=int(payload_limit_raw.get("max_string_length", 256)),
            max_ports_entries=int(payload_limit_raw.get("max_ports_entries", 64)),
        ),
        command=CommandConfig(timeout_seconds=int(command_raw.get("timeout_seconds", 60))),
        retention=RetentionConfig(
            raw_metrics_days=int(retention_raw.get("raw_metrics_days", 7)),
            hourly_rollup_days=int(retention_raw.get("hourly_rollup_days", 90)),
            daily_rollup_days=int(retention_raw.get("daily_rollup_days", 365)),
            rollup_interval_seconds=int(retention_raw.get("rollup_interval_seconds", 3600)),
        ),
        heartbeat=HeartbeatConfig(
            warning_after_seconds=int(heartbeat_raw.get("warning_after_seconds", 30)),
            offline_after_seconds=int(heartbeat_raw.get("offline_after_seconds", 60)),
        ),
    )
