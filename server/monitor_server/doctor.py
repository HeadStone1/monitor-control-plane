from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .config import DEV_ADMIN_PASSWORD_HASH, DEV_AGENT_TOKEN_HASH, ServerConfig
from .security import is_secret_hash


DoctorCheck = dict[str, str]


def run_config_doctor(config: ServerConfig) -> dict[str, Any]:
    checks: list[DoctorCheck] = []

    _check_admin_auth(config, checks)
    _check_users(config, checks)
    _check_agents(config, checks)
    _check_roles(config, checks)
    _check_session(config, checks)
    _check_production_security(config, checks)
    _check_database_path(config, checks)

    if any(check["status"] == "error" for check in checks):
        status = "error"
    elif any(check["status"] == "warning" for check in checks):
        status = "warning"
    else:
        status = "ok"

    return {"status": status, "checks": checks}


def format_doctor_report(report: dict[str, Any]) -> str:
    lines = [f"Config doctor: {report.get('status', 'unknown')}"]
    for check in report.get("checks", []):
        lines.append(f"[{check['status']}] {check['name']}: {check['message']}")
    return "\n".join(lines)


def _add(checks: list[DoctorCheck], name: str, status: str, message: str) -> None:
    checks.append({"name": name, "status": status, "message": message})


def _check_admin_auth(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    if not config.admin_password_hash:
        _add(checks, "admin_password_hash", "error", "admin password hash is required")
        return
    if not is_secret_hash(config.admin_password_hash):
        _add(checks, "admin_password_hash", "error", "admin password hash is not a valid Argon2id hash")
        return
    if config.admin_password_hash == DEV_ADMIN_PASSWORD_HASH:
        _add(checks, "admin_password_hash", "warning", "development default admin password hash is configured")
        return
    _add(checks, "admin_password_hash", "ok", "admin password hash is configured")


def _check_users(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    enabled_users = [user for user in config.users if user.enabled]
    if not enabled_users:
        if config.admin_username and is_secret_hash(config.admin_password_hash):
            _add(checks, "users", "ok", "fallback admin user is configured")
            return
        _add(checks, "users", "error", "at least one enabled user is required")
        return
    invalid = [user.username for user in enabled_users if not is_secret_hash(user.password_hash)]
    if invalid:
        _add(checks, "users", "error", f"users with invalid password hashes: {', '.join(invalid)}")
        return
    _add(checks, "users", "ok", f"{len(enabled_users)} enabled user(s)")


def _check_agents(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    enabled_agents = [agent for agent in config.agents if agent.enabled]
    if not enabled_agents:
        _add(checks, "agents", "warning", "no enabled agents are configured")
        return
    invalid = [agent.node_id for agent in enabled_agents if not is_secret_hash(agent.token_hash)]
    if invalid:
        _add(checks, "agents", "error", f"agents with invalid token hashes: {', '.join(invalid)}")
        return
    if any(agent.token_hash == DEV_AGENT_TOKEN_HASH for agent in enabled_agents):
        _add(checks, "agents", "warning", "development default agent token hash is configured")
        return
    _add(checks, "agents", "ok", f"{len(enabled_agents)} enabled agent credential(s)")


def _check_roles(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    if "*" not in config.roles.get("admin", []):
        _add(checks, "roles", "error", "admin role must include '*'")
        return
    missing_roles = sorted({user.role for user in config.users if user.enabled and user.role not in config.roles})
    if missing_roles:
        _add(checks, "roles", "error", f"enabled users reference missing roles: {', '.join(missing_roles)}")
        return
    _add(checks, "roles", "ok", f"{len(config.roles)} role(s) configured")


def _check_session(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    if len(config.session_secret) < 24:
        _add(checks, "session_secret", "error", "session secret must be at least 24 characters")
        return
    if config.session_secret == "dev-session-secret-change-me" or "change-me" in config.session_secret.lower():
        _add(checks, "session_secret", "warning", "development default session secret is configured")
        return
    _add(checks, "session_secret", "ok", "session secret length is acceptable")


def _check_production_security(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    if config.environment.lower() != "production":
        _add(checks, "environment", "ok", f"environment is {config.environment}")
        return
    if config.admin_token:
        _add(checks, "production_admin_token", "error", "admin_token is disabled in production")
    else:
        _add(checks, "production_admin_token", "ok", "static admin token is disabled")
    if not config.secure_cookies:
        _add(checks, "production_secure_cookies", "error", "secure_cookies must be true in production")
    else:
        _add(checks, "production_secure_cookies", "ok", "secure cookies are enabled")
    if not config.require_secure_transport:
        _add(checks, "production_secure_transport", "error", "require_secure_transport must be true in production")
    else:
        _add(checks, "production_secure_transport", "ok", "secure transport is required")


def _check_database_path(config: ServerConfig, checks: list[DoctorCheck]) -> None:
    parent = _nearest_existing_parent(config.database_path)
    if parent is None:
        _add(checks, "database_path", "error", f"no existing parent directory for {config.database_path}")
        return
    if not os.access(parent, os.W_OK):
        _add(checks, "database_path", "error", f"database parent is not writable: {parent}")
        return
    _add(checks, "database_path", "ok", f"database parent is writable: {parent}")


def _nearest_existing_parent(path: Path) -> Path | None:
    current = path.parent
    while current != current.parent:
        if current.exists():
            return current
        current = current.parent
    return current if current.exists() else None
