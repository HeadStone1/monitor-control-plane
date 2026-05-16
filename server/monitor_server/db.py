from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def init(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    hostname TEXT,
                    ip TEXT,
                    os TEXT,
                    arch TEXT,
                    agent_version TEXT,
                    docker_available INTEGER NOT NULL DEFAULT 0,
                    docker_version TEXT,
                    status TEXT NOT NULL DEFAULT 'offline',
                    last_seen TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    load1 REAL,
                    load5 REAL,
                    load15 REAL,
                    net_rx INTEGER,
                    net_tx INTEGER,
                    FOREIGN KEY(node_id) REFERENCES nodes(id)
                );

                CREATE INDEX IF NOT EXISTS idx_metrics_node_time
                    ON metrics(node_id, captured_at DESC);

                CREATE TABLE IF NOT EXISTS containers (
                    node_id TEXT NOT NULL,
                    container_id TEXT NOT NULL,
                    name TEXT,
                    image TEXT,
                    status TEXT,
                    ports_json TEXT,
                    cpu_percent REAL,
                    memory_usage INTEGER,
                    memory_limit INTEGER,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(node_id, container_id),
                    FOREIGN KEY(node_id) REFERENCES nodes(id)
                );

                CREATE TABLE IF NOT EXISTS commands (
                    id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_message TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    sent_at TEXT,
                    finished_at TEXT,
                    FOREIGN KEY(node_id) REFERENCES nodes(id)
                );

                CREATE INDEX IF NOT EXISTS idx_commands_node_time
                    ON commands(node_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    node_id TEXT,
                    result TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ensure_node(self, node_id: str, name: str | None = None) -> None:
        now = utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO nodes (id, name, status, created_at, updated_at)
                VALUES (?, ?, 'online', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = COALESCE(excluded.name, nodes.name),
                    status = 'online',
                    updated_at = excluded.updated_at
                """,
                (node_id, name or node_id, now, now),
            )

    def mark_seen(self, node_id: str) -> None:
        now = utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE nodes
                SET status = 'online', last_seen = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, node_id),
            )

    def update_host_info(self, node_id: str, data: dict[str, Any]) -> None:
        now = utc_now()
        docker = data.get("docker") or {}
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO nodes (
                    id, name, hostname, ip, os, arch, agent_version,
                    docker_available, docker_version, status, last_seen,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    hostname = excluded.hostname,
                    ip = excluded.ip,
                    os = excluded.os,
                    arch = excluded.arch,
                    agent_version = excluded.agent_version,
                    docker_available = excluded.docker_available,
                    docker_version = excluded.docker_version,
                    status = 'online',
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at
                """,
                (
                    node_id,
                    data.get("agent_name") or data.get("hostname") or node_id,
                    data.get("hostname"),
                    data.get("ip"),
                    data.get("os"),
                    data.get("arch"),
                    data.get("agent_version"),
                    1 if docker.get("available") else 0,
                    docker.get("version"),
                    now,
                    now,
                    now,
                ),
            )

    def save_metrics(self, node_id: str, data: dict[str, Any]) -> None:
        captured_at = data.get("captured_at") or utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO metrics (
                    node_id, captured_at, cpu_percent, memory_percent,
                    disk_percent, load1, load5, load15, net_rx, net_tx
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    node_id,
                    captured_at,
                    data.get("cpu_percent"),
                    data.get("memory_percent"),
                    data.get("disk_percent"),
                    data.get("load1"),
                    data.get("load5"),
                    data.get("load15"),
                    data.get("net_rx"),
                    data.get("net_tx"),
                ),
            )

    def replace_inventory(self, node_id: str, containers: list[dict[str, Any]]) -> None:
        now = utc_now()
        seen_ids = [str(item.get("id") or item.get("container_id")) for item in containers if item.get("id") or item.get("container_id")]
        with self._lock, self._conn:
            for item in containers:
                container_id = str(item.get("id") or item.get("container_id") or "")
                if not container_id:
                    continue
                self._conn.execute(
                    """
                    INSERT INTO containers (
                        node_id, container_id, name, image, status,
                        ports_json, cpu_percent, memory_usage, memory_limit, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id, container_id) DO UPDATE SET
                        name = excluded.name,
                        image = excluded.image,
                        status = excluded.status,
                        ports_json = excluded.ports_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        node_id,
                        container_id,
                        item.get("name"),
                        item.get("image"),
                        item.get("status"),
                        json.dumps(item.get("ports") or {}, ensure_ascii=True),
                        item.get("cpu_percent"),
                        item.get("memory_usage"),
                        item.get("memory_limit"),
                        now,
                    ),
                )
            if seen_ids:
                placeholders = ",".join("?" for _ in seen_ids)
                self._conn.execute(
                    f"DELETE FROM containers WHERE node_id = ? AND container_id NOT IN ({placeholders})",
                    [node_id, *seen_ids],
                )
            else:
                self._conn.execute("DELETE FROM containers WHERE node_id = ?", (node_id,))

    def update_container_stats(self, node_id: str, stats: list[dict[str, Any]]) -> None:
        now = utc_now()
        with self._lock, self._conn:
            for item in stats:
                container_id = str(item.get("id") or item.get("container_id") or "")
                if not container_id:
                    continue
                self._conn.execute(
                    """
                    UPDATE containers
                    SET cpu_percent = ?, memory_usage = ?, memory_limit = ?, updated_at = ?
                    WHERE node_id = ? AND container_id = ?
                    """,
                    (
                        item.get("cpu_percent"),
                        item.get("memory_usage"),
                        item.get("memory_limit"),
                        now,
                        node_id,
                        container_id,
                    ),
                )

    def create_command(self, node_id: str, action: str, payload: dict[str, Any], created_by: str) -> dict[str, Any]:
        now = utc_now()
        command_id = f"cmd_{uuid.uuid4().hex}"
        payload_json = json.dumps(payload, ensure_ascii=True)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO commands (
                    id, node_id, action, payload_json, status,
                    created_by, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (command_id, node_id, action, payload_json, created_by, now, now),
            )
        return self.get_command(command_id)

    def mark_command_sent(self, command_id: str) -> None:
        now = utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE commands
                SET status = 'sent', sent_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, command_id),
            )

    def mark_command_result(self, command_id: str, status: str, message: str | None) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE commands
                SET status = ?, result_message = ?, finished_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, message, now, now, command_id),
            )
        return self.get_command(command_id)

    def get_command(self, command_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM commands WHERE id = ?", (command_id,)).fetchone()
        if not row:
            return None
        item = _row_to_dict(row)
        item["payload"] = _loads(item.pop("payload_json"), {})
        return item

    def add_audit_log(
        self,
        user: str,
        action: str,
        target: str | None,
        node_id: str | None,
        result: str | None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_logs (user, action, target, node_id, result, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user, action, target, node_id, result, utc_now()),
            )

    def list_nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    n.*,
                    m.cpu_percent AS latest_cpu_percent,
                    m.memory_percent AS latest_memory_percent,
                    m.disk_percent AS latest_disk_percent,
                    m.captured_at AS latest_metric_at
                FROM nodes n
                LEFT JOIN metrics m
                    ON m.id = (
                        SELECT id FROM metrics
                        WHERE node_id = n.id
                        ORDER BY captured_at DESC
                        LIMIT 1
                    )
                ORDER BY n.updated_at DESC
                """
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_metrics(self, node_id: str, limit: int = 120) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM (
                    SELECT * FROM metrics
                    WHERE node_id = ?
                    ORDER BY captured_at DESC
                    LIMIT ?
                )
                ORDER BY captured_at ASC
                """,
                (node_id, limit),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_containers(self, node_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM containers"
        params: list[Any] = []
        if node_id:
            sql += " WHERE node_id = ?"
            params.append(node_id)
        sql += " ORDER BY updated_at DESC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        items = []
        for row in rows:
            item = _row_to_dict(row)
            item["ports"] = _loads(item.pop("ports_json"), {})
            items.append(item)
        return items

    def list_commands(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM commands ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        items = []
        for row in rows:
            item = _row_to_dict(row)
            item["payload"] = _loads(item.pop("payload_json"), {})
            items.append(item)
        return items

    def list_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def update_stale_node_statuses(self, warning_after_seconds: int, offline_after_seconds: int) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        changed: list[dict[str, Any]] = []
        with self._lock, self._conn:
            rows = self._conn.execute("SELECT id, status, last_seen FROM nodes").fetchall()
            for row in rows:
                last_seen = row["last_seen"]
                if not last_seen:
                    continue
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen)
                except ValueError:
                    continue
                age = (now - last_seen_dt).total_seconds()
                next_status = "online"
                if age > offline_after_seconds:
                    next_status = "offline"
                elif age > warning_after_seconds:
                    next_status = "warning"
                if next_status != row["status"]:
                    self._conn.execute(
                        "UPDATE nodes SET status = ?, updated_at = ? WHERE id = ?",
                        (next_status, utc_now(), row["id"]),
                    )
                    changed.append({"node_id": row["id"], "status": next_status})
        return changed
