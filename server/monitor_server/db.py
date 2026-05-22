from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
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


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bucket_start(value: datetime, bucket: str) -> datetime:
    if bucket == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    return value.replace(microsecond=0)


def _average(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 2)


def _metric_values(rows: list[dict[str, Any]], key: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(key)
        if value is None:
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return values


def _metric_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sample_count": len(rows),
        "cpu": _series_summary(rows, "cpu_percent"),
        "memory": _series_summary(rows, "memory_percent"),
        "disk": _series_summary(rows, "disk_percent"),
    }


def _series_summary(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    values = _metric_values(rows, key)
    if not values:
        return {"avg": None, "max": None, "peak_at": None}

    peak_value = max(values)
    peak_at = None
    for row in rows:
        try:
            value = float(row.get(key))
        except (TypeError, ValueError):
            continue
        if value == peak_value:
            peak_at = row.get("captured_at")
            break

    return {
        "avg": _average(values),
        "max": round(peak_value, 2),
        "peak_at": peak_at,
    }


def _raw_metric_points(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for row in rows:
        points.append(
            {
                "captured_at": row.get("captured_at"),
                "bucket_start": row.get("captured_at"),
                "bucket_end": row.get("captured_at"),
                "sample_count": 1,
                **_point_metric("cpu", row.get("cpu_percent"), row.get("captured_at")),
                **_point_metric("memory", row.get("memory_percent"), row.get("captured_at")),
                **_point_metric("disk", row.get("disk_percent"), row.get("captured_at")),
                "load1": row.get("load1"),
                "load5": row.get("load5"),
                "load15": row.get("load15"),
                "net_rx": row.get("net_rx"),
                "net_tx": row.get("net_tx"),
            }
        )
    return points


def _point_metric(prefix: str, value: Any, captured_at: Any) -> dict[str, Any]:
    try:
        number = None if value is None else round(float(value), 2)
    except (TypeError, ValueError):
        number = None
    return {
        f"{prefix}_percent": number,
        f"{prefix}_avg": number,
        f"{prefix}_max": number,
        f"{prefix}_peak_at": captured_at if number is not None else None,
    }


def _aggregate_metric_points(rows: list[dict[str, Any]], bucket: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        captured_at = _parse_utc(str(row.get("captured_at") or ""))
        if captured_at is None:
            continue
        bucket_start = _bucket_start(captured_at, bucket)
        grouped.setdefault(bucket_start.isoformat(timespec="seconds"), []).append(row)

    points: list[dict[str, Any]] = []
    for bucket_start, bucket_rows in grouped.items():
        points.append(
            {
                "captured_at": bucket_start,
                "bucket_start": bucket_start,
                "bucket_end": _bucket_end(bucket_start, bucket),
                "sample_count": len(bucket_rows),
                **_aggregate_point_metric("cpu", bucket_rows, "cpu_percent"),
                **_aggregate_point_metric("memory", bucket_rows, "memory_percent"),
                **_aggregate_point_metric("disk", bucket_rows, "disk_percent"),
                "load1": _average(_metric_values(bucket_rows, "load1")),
                "load5": _average(_metric_values(bucket_rows, "load5")),
                "load15": _average(_metric_values(bucket_rows, "load15")),
                "net_rx": _average(_metric_values(bucket_rows, "net_rx")),
                "net_tx": _average(_metric_values(bucket_rows, "net_tx")),
            }
        )
    return points


def _bucket_end(bucket_start: str, bucket: str) -> str:
    start = _parse_utc(bucket_start)
    if start is None:
        return bucket_start
    delta = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    return (start + delta).isoformat(timespec="seconds")


def _aggregate_point_metric(prefix: str, rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    summary = _series_summary(rows, key)
    return {
        f"{prefix}_percent": summary["avg"],
        f"{prefix}_avg": summary["avg"],
        f"{prefix}_max": summary["max"],
        f"{prefix}_peak_at": summary["peak_at"],
    }


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
                    event_type TEXT,
                    actor TEXT,
                    client_ip TEXT,
                    user_agent TEXT,
                    detail_json TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column("audit_logs", "event_type", "TEXT")
            self._ensure_column("audit_logs", "actor", "TEXT")
            self._ensure_column("audit_logs", "client_ip", "TEXT")
            self._ensure_column("audit_logs", "user_agent", "TEXT")
            self._ensure_column("audit_logs", "detail_json", "TEXT")

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        existing = {
            row["name"]
            for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in existing:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

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

    def mark_command_result(
        self,
        command_id: str,
        node_id: str,
        status: str,
        message: str | None,
    ) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                UPDATE commands
                SET status = ?, result_message = ?, finished_at = ?, updated_at = ?
                WHERE id = ? AND node_id = ?
                """,
                (status, message, now, now, command_id, node_id),
            )
            if cursor.rowcount == 0:
                return None
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
                INSERT INTO audit_logs (
                    user, action, target, node_id, result,
                    event_type, actor, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user, action, target, node_id, result, action, user, utc_now()),
            )

    def add_security_event(
        self,
        event_type: str,
        actor: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        node_id: str | None = None,
        target: str | None = None,
        result: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        detail_json = json.dumps(detail or {}, ensure_ascii=True, default=str)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_logs (
                    user, action, target, node_id, result,
                    event_type, actor, client_ip, user_agent, detail_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    actor or "system",
                    event_type,
                    target,
                    node_id,
                    result,
                    event_type,
                    actor,
                    client_ip,
                    user_agent,
                    detail_json,
                    utc_now(),
                ),
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

    def list_metric_series(self, node_id: str, range_name: str = "1h") -> dict[str, Any]:
        config = {
            "1h": {"duration": timedelta(hours=1), "bucket": "raw", "limit": 1000},
            "7d": {"duration": timedelta(days=7), "bucket": "hour", "limit": 200000},
            "30d": {"duration": timedelta(days=30), "bucket": "day", "limit": 750000},
        }.get(range_name)
        if not config:
            range_name = "1h"
            config = {"duration": timedelta(hours=1), "bucket": "raw", "limit": 1000}

        now = datetime.now(timezone.utc)
        start = now - config["duration"]
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT *
                FROM metrics
                WHERE node_id = ? AND captured_at >= ?
                ORDER BY captured_at ASC
                LIMIT ?
                """,
                (node_id, start.isoformat(timespec="seconds"), config["limit"]),
            ).fetchall()

        raw_rows = [_row_to_dict(row) for row in rows]
        parsed_rows = []
        for row in raw_rows:
            captured_at = _parse_utc(row.get("captured_at"))
            if captured_at is None:
                continue
            row["captured_at"] = captured_at.isoformat(timespec="seconds")
            parsed_rows.append(row)

        bucket = str(config["bucket"])
        points = _raw_metric_points(parsed_rows) if bucket == "raw" else _aggregate_metric_points(parsed_rows, bucket)
        return {
            "range": range_name,
            "bucket": bucket,
            "from": start.isoformat(timespec="seconds"),
            "to": now.isoformat(timespec="seconds"),
            "points": points,
            "summary": _metric_summary(parsed_rows),
        }

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

    def container_exists(self, node_id: str, container_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM containers WHERE node_id = ? AND container_id = ? LIMIT 1",
                (node_id, container_id),
            ).fetchone()
        return row is not None

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

    def expire_stale_commands(self, timeout_seconds: int) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=max(0, timeout_seconds))
        expired_ids: list[str] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT id FROM commands
                WHERE status IN ('pending', 'sent') AND created_at <= ?
                """,
                (cutoff.isoformat(timespec="seconds"),),
            ).fetchall()
            expired_ids = [row["id"] for row in rows]
            if expired_ids:
                placeholders = ",".join("?" for _ in expired_ids)
                self._conn.execute(
                    f"""
                    UPDATE commands
                    SET status = 'timeout',
                        result_message = 'agent did not acknowledge in time',
                        finished_at = ?,
                        updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    [utc_now(), utc_now(), *expired_ids],
                )
        return [command for command_id in expired_ids if (command := self.get_command(command_id))]

    def prune_metrics(self, raw_metrics_days: int) -> int:
        if raw_metrics_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=raw_metrics_days)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM metrics WHERE captured_at < ?",
                (cutoff.isoformat(timespec="seconds"),),
            )
            return int(cursor.rowcount or 0)
