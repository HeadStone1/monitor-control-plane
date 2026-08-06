from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


METRIC_RANGE_CONFIG: dict[str, dict[str, Any]] = {
    "1h": {"duration": timedelta(hours=1), "bucket": "raw", "limit": 1000, "table": ""},
    "24h": {"duration": timedelta(hours=24), "bucket": "hour", "limit": 25000, "table": "metrics_hourly"},
    "7d": {"duration": timedelta(days=7), "bucket": "hour", "limit": 200000, "table": "metrics_hourly"},
    "15d": {"duration": timedelta(days=15), "bucket": "hour", "limit": 300000, "table": "metrics_hourly"},
    "30d": {"duration": timedelta(days=30), "bucket": "day", "limit": 750000, "table": "metrics_daily"},
    "60d": {"duration": timedelta(days=60), "bucket": "day", "limit": 750000, "table": "metrics_daily"},
    "90d": {"duration": timedelta(days=90), "bucket": "day", "limit": 750000, "table": "metrics_daily"},
}
SUPPORTED_METRIC_RANGES = frozenset(METRIC_RANGE_CONFIG)


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


def _alert_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = _row_to_dict(row)
    item["detail"] = _loads(item.pop("detail_json", None), {})
    return item


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:
        return None
    return number


def _normalize_thresholds(values: dict[str, Any]) -> dict[str, float | None]:
    normalized: dict[str, float | None] = {}
    for metric in ALERT_METRIC_FIELDS:
        value = values.get(metric)
        if value is None or value == "":
            normalized[metric] = None
            continue
        number = _float_or_none(value)
        if number is None:
            normalized[metric] = None
            continue
        normalized[metric] = max(0.0, min(100.0, number))
    return normalized


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


DEFAULT_THRESHOLDS = {"cpu": 60.0, "memory": 80.0, "disk": 85.0}
ALERT_METRIC_FIELDS = {
    "cpu": "cpu_percent",
    "memory": "memory_percent",
    "disk": "disk_percent",
}


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


def _rollup_metric_points(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for row in rows:
        points.append(
            {
                "captured_at": row.get("bucket_start"),
                "bucket_start": row.get("bucket_start"),
                "bucket_end": row.get("bucket_end"),
                "sample_count": row.get("sample_count") or 0,
                "cpu_percent": row.get("cpu_avg"),
                "cpu_avg": row.get("cpu_avg"),
                "cpu_max": row.get("cpu_max"),
                "cpu_peak_at": row.get("cpu_peak_at"),
                "memory_percent": row.get("memory_avg"),
                "memory_avg": row.get("memory_avg"),
                "memory_max": row.get("memory_max"),
                "memory_peak_at": row.get("memory_peak_at"),
                "disk_percent": row.get("disk_avg"),
                "disk_avg": row.get("disk_avg"),
                "disk_max": row.get("disk_max"),
                "disk_peak_at": row.get("disk_peak_at"),
                "load1": row.get("load1"),
                "load5": row.get("load5"),
                "load15": row.get("load15"),
                "net_rx": row.get("net_rx"),
                "net_tx": row.get("net_tx"),
            }
        )
    return points


def _metric_summary_from_points(points: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sample_count": sum(int(point.get("sample_count") or 0) for point in points),
        "cpu": _point_series_summary(points, "cpu"),
        "memory": _point_series_summary(points, "memory"),
        "disk": _point_series_summary(points, "disk"),
    }


def _point_series_summary(points: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    weighted_total = 0.0
    sample_total = 0
    max_value = None
    peak_at = None
    for point in points:
        avg = _float_or_none(point.get(f"{prefix}_avg"))
        count = int(point.get("sample_count") or 0)
        if avg is not None and count > 0:
            weighted_total += avg * count
            sample_total += count

        peak_value = _float_or_none(point.get(f"{prefix}_max"))
        if peak_value is not None and (max_value is None or peak_value > max_value):
            max_value = peak_value
            peak_at = point.get(f"{prefix}_peak_at")

    return {
        "avg": round(weighted_total / sample_total, 2) if sample_total else None,
        "max": round(max_value, 2) if max_value is not None else None,
        "peak_at": peak_at,
    }


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
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def init(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
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
                    docker_inventory_status TEXT NOT NULL DEFAULT 'unknown',
                    docker_inventory_error TEXT,
                    docker_inventory_last_attempt_at TEXT,
                    docker_inventory_last_success_at TEXT,
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

                CREATE INDEX IF NOT EXISTS idx_metrics_time
                    ON metrics(captured_at);

                CREATE TABLE IF NOT EXISTS metrics_hourly (
                    node_id TEXT NOT NULL,
                    bucket_start TEXT NOT NULL,
                    bucket_end TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    cpu_avg REAL,
                    cpu_max REAL,
                    cpu_peak_at TEXT,
                    memory_avg REAL,
                    memory_max REAL,
                    memory_peak_at TEXT,
                    disk_avg REAL,
                    disk_max REAL,
                    disk_peak_at TEXT,
                    load1 REAL,
                    load5 REAL,
                    load15 REAL,
                    net_rx REAL,
                    net_tx REAL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(node_id, bucket_start),
                    FOREIGN KEY(node_id) REFERENCES nodes(id)
                );

                CREATE TABLE IF NOT EXISTS metrics_daily (
                    node_id TEXT NOT NULL,
                    bucket_start TEXT NOT NULL,
                    bucket_end TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    cpu_avg REAL,
                    cpu_max REAL,
                    cpu_peak_at TEXT,
                    memory_avg REAL,
                    memory_max REAL,
                    memory_peak_at TEXT,
                    disk_avg REAL,
                    disk_max REAL,
                    disk_peak_at TEXT,
                    load1 REAL,
                    load5 REAL,
                    load15 REAL,
                    net_rx REAL,
                    net_tx REAL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(node_id, bucket_start),
                    FOREIGN KEY(node_id) REFERENCES nodes(id)
                );

                CREATE INDEX IF NOT EXISTS idx_metrics_hourly_node_time
                    ON metrics_hourly(node_id, bucket_start DESC);

                CREATE INDEX IF NOT EXISTS idx_metrics_daily_node_time
                    ON metrics_daily(node_id, bucket_start DESC);

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
                    acknowledged_at TEXT,
                    running_at TEXT,
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

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    status TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    value REAL NOT NULL,
                    triggered_at TEXT NOT NULL,
                    resolved_at TEXT,
                    updated_at TEXT NOT NULL,
                    detail_json TEXT,
                    FOREIGN KEY(node_id) REFERENCES nodes(id)
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_node_status_time
                    ON alerts(node_id, status, triggered_at DESC);

                CREATE INDEX IF NOT EXISTS idx_alerts_status_time
                    ON alerts(status, triggered_at DESC);

                CREATE TABLE IF NOT EXISTS agent_token_revocations (
                    node_id TEXT NOT NULL,
                    credential_fingerprint TEXT NOT NULL,
                    token_id TEXT NOT NULL DEFAULT '',
                    revoked_at TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    client_ip TEXT,
                    PRIMARY KEY(node_id, credential_fingerprint)
                );

                CREATE INDEX IF NOT EXISTS idx_agent_token_revocations_node_token
                    ON agent_token_revocations(node_id, token_id);
                """
            )
            self._ensure_column("audit_logs", "event_type", "TEXT")
            self._ensure_column("audit_logs", "actor", "TEXT")
            self._ensure_column("audit_logs", "client_ip", "TEXT")
            self._ensure_column("audit_logs", "user_agent", "TEXT")
            self._ensure_column("audit_logs", "detail_json", "TEXT")
            self._ensure_column("commands", "acknowledged_at", "TEXT")
            self._ensure_column("commands", "running_at", "TEXT")
            self._ensure_column("nodes", "docker_inventory_status", "TEXT NOT NULL DEFAULT 'unknown'")
            self._ensure_column("nodes", "docker_inventory_error", "TEXT")
            self._ensure_column("nodes", "docker_inventory_last_attempt_at", "TEXT")
            self._ensure_column("nodes", "docker_inventory_last_success_at", "TEXT")

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

    def health_summary(self, *, public: bool = False) -> dict[str, Any]:
        with self._lock:
            journal_mode = str(self._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            synchronous = int(self._conn.execute("PRAGMA synchronous").fetchone()[0])
            if public:
                return {
                    "journal_mode": journal_mode,
                    "synchronous": synchronous,
                }

            node_count = int(self._conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0])
            online_nodes = int(
                self._conn.execute("SELECT COUNT(*) FROM nodes WHERE status = 'online'").fetchone()[0]
            )
            metrics_count = int(self._conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0])
            hourly_count = int(self._conn.execute("SELECT COUNT(*) FROM metrics_hourly").fetchone()[0])
            daily_count = int(self._conn.execute("SELECT COUNT(*) FROM metrics_daily").fetchone()[0])
            active_alerts = int(
                self._conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active'").fetchone()[0]
            )
            revoked_agent_tokens = int(
                self._conn.execute("SELECT COUNT(*) FROM agent_token_revocations").fetchone()[0]
            )
            pending_commands = int(
                self._conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM commands
                    WHERE status IN ('pending', 'sent', 'acknowledged', 'running')
                    """
                ).fetchone()[0]
            )

        return {
            "path": str(self.path),
            "journal_mode": journal_mode,
            "synchronous": synchronous,
            "nodes": node_count,
            "online_nodes": online_nodes,
            "raw_metrics": metrics_count,
            "hourly_rollups": hourly_count,
            "daily_rollups": daily_count,
            "active_alerts": active_alerts,
            "revoked_agent_tokens": revoked_agent_tokens,
            "pending_commands": pending_commands,
        }

    def revoke_agent_credentials(
        self,
        node_id: str,
        credentials: list[tuple[str, str]],
        revoked_by: str,
        client_ip: str | None,
    ) -> int:
        unique_credentials = {
            (fingerprint, token_id)
            for fingerprint, token_id in credentials
            if fingerprint
        }
        if not node_id or not unique_credentials:
            return 0
        now = utc_now()
        with self._lock, self._conn:
            for fingerprint, token_id in unique_credentials:
                self._conn.execute(
                    """
                    INSERT INTO agent_token_revocations (
                        node_id, credential_fingerprint, token_id,
                        revoked_at, revoked_by, client_ip
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id, credential_fingerprint) DO UPDATE SET
                        token_id = excluded.token_id,
                        revoked_at = excluded.revoked_at,
                        revoked_by = excluded.revoked_by,
                        client_ip = excluded.client_ip
                    """,
                    (node_id, fingerprint, token_id, now, revoked_by, client_ip),
                )
        return len(unique_credentials)

    def is_agent_credential_revoked(
        self,
        node_id: str,
        credential_fingerprint: str,
        token_id: str = "",
    ) -> bool:
        if not node_id or not credential_fingerprint:
            return False
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1
                FROM agent_token_revocations
                WHERE node_id = ?
                  AND (
                    credential_fingerprint = ?
                    OR (? <> '' AND token_id = ?)
                  )
                LIMIT 1
                """,
                (node_id, credential_fingerprint, token_id, token_id),
            ).fetchone()
        return row is not None

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

    def get_thresholds(self) -> tuple[dict[str, float | None], bool]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value_json FROM settings WHERE key = ?",
                ("thresholds",),
            ).fetchone()
        if not row:
            return DEFAULT_THRESHOLDS.copy(), False
        raw = _loads(row["value_json"], {})
        if not isinstance(raw, dict):
            return DEFAULT_THRESHOLDS.copy(), False
        return _normalize_thresholds(raw), True

    def set_thresholds(self, thresholds: dict[str, Any]) -> dict[str, float | None]:
        normalized = _normalize_thresholds(thresholds)
        now = utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO settings (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                ("thresholds", json.dumps(normalized, ensure_ascii=True), now),
            )
        return normalized

    def evaluate_metric_alerts(
        self,
        node_id: str,
        metrics: dict[str, Any],
        thresholds: dict[str, float | None],
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        now = utc_now()
        normalized = _normalize_thresholds(thresholds)
        with self._lock, self._conn:
            for metric, field in ALERT_METRIC_FIELDS.items():
                threshold = normalized.get(metric)
                if threshold is None:
                    continue
                value = _float_or_none(metrics.get(field))
                if value is None:
                    continue

                active = self._conn.execute(
                    """
                    SELECT * FROM alerts
                    WHERE node_id = ? AND metric = ? AND status = 'active'
                    ORDER BY triggered_at DESC
                    LIMIT 1
                    """,
                    (node_id, metric),
                ).fetchone()

                if value > threshold:
                    if active:
                        self._conn.execute(
                            """
                            UPDATE alerts
                            SET threshold = ?, value = ?, updated_at = ?
                            WHERE id = ?
                            """,
                            (threshold, value, now, active["id"]),
                        )
                        continue
                    alert_id = f"alert_{uuid.uuid4().hex}"
                    detail = {
                        "field": field,
                        "captured_at": metrics.get("captured_at"),
                    }
                    self._conn.execute(
                        """
                        INSERT INTO alerts (
                            id, node_id, metric, status, threshold, value,
                            triggered_at, updated_at, detail_json
                        )
                        VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?)
                        """,
                        (
                            alert_id,
                            node_id,
                            metric,
                            threshold,
                            value,
                            now,
                            now,
                            json.dumps(detail, ensure_ascii=True),
                        ),
                    )
                    alert = self._alert_by_id(alert_id)
                    if alert:
                        events.append({"type": "alert_created", "alert": alert})
                elif active:
                    self._conn.execute(
                        """
                        UPDATE alerts
                        SET status = 'resolved',
                            threshold = ?,
                            value = ?,
                            resolved_at = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (threshold, value, now, now, active["id"]),
                    )
                    alert = self._alert_by_id(active["id"])
                    if alert:
                        events.append({"type": "alert_resolved", "alert": alert})
        return events

    def _alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _alert_row_to_dict(row) if row else None

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
            self._conn.execute(
                """
                UPDATE nodes
                SET docker_inventory_status = 'current',
                    docker_inventory_error = NULL,
                    docker_inventory_last_attempt_at = ?,
                    docker_inventory_last_success_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (now, now, now, node_id),
            )

    def mark_inventory_failed(self, node_id: str, error: str | None) -> None:
        now = utc_now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE nodes
                SET docker_inventory_status = 'stale',
                    docker_inventory_error = ?,
                    docker_inventory_last_attempt_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (error, now, now, node_id),
            )

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

    def mark_command_send_failed(self, command_id: str, message: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                UPDATE commands
                SET status = 'send_failed', result_message = ?, finished_at = ?, updated_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (message, now, now, command_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get_command(command_id)

    def mark_command_acknowledged(self, command_id: str, node_id: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                UPDATE commands
                SET status = 'acknowledged', acknowledged_at = ?, updated_at = ?
                WHERE id = ? AND node_id = ? AND status IN ('pending', 'sent')
                """,
                (now, now, command_id, node_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get_command(command_id)

    def mark_command_running(self, command_id: str, node_id: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                UPDATE commands
                SET status = 'running', running_at = ?, updated_at = ?
                WHERE id = ? AND node_id = ? AND status IN ('pending', 'sent', 'acknowledged')
                """,
                (now, now, command_id, node_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get_command(command_id)

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
                WHERE id = ? AND node_id = ? AND status IN ('pending', 'sent', 'acknowledged', 'running')
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

    def rollup_metrics(self) -> dict[str, int]:
        with self._lock, self._conn:
            hourly, hourly_source_rows = self._rollup_metric_table("metrics_hourly", "hour")
            daily, daily_source_rows = self._rollup_metric_table("metrics_daily", "day")
        return {
            "hourly": hourly,
            "daily": daily,
            "hourly_source_rows": hourly_source_rows,
            "daily_source_rows": daily_source_rows,
        }

    def _rollup_metric_table(self, table: str, bucket: str) -> tuple[int, int]:
        if (table, bucket) not in {("metrics_hourly", "hour"), ("metrics_daily", "day")}:
            raise ValueError("unsupported metric rollup target")

        latest_row = self._conn.execute(f"SELECT MAX(bucket_start) AS value FROM {table}").fetchone()
        latest = _parse_utc(str(latest_row["value"] or "")) if latest_row else None
        if latest is None:
            earliest_row = self._conn.execute("SELECT MIN(captured_at) AS value FROM metrics").fetchone()
            cutoff = str(earliest_row["value"] or "") if earliest_row else ""
            if not cutoff:
                return 0, 0
        else:
            now = datetime.now(timezone.utc)
            latest = min(latest, now)
            lookback = timedelta(hours=2) if bucket == "hour" else timedelta(days=2)
            cutoff = (latest - lookback).isoformat(timespec="seconds")

        source_rows = int(
            self._conn.execute(
                "SELECT COUNT(*) FROM metrics WHERE captured_at >= ? AND datetime(captured_at) IS NOT NULL",
                (cutoff,),
            ).fetchone()[0]
        )
        if source_rows == 0:
            return 0, 0

        bucket_expression = (
            "substr(captured_at, 1, 13) || ':00:00+00:00'"
            if bucket == "hour"
            else "substr(captured_at, 1, 10) || 'T00:00:00+00:00'"
        )
        bucket_modifier = "+1 hour" if bucket == "hour" else "+1 day"
        self._conn.execute(
            f"""
            WITH source AS (
                SELECT
                    node_id, captured_at, cpu_percent, memory_percent, disk_percent,
                    load1, load5, load15, net_rx, net_tx,
                    {bucket_expression} AS bucket_start
                FROM metrics
                WHERE captured_at >= ? AND datetime(captured_at) IS NOT NULL
            ),
            aggregated AS (
                SELECT
                    node_id, bucket_start, COUNT(*) AS sample_count,
                    AVG(cpu_percent) AS cpu_avg, MAX(cpu_percent) AS cpu_max,
                    AVG(memory_percent) AS memory_avg, MAX(memory_percent) AS memory_max,
                    AVG(disk_percent) AS disk_avg, MAX(disk_percent) AS disk_max,
                    AVG(load1) AS load1, AVG(load5) AS load5, AVG(load15) AS load15,
                    AVG(net_rx) AS net_rx, AVG(net_tx) AS net_tx
                FROM source
                GROUP BY node_id, bucket_start
            ),
            peaks AS (
                SELECT DISTINCT
                    node_id,
                    bucket_start,
                    FIRST_VALUE(captured_at) OVER (
                        PARTITION BY node_id, bucket_start
                        ORDER BY (cpu_percent IS NULL), cpu_percent DESC, captured_at ASC
                    ) AS cpu_peak_at,
                    FIRST_VALUE(captured_at) OVER (
                        PARTITION BY node_id, bucket_start
                        ORDER BY (memory_percent IS NULL), memory_percent DESC, captured_at ASC
                    ) AS memory_peak_at,
                    FIRST_VALUE(captured_at) OVER (
                        PARTITION BY node_id, bucket_start
                        ORDER BY (disk_percent IS NULL), disk_percent DESC, captured_at ASC
                    ) AS disk_peak_at
                FROM source
            )
            INSERT INTO {table} (
                node_id, bucket_start, bucket_end, sample_count,
                cpu_avg, cpu_max, cpu_peak_at,
                memory_avg, memory_max, memory_peak_at,
                disk_avg, disk_max, disk_peak_at,
                load1, load5, load15, net_rx, net_tx, updated_at
            )
            SELECT
                aggregated.node_id,
                aggregated.bucket_start,
                strftime('%Y-%m-%dT%H:%M:%S+00:00', datetime(aggregated.bucket_start, '{bucket_modifier}')),
                aggregated.sample_count,
                ROUND(aggregated.cpu_avg, 2), aggregated.cpu_max,
                CASE WHEN aggregated.cpu_max IS NULL THEN NULL ELSE peaks.cpu_peak_at END,
                ROUND(aggregated.memory_avg, 2), aggregated.memory_max,
                CASE WHEN aggregated.memory_max IS NULL THEN NULL ELSE peaks.memory_peak_at END,
                ROUND(aggregated.disk_avg, 2), aggregated.disk_max,
                CASE WHEN aggregated.disk_max IS NULL THEN NULL ELSE peaks.disk_peak_at END,
                ROUND(aggregated.load1, 2), ROUND(aggregated.load5, 2), ROUND(aggregated.load15, 2),
                ROUND(aggregated.net_rx, 2), ROUND(aggregated.net_tx, 2), ?
            FROM aggregated
            JOIN peaks
              ON peaks.node_id = aggregated.node_id
             AND peaks.bucket_start = aggregated.bucket_start
            WHERE 1
            ON CONFLICT(node_id, bucket_start) DO UPDATE SET
                bucket_end = excluded.bucket_end,
                sample_count = excluded.sample_count,
                cpu_avg = excluded.cpu_avg,
                cpu_max = excluded.cpu_max,
                cpu_peak_at = excluded.cpu_peak_at,
                memory_avg = excluded.memory_avg,
                memory_max = excluded.memory_max,
                memory_peak_at = excluded.memory_peak_at,
                disk_avg = excluded.disk_avg,
                disk_max = excluded.disk_max,
                disk_peak_at = excluded.disk_peak_at,
                load1 = excluded.load1,
                load5 = excluded.load5,
                load15 = excluded.load15,
                net_rx = excluded.net_rx,
                net_tx = excluded.net_tx,
                updated_at = excluded.updated_at
            """,
            (cutoff, utc_now()),
        )
        changed = int(self._conn.execute("SELECT changes()").fetchone()[0])
        return changed, source_rows

    def list_metric_series(self, node_id: str, range_name: str = "1h") -> dict[str, Any]:
        config = METRIC_RANGE_CONFIG.get(range_name)
        if not config:
            range_name = "1h"
            config = METRIC_RANGE_CONFIG[range_name]

        now = datetime.now(timezone.utc)
        start = now - config["duration"]
        bucket = str(config["bucket"])
        table = str(config["table"])
        if table:
            rollup_payload = self._list_rollup_metric_series(node_id, range_name, bucket, table, start, now)
            if rollup_payload is not None:
                return rollup_payload

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

        points = _raw_metric_points(parsed_rows) if bucket == "raw" else _aggregate_metric_points(parsed_rows, bucket)
        return {
            "range": range_name,
            "bucket": bucket,
            "source": "raw",
            "from": start.isoformat(timespec="seconds"),
            "to": now.isoformat(timespec="seconds"),
            "points": points,
            "summary": _metric_summary(parsed_rows),
        }

    def _list_rollup_metric_series(
        self,
        node_id: str,
        range_name: str,
        bucket: str,
        table: str,
        start: datetime,
        now: datetime,
    ) -> dict[str, Any] | None:
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT *
                FROM {table}
                WHERE node_id = ? AND bucket_start >= ?
                ORDER BY bucket_start ASC
                """,
                (node_id, start.isoformat(timespec="seconds")),
            ).fetchall()
        if not rows:
            return None
        points = _rollup_metric_points([_row_to_dict(row) for row in rows])
        return {
            "range": range_name,
            "bucket": bucket,
            "source": "rollup",
            "from": start.isoformat(timespec="seconds"),
            "to": now.isoformat(timespec="seconds"),
            "points": points,
            "summary": _metric_summary_from_points(points),
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

    def list_audit_logs(
        self,
        limit: int = 100,
        node_id: str | None = None,
        action: str | None = None,
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_logs"
        conditions: list[str] = []
        params: list[Any] = []
        if node_id:
            conditions.append("node_id = ?")
            params.append(node_id)
        if action:
            conditions.append("(action = ? OR event_type = ?)")
            params.extend([action, action])
        if from_time:
            conditions.append("created_at >= ?")
            params.append(from_time)
        if to_time:
            conditions.append("created_at <= ?")
            params.append(to_time)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_alerts(
        self,
        limit: int = 100,
        status: str | None = None,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts"
        conditions: list[str] = []
        params: list[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if node_id:
            conditions.append("node_id = ?")
            params.append(node_id)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY triggered_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_alert_row_to_dict(row) for row in rows]

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
        expired: list[tuple[str, str]] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT id, status FROM commands
                WHERE status IN ('pending', 'sent', 'acknowledged', 'running') AND created_at <= ?
                """,
                (cutoff.isoformat(timespec="seconds"),),
            ).fetchall()
            expired = [(row["id"], row["status"]) for row in rows]
            if expired:
                now_text = utc_now()
                unacked_ids = [command_id for command_id, status in expired if status in {"pending", "sent"}]
                unfinished_ids = [
                    command_id for command_id, status in expired if status in {"acknowledged", "running"}
                ]
                if unacked_ids:
                    placeholders = ",".join("?" for _ in unacked_ids)
                    self._conn.execute(
                        f"""
                        UPDATE commands
                        SET status = 'timeout',
                            result_message = 'agent did not acknowledge in time',
                            finished_at = ?,
                            updated_at = ?
                        WHERE id IN ({placeholders})
                        """,
                        [now_text, now_text, *unacked_ids],
                    )
                if unfinished_ids:
                    placeholders = ",".join("?" for _ in unfinished_ids)
                    self._conn.execute(
                        f"""
                        UPDATE commands
                        SET status = 'timeout',
                            result_message = 'agent did not finish in time',
                            finished_at = ?,
                            updated_at = ?
                        WHERE id IN ({placeholders})
                        """,
                        [now_text, now_text, *unfinished_ids],
                    )
        return [command for command_id, _ in expired if (command := self.get_command(command_id))]

    def prune_metrics(self, raw_metrics_days: int, batch_size: int = 5000) -> int:
        if raw_metrics_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=raw_metrics_days)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                DELETE FROM metrics
                WHERE id IN (
                    SELECT id FROM metrics
                    WHERE captured_at < ?
                    ORDER BY captured_at ASC
                    LIMIT ?
                )
                """,
                (cutoff.isoformat(timespec="seconds"), max(1, batch_size)),
            )
            return int(cursor.rowcount or 0)

    def prune_rollups(self, hourly_days: int, daily_days: int, batch_size: int = 5000) -> dict[str, int]:
        return {
            "hourly": self._prune_rollup_table("metrics_hourly", hourly_days, batch_size),
            "daily": self._prune_rollup_table("metrics_daily", daily_days, batch_size),
        }

    def _prune_rollup_table(self, table: str, days: int, batch_size: int) -> int:
        if days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"""
                DELETE FROM {table}
                WHERE rowid IN (
                    SELECT rowid FROM {table}
                    WHERE bucket_start < ?
                    ORDER BY bucket_start ASC
                    LIMIT ?
                )
                """,
                (cutoff.isoformat(timespec="seconds"), max(1, batch_size)),
            )
            return int(cursor.rowcount or 0)
