#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:-${MONITOR_DATABASE_PATH:-data/monitor.db}}"
BACKUP_DIR="${2:-${MONITOR_BACKUP_DIR:-backups}}"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 is required for online backups" >&2
  exit 1
fi

if [ ! -f "$DB_PATH" ]; then
  echo "database not found: $DB_PATH" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
target="$BACKUP_DIR/monitor-$timestamp.db"

sqlite3 "$DB_PATH" ".backup '$target'"
sqlite3 "$target" "PRAGMA integrity_check;" | grep -qx "ok"

echo "$target"
