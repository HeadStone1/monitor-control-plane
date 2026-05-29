param(
    [string]$DatabasePath = "data/monitor.db",
    [string]$OutputDir = "backups"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dbPath = [System.IO.Path]::GetFullPath((Join-Path $root $DatabasePath))
$backupDir = [System.IO.Path]::GetFullPath((Join-Path $root $OutputDir))

if (-not (Test-Path -LiteralPath $dbPath)) {
    throw "Database not found: $dbPath"
}

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = Join-Path $backupDir "monitor-$timestamp.db"

$sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
if (-not $sqlite) {
    throw "sqlite3 was not found in PATH. Install SQLite CLI and retry."
}

& $sqlite.Source $dbPath ".backup '$backupPath'"

Write-Output "Backup written to $backupPath"
