param(
    [string]$BaseUrl = "http://127.0.0.1:8000",
    [string]$Username = "admin",
    [string]$Password = $env:MONITOR_UI_PASSWORD,
    [switch]$Headed
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
    throw @"
npx was not found. Install Node.js/npm first, then retry:

node --version
npm --version
npm install -g @playwright/cli@latest
playwright-cli --help
"@
}

if ([string]::IsNullOrWhiteSpace($Password)) {
    throw "Missing password. Pass -Password or set MONITOR_UI_PASSWORD."
}

$scriptPath = Join-Path $PSScriptRoot "ui_smoke_check.mjs"
$args = @(
    "--yes",
    "--package",
    "playwright",
    "node",
    $scriptPath,
    "--base-url",
    $BaseUrl,
    "--username",
    $Username,
    "--password",
    $Password
)

if ($Headed) {
    $args += "--headed"
}

& npx @args
