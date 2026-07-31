# Changelog

## 2026-07-31

### Added

- Added `--init-config` to generate local `server.yaml` and `agent.yaml` with Argon2id hashes, a random session secret, an initial Agent token, RBAC defaults, retention settings, and Docker allowed-label defaults.
- Added `scripts/ui_smoke_check.ps1` and `scripts/ui_smoke_check.mjs` for optional real-browser WebUI validation with Playwright.
- Added tests for the config initialization flow and UI smoke-check script coverage.

### Changed

- Updated README quick start to recommend the config initialization wizard before manual hash generation.
- Documented the optional browser smoke check command and the files that should be included in this update.

## 2026-05-18

### Security

- Added Argon2id password hashing support through `admin_password_hash`; plaintext admin passwords and legacy PBKDF2 hashes are rejected.
- Added per-node Agent credentials through `agents[].node_id` and required Argon2id `agents[].token_hash`; plaintext Agent token config is rejected.
- Changed Agent authentication so a valid token can only claim its configured node ID.
- Added runtime config reload for users, roles, API tokens, and Agent credentials.
- Added runtime Agent token revoke API that disables the in-memory credential and disconnects the current Agent connection.
- Added command ACK/running states and state-aware command timeout messages.
- Added server-side metric thresholds, active/resolved alerts, and WebUI alert count display.
- Added hourly/daily metrics rollup tables and long-range query routing to rollup data.
- Added audit log filtering and WebUI CSV export.
- Added deployment examples for systemd Server/Agent services, daily SQLite backups, Docker images, and Docker Compose.
- Added a WebUI node overview dashboard with per-node CPU, memory, disk rings, status, and alert count.
- Added container list search and running/stopped status filters.
- Added WebUI RBAC awareness so read-only users no longer see active container command controls or threshold editors.
- Added WebUI dark mode with persisted preference and chart colors driven by theme variables.
- Added Canvas chart drag-to-zoom with a reset control for narrowing metric time ranges.
- Added an authenticated Prometheus `/metrics` endpoint for latest node status and utilization gauges.
- Added Dependabot monitoring for Python dependencies and GitHub Actions.
- Added production startup checks that refuse development defaults, plaintext secrets, insecure cookies, and missing secure-transport enforcement.
- Added login and WebSocket authentication failure rate limiting.
- Added Agent payload limits for container inventory/stat messages and command result text.
- Added Agent-side guard against non-loopback `ws://` connections unless explicitly allowed.
- Added `--hash-secret` helper for generating admin password and Agent token hashes.

## 2026-05-17

### Added

- Added a Google / Material inspired WebUI layout for the dashboard, node list, metrics, containers, commands, and audit logs.
- Added login flow for the WebUI.
- Added `HttpOnly` and `SameSite=Strict` cookie based Web sessions.
- Added security headers, including CSP, frame protection, content sniffing protection, referrer policy, and permissions policy.
- Added Host header allowlist support through `allowed_hosts`.
- Added example config files: `server.example.yaml` and `agent.example.yaml`.
- Added `SECURITY.md` with XSS, MITM, credential leakage, request tampering, and 0day risk notes.
- Added metric range selection for `1h`, `7d`, and `30d`.
- Added metric aggregation:
  - `1h`: raw samples.
  - `7d`: hourly averages.
  - `30d`: daily averages.
- Added CPU, memory, and disk summaries with average value, max value, and peak time.
- Added configurable CPU, memory, and disk threshold lines on the chart.
- Added chart hover details for bucket time, sample count, average value, max value, and peak time.
- Added chart time axis labels that adapt to the selected metric range.

### Changed

- Moved Agent and UI WebSocket authentication out of URL query parameters and into the first WebSocket `auth` message or cookie.
- Reworked WebUI dynamic rendering to use DOM APIs and `textContent` instead of raw HTML string insertion.
- Reworked README to explain project audience, risks, responsibility boundaries, setup steps, production warnings, and license terms.
- Updated development docs to use project-local virtual environment commands.
- Kept real `server.yaml` and `agent.yaml` out of Git tracking; only example configs should be committed.

### Security

- Added command allowlisting on the server.
- Added server-side check that a target container belongs to the selected node before a command is sent.
- Added Agent-side command action and Docker container ID validation.
- Disabled insecure `tls_verify=false` behavior for `wss://` connections.
- Added startup warnings when development default admin credentials or session secret are still in use.

### Validation

- Python compile check passed for `agent` and `server`.
- JavaScript syntax check passed for `web/app.js`.
- Static scan found no `innerHTML`, `eval`, `document.write`, URL token query, or similar high-risk frontend patterns.
