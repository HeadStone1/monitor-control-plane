# Changelog

## 2026-07-31

### Added

- Added `--init-config` to generate local `server.yaml` and `agent.yaml` with Argon2id hashes, a random session secret, an initial Agent token, RBAC defaults, retention settings, and Docker allowed-label defaults.
- Added `scripts/ui_smoke_check.ps1` and `scripts/ui_smoke_check.mjs` for optional real-browser WebUI validation with Playwright.
- Added an admin-only `Admin / Health` WebUI page for database status, background task status, runtime config details, capacity counters, and config reload.
- Added tests for the config initialization flow and UI smoke-check script coverage.
- Added signed external alert webhooks with environment-only secrets, a bounded worker queue, delivery retries, failure auditing, and Admin health telemetry.

### Changed

- Refined the overview icons and metric chart, added per-series visibility controls, and expanded selectable ranges to `1h / 24h / 7d / 15d / 30d / 60d / 90d`.
- Refined dashboard spacing, responsive header grouping, compact overview cards, drawer behavior, and mobile chart sizing.
- Added a dedicated mobile navigation drawer, responsive container cards, and distinct loading, failure, and empty states.
- Updated README quick start to recommend the config initialization wizard before manual hash generation.
- Updated WebUI smoke check coverage to include the admin health page.
- Documented the optional browser smoke check command and the files that should be included in this update.

### Fixed

- Preserve the last successful Docker container inventory when collection fails, and expose stale/error timestamps instead of treating a transient Docker error as an empty host.
- Run blocking system and Docker collectors in a bounded worker pool with Docker API and collection timeouts, keeping heartbeats and WebSocket command handling responsive.
- Add bounded, serialized WebSocket sends with concurrent UI fan-out, stale-client cleanup, and a terminal `send_failed` command state when Agent delivery fails.
- Replace full-table Python metric rollups with incremental SQLite aggregation, move maintenance work off the async event loop, prune data in bounded batches, and expose maintenance health telemetry.
- Keep the background status watcher alive after transient cycle failures with bounded retry backoff, audited failures, degraded health reporting, and Admin-page recovery telemetry.
- Require an Agent `auth_ok` protocol handshake before telemetry starts, add configurable jittered reconnect backoff with stable-connection reset, clean up connection tasks deterministically, and prevent duplicate WebUI reconnect timers.
- Persist Agent credential revocations in SQLite using token IDs and non-secret fingerprints, enforce them after restart and config reload, and preserve rotation through a new token identity.
- Keep alert delivery outside the Agent metrics path, require HTTPS in production, disable redirects and environment proxies, and avoid reading response bodies.

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
