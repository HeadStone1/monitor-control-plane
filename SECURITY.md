# Security Notes

Monitor Control Plane is a monitoring and remote-control prototype. Treat it as a privileged system because it can send Docker container commands to connected agents.

## Threats Considered

### XSS

Current mitigations:

- Dynamic WebUI values are inserted with DOM APIs and `textContent`, not raw HTML strings.
- Status CSS classes are allowlisted instead of using raw server values.
- The server sends a Content Security Policy that only allows same-origin scripts and styles.
- The UI does not load third-party scripts.
- Browser session credentials are stored in an `HttpOnly` cookie, so JavaScript cannot directly read the session token.

Remaining work:

- Add automated browser security tests.
- Add dependency and frontend lint checks in CI.
- Consider a typed frontend framework if the UI grows.

### Man-in-the-Middle Attacks

Current mitigations:

- Agent and UI WebSocket secrets are not placed in URL query strings.
- The app is designed to run behind HTTPS/WSS.
- HSTS is emitted when the request is served through HTTPS.

Required production setup:

- Use HTTPS/WSS.
- Terminate TLS at Caddy, Nginx, or another trusted reverse proxy.
- Do not expose plain HTTP/WebSocket to untrusted networks.
- Keep certificates renewed and disable weak TLS settings at the proxy layer.

### Credential Leakage

Current mitigations:

- Real `server.yaml` and `agent.yaml` should not be committed.
- The repository contains `server.example.yaml` and `agent.example.yaml`.
- Sensitive server settings can be provided through environment variables.
- Web sessions use `HttpOnly` and `SameSite=Strict` cookies.
- Admin passwords, API tokens, and Server-side Agent credentials use Argon2id hashes.
- Agent credentials are node-bound, support rotation IDs, and can be persistently revoked.
- Alert webhook signing secrets are resolved from environment variables and are rejected if placed directly in YAML.

Remaining work:

- Protect process environment access and rotate credentials after suspected exposure.
- Use an external secret manager when moving beyond a single-host deployment.

### Host Header And Request Tampering

Current mitigations:

- The server restricts allowed Host headers through `allowed_hosts`.
- Command actions use a strict allowlist.
- The server checks that a target container is known on the selected node before sending a command.
- The agent validates command action and Docker container ID format again before touching Docker.
- Browser mutations require a session-bound CSRF token.
- Commands use node-bound IDs, ACK/running/result states, and state-aware expiry.
- API routes enforce RBAC scopes.

Remaining work:

- Add explicit command idempotency keys before supporting automatic command retries.

### Outbound Alert Webhooks

Current mitigations:

- Webhook destinations come only from administrator-controlled configuration, never Agent payloads or request parameters.
- Production destinations must use HTTPS; development HTTP is restricted to loopback hosts.
- URLs cannot contain credentials or fragments, redirects are disabled, environment proxy settings are ignored, and response bodies are not buffered.
- Delivery runs in a bounded worker queue with short timeouts and finite retries, outside the Agent metrics ingestion path.
- Every request is signed with HMAC-SHA256 over the timestamp and exact request body.
- Success, final failure, and queue overflow are written to the audit log without recording the signing secret.

Operational requirements:

- The receiver must validate `X-Monitor-Signature` using the raw body and reject stale `X-Monitor-Timestamp` values.
- Keep signing secrets out of YAML, rotate them periodically, and restrict the receiver to expected source networks where practical.
- Treat internal webhook destinations as trusted infrastructure; DNS and network policy remain deployment responsibilities.

### 0day Vulnerabilities

No application can fully prevent unknown vulnerabilities in Python, Docker, the OS, browser engines, TLS stacks, reverse proxies, or dependencies.

Risk reduction:

- Keep Python, Docker, the OS, and dependencies patched.
- Run the server behind a reverse proxy and firewall.
- Limit access to trusted networks.
- Run the agent with the smallest practical permissions.
- Back up data and test restore procedures.
- Monitor dependency advisories.
- Assume a compromised control plane can affect connected Docker hosts.

## Disclosure

For private security reports, contact the repository owner. Do not publish exploit details before the maintainer has had time to investigate.

## Implemented Hardening After Audit

- Admin passwords must be stored as Argon2id hashes with `admin_password_hash`; plaintext admin passwords and legacy PBKDF2 hashes are rejected.
- Agent tokens must be stored as Argon2id hashes with per-node `agents[].token_hash`; plaintext `agent_tokens`, `MONITOR_AGENT_TOKENS`, and `agents[].token` are rejected.
- Agent authentication now binds a token to a specific `node_id`; a token for one node cannot claim another node.
- Runtime config reload updates users, roles, API tokens, and Agent credentials without restarting the Server.
- Agent credentials can be revoked persistently; SQLite stores only the credential fingerprint and token ID, rejects the revoked credential after restart or config reload, disconnects the current WebSocket, and writes audit events.
- Container command delivery now has ACK and running states before the final success/failed result, with state-aware timeout audit records.
- Metrics are rolled up into hourly and daily summaries to reduce long-range raw-data scans.
- Threshold settings are stored server-side and generate active/resolved alert events.
- Active/resolved alert events can be delivered through signed, bounded, non-blocking webhooks with audited failures.
- Audit logs support node/action/time filtering and WebUI CSV export for incident review.
- Production mode refuses plaintext admin passwords, plaintext Agent tokens, development defaults, insecure cookies, and missing secure-transport enforcement.
- Deployment examples include hardened systemd units, daily SQLite backup timer, a non-root Dockerfile, and Docker Compose with the Agent socket mount behind an opt-in profile.
- Prometheus scraping is supported through `/metrics`, but it requires a scoped `metrics:read` token.
- Login and WebSocket authentication failures are rate limited.
- Agent container inventory and command result messages are capped to reduce resource exhaustion.
- Non-loopback Agent `ws://` connections are blocked unless explicitly allowed by configuration.
