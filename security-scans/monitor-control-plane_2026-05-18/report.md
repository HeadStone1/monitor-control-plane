# Monitor Control Plane Security Audit

Date: 2026-05-18
Repository: HeadStone1/monitor-control-plane
Remote commit reviewed: a58529c207237934bfc228933d2a3629fce0b3cb
Local commit reviewed: 12d030d
Scope: repository-wide review of Server, Agent, WebUI, configuration examples, and dependency posture.

Remediation status: the findings in this report were addressed by the follow-up security hardening patch on 2026-05-18. Keep the findings as audit history and use the remediation notes as the implementation checklist.

## Executive Summary

This audit used the Codex Security workflow: threat model, finding discovery, validation, attack-path analysis, and remediation planning.

The project already has several good controls for an MVP: WebUI authentication, HttpOnly SameSite cookies, CSP/security headers, command allowlists, server-side container ownership checks, Agent-side Docker action validation, no token-in-URL WebSocket auth, ignored real config files, and DOM rendering through `textContent`.

At scan time, the main remaining risks were around production hardening: Agent identity binding, fail-closed secret handling, enforced secure transport, and rate limiting. These were selected for the follow-up remediation patch.

## Threat Model

Assets:

- Admin session, admin token, admin password, and session secret.
- Agent token and Agent identity.
- Docker command channel.
- Container inventory, metrics, and audit logs.
- SQLite database contents.

Trust boundaries:

- Browser to Server HTTP/WebSocket.
- Agent to Server WebSocket.
- Server to SQLite database.
- Agent to local Docker Engine.

Primary attacker models:

- Network attacker on an unencrypted Server/Agent path.
- External user who reaches the WebUI/API.
- Compromised or malicious Agent host.
- Operator who accidentally exposes development defaults to a network.

## Findings

### Finding 1: Agent token is not bound to a specific node identity

Priority: P1
Severity: high
Confidence: high
CWE: CWE-287 Improper Authentication, CWE-306 Missing Authentication for Critical Function
Affected lines:

- `server/monitor_server/app.py:198-203`
- `server/monitor_server/hub.py:15-18`
- `server/monitor_server/hub.py:36-50`

Summary:

The Agent WebSocket accepts any token in `config.agent_tokens` and any non-empty `node_id`. There is no mapping from token to the node identity it is allowed to claim. Once accepted, `ConnectionHub.register_agent` stores the WebSocket under that `node_id`, replacing any existing connection for the same node.

Validation:

- Static trace confirms `/agent/ws` reads `token` and `node_id`, then checks only `token in config.agent_tokens` and `node_id`.
- Runtime check confirmed the default global Agent token is accepted by the same boolean logic for an arbitrary node string.
- `send_command` routes future commands to whichever WebSocket is currently registered for that `node_id`.

Attack path:

1. Attacker obtains any valid Agent token from one host, backup, logs, or misconfiguration.
2. Attacker connects to `/agent/ws` and claims `agent_id` equal to another node.
3. Server accepts the connection and registers it under that node id.
4. Attacker can poison metrics/inventory, mark command results, and receive commands intended for that node.

Impact:

This can corrupt control-plane integrity, hide real container state, confuse operators, and hijack command routing. It does not directly execute code on the real host by itself, but it breaks a core distributed identity boundary.

Remediation:

- Replace `agent_tokens: list[str]` with per-node credentials, for example:
  - `agents: [{node_id, token_hash, name, scopes, enabled}]`
- On `/agent/ws`, derive the allowed node from the token record and reject mismatched `agent_id`.
- Store only token hashes, not plaintext tokens.
- Support token rotation and revocation.
- Reject duplicate active connections unless they present a reconnection nonce or explicitly replace an expired connection.
- Add audit events for Agent auth failure, Agent reconnect, node-id mismatch, and duplicate connection replacement.
- Add tests:
  - valid token + matching node succeeds.
  - valid token + different node fails.
  - duplicate node registration follows the intended replacement policy.

### Finding 2: Development credentials and secrets are valid by default and only produce warnings

Priority: P2
Severity: medium
Confidence: high
CWE: CWE-798 Use of Hard-coded Credentials, CWE-521 Weak Password Requirements
Affected lines:

- `server/monitor_server/config.py:23-28`
- `server/monitor_server/config.py:71-76`
- `server/monitor_server/app.py:254-262`
- `web/index.html:30`

Summary:

The default server config includes `dev-admin-token`, `dev-admin-password`, `dev-session-secret-change-me`, and `dev-agent-token`. Startup logs warnings when weak defaults are used, but the application still starts and accepts those credentials. The login page also displays the development account hint.

Validation:

- Runtime check confirmed `verify_admin_token(ServerConfig(), "dev-admin-token")` returns `admin`.
- Runtime check confirmed a session created with the default session secret validates successfully.
- The login UI shows `Development account: admin / dev-admin-password`.

Attack path:

1. Operator exposes the server to a network before changing defaults.
2. Attacker opens the login page and sees the development credential hint or uses known defaults from the public repo.
3. Attacker logs in or uses the static admin token.
4. Attacker can view nodes, containers, commands, audit logs, and issue Docker start/stop/restart commands.

Impact:

If deployed outside localhost, known defaults can grant full control-plane access. Repository documentation warns against this, but the application should fail closed for dangerous deployments.

Remediation:

- Fail startup when defaults are present and `host` is not loopback or when `MONITOR_ENV=production`.
- Remove the login hint from production builds, or render it only when an explicit `show_dev_hints: true` flag is set.
- Replace plaintext admin password with Argon2id or bcrypt password hash.
- Remove or disable the permanent `admin_token` by default; prefer short-lived sessions and explicitly provisioned API tokens.
- Add minimum length/entropy checks for `admin_password`, `admin_token`, `session_secret`, and Agent tokens.
- Add a one-time local setup command to generate secrets.

### Finding 3: Secure transport is recommended but not enforced for privileged channels

Priority: P2
Severity: medium
Confidence: medium-high
CWE: CWE-319 Cleartext Transmission of Sensitive Information
Affected lines:

- `agent/monitor_agent/config.py:26-30`
- `agent.example.yaml:1`
- `server/monitor_server/security.py:101-109`
- `server/monitor_server/app.py:56-57`

Summary:

The Agent default and example URL use `ws://127.0.0.1:8000/agent/ws`, and the server accepts plain HTTP/WebSocket when configured that way. Cookies are marked `Secure` only when FastAPI sees `request.url.scheme == "https"`. Behind a TLS-terminating proxy, this can be wrong if proxy headers are not configured, causing HTTPS deployments to emit non-Secure cookies.

Validation:

- The Agent accepts `ws://` and returns no TLS context for non-WSS URLs.
- Example config uses `ws://`.
- Session cookie `secure` is derived from request scheme, not from an explicit deployment setting.
- HSTS is emitted only when the app sees HTTPS.

Attack path:

1. Operator exposes HTTP/WS directly or deploys behind TLS termination without proxy-header handling.
2. Network attacker observes or tampers with traffic.
3. Agent tokens or admin cookies can be stolen on plaintext paths.
4. Stolen credentials enable Agent impersonation or admin control-plane access.

Impact:

MITM on a privileged control plane can lead to credential theft, telemetry tampering, and container command abuse.

Remediation:

- Add `require_secure_transport: true` defaulting to true for non-loopback hosts.
- Reject `ws://` Agent URLs unless `allow_insecure_local_transport: true` and host is loopback.
- Add explicit `secure_cookies: true` config for production instead of deriving solely from request scheme.
- Document and configure Uvicorn proxy headers when behind Caddy/Nginx.
- Prefer WSS for Agent traffic and HTTPS for WebUI.
- Consider mTLS for Agent-to-Server authentication in a later production version.

### Finding 4: No rate limiting on login, WebSocket auth, or Agent message ingestion

Priority: P3
Severity: low-medium
Confidence: medium
CWE: CWE-307 Improper Restriction of Excessive Authentication Attempts, CWE-770 Allocation of Resources Without Limits
Affected lines:

- `server/monitor_server/app.py:87-98`
- `server/monitor_server/app.py:190-203`
- `server/monitor_server/app.py:244-251`
- `server/monitor_server/app.py:282-298`
- `server/monitor_server/db.py:371-413`

Summary:

Login attempts, WebSocket authentication failures, and authenticated Agent data ingestion are not rate limited at the application layer. Agent inventory replacement accepts arbitrary list sizes from a connected Agent and writes them into SQLite.

Validation:

- Login route performs credential comparison and returns 401 without backoff or lockout.
- WebSocket auth has a 5-second first-message timeout but no per-IP or per-token failure throttle.
- `replace_inventory` loops over every item supplied by an authenticated Agent and builds a variable placeholder list for all observed container IDs.

Attack path:

1. External attacker repeatedly probes login if WebUI is reachable.
2. Network attacker or malicious host repeatedly attempts Agent WebSocket auth.
3. Compromised Agent sends very large inventory/stat payloads.
4. Server CPU, memory, or SQLite writes can be degraded, and logs/audit become noisy.

Impact:

This is mostly availability and operational-risk hardening. It becomes more important once the server is exposed beyond localhost or supports many agents.

Remediation:

- Add per-IP and per-username login throttling with exponential backoff.
- Add WebSocket auth failure counters per IP/token prefix and close aggressively.
- Add request body/message size and schema validation limits.
- Cap containers per Agent and truncate/flag oversized inventory messages.
- Add metrics for auth failures and rejected oversized messages.

## Coverage Closure

Reviewed but not promoted to findings:

- XSS: no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, `new Function`, or `document.write` usage found in WebUI. Dynamic data is written via DOM APIs and `textContent`.
- SQL injection: SQLite calls use parameterized queries. The dynamic `NOT IN` placeholder string is generated from `?` placeholders, not user-controlled SQL fragments.
- Docker command injection: commands use Docker SDK methods, action allowlists, and container ID regex checks. No shell execution was found.
- CSRF: current `SameSite=Strict` HttpOnly cookie and JSON fetch flow reduce practical CSRF risk. Add CSRF tokens before multi-origin, reverse-proxy, or multi-user production deployments.
- Dependency posture: installed Starlette was 0.41.3 at scan time. GitHub Advisory GHSA-2c2j-9gv5-cj73 / CVE-2025-54121 affects Starlette versions before 0.47.2 for multipart-form DoS. This project had no multipart upload endpoint, so it was not treated as directly reachable. The follow-up patch upgraded FastAPI and Starlette.

## Recommended Fix Order

1. Bind Agent tokens to node IDs and add token rotation/revocation.
2. Fail startup on default secrets when binding outside loopback or in production mode.
3. Add secure transport enforcement and explicit production cookie settings.
4. Add login/WebSocket rate limiting and Agent payload size limits.
5. Upgrade dependencies, add `pip-audit` or equivalent to CI, and keep a lock file.
6. Add focused tests for authentication, Agent identity binding, command authorization, and XSS-safe rendering.

## References

- GitHub repository: https://github.com/HeadStone1/monitor-control-plane
- Reviewed remote commit: https://github.com/HeadStone1/monitor-control-plane/commit/a58529c207237934bfc228933d2a3629fce0b3cb
- Starlette advisory: https://github.com/encode/starlette/security/advisories/GHSA-2c2j-9gv5-cj73
