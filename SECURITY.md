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

Remaining work:

- Store password hashes instead of plaintext passwords.
- Use per-agent tokens instead of a shared token list.
- Add token rotation and revocation.
- Add rate limiting and lockout for repeated failed login attempts.

### Host Header And Request Tampering

Current mitigations:

- The server restricts allowed Host headers through `allowed_hosts`.
- Command actions use a strict allowlist.
- The server checks that a target container is known on the selected node before sending a command.
- The agent validates command action and Docker container ID format again before touching Docker.

Remaining work:

- Add CSRF tokens for state-changing browser requests.
- Add command expiry, acknowledgement, and replay protection.
- Add RBAC before supporting multiple operators.

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

- Admin passwords can now be stored as PBKDF2 hashes with `admin_password_hash`.
- Agent tokens can now be stored as PBKDF2 hashes with per-node `agents[].token_hash`.
- Agent authentication now binds a token to a specific `node_id`; a token for one node cannot claim another node.
- Production mode refuses plaintext admin passwords, plaintext Agent tokens, development defaults, insecure cookies, and missing secure-transport enforcement.
- Login and WebSocket authentication failures are rate limited.
- Agent container inventory and command result messages are capped to reduce resource exhaustion.
- Non-loopback Agent `ws://` connections are blocked unless explicitly allowed by configuration.
