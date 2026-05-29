# Deployment

This project can run as plain Python services under systemd or as local Docker
Compose services. Keep the Server behind a TLS reverse proxy for production.

## Production Server Config

Use a production `server.yaml` with an absolute database path:

```yaml
environment: production
host: 127.0.0.1
database_path: /var/lib/monitor/monitor.db
secure_cookies: true
trust_proxy_headers: true
require_secure_transport: true
admin_token: ""
admin_username: admin
admin_password_hash: replace-with-argon2id-hash
session_secret: replace-with-long-random-secret
agents:
  - node_id: prod-01
    name: prod-01
    token_id: token-2026-05
    token_hash: replace-with-argon2id-token-hash
    enabled: true
```

Generate Argon2id hashes with:

```bash
python -m server.monitor_server --hash-secret "secret-to-hash"
```

Plaintext `admin_password`, `users[].password`, `agent_tokens`,
`MONITOR_AGENT_TOKENS`, and `agents[].token` are rejected.

## systemd

Example unit files live in `deploy/systemd/`:

- `monitor-server.service`
- `monitor-agent.service`
- `monitor-db-backup.service`
- `monitor-db-backup.timer`

Suggested layout:

```bash
sudo useradd --system --home /opt/monitor --shell /usr/sbin/nologin monitor
sudo mkdir -p /opt/monitor /etc/monitor /var/lib/monitor /var/log/monitor /var/backups/monitor
sudo chown -R monitor:monitor /opt/monitor /etc/monitor /var/lib/monitor /var/log/monitor /var/backups/monitor
```

Install the app into `/opt/monitor`, create `/opt/monitor/.venv`, install
`requirements.txt`, and place real config files at `/etc/monitor/server.yaml`
and `/etc/monitor/agent.yaml`.

Enable the Server and daily database backups:

```bash
sudo cp deploy/systemd/monitor-server.service /etc/systemd/system/
sudo cp deploy/systemd/monitor-db-backup.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now monitor-server.service
sudo systemctl enable --now monitor-db-backup.timer
```

For Linux Agents that need Docker control, the service uses a non-root
`monitor` user plus `SupplementaryGroups=docker`. Docker group access is still
high privilege. Prefer Rootless Docker or Docker API over TLS with an
authorization proxy when possible.

Reload runtime auth config without restarting the Server:

```bash
sudo systemctl reload monitor-server.service
```

Runtime reload updates users, roles, API tokens, and Agent credentials. It does
not rewrite YAML, so persistent revocation still requires editing
`/etc/monitor/server.yaml`.

## SQLite Backups

The Server enables SQLite WAL mode. Use the backup helper for online backups:

```bash
scripts/backup_sqlite.sh /var/lib/monitor/monitor.db /var/backups/monitor
```

The script uses `sqlite3 .backup` and verifies the backup with
`PRAGMA integrity_check`.

On Windows:

```powershell
.\scripts\backup_sqlite.ps1
```

Restore by stopping the Server, replacing the database file with the backup,
then starting the Server.

## Docker Compose

`docker-compose.yml` builds two non-root images:

- `monitor-server`, bound to `127.0.0.1:8000`
- `monitor-agent`, behind the optional `agent` profile

The compose file overrides `MONITOR_HOST=0.0.0.0` and
`MONITOR_DATABASE_PATH=/app/data/monitor.db` so the container can receive host
port traffic and keep SQLite data on the named volume. For the Agent container,
set `server_url: ws://monitor-server:8000/agent/ws` in `agent.yaml`.

Run only the Server:

```bash
docker compose up --build monitor-server
```

Run the optional Agent profile:

```bash
DOCKER_GID="$(getent group docker | cut -d: -f3)" docker compose --profile agent up --build
```

The Agent profile mounts `/var/run/docker.sock`; this is equivalent to broad
Docker host control. Keep Docker label restrictions enabled and only label
containers that are safe for remote start/stop/restart:

```bash
docker run --label monitor.control-plane.allow=true ...
```
