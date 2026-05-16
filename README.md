# Monitor

Lightweight distributed Linux and Docker monitoring MVP.

## Project Note

This project is a vibe coding prototype for a lightweight distributed
monitoring and Docker control plane. The first version focuses on validating
the Agent -> Server -> WebUI workflow before evolving into a production-ready
system.

This repository contains three parts:

- `agent`: runs on monitored Linux servers, collects host and Docker data, and executes container commands.
- `server`: central API, WebSocket hub, SQLite storage, and command dispatcher.
- `web`: static WebUI served by the Python server.

## Tech Stack

- Python 3.11+
- FastAPI + WebSocket for the server
- SQLite for the first version database
- Python Agent with `psutil`, `docker`, and `websockets`
- Static HTML/CSS/JS WebUI for zero frontend build tooling
- JSON messages over WebSocket
- TLS-ready transport via HTTPS/WSS behind Caddy, Nginx, or another reverse proxy

## License

This project is source-available under the Monitor Personal Use License v0.1.

- Personal, educational, research, and other non-commercial use is allowed.
- Commercial use requires prior written authorization from the copyright holder.
- This is not an OSI open source license.

See [LICENSE](LICENSE) for details.

## Quick Start

Create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start the server:

```powershell
python -m server.monitor_server --config server.yaml
```

Open the WebUI:

```text
http://127.0.0.1:8000
```

Default development login:

```text
username: admin
password: dev-admin-password
```

Start an agent in another terminal:

```powershell
.\.venv\Scripts\Activate.ps1
python -m agent.monitor_agent --config agent.yaml
```

On Linux, the agent can read Docker data if:

- Docker is installed and running.
- The agent user can access `/var/run/docker.sock`, usually by being in the `docker` group.

## First-Version Security Model

- Agent connects outward to the server; the agent does not open an inbound port.
- Agent authentication uses a shared token from `server.yaml` and `agent.yaml`.
- WebUI/API authentication uses username/password login and a signed session token.
- The static `admin_token` remains available for development API calls.
- Production should run behind HTTPS/WSS.
- Dangerous container actions are stored in `audit_logs`.

For production, prefer replacing shared agent tokens with per-node tokens or mTLS certificates.

## Message Timing

- Heartbeat: every 10 seconds.
- System metrics: every 5 seconds.
- Docker stats: every 5 seconds.
- Docker inventory: every 30 seconds.
- Host info: every 60 seconds.
- Warning state: 30 seconds without heartbeat.
- Offline state: 60 seconds without heartbeat.
