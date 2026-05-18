# Development

## Local Dependencies

Install Python 3.11 or newer, then create a virtual environment in the project root:

```powershell
cd G:\33258\Desktop\Monitor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The command uses the Python inside `.venv`, so dependencies stay inside the project virtual environment.

Generate local development hashes when replacing secrets:

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --hash-secret "your-admin-password"
.\.venv\Scripts\python.exe -m server.monitor_server --hash-secret "your-agent-token"
```

The current MVP intentionally avoids a frontend build step. The WebUI is plain static HTML/CSS/JS served by the Python server.

## Local Config

```powershell
Copy-Item server.example.yaml server.yaml
Copy-Item agent.example.yaml agent.yaml
```

Then replace the default password hash, Agent token hash, Agent token, and `session_secret` in both files. Keep `server.yaml` and `agent.yaml` out of Git.

## Run Server

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --config server.yaml
```

Then open:

```text
http://127.0.0.1:8000
```

## Run Agent

Open another terminal:

```powershell
cd G:\33258\Desktop\Monitor
.\.venv\Scripts\python.exe -m agent.monitor_agent --config agent.yaml
```

On Windows, the agent can still send basic host metrics. Docker data is primarily intended for Linux hosts with Docker Engine available.

## Production Direction

- Put the server behind Caddy or Nginx.
- Use HTTPS/WSS.
- Replace static development tokens with per-agent tokens.
- Store admin passwords as hashes.
- Run the Linux agent as a `systemd` service.
- Restrict Docker command actions to a strict allowlist.
