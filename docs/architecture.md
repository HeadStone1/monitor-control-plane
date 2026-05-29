# Architecture

## Deployment Shape

```text
Linux Server A [monitor-agent] --\
Linux Server B [monitor-agent] ----> [monitor-server + SQLite + WebUI] <--- Browser
Linux Server C [monitor-agent] --/
```

Agents always initiate the connection to the server. The server does not SSH into monitored machines.

## Protocol

- Transport: WebSocket over TCP.
- Development URL: `ws://server/agent/ws`.
- Production URL: `wss://server/agent/ws`.
- Payload format: JSON.
- Authentication: the first WebSocket message is `{"type":"auth","agent_id":"...","token":"..."}`. Tokens are never sent in URL query strings.

## Agent Messages

```json
{
  "type": "heartbeat",
  "agent_id": "prod-node-01",
  "timestamp": 1710000000,
  "seq": 1001,
  "data": {}
}
```

Important message types:

- `hello`
- `heartbeat`
- `host_info`
- `metrics`
- `docker_inventory`
- `docker_stats`
- `command_ack`
- `command_running`
- `command_result`

## Server Messages

```json
{
  "type": "command",
  "request_id": "cmd_abc",
  "command_id": "cmd_abc",
  "action": "container.restart",
  "payload": {
    "container_id": "abc123"
  },
  "timeout_seconds": 30
}
```

Command lifecycle:

```text
pending -> sent -> acknowledged -> running -> success / failed / timeout
```

## Security Notes

The Docker socket is effectively root-equivalent on many Linux systems. The agent must be treated as a privileged component. Production deployments should use:

- HTTPS/WSS.
- Per-agent tokens or mTLS certificates.
- Admin sessions instead of static admin tokens.
- Strict command allowlists.
- Audit logs for all container operations.
