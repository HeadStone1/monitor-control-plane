from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class AgentConnection:
    def __init__(self, websocket: WebSocket, credential_fingerprint: str = "") -> None:
        self.websocket = websocket
        self.credential_fingerprint = credential_fingerprint


class ConnectionHub:
    def __init__(self) -> None:
        self._agents: dict[str, AgentConnection] = {}
        self._ui_clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register_agent(
        self,
        node_id: str,
        websocket: WebSocket,
        credential_fingerprint: str = "",
    ) -> bool:
        async with self._lock:
            if node_id in self._agents:
                return False
            self._agents[node_id] = AgentConnection(websocket, credential_fingerprint)
            return True

    async def unregister_agent(self, node_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            connection = self._agents.get(node_id)
            if connection and connection.websocket is websocket:
                self._agents.pop(node_id, None)

    async def connected_agent_ids(self) -> list[str]:
        async with self._lock:
            return list(self._agents)

    async def agent_credential_fingerprint(self, node_id: str) -> str | None:
        async with self._lock:
            connection = self._agents.get(node_id)
            return connection.credential_fingerprint if connection else None

    async def disconnect_agent(self, node_id: str, code: int = 1008, reason: str = "") -> bool:
        async with self._lock:
            connection = self._agents.pop(node_id, None)
        if not connection:
            return False
        try:
            await connection.websocket.close(code=code, reason=reason)
        except RuntimeError:
            pass
        return True

    async def register_ui(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._ui_clients.add(websocket)

    async def unregister_ui(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._ui_clients.discard(websocket)

    async def is_agent_connected(self, node_id: str) -> bool:
        async with self._lock:
            return node_id in self._agents

    async def send_command(self, node_id: str, command: dict[str, Any], timeout_seconds: int = 30) -> bool:
        async with self._lock:
            connection = self._agents.get(node_id)
        if not connection:
            return False

        await connection.websocket.send_json(
            {
                "type": "command",
                "request_id": command["id"],
                "command_id": command["id"],
                "action": command["action"],
                "payload": command.get("payload") or {},
                "timeout_seconds": timeout_seconds,
            }
        )
        return True

    async def broadcast_ui(self, message: dict[str, Any]) -> None:
        async with self._lock:
            clients = list(self._ui_clients)

        stale: list[WebSocket] = []
        for websocket in clients:
            try:
                await websocket.send_json(message)
            except RuntimeError:
                stale.append(websocket)

        if stale:
            async with self._lock:
                for websocket in stale:
                    self._ui_clients.discard(websocket)
