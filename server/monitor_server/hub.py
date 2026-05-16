from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class ConnectionHub:
    def __init__(self) -> None:
        self._agents: dict[str, WebSocket] = {}
        self._ui_clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register_agent(self, node_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._agents[node_id] = websocket

    async def unregister_agent(self, node_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            if self._agents.get(node_id) is websocket:
                self._agents.pop(node_id, None)

    async def register_ui(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._ui_clients.add(websocket)

    async def unregister_ui(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._ui_clients.discard(websocket)

    async def is_agent_connected(self, node_id: str) -> bool:
        async with self._lock:
            return node_id in self._agents

    async def send_command(self, node_id: str, command: dict[str, Any]) -> bool:
        async with self._lock:
            websocket = self._agents.get(node_id)
        if not websocket:
            return False

        await websocket.send_json(
            {
                "type": "command",
                "command_id": command["id"],
                "action": command["action"],
                "payload": command.get("payload") or {},
                "timeout_seconds": 30,
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
