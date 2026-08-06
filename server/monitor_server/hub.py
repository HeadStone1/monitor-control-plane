from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class AgentConnection:
    def __init__(self, websocket: WebSocket, credential_fingerprint: str = "") -> None:
        self.websocket = websocket
        self.credential_fingerprint = credential_fingerprint
        self.send_lock = asyncio.Lock()


class ConnectionHub:
    def __init__(self, send_timeout_seconds: float = 5) -> None:
        self._agents: dict[str, AgentConnection] = {}
        self._ui_clients: set[WebSocket] = set()
        self._ui_send_locks: dict[WebSocket, asyncio.Lock] = {}
        self._lock = asyncio.Lock()
        self._send_timeout_seconds = max(0.1, float(send_timeout_seconds))

    def set_send_timeout_seconds(self, timeout_seconds: float) -> None:
        self._send_timeout_seconds = max(0.1, float(timeout_seconds))

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
        await self._close_websocket(connection.websocket, code=code, reason=reason)
        return True

    async def register_ui(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._ui_clients.add(websocket)
            self._ui_send_locks.setdefault(websocket, asyncio.Lock())

    async def unregister_ui(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._ui_clients.discard(websocket)
            self._ui_send_locks.pop(websocket, None)

    async def connected_ui_count(self) -> int:
        async with self._lock:
            return len(self._ui_clients)

    async def is_agent_connected(self, node_id: str) -> bool:
        async with self._lock:
            return node_id in self._agents

    async def send_command(self, node_id: str, command: dict[str, Any], timeout_seconds: int = 30) -> bool:
        async with self._lock:
            connection = self._agents.get(node_id)
        if not connection:
            return False

        message = {
            "type": "command",
            "request_id": command["id"],
            "command_id": command["id"],
            "action": command["action"],
            "payload": command.get("payload") or {},
            "timeout_seconds": timeout_seconds,
        }
        try:
            await asyncio.wait_for(
                self._send_agent_message(connection, message),
                timeout=self._send_timeout_seconds,
            )
            return True
        except (Exception, asyncio.TimeoutError):
            async with self._lock:
                if self._agents.get(node_id) is connection:
                    self._agents.pop(node_id, None)
            await self._close_websocket(
                connection.websocket,
                code=1011,
                reason="command delivery failed",
            )
            return False

    @staticmethod
    async def _send_agent_message(connection: AgentConnection, message: dict[str, Any]) -> None:
        async with connection.send_lock:
            await connection.websocket.send_json(message)

    async def broadcast_ui(self, message: dict[str, Any]) -> None:
        async with self._lock:
            clients = list(self._ui_clients)

        results = await asyncio.gather(
            *(self._send_ui_message(websocket, message) for websocket in clients),
            return_exceptions=False,
        )
        stale = [websocket for websocket, sent in zip(clients, results) if not sent]

        if stale:
            async with self._lock:
                for websocket in stale:
                    self._ui_clients.discard(websocket)
                    self._ui_send_locks.pop(websocket, None)
            await asyncio.gather(
                *(self._close_websocket(websocket, code=1011, reason="websocket send failed") for websocket in stale),
                return_exceptions=False,
            )

    async def _send_ui_message(self, websocket: WebSocket, message: dict[str, Any]) -> bool:
        async with self._lock:
            send_lock = self._ui_send_locks.get(websocket)
        if send_lock is None:
            return False
        try:
            await asyncio.wait_for(
                self._send_ui_message_locked(websocket, send_lock, message),
                timeout=self._send_timeout_seconds,
            )
            return True
        except (Exception, asyncio.TimeoutError):
            return False

    @staticmethod
    async def _send_ui_message_locked(
        websocket: WebSocket,
        send_lock: asyncio.Lock,
        message: dict[str, Any],
    ) -> None:
        async with send_lock:
            await websocket.send_json(message)

    async def _close_websocket(self, websocket: WebSocket, code: int, reason: str) -> None:
        try:
            await asyncio.wait_for(
                websocket.close(code=code, reason=reason),
                timeout=self._send_timeout_seconds,
            )
        except Exception:
            pass
