from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import Any
from urllib.parse import urlsplit

try:
    from websockets.asyncio.client import connect
except ImportError:  # pragma: no cover
    from websockets import connect

from .collectors.docker_collector import DockerCollector
from .collectors.system import SystemCollector, collect_host_info
from .config import AgentConfig
from .timeutil import utc_now

LOGGER = logging.getLogger("monitor.agent")


class MonitorAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.system = SystemCollector()
        self.docker = DockerCollector(
            enabled=config.docker.enabled,
            allowed_labels=config.docker.allowed_labels,
        )
        self.seq = 0
        self._send_lock = asyncio.Lock()

    async def run_forever(self) -> None:
        backoff = 1
        while True:
            try:
                await self._run_once()
                backoff = 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning("agent disconnected: %s", exc)
                LOGGER.info("reconnecting in %s seconds", backoff)
                await asyncio.sleep(backoff)
                backoff = min(30, backoff * 2)

    async def _run_once(self) -> None:
        url = self._build_url()
        ssl_context = self._ssl_context(url)
        LOGGER.info("connecting to %s", urlsplit(url)._replace(query="...").geturl())

        async with connect(
            url,
            ssl=ssl_context,
            ping_interval=20,
            ping_timeout=20,
            max_size=2_000_000,
        ) as websocket:
            LOGGER.info("connected")
            await self._send_auth(websocket)
            await self._send(websocket, "hello", self._host_info())

            tasks = [
                asyncio.create_task(self._heartbeat_loop(websocket)),
                asyncio.create_task(self._metrics_loop(websocket)),
                asyncio.create_task(self._docker_inventory_loop(websocket)),
                asyncio.create_task(self._docker_stats_loop(websocket)),
                asyncio.create_task(self._host_info_loop(websocket)),
                asyncio.create_task(self._receive_loop(websocket)),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for task in pending:
                task.cancel()
            for task in done:
                task.result()

    def _build_url(self) -> str:
        return self.config.server_url

    def _ssl_context(self, url: str) -> ssl.SSLContext | None:
        parts = urlsplit(url)
        if parts.scheme == "ws":
            if self.config.allow_insecure_transport or _is_loopback_host(parts.hostname or ""):
                return None
            raise ValueError("ws:// is only allowed for loopback hosts unless allow_insecure_transport=true")
        if parts.scheme != "wss":
            return None
        if self.config.tls_verify:
            return ssl.create_default_context()
        raise ValueError("tls_verify=false is not allowed for wss:// connections")

    def _host_info(self) -> dict[str, Any]:
        return collect_host_info(self.config.agent_name, self.docker.info())

    async def _send_auth(self, websocket: Any) -> None:
        message = {
            "type": "auth",
            "agent_id": self.config.agent_id,
            "agent_name": self.config.agent_name,
            "token": self.config.token,
            "agent_version": "0.1.0",
            "protocol_version": "1",
        }
        await websocket.send(json.dumps(message, ensure_ascii=True))

    async def _send(self, websocket: Any, message_type: str, data: dict[str, Any]) -> None:
        self.seq += 1
        message = {
            "type": message_type,
            "agent_id": self.config.agent_id,
            "timestamp": int(time.time()),
            "sent_at": utc_now(),
            "seq": self.seq,
            "data": data,
        }
        async with self._send_lock:
            await websocket.send(json.dumps(message, ensure_ascii=True))

    async def _heartbeat_loop(self, websocket: Any) -> None:
        while True:
            await self._send(websocket, "heartbeat", {})
            await asyncio.sleep(self.config.intervals.heartbeat)

    async def _metrics_loop(self, websocket: Any) -> None:
        while True:
            await self._send(websocket, "metrics", self.system.collect())
            await asyncio.sleep(self.config.intervals.metrics)

    async def _docker_inventory_loop(self, websocket: Any) -> None:
        while True:
            await self._send(websocket, "docker_inventory", {"containers": self.docker.inventory()})
            await asyncio.sleep(self.config.intervals.docker_inventory)

    async def _docker_stats_loop(self, websocket: Any) -> None:
        while True:
            await self._send(websocket, "docker_stats", {"containers": self.docker.stats()})
            await asyncio.sleep(self.config.intervals.docker_stats)

    async def _host_info_loop(self, websocket: Any) -> None:
        while True:
            await asyncio.sleep(self.config.intervals.host_info)
            await self._send(websocket, "host_info", self._host_info())

    async def _receive_loop(self, websocket: Any) -> None:
        async for raw in websocket:
            message = json.loads(raw)
            if message.get("type") == "command":
                await self._handle_command(websocket, message)

    async def _handle_command(self, websocket: Any, message: dict[str, Any]) -> None:
        command_id = str(message.get("command_id") or message.get("request_id") or "")
        request_id = str(message.get("request_id") or command_id)
        action = str(message.get("action") or "")
        payload = message.get("payload") or {}
        container_id = str(payload.get("container_id") or "")

        if not command_id:
            return

        await self._send(
            websocket,
            "command_ack",
            {
                "command_id": command_id,
                "request_id": request_id,
                "status": "received",
            },
        )

        if not container_id:
            await self._send(
                websocket,
                "command_result",
                {
                    "command_id": command_id,
                    "request_id": request_id,
                    "status": "failed",
                    "message": "payload.container_id is required",
                },
            )
            return

        await self._send(
            websocket,
            "command_running",
            {
                "command_id": command_id,
                "request_id": request_id,
                "status": "running",
            },
        )
        ok, result = await asyncio.to_thread(self.docker.execute, action, container_id)
        await self._send(
            websocket,
            "command_result",
            {
                "command_id": command_id,
                "request_id": request_id,
                "status": "success" if ok else "failed",
                "message": result,
            },
        )
        await self._send(websocket, "docker_inventory", {"containers": self.docker.inventory()})


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}
