from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import random
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
AGENT_PROTOCOL_VERSION = "1"


class CollectionInProgressError(RuntimeError):
    pass


class CollectionTimeoutError(TimeoutError):
    pass


class AgentAuthenticationError(RuntimeError):
    pass


class AgentProtocolError(RuntimeError):
    pass


class MonitorAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.system = SystemCollector()
        self.docker = DockerCollector(
            enabled=config.docker.enabled,
            allowed_labels=config.docker.allowed_labels,
            api_timeout_seconds=config.docker.api_timeout_seconds,
        )
        self.seq = 0
        self._send_lock = asyncio.Lock()
        self._collector_executor = ThreadPoolExecutor(
            max_workers=config.docker.collection_workers,
            thread_name_prefix="monitor-collector",
        )
        self._collector_futures: dict[str, asyncio.Future[Any]] = {}
        self._connected_at: float | None = None

    async def run_forever(self) -> None:
        backoff = self.config.reconnect.initial_seconds
        try:
            while True:
                try:
                    await self._run_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    backoff = self._backoff_after_disconnect(backoff)
                    delay = self._jittered_reconnect_delay(backoff)
                    LOGGER.warning("agent disconnected: %s", exc)
                    LOGGER.info("reconnecting in %.2f seconds", delay)
                    await asyncio.sleep(delay)
                    backoff = min(
                        self.config.reconnect.max_seconds,
                        max(self.config.reconnect.initial_seconds, backoff * 2),
                    )
        finally:
            self.close()

    def close(self) -> None:
        self._collector_executor.shutdown(wait=False, cancel_futures=True)

    async def _run_once(self) -> None:
        self._connected_at = None
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
            LOGGER.info("transport connected; authenticating")
            await self._authenticate(websocket)
            LOGGER.info("authenticated")
            host_info = await self._collect_host_info()
            await self._send(websocket, "hello", host_info)

            tasks = [
                asyncio.create_task(self._heartbeat_loop(websocket)),
                asyncio.create_task(self._metrics_loop(websocket)),
                asyncio.create_task(self._docker_inventory_loop(websocket)),
                asyncio.create_task(self._docker_stats_loop(websocket)),
                asyncio.create_task(self._host_info_loop(websocket)),
                asyncio.create_task(self._receive_loop(websocket)),
            ]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                raise ConnectionError("agent WebSocket closed")
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _authenticate(self, websocket: Any) -> None:
        await self._send_auth(websocket)
        try:
            raw = await asyncio.wait_for(
                websocket.recv(),
                timeout=self.config.reconnect.auth_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise AgentAuthenticationError("server authentication response timed out") from exc

        try:
            response = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AgentAuthenticationError("server returned an invalid authentication response") from exc
        if not isinstance(response, dict) or response.get("type") != "auth_ok":
            reason = str(response.get("error") or "authentication rejected") if isinstance(response, dict) else "authentication rejected"
            raise AgentAuthenticationError(reason)
        protocol_version = str(response.get("protocol_version") or "")
        if protocol_version != AGENT_PROTOCOL_VERSION:
            raise AgentProtocolError(
                f"unsupported server protocol version {protocol_version or 'missing'}; expected {AGENT_PROTOCOL_VERSION}"
            )
        self._connected_at = time.monotonic()

    def _backoff_after_disconnect(self, current_backoff: int) -> int:
        connected_at = self._connected_at
        self._connected_at = None
        if connected_at is not None and time.monotonic() - connected_at >= self.config.reconnect.stable_reset_seconds:
            return self.config.reconnect.initial_seconds
        return current_backoff

    def _jittered_reconnect_delay(self, backoff: int) -> float:
        bounded = min(self.config.reconnect.max_seconds, max(self.config.reconnect.initial_seconds, backoff))
        jitter = bounded * (self.config.reconnect.jitter_percent / 100)
        return max(0.0, bounded + random.uniform(-jitter, jitter))

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
            "protocol_version": AGENT_PROTOCOL_VERSION,
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
            metrics = await self._collect_optional("metrics", self.system.collect)
            if metrics is not None:
                await self._send(websocket, "metrics", metrics)
            await asyncio.sleep(self.config.intervals.metrics)

    async def _docker_inventory_loop(self, websocket: Any) -> None:
        while True:
            inventory = await self._collect_optional("docker_inventory", self.docker.inventory_snapshot)
            if inventory is None:
                inventory = {
                    "ok": False,
                    "containers": [],
                    "error": "docker inventory collection timed out or is still running",
                }
            await self._send(websocket, "docker_inventory", inventory)
            await asyncio.sleep(self.config.intervals.docker_inventory)

    async def _docker_stats_loop(self, websocket: Any) -> None:
        while True:
            stats = await self._collect_optional("docker_stats", self.docker.stats)
            if stats is not None:
                await self._send(websocket, "docker_stats", {"containers": stats})
            await asyncio.sleep(self.config.intervals.docker_stats)

    async def _host_info_loop(self, websocket: Any) -> None:
        while True:
            await asyncio.sleep(self.config.intervals.host_info)
            host_info = await self._collect_optional("host_info", self._host_info)
            if host_info is not None:
                await self._send(websocket, "host_info", host_info)

    async def _collect_host_info(self) -> dict[str, Any]:
        host_info = await self._collect_optional("host_info", self._host_info)
        if host_info is not None:
            return host_info
        return {
            "agent_name": self.config.agent_name,
            "agent_version": "0.1.0",
            "docker": {
                "available": False,
                "version": None,
                "error": "host information collection timed out",
            },
        }

    async def _collect_optional(self, key: str, callback: Any) -> Any | None:
        try:
            return await self._run_blocking_collection(
                key,
                callback,
                self.config.docker.collection_timeout_seconds,
            )
        except (CollectionInProgressError, CollectionTimeoutError) as exc:
            LOGGER.warning("%s", exc)
        except Exception as exc:
            LOGGER.warning("%s collection failed: %s", key, exc)
        return None

    async def _run_blocking_collection(self, key: str, callback: Any, timeout_seconds: int) -> Any:
        existing = self._collector_futures.get(key)
        if existing is not None and not existing.done():
            raise CollectionInProgressError(f"{key} collection is still running")
        if existing is not None:
            self._collector_futures.pop(key, None)

        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(self._collector_executor, callback)
        self._collector_futures[key] = future
        future.add_done_callback(lambda finished, name=key: self._collection_finished(name, finished))
        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout=timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise CollectionTimeoutError(
                f"{key} collection exceeded {timeout_seconds} seconds"
            ) from exc

    def _collection_finished(self, key: str, future: asyncio.Future[Any]) -> None:
        if self._collector_futures.get(key) is future:
            self._collector_futures.pop(key, None)
        if future.cancelled():
            return
        future.exception()

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
        inventory = await self._collect_optional("docker_inventory", self.docker.inventory_snapshot)
        if inventory is None:
            inventory = {
                "ok": False,
                "containers": [],
                "error": "docker inventory collection timed out or is still running",
            }
        await self._send(websocket, "docker_inventory", inventory)


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}
