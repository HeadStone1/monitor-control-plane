from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .config import AlertNotificationConfig, AlertWebhookConfig


AuditCallback = Callable[..., None]
LOGGER = logging.getLogger("monitor.alerts")


@dataclass(slots=True)
class _NotificationJob:
    webhook: AlertWebhookConfig
    event: dict[str, Any]


class AlertNotifier:
    def __init__(
        self,
        config: AlertNotificationConfig,
        audit_callback: AuditCallback,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._audit = audit_callback
        self._transport = transport
        self._queue: asyncio.Queue[_NotificationJob] = asyncio.Queue(maxsize=config.queue_size)
        self._client: httpx.AsyncClient | None = None
        self._workers: list[asyncio.Task[None]] = []
        self._delivered = 0
        self._failed = 0
        self._dropped = 0
        self._inflight = 0

    async def start(self) -> None:
        if self._workers or not self._config.enabled or not self._enabled_webhooks():
            return
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._config.request_timeout_seconds),
            follow_redirects=False,
            transport=self._transport,
            trust_env=False,
        )
        self._workers = [
            asyncio.create_task(self._worker(), name=f"alert-notifier-{index + 1}")
            for index in range(self._config.worker_count)
        ]

    async def stop(self, reason: str = "shutdown") -> None:
        abandoned = self._queue.qsize() + self._inflight
        workers, self._workers = self._workers, []
        for worker in workers:
            worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self._queue.task_done()
        if abandoned:
            self._dropped += abandoned
            self._audit(
                event_type="alert_notification_dropped",
                actor="system",
                target="alert-notifier",
                result=reason,
                detail={"jobs": abandoned, "reason": reason},
            )
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    def enqueue(self, event: dict[str, Any]) -> int:
        if not self._workers:
            return 0
        accepted = 0
        for webhook in self._enabled_webhooks():
            try:
                self._queue.put_nowait(_NotificationJob(webhook=webhook, event=dict(event)))
                accepted += 1
            except asyncio.QueueFull:
                self._dropped += 1
                self._record(
                    "alert_notification_dropped",
                    webhook,
                    "queue_full",
                    {"event_type": event.get("type"), "queue_size": self._config.queue_size},
                )
        return accepted

    async def join(self) -> None:
        await self._queue.join()

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._config.enabled,
            "configured_webhooks": len(self._enabled_webhooks()),
            "workers_running": sum(not worker.done() for worker in self._workers),
            "queue_depth": self._queue.qsize(),
            "queue_capacity": self._config.queue_size,
            "inflight": self._inflight,
            "delivered": self._delivered,
            "failed": self._failed,
            "dropped": self._dropped,
        }

    def _enabled_webhooks(self) -> list[AlertWebhookConfig]:
        return [webhook for webhook in self._config.webhooks if webhook.enabled]

    async def _worker(self) -> None:
        while True:
            job = await self._queue.get()
            self._inflight += 1
            try:
                await self._deliver(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - final worker isolation guard
                self._failed += 1
                LOGGER.exception("Unexpected alert notification worker failure")
                try:
                    self._record(
                        "alert_notification_failed",
                        job.webhook,
                        "failed",
                        {"event_type": job.event.get("type"), "error_type": type(exc).__name__},
                    )
                except Exception:
                    LOGGER.exception("Failed to audit alert notification worker failure")
            finally:
                self._inflight -= 1
                self._queue.task_done()

    async def _deliver(self, job: _NotificationJob) -> None:
        client = self._client
        if client is None:
            return
        body = json.dumps(job.event, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = hmac.new(
            job.webhook.secret.encode("utf-8"),
            timestamp.encode("ascii") + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "monitor-control-plane/alert-webhook",
            "X-Monitor-Event": str(job.event.get("type") or "alert"),
            "X-Monitor-Timestamp": timestamp,
            "X-Monitor-Signature": f"sha256={signature}",
        }

        last_status: int | None = None
        last_error = ""
        attempts = 0
        for attempts in range(1, self._config.max_attempts + 1):
            retryable = False
            try:
                request = client.build_request("POST", job.webhook.url, content=body, headers=headers)
                response = await client.send(request, stream=True)
                last_status = response.status_code
                await response.aclose()
                if 200 <= last_status < 300:
                    self._delivered += 1
                    self._record(
                        "alert_notification_delivered",
                        job.webhook,
                        "success",
                        {"event_type": job.event.get("type"), "status_code": last_status, "attempts": attempts},
                    )
                    return
                retryable = last_status == 429 or last_status >= 500
                last_error = "retryable_status" if retryable else "non_retryable_status"
            except httpx.HTTPError as exc:
                retryable = True
                last_error = type(exc).__name__

            if not retryable or attempts >= self._config.max_attempts:
                break
            delay = min(self._config.retry_base_seconds * (2 ** (attempts - 1)), 60)
            await asyncio.sleep(delay)

        self._failed += 1
        self._record(
            "alert_notification_failed",
            job.webhook,
            "failed",
            {
                "event_type": job.event.get("type"),
                "status_code": last_status,
                "attempts": attempts,
                "error_type": last_error,
            },
        )

    def _record(
        self,
        event_type: str,
        webhook: AlertWebhookConfig,
        result: str,
        detail: dict[str, Any],
    ) -> None:
        host = urlsplit(webhook.url).hostname or ""
        self._audit(
            event_type=event_type,
            actor="system",
            target=webhook.name,
            result=result,
            detail={"webhook_host": host, **detail},
        )
