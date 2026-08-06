from __future__ import annotations

import re
import threading
from typing import Any

try:
    import docker
    from docker.errors import DockerException, NotFound
except ImportError:  # pragma: no cover
    docker = None
    DockerException = Exception
    NotFound = Exception


class DockerCollector:
    def __init__(
        self,
        enabled: bool = True,
        allowed_labels: dict[str, str] | None = None,
        api_timeout_seconds: int = 10,
    ) -> None:
        self.enabled = enabled
        self.allowed_labels = allowed_labels or {"monitor.control-plane.allow": "true"}
        self.api_timeout_seconds = api_timeout_seconds
        self.client: Any | None = None
        self.error: str | None = None
        self._connect_lock = threading.Lock()

    def _connect(self) -> None:
        with self._connect_lock:
            if self.client:
                return
            if not self.enabled:
                self.error = "disabled"
                return
            if docker is None:
                self.error = "docker python package is not installed"
                return
            try:
                self.client = docker.from_env(timeout=self.api_timeout_seconds)
                self.client.ping()
                self.error = None
            except DockerException as exc:
                self.client = None
                self.error = str(exc)

    def _client_or_connect(self) -> Any | None:
        client = self.client
        if client is None:
            self._connect()
            client = self.client
        return client

    def _invalidate_client(self, client: Any, error: Exception) -> None:
        with self._connect_lock:
            if self.client is client:
                self.client = None
            self.error = str(error)

    def info(self) -> dict[str, Any]:
        client = self._client_or_connect()
        if client is None:
            return {
                "available": False,
                "version": None,
                "error": self.error,
            }
        try:
            version = client.version().get("Version")
            return {
                "available": True,
                "version": version,
                "error": None,
            }
        except DockerException as exc:
            self._invalidate_client(client, exc)
            return {
                "available": False,
                "version": None,
                "error": self.error,
            }

    def inventory_snapshot(self) -> dict[str, Any]:
        client = self._client_or_connect()
        if client is None:
            return {
                "ok": False,
                "containers": [],
                "error": self.error or "docker is not available",
            }

        try:
            containers = client.containers.list(all=True)
        except DockerException as exc:
            self._invalidate_client(client, exc)
            return {
                "ok": False,
                "containers": [],
                "error": self.error,
            }

        items: list[dict[str, Any]] = []
        for container in containers:
            attrs = container.attrs or {}
            config = attrs.get("Config") or {}
            network = attrs.get("NetworkSettings") or {}
            image = config.get("Image")
            if not image:
                tags = getattr(container.image, "tags", None) or []
                image = tags[0] if tags else container.image.short_id
            items.append(
                {
                    "id": container.id,
                    "short_id": container.short_id,
                    "name": container.name,
                    "image": image,
                    "status": container.status,
                    "ports": network.get("Ports") or {},
                }
            )
        self.error = None
        return {
            "ok": True,
            "containers": items,
            "error": None,
        }

    def inventory(self) -> list[dict[str, Any]]:
        """Return containers for callers that do not need collection health."""
        return self.inventory_snapshot()["containers"]

    def stats(self) -> list[dict[str, Any]]:
        client = self._client_or_connect()
        if client is None:
            return []

        try:
            containers = client.containers.list(all=False)
        except DockerException as exc:
            self._invalidate_client(client, exc)
            return []

        items: list[dict[str, Any]] = []
        for container in containers:
            try:
                raw = container.stats(stream=False)
            except DockerException:
                continue
            items.append(
                {
                    "id": container.id,
                    "cpu_percent": _calculate_cpu_percent(raw),
                    "memory_usage": _memory_usage(raw),
                    "memory_limit": _memory_limit(raw),
                }
            )
        return items

    def execute(self, action: str, container_id: str) -> tuple[bool, str]:
        if action not in {"container.start", "container.stop", "container.restart"}:
            return False, f"unsupported action: {action}"
        if not re.fullmatch(r"[a-fA-F0-9]{12,128}", container_id):
            return False, "invalid container id"

        client = self._client_or_connect()
        if client is None:
            return False, self.error or "docker is not available"

        try:
            container = client.containers.get(container_id)
            if not self._is_control_allowed(container):
                return False, "container is not labeled for monitor control-plane actions"
            if action == "container.start":
                container.start()
                return True, "container started"
            if action == "container.stop":
                container.stop(timeout=10)
                return True, "container stopped"
            if action == "container.restart":
                container.restart(timeout=10)
                return True, "container restarted"
        except NotFound:
            return False, "container not found"
        except DockerException as exc:
            return False, str(exc)

    def _is_control_allowed(self, container: Any) -> bool:
        if not self.allowed_labels:
            return False
        attrs = container.attrs or {}
        config = attrs.get("Config") or {}
        labels = config.get("Labels") or {}
        return all(str(labels.get(key)) == str(value) for key, value in self.allowed_labels.items())


def _calculate_cpu_percent(stats: dict[str, Any]) -> float:
    cpu_stats = stats.get("cpu_stats") or {}
    precpu_stats = stats.get("precpu_stats") or {}
    cpu_usage = cpu_stats.get("cpu_usage") or {}
    precpu_usage = precpu_stats.get("cpu_usage") or {}

    cpu_delta = float(cpu_usage.get("total_usage", 0) - precpu_usage.get("total_usage", 0))
    system_delta = float(cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0))
    online_cpus = cpu_stats.get("online_cpus") or len(cpu_usage.get("percpu_usage") or []) or 1

    if cpu_delta <= 0 or system_delta <= 0:
        return 0.0
    return round((cpu_delta / system_delta) * float(online_cpus) * 100.0, 2)


def _memory_usage(stats: dict[str, Any]) -> int:
    memory_stats = stats.get("memory_stats") or {}
    usage = int(memory_stats.get("usage") or 0)
    cache = int((memory_stats.get("stats") or {}).get("cache") or 0)
    return max(0, usage - cache)


def _memory_limit(stats: dict[str, Any]) -> int:
    memory_stats = stats.get("memory_stats") or {}
    return int(memory_stats.get("limit") or 0)
