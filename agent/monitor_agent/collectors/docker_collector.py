from __future__ import annotations

from typing import Any

try:
    import docker
    from docker.errors import DockerException, NotFound
except ImportError:  # pragma: no cover
    docker = None
    DockerException = Exception
    NotFound = Exception


class DockerCollector:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.client: Any | None = None
        self.error: str | None = None
        self._connect()

    def _connect(self) -> None:
        if not self.enabled:
            self.error = "disabled"
            return
        if docker is None:
            self.error = "docker python package is not installed"
            return
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.error = None
        except DockerException as exc:
            self.client = None
            self.error = str(exc)

    def info(self) -> dict[str, Any]:
        if not self.client:
            self._connect()
        if not self.client:
            return {
                "available": False,
                "version": None,
                "error": self.error,
            }
        try:
            version = self.client.version().get("Version")
            return {
                "available": True,
                "version": version,
                "error": None,
            }
        except DockerException as exc:
            self.client = None
            self.error = str(exc)
            return {
                "available": False,
                "version": None,
                "error": self.error,
            }

    def inventory(self) -> list[dict[str, Any]]:
        if not self.client:
            self._connect()
        if not self.client:
            return []

        try:
            containers = self.client.containers.list(all=True)
        except DockerException as exc:
            self.client = None
            self.error = str(exc)
            return []

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
        return items

    def stats(self) -> list[dict[str, Any]]:
        if not self.client:
            self._connect()
        if not self.client:
            return []

        try:
            containers = self.client.containers.list(all=False)
        except DockerException as exc:
            self.client = None
            self.error = str(exc)
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
        if not self.client:
            self._connect()
        if not self.client:
            return False, self.error or "docker is not available"

        try:
            container = self.client.containers.get(container_id)
            if action == "container.start":
                container.start()
                return True, "container started"
            if action == "container.stop":
                container.stop(timeout=10)
                return True, "container stopped"
            if action == "container.restart":
                container.restart(timeout=10)
                return True, "container restarted"
            return False, f"unsupported action: {action}"
        except NotFound:
            return False, "container not found"
        except DockerException as exc:
            return False, str(exc)


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
