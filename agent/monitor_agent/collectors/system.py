from __future__ import annotations

import os
import platform
import socket
from pathlib import Path
from typing import Any

import psutil

from ..timeutil import utc_now


AGENT_VERSION = "0.1.0"


def _primary_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def collect_host_info(agent_name: str, docker_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_name": agent_name,
        "agent_version": AGENT_VERSION,
        "hostname": socket.gethostname(),
        "ip": _primary_ip(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "docker": docker_info,
    }


class SystemCollector:
    def __init__(self) -> None:
        psutil.cpu_percent(interval=None)

    def collect(self) -> dict[str, Any]:
        memory = psutil.virtual_memory()
        net = psutil.net_io_counters()
        disk_path = "/" if os.name != "nt" else Path.home().anchor
        disk = psutil.disk_usage(disk_path)
        load1, load5, load15 = self._load_avg()

        return {
            "captured_at": utc_now(),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": memory.percent,
            "disk_percent": disk.percent,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "net_rx": net.bytes_recv,
            "net_tx": net.bytes_sent,
        }

    @staticmethod
    def _load_avg() -> tuple[float, float, float]:
        if hasattr(os, "getloadavg"):
            try:
                values = os.getloadavg()
                return float(values[0]), float(values[1]), float(values[2])
            except OSError:
                pass
        return 0.0, 0.0, 0.0

