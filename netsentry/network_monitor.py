"""
Live network connection monitor built on psutil.

Runs in a background thread, polls active OS-level sockets on an interval,
persists new connections to SQLite, and hands each snapshot to a callback
(typically a thread-safe queue consumed by the GUI's polling loop).
"""
from __future__ import annotations

import threading
import time
from typing import Callable

import psutil

from netsentry.database import Database
from netsentry.utils import load_config, now_iso, setup_logger

logger = setup_logger(__name__)

def _protocol_name(kind_family, kind_type) -> str:
    import socket
    if kind_type == socket.SOCK_STREAM:
        return "TCP"
    if kind_type == socket.SOCK_DGRAM:
        return "UDP"
    return "OTHER"


def _addr_to_tuple(addr):
    if not addr:
        return (None, None)
    return (addr.ip, addr.port)


class NetworkMonitor(threading.Thread):
    """Background thread that polls psutil.net_connections()."""

    def __init__(
        self,
        db: Database,
        on_snapshot: Callable[[list[dict]], None],
        interval: float | None = None,
    ):
        super().__init__(daemon=True, name="NetworkMonitorThread")
        self.db = db
        self.on_snapshot = on_snapshot
        config = load_config()
        self.interval = interval or (config["app"]["refresh_interval_ms"] / 1000)
        self._stop_event = threading.Event()
        self._seen_keys: set[tuple] = set()

        # process-name cache to avoid repeated psutil.Process() lookups
        self._proc_name_cache: dict[int, str] = {}

    def stop(self):
        self._stop_event.set()

    def _process_name(self, pid: int | None) -> str:
        if pid is None:
            return ""
        if pid in self._proc_name_cache:
            return self._proc_name_cache[pid]
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = ""
        self._proc_name_cache[pid] = name
        return name

    def poll_once(self) -> list[dict]:
        """Single poll cycle -- also usable synchronously/for testing."""
        results = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Fall back to the current process only if we lack privileges
            # for a system-wide view (common on locked-down Windows accounts).
            conns = psutil.Process().connections(kind="inet")

        ts = now_iso()
        new_rows = []
        current_keys = set()

        for c in conns:
            laddr_ip, laddr_port = _addr_to_tuple(c.laddr)
            raddr_ip, raddr_port = _addr_to_tuple(c.raddr)
            proto = _protocol_name(c.family, c.type)
            status = c.status if proto == "TCP" else "STATELESS"
            pname = self._process_name(c.pid)

            key = (laddr_ip, laddr_port, raddr_ip, raddr_port, proto, c.pid)
            current_keys.add(key)

            row = {
                "timestamp": ts,
                "local_addr": laddr_ip,
                "local_port": laddr_port,
                "remote_addr": raddr_ip,
                "remote_port": raddr_port,
                "protocol": proto,
                "status": status,
                "pid": c.pid,
                "process_name": pname,
            }
            results.append(row)

            if key not in self._seen_keys:
                new_rows.append(row)

        self._seen_keys = current_keys

        if new_rows:
            try:
                self.db.bulk_insert_connections(new_rows)
            except Exception:
                logger.exception("Failed to persist connection snapshot")

        return results

    def run(self):
        logger.info("NetworkMonitor started (interval=%.2fs)", self.interval)
        while not self._stop_event.is_set():
            try:
                snapshot = self.poll_once()
                self.on_snapshot(snapshot)
            except Exception:
                logger.exception("NetworkMonitor poll failed")
            self._stop_event.wait(self.interval)
        logger.info("NetworkMonitor stopped")


def connection_summary(snapshot: list[dict]) -> dict:
    """Quick aggregate stats used by the dashboard tab."""
    tcp = sum(1 for c in snapshot if c["protocol"] == "TCP")
    udp = sum(1 for c in snapshot if c["protocol"] == "UDP")
    established = sum(1 for c in snapshot if c.get("status") == "ESTABLISHED")
    remote_ips = {c["remote_addr"] for c in snapshot if c["remote_addr"]}
    return {
        "total": len(snapshot),
        "tcp": tcp,
        "udp": udp,
        "established": established,
        "unique_remote_ips": len(remote_ips),
    }
