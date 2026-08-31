"""
Packet capture and protocol analysis built on Scapy.

Requires libpcap/Npcap and, on most systems, administrator/root privileges.
The GUI is expected to catch PermissionError / OSError raised on start() and
show a friendly message rather than crash -- NetSentry's connection-level
monitoring (network_monitor.py) works fully without this module.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Optional

from netsentry.database import Database
from netsentry.utils import load_config, now_iso, setup_logger

logger = setup_logger(__name__)


class ScapyUnavailableError(RuntimeError):
    """Raised when Scapy / the capture backend cannot be used."""


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.warning("Could not list interfaces: %s", exc)
        return []


def _classify_packet(pkt) -> dict | None:
    """Extract a normalized dict of fields from a Scapy packet."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet6 import IPv6

    ts = now_iso()
    length = len(pkt)

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    else:
        return None  # non-IP traffic (ARP, etc.) -- ignored for this tool

    src_port = dst_port = None
    protocol = "OTHER"
    summary = pkt.summary()
    dns_info = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        if pkt.haslayer(DNS):
            protocol = "DNS"
        elif dst_port in (80, 8080) or src_port in (80, 8080):
            protocol = "HTTP"
        elif dst_port == 443 or src_port == 443:
            protocol = "TLS/HTTPS"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        if pkt.haslayer(DNS):
            protocol = "DNS"
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            qtype = pkt[DNSQR].qtype
            dns_info = {"query_name": qname, "query_type": str(qtype)}
        except Exception:
            dns_info = None

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "summary": summary,
        "dns": dns_info,
    }


class PacketAnalyzer(threading.Thread):
    """Background thread wrapping scapy.sniff with a non-blocking stop."""

    def __init__(
        self,
        db: Database,
        on_packet: Callable[[dict], None],
        interface: Optional[str] = None,
        bpf_filter: str = "",
    ):
        super().__init__(daemon=True, name="PacketAnalyzerThread")
        self.db = db
        self.on_packet = on_packet
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._error: Optional[Exception] = None

        self.pps_window: deque[float] = deque(maxlen=2048)  # timestamps for pkts/sec
        self.protocol_counter: dict[str, int] = {}

    @property
    def error(self) -> Optional[Exception]:
        return self._error

    def stop(self):
        self._stop_event.set()

    def packets_per_second(self, window_seconds: float = 5.0) -> float:
        cutoff = time.time() - window_seconds
        recent = [t for t in self.pps_window if t >= cutoff]
        return len(recent) / window_seconds if window_seconds > 0 else 0.0

    def _handle(self, pkt):
        try:
            info = _classify_packet(pkt)
        except Exception:
            logger.exception("Failed to parse packet")
            return
        if info is None:
            return

        self.pps_window.append(time.time())
        self.protocol_counter[info["protocol"]] = (
            self.protocol_counter.get(info["protocol"], 0) + 1
        )

        dns_info = info.pop("dns", None)
        try:
            self.db.insert_packet(info)
            if dns_info:
                self.db.insert_dns_query(
                    info["src_ip"], dns_info["query_name"], dns_info["query_type"]
                )
        except Exception:
            logger.exception("Failed to persist packet")

        if dns_info:
            info = {**info, **dns_info}
        self.on_packet(info)

    def run(self):
        try:
            from scapy.all import sniff
        except Exception as exc:  # pragma: no cover
            self._error = ScapyUnavailableError(
                f"Scapy is not available: {exc}"
            )
            logger.error(str(self._error))
            return

        logger.info(
            "PacketAnalyzer starting on interface=%s filter=%r",
            self.interface or "default",
            self.bpf_filter,
        )
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=self._handle,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            self._error = exc
            logger.error(
                "Permission denied capturing packets. Run as Administrator/root "
                "and ensure Npcap (Windows) or libpcap (Linux/macOS) is installed."
            )
        except OSError as exc:
            self._error = exc
            logger.error("Capture backend error: %s", exc)
        except Exception as exc:  # pragma: no cover
            self._error = exc
            logger.exception("Unexpected packet capture failure")
        logger.info("PacketAnalyzer stopped")
