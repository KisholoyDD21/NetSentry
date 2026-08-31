"""
Rule-based threat detection engine.

Consumes connection snapshots (from network_monitor), raw packets and DNS
queries (from packet_analyzer), and produces alert dicts that get persisted
via Database.insert_alert() and forwarded to the GUI.

Detections implemented:
  - Port-scan detection        (many distinct local ports probed by one remote IP)
  - Excessive connections      (one remote IP opening unusually many connections)
  - Brute-force patterns       (repeated hits on sensitive ports: SSH/RDP/SMB/DB)
  - Suspicious DNS activity    (query floods, DGA-like/high-entropy domains, bad TLDs)
  - Unusual traffic spikes     (packets/sec far above the recent baseline)
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable

from netsentry.database import Database
from netsentry.utils import load_config, now_iso, setup_logger, shannon_entropy, is_private_ip

logger = setup_logger(__name__)


class ThreatDetectionEngine:
    def __init__(self, db: Database, on_alert: Callable[[dict], None]):
        self.db = db
        self.on_alert = on_alert
        cfg = load_config()["threat_detection"]
        self.cfg = cfg
        self._lock = threading.Lock()

        # remote_ip -> deque[(timestamp, local_port)]
        self._port_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        # remote_ip -> deque[timestamp]  (any connection)
        self._conn_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        # (remote_ip, target_port) -> deque[timestamp]
        self._bruteforce_hits: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=2000))
        # src_ip -> deque[timestamp]  (DNS queries)
        self._dns_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))

        # traffic-spike baseline: fixed-size deque of (timestamp,) for all packets
        self._packet_times: deque = deque(maxlen=20000)

        # cooldown so one ongoing scan doesn't spam duplicate alerts
        self._last_alert_at: dict[str, float] = {}
        self._alert_cooldown_seconds = 30

    # -- helpers ------------------------------------------------------

    def _cooldown_ok(self, key: str) -> bool:
        last = self._last_alert_at.get(key, 0)
        if time.time() - last >= self._alert_cooldown_seconds:
            self._last_alert_at[key] = time.time()
            return True
        return False

    def _emit(self, alert_type: str, severity: str, source_ip: str,
               description: str, target_port: int | None = None, details: dict | None = None):
        cooldown_key = f"{alert_type}:{source_ip}:{target_port}"
        if not self._cooldown_ok(cooldown_key):
            return
        alert = {
            "timestamp": now_iso(),
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "target_port": target_port,
            "description": description,
            "details": details or {},
        }
        try:
            self.db.insert_alert(alert)
        except Exception:
            logger.exception("Failed to persist alert")
        self.on_alert(alert)

    @staticmethod
    def _purge(dq: deque, window_seconds: float):
        cutoff = time.time() - window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    @staticmethod
    def _purge_flat(dq: deque, window_seconds: float):
        cutoff = time.time() - window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    # -- connection-based detections -----------------------------------

    def process_connection_snapshot(self, snapshot: list[dict]):
        with self._lock:
            for c in snapshot:
                remote_ip = c.get("remote_addr")
                local_port = c.get("local_port")
                if not remote_ip or is_private_ip(remote_ip):
                    continue

                now = time.time()

                # -- port scan: distinct local ports touched by one remote IP
                ps_cfg = self.cfg["port_scan"]
                dq = self._port_hits[remote_ip]
                dq.append((now, local_port))
                self._purge(dq, ps_cfg["window_seconds"])
                distinct_ports = {p for _, p in dq}
                if len(distinct_ports) >= ps_cfg["distinct_ports_threshold"]:
                    self._emit(
                        "port_scan", "high", remote_ip,
                        f"{remote_ip} probed {len(distinct_ports)} distinct ports "
                        f"in {ps_cfg['window_seconds']}s",
                        details={"ports": sorted(distinct_ports)[:50]},
                    )

                # -- excessive connections from one remote IP
                ec_cfg = self.cfg["excessive_connections"]
                cdq = self._conn_hits[remote_ip]
                cdq.append(now)
                self._purge_flat(cdq, ec_cfg["window_seconds"])
                if len(cdq) >= ec_cfg["connection_threshold"]:
                    self._emit(
                        "excessive_connections", "medium", remote_ip,
                        f"{remote_ip} opened {len(cdq)} connections in "
                        f"{ec_cfg['window_seconds']}s",
                    )

                # -- brute-force pattern on sensitive ports
                bf_cfg = self.cfg["brute_force"]
                target_port = local_port
                if target_port in bf_cfg["target_ports"]:
                    key = (remote_ip, target_port)
                    bdq = self._bruteforce_hits[key]
                    bdq.append(now)
                    self._purge_flat(bdq, bf_cfg["window_seconds"])
                    if len(bdq) >= bf_cfg["attempt_threshold"]:
                        self._emit(
                            "brute_force", "critical", remote_ip,
                            f"{remote_ip} made {len(bdq)} attempts on port "
                            f"{target_port} in {bf_cfg['window_seconds']}s "
                            "(possible brute-force)",
                            target_port=target_port,
                        )

    # -- packet-based detections -----------------------------------------

    def process_packet(self, pkt: dict):
        with self._lock:
            self._packet_times.append(time.time())
            self._maybe_check_traffic_spike()

    def _maybe_check_traffic_spike(self):
        cfg = self.cfg["traffic_spike"]
        window = cfg["baseline_window_seconds"]
        now = time.time()

        # split the retained window into two halves: baseline vs "current"
        half = window / 2
        baseline_count = sum(1 for t in self._packet_times if now - window <= t < now - half)
        current_count = sum(1 for t in self._packet_times if t >= now - half)

        baseline_pps = baseline_count / half if half else 0
        current_pps = current_count / half if half else 0

        if baseline_pps < cfg["min_baseline_pps"]:
            return  # not enough traffic yet to establish a meaningful baseline

        if current_pps >= baseline_pps * cfg["spike_multiplier"]:
            self._emit(
                "traffic_spike", "medium", "local",
                f"Traffic spike detected: {current_pps:.1f} pkt/s vs baseline "
                f"{baseline_pps:.1f} pkt/s",
                details={"current_pps": current_pps, "baseline_pps": baseline_pps},
            )

    # -- DNS-based detections ---------------------------------------------

    def process_dns_query(self, src_ip: str, query_name: str):
        with self._lock:
            cfg = self.cfg["dns_anomaly"]
            now = time.time()

            dq = self._dns_hits[src_ip]
            dq.append(now)
            self._purge_flat(dq, cfg["window_seconds"])
            if len(dq) >= cfg["query_rate_threshold"]:
                self._emit(
                    "dns_query_flood", "medium", src_ip,
                    f"{src_ip} issued {len(dq)} DNS queries in "
                    f"{cfg['window_seconds']}s (possible tunneling/exfiltration)",
                )

            label = query_name.split(".")[0] if query_name else ""
            entropy = shannon_entropy(label)
            tld = query_name.rsplit(".", 1)[-1].lower() if "." in query_name else ""

            if len(label) >= 12 and entropy >= cfg["min_entropy_for_dga"]:
                self._emit(
                    "suspicious_dns_domain", "low", src_ip,
                    f"High-entropy domain queried: {query_name} (entropy={entropy:.2f}) "
                    "-- possible DGA/C2 domain",
                    details={"domain": query_name, "entropy": entropy},
                )
            elif tld in cfg["suspicious_tlds"]:
                self._emit(
                    "suspicious_dns_tld", "low", src_ip,
                    f"Query to domain with suspicious TLD: {query_name}",
                    details={"domain": query_name, "tld": tld},
                )
