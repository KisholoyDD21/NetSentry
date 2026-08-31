"""
SQLite persistence layer for NetSentry.

A single connection is shared across threads, guarded by a lock, since the
monitor, packet-capture, and threat-detection threads all need to write
concurrently while the GUI thread reads for display.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterable

from netsentry.utils import load_config, resolve_path, now_iso, setup_logger

logger = setup_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    protocol TEXT,
    status TEXT,
    pid INTEGER,
    process_name TEXT
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    query_name TEXT,
    query_type TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    target_port INTEGER,
    description TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS ip_intel_cache (
    ip TEXT PRIMARY KEY,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    isp TEXT,
    org TEXT,
    asn TEXT,
    whois_json TEXT,
    reputation_score INTEGER,
    reputation_label TEXT,
    cached_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(timestamp);
"""


class Database:
    """Thread-safe wrapper around a single sqlite3 connection."""

    def __init__(self, db_path: str | None = None):
        config = load_config()
        path = db_path or config["database"]["path"]
        self._path = resolve_path(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @contextmanager
    def cursor(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    # -- connections ---------------------------------------------------

    def insert_connection(self, conn_info: dict):
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO connections
                   (timestamp, local_addr, local_port, remote_addr, remote_port,
                    protocol, status, pid, process_name)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    conn_info.get("timestamp", now_iso()),
                    conn_info.get("local_addr"),
                    conn_info.get("local_port"),
                    conn_info.get("remote_addr"),
                    conn_info.get("remote_port"),
                    conn_info.get("protocol"),
                    conn_info.get("status"),
                    conn_info.get("pid"),
                    conn_info.get("process_name"),
                ),
            )

    def bulk_insert_connections(self, rows: Iterable[dict]):
        rows = list(rows)
        if not rows:
            return
        with self.cursor() as cur:
            cur.executemany(
                """INSERT INTO connections
                   (timestamp, local_addr, local_port, remote_addr, remote_port,
                    protocol, status, pid, process_name)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        r.get("timestamp", now_iso()),
                        r.get("local_addr"),
                        r.get("local_port"),
                        r.get("remote_addr"),
                        r.get("remote_port"),
                        r.get("protocol"),
                        r.get("status"),
                        r.get("pid"),
                        r.get("process_name"),
                    )
                    for r in rows
                ],
            )

    def recent_connections(self, limit: int = 200) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM connections ORDER BY id DESC LIMIT ?", (limit,)
            )
            return cur.fetchall()

    # -- packets ---------------------------------------------------------

    def insert_packet(self, pkt: dict):
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO packets
                   (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, summary)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    pkt.get("timestamp", now_iso()),
                    pkt.get("src_ip"),
                    pkt.get("dst_ip"),
                    pkt.get("src_port"),
                    pkt.get("dst_port"),
                    pkt.get("protocol"),
                    pkt.get("length"),
                    pkt.get("summary"),
                ),
            )

    def recent_packets(self, limit: int = 200) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,))
            return cur.fetchall()

    def protocol_counts(self, since_seconds: int = 3600) -> dict[str, int]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT protocol, COUNT(*) as c FROM packets
                   WHERE timestamp >= datetime('now', ?)
                   GROUP BY protocol""",
                (f"-{since_seconds} seconds",),
            )
            return {row["protocol"]: row["c"] for row in cur.fetchall()}

    # -- dns ---------------------------------------------------------------

    def insert_dns_query(self, src_ip: str, query_name: str, query_type: str):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO dns_queries (timestamp, src_ip, query_name, query_type) VALUES (?,?,?,?)",
                (now_iso(), src_ip, query_name, query_type),
            )

    def recent_dns_queries(self, limit: int = 200) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM dns_queries ORDER BY id DESC LIMIT ?", (limit,)
            )
            return cur.fetchall()

    # -- alerts --------------------------------------------------------

    def insert_alert(self, alert: dict):
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO alerts
                   (timestamp, alert_type, severity, source_ip, target_port, description, details)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    alert.get("timestamp", now_iso()),
                    alert["alert_type"],
                    alert.get("severity", "medium"),
                    alert.get("source_ip"),
                    alert.get("target_port"),
                    alert.get("description", ""),
                    json.dumps(alert.get("details", {})),
                ),
            )
        logger.warning(
            "ALERT [%s] %s - %s",
            alert.get("severity", "medium").upper(),
            alert["alert_type"],
            alert.get("description", ""),
        )

    def recent_alerts(self, limit: int = 200) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            return cur.fetchall()

    def alert_counts_by_severity(self) -> dict[str, int]:
        with self.cursor() as cur:
            cur.execute("SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity")
            return {row["severity"]: row["c"] for row in cur.fetchall()}

    # -- ip intel cache --------------------------------------------------

    def get_ip_cache(self, ip: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM ip_intel_cache WHERE ip = ?", (ip,))
            return cur.fetchone()

    def upsert_ip_cache(self, ip: str, data: dict):
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO ip_intel_cache
                   (ip, country, country_code, region, city, isp, org, asn,
                    whois_json, reputation_score, reputation_label, cached_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     country=excluded.country, country_code=excluded.country_code,
                     region=excluded.region, city=excluded.city, isp=excluded.isp,
                     org=excluded.org, asn=excluded.asn, whois_json=excluded.whois_json,
                     reputation_score=excluded.reputation_score,
                     reputation_label=excluded.reputation_label,
                     cached_at=excluded.cached_at""",
                (
                    ip,
                    data.get("country"),
                    data.get("country_code"),
                    data.get("region"),
                    data.get("city"),
                    data.get("isp"),
                    data.get("org"),
                    data.get("asn"),
                    json.dumps(data.get("whois", {})),
                    data.get("reputation_score"),
                    data.get("reputation_label"),
                    now_iso(),
                ),
            )

    # -- maintenance -------------------------------------------------------

    def prune_old_rows(self, table: str, keep_last: int = 20000):
        """Keep tables from growing unbounded during long monitoring sessions."""
        with self.cursor() as cur:
            cur.execute(
                f"""DELETE FROM {table} WHERE id NOT IN (
                        SELECT id FROM {table} ORDER BY id DESC LIMIT ?
                    )""",
                (keep_last,),
            )

    def close(self):
        with self._lock:
            self._conn.close()
