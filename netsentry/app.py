"""
Main application window: wires together the network monitor, packet
analyzer, threat detection engine, IP intelligence, and report generator
behind a CustomTkinter tabbed UI.

Threading model
----------------
- NetworkMonitor and PacketAnalyzer run on their own daemon threads and
  never touch Tkinter widgets directly.
- Their callbacks push data into thread-safe structures (a lock-guarded
  "latest snapshot" for connections, and queue.Queue for packets/alerts).
- App._poll_loop() runs on the Tk main loop via `self.after(...)` and is
  the only place that drains those structures and updates widgets, which
  keeps all Tkinter calls on the main thread as required.
"""
from __future__ import annotations

import queue
import threading
from tkinter import ttk

import customtkinter as ctk

from netsentry.database import Database
from netsentry.ip_intelligence import IPIntelligence
from netsentry.network_monitor import NetworkMonitor, connection_summary
from netsentry.report_generator import ReportGenerator
from netsentry.threat_detection import ThreatDetectionEngine
from netsentry.utils import ensure_dirs, load_config, setup_logger

from netsentry.gui.widgets import style_treeview
from netsentry.gui.dashboard_tab import DashboardTab
from netsentry.gui.connections_tab import ConnectionsTab
from netsentry.gui.packets_tab import PacketsTab
from netsentry.gui.threats_tab import ThreatsTab
from netsentry.gui.ip_intel_tab import IPIntelTab
from netsentry.gui.reports_tab import ReportsTab

logger = setup_logger(__name__)


class App(ctk.CTk):
    def __init__(self):
        ensure_dirs()
        config = load_config()

        ctk.set_appearance_mode(config["app"].get("theme", "dark"))
        ctk.set_default_color_theme(config["app"].get("accent_color", "blue"))

        super().__init__()
        self.title(f"{config['app']['name']} — Network Security Monitor")
        self.geometry("1320x840")
        self.minsize(1040, 680)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        style_treeview(ttk.Style())

        # -- core services ------------------------------------------------
        self.db = Database()
        self.ip_intel = IPIntelligence(self.db)
        self.reports = ReportGenerator(self.db)
        self.threat_engine = ThreatDetectionEngine(self.db, on_alert=self._handle_alert)

        self._snapshot_lock = threading.Lock()
        self._latest_snapshot: list[dict] = []
        self._packet_queue: "queue.Queue" = queue.Queue()
        self._alert_queue: "queue.Queue" = queue.Queue()
        self._total_alerts = 0

        self.active_analyzer = None  # set by PacketsTab when capture starts

        # -- UI -------------------------------------------------------------
        self._build_header()
        self._build_tabs()

        # -- background monitor (connections view works without admin rights)
        self.network_monitor = NetworkMonitor(self.db, on_snapshot=self._handle_snapshot)
        self.network_monitor.start()

        self._load_initial_data()
        self.after(500, self._poll_loop)

    # -- layout --------------------------------------------------------

    def _build_header(self):
        header = ctk.CTkFrame(self, height=56, corner_radius=0, fg_color="#141414")
        header.pack(fill="x", side="top")
        ctk.CTkLabel(
            header, text="🛡  NetSentry", font=ctk.CTkFont(size=20, weight="bold")
        ).pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(
            header, text="Live network monitoring & threat detection",
            font=ctk.CTkFont(size=12), text_color="#9ca3af",
        ).pack(side="left", padx=(0, 20))
        self.monitor_status = ctk.CTkLabel(
            header, text="● Monitoring active", text_color="#22c55e",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.monitor_status.pack(side="right", padx=20)

    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(fill="both", expand=True, padx=12, pady=12)

        names = ["Dashboard", "Connections", "Packet Analyzer", "Threat Detection",
                 "IP Intelligence", "Reports"]
        for n in names:
            self.tabview.add(n)

        self.dashboard_tab = DashboardTab(self.tabview.tab("Dashboard"), self)
        self.dashboard_tab.pack(fill="both", expand=True)

        self.connections_tab = ConnectionsTab(self.tabview.tab("Connections"), self)
        self.connections_tab.pack(fill="both", expand=True)

        self.packets_tab = PacketsTab(self.tabview.tab("Packet Analyzer"), self)
        self.packets_tab.pack(fill="both", expand=True)

        self.threats_tab = ThreatsTab(self.tabview.tab("Threat Detection"), self)
        self.threats_tab.pack(fill="both", expand=True)

        self.ip_intel_tab = IPIntelTab(self.tabview.tab("IP Intelligence"), self)
        self.ip_intel_tab.pack(fill="both", expand=True)

        self.reports_tab = ReportsTab(self.tabview.tab("Reports"), self)
        self.reports_tab.pack(fill="both", expand=True)

    def _load_initial_data(self):
        try:
            rows = [dict(r) for r in self.db.recent_alerts(limit=300)]
            self.threats_tab.load_initial(rows)
            self._total_alerts = len(self.db.recent_alerts(limit=100000))
        except Exception:
            logger.exception("Failed to load historical alerts")

    # -- thread-safe callbacks (called from worker threads) --------------

    def _handle_snapshot(self, snapshot: list[dict]):
        with self._snapshot_lock:
            self._latest_snapshot = snapshot
        try:
            self.threat_engine.process_connection_snapshot(snapshot)
        except Exception:
            logger.exception("Threat engine failed processing connection snapshot")

    def on_packet_captured(self, pkt: dict):
        """Callback passed to PacketAnalyzer -- runs on the capture thread."""
        self._packet_queue.put(pkt)
        try:
            self.threat_engine.process_packet(pkt)
            if pkt.get("query_name"):
                self.threat_engine.process_dns_query(pkt.get("src_ip", ""), pkt["query_name"])
        except Exception:
            logger.exception("Threat engine failed processing packet")

    def _handle_alert(self, alert: dict):
        self._total_alerts += 1
        self._alert_queue.put(alert)

    def get_latest_connection_snapshot(self) -> list[dict]:
        with self._snapshot_lock:
            return list(self._latest_snapshot)

    # -- main-thread poll loop --------------------------------------------

    def _poll_loop(self):
        # drain packets
        drained_packets = 0
        try:
            while drained_packets < 200:
                pkt = self._packet_queue.get_nowait()
                self.packets_tab.add_packet_row(pkt)
                drained_packets += 1
        except queue.Empty:
            pass

        # drain alerts
        try:
            while True:
                alert = self._alert_queue.get_nowait()
                self.threats_tab.add_alert(alert)
        except queue.Empty:
            pass

        # connections + dashboard
        snapshot = self.get_latest_connection_snapshot()
        self.connections_tab.update_connections(snapshot)

        summary = connection_summary(snapshot)
        pps = self.active_analyzer.packets_per_second() if self.active_analyzer else 0.0
        self.dashboard_tab.update_stats(
            pps=pps,
            active_connections=summary["total"],
            total_alerts=self._total_alerts,
            unique_remote_ips=summary["unique_remote_ips"],
        )

        if self.active_analyzer:
            self.packets_tab.update_protocol_breakdown(dict(self.active_analyzer.protocol_counter))

        self.after(700, self._poll_loop)

    # -- shutdown ------------------------------------------------------

    def on_close(self):
        logger.info("Shutting down NetSentry...")
        try:
            self.network_monitor.stop()
        except Exception:
            pass
        try:
            if self.active_analyzer:
                self.active_analyzer.stop()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        self.destroy()
