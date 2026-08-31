"""
Dashboard tab: at-a-glance stat cards + live packets/sec and connections
graphs rendered with Matplotlib embedded inside the CustomTkinter frame.
"""
from __future__ import annotations

from collections import deque

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from netsentry.gui.widgets import StatCard

MAX_POINTS = 60  # ~ last 60 samples on the live graphs


class DashboardTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        self.pps_history: deque[float] = deque(maxlen=MAX_POINTS)
        self.conn_history: deque[int] = deque(maxlen=MAX_POINTS)

        self._build_stat_cards()
        self._build_graphs()

    # -- layout --------------------------------------------------------

    def _build_stat_cards(self):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=(10, 0))
        for i in range(4):
            row.grid_columnconfigure(i, weight=1)

        self.card_packets = StatCard(row, "PACKETS / SEC", "0.0", accent="#22c55e")
        self.card_connections = StatCard(row, "ACTIVE CONNECTIONS", "0", accent="#3b82f6")
        self.card_alerts = StatCard(row, "TOTAL ALERTS", "0", accent="#ef4444")
        self.card_remote_ips = StatCard(row, "UNIQUE REMOTE IPs", "0", accent="#a855f7")

        self.card_packets.grid(row=0, column=0, sticky="ew", padx=6)
        self.card_connections.grid(row=0, column=1, sticky="ew", padx=6)
        self.card_alerts.grid(row=0, column=2, sticky="ew", padx=6)
        self.card_remote_ips.grid(row=0, column=3, sticky="ew", padx=6)

    def _build_graphs(self):
        graph_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=12)
        graph_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.fig = Figure(figsize=(8, 4), dpi=100, facecolor="#1a1a1a")
        self.ax_pps = self.fig.add_subplot(211)
        self.ax_conn = self.fig.add_subplot(212)

        for ax, title, color in (
            (self.ax_pps, "Packets / sec", "#22c55e"),
            (self.ax_conn, "Active connections", "#3b82f6"),
        ):
            ax.set_facecolor("#1a1a1a")
            ax.set_title(title, color="#e5e5e5", fontsize=9, loc="left")
            ax.tick_params(colors="#9ca3af", labelsize=7)
            for spine in ax.spines.values():
                spine.set_color("#333333")

        self.fig.tight_layout(pad=2.0)

        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

    # -- updates -------------------------------------------------------

    def update_stats(self, *, pps: float, active_connections: int,
                      total_alerts: int, unique_remote_ips: int):
        self.card_packets.set_value(f"{pps:.1f}")
        self.card_connections.set_value(str(active_connections))
        self.card_alerts.set_value(str(total_alerts))
        self.card_remote_ips.set_value(str(unique_remote_ips))

        self.pps_history.append(pps)
        self.conn_history.append(active_connections)
        self._redraw()

    def _redraw(self):
        self.ax_pps.cla()
        self.ax_conn.cla()

        self.ax_pps.plot(list(self.pps_history), color="#22c55e", linewidth=1.5)
        self.ax_pps.fill_between(range(len(self.pps_history)), list(self.pps_history),
                                  color="#22c55e", alpha=0.15)
        self.ax_conn.plot(list(self.conn_history), color="#3b82f6", linewidth=1.5)
        self.ax_conn.fill_between(range(len(self.conn_history)), list(self.conn_history),
                                   color="#3b82f6", alpha=0.15)

        for ax, title in ((self.ax_pps, "Packets / sec"), (self.ax_conn, "Active connections")):
            ax.set_facecolor("#1a1a1a")
            ax.set_title(title, color="#e5e5e5", fontsize=9, loc="left")
            ax.tick_params(colors="#9ca3af", labelsize=7)
            for spine in ax.spines.values():
                spine.set_color("#333333")

        self.fig.tight_layout(pad=2.0)
        self.canvas.draw_idle()
