"""
Threat Detection tab: live-updating alert feed with severity color coding
and a severity filter.
"""
from __future__ import annotations

import customtkinter as ctk

from netsentry.gui.widgets import build_table, prepend_row

COLUMNS = ["Time", "Type", "Severity", "Source IP", "Port", "Description"]
SEVERITIES = ["all", "critical", "high", "medium", "low"]


class ThreatsTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._all_rows: list[dict] = []

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(toolbar, text="Severity:").pack(side="left", padx=(0, 6))
        self.severity_var = ctk.StringVar(value="all")
        ctk.CTkOptionMenu(
            toolbar, variable=self.severity_var, values=SEVERITIES,
            command=lambda _: self._render(),
        ).pack(side="left")

        self.count_label = ctk.CTkLabel(toolbar, text="0 alerts")
        self.count_label.pack(side="right")

        self.tree = build_table(self, COLUMNS, height=20)

    def add_alert(self, alert: dict):
        self._all_rows.insert(0, alert)
        self._all_rows = self._all_rows[:1000]
        self._render()

    def load_initial(self, rows: list[dict]):
        self._all_rows = rows
        self._render()

    def _render(self):
        wanted = self.severity_var.get()
        self.tree.delete(*self.tree.get_children())
        rows = self._all_rows if wanted == "all" else [
            r for r in self._all_rows if r.get("severity") == wanted
        ]
        for a in rows[:500]:
            self.tree.insert("", "end", values=(
                (a.get("timestamp") or "")[-8:], a.get("alert_type"),
                a.get("severity"), a.get("source_ip") or "-",
                a.get("target_port") or "-", a.get("description"),
            ), tags=(a.get("severity"),))
        self.count_label.configure(text=f"{len(rows)} alerts")
