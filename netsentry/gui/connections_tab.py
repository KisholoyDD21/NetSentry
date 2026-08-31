"""
Connections tab: live table of active OS-level sockets (from psutil),
with a text filter over IP / process name.
"""
from __future__ import annotations

import customtkinter as ctk

from netsentry.gui.widgets import build_table

COLUMNS = ["Time", "Local Address", "Remote Address", "Protocol", "Status", "PID", "Process"]


class ConnectionsTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._latest_rows: list[dict] = []

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(toolbar, text="Filter:").pack(side="left", padx=(0, 6))
        self.filter_var = ctk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._render())
        entry = ctk.CTkEntry(toolbar, textvariable=self.filter_var,
                              placeholder_text="IP address or process name")
        entry.pack(side="left", fill="x", expand=True)

        self.count_label = ctk.CTkLabel(toolbar, text="0 connections")
        self.count_label.pack(side="right", padx=(10, 0))

        self.tree = build_table(self, COLUMNS, height=20)

    def update_connections(self, snapshot: list[dict]):
        self._latest_rows = snapshot
        self._render()

    def _render(self):
        needle = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())

        rows = self._latest_rows
        if needle:
            rows = [
                r for r in rows
                if needle in (r.get("remote_addr") or "").lower()
                or needle in (r.get("local_addr") or "").lower()
                or needle in (r.get("process_name") or "").lower()
            ]

        for r in rows[:1000]:
            local = f"{r.get('local_addr') or '-'}:{r.get('local_port') or '-'}"
            remote = f"{r.get('remote_addr') or '-'}:{r.get('remote_port') or '-'}"
            self.tree.insert("", "end", values=(
                r.get("timestamp", "")[-8:], local, remote,
                r.get("protocol", ""), r.get("status", ""),
                r.get("pid", ""), r.get("process_name", ""),
            ))

        self.count_label.configure(text=f"{len(rows)} connections")
