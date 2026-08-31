"""
IP Intelligence tab: manual WHOIS/ASN/geo/reputation lookups, plus a
one-click batch lookup of every distinct public remote IP currently seen
in active connections. Lookups run on background threads (via asyncio in
ip_intelligence.py) and results are drained from a thread-safe queue on
the Tkinter main loop, keeping the GUI responsive.
"""
from __future__ import annotations

import json
import queue
import threading

import customtkinter as ctk

from netsentry.gui.widgets import build_table
from netsentry.utils import is_private_ip

COLUMNS = ["IP", "Country", "ISP / Org", "ASN", "Reputation"]


class IPIntelTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._results_queue: "queue.Queue" = queue.Queue()
        self._raw_by_ip: dict[str, dict] = {}

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=10, pady=(10, 0))

        self.ip_var = ctk.StringVar()
        ctk.CTkEntry(toolbar, textvariable=self.ip_var, width=200,
                     placeholder_text="e.g. 8.8.8.8").pack(side="left")
        ctk.CTkButton(toolbar, text="Lookup", width=90,
                      command=self._lookup_single).pack(side="left", padx=6)
        ctk.CTkButton(toolbar, text="Lookup all active remote IPs", width=200,
                      command=self._lookup_active).pack(side="left", padx=6)

        self.status_label = ctk.CTkLabel(toolbar, text="", text_color="#9ca3af")
        self.status_label.pack(side="right")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        table_holder = ctk.CTkFrame(body, fg_color="transparent")
        table_holder.grid(row=0, column=0, sticky="nsew")
        self.tree = build_table(table_holder, COLUMNS, height=18)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        detail_holder = ctk.CTkFrame(body, fg_color="#1a1a1a", corner_radius=12)
        detail_holder.grid(row=0, column=1, sticky="nsew", padx=(10, 10), pady=10)
        ctk.CTkLabel(detail_holder, text="Details / raw WHOIS", font=ctk.CTkFont(weight="bold")).pack(
            anchor="w", padx=12, pady=(12, 4)
        )
        self.detail_box = ctk.CTkTextbox(detail_holder, wrap="word", font=("Consolas", 11))
        self.detail_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.after(400, self._poll_results)

    # -- actions -------------------------------------------------------

    def _lookup_single(self):
        ip = self.ip_var.get().strip()
        if not ip:
            return
        self._dispatch([ip])

    def _lookup_active(self):
        conns = self.app.get_latest_connection_snapshot()
        ips = sorted({
            c.get("remote_addr") for c in conns
            if c.get("remote_addr") and not is_private_ip(c["remote_addr"])
        })
        if not ips:
            self.status_label.configure(text="No public remote IPs currently active")
            return
        self._dispatch(ips)

    def _dispatch(self, ips: list[str]):
        self.status_label.configure(text=f"Looking up {len(ips)} IP(s)...")

        def worker():
            try:
                results = self.app.ip_intel.batch_lookup(ips)
            except Exception as exc:
                results = {}
                self._results_queue.put(("__error__", str(exc)))
            for ip, data in results.items():
                self._results_queue.put((ip, data))
            self._results_queue.put(("__done__", len(results)))

        threading.Thread(target=worker, daemon=True).start()

    # -- queue draining (runs on the Tk main loop) ---------------------

    def _poll_results(self):
        try:
            while True:
                ip, data = self._results_queue.get_nowait()
                if ip == "__done__":
                    self.status_label.configure(text=f"Done ({data} looked up)")
                elif ip == "__error__":
                    self.status_label.configure(text=f"Error: {data}")
                else:
                    self._add_result(ip, data)
        except queue.Empty:
            pass
        self.after(400, self._poll_results)

    def _add_result(self, ip: str, data: dict):
        self._raw_by_ip[ip] = data
        # replace existing row for this IP if present
        for item in self.tree.get_children():
            if self.tree.item(item, "values")[0] == ip:
                self.tree.delete(item)
                break
        country = data.get("country") or "-"
        org = data.get("org") or data.get("isp") or "-"
        asn = str(data.get("asn") or "-")
        rep = f"{data.get('reputation_score', '-')} ({data.get('reputation_label', 'unknown')})"
        self.tree.insert("", 0, values=(ip, country, org, asn, rep))

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0], "values")[0]
        data = self._raw_by_ip.get(ip, {})
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("1.0", json.dumps(data, indent=2, default=str))
