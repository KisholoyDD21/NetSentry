"""
Packet Analyzer tab: start/stop Scapy capture on a chosen interface, view
parsed packets (TCP/UDP/DNS/HTTP/ICMP) live, and see a protocol breakdown.
"""
from __future__ import annotations

from tkinter import messagebox

import customtkinter as ctk

from netsentry.gui.widgets import build_table
from netsentry.packet_analyzer import PacketAnalyzer, list_interfaces

COLUMNS = ["Time", "Source", "Destination", "Protocol", "Length", "Summary"]


class PacketsTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.analyzer: PacketAnalyzer | None = None

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(toolbar, text="Interface:").pack(side="left")
        interfaces = list_interfaces() or ["default"]
        self.iface_var = ctk.StringVar(value=interfaces[0])
        ctk.CTkOptionMenu(toolbar, variable=self.iface_var, values=interfaces, width=200).pack(
            side="left", padx=(6, 16)
        )

        ctk.CTkLabel(toolbar, text="BPF filter:").pack(side="left")
        self.filter_var = ctk.StringVar(value="")
        ctk.CTkEntry(toolbar, textvariable=self.filter_var, width=180,
                     placeholder_text="e.g. tcp port 443").pack(side="left", padx=(6, 16))

        self.start_btn = ctk.CTkButton(toolbar, text="Start Capture", command=self.start_capture,
                                        fg_color="#16a34a", hover_color="#15803d")
        self.start_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ctk.CTkButton(toolbar, text="Stop Capture", command=self.stop_capture,
                                       fg_color="#dc2626", hover_color="#b91c1c", state="disabled")
        self.stop_btn.pack(side="left")

        self.status_label = ctk.CTkLabel(toolbar, text="Capture stopped", text_color="#9ca3af")
        self.status_label.pack(side="right")

        proto_row = ctk.CTkFrame(self, fg_color="transparent")
        proto_row.pack(fill="x", padx=10, pady=(8, 0))
        self.proto_label = ctk.CTkLabel(proto_row, text="Protocol breakdown: (no packets yet)",
                                         text_color="#9ca3af")
        self.proto_label.pack(side="left")

        self.tree = build_table(self, COLUMNS, height=18)

    def start_capture(self):
        if self.analyzer and self.analyzer.is_alive():
            return
        iface = self.iface_var.get()
        bpf = self.filter_var.get().strip()

        self.analyzer = PacketAnalyzer(
            db=self.app.db,
            on_packet=self.app.on_packet_captured,
            interface=None if iface == "default" else iface,
            bpf_filter=bpf,
        )
        self.analyzer.start()
        self.app.active_analyzer = self.analyzer

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="Capturing...", text_color="#22c55e")

        # Give the sniff thread a moment to fail fast (permissions/backend) and surface it.
        self.after(1200, self._check_startup_error)

    def _check_startup_error(self):
        if self.analyzer and self.analyzer.error and not self.analyzer.is_alive():
            messagebox.showerror(
                "Packet capture failed",
                f"{self.analyzer.error}\n\n"
                "On Windows: install Npcap (https://npcap.com) and run NetSentry as "
                "Administrator.\nOn Linux/macOS: install libpcap and run with sudo, or "
                "grant CAP_NET_RAW to python.",
            )
            self._reset_controls()

    def stop_capture(self):
        if self.analyzer:
            self.analyzer.stop()
        self._reset_controls()

    def _reset_controls(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="Capture stopped", text_color="#9ca3af")

    def add_packet_row(self, pkt: dict):
        src = f"{pkt.get('src_ip','-')}:{pkt.get('src_port') or '-'}"
        dst = f"{pkt.get('dst_ip','-')}:{pkt.get('dst_port') or '-'}"
        self.tree.insert("", 0, values=(
            pkt.get("timestamp", "")[-8:], src, dst,
            pkt.get("protocol", ""), pkt.get("length", ""),
            (pkt.get("summary") or "")[:80],
        ))
        children = self.tree.get_children()
        if len(children) > 500:
            for item in children[500:]:
                self.tree.delete(item)

    def update_protocol_breakdown(self, counts: dict[str, int]):
        if not counts:
            self.proto_label.configure(text="Protocol breakdown: (no packets yet)")
            return
        parts = ", ".join(f"{proto}: {n}" for proto, n in sorted(counts.items(), key=lambda x: -x[1]))
        self.proto_label.configure(text=f"Protocol breakdown: {parts}")
