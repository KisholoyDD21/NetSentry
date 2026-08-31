"""
Reports tab: export collected data as JSON, CSV (per table), or a
formatted PDF summary report.
"""
from __future__ import annotations

import os
import platform
import subprocess
import threading
from tkinter import messagebox

import customtkinter as ctk

CSV_TABLES = ["alerts", "connections", "packets", "dns_queries"]


class ReportsTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.last_export_path: str | None = None

        card = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=12)
        card.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(card, text="Export Data", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=16, pady=(16, 8)
        )

        json_row = ctk.CTkFrame(card, fg_color="transparent")
        json_row.pack(fill="x", padx=16, pady=6)
        ctk.CTkButton(json_row, text="Export Full Report (JSON)", width=220,
                      command=self._export_json).pack(side="left")

        csv_row = ctk.CTkFrame(card, fg_color="transparent")
        csv_row.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(csv_row, text="CSV table:").pack(side="left", padx=(0, 6))
        self.csv_table_var = ctk.StringVar(value=CSV_TABLES[0])
        ctk.CTkOptionMenu(csv_row, variable=self.csv_table_var, values=CSV_TABLES,
                          width=160).pack(side="left")
        ctk.CTkButton(csv_row, text="Export CSV", width=140,
                      command=self._export_csv).pack(side="left", padx=(10, 0))

        pdf_row = ctk.CTkFrame(card, fg_color="transparent")
        pdf_row.pack(fill="x", padx=16, pady=6)
        ctk.CTkButton(pdf_row, text="Export PDF Summary Report", width=220,
                      command=self._export_pdf).pack(side="left")

        self.status_label = ctk.CTkLabel(card, text="", text_color="#9ca3af")
        self.status_label.pack(anchor="w", padx=16, pady=(6, 6))

        open_row = ctk.CTkFrame(card, fg_color="transparent")
        open_row.pack(fill="x", padx=16, pady=(0, 16))
        ctk.CTkButton(open_row, text="Open Export Folder", width=180, fg_color="#374151",
                      hover_color="#4b5563", command=self._open_folder).pack(side="left")

    # -- actions -------------------------------------------------------

    def _run_async(self, fn, label: str):
        self.status_label.configure(text=f"Generating {label}...")

        def worker():
            try:
                path = fn()
                self.last_export_path = str(path)
                self.after(0, lambda: self.status_label.configure(
                    text=f"Saved: {path}"))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Export failed", str(exc)))
                self.after(0, lambda: self.status_label.configure(text="Export failed"))

        threading.Thread(target=worker, daemon=True).start()

    def _export_json(self):
        self._run_async(self.app.reports.export_json, "JSON report")

    def _export_csv(self):
        table = self.csv_table_var.get()
        self._run_async(lambda: self.app.reports.export_csv(table), f"{table}.csv")

    def _export_pdf(self):
        self._run_async(self.app.reports.export_pdf, "PDF report")

    def _open_folder(self):
        folder = str(self.app.reports.export_dir)
        try:
            if platform.system() == "Windows":
                os.startfile(folder)  # noqa: S606
            elif platform.system() == "Darwin":
                subprocess.run(["open", folder], check=False)
            else:
                subprocess.run(["xdg-open", folder], check=False)
        except Exception as exc:
            messagebox.showerror("Could not open folder", str(exc))
