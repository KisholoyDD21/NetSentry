"""
Small reusable GUI building blocks shared across tabs.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
}


def style_treeview(style: ttk.Style):
    """Apply a dark theme to ttk.Treeview so it matches customtkinter."""
    bg = "#1a1a1a"
    fg = "#e5e5e5"
    field_bg = "#212121"
    heading_bg = "#2b2b2b"
    selected = "#2563eb"

    style.theme_use("clam")
    style.configure(
        "Netsentry.Treeview",
        background=field_bg,
        fieldbackground=field_bg,
        foreground=fg,
        rowheight=24,
        borderwidth=0,
        font=("Segoe UI", 10),
    )
    style.map("Netsentry.Treeview", background=[("selected", selected)])
    style.configure(
        "Netsentry.Treeview.Heading",
        background=heading_bg,
        foreground=fg,
        borderwidth=0,
        font=("Segoe UI", 10, "bold"),
    )
    style.map("Netsentry.Treeview.Heading", background=[("active", heading_bg)])


def build_table(parent, columns: list[str], height: int = 15) -> ttk.Treeview:
    """Create a themed, scrollable Treeview with the given columns."""
    container = ctk.CTkFrame(parent, fg_color="transparent")
    container.grid_rowconfigure(0, weight=1)
    container.grid_columnconfigure(0, weight=1)

    tree = ttk.Treeview(
        container, columns=columns, show="headings",
        height=height, style="Netsentry.Treeview",
    )
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=110, anchor="w", stretch=True)
    tree.grid(row=0, column=0, sticky="nsew")

    vsb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
    vsb.grid(row=0, column=1, sticky="ns")
    tree.configure(yscrollcommand=vsb.set)

    for sev, color in SEVERITY_COLORS.items():
        tree.tag_configure(sev, foreground=color)

    container.pack(fill="both", expand=True, padx=10, pady=10)
    return tree


def prepend_row(tree: ttk.Treeview, values: tuple, tag: str | None = None, max_rows: int = 500):
    """Insert a row at the top and cap total rows so the UI stays snappy."""
    kwargs = {"tags": (tag,)} if tag else {}
    tree.insert("", 0, values=values, **kwargs)
    children = tree.get_children()
    if len(children) > max_rows:
        for item in children[max_rows:]:
            tree.delete(item)


class StatCard(ctk.CTkFrame):
    """A small labeled metric card used on the Dashboard tab."""

    def __init__(self, parent, title: str, value: str = "0", accent: str = "#3b82f6"):
        super().__init__(parent, corner_radius=12, fg_color="#1f1f1f", border_width=1,
                          border_color="#333333")
        self.title_label = ctk.CTkLabel(
            self, text=title, font=ctk.CTkFont(size=12), text_color="#9ca3af"
        )
        self.title_label.pack(anchor="w", padx=16, pady=(12, 0))

        self.value_label = ctk.CTkLabel(
            self, text=value, font=ctk.CTkFont(size=26, weight="bold"), text_color=accent
        )
        self.value_label.pack(anchor="w", padx=16, pady=(0, 12))

    def set_value(self, value: str):
        self.value_label.configure(text=value)
