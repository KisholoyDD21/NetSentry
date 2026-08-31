"""
Export monitoring data and alerts to JSON, CSV, or a formatted PDF report.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from netsentry.database import Database
from netsentry.utils import load_config, resolve_path, setup_logger

logger = setup_logger(__name__)

_TABLE_COLUMNS = {
    "alerts": ["id", "timestamp", "alert_type", "severity", "source_ip",
               "target_port", "description", "details"],
    "connections": ["id", "timestamp", "local_addr", "local_port", "remote_addr",
                     "remote_port", "protocol", "status", "pid", "process_name"],
    "packets": ["id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "length", "summary"],
    "dns_queries": ["id", "timestamp", "src_ip", "query_name", "query_type"],
}


class ReportGenerator:
    def __init__(self, db: Database):
        self.db = db
        cfg = load_config()["reports"]
        self.export_dir = resolve_path(cfg["export_dir"] + "/.keep").parent

    def _timestamped_path(self, prefix: str, ext: str) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.export_dir / f"{prefix}_{stamp}.{ext}"

    def _fetch_table(self, table: str, limit: int = 5000) -> list[dict]:
        with self.db.cursor() as cur:
            cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    # -- JSON -----------------------------------------------------------

    def export_json(self, path: str | None = None) -> Path:
        out_path = Path(path) if path else self._timestamped_path("netsentry_report", "json")
        payload = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "alerts": self._fetch_table("alerts"),
            "connections": self._fetch_table("connections", limit=2000),
            "packets": self._fetch_table("packets", limit=2000),
            "dns_queries": self._fetch_table("dns_queries", limit=2000),
            "alert_counts_by_severity": self.db.alert_counts_by_severity(),
            "protocol_counts": self.db.protocol_counts(),
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        logger.info("Wrote JSON report to %s", out_path)
        return out_path

    # -- CSV --------------------------------------------------------------

    def export_csv(self, table: str, path: str | None = None) -> Path:
        if table not in _TABLE_COLUMNS:
            raise ValueError(f"Unknown table '{table}'. Choose from {list(_TABLE_COLUMNS)}")
        out_path = Path(path) if path else self._timestamped_path(f"netsentry_{table}", "csv")
        rows = self._fetch_table(table, limit=20000)
        columns = _TABLE_COLUMNS[table]
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k) for k in columns})
        logger.info("Wrote CSV report (%s) to %s", table, out_path)
        return out_path

    # -- PDF --------------------------------------------------------------

    def export_pdf(self, path: str | None = None) -> Path:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )

        out_path = Path(path) if path else self._timestamped_path("netsentry_report", "pdf")
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(str(out_path), pagesize=A4,
                                 topMargin=1.5 * cm, bottomMargin=1.5 * cm)
        story = []

        story.append(Paragraph("NetSentry Security Report", styles["Title"]))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]
        ))
        story.append(Spacer(1, 0.5 * cm))

        # -- summary stats
        sev_counts = self.db.alert_counts_by_severity()
        proto_counts = self.db.protocol_counts()
        story.append(Paragraph("Summary", styles["Heading2"]))
        summary_rows = [["Metric", "Value"]]
        summary_rows += [[f"Alerts ({sev})", str(count)] for sev, count in sev_counts.items()]
        summary_rows += [[f"Packets ({proto})", str(count)] for proto, count in proto_counts.items()]
        if len(summary_rows) == 1:
            summary_rows.append(["No data collected yet", ""])
        story.append(_styled_table(summary_rows))
        story.append(Spacer(1, 0.5 * cm))

        # -- recent alerts
        story.append(Paragraph("Recent Alerts", styles["Heading2"]))
        alerts = self._fetch_table("alerts", limit=40)
        alert_rows = [["Time", "Type", "Severity", "Source IP", "Description"]]
        for a in alerts:
            alert_rows.append([
                a["timestamp"], a["alert_type"], a["severity"],
                a["source_ip"] or "-", (a["description"] or "")[:70],
            ])
        if len(alert_rows) == 1:
            alert_rows.append(["-", "-", "-", "-", "No alerts recorded"])
        story.append(_styled_table(alert_rows, col_widths=[3.2 * cm, 3 * cm, 2 * cm, 3 * cm, 6.5 * cm]))

        doc.build(story)
        logger.info("Wrote PDF report to %s", out_path)
        return out_path


def _styled_table(rows, col_widths=None):
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9ca3af")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t
