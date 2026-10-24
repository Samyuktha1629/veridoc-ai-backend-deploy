"""Human-readable PDF report generation."""

from __future__ import annotations

import io
from xml.sax.saxutils import escape
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_pdf(report: dict[str, Any]) -> bytes:
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#183a5a")))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=11))
    story = [
        Paragraph("Veridoc AI | Document Verification", styles["ReportTitle"]),
        Spacer(1, 5 * mm),
        Paragraph(f"<b>Report:</b> {escape(str(report.get('id', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Document:</b> {escape(str(report.get('document_name', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Created:</b> {escape(str(report.get('created_at', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Review status:</b> {escape(str(report.get('status', 'pending_review')))}", styles["BodyText"]),
        Paragraph(f"<b>Risk signal:</b> {escape(str(report.get('risk_level', 'Warning')))}", styles["BodyText"]),
        Spacer(1, 4 * mm),
        Paragraph(escape(str(report.get("review_notice", ""))), styles["Small"]),
        Spacer(1, 4 * mm),
    ]
    for section_name in ("validation", "compliance", "fraud"):
        section = report.get(section_name, {})
        story.append(Paragraph(section_name.replace("_", " ").title(), styles["Heading2"]))
        if section_name == "validation":
            items = section.get("fields", []) + section.get("invalid_fields", [])
            rows = [["Field", "Value", "Result", "Explanation"]]
            rows.extend([
                [
                    escape(str(item.get("field", ""))),
                    escape(str(item.get("value") or "Not detected")),
                    "Valid" if item.get("valid") else "Review",
                    escape(str(item.get("reason", "Format/checksum rule passed."))),
                ]
                for item in items
            ])
        elif section_name == "compliance":
            rows = [["Rule", "Status", "Explanation"]]
            rows.extend([
                [escape(str(item.get("name", ""))), escape(str(item.get("status", ""))), escape(str(item.get("explanation", "")))]
                for item in section.get("results", [])
            ])
        else:
            rows = [["Signal", "Severity", "Explanation"]]
            rows.extend([
                [escape(str(item.get("signal", ""))), escape(str(item.get("severity", ""))), escape(str(item.get("explanation", "")))]
                for item in section.get("indicators", [])
            ])
        if len(rows) == 1:
            rows.append(["No findings", "", ""])
        table = Table(rows, repeatRows=1, colWidths=[36 * mm, 30 * mm, None, None] if section_name == "validation" else None)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef4")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#183a5a")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5df")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([table, Spacer(1, 4 * mm)])
    if "human_review" in report:
        review = report["human_review"]
        story.extend([
            Paragraph("Human review", styles["Heading2"]),
            Paragraph(f"<b>Decision:</b> {escape(str(review.get('decision', '')))}", styles["BodyText"]),
            Paragraph(f"<b>Note:</b> {escape(str(review.get('note', '')))}", styles["BodyText"]),
        ])
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Screening output only. Confirm the source document and current official requirements before making a decision.",
        styles["Small"],
    ))
    document.build(story)
    return output.getvalue()
