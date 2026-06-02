"""PDF export for Operational Intelligence Briefing."""
from __future__ import annotations

from io import BytesIO

from src.modules.deep_scan.models_report import IntelReport


def export_pdf(report: IntelReport) -> bytes:
    """Render IntelReport briefing as PDF bytes."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements: list = []

    elements.append(Paragraph("Operational Intelligence Brief", styles["Title"]))
    elements.append(Paragraph(f"Subject: {report.target}", styles["Heading2"]))
    elements.append(Paragraph(report.briefing.classification, styles["Normal"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>BLUF:</b> {report.briefing.bluf}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Key Judgments", styles["Heading2"]))
    for j in report.briefing.key_judgments:
        elements.append(Paragraph(f"• {j}", styles["Normal"]))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Digital Presence", styles["Heading2"]))
    if report.briefing.digital_accounts:
        data = [["Platform", "Handle", "Status", "Conf."]]
        for ac in report.briefing.digital_accounts[:40]:
            data.append([
                ac.platform, ac.username, ac.status, f"{ac.confidence:.0%}",
            ])
        t = Table(data, colWidths=[90, 120, 70, 50])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(t)

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Intelligence Gaps", styles["Heading2"]))
    for g in report.briefing.intelligence_gaps:
        elements.append(Paragraph(f"• {g}", styles["Normal"]))

    doc.build(elements)
    return buffer.getvalue()
