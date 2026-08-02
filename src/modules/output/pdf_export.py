"""PDF report generation for CLI scan results.

Deprecated: prefer the wired `src.modules.output.pdf_generator.PDFGenerator`.
Kept for legacy CLI output paths; PII targets are hashed like PDFGenerator.
"""

import hashlib
from datetime import datetime, timezone
from io import BytesIO


def _hash_value(value: str, salt: str = "") -> str:
    """SHA-256 hash of a value, matching `PDFGenerator._hash_value`."""
    preimage = f"{salt}:{value}".encode()
    return hashlib.sha256(preimage).hexdigest()


def format_pdf(results: list, salt: str = "") -> bytes:
    """Format scan results as a PDF report.

    Deprecated: prefer `PDFGenerator.generate`.
    PII (`scan_result.target`) is exported hashed (SHA-256, salted).
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements: list = []

    elements.append(Paragraph("1ai-osint Scan Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}Z", styles["Normal"]))
    elements.append(Spacer(1, 24))

    for scan_result in results:
        elements.append(Paragraph(f"Module: {scan_result.module}", styles["Heading2"]))
        elements.append(Paragraph(f"Target (hashed): {_hash_value(scan_result.target, salt)}", styles["Normal"]))
        elements.append(Paragraph(f"Status: {scan_result.status}", styles["Normal"]))
        elements.append(Paragraph(f"Findings: {scan_result.finding_count}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        if scan_result.findings:
            table_data = [["Severity", "Title", "Confidence"]]
            for f in scan_result.findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                table_data.append([sev, f.title[:60], f"{f.confidence:.0%}"])

            table = Table(table_data, colWidths=[80, 300, 70])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.lightgrey],
                        ),
                    ]
                )
            )
            elements.append(table)
            elements.append(Spacer(1, 24))

    doc.build(elements)
    return buffer.getvalue()
