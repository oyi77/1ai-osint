"""PDF report generator with charts using reportlab."""

import hashlib
import io
from datetime import datetime, timezone
from typing import Any

from src.core.models import ScanResult, Severity


class PDFGenerator:
    """Generates PDF reports from ScanResult objects with severity charts.

    All PII fields are hashed using a configurable salt before inclusion.
    """

    def __init__(self, salt: str = ""):
        self._salt = salt

    def _hash_value(self, value: str) -> str:
        preimage = f"{self._salt}:{value}".encode("utf-8")
        return hashlib.sha256(preimage).hexdigest()

    def _severity_counts(self, results: list[ScanResult]) -> dict[str, int]:
        """Aggregate severity counts across all scan results."""
        counts = {s.value: 0 for s in Severity}
        for scan in results:
            for finding in scan.findings:
                counts[finding.severity.value] += 1
        return counts

    def _build_severity_chart(self, severity_counts: dict[str, int]) -> Any:
        """Build a bar chart image of severity distribution using reportlab."""
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.shapes import Drawing
        from reportlab.lib.colors import HexColor

        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 30
        chart.width = 400
        chart.height = 200

        labels = list(severity_counts.keys())
        values = list(severity_counts.values())

        chart.data = [values]
        chart.categoryAxis.categoryNames = labels
        chart.categoryAxis.labels.boxAnchor = "n"
        chart.categoryAxis.labels.fontSize = 8
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(values) + 1 if max(values) > 0 else 5
        chart.valueAxis.valueStep = max(1, max(values) // 5) if max(values) > 0 else 1
        chart.bars[0].fillColor = HexColor("#3b82f6")

        drawing = Drawing(500, 280)
        drawing.add(chart)
        return drawing

    def generate(self, results: list[ScanResult]) -> bytes:
        """Generate a PDF report from ScanResult objects.

        Args:
            results: List of ScanResult objects to include in the report.
        Returns:
            PDF file content as bytes.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=20,
            spaceAfter=20,
        )
        story.append(Paragraph("1ai-osint Security Report", title_style))
        story.append(
            Paragraph(
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 20))

        # Summary
        total_findings = sum(r.finding_count for r in results)
        total_critical = sum(r.critical_count for r in results)
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        summary_data = [
            ["Metric", "Value"],
            ["Total Scans", str(len(results))],
            ["Total Findings", str(total_findings)],
            ["Critical Findings", str(total_critical)],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, 0), 11),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f0f4ff")],
                    ),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Severity chart
        severity_counts = self._severity_counts(results)
        if any(v > 0 for v in severity_counts.values()):
            story.append(Paragraph("Findings by Severity", styles["Heading2"]))
            chart_drawing = self._build_severity_chart(severity_counts)
            story.append(chart_drawing)
            story.append(Spacer(1, 20))

        # Per-scan details
        for scan in results:
            story.append(
                Paragraph(
                    f"Scan: {scan.module} - {scan.scan_id}",
                    styles["Heading2"],
                )
            )
            meta_data = [
                ["Field", "Value"],
                ["Module", scan.module],
                ["Target (hashed)", self._hash_value(scan.target)],
                ["Status", scan.status],
                ["Findings", str(scan.finding_count)],
                ["Critical", str(scan.critical_count)],
            ]
            meta_table = Table(meta_data, colWidths=[2.5 * inch, 3.5 * inch])
            meta_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ]
                )
            )
            story.append(meta_table)
            story.append(Spacer(1, 10))

            # Findings table
            if scan.findings:
                findings_header = ["ID", "Title", "Severity", "Confidence", "Module"]
                findings_rows = [findings_header]
                for f in scan.findings:
                    findings_rows.append(
                        [
                            f.id[:12],
                            f.title[:40],
                            f.severity.value,
                            f"{f.confidence:.0%}",
                            f.module,
                        ]
                    )
                findings_table = Table(
                    findings_rows,
                    colWidths=[1 * inch, 2.5 * inch, 1 * inch, 0.8 * inch, 1 * inch],
                )
                findings_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dc2626")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                            (
                                "ROWBACKGROUNDS",
                                (0, 1),
                                (-1, -1),
                                [colors.white, colors.HexColor("#fef2f2")],
                            ),
                        ]
                    )
                )
                story.append(findings_table)
            story.append(Spacer(1, 20))

        doc.build(story)
        return buffer.getvalue()
