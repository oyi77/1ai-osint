"""Deep scan report generator — HTML and PDF output."""

from __future__ import annotations
import logging
from datetime import datetime

from src.modules.deep_scan import DeepScanResult, IdentifierType

logger = logging.getLogger(__name__)


def generate_html_report(result: DeepScanResult) -> str:
    """Generate a comprehensive HTML report from deep scan results."""
    emails = result.get_emails()
    usernames = result.get_usernames()
    phones = result.get_phones()
    domains = result.get_domains()
    crypto = result.get_crypto_addresses()
    niks = [i.value for i in result.identifiers if i.id_type == IdentifierType.NIK]
    social_profiles = [
        i for i in result.identifiers if i.id_type == IdentifierType.SOCIAL_PROFILE
    ]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Deep Scan Report: {_esc(result.target)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 10px; }}
  h2 {{ color: #79c0ff; margin-top: 30px; }}
  .card {{ background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 16px; margin: 10px 0; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
  .badge-critical {{ background: #da3633; color: white; }}
  .badge-high {{ background: #d29922; color: white; }}
  .badge-medium {{ background: #e3b341; color: black; }}
  .badge-low {{ background: #3fb950; color: black; }}
  .badge-info {{ background: #388bfd; color: white; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #21262d; }}
  th {{ color: #8b949e; font-weight: 600; }}
  .stat {{ display: inline-block; text-align: center; padding: 10px 20px; margin: 5px; background: #161b22; border: 1px solid #21262d; border-radius: 6px; }}
  .stat-value {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
  .stat-label {{ font-size: 12px; color: #8b949e; }}
  .section {{ margin: 20px 0; }}
  code {{ background: #1f2937; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
<h1>Deep Scan Report</h1>
<p><strong>Target:</strong> {_esc(result.target)}</p>
<p><strong>Started:</strong> {result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if result.started_at else "N/A"}</p>
<p><strong>Duration:</strong> {result.duration_sec:.1f}s | <strong>Iterations:</strong> {result.iterations}</p>

<div class="section">
<div class="stat"><div class="stat-value">{result.identifier_count}</div><div class="stat-label">Identifiers</div></div>
<div class="stat"><div class="stat-value">{result.finding_count}</div><div class="stat-label">Findings</div></div>
<div class="stat"><div class="stat-value">{len(emails)}</div><div class="stat-label">Emails</div></div>
<div class="stat"><div class="stat-value">{len(usernames)}</div><div class="stat-label">Usernames</div></div>
<div class="stat"><div class="stat-value">{len(phones)}</div><div class="stat-label">Phones</div></div>
<div class="stat"><div class="stat-value">{len(domains)}</div><div class="stat-label">Domains</div></div>
<div class="stat"><div class="stat-value">{len(crypto)}</div><div class="stat-label">Crypto</div></div>
<div class="stat"><div class="stat-value">{len(niks)}</div><div class="stat-label">NIKs</div></div>
</div>
"""

    # Emails
    if emails:
        html += "<h2>Emails</h2><div class='card'><table><tr><th>Email</th><th>Source</th></tr>"
        for ident in result.get_identifiers_by_type(IdentifierType.EMAIL):
            html += f"<tr><td><code>{_esc(ident.value)}</code></td><td>{_esc(ident.source)}</td></tr>"
        html += "</table></div>"

    # Usernames
    if usernames:
        html += "<h2>Usernames</h2><div class='card'><table><tr><th>Username</th><th>Source</th></tr>"
        for ident in result.get_identifiers_by_type(IdentifierType.USERNAME):
            html += f"<tr><td><code>{_esc(ident.value)}</code></td><td>{_esc(ident.source)}</td></tr>"
        html += "</table></div>"

    # Social Profiles
    if social_profiles:
        html += "<h2>Social Profiles</h2><div class='card'><table><tr><th>Platform</th><th>URL</th></tr>"
        for ident in social_profiles:
            platform = ident.metadata.get("platform", "unknown")
            html += f"<tr><td>{_esc(platform)}</td><td><a href='{_esc(ident.value)}' style='color:#58a6ff'>{_esc(ident.value)}</a></td></tr>"
        html += "</table></div>"

    # Phones
    if phones:
        html += "<h2>Phone Numbers</h2><div class='card'><table><tr><th>Number</th><th>Source</th></tr>"
        for ident in result.get_identifiers_by_type(IdentifierType.PHONE):
            html += f"<tr><td><code>{_esc(ident.value)}</code></td><td>{_esc(ident.source)}</td></tr>"
        html += "</table></div>"

    # NIKs
    if niks:
        html += "<h2>Indonesian NIKs</h2><div class='card'><table><tr><th>NIK</th><th>Province</th><th>Birth</th><th>Gender</th></tr>"
        for ident in result.get_identifiers_by_type(IdentifierType.NIK):
            meta = ident.metadata
            html += f"<tr><td><code>{_esc(ident.value)}</code></td>"
            html += f"<td>{meta.get('province_code', '?')}-{meta.get('city_code', '?')}</td>"
            html += f"<td>{meta.get('birth_year', '?')}-{meta.get('birth_month', '?'):02d}-{meta.get('birth_day', '?'):02d}</td>"
            html += f"<td>{meta.get('gender', '?')}</td></tr>"
        html += "</table></div>"

    # Crypto Addresses
    if crypto:
        html += "<h2>Crypto Addresses</h2><div class='card'><table><tr><th>Address</th><th>Chain</th><th>Source</th></tr>"
        for ident in result.get_identifiers_by_type(IdentifierType.CRYPTO_ADDRESS):
            chain = ident.metadata.get("chain", "unknown")
            short_val = _esc(ident.value[:20]) + "..." + _esc(ident.value[-10:])
            html += f"<tr><td><code>{short_val}</code></td><td>{chain}</td><td>{_esc(ident.source)}</td></tr>"
        html += "</table></div>"

    # Findings
    if result.findings:
        html += "<h2>Findings</h2>"
        for f in result.findings:
            severity_class = f"badge-{f.severity.value.lower()}"
            html += f"""<div class='card'>
<span class='badge {severity_class}'>{f.severity.value}</span>
<strong>{_esc(f.title)}</strong>
<p>{_esc(f.description[:200])}</p>
<small style='color:#8b949e'>Module: {_esc(f.module)}</small>
</div>"""

    # Errors
    if result.errors:
        html += "<h2>Errors</h2><div class='card'>"
        for err in result.errors[:20]:
            html += f"<p style='color:#f85149'>{_esc(err)}</p>"
        html += "</div>"

    html += f"""
<p style='color:#8b949e;margin-top:40px;font-size:12px'>
Generated by 1ai-osint Deep Scan Engine | {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
</p>
</div></body></html>"""

    return html


def generate_pdf_report(result: DeepScanResult) -> bytes:
    """Generate a PDF report from deep scan results."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        from io import BytesIO

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(
            Paragraph(f"Deep Scan Report: {result.target}", styles["Title"])
        )
        elements.append(Spacer(1, 12))
        elements.append(
            Paragraph(
                f"Duration: {result.duration_sec:.1f}s | Iterations: {result.iterations} | "
                f"Identifiers: {result.identifier_count} | Findings: {result.finding_count}",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 24))

        # Identifiers table
        if result.identifiers:
            elements.append(Paragraph("Identifiers", styles["Heading2"]))
            data = [["Type", "Value", "Source"]]
            for ident in result.identifiers[:100]:
                data.append([ident.id_type.value, ident.value[:50], ident.source])
            t = Table(data, colWidths=[80, 300, 100])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ]
                )
            )
            elements.append(t)

        # Findings table
        if result.findings:
            elements.append(Spacer(1, 24))
            elements.append(Paragraph("Findings", styles["Heading2"]))
            data = [["Severity", "Title", "Module"]]
            for f in result.findings[:100]:
                data.append([f.severity.value, f.title[:50], f.module])
            t = Table(data, colWidths=[60, 320, 100])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ]
                )
            )
            elements.append(t)

        doc.build(elements)
        return buffer.getvalue()
    except ImportError:
        logger.warning("reportlab not installed — PDF generation unavailable")
        return b""


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
