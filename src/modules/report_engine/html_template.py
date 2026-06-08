"""High-quality HTML report template — dark theme, hacker dashboard style."""

from __future__ import annotations

from datetime import datetime

from src.modules.report_engine import ReportData


def render_html(report: ReportData) -> str:
    """Render a ReportData into a professional dark-themed HTML report."""
    emails = _get_section_items(report, "Emails")
    usernames = _get_section_items(report, "Usernames")
    phones = _get_section_items(report, "Phones")
    domains = _get_section_items(report, "Domains")
    ips = _get_section_items(report, "IP Addresses")
    crypto = _get_section_items(report, "Crypto Addresses")

    critical = [f for f in report.findings if f.severity.value == "critical"]
    high = [f for f in report.findings if f.severity.value == "high"]
    medium = [f for f in report.findings if f.severity.value == "medium"]
    low = [f for f in report.findings if f.severity.value == "low"]
    info = [f for f in report.findings if f.severity.value == "info"]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(report.title)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:#0b0e14;color:#c5cdd9;line-height:1.6;min-height:100vh}}
.container{{max-width:1400px;margin:0 auto;padding:24px}}
.header{{background:linear-gradient(135deg,#0f1923 0%,#1a2332 100%);border:1px solid #1e2d3d;border-radius:16px;padding:40px;margin-bottom:28px;position:relative;overflow:hidden}}
.header::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00d4ff,#7c3aed,#ff006e)}}
.header h1{{font-size:32px;font-weight:800;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}}
.header .target{{font-size:22px;color:#ff6b6b;font-weight:700;font-family:'Fira Code',monospace}}
.header .meta{{color:#5a6a7a;font-size:13px;margin-top:14px;display:flex;gap:20px;flex-wrap:wrap}}
.header .meta span{{display:flex;align-items:center;gap:4px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px}}
.stat{{background:#0f1923;border:1px solid #1e2d3d;border-radius:12px;padding:20px;text-align:center;transition:transform .2s}}
.stat:hover{{transform:translateY(-2px);border-color:#00d4ff33}}
.stat .value{{font-size:36px;font-weight:800;color:#00d4ff;font-family:'Fira Code',monospace}}
.stat .label{{font-size:12px;color:#5a6a7a;text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
.section{{background:#0f1923;border:1px solid #1e2d3d;border-radius:14px;padding:28px;margin-bottom:20px}}
.section h2{{color:#00d4ff;font-size:20px;font-weight:700;margin-bottom:18px;display:flex;align-items:center;gap:10px}}
.badge{{display:inline-block;padding:3px 12px;border-radius:20px;font-size:12px;font-weight:700}}
.badge-count{{background:#1e2d3d;color:#00d4ff}}
.badge-critical{{background:#ff1744;color:#fff}}
.badge-high{{background:#ff6d00;color:#fff}}
.badge-medium{{background:#ffd600;color:#1a1a2e}}
.badge-low{{background:#00e676;color:#1a1a2e}}
.badge-info{{background:#2196f3;color:#fff}}
.tag{{display:inline-block;background:#1e2d3d;color:#8fa3bf;padding:4px 14px;border-radius:8px;font-size:13px;margin:3px;font-family:'Fira Code',monospace;border:1px solid #2a3a4a;transition:all .2s}}
.tag:hover{{background:#2a3a4a;color:#00d4ff;border-color:#00d4ff33}}
.finding{{background:#0b0e14;border-radius:10px;padding:16px;margin-bottom:10px;border-left:4px solid #333;transition:all .2s}}
.finding:hover{{background:#0f1923}}
.finding.critical{{border-left-color:#ff1744}}
.finding.high{{border-left-color:#ff6d00}}
.finding.medium{{border-left-color:#ffd600}}
.finding.low{{border-left-color:#00e676}}
.finding.info{{border-left-color:#2196f3}}
.finding .title{{font-weight:700;color:#fff;font-size:15px}}
.finding .desc{{color:#8fa3bf;font-size:13px;margin-top:6px;line-height:1.5}}
.finding .meta-line{{display:flex;gap:16px;margin-top:8px;font-size:12px;color:#5a6a7a}}
table{{width:100%;border-collapse:collapse;margin-top:14px}}
th{{color:#00d4ff;font-size:12px;text-transform:uppercase;letter-spacing:1px;padding:12px 16px;text-align:left;border-bottom:2px solid #1e2d3d}}
td{{padding:12px 16px;border-bottom:1px solid #141a24;font-size:14px}}
tr:hover{{background:#0f192333}}
.timeline{{position:relative;padding-left:30px}}
.timeline::before{{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:#1e2d3d}}
.timeline-item{{position:relative;margin-bottom:20px;padding-left:20px}}
.timeline-item::before{{content:'';position:absolute;left:-26px;top:8px;width:12px;height:12px;border-radius:50%;background:#00d4ff;border:3px solid #0b0e14}}
.timeline-item .time{{font-size:12px;color:#5a6a7a;font-family:'Fira Code',monospace}}
.timeline-item .event{{color:#c5cdd9;margin-top:4px}}
.footer{{text-align:center;color:#3a4a5a;font-size:12px;margin-top:40px;padding:24px;border-top:1px solid #1e2d3d}}
.risk-meter{{height:8px;background:#1e2d3d;border-radius:4px;overflow:hidden;margin:12px 0}}
.risk-meter .fill{{height:100%;border-radius:4px;transition:width .5s}}
@media(max-width:768px){{.container{{padding:12px}}.header{{padding:20px}}.stats{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<div class="container">

<div class="header">
<h1>OSINT Intelligence Report</h1>
<div class="target">{_esc(report.target)}</div>
<div class="meta">
<span>&#128202; {report.metadata.get("scan_count", 0)} scans</span>
<span>&#128270; {report.metadata.get("total_findings", 0)} findings</span>
<span>&#128308; {report.metadata.get("critical_findings", 0)} critical</span>
<span>&#128197; {datetime.now().strftime("%Y-%m-%d %H:%M")}</span>
</div>
</div>

<div class="stats">
<div class="stat"><div class="value">{len(emails)}</div><div class="label">Emails</div></div>
<div class="stat"><div class="value">{len(usernames)}</div><div class="label">Usernames</div></div>
<div class="stat"><div class="value">{len(phones)}</div><div class="label">Phones</div></div>
<div class="stat"><div class="value">{len(domains)}</div><div class="label">Domains</div></div>
<div class="stat"><div class="value">{len(crypto)}</div><div class="label">Crypto</div></div>
<div class="stat"><div class="value">{report.finding_count}</div><div class="label">Findings</div></div>
</div>

{_id_section("Emails", emails, "&#128231;")}
{_id_section("Usernames", usernames, "&#128100;")}
{_id_section("Phones", phones, "&#128241;")}
{_id_section("Domains", domains, "&#127760;")}
{_id_section("IP Addresses", ips, "&#128279;")}
{_id_section("Crypto Addresses", crypto, "&#128176;")}

{_findings_section("Critical Findings", critical, "critical")}
{_findings_section("High Findings", high, "high")}
{_findings_section("Medium Findings", medium, "medium")}
{_findings_section("Low Findings", low, "low")}
{_findings_section("Informational", info, "info")}

<div class="footer">
<p>Generated by <strong>1ai-osint</strong> &mdash; Deep OSINT Intelligence Platform</p>
<p style="margin-top:6px">Report ID: {report.metadata.get("report_id", "N/A")}</p>
</div>

</div>
</body>
</html>"""


def _get_section_items(report: ReportData, title: str) -> list[str]:
    for s in report.sections:
        if s.title == title:
            return [str(i) for i in s.items]
    return []


def _id_section(title: str, items: list[str], icon: str) -> str:
    if not items:
        return ""
    tags = "".join(f'<span class="tag">{_esc(i)}</span>' for i in items[:30])
    more = (
        f'<p style="color:#5a6a7a;margin-top:10px">+ {len(items) - 30} more</p>'
        if len(items) > 30
        else ""
    )
    return f"""<div class="section">
<h2>{icon} {title} <span class="badge badge-count">{len(items)}</span></h2>
<div>{tags}{more}</div>
</div>"""


def _findings_section(title: str, findings: list, severity: str) -> str:
    if not findings:
        return ""
    items = ""
    for f in findings[:50]:
        items += f"""<div class="finding {severity}">
<div class="title">{_esc(f.title)}</div>
<div class="desc">{_esc(f.description[:300])}</div>
<div class="meta-line"><span>Module: {_esc(f.module)}</span><span>ID: {_esc(f.id[:8])}</span></div>
</div>"""
    more = (
        f'<p style="color:#5a6a7a;margin-top:10px">+ {len(findings) - 50} more</p>'
        if len(findings) > 50
        else ""
    )
    return f"""<div class="section">
<h2>{title} <span class="badge badge-{severity}">{len(findings)}</span></h2>
{items}{more}
</div>"""


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
