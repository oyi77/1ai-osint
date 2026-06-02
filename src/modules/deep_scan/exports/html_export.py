"""HTML export — Jinja2-rendered IntelReport as single-file HTML.

Includes:
  - Inline SVG identity graph (no D3 dependency)
  - Risk gauge (semi-circular meter)
  - Confidence-filtered evidence grid
  - Timeline card
  - Pivot recommendations
  - Print-friendly CSS embedded
"""
from __future__ import annotations

import math
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from src.modules.deep_scan.field_labels import format_platform_block, format_record_fields
from src.modules.deep_scan.models_report import IntelReport

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def _format_block_record(record: dict) -> str:
    """Jinja helper: format one raw_data record."""
    if not record:
        return ""
    platforms = record.get("platforms")
    if isinstance(platforms, list) and platforms:
        user = str(record.get("username") or record.get("display_name") or "")
        body = format_platform_block(platforms, user)
        if record.get("display_name") and record.get("display_name") != user:
            body = (
                f"<b>👤Display name: </b> <code>{record['display_name']}</code><br>"
                f"<b>👤Handle: </b> <code>{user}</code><br><br>{body}"
            )
        return body
    return format_record_fields(record)


def _svg_graph(report: IntelReport) -> str:
    """Generate inline SVG for the identity graph."""
    nodes = report.identity_graph.nodes
    edges = report.identity_graph.edges

    if not nodes:
        return '<svg width="400" height="100"><text x="200" y="50" text-anchor="middle">No graph data</text></svg>'

    # Simple layered layout
    width = 600
    height = max(200, len(nodes) * 60 + 60)
    svg_parts = [
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#64748b"/></marker></defs>',
    ]

    # Positions
    positions: dict[str, tuple[float, float]] = {}
    center_x = width / 2
    for i, node in enumerate(nodes):
        if node.id == "target":
            positions[node.id] = (center_x, 40)
        else:
            col = i % 3
            row = i // 3
            x = 100 + col * 200
            y = 120 + row * 60
            positions[node.id] = (x, y)

    # Edges
    for edge in edges:
        src = positions.get(edge.source_id)
        tgt = positions.get(edge.target_id)
        if src and tgt:
            color = "#94a3b8"
            sw = 1
            if edge.relationship == "found_on":
                color = "#3b82f6"
                sw = 1.5
            svg_parts.append(
                f'<line x1="{src[0]}" y1="{src[1]}" x2="{tgt[0]}" y2="{tgt[1]}" '
                f'stroke="{color}" stroke-width="{sw}" marker-end="url(#arrow)"/>'
            )

    # Nodes
    for node in nodes:
        pos = positions.get(node.id, (center_x, 40))
        fill = "#3b82f6"
        if node.type == "target" or node.id == "target":
            fill = "#ef4444"
        elif node.type == "social":
            fill = "#10b981"
        elif node.type == "name":
            fill = "#f59e0b"
        r = 18
        label = node.label[:12] + (".." if len(node.label) > 12 else "")
        svg_parts.append(
            f'<circle cx="{pos[0]}" cy="{pos[1]}" r="{r}" fill="{fill}" opacity="0.8"/>'
        )
        svg_parts.append(
            f'<text x="{pos[0]}" y="{pos[1] + 4}" text-anchor="middle" fill="white" font-size="9">{label}</text>'
        )

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def _risk_gauge(score: float) -> str:
    """Inline SVG risk gauge (semi-circle)."""
    angle = min(180, max(0, score * 180))
    rad = angle * math.pi / 180
    x = 50 + 40 * (1 - math.cos(rad))
    y = 50 - 40 * math.sin(rad)

    color = "#22c55e"
    if score > 0.7:
        color = "#ef4444"
    elif score > 0.5:
        color = "#f97316"
    elif score > 0.25:
        color = "#eab308"

    return (
        f'<svg width="120" height="70" xmlns="http://www.w3.org/2000/svg">'
        f'<path d="M10,50 A40,40 0 0,1 90,50" fill="none" stroke="#e2e8f0" stroke-width="8"/>'
        f'<path d="M10,50 A40,40 0 0,1 {x:.1f},{y:.1f}" fill="none" stroke="{color}" stroke-width="8"/>'
        f'<text x="50" y="58" text-anchor="middle" font-size="14" font-weight="bold">{int(score * 100)}%</text>'
        f"</svg>"
    )


def export_html(report: IntelReport) -> str:
    """Render IntelReport to self-contained HTML (LeakBase-style + dashboard)."""
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))
    env.globals["format_record"] = _format_block_record
    try:
        template = env.get_template("report_briefing.html.j2")
    except Exception:
        try:
            template = env.get_template("report.html.j2")
        except Exception:
            return _render_inline(report)

    return template.render(
        report=report,
        svg_graph=_svg_graph(report),
        risk_gauge=_risk_gauge(report.risk.score),
        confidence_by_identifier=report.confidence_by_identifier,
    )


def _reliability_badge(reliability: str) -> str:
    """Render a colored NATO A-F reliability badge."""
    cls = f"badge-{reliability.lower()}" if reliability.lower() in "abcdf" else "badge-f"
    return f'<span class="badge {cls}">{reliability}</span>'


def _render_inline(report: IntelReport) -> str:
    """Fallback inline HTML renderer (no Jinja2 needed)."""
    graph_svg = _svg_graph(report)
    gauge_svg = _risk_gauge(report.risk.score)

    evidence_rows = ""
    for ev in report.evidence:
        status_badge = ""
        if ev.http_status:
            color = "#22c55e" if 200 <= ev.http_status < 300 else "#ef4444"
            status_badge = (
                f'<span style="background:{color};color:white;padding:2px 6px;border-radius:4px;font-size:11px">'
                f"{ev.http_status}</span>"
            )
        url_display = ev.url or ""
        evidence_rows += f"""
        <tr>
            <td>{ev.identifier_value}</td>
            <td>{ev.identifier_type}</td>
            <td>{ev.source} {_reliability_badge(ev.source_reliability)}</td>
            <td>{status_badge}</td>
            <td><a href="{url_display}" target="_blank">{url_display[:50]}</a></td>
            <td>{ev.confidence:.0%}</td>
        </tr>"""

    confidence_rows = ""
    for k, v in report.confidence_by_identifier.items():
        confidence_rows += f"""
        <tr>
            <td>{k}</td>
            <td>{v.total:.0%}</td>
            <td>{v.grade}</td>
        </tr>"""

    timeline_rows = ""
    for t in report.timeline:
        ts = t.timestamp.isoformat() if t.timestamp else ""
        timeline_rows += f"""
        <tr>
            <td>{ts[:19]}</td>
            <td>{t.source}</td>
            <td>{t.detail}</td>
            <td>{t.confidence:.0%}</td>
        </tr>"""

    pivot_rows = ""
    for p in report.pivots:
        pivot_rows += f"""
        <tr>
            <td><strong>{p.target_type}</strong></td>
            <td>{p.target_value}</td>
            <td>{p.rationale}</td>
            <td>{", ".join(p.expected_sources)}</td>
        </tr>"""

    # Breach timeline
    breach_items = [e for e in report.evidence if e.identifier_type == "breach"]
    breach_rows = ""
    for ev in breach_items:
        name = ev.raw_data.get("Name") or ev.identifier_value or "?"
        date = ev.raw_data.get("BreachDate") or ev.raw_data.get("breach_date") or "?"
        data_classes = ev.raw_data.get("DataClasses", [])
        if isinstance(data_classes, list):
            data_classes = ", ".join(data_classes)
        breach_rows += f"""
        <tr>
            <td>{name}</td><td>{date}</td><td>{data_classes}</td><td>{ev.source}</td>
        </tr>"""

    # Cross-module correlations
    correlation_rows = ""
    for c in (getattr(report, "correlation_clusters", None) or []):
        correlation_rows += f"""
        <div class="card" style="margin:8px 0">
            <b>Entity {c.get("entity_id", "?")}</b><br>
            Confidence: {c.get("confidence", 0):.0%}<br>
            Modules: {', '.join(c.get("source_modules", []))}<br>
            Evidence: {', '.join(c.get("evidence", []))}
        </div>"""

    # Structured PII section
    pii_types = {"nik", "phone", "email", "address"}
    pii_items = [e for e in report.evidence if e.identifier_type in pii_types]
    pii_rows = ""
    for ev in pii_items:
        pii_rows += f"""
        <tr>
            <td>{ev.identifier_type.upper()}</td><td>{ev.identifier_value}</td>
            <td>{ev.source}</td><td>{ev.confidence:.0%}</td>
        </tr>"""

    # Breaches found count
    n_breaches = len(breach_items)
    n_correlations = len(getattr(report, "correlation_clusters", None) or [])

    factors_html = ""
    for f in report.risk.factors:
        check = "&#x2705;" if f.triggered else "&#x2796;"
        factors_html += f'<span style="margin:4px">{check} {f.description}</span><br>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Intel Report: {report.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  h2 {{ font-size: 18px; margin: 24px 0 12px; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; }}
  .meta {{ color: #94a3b8; font-size: 13px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 16px; }}
  .card .label {{ font-size: 11px; color: #64748b; text-transform: uppercase; }}
  .card .value {{ font-size: 24px; font-weight: 700; }}
  .risk-critical {{ color: #ef4444; }}
  .risk-high {{ color: #f97316; }}
  .risk-medium {{ color: #eab308; }}
  .risk-low {{ color: #22c55e; }}
  .gauge {{ text-align: center; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }}
  th {{ background: #1e293b; padding: 8px 10px; text-align: left; font-size: 11px; color: #64748b; text-transform: uppercase; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #1e293b; }}
  a {{ color: #60a5fa; }}
  .warning {{ background: #422006; color: #fbbf24; padding: 8px 12px; border-radius: 6px; margin: 4px 0; font-size: 13px; }}
  .summary {{ background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 24px; line-height: 1.6; }}
  .graph-container {{ background: #1e293b; border-radius: 8px; padding: 16px; text-align: center; overflow-x: auto; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-a {{ background: #22c55e; color: #052e16; }}
  .badge-b {{ background: #3b82f6; color: #052e16; }}
  .badge-c {{ background: #eab308; color: #422006; }}
  .badge-d {{ background: #f97316; color: #422006; }}
  .badge-f {{ background: #ef4444; color: #450a0a; }}
  @media print {{
    body {{ background: white; color: black; }}
    .card, .summary, .graph-container {{ background: #f8fafc; border: 1px solid #e2e8f0; }}
    th {{ background: #f1f5f9; color: #334155; }}
  }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <div>
    <h1>Intel Report</h1>
    <div class="meta">
      Target: <strong>{report.target}</strong> &middot;
      Report ID: {report.report_id} &middot;
      Duration: {report.duration_sec:.1f}s &middot;
      Iterations: {report.iterations}
    </div>
  </div>
  <div class="gauge">{gauge_svg}</div>
</div>

<div class="cards">
  <div class="card"><div class="label">Evidence Items</div><div class="value">{len(report.evidence)}</div></div>
  <div class="card"><div class="label">Modules Used</div><div class="value">{len(report.modules_run)}</div></div>
  <div class="card"><div class="label">Platforms Found</div><div class="value">{len(set(e.notes for e in report.evidence if e.notes))}</div></div>
  <div class="card"><div class="label">Risk Score</div><div class="value risk-{report.risk.level.value}">{report.risk.level.value.upper()}</div></div>
  <div class="card"><div class="label">Identifiers</div><div class="value">{len(report.confidence_by_identifier)}</div></div>
  <div class="card"><div class="label">Pivot Suggestions</div><div class="value">{len(report.pivots)}</div></div>
  <div class="card"><div class="label">Correlations</div><div class="value">{n_correlations}</div></div>
  <div class="card"><div class="label">Breaches Found</div><div class="value">{n_breaches}</div></div>
</div>

<div class="summary">
  <strong>Summary:</strong> {report.summary}
</div>

{'<div class="warning">' + "</div><div class='warning'>".join(report.warnings) + "</div>" if report.warnings else ""}

<h2>Risk Factors</h2>
<div class="card">{factors_html}</div>

<h2>Identity Graph</h2>
<div class="graph-container">{graph_svg}</div>

<h2>Evidence ({len(report.evidence)} items)</h2>
<table>
  <tr><th>Value</th><th>Type</th><th>Source</th><th>HTTP</th><th>URL</th><th>Confidence</th></tr>
  {evidence_rows}
</table>

<h2>Confidence by Identifier</h2>
<table>
  <tr><th>Identifier</th><th>Total</th><th>Grade</th></tr>
  {confidence_rows}
</table>

<h2>Timeline</h2>
<table>
  <tr><th>Timestamp</th><th>Source</th><th>Detail</th><th>Confidence</th></tr>
  {timeline_rows}
</table>

<h2>Pivot Suggestions</h2>
<table>
  <tr><th>Type</th><th>Value</th><th>Rationale</th><th>Sources</th></tr>
  {pivot_rows}
</table>

{f'<h2>Breach Timeline ({n_breaches} records)</h2><table><tr><th>Breach Name</th><th>Date</th><th>Data Classes</th><th>Source</th></tr>{breach_rows}</table>' if breach_rows else ""}

{f'<h2>Cross-Module Correlations ({n_correlations} clusters)</h2>{correlation_rows}' if correlation_rows else ""}

{f'<h2>Structured PII <small style="color:#ef4444">(restricted)</small></h2><details><summary style="cursor:pointer;color:#60a5fa">Show PII data (authorized personnel only)</summary><table><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th></tr>{pii_rows}</table></details>' if pii_rows else ""}

</div>
</body>
</html>"""
