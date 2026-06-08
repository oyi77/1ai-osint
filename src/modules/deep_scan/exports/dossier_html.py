"""Export a TargetDossier to beautiful HTML."""

from __future__ import annotations

from src.modules.deep_scan.dossier_compiler import TargetDossier


def export_dossier_html(dossier: TargetDossier) -> str:
    """Generate a beautiful HTML intelligence dossier."""

    # Safely convert to dict for template rendering
    try:
        data = dossier.model_dump()
    except AttributeError:
        data = dossier.dict()

    pfp = (
        data["profile_pictures"][0]
        if data["profile_pictures"]
        else "https://ui-avatars.com/api/?name=" + data["full_name"]
    )

    # Build sections
    emails_html = (
        "".join(
            [
                f"<li><strong>{e['address']}</strong> (Source: {e['source']}, Conf: {e['confidence']})</li>"
                for e in data["emails"]
            ]
        )
        or "<li>None discovered</li>"
    )
    phones_html = (
        "".join(
            [
                f"<li><strong>{p['number']}</strong> (Operator: {p['operator']}, WA: {p['whatsapp_registered']})</li>"
                for p in data["phones"]
            ]
        )
        or "<li>None discovered</li>"
    )

    socials_html = ""
    for s in data["social_accounts"]:
        socials_html += f"""
        <div class="social-card">
            <h4>{s["platform"].title()} - @{s["username"]}</h4>
            <p><a href="{s["url"]}">{s["url"]}</a></p>
            {f'<p><em>"{s["bio"]}"</em></p>' if s.get("bio") else ""}
        </div>
        """
    if not socials_html:
        socials_html = "<p>No social accounts discovered.</p>"

    gaps_html = (
        "".join([f"<li>{gap}</li>" for gap in data["intelligence_gaps"]])
        or "<li>None</li>"
    )

    breaches_html = (
        "".join(
            [
                f"<li><span class='badge red'>{b}</span></li>"
                for b in data["breached_services"]
            ]
        )
        or "<li>No breaches found</li>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Intelligence Dossier: {data["full_name"]}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --danger: #ef4444;
            --success: #22c55e;
            --warning: #f59e0b;
        }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            padding: 2rem;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--surface);
            padding-bottom: 2rem;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 2rem;
        }}
        .avatar {{
            width: 120px;
            height: 120px;
            border-radius: 60px;
            border: 3px solid var(--primary);
            object-fit: cover;
        }}
        .header-content h1 {{ margin: 0 0 0.5rem 0; font-size: 2.5rem; }}
        .header-content p {{ margin: 0; color: var(--text-muted); font-size: 1.1rem; }}

        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }}
        .card {{
            background: var(--surface);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--surface-hover);
        }}
        .card h3 {{
            margin-top: 0;
            border-bottom: 1px solid var(--surface-hover);
            padding-bottom: 0.5rem;
            color: var(--primary);
        }}
        ul {{ padding-left: 1.5rem; margin: 0; }}
        li {{ margin-bottom: 0.5rem; }}

        .social-card {{
            background: var(--bg);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid var(--surface-hover);
        }}
        .social-card h4 {{ margin: 0 0 0.5rem 0; }}
        .social-card p {{ margin: 0.25rem 0; font-size: 0.9rem; color: var(--text-muted); }}
        .social-card a {{ color: var(--primary); text-decoration: none; }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge.red {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); }}
        .badge.green {{ background: rgba(34, 197, 94, 0.2); color: var(--success); }}

        .classification {{
            text-align: center;
            color: var(--warning);
            font-weight: bold;
            letter-spacing: 2px;
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }}

        .full-width {{ grid-column: 1 / -1; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="classification">{data["classification"]}</div>

        <div class="header">
            <img src="{pfp}" alt="Subject Avatar" class="avatar">
            <div class="header-content">
                <h1>{data["full_name"]}</h1>
                <p><strong>Aliases:</strong> {", ".join(data["aliases"]) or "None"}</p>
                <p><strong>Confidence Score:</strong> <span class="badge {"green" if data["confidence_score"] > 0.5 else "red"}">{data["confidence_score"] * 100}%</span></p>
                <p><small>ID: {data["report_id"]} | Generated: {data["generated_at"]}</small></p>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Contact Information</h3>
                <p><strong>Emails:</strong></p>
                <ul>{emails_html}</ul>
                <p><strong>Phones:</strong></p>
                <ul>{phones_html}</ul>
            </div>

            <div class="card">
                <h3>Employment & Location</h3>
                <p><strong>Employer:</strong> {data["current_employer"] or "Unknown"}</p>
                <p><strong>Title:</strong> {data["job_title"] or "Unknown"}</p>
                <p><strong>Locations:</strong> {", ".join(data["known_locations"]) or "Unknown"}</p>
            </div>

            <div class="card full-width">
                <h3>Digital Footprint</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1rem;">
                    {socials_html}
                </div>
            </div>

            <div class="card">
                <h3>Security Profile</h3>
                <p><strong>Breached Services:</strong></p>
                <ul>{breaches_html}</ul>
                <p><strong>Exposed Data Types:</strong> {", ".join(data["exposed_data_types"]) or "None"}</p>
            </div>

            <div class="card">
                <h3>Intelligence Gaps</h3>
                <ul style="color: var(--warning);">{gaps_html}</ul>
            </div>
        </div>

        <div class="classification" style="margin-top: 3rem;">{data["classification"]}</div>
    </div>
</body>
</html>
"""
