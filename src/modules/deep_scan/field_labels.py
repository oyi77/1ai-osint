"""Emoji field labels for intel report presentation (LeakBase-style)."""
from __future__ import annotations

import html
import re
from typing import Any

# (field_key, emoji, display_label) — order matters for presentation
FIELD_SPECS: tuple[tuple[str, str, str], ...] = (
    ("email", "📩", "Email"),
    ("username", "👤", "Nick"),
    ("name", "👤", "Full name"),
    ("full_name", "👤", "Full name"),
    ("phone", "📞", "Telephone"),
    ("phone_number", "📞", "Telephone"),
    ("password", "🔑", "Password"),
    ("password_hash", "🔐", "Encrypted password"),
    ("ip_address", "🎯", "IP"),
    ("ip", "🎯", "IP"),
    ("domain", "🌐", "Domain"),
    ("address", "🏘️", "Address"),
    ("city", "🌃", "City"),
    ("region", "🗺️", "Region"),
    ("country", "🗾", "Country"),
    ("gender", "🚻", "Gender"),
    ("birth_date", "🎂", "Date of birth"),
    ("date_of_birth", "🎂", "Date of birth"),
    ("dob", "🎂", "Date of birth"),
    ("nik", "📖", "NIK / ID number"),
    ("passport_number", "📖", "Passport number"),
    ("breach_name", "💀", "Breach name"),
    ("breach_date", "📆", "Breach date"),
    ("data_classes", "📋", "Data classes"),
    ("registration_date", "📆", "Registration date"),
    ("last_activity", "📆", "Last activity"),
    ("job_title", "🏢", "Job title"),
    ("company", "🏢", "Company"),
    ("company_name", "🏢", "Company name"),
    ("platform", "📱", "Platform"),
    ("source_url", "🔗", "Source URL"),
    ("target", "🎯", "Search target"),
    ("display_name", "👤", "Display name"),
    ("type", "🏷️", "Record type"),
)

_SKIP_KEYS = frozenset({
    "platforms", "_source", "_id", "profile", "type",
})

_SOURCE_META: dict[str, tuple[str, str]] = {
    "social_osint": ("🌐", "Cross-platform social profile presence and username availability."),
    "people_finder": ("🔍", "Username enumeration across public social platforms (Sherlock/Maigret)."),
    "data_leaks": ("💧", "Aggregated breach and leak database matches."),
    "source_dehashed": ("🔓", "DeHashed breach intelligence API."),
    "source_hibp": ("💀", "Have I Been Pwned breach exposure."),
    "source_leakcheck": ("🕵️", "LeakCheck credential exposure."),
    "source_snusbase": ("🗄️", "Snusbase breach records."),
    "source_snylla": ("🗄️", "Scylla / Snylla breach index."),
    "source_intelx": ("🧠", "Intelligence X deep-web and leak index."),
    "email_osint": ("📧", "Email OSINT and verification signals."),
    "phone_finder": ("📞", "Phone number OSINT."),
    "domain_recon": ("🌍", "Domain reconnaissance."),
}


def source_display_name(module: str) -> str:
    key = (module or "unknown").lower()
    if key.startswith("source_"):
        key = key[7:]
    emoji, blurb = _SOURCE_META.get(module.lower(), _SOURCE_META.get(f"source_{key}", ("📁", "")))
    if module.lower() in _SOURCE_META:
        emoji, _ = _SOURCE_META[module.lower()]
    name = key.replace("_", " ").title()
    if module.lower() in _SOURCE_META:
        return f"{emoji}{name}"
    if key in {k.replace("source_", "") for k in _SOURCE_META if k.startswith("source_")}:
        for mk, (em, _) in _SOURCE_META.items():
            if mk.endswith(key):
                return f"{em}{name}"
    return f"{emoji}{name}"


def source_blurb(module: str) -> str:
    mod = (module or "").lower()
    if mod in _SOURCE_META:
        return _SOURCE_META[mod][1]
    if mod.startswith("source_"):
        return _SOURCE_META.get(mod, ("", "Structured breach/leak source record."))[1]
    return f"Intelligence collected from module <code>{html.escape(module)}</code>."


def _humanize_key(key: str) -> str:
    return re.sub(r"\s+", " ", key.replace("_", " ").strip()).title()


def format_record_fields(record: dict[str, Any]) -> str:
    """Render one record as HTML field lines (LeakBase-style)."""
    if not record:
        return ""
    used: set[str] = set()
    lines: list[str] = []

    for key, emoji, label in FIELD_SPECS:
        val = record.get(key)
        if val is None or val == "":
            val = record.get(key.replace("_", " "))
        if val is None or val == "":
            continue
        used.add(key)
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        lines.append(
            f"<b>{emoji}{label}: </b> <code>{html.escape(str(val))}</code><br>"
        )

    for key, val in sorted(record.items()):
        if key in used or key in _SKIP_KEYS or key.startswith("_"):
            continue
        if val is None or val == "":
            continue
        if isinstance(val, (dict, list)):
            if isinstance(val, list) and val and isinstance(val[0], dict):
                continue
            if isinstance(val, dict):
                continue
        lines.append(
            f"<b>📌{_humanize_key(key)}: </b> <code>{html.escape(str(val))}</code><br>"
        )

    return "<br>".join(lines) if lines else "<i>No structured fields</i><br>"


def _platform_url(platform: str, username: str) -> str:
    handle = re.sub(r"[^a-zA-Z0-9._-]", "", username.lower().replace(" ", ""))
    urls = {
        "github": f"https://github.com/{handle}",
        "gitlab": f"https://gitlab.com/{handle}",
        "twitter": f"https://twitter.com/{handle}",
        "instagram": f"https://instagram.com/{handle}",
        "reddit": f"https://reddit.com/user/{handle}",
        "linkedin": f"https://linkedin.com/in/{handle}",
    }
    return urls.get((platform or "").lower(), "")


def format_platform_block(platforms: list[dict[str, Any]], username: str) -> str:
    """Render social platform checklist as readable records."""
    chunks: list[str] = []
    for plat in platforms:
        if not isinstance(plat, dict):
            continue
        name = plat.get("platform", "?")
        status = plat.get("status", "?")
        exists = plat.get("exists", False)
        url = plat.get("url") or _platform_url(name, username)
        flag = "✅" if exists else "❌"
        chunks.append(
            f"<b>📱Platform: </b> {html.escape(str(name))} {flag}<br>"
            f"<b>🔗URL: </b> <a href=\"{html.escape(url)}\" target=\"_blank\">"
            f"<code>{html.escape(url)}</code></a><br>"
            f"<b>📊HTTP: </b> <code>{html.escape(str(status))}</code><br>"
        )
    return "<br>".join(chunks)
