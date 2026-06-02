"""Operational intelligence briefing — pre-deployment style OSINT packet."""
from __future__ import annotations

import re
from typing import Any

from src.modules.deep_scan import IdentifierType
from src.modules.deep_scan.models_report import (
    BreachIntelRecord,
    DigitalAccount,
    IntelReport,
    OperationalBriefing,
    SubjectProfile,
)


def build_operational_briefing(result: Any, report: IntelReport) -> OperationalBriefing:
    """Assemble CIA/FBI-style briefing sections from scan + intel report."""
    subject = _build_subject(result, report)
    accounts = _build_digital_accounts(result)
    breaches = _build_breach_records(result)
    gaps = _build_gaps(result, report, subject, accounts, breaches)
    actions = _build_actions(report, subject, gaps)
    judgments = _build_key_judgments(report, subject, accounts, breaches)
    bluf = _build_bluf(report, subject, accounts, breaches)

    return OperationalBriefing(
        bluf=bluf,
        subject=subject,
        digital_accounts=accounts,
        breach_records=breaches,
        intelligence_gaps=gaps,
        recommended_actions=actions,
        key_judgments=judgments,
    )


def _build_subject(result: Any, report: IntelReport) -> SubjectProfile:
    profile = SubjectProfile(primary_name=result.target)
    aliases: set[str] = set()
    handles: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()
    niks: set[str] = set()
    locations: set[str] = set()

    for ident in getattr(result, "identifiers", []) or []:
        val = ident.value.strip()
        if not val or val.startswith(("http://", "https://")):
            continue
        if ident.id_type == IdentifierType.NAME and val.lower() != result.target.lower():
            aliases.add(val)
        elif ident.id_type == IdentifierType.USERNAME:
            handles.add(val)
        elif ident.id_type == IdentifierType.EMAIL:
            emails.add(val.lower())
        elif ident.id_type == IdentifierType.PHONE:
            from src.utils.phone_normalize import normalize_phone_e164

            normalized = normalize_phone_e164(val) or val
            phones.add(normalized)
        elif ident.id_type == IdentifierType.NIK:
            niks.add(val)

    for ev in report.evidence:
        t = ev.identifier_type
        v = ev.identifier_value.strip()
        if t == "email" and v:
            emails.add(v.lower())
        elif t == "phone" and v:
            phones.add(v)
        elif t == "nik" and v:
            niks.add(v)
        elif t == "username" and v and not v.startswith("http"):
            handles.add(v)

    for finding in getattr(result, "findings", []) or []:
        rd = finding.raw_data or {}
        for key in ("address", "city", "region", "location", "country"):
            if rd.get(key):
                locations.add(str(rd[key]))

    profile.known_aliases = sorted(aliases)
    profile.known_handles = sorted(handles)
    profile.emails = sorted(emails)
    profile.phones = sorted(phones)
    profile.niks = sorted(niks)
    profile.locations = sorted(locations)
    return profile


def _build_digital_accounts(result: Any) -> list[DigitalAccount]:
    seen: set[tuple[str, str]] = set()
    accounts: list[DigitalAccount] = []

    for finding in getattr(result, "findings", []) or []:
        mod = getattr(finding, "module", "") or ""
        rd = finding.raw_data or {}

        if mod == "people_finder" and rd.get("platform"):
            key = (str(rd["platform"]).lower(), str(rd.get("username", "")))
            if key in seen:
                continue
            seen.add(key)
            providers = rd.get("source_providers") or []
            if isinstance(providers, str):
                providers = [providers]
            accounts.append(DigitalAccount(
                platform=str(rd["platform"]),
                username=str(rd.get("username", "")),
                url=str(rd.get("url", "")),
                status=str(rd.get("status", "found")),
                confidence=float(getattr(finding, "confidence", 0.7) or 0.7),
                sources=list(providers) or ["people_finder"],
            ))
            continue

        if mod == "social_osint" and isinstance(rd.get("platforms"), list):
            user = str(rd.get("username", ""))
            for plat in rd["platforms"]:
                if not isinstance(plat, dict):
                    continue
                platform = str(plat.get("platform", "?"))
                key = (platform.lower(), user)
                if key in seen:
                    continue
                seen.add(key)
                exists = plat.get("exists", False)
                from src.modules.deep_scan.field_labels import _platform_url

                accounts.append(DigitalAccount(
                    platform=platform,
                    username=user,
                    url=plat.get("url") or _platform_url(platform, user),
                    status="confirmed" if exists else "not_found",
                    confidence=0.85 if exists else 0.25,
                    sources=["social_osint"],
                ))

    accounts.sort(key=lambda a: (-a.confidence, a.platform))
    return accounts


def _build_breach_records(result: Any) -> list[BreachIntelRecord]:
    records: list[BreachIntelRecord] = []
    for finding in getattr(result, "findings", []) or []:
        mod = (getattr(finding, "module", "") or "").lower()
        if not (mod.startswith("source_") or mod == "data_leaks"):
            continue
        rd = dict(getattr(finding, "raw_data", None) or {})
        skip = {"platforms", "type", "profile"}
        from src.modules.deep_scan.breach_normalizer import normalize_breach_record

        fields = normalize_breach_record({
            k: v for k, v in rd.items()
            if k not in skip and v is not None and str(v).strip()
        })
        if not fields:
            fields = {
                _label_key(k): str(v)
                for k, v in rd.items()
                if k not in skip and v is not None and str(v).strip()
            }
        if not fields:
            continue
        records.append(BreachIntelRecord(
            source=mod.replace("source_", ""),
            breach_name=str(
                fields.get("breach_name")
                or fields.get("Breach Name")
                or fields.get("Breach")
                or rd.get("breach_name")
                or mod
            ),
            fields=fields,
            confidence=float(getattr(finding, "confidence", 0.6) or 0.6),
        ))
    return records


def _label_key(key: str) -> str:
    return re.sub(r"\s+", " ", key.replace("_", " ").strip()).title()


def _build_gaps(
    result: Any,
    report: IntelReport,
    subject: SubjectProfile,
    accounts: list[DigitalAccount],
    breaches: list[BreachIntelRecord],
) -> list[str]:
    gaps: list[str] = []
    if not subject.emails:
        gaps.append("No verified email addresses — run breach APIs (HIBP, DeHashed, LeakCheck) after email discovery.")
    if not subject.phones:
        gaps.append("No phone numbers identified — consider phone_finder / regional registries.")
    if not breaches:
        gaps.append("No breach corpus hits — configure DEHASHED_API_KEY, HIBP_API_KEY, LEAKCHECK_API_KEY in .env.")
    if len(accounts) < 3:
        gaps.append("Limited digital footprint — run full deep scan with sherlock + maigret (pip install).")
    if not subject.niks and _likely_indonesian(result.target):
        gaps.append("No NIK / national ID — Indonesian civil registry sources not queried.")
    if not subject.locations:
        gaps.append("No geolocation indicators — expand to domain/WHOIS and address fields in breach data.")
    for err in getattr(result, "errors", []) or []:
        if "timeout" in str(err).lower():
            gaps.append(f"Collection incomplete: {err}")
    if not gaps:
        gaps.append("No critical collection gaps flagged — validate high-confidence items manually.")
    return gaps


def _likely_indonesian(name: str) -> bool:
    return bool(name) and not re.search(r"[àáâãäå]", name, re.I)


def _build_actions(
    report: IntelReport, subject: SubjectProfile, gaps: list[str],
) -> list[str]:
    actions: list[str] = []
    for p in sorted(report.pivots, key=lambda x: x.priority)[:8]:
        if p.target_value and not p.target_value.startswith("http"):
            actions.append(
                f"[P{p.priority}] {p.target_type.upper()}: {p.target_value} — {p.rationale}"
            )
    for handle in subject.known_handles[:3]:
        actions.append(f"Enumerate {handle} across archived web (Wayback) and code repos (GitHub dorks).")
    for email in subject.emails[:2]:
        actions.append(f"Deep breach pivot on {email} (HIBP, DeHashed, IntelX).")
    if not actions:
        actions.append("Re-run deep scan with API keys and --fast disabled for full module coverage.")
    return actions[:12]


def _build_key_judgments(
    report: IntelReport,
    subject: SubjectProfile,
    accounts: list[DigitalAccount],
    breaches: list[BreachIntelRecord],
) -> list[str]:
    judgments: list[str] = []
    confirmed = [a for a in accounts if a.status in ("found", "confirmed") and a.confidence >= 0.7]
    if confirmed:
        platforms = ", ".join(sorted({a.platform for a in confirmed})[:6])
        judgments.append(
            f"Subject likely operates accounts on: {platforms} ({len(confirmed)} high-confidence hits)."
        )
    if subject.known_handles:
        judgments.append(
            f"Primary handle candidates: {', '.join(subject.known_handles[:5])}."
        )
    if breaches:
        judgments.append(
            f"Credential exposure detected in {len(breaches)} breach source(s) — treat as compromise risk."
        )
    if report.risk.factors:
        triggered = [f.description for f in report.risk.factors if f.triggered]
        if triggered:
            judgments.append(f"Risk drivers: {'; '.join(triggered[:3])}.")
    if not judgments:
        judgments.append("Insufficient corroboration for strong identity attribution — collection phase ongoing.")
    return judgments


def _build_bluf(
    report: IntelReport,
    subject: SubjectProfile,
    accounts: list[DigitalAccount],
    breaches: list[BreachIntelRecord],
) -> str:
    confirmed = sum(1 for a in accounts if a.confidence >= 0.7 and a.status in ("found", "confirmed"))
    parts = [
        f"Open-source scan on '{report.target}' completed in {report.duration_sec:.0f}s",
        f"with {len(report.evidence)} observations across {len(report.modules_run)} module(s).",
    ]
    if subject.known_handles:
        parts.append(f"Key handles: {', '.join(subject.known_handles[:3])}.")
    if confirmed:
        parts.append(f"{confirmed} confirmed platform presence(s).")
    if breaches:
        parts.append(f"{len(breaches)} breach record(s) require analyst review.")
    parts.append(f"Overall exposure: {report.risk.level.value.upper()} ({report.risk.score:.0%}).")
    return " ".join(parts)
