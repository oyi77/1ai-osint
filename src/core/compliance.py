"""Compliance layer — legal-basis registry and audit logging (blueprint Layer 3).

Implements the blueprint's compliance-by-design mandate (UU PDP Law 27/2022):

S1 — Legal-basis registry: every data source carries a ``LegalBasis`` enum,
     retention policy, and consent flag. Unknown sources default to
     ``UNDOCUMENTED`` so the gap is visible instead of silently assumed.

S2 — Central audit log: every adapter query records source, target,
     legal basis, timestamp, requester, and outcome. Retention-aware
     purge helper enforces the default 30-day policy.

The registry is keyed by source name (``src/modules/sources/*_source.py``
and ``src/modules/free_intel/*.py``). Backfill values reflect each
source's public contract; anything not listed is UNDOCUMENTED by design.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.config import settings
from src.core.rbac import AccessTier

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 30  # Sherlockeye standard per blueprint §4.5
DEFAULT_RPM = 60  # default per-source requests-per-minute (ToS guard)


class LegalBasis(str, Enum):
    """Documented legal basis for querying a data source (UU PDP)."""

    GOVERNMENT_OPEN_DATA = "government_open_data"
    LEGITIMATE_INTEREST = "legitimate_interest"
    CONSENT = "consent"
    PUBLIC_API_TOS = "public_api_tos"
    UNDOCUMENTED = "undocumented"


class SourceCompliance(BaseModel):
    """Compliance metadata for a single data source."""

    source: str
    legal_basis: LegalBasis = LegalBasis.UNDOCUMENTED
    retention_days: int = DEFAULT_RETENTION_DAYS
    requires_consent: bool = False
    tos_notes: str = ""
    # RBAC (Layer 3): minimum tier required to query this source.
    min_tier: AccessTier = AccessTier.READONLY
    # ToS guard (Layer 3): per-source rate ceiling in requests/minute.
    requests_per_minute: int = DEFAULT_RPM


class AuditEntry(BaseModel):
    """A single audit log entry — one query = one entry."""

    id: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str
    target: str
    legal_basis: str
    requester: str
    outcome: str  # ok | empty | error | blocked | throttled
    findings_count: int = 0
    retention_days: int = DEFAULT_RETENTION_DAYS


# ── S1: Legal-basis registry ──────────────────────────────────────────────────

# Keyed by source name → SourceCompliance. Backfill reflects each source's
# actual public contract (API, CLI, or scraping) and UU PDP posture.
_COMPLIANCE_REGISTRY: dict[str, SourceCompliance] = {}


def _register(
    source: str,
    legal_basis: LegalBasis,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    requires_consent: bool = False,
    tos_notes: str = "",
    min_tier: AccessTier = AccessTier.READONLY,
    requests_per_minute: int = DEFAULT_RPM,
) -> None:
    _COMPLIANCE_REGISTRY[source] = SourceCompliance(
        source=source,
        legal_basis=legal_basis,
        retention_days=retention_days,
        requires_consent=requires_consent,
        tos_notes=tos_notes,
        min_tier=min_tier,
        requests_per_minute=requests_per_minute,
    )


# — Public API / ToS-gated sources (blueprint §3: API resmi > scraping) —
_PUBLIC_API_SOURCES = {
    "abuseipdb": "AbuseIPDB API — ToS-governed, API key required",
    "anubis": "Anubis (jldc.me) subdomain index — keyless public endpoint",
    "bgpview": "BGPView public API — open BGP/ASN data",
    "certspotter": "Cert Spotter CT API — public certificate transparency data",
    "blockchair": "Blockchair API — public blockchain data",
    "cargo": "crates.io public registry API",
    "censys": "Censys API — paid tier, ToS-governed",
    "codeberg": "Gitea public API",
    "crtsh": "Certificate Transparency log API",
    "dns_records": "Google DoH resolver — public DNS data",
    "etherscan": "Etherscan API — public blockchain data",
    "feodo": "abuse.ch Feodo tracker feed (open threat intel)",
    "github": "GitHub REST API — ToS-governed, token auth",
    "gitlab": "GitLab public API",
    "gomod": "Go module proxy public API",
    "greynoise": "GreyNoise API — ToS-governed",
    "hackertarget": "HackerTarget free API — keyless, ToS-governed",
    "hibp": "HIBP v3 API — lawful gold standard per blueprint §3",
    "hunter": "Hunter.io API — paid tier, ToS-governed",
    "ip_api": "ip-api.com free endpoint — HTTP-only, ToS-governed",
    "ipinfo": "ipinfo.io API — ToS-governed",
    "keybase": "Keybase public profile API — keyless",
    "malwarebazaar": "MalwareBazaar API (abuse.ch open feed)",
    "mastodon": "Mastodon public API",
    "mempool": "mempool.space public API — open blockchain data",
    "npm": "npm registry public API",
    "otx": "AlienVault OTX API — open threat intel",
    "pgp_keys": "keys.openpgp.org VKS — public key directory",
    "proxynova": "ProxyNova combine — keyless public breach/paste search",
    "pulsedive": "Pulsedive API — threat intel feed",
    "pypi": "PyPI JSON API",
    "rapiddns": "RapidDNS public search — keyless subdomain lookup",
    "reddit": "Reddit via pullpush.io API",
    "rubygems": "RubyGems public API",
    "securitytrails": "SecurityTrails API — paid tier, ToS-governed",
    "shodan": "Shodan API — paid tier, ToS-governed (blueprint Phase 4 premium)",
    "stackoverflow": "StackExchange API — ToS-governed",
    "threatfox": "ThreatFox API (abuse.ch open feed)",
    "urlhaus": "URLhaus API (abuse.ch open feed)",
    "urlscan": "urlscan.io public search API — keyless limited tier",
    "veriphone": "Veriphone public phone-verify API — keyless",
    "virustotal": "VirusTotal API — ToS-governed",
    "wayback": "Wayback Machine CDX/availability API",
    "wigle": "WiGLE API — ToS-governed; network metadata is location-sensitive",
    "zoomeye": "ZoomEye API — paid tier, ToS-governed",
}
for _name, _note in _PUBLIC_API_SOURCES.items():
    _register(_name, LegalBasis.PUBLIC_API_TOS, tos_notes=_note)

# Real per-source rate ceilings from each API's published rate-limit
# contract (Layer 3 ToS guard). These override the generic 60 rpm default
# so the guard enforces what each provider actually allows.
for _name, _rpm in (("virustotal", 4), ("hibp", 30), ("abuseipdb", 120)):
    if _name in _COMPLIANCE_REGISTRY:
        _COMPLIANCE_REGISTRY[_name].requests_per_minute = _rpm

# Tier overrides: sources whose data is sensitive enough that credentialed
# access alone is insufficient (RBAC Layer 3). Shodan/Censys expose raw
# service banners and CVE context — ANALYST+ only, READONLY tokens blocked.
for _name in ("shodan", "censys"):
    if _name in _COMPLIANCE_REGISTRY:
        _COMPLIANCE_REGISTRY[_name].min_tier = AccessTier.ANALYST

# — Legitimate-interest sources (publicly available data via OSINT tooling) —
_LEGITIMATE_INTEREST_SOURCES = {
    "amass": "Public DNS/cert data enumeration",
    "bbot": "OSINT recon aggregator over public data",
    "bitcointalk": "Public forum posts",
    "darknet": "Public Tor-hidden-service pages",
    "discord": "Public server/account data via API",
    "dnsdumpster": "Public DNS data",
    "duckduckgo": "Public web search (HTML)",
    "exiftool": "Local file metadata extraction — no network",
    "h8mail": "Email breach data from public sources; verify each feed's ToS",
    "holehe": "Email→platform registration check against public endpoints",
    "httpx": "Public HTTP probing",
    "maigret": "Username enumeration across 3,000+ public sites",
    "maltego": "Public transforms",
    "nmap": "Network scanning — authorized use only",
    "paste": "Public pastebin/paste sites",
    "phoneinfoga": "Public phone-number OSINT lookups",
    "recon_ng": "Public recon modules",
    "rss": "Public RSS feeds",
    "s3": "Open AWS S3 bucket discovery — only public buckets",
    "sherlock": "Username enumeration across 400+ public sites",
    "social": "Public social profile data",
    "spiderfoot": "Aggregator over public OSINT sources",
    "subfinder": "Public subdomain enumeration",
    "telegram": "Public Telegram channels via Telethon",
    "theharvester": "Public email/subdomain search",
    "twitter": "Public Twitter/X data — verify API tier ToS",
    "whatsmyname": "Username enumeration across public sites",
    "whois": "Public WHOIS records",
}
for _name, _note in _LEGITIMATE_INTEREST_SOURCES.items():
    _register(_name, LegalBasis.LEGITIMATE_INTEREST, tos_notes=_note)

# — Paid breach DBs: legal review required before production use (blueprint §3 ⛔) —
for _name in ("dehashed", "intelx", "leakcheck", "snusbase", "snylla", "scylla"):
    _register(
        _name,
        LegalBasis.UNDOCUMENTED,
        tos_notes=(
            "Paid breach database — legal basis review required before production use (blueprint §3 ⛔ category)"
        ),
        # Undocumented + sensitive → ADMIN-only (RBAC Layer 3).
        min_tier=AccessTier.ADMIN,
        requests_per_minute=10,
    )

# — Free intel module (public endpoints, no API keys) —
_FREE_INTEL_SOURCES = {
    "ai_enricher": "Internal AI enrichment — no external query",
    "bts_intel": "Public telecom/BTS data",
    "github_intel": "GitHub public profiles via public API",
    "google_dork_intel": "Public search-engine dorking",
    "gravatar_intel": "Gravatar public profile API",
    "hibp_free": "HIBP free tier (public API)",
    "pddikti_intel": "Indonesian higher-ed open data (PDDIKTI, Kemendikbud)",
    "social_dorks_intel": "Public social search dorking",
    "tech_jobs_intel": "Public job-platform data",
    "wayback_intel": "Wayback Machine public API",
    "whatsapp_telegram_check": "Public account-existence checks",
}
for _name, _note in _FREE_INTEL_SOURCES.items():
    _register(_name, LegalBasis.PUBLIC_API_TOS, tos_notes=_note)

# Indonesian government open data — strongest legal basis (blueprint §4.1)
_register(
    "pddikti_intel",
    LegalBasis.GOVERNMENT_OPEN_DATA,
    tos_notes="PDDIKTI open data — government open data basis (blueprint §4)",
)
_register(
    "pandi_whois_intel",
    LegalBasis.GOVERNMENT_OPEN_DATA,
    tos_notes="PANDI RDAP registry data — public .id registration records (blueprint §5 local moat)",
)
_register(
    "data_go_id_intel",
    LegalBasis.GOVERNMENT_OPEN_DATA,
    tos_notes="data.go.id Satu Data Indonesia — public government datasets (blueprint §5 local moat)",
)


def get_compliance(source_name: str) -> SourceCompliance:
    """Return compliance metadata for a source.

    Unknown sources default to UNDOCUMENTED — the gap is visible in the
    audit trail instead of silently assumed compliant.
    """
    return _COMPLIANCE_REGISTRY.get(
        source_name,
        SourceCompliance(source=source_name, legal_basis=LegalBasis.UNDOCUMENTED),
    )


def is_consent_required(source_name: str) -> bool:
    """True if the source touches Pasal 4.2 sensitive categories."""
    return get_compliance(source_name).requires_consent


def min_tier_for(source_name: str) -> AccessTier:
    """Return the minimum access tier required to query this source."""
    return get_compliance(source_name).min_tier


def source_allows_tier(source_name: str, requester_tier: AccessTier) -> bool:
    """True if ``requester_tier`` is privileged enough to query the source.

    RBAC (Layer 3): a requester must hold a tier at least as privileged as
    the source's ``min_tier``.
    """
    return requester_tier >= min_tier_for(source_name)


def requests_per_minute_for(source_name: str) -> int:
    """Return the per-source ToS rate ceiling (requests per minute)."""
    return get_compliance(source_name).requests_per_minute


def registered_sources() -> list[str]:
    """Return all source names with explicit compliance metadata."""
    return sorted(_COMPLIANCE_REGISTRY)


# ── S2: Audit log ─────────────────────────────────────────────────────────────


def audit_log_path() -> Path:
    """Resolve the audit log file path from settings."""
    path = Path(settings.audit_log_path)
    if not path.is_absolute():
        path = settings.project_root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def record_audit(
    *,
    source: str,
    target: str,
    requester: str,
    outcome: str,
    findings_count: int = 0,
    legal_basis: str | None = None,
) -> AuditEntry:
    """Append one audit entry to the JSONL audit log.

    Every adapter query must pass through here (S2). The entry records
    source, target, legal basis, timestamp, requester, and outcome.
    """
    compliance = get_compliance(source)
    entry = AuditEntry(
        source=source,
        target=target,
        legal_basis=legal_basis or compliance.legal_basis.value,
        requester=requester,
        outcome=outcome,
        findings_count=findings_count,
        retention_days=compliance.retention_days,
    )
    try:
        with audit_log_path().open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")
    except OSError as exc:
        logger.warning("Audit log write failed: %s", exc)
    return entry


def purge_expired_audit_entries(now: datetime | None = None) -> int:
    """Remove audit entries older than their retention window.

    Default retention is 30 days (blueprint §4.5). Returns the number of
    purged entries. The rewrite is atomic (temp file + ``os.replace``) so a
    crash mid-purge can never truncate the audit log.
    """
    path = audit_log_path()
    if not path.exists():
        return 0
    now = now or datetime.now(timezone.utc)
    kept: list[str] = []
    purged = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ts = datetime.fromisoformat(data["timestamp"])
                retention = int(data.get("retention_days", DEFAULT_RETENTION_DAYS))
                if ts + timedelta(days=retention) < now:
                    purged += 1
                    continue
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.debug("Skipping malformed audit line: %s", exc)
            kept.append(line)
    if purged:
        body = "\n".join(kept) + ("\n" if kept else "")
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                tmp.write(body)
            os.replace(tmp_name, path)
        except OSError:
            logger.warning("Atomic audit purge failed; leaving log untouched")
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
    return purged


def read_audit_entries(limit: int = 100) -> list[dict[str, Any]]:
    """Read recent audit entries (newest first)."""
    path = audit_log_path()
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(entries[-limit:]))
