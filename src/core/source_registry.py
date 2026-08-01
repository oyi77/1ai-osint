"""Source transport registry — how every collection source reaches the network.

Every module/source name is classified by transport:

    RE      — keyless reverse-engineered/public endpoint (no credential needed)
    SCRAPE  — keyless HTML/structured scraping (no credential needed)
    API     — vendor API; may require an API key
    TOOL    — local CLI tool invocation (keyless, runs on this host)
    LOCAL   — purely local processing (no network)

0-API mode (``NO_API=1`` env or ``--no-api`` CLI flag) runs only keyless-
capable modules and orders RE first. The registry is separate from the
compliance registry: it describes *how* we fetch, not *whether* we may.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TransportKind(str, Enum):
    RE = "re"
    SCRAPE = "scrape"
    API = "api"
    TOOL = "tool"
    LOCAL = "local"


RE = TransportKind.RE
SCRAPE = TransportKind.SCRAPE
API = TransportKind.API
TOOL = TransportKind.TOOL
LOCAL = TransportKind.LOCAL


@dataclass(frozen=True)
class SourceEntry:
    kind: TransportKind
    key_env: str = ""
    key_optional: bool = False
    keyless_fallback: bool = False
    note: str = ""


_REGISTRY: dict[str, SourceEntry] = {
    # --- RE: keyless reverse-engineered / public endpoints ---
    "crtsh": SourceEntry(RE),
    "wayback": SourceEntry(RE),
    "whois": SourceEntry(RE),
    "urlhaus": SourceEntry(RE),
    "threatfox": SourceEntry(RE),
    "feodo": SourceEntry(RE),
    "malwarebazaar": SourceEntry(RE),
    "blockchair": SourceEntry(RE),
    "cargo": SourceEntry(RE),
    "codeberg": SourceEntry(RE),
    "gitlab": SourceEntry(RE),
    "npm": SourceEntry(RE),
    "pypi": SourceEntry(RE),
    "rubygems": SourceEntry(RE),
    "mastodon": SourceEntry(RE),
    "reddit": SourceEntry(RE),
    "stackoverflow": SourceEntry(RE),
    "s3": SourceEntry(RE),
    "rss": SourceEntry(RE),
    "social": SourceEntry(RE),
    "twitter": SourceEntry(RE),
    "telegram": SourceEntry(RE, "TELEGRAM_API_ID", key_optional=True, note="free API ID/HASH; bot token optional"),
    "crypto_balance": SourceEntry(RE),
    "crypto_tracer": SourceEntry(RE),
    "vuln_scanner": SourceEntry(RE),
    "hackertarget": SourceEntry(RE),
    "dns_records": SourceEntry(RE),
    "mempool": SourceEntry(RE),
    "ip_api": SourceEntry(RE),
    "pgp_keys": SourceEntry(RE),
    "anubis": SourceEntry(RE),
    "bgpview": SourceEntry(RE),
    "certspotter": SourceEntry(RE),
    "rapiddns": SourceEntry(RE),
    "urlscan": SourceEntry(RE),
    "proxynova": SourceEntry(RE),
    "veriphone": SourceEntry(RE),
    "keybase": SourceEntry(RE),
    "huggingface": SourceEntry(RE),
    "scratch": SourceEntry(RE),
    "itchio": SourceEntry(RE),
    "codeforces": SourceEntry(RE),
    # --- SCRAPE: keyless HTML / structured scraping ---
    "paste": SourceEntry(SCRAPE),
    "duckduckgo": SourceEntry(SCRAPE),
    "whatsmyname": SourceEntry(SCRAPE),
    "discord": SourceEntry(SCRAPE),
    "bitcointalk": SourceEntry(SCRAPE),
    "darknet": SourceEntry(SCRAPE),
    "dnsdumpster": SourceEntry(SCRAPE),
    "social_osint": SourceEntry(SCRAPE),
    "email_osint": SourceEntry(SCRAPE),
    "domain_recon": SourceEntry(SCRAPE),
    "people_finder": SourceEntry(SCRAPE),
    "phone_finder": SourceEntry(SCRAPE),
    "data_leaks": SourceEntry(SCRAPE),
    "social_dorks_intel": SourceEntry(SCRAPE),
    "gravatar_intel": SourceEntry(SCRAPE),
    "wayback_intel": SourceEntry(SCRAPE),
    "github_intel": SourceEntry(SCRAPE),
    "google_dork_intel": SourceEntry(SCRAPE),
    "hibp_free": SourceEntry(SCRAPE),
    "bts_intel": SourceEntry(SCRAPE),
    "pddikti_intel": SourceEntry(SCRAPE),
    "tech_jobs_intel": SourceEntry(SCRAPE),
    "whatsapp_check": SourceEntry(SCRAPE),
    "telegram_check": SourceEntry(SCRAPE),
    "pandi_whois_intel": SourceEntry(SCRAPE),
    "data_go_id_intel": SourceEntry(SCRAPE),
    # --- API: keyless-capable (key_optional or keyless_fallback) ---
    "shodan": SourceEntry(
        API, "SHODAN_API_KEY", key_optional=True, keyless_fallback=True, note="InternetDB fallback when keyless"
    ),
    "etherscan": SourceEntry(
        API, "ETHERSCAN_API_KEY", key_optional=True, keyless_fallback=True, note="keyless ~5 req/s"
    ),
    "otx": SourceEntry(API, "OTX_API_KEY", key_optional=True, note="keyless endpoints available"),
    "ipinfo": SourceEntry(API, "IPINFO_API_KEY", key_optional=True, note="keyless limited tier"),
    "pulsedive": SourceEntry(API, "PULSEDIVE_API_KEY", key_optional=True, note="keyless limited tier"),
    "github": SourceEntry(API, "GITHUB_TOKEN", key_optional=True, note="keyless REST works at 60 req/h"),
    # --- API: key required ---
    "dehashed": SourceEntry(API, "DEHASHED_API_KEY"),
    "leakcheck": SourceEntry(API, "LEAKCHECK_API_KEY"),
    "snylla": SourceEntry(API, "SCYLLA_API_KEY"),
    "snusbase": SourceEntry(API, "SNUSBASE_API_KEY"),
    "hibp": SourceEntry(API, "HIBP_API_KEY"),
    "intelx": SourceEntry(API, "INTELX_API_KEY"),
    "abuseipdb": SourceEntry(API, "ABUSEIPDB_API_KEY"),
    "censys": SourceEntry(API, "CENSYS_API_KEY"),
    "securitytrails": SourceEntry(API, "SECURITYTRAILS_API_KEY"),
    "virustotal": SourceEntry(API, "VIRUSTOTAL_API_KEY"),
    "greynoise": SourceEntry(API, "GREYNOISE_API_KEY"),
    "hunter": SourceEntry(API, "HUNTER_API_KEY"),
    "wigle": SourceEntry(API, "WIGLE_API_KEY"),
    "zoomeye": SourceEntry(API, "ZOOMEYE_API_KEY"),
    # --- TOOL: local CLI wrappers ---
    "nmap": SourceEntry(TOOL),
    "subfinder": SourceEntry(TOOL),
    "amass": SourceEntry(TOOL),
    "bbot": SourceEntry(TOOL),
    "httpx": SourceEntry(TOOL),
    "exiftool": SourceEntry(TOOL),
    "theharvester": SourceEntry(TOOL),
    "h8mail": SourceEntry(TOOL),
    "sherlock": SourceEntry(TOOL),
    "maigret": SourceEntry(TOOL),
    "holehe": SourceEntry(TOOL),
    "recon_ng": SourceEntry(TOOL),
    "spiderfoot": SourceEntry(TOOL),
    "phoneinfoga": SourceEntry(TOOL),
    "gomod": SourceEntry(TOOL),
    "maltego": SourceEntry(TOOL),
    "gitleaks": SourceEntry(TOOL),
}


def kind_of(name: str) -> TransportKind:
    """Transport kind for a module/source name (unknown → API, safe default)."""
    entry = _REGISTRY.get(name)
    return entry.kind if entry else TransportKind.API


def requires_key(name: str) -> bool:
    """True when the named source cannot function without its API key."""
    entry = _REGISTRY.get(name)
    if not entry or entry.kind != TransportKind.API:
        return False
    if entry.key_optional or entry.keyless_fallback:
        return False
    return bool(entry.key_env)


def can_run_keyless(name: str) -> bool:
    """True when the named source can produce data without any API key."""
    entry = _REGISTRY.get(name)
    if not entry:
        return False
    if entry.kind in (RE, SCRAPE, TOOL, LOCAL):
        return True
    return bool(entry.key_optional or entry.keyless_fallback)


def key_env(name: str) -> str:
    """Env var that carries the API key for a source ('' if none)."""
    entry = _REGISTRY.get(name)
    return entry.key_env if entry else ""


def transport_priority(name: str) -> int:
    """Lower = preferred: RE(0) < SCRAPE(1) < keyless API(2) < keyed API(3) < TOOL(4) < LOCAL(5)."""
    kind = kind_of(name)
    if kind == RE:
        return 0
    if kind == SCRAPE:
        return 1
    if kind == API:
        return 2 if can_run_keyless(name) else 3
    if kind == TOOL:
        return 4
    return 5  # LOCAL


def keyless_source_names() -> list[str]:
    """All registered names that can run without API keys, RE first."""
    return sorted((n for n in _REGISTRY if can_run_keyless(n)), key=transport_priority)


def no_api_metrics() -> dict[str, int]:
    """0-API posture of the registry: totals + keyless counts."""
    total = len(_REGISTRY)
    keyless = sum(1 for n in _REGISTRY if can_run_keyless(n))
    keyless_only = sum(1 for e in _REGISTRY.values() if e.kind in (RE, SCRAPE, TOOL, LOCAL))
    return {
        "total_sources": total,
        "keyless_capable": keyless,
        "keyless_only": keyless_only,
    }


__all__ = [
    "TransportKind",
    "SourceEntry",
    "kind_of",
    "requires_key",
    "can_run_keyless",
    "key_env",
    "transport_priority",
    "keyless_source_names",
    "no_api_metrics",
]
