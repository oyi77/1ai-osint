"""Deep Scan Engine module configuration — maps and constants.

Extracted from engine.py to reduce file size.
"""

from __future__ import annotations

from src.modules.deep_scan import IdentifierType

# Module → identifier types it can consume
MODULE_INPUTS: dict[str, set[IdentifierType]] = {
    "social_osint": {
        IdentifierType.USERNAME,
        IdentifierType.NAME,
        IdentifierType.SOCIAL_PROFILE,
    },
    "email_osint": {IdentifierType.EMAIL},
    "domain_recon": {IdentifierType.DOMAIN},
    "people_finder": {IdentifierType.USERNAME, IdentifierType.NAME},
    "phone_finder": {IdentifierType.PHONE},
    "data_leaks": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "crypto_balance": {IdentifierType.CRYPTO_ADDRESS},
    "crypto_tracer": {IdentifierType.CRYPTO_ADDRESS},
    "gitleaks": {IdentifierType.DOMAIN, IdentifierType.URL},
    "vuln_scanner": {IdentifierType.DOMAIN, IdentifierType.IP},
    "dehashed": {
        IdentifierType.EMAIL,
        IdentifierType.USERNAME,
        IdentifierType.PHONE,
        IdentifierType.DOMAIN,
    },
    "leakcheck": {IdentifierType.EMAIL, IdentifierType.USERNAME},
    "snylla": {
        IdentifierType.EMAIL,
        IdentifierType.USERNAME,
        IdentifierType.PHONE,
        IdentifierType.DOMAIN,
    },
    "snusbase": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "hibp": {IdentifierType.EMAIL},
    "intelx": {
        IdentifierType.EMAIL,
        IdentifierType.USERNAME,
        IdentifierType.PHONE,
        IdentifierType.DOMAIN,
        IdentifierType.NAME,
    },
    # Keyless RE sources (0-API mode; reverse-engineered / public endpoints)
    "hackertarget": {IdentifierType.DOMAIN, IdentifierType.IP},
    "dns_records": {IdentifierType.DOMAIN},
    "mempool": {IdentifierType.CRYPTO_ADDRESS},
    "ip_api": {IdentifierType.IP},
    "pgp_keys": {IdentifierType.EMAIL},
    "anubis": {IdentifierType.DOMAIN},
    "bgpview": {IdentifierType.IP},
    "certspotter": {IdentifierType.DOMAIN},
    "rapiddns": {IdentifierType.DOMAIN},
    "urlscan": {IdentifierType.DOMAIN},
    "proxynova": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "veriphone": {IdentifierType.PHONE},
    "keybase": {IdentifierType.USERNAME},
    "whatsmyname": {IdentifierType.USERNAME},
    # Keyless TOOL sources (local CLI wrappers, 0-key; transport_priority(4)
    # keeps them after RE/SCRAPE in 0-API ordering, and they degrade to an
    # empty/audited outcome when the CLI binary is not installed)
    "sherlock": {IdentifierType.USERNAME},
    "maigret": {IdentifierType.USERNAME},
    "holehe": {IdentifierType.EMAIL},
    "theharvester": {IdentifierType.DOMAIN},
    "subfinder": {IdentifierType.DOMAIN},
    "amass": {IdentifierType.DOMAIN},
    "bbot": {IdentifierType.DOMAIN},
    "nmap": {IdentifierType.IP, IdentifierType.DOMAIN},
    "httpx": {IdentifierType.DOMAIN, IdentifierType.IP, IdentifierType.URL},
    "phoneinfoga": {IdentifierType.PHONE},
    "h8mail": {IdentifierType.EMAIL},
    # Free intel modules (search engine dorking, gravatar, wayback)
    "social_dorks_intel": {IdentifierType.NAME},
    "gravatar_intel": {IdentifierType.EMAIL},
    "wayback_intel": {IdentifierType.URL},
    "github_intel": {IdentifierType.USERNAME},
    "google_dork_intel": {IdentifierType.NAME},
    "hibp_free": {IdentifierType.EMAIL},
    "bts_intel": {IdentifierType.PHONE},
    "pddikti_intel": {IdentifierType.NAME},
    "tech_jobs_intel": {IdentifierType.NAME},
    "whatsapp_check": {IdentifierType.PHONE},
    "telegram_check": {IdentifierType.USERNAME},
}

# Sources handled by source_adapter (separate from CLI modules)
SOURCE_MODULES: set[str] = {
    "dehashed",
    "leakcheck",
    "snylla",
    "snusbase",
    "hibp",
    "intelx",
    "hackertarget",
    "dns_records",
    "mempool",
    "ip_api",
    "pgp_keys",
    "anubis",
    "bgpview",
    "certspotter",
    "rapiddns",
    "urlscan",
    "proxynova",
    "veriphone",
    "keybase",
    "whatsmyname",
    # Keyless TOOL sources (local CLI wrappers — 0-key, RE-first ordering)
    "sherlock",
    "maigret",
    "holehe",
    "theharvester",
    "subfinder",
    "amass",
    "bbot",
    "nmap",
    "httpx",
    "phoneinfoga",
    "h8mail",
}
