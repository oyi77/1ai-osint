"""PANDI WHOIS/RDAP Intelligence — Indonesian .id domain registry lookups.

Queries PANDI (Pengelola Nama Domain Internet Indonesia) RDAP service for
.id domains. RDAP (RFC 7483) is the modern successor to WHOIS port 43 and
is the documented interface PANDI exposes at rdap.pandi.id.

Legal basis: registry data published by the Indonesian ccTLD registry
(govt-mandated operator) — public domain registration records.

NOTE: PANDI rate-limits / geo-filters object lookups from some networks;
the adapter treats non-200 as "no data" and always returns a structured
ScanResult via the caller, so failures never crash the scan pipeline.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

RDAP_ENDPOINT = "https://rdap.pandi.id/domain/{domain}"
_ID_TLD_RE = re.compile(
    r"^[a-z0-9-]+\.(?:co\.id|or\.id|web\.id|ac\.id|sch\.id|go\.id|mil\.id|biz\.id|id)$", re.IGNORECASE
)


@dataclass
class PandiWhoisRecord:
    """Normalized PANDI RDAP record for a .id domain."""

    domain: str
    registrant_org: str = ""
    registrant_name: str = ""
    created: str = ""
    expires: str = ""
    updated: str = ""
    status: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def _is_id_domain(domain: str) -> bool:
    """True if the domain looks like a registrable .id second-level domain."""
    return bool(_ID_TLD_RE.match(domain.strip().lower()))


def _vcard_value(entity: dict) -> tuple[str, str]:
    """Extract (name, org) from an RDAP entity's jCard vcardArray."""
    name = org = ""
    vcards = entity.get("vcardArray", [[]])
    if len(vcards) < 2:
        return name, org
    for item in vcards[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        field_name = item[0].lower()
        value = item[3]
        if field_name == "fn" and isinstance(value, str):
            name = value
        elif field_name == "org" and isinstance(value, str):
            org = value
    return name, org


def parse_rdap_response(domain: str, payload: dict) -> PandiWhoisRecord:
    """Parse an RDAP domain response into a normalized record.

    Tolerates partial payloads (some .id RDAP responses omit entities or
    events) — missing fields stay empty strings rather than raising.
    """
    rec = PandiWhoisRecord(domain=domain, raw=payload)

    for entity in payload.get("entities", []):
        roles = entity.get("roles", [])
        name, org = _vcard_value(entity)
        if "registrant" in roles:
            rec.registrant_name = name or rec.registrant_name
            rec.registrant_org = org or rec.registrant_org
        elif name or org:
            # First non-registrant entity (registrar, admin, tech) — keep as
            # best-effort org attribution when no registrant entity exists.
            if not rec.registrant_org:
                rec.registrant_org = org or name

    for event in payload.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration" and not rec.created:
            rec.created = date
        elif action == "expiration" and not rec.expires:
            rec.expires = date
        elif action == "last changed" and not rec.updated:
            rec.updated = date

    rec.status = [s for s in payload.get("status", []) if isinstance(s, str)]
    for ns in payload.get("nameservers", []):
        ldh = ns.get("ldhName") or ns.get("unicodeName")
        if ldh:
            rec.nameservers.append(ldh)

    return rec


class PandiWhoisIntel:
    """Query PANDI RDAP for .id domain registration records."""

    async def lookup(self, domain: str) -> PandiWhoisRecord | None:
        """Look up a .id domain. Returns None for non-.id targets or errors."""
        if not _is_id_domain(domain):
            return None
        url = RDAP_ENDPOINT.format(domain=domain.strip().lower())
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    return parse_rdap_response(domain, resp.json())
                logger.debug("PANDI RDAP %s -> HTTP %s", domain, resp.status_code)
        except Exception as e:
            logger.debug("PANDI RDAP lookup failed for %s: %s", domain, e)
        return None
