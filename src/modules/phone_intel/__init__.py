"""Phone intelligence aggregation — multiple sources into one local DB.

PhoneIntelTool queries the shared SQLite store (state/phone_intel.db) for each
source (getcontact, web, carrier, truecaller). Fresh entries are served from
the DB; missing/expired entries are fetched from the live source and written
back. This keeps limited/quota-billed sources (getcontact) from being called
more than once per phone within their TTL.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.modules.phone_intel import db as phone_db
from src.modules.phone_intel.carrier import PhoneCarrierLookup
from src.modules.phone_intel.truecaller import TruecallerLookup
from src.modules.phone_intel.web_search import PhoneWebSearch
from src.modules.phone_intel.whatsapp_osint import WhatsAppOSINT
from src.utils.phone_normalize import normalize_phone_e164

logger = logging.getLogger(__name__)

# Per-source cache TTLs (seconds).
TTL_GETCONTACT = 7 * 24 * 3600
TTL_WEB = 7 * 24 * 3600
TTL_CARRIER = 30 * 24 * 3600
TTL_TRUECALLER = 30 * 24 * 3600
TTL_WHATSAPP = 7 * 24 * 3600
TTL_HUDSON = 30 * 24 * 3600

_SOURCES = ("getcontact", "web", "carrier", "truecaller", "whatsapp")


class PhoneIntelTool(BaseOSINTTool):
    """Aggregate phone intelligence from getcontact, web, carrier, truecaller."""

    name = "phone_intel"
    description = "Aggregated phone intel: GetContact + web + carrier + Truecaller"
    version = "0.1.0"

    def __init__(
        self,
        db_path: str | None = None,
        gc_lookup: Any = None,
        web_search: PhoneWebSearch | None = None,
        carrier: PhoneCarrierLookup | None = None,
        truecaller: TruecallerLookup | None = None,
        whatsapp: WhatsAppOSINT | None = None,
        zkit_salt: str | None = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.db_path = db_path or phone_db.default_db_path()
        self.gc_lookup = gc_lookup
        self.web_search = web_search or PhoneWebSearch()
        self.carrier = carrier or PhoneCarrierLookup()
        self.truecaller = truecaller or TruecallerLookup()
        self.whatsapp = whatsapp or WhatsAppOSINT()

    # -- source runners ------------------------------------------------------

    async def _fetch_getcontact(self, phone: str) -> dict[str, Any] | None:
        if self.gc_lookup is None:
            from src.modules.phone_finder.gc_lookup import GCLookupTool

            self.gc_lookup = GCLookupTool()
        result = await self.gc_lookup.search(phone)
        profile: dict[str, Any] | None = None
        tags: list[Any] = []
        for f in result.findings:
            if f.title == "GetContact profile":
                profile = f.raw_data or {}
            elif f.title == "GetContact tags":
                tags = (f.raw_data or {}).get("tags") or []
        if profile or tags:
            return {"profile": profile, "tags": tags}
        return None

    async def _fetch_web(self, phone: str) -> dict[str, Any]:
        pages = await self.web_search.search(phone)
        return {"pages": pages, "count": len(pages)}

    async def _fetch_carrier(self, phone: str) -> dict[str, Any] | None:
        return await self.carrier.lookup(phone)

    async def _fetch_truecaller(self, phone: str) -> dict[str, Any] | None:
        return await self.truecaller.lookup(phone)

    async def _fetch_whatsapp(self, phone: str) -> dict[str, Any]:
        return await self.whatsapp.lookup(phone)

    # -- main ----------------------------------------------------------------

    async def search(self, query: str, **kwargs) -> ScanResult:
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        normalized = normalize_phone_e164(query, default_region="ID")
        phone = normalized or query
        if not normalized:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=query,
                status="partial",
                findings=[],
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                metadata={"note": "Target is not a valid phone number; sources not invoked"},
            )

        ttl = {s: 0 for s in _SOURCES}
        ttl["getcontact"] = TTL_GETCONTACT
        ttl["web"] = TTL_WEB
        ttl["carrier"] = TTL_CARRIER
        ttl["truecaller"] = TTL_TRUECALLER
        ttl["whatsapp"] = TTL_WHATSAPP

        fetchers = {
            "getcontact": self._fetch_getcontact,
            "web": self._fetch_web,
            "carrier": self._fetch_carrier,
            "truecaller": self._fetch_truecaller,
            "whatsapp": self._fetch_whatsapp,
        }

        results: dict[str, Any] = {}
        for source in _SOURCES:
            data = None
            cached = phone_db.get_lookup(self.db_path, phone, source, ttl[source])
            if cached is not None:
                data = cached["data"]
            else:
                try:
                    data = await fetchers[source](phone)
                except Exception as e:  # noqa: BLE001 — one source must not break the rest
                    logger.warning("phone_intel %s for %s failed: %s", source, phone, e)
                    data = None
                if data is not None:
                    phone_db.save_lookup(self.db_path, phone, source, data, ttl_seconds=ttl[source])
            results[source] = data

        # Correlation: if the GetContact profile reveals an email, query Hudson
        # Rock infostealer data for that email (free API, cached 30d).
        gc = results.get("getcontact") or {}
        email = (gc.get("profile") or {}).get("email")
        if email:
            hr = phone_db.get_lookup(self.db_path, phone, "hudson", TTL_HUDSON)
            if hr is not None:
                results["hudson"] = hr["data"]
            else:
                try:
                    from src.modules.data_leaks.hudson_rock import HudsonRockIntel

                    hr_data = await HudsonRockIntel().search("email", email)
                except Exception as e:  # noqa: BLE001
                    logger.warning("hudson rock correlation failed: %s", e)
                    hr_data = None
                if hr_data is not None:
                    phone_db.save_lookup(self.db_path, phone, "hudson", hr_data, ttl_seconds=TTL_HUDSON)
                    results["hudson"] = hr_data

        # Build findings from whatever each source returned.
        self._findings_from(phone, results, findings)

        status = "ok" if findings else "partial"
        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=query,
            status=status,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            metadata={"phone": phone, "sources": _SOURCES},
        )

    def _findings_from(self, phone: str, results: dict[str, Any], findings: list[Finding]) -> None:
        gc = results.get("getcontact")
        if gc and (gc.get("profile") or gc.get("tags")):
            if gc.get("profile"):
                findings.append(
                    Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        title="GetContact profile",
                        description=f"GetContact profile for {phone}",
                        severity=Severity.INFO,
                        raw_data=gc["profile"],
                        confidence=0.9,
                        tags=["getcontact", "phone"],
                    )
                )
            if gc.get("tags"):
                findings.append(
                    Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        title="GetContact tags",
                        description=f"GetContact tags for {phone}",
                        severity=Severity.INFO,
                        raw_data={"tags": gc["tags"]},
                        confidence=0.8,
                        tags=["getcontact", "phone", "tags"],
                    )
                )

        web = results.get("web")
        if web and web.get("pages"):
            pages = web["pages"]
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title="Public pages mentioning this number",
                    description=f"{len(pages)} public page(s) reference this phone",
                    severity=Severity.INFO,
                    raw_data={"pages": pages},
                    confidence=0.6,
                    tags=["web", "phone"],
                )
            )

        carrier = results.get("carrier")
        if carrier and carrier.get("is_valid_number") is not False:
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title="Carrier and line type",
                    description=(
                        f"{carrier.get('carrier')} ({carrier.get('line_type')}) — {carrier.get('country_code')}"
                    ),
                    severity=Severity.INFO,
                    raw_data=carrier,
                    confidence=0.8,
                    tags=["carrier", "phone"],
                )
            )

        wa = results.get("whatsapp")
        if wa:
            presence = wa.get("presence")
            profile = wa.get("profile") or {}
            desc = f"WhatsApp presence: {presence}"
            if profile:
                desc += f" | about: {profile.get('about') or profile.get('status') or 'n/a'}"
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title="WhatsApp OSINT",
                    description=desc,
                    severity=Severity.INFO,
                    raw_data=wa,
                    confidence=0.7 if presence is True else 0.3,
                    tags=["whatsapp", "phone"],
                )
            )

        hr = results.get("hudson")
        if hr and hr.get("stealers"):
            stealers = hr["stealers"]
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title="Hudson Rock infostealer hits",
                    description=f"{len(stealers)} infostealer-compromised machine(s)",
                    severity=Severity.MEDIUM,
                    raw_data=hr,
                    confidence=0.8,
                    tags=["hudson", "breach", "infostealer"],
                )
            )

        tc = results.get("truecaller")
        if tc:
            name = ""
            data = tc.get("data") or [{}]
            if data:
                name = data[0].get("name") or ""
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title="Truecaller entry",
                    description=f"Truecaller lookup for {phone}" + (f" — {name}" if name else ""),
                    severity=Severity.INFO,
                    raw_data=tc,
                    confidence=0.5,
                    tags=["truecaller", "phone"],
                )
            )

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Alias for search."""
        return await self.search(target, **kwargs)

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        return {"modules": [self.name]}

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        pass
