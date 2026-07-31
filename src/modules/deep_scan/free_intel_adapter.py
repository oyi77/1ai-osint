"""Free Intel adapter — bridges free/open-source modules to deep scan engine.

Converts results from social_dorks_intel, gravatar_intel, wayback_intel
into structured ScanResult objects the engine can consume.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.core.compliance import get_compliance, record_audit, source_allows_tier
from src.core.models import Finding, ScanResult, Severity
from src.core.rbac import AccessTier
from src.core.tos_guard import tos_allows

logger = logging.getLogger(__name__)


async def _run_social_dorks_intel(target: str) -> ScanResult | None:
    """Run social dorks intel on a name and return findings."""
    from src.modules.free_intel.social_dorks_intel import SocialDorksIntel

    scanner = SocialDorksIntel()
    try:
        result = await scanner.search(target)
    except Exception as exc:
        logger.debug("social_dorks_intel search failed: %s", exc)
        return None

    if not result.results:
        if result.blocked_msg:
            logger.warning("social_dorks_intel: %s", result.blocked_msg)
        return None

    findings: list[Finding] = []
    for r in result.results:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_social_dorks",
                title=f"Social handle: {r.username} on {r.platform}",
                description=f"Found via search engine dorking ({r.platform})",
                severity=Severity.INFO,
                raw_data={
                    "platform": r.platform,
                    "username": r.username,
                    "url": r.url,
                    "snippet": r.snippet,
                },
                confidence=0.4,
                tags=["social", "handle", r.platform],
            )
        )

    return ScanResult(
        scan_id=f"free-social_dorks-{uuid.uuid4().hex[:8]}",
        module="free_social_dorks",
        target=target,
        status="ok",
        findings=findings,
        metadata={
            "blocked_msg": result.blocked_msg,
            "count": len(result.results),
        },
    )


async def _run_gravatar_intel(target: str) -> ScanResult | None:
    """Run Gravatar lookup on an email and return findings."""
    from src.modules.free_intel.gravatar_intel import GravatarIntel

    scanner = GravatarIntel()
    try:
        profile = await scanner.lookup(target)
    except Exception as exc:
        logger.debug("gravatar_intel lookup failed: %s", exc)
        return None

    if not profile:
        return None

    findings: list[Finding] = []
    if profile.display_name:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_gravatar",
                title=f"Gravatar: {profile.display_name}",
                description="Display name from Gravatar profile",
                severity=Severity.INFO,
                raw_data={
                    "email_hash": profile.email_hash,
                    "display_name": profile.display_name,
                    "profile_url": profile.profile_url,
                    "photo_url": profile.photo_url,
                    "about_me": profile.about_me,
                    "current_location": profile.current_location,
                },
                confidence=0.6,
                tags=["gravatar", "profile"],
            )
        )

    for account in profile.verified_accounts:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_gravatar",
                title=f"Gravatar verified: {account.get('username', '?')} on {account.get('domain', '?')}",
                description="Verified account linked from Gravatar",
                severity=Severity.INFO,
                raw_data={
                    "domain": account.get("domain", ""),
                    "url": account.get("url", ""),
                    "username": account.get("username", ""),
                },
                confidence=0.7,
                tags=["gravatar", "verified", account.get("domain", "")],
            )
        )

    if not findings:
        return None

    return ScanResult(
        scan_id=f"free-gravatar-{uuid.uuid4().hex[:8]}",
        module="free_gravatar",
        target=target,
        status="ok",
        findings=findings,
    )


async def _run_wayback_intel(target: str) -> ScanResult | None:
    """Run Wayback Machine snapshot finder on a URL and return findings."""
    from src.modules.free_intel.wayback_intel import WaybackIntel

    scanner = WaybackIntel()
    try:
        snapshots = await scanner.find_snapshots(target, limit=10)
    except Exception as exc:
        logger.debug("wayback_intel find_snapshots failed: %s", exc)
        return None

    if not snapshots:
        return None

    findings: list[Finding] = []
    for snap in snapshots:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_wayback",
                title=f"Wayback snapshot: {snap.url}",
                description=f"Archived at {snap.timestamp}",
                severity=Severity.INFO,
                raw_data={
                    "url": snap.url,
                    "timestamp": snap.timestamp,
                    "archive_url": snap.archive_url,
                },
                confidence=0.8,
                tags=["wayback", "archive", "historical"],
            )
        )

    return ScanResult(
        scan_id=f"free-wayback-{uuid.uuid4().hex[:8]}",
        module="free_wayback",
        target=target,
        status="ok",
        findings=findings,
        metadata={"count": len(snapshots)},
    )


async def _run_github_intel(target: str) -> ScanResult | None:
    """Run GitHub intel extraction on a username."""
    from src.modules.free_intel.github_intel import GitHubIntel

    scanner = GitHubIntel()
    try:
        profile = await scanner.extract(target)
    except Exception as exc:
        logger.debug("github_intel extract failed: %s", exc)
        return None

    if not profile:
        return None

    findings: list[Finding] = []

    if profile.full_name:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_github",
                title=f"GitHub user: {profile.full_name}",
                description=f"GitHub profile for {target} — {profile.full_name}",
                severity=Severity.INFO,
                raw_data={
                    "username": profile.username,
                    "full_name": profile.full_name,
                    "email": profile.email,
                    "company": profile.company,
                    "location": profile.location,
                    "bio": profile.bio,
                    "blog": profile.blog,
                    "twitter_username": profile.twitter_username,
                    "avatar_url": profile.avatar_url,
                    "public_repos": profile.public_repos,
                    "followers": profile.followers,
                    "following": profile.following,
                    "created_at": profile.created_at,
                },
                confidence=0.8,
                tags=["github", "profile", "code"],
            )
        )

    for email in profile.commit_emails:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_github",
                title=f"GitHub commit email: {email}",
                description=f"Email found in public commits for {target}",
                severity=Severity.INFO,
                raw_data={"email": email, "username": target},
                confidence=0.7,
                tags=["github", "email", "commit"],
            )
        )

    for repo in profile.repo_names:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_github",
                title=f"GitHub repo: {repo}",
                description=f"Public repository by {target}",
                severity=Severity.INFO,
                raw_data={"repo": repo, "username": target},
                confidence=0.8,
                tags=["github", "repo"],
            )
        )

    if not findings:
        return None

    return ScanResult(
        scan_id=f"free-github-{uuid.uuid4().hex[:8]}",
        module="free_github",
        target=target,
        status="ok",
        findings=findings,
        metadata={"commit_email_count": len(profile.commit_emails), "repo_count": len(profile.repo_names)},
    )


async def _run_google_dork_intel(target: str) -> ScanResult | None:
    """Run Google dork search on a name."""
    from src.modules.free_intel.google_dork_intel import GoogleDorkIntel

    scanner = GoogleDorkIntel()
    try:
        result = await scanner.search(target)
    except Exception as exc:
        logger.debug("google_dork_intel search failed: %s", exc)
        return None

    if not result or not result.snippets:
        return None

    findings: list[Finding] = []

    for email in result.extracted_emails:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_google_dork",
                title=f"Dorked email: {email}",
                description=f"Email address found via search engine dorking for {target}",
                severity=Severity.INFO,
                raw_data={"email": email, "target": target},
                confidence=0.5,
                tags=["dork", "email", "pii"],
            )
        )

    for phone in result.extracted_phones:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_google_dork",
                title=f"Dorked phone: {phone}",
                description=f"Phone number found via search engine dorking for {target}",
                severity=Severity.INFO,
                raw_data={"phone": phone, "target": target},
                confidence=0.5,
                tags=["dork", "phone", "pii"],
            )
        )

    for url in result.linkedin_urls:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_google_dork",
                title=f"Dorked LinkedIn: {url}",
                description=f"LinkedIn profile found via search engine dorking for {target}",
                severity=Severity.INFO,
                raw_data={"url": url, "target": target},
                confidence=0.6,
                tags=["dork", "linkedin", "profile"],
            )
        )

    for url in result.pdf_urls:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_google_dork",
                title=f"Dorked PDF/CV: {url}",
                description=f"PDF document found via search engine dorking for {target}",
                severity=Severity.INFO,
                raw_data={"url": url, "target": target},
                confidence=0.6,
                tags=["dork", "pdf", "cv"],
            )
        )

    if result.urls or result.snippets:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_google_dork",
                title=f"Dork results: {len(result.urls)} URLs found",
                description=f"Found {len(result.urls)} URLs, {len(result.extracted_emails)} emails, {len(result.extracted_phones)} phones via search engine dorking for {target}",
                severity=Severity.INFO,
                raw_data={
                    "urls": result.urls[:10],
                    "snippets": result.snippets[:40],
                    "extracted_emails": result.extracted_emails,
                    "extracted_phones": result.extracted_phones,
                    "linkedin_urls": result.linkedin_urls,
                    "pdf_urls": result.pdf_urls,
                    "target": target,
                },
                confidence=0.5,
                tags=["dork", "urls", "pii"],
            )
        )

    if not findings:
        return None

    return ScanResult(
        scan_id=f"free-google_dork-{uuid.uuid4().hex[:8]}",
        module="free_google_dork",
        target=target,
        status="ok",
        findings=findings,
        metadata={
            "url_count": len(result.urls),
            "email_count": len(result.extracted_emails),
            "phone_count": len(result.extracted_phones),
            "linkedin_count": len(result.linkedin_urls),
            "pdf_count": len(result.pdf_urls),
        },
    )


async def _run_hibp_free(target: str) -> ScanResult | None:
    """Run HIBP free breach check on an email."""
    from src.modules.free_intel.hibp_free import HIBPIntel

    scanner = HIBPIntel()
    try:
        breaches = await scanner.check_email(target)
    except Exception as exc:
        logger.debug("hibp_free check_email failed: %s", exc)
        return None

    if not breaches:
        return None

    findings: list[Finding] = []
    for breach in breaches:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_hibp",
                title=f"Breach: {breach.name}",
                description=f"{breach.description or 'No description'}"[:200],
                severity=Severity.MEDIUM,
                raw_data={
                    "breach_name": breach.name,
                    "domain": breach.domain,
                    "breach_date": breach.breach_date,
                    "data_classes": breach.data_classes,
                    "pwn_count": breach.pwn_count,
                    "is_verified": breach.is_verified,
                },
                confidence=0.8,
                tags=["breach", "leak", "hibp"],
            )
        )

    return ScanResult(
        scan_id=f"free-hibp-{uuid.uuid4().hex[:8]}",
        module="free_hibp",
        target=target,
        status="ok",
        findings=findings,
        metadata={"breach_count": len(breaches)},
    )


async def _run_bts_intel(target: str) -> ScanResult | None:
    """Run BTS tower intelligence on a phone number."""
    from src.modules.free_intel.bts_intel import BTSIntel

    scanner = BTSIntel()
    try:
        phone_info = await scanner.analyze_phone(target)
    except Exception as exc:
        logger.debug("bts_intel analyze_phone failed: %s", exc)
        return None

    if not phone_info:
        return None

    findings: list[Finding] = []

    if phone_info.operator:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_bts",
                title=f"Mobile operator: {phone_info.operator}",
                description=f"Phone {target} identified as {phone_info.operator} (MCC={phone_info.mcc}, MNC={phone_info.mnc})",
                severity=Severity.INFO,
                raw_data={
                    "phone": target,
                    "operator": phone_info.operator,
                    "mnc": phone_info.mnc,
                    "mcc": phone_info.mcc,
                    "country": phone_info.country,
                },
                confidence=0.7,
                tags=["phone", "operator", "bts"],
            )
        )

    if not findings:
        return None

    return ScanResult(
        scan_id=f"free-bts-{uuid.uuid4().hex[:8]}",
        module="free_bts",
        target=target,
        status="ok",
        findings=findings,
        metadata={
            "operator": phone_info.operator,
        },
    )


async def _run_pddikti_intel(target: str) -> ScanResult | None:
    """Run PDDIKTI Indonesian student database search on a name."""
    from src.modules.free_intel.pddikti_intel import PDDIKTIIntel

    scanner = PDDIKTIIntel()
    try:
        records = await scanner.search(target)
    except Exception as exc:
        logger.debug("pddikti_intel search failed: %s", exc)
        return None

    if not records:
        return None

    findings: list[Finding] = []
    for rec in records:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_pddikti",
                title=f"PDDIKTI: {rec.name} at {rec.university}",
                description=f"Student record at {rec.university} — {rec.major or 'Unknown major'}",
                severity=Severity.INFO,
                raw_data={
                    "name": rec.name,
                    "university": rec.university,
                    "major": rec.major,
                    "student_id": rec.student_id,
                },
                confidence=0.5,
                tags=["pddikti", "education", "indonesia"],
            )
        )

    return ScanResult(
        scan_id=f"free-pddikti-{uuid.uuid4().hex[:8]}",
        module="free_pddikti",
        target=target,
        status="ok",
        findings=findings,
        metadata={"record_count": len(records)},
    )


async def _run_pandi_whois_intel(target: str) -> ScanResult | None:
    """Run PANDI RDAP lookup on a .id domain."""
    from src.modules.free_intel.pandi_whois_intel import PandiWhoisIntel

    scanner = PandiWhoisIntel()
    try:
        record = await scanner.lookup(target)
    except Exception as exc:
        logger.debug("pandi_whois_intel lookup failed: %s", exc)
        return None

    if record is None:
        return None

    findings: list[Finding] = []
    if record.registrant_org or record.registrant_name:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_pandi_whois",
                title=f".id registrant: {record.registrant_org or record.registrant_name}",
                description=f"PANDI registry record for {record.domain}",
                severity=Severity.INFO,
                raw_data={
                    "domain": record.domain,
                    "registrant_org": record.registrant_org,
                    "registrant_name": record.registrant_name,
                    "created": record.created,
                    "expires": record.expires,
                    "nameservers": record.nameservers,
                },
                confidence=0.85,
                tags=["pandi", "whois", "rdap", "indonesia", "domain"],
            )
        )
    if record.nameservers:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_pandi_whois",
                title=f"Nameservers: {', '.join(record.nameservers[:4])}",
                description=f"NS records for {record.domain} (PANDI registry)",
                severity=Severity.INFO,
                raw_data={"nameservers": record.nameservers, "domain": record.domain},
                confidence=0.9,
                tags=["pandi", "whois", "dns"],
            )
        )

    if not findings:
        return None

    return ScanResult(
        scan_id=f"free-pandi-{uuid.uuid4().hex[:8]}",
        module="free_pandi_whois",
        target=target,
        status="ok",
        findings=findings,
        metadata={
            "created": record.created,
            "expires": record.expires,
            "status": record.status,
        },
    )


async def _run_data_go_id_intel(target: str) -> ScanResult | None:
    """Run data.go.id government open-data search on a keyword."""
    from src.modules.free_intel.data_go_id_intel import DataGoIdIntel

    scanner = DataGoIdIntel()
    try:
        datasets = await scanner.search_datasets(target)
    except Exception as exc:
        logger.debug("data_go_id_intel search failed: %s", exc)
        return None

    if not datasets:
        return None

    findings: list[Finding] = []
    for ds in datasets:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_data_go_id",
                title=f"Dataset: {ds['title'][:90]}",
                description="Public government dataset on data.go.id"
                + (f" — {ds['organization']}" if ds.get("organization") else ""),
                severity=Severity.INFO,
                raw_data={"title": ds["title"], "organization": ds.get("organization", "")},
                confidence=0.6,
                tags=["data_go_id", "open_data", "indonesia", "government"],
            )
        )

    return ScanResult(
        scan_id=f"free-data-go-id-{uuid.uuid4().hex[:8]}",
        module="free_data_go_id",
        target=target,
        status="ok",
        findings=findings,
        metadata={"dataset_count": len(datasets)},
    )


async def _run_tech_jobs_intel(target: str) -> ScanResult | None:
    """Run tech jobs profile search on a name."""
    from src.modules.free_intel.tech_jobs_intel import TechJobsIntel

    scanner = TechJobsIntel()
    try:
        profiles = await scanner.search(target)
    except Exception as exc:
        logger.debug("tech_jobs_intel search failed: %s", exc)
        return None

    if not profiles:
        return None

    findings: list[Finding] = []
    for prof in profiles:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_tech_jobs",
                title=f"Tech job profile on {prof.platform}",
                description=f"Found profile for {target} on {prof.platform}",
                severity=Severity.INFO,
                raw_data={
                    "platform": prof.platform,
                    "url": prof.url,
                    "snippets": prof.snippets[:3] if prof.snippets else [],
                },
                confidence=0.5,
                tags=["jobs", prof.platform, "profile"],
            )
        )

    if not findings:
        return None

    return ScanResult(
        scan_id=f"free-tech_jobs-{uuid.uuid4().hex[:8]}",
        module="free_tech_jobs",
        target=target,
        status="ok",
        findings=findings,
        metadata={"profile_count": len(profiles)},
    )


async def _run_whatsapp_check(target: str) -> ScanResult | None:
    """Run WhatsApp presence check on a phone number."""
    from src.modules.free_intel.whatsapp_telegram_check import MessagingIntel

    scanner = MessagingIntel()
    try:
        registered = await scanner.check_whatsapp(target)
    except Exception as exc:
        logger.debug("whatsapp_check failed: %s", exc)
        return None

    if registered is None:
        return None

    findings = [
        Finding(
            id=f"find-{uuid.uuid4().hex[:8]}",
            module="free_whatsapp",
            title=f"WhatsApp: {'registered' if registered else 'not found'}",
            description=f"WhatsApp presence check for {target}: {'registered' if registered else 'not found'}",
            severity=Severity.INFO,
            raw_data={"phone": target, "whatsapp_registered": registered},
            confidence=0.7,
            tags=["whatsapp", "messaging", "phone"],
        )
    ]

    return ScanResult(
        scan_id=f"free-whatsapp-{uuid.uuid4().hex[:8]}",
        module="free_whatsapp",
        target=target,
        status="ok",
        findings=findings,
        metadata={"whatsapp": registered},
    )


async def _run_telegram_check(target: str) -> ScanResult | None:
    """Run Telegram username presence check."""
    from src.modules.free_intel.whatsapp_telegram_check import MessagingIntel

    scanner = MessagingIntel()
    try:
        exists = await scanner.check_telegram(target)
    except Exception as exc:
        logger.debug("telegram_check failed: %s", exc)
        return None

    if exists is None:
        return None

    findings = [
        Finding(
            id=f"find-{uuid.uuid4().hex[:8]}",
            module="free_telegram",
            title=f"Telegram: {'exists' if exists else 'not found'}",
            description=f"Telegram presence check for @{target}: {'exists' if exists else 'not found'}",
            severity=Severity.INFO,
            raw_data={"username": target, "telegram_exists": exists},
            confidence=0.7,
            tags=["telegram", "messaging", "username"],
        )
    ]

    return ScanResult(
        scan_id=f"free-telegram-{uuid.uuid4().hex[:8]}",
        module="free_telegram",
        target=target,
        status="ok",
        findings=findings,
        metadata={"telegram": exists},
    )


# Module dispatch registry — maps module name to handler function
_FREE_INTEL_DISPATCH: dict[str, tuple[str, str, Any]] = {
    "social_dorks_intel": (
        "name",
        "social_dorks_intel",
        _run_social_dorks_intel,
    ),
    "gravatar_intel": (
        "email",
        "gravatar_intel",
        _run_gravatar_intel,
    ),
    "wayback_intel": (
        "url",
        "wayback_intel",
        _run_wayback_intel,
    ),
    "github_intel": (
        "github_username",
        "github_intel",
        _run_github_intel,
    ),
    "google_dork_intel": (
        "name",
        "google_dork_intel",
        _run_google_dork_intel,
    ),
    "hibp_free": (
        "email",
        "hibp_free",
        _run_hibp_free,
    ),
    "bts_intel": (
        "phone",
        "bts_intel",
        _run_bts_intel,
    ),
    "pddikti_intel": (
        "name",
        "pddikti_intel",
        _run_pddikti_intel,
    ),
    "pandi_whois_intel": (
        "domain",
        "pandi_whois_intel",
        _run_pandi_whois_intel,
    ),
    "data_go_id_intel": (
        "keyword",
        "data_go_id_intel",
        _run_data_go_id_intel,
    ),
    "tech_jobs_intel": (
        "name",
        "tech_jobs_intel",
        _run_tech_jobs_intel,
    ),
    "whatsapp_check": (
        "phone",
        "whatsapp_check",
        _run_whatsapp_check,
    ),
    "telegram_check": (
        "telegram_username",
        "telegram_check",
        _run_telegram_check,
    ),
}


async def run_free_intel_scan(
    module_name: str,
    target: str,
    requester: str = "unknown",
    requester_tier: AccessTier = AccessTier.ADMIN,
) -> ScanResult | None:
    """Run a single free intel module scan and return a structured ScanResult.

    Args:
        module_name: Module key from _FREE_INTEL_DISPATCH (e.g. 'social_dorks_intel')
        target: Search target string (name, email, or URL).
        requester: Caller identity for the audit trail.
        requester_tier: Caller's access tier for the RBAC gate.

    Returns:
        ScanResult with findings, or None on failure/no data.

    Compliance: RBAC (min-tier) and ToS (rate ceiling) gates are enforced
    here for free-intel modules — same Layer 3 guarantees as the
    breach/leak source adapter path.

    """
    entry = _FREE_INTEL_DISPATCH.get(module_name)
    if not entry:
        logger.warning("Unknown free intel module: %s", module_name)
        return None

    # RBAC gate — tier must be at least the source's min_tier.
    if not source_allows_tier(module_name, requester_tier):
        record_audit(
            source=module_name,
            target=target,
            requester=requester,
            outcome="blocked",
            legal_basis=get_compliance(module_name).legal_basis.value,
        )
        logger.warning(
            "Blocked free intel %s for '%s': requester tier %s below required %s",
            module_name,
            target,
            requester_tier.name,
            get_compliance(module_name).min_tier.name,
        )
        return None

    # ToS guard — respect the platform's documented rate ceiling.
    if not tos_allows(module_name):
        record_audit(
            source=module_name,
            target=target,
            requester=requester,
            outcome="throttled",
            legal_basis=get_compliance(module_name).legal_basis.value,
        )
        logger.warning("Throttled free intel %s for '%s': ToS rate ceiling hit", module_name, target)
        return None

    label, _, handler = entry
    logger.debug("Running free intel %s on '%s'", label, target)
    return await handler(target)


def list_free_intel_modules() -> list[str]:
    """Return list of registered free intel module names."""
    return list(_FREE_INTEL_DISPATCH.keys())
