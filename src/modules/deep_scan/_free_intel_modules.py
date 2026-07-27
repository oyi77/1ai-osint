"""Free intel module runner functions — one per free/open-source module.

Extracted from free_intel_adapter.py to reduce file size.
"""

from __future__ import annotations

import logging
import uuid

from src.core.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


async def run_social_dorks_intel(target: str) -> ScanResult | None:
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


async def run_gravatar_intel(target: str) -> ScanResult | None:
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


async def run_wayback_intel(target: str) -> ScanResult | None:
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


async def run_github_intel(target: str) -> ScanResult | None:
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


async def run_google_dork_intel(target: str) -> ScanResult | None:
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

    if result.urls:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:8]}",
                module="free_google_dork",
                title=f"Dork results: {len(result.urls)} URLs found",
                description=f"Found {len(result.urls)} URLs, {len(result.extracted_emails)} emails, {len(result.extracted_phones)} phones via search engine dorking for {target}",
                severity=Severity.INFO,
                raw_data={
                    "urls": result.urls[:10],
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


async def run_hibp_free(target: str) -> ScanResult | None:
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


async def run_bts_intel(target: str) -> ScanResult | None:
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


async def run_pddikti_intel(target: str) -> ScanResult | None:
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


async def run_tech_jobs_intel(target: str) -> ScanResult | None:
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


async def run_whatsapp_check(target: str) -> ScanResult | None:
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


async def run_telegram_check(target: str) -> ScanResult | None:
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
