"""Target Dossier Compiler — assembles all intelligence into a structured dossier.

This is the output format the user actually wants: not a scan report,
but a comprehensive background file answering specific questions about the target.
"""

import logging
from typing import Any, Optional

from src.modules.deep_scan._dossier_models import (
    EmailIntel,
    PhoneDossierIntel,
    SocialAccount,
    TargetDossier,
    WorkHistory,
)

logger = logging.getLogger(__name__)


class DossierCompiler:
    """Compiles intelligence from all sources into a TargetDossier."""

    def compile(
        self,
        target: str,
        *,
        github_profiles: Optional[list[Any]] = None,
        gravatar_profiles: Optional[list[Any]] = None,
        dork_results: Optional[list[Any]] = None,
        messaging_results: Optional[list[Any]] = None,
        bts_results: Optional[list[Any]] = None,
        hibp_results: Optional[list[Any]] = None,
        wayback_results: Optional[list[Any]] = None,
        social_findings: Optional[list[Any]] = None,
        deep_scan_result: Any = None,
    ) -> TargetDossier:
        """Compile all intelligence into a dossier."""
        import uuid

        dossier = TargetDossier(
            report_id=f"dossier-{uuid.uuid4().hex[:12]}",
            full_name=target,
        )

        # --- GitHub Intelligence ---
        for gp in github_profiles or []:
            if hasattr(gp, "full_name") and gp.full_name:
                if gp.full_name != target and gp.full_name not in dossier.aliases:
                    dossier.aliases.append(gp.full_name)
            if hasattr(gp, "email") and gp.email:
                dossier.emails.append(EmailIntel(address=gp.email, source="github_profile", confidence=0.9))
            if hasattr(gp, "commit_emails"):
                for ce in gp.commit_emails:
                    if not any(e.address == ce for e in dossier.emails):
                        dossier.emails.append(EmailIntel(address=ce, source="github_commits", confidence=0.95))
            if hasattr(gp, "company") and gp.company:
                dossier.current_employer = gp.company.lstrip("@")
                dossier.work_history.append(
                    WorkHistory(company=gp.company.lstrip("@"), source="github", confidence=0.8)
                )
            if hasattr(gp, "location") and gp.location:
                if gp.location not in dossier.known_locations:
                    dossier.known_locations.append(gp.location)
            if hasattr(gp, "bio") and gp.bio:
                pass  # Will be used in social accounts
            if hasattr(gp, "avatar_url") and gp.avatar_url:
                if gp.avatar_url not in dossier.profile_pictures:
                    dossier.profile_pictures.append(gp.avatar_url)
            if hasattr(gp, "blog") and gp.blog:
                if gp.blog not in dossier.websites:
                    dossier.websites.append(gp.blog)
            if hasattr(gp, "twitter_username") and gp.twitter_username:
                if not any(a.platform == "twitter" for a in dossier.social_accounts):
                    dossier.social_accounts.append(
                        SocialAccount(
                            platform="twitter",
                            username=gp.twitter_username,
                            url=f"https://twitter.com/{gp.twitter_username}",
                            source="github_profile",
                        )
                    )
            # Add GitHub as social account
            dossier.social_accounts.append(
                SocialAccount(
                    platform="github",
                    username=gp.username,
                    url=f"https://github.com/{gp.username}",
                    bio=getattr(gp, "bio", "") or "",
                    followers=getattr(gp, "followers", 0),
                    profile_picture=getattr(gp, "avatar_url", ""),
                    source="github_api",
                )
            )
            dossier.data_sources_used.append("GitHub API")

        # --- Gravatar Intelligence ---
        for grav in gravatar_profiles or []:
            if hasattr(grav, "display_name") and grav.display_name:
                if grav.display_name not in dossier.aliases and grav.display_name != target:
                    dossier.aliases.append(grav.display_name)
            if hasattr(grav, "photo_url") and grav.photo_url:
                if grav.photo_url not in dossier.profile_pictures:
                    dossier.profile_pictures.append(grav.photo_url)
            if hasattr(grav, "current_location") and grav.current_location:
                if grav.current_location not in dossier.known_locations:
                    dossier.known_locations.append(grav.current_location)
            if hasattr(grav, "verified_accounts"):
                for acc in grav.verified_accounts:
                    domain = acc.get("domain", "")
                    url = acc.get("url", "")
                    username = acc.get("username", "")
                    if domain and not any(a.platform == domain for a in dossier.social_accounts):
                        dossier.social_accounts.append(
                            SocialAccount(
                                platform=domain,
                                username=username,
                                url=url,
                                source="gravatar",
                            )
                        )
            dossier.data_sources_used.append("Gravatar")

        # --- Dork Results ---
        for dr in dork_results or []:
            if hasattr(dr, "extracted_emails"):
                for email in dr.extracted_emails:
                    if not any(e.address == email for e in dossier.emails):
                        dossier.emails.append(EmailIntel(address=email, source="search_dork", confidence=0.6))
            if hasattr(dr, "extracted_phones"):
                for phone in dr.extracted_phones:
                    if not any(p.number == phone for p in dossier.phones):
                        dossier.phones.append(PhoneDossierIntel(number=phone, source="search_dork", confidence=0.5))
            if hasattr(dr, "linkedin_urls"):
                for url in dr.linkedin_urls:
                    if not any(a.platform == "linkedin" for a in dossier.social_accounts):
                        username = url.rstrip("/").split("/")[-1]
                        dossier.social_accounts.append(
                            SocialAccount(
                                platform="linkedin",
                                username=username,
                                url=url,
                                source="search_dork",
                            )
                        )
            dossier.data_sources_used.append("DuckDuckGo Dorks")

        # --- Messaging Results ---
        for mr in messaging_results or []:
            if hasattr(mr, "phone_number") and mr.phone_number:
                existing = next((p for p in dossier.phones if p.number == mr.phone_number), None)
                if existing:
                    existing.whatsapp_registered = getattr(mr, "whatsapp_registered", None)
                else:
                    dossier.phones.append(
                        PhoneDossierIntel(
                            number=mr.phone_number,
                            whatsapp_registered=getattr(mr, "whatsapp_registered", None),
                            source="messaging_check",
                        )
                    )
            dossier.data_sources_used.append("WhatsApp/Telegram")

        # --- BTS Results ---
        for bt in bts_results or []:
            if hasattr(bt, "operator") and bt.operator:
                existing = next((p for p in dossier.phones if p.number == bt.phone_number), None)
                if existing:
                    existing.operator = bt.operator
            dossier.data_sources_used.append("OpenCelliD BTS")

        # --- HIBP Results ---
        for breach_list in hibp_results or []:
            if isinstance(breach_list, list):
                for b in breach_list:
                    bname = getattr(b, "name", str(b))
                    if bname and bname not in dossier.breached_services:
                        dossier.breached_services.append(bname)
                    for dc in getattr(b, "data_classes", []):
                        if dc not in dossier.exposed_data_types:
                            dossier.exposed_data_types.append(dc)
            dossier.data_sources_used.append("HIBP")

        # --- Social Findings (from deep scan) ---
        if social_findings:
            for f in social_findings:
                rd = getattr(f, "raw_data", {}) or {}
                if rd.get("type") == "github" and "profile" in rd:
                    p = rd["profile"]
                    if p.get("email") and not any(e.address == p["email"] for e in dossier.emails):
                        dossier.emails.append(
                            EmailIntel(
                                address=p["email"],
                                source="github_api_direct",
                                confidence=0.9,
                            )
                        )
                    if p.get("company") and not dossier.current_employer:
                        dossier.current_employer = p["company"].lstrip("@")
                    if p.get("location") and p["location"] not in dossier.known_locations:
                        dossier.known_locations.append(p["location"])

                # External tools (Sherlock, Maigret)
                if rd.get("type") == "social_account":
                    platform = rd.get("platform", "")
                    url = rd.get("url", "")
                    username = rd.get("username", "")
                    source = rd.get("source", "external_tools")
                    if platform and url:
                        if not any(a.platform == platform and a.username == username for a in dossier.social_accounts):
                            dossier.social_accounts.append(
                                SocialAccount(
                                    platform=platform,
                                    username=username,
                                    url=url,
                                    source=source,
                                    verified=rd.get("verified", False),
                                    bio=rd.get("bio", "") or "",
                                    profile_picture=rd.get("profile_picture", "") or "",
                                )
                            )
                            if "External Open-Source Tools" not in dossier.data_sources_used:
                                dossier.data_sources_used.append("External Open-Source Tools")

        # --- Intelligence Gaps ---
        if not dossier.emails:
            dossier.intelligence_gaps.append(
                "No email addresses discovered — try configuring HIBP_API_KEY or DEHASHED_API_KEY"
            )
        if not dossier.phones:
            dossier.intelligence_gaps.append("No phone numbers discovered — try search dorks with local phone formats")
        if not dossier.current_employer:
            dossier.intelligence_gaps.append(
                "Employment not identified — LinkedIn scraping or TechInAsia lookup needed"
            )
        if not dossier.known_locations:
            dossier.intelligence_gaps.append("No location data — expand to WHOIS, EXIF, and social media geo-tags")
        if not dossier.breached_services:
            dossier.intelligence_gaps.append("No breach data — configure HIBP_API_KEY for personalized breach lookups")
            dossier.requires_api_keys.append("HIBP_API_KEY ($3.50/mo) — personal breach lookup")
        if not any(p.whatsapp_registered for p in dossier.phones):
            dossier.intelligence_gaps.append("WhatsApp verification pending — requires discovered phone number first")

        # Deduplicate data_sources_used
        dossier.data_sources_used = list(dict.fromkeys(dossier.data_sources_used))

        # Confidence score
        filled = sum(
            [
                1 if dossier.emails else 0,
                1 if dossier.phones else 0,
                1 if dossier.current_employer else 0,
                1 if dossier.known_locations else 0,
                1 if dossier.social_accounts else 0,
                1 if dossier.profile_pictures else 0,
                1 if dossier.breached_services else 0,
                1 if dossier.websites else 0,
            ]
        )
        dossier.confidence_score = round(filled / 8.0, 2)

        return dossier
