"""Intel report generator — transforms DeepScanResult → IntelReport.

Pure function over the result data. Reads raw_data captured at the source
level (url, http_status, snippet) and builds:
  - per-evidence provenance with source reliability rating
  - deterministic confidence breakdown per identifier
  - rule-based risk matrix
  - chronological timeline
  - identity graph (identifier↔platform links)
  - pivot suggestions (what to investigate next)
"""

from __future__ import annotations

import re
import uuid
import logging
from collections import Counter
from typing import Any

from src.modules.deep_scan.models_report import (
    ConfidenceBreakdown,
    EvidenceItem,
    IdentityEdge,
    IdentityGraph,
    IdentityNode,
    IntelReport,
    PivotSuggestion,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    SourceIntelBlock,
    TimelineEntry,
    rate_source,
)
from src.modules.deep_scan.briefing_builder import build_operational_briefing
from src.modules.deep_scan.field_labels import source_blurb, source_display_name
from src.modules.deep_scan import IdentifierType

logger = logging.getLogger(__name__)


# Risk rules — checked in order
_RISK_RULES: list[tuple[str, str, str, float, RiskLevel]] = [
    # (rule_id, condition_check_fn_name, description, weight, level_if_triggered)
    (
        "nik_plus_name_plus_phone",
        "_has_nik_name_phone",
        "NIK + name + phone combined (full PII exposure)",
        0.7,
        RiskLevel.CRITICAL,
    ),
    (
        "nik_present",
        "_has_nik",
        "Indonesian NIK (national ID) found",
        0.5,
        RiskLevel.HIGH,
    ),
    (
        "crypto_mixer",
        "_has_mixer_tagged_crypto",
        "Crypto address tagged as mixer (sanctioned risk)",
        0.9,
        RiskLevel.CRITICAL,
    ),
    (
        "seed_phrase_leak",
        "_has_seed_phrase",
        "Seed phrase / private key exposed",
        1.0,
        RiskLevel.CRITICAL,
    ),
    (
        "password_leak",
        "_has_password",
        "Plaintext password discovered",
        0.8,
        RiskLevel.CRITICAL,
    ),
    (
        "multi_platform_corroboration",
        "_has_3plus_platforms",
        "Username confirmed on 3+ platforms (high visibility)",
        0.3,
        RiskLevel.MEDIUM,
    ),
    ("phone_present", "_has_phone", "Phone number exposed", 0.3, RiskLevel.MEDIUM),
    ("email_present", "_has_email", "Email exposed", 0.2, RiskLevel.LOW),
    (
        "nik_plus_address_plus_phone",
        "_has_nik_address_phone",
        "NIK + address + phone (full KYC exposure)",
        0.8,
        RiskLevel.CRITICAL,
    ),
    (
        "multi_breach_credentials",
        "_has_multi_breach_password",
        "Password found in 2+ breaches",
        0.9,
        RiskLevel.CRITICAL,
    ),
    (
        "password_plus_email",
        "_has_password_email",
        "Password + email combo leaked",
        0.8,
        RiskLevel.CRITICAL,
    ),
    (
        "dob_plus_nik",
        "_has_dob_nik",
        "Date of birth + NIK (identity theft risk)",
        0.6,
        RiskLevel.HIGH,
    ),
    (
        "crypto_key_leak",
        "_has_crypto_key",
        "Crypto private key or seed phrase in raw data",
        0.9,
        RiskLevel.CRITICAL,
    ),
]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
def generate_intel_report(result: Any) -> IntelReport:
    """Build a full IntelReport from a DeepScanResult."""
    report = IntelReport(
        report_id=f"intel-{uuid.uuid4().hex[:12]}",
        target=result.target,
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_sec=result.duration_sec,
        iterations=result.iterations,
    )

    evidence = _extract_evidence(result)
    report.evidence = evidence
    report.modules_run = sorted({e.source for e in evidence if e.source != "input"})

    # Per-identifier confidence breakdown
    report.confidence_by_identifier = _compute_confidence(result, evidence)

    # Risk matrix
    report.risk = _assess_risk(result, evidence)

    # Timeline
    report.timeline = _build_timeline(result, evidence)

    # Identity graph
    report.identity_graph = _build_graph(result, evidence)

    # Pivots
    report.pivots = _suggest_pivots(result, evidence)

    # ZKIT correlation
    if getattr(result, "zkit_result", None):
        report.correlation_clusters = _build_correlation(result.zkit_result)
        report.correlation_stats = (
            result.zkit_result.graph_stats
            if hasattr(result.zkit_result, "graph_stats")
            else {}
        )

    # Summary + warnings
    report.summary = _summarize(result, evidence, report.risk)
    report.warnings = _collect_warnings(result, evidence)

    report.source_blocks = _build_source_blocks(result)
    modules_from_blocks = {b.module for b in report.source_blocks}
    report.modules_run = sorted(set(report.modules_run) | modules_from_blocks)

    report.briefing = build_operational_briefing(result, report)

    try:
        from src.modules.identity_tracking.neo4j_export import export_neo4j_json

        report.correlation_stats = report.correlation_stats or {}
        report.correlation_stats["neo4j"] = export_neo4j_json(report.identity_graph)
    except Exception:
        pass

    # Phase 5: CIA-level analytical layers (synchronous, all gracefully degrade on error)
    _run_phase5_analysis(report, result)

    return report


def generate_intel_report_with_ai(result: Any, *, use_ai: bool = False) -> Any:
    """Build intel report with optional AI enhancement."""
    report = generate_intel_report(result)
    if use_ai:
        from src.modules.deep_scan.ai_briefing import enhance_briefing_with_ai

        enhance_briefing_with_ai(report, result)
    return report


# ---------------------------------------------------------------------------
# Phase 5: CIA-level analytical pipeline
# ---------------------------------------------------------------------------
def _run_phase5_analysis(report: Any, result: Any) -> None:
    """Run all Phase 5 CIA-level analytical layers on the completed report.

    Each layer degrades gracefully — a failure in one pillar never blocks others.
    Results are written directly to report fields.
    """
    # Pillar 6: Predictive Threat Modeling
    try:
        from src.modules.deep_scan.threat_model import PredictiveThreatModeler

        modeler = PredictiveThreatModeler()
        trajectory = modeler.predict_trajectory(report)
        report.threat_trajectory = trajectory
        report.briefing.threat_trajectory_summary = (
            f"Archetype: {trajectory.most_likely_archetype.value.replace('_', ' ').title()} "
            f"({trajectory.confidence} confidence). "
            + (
                trajectory.predicted_next_actions[0]
                if trajectory.predicted_next_actions
                else ""
            )
        )
    except Exception as exc:
        logger.warning("Phase 5 threat model failed: %s", exc)

    # Pillar 7: Counterintelligence & Legend Detection
    try:
        from src.modules.identity_tracking.counterintel import CounterIntelAnalyzer

        ci_analyzer = CounterIntelAnalyzer()
        ci_assessment = ci_analyzer.assess_legend_probability(result)
        report.counterintel = ci_assessment
        report.briefing.counterintel_summary = (
            f"OPSEC: {ci_assessment.opsec_level.value.upper()} | "
            f"Legend probability: {ci_assessment.legend_confidence:.0%} | "
            + (
                "LEGEND SUSPECTED"
                if ci_assessment.is_likely_legend
                else "No legend detected"
            )
        )
    except Exception as exc:
        logger.warning("Phase 5 counterintel failed: %s", exc)

    # Pillar 2: Behavioral Fingerprint (requires social evidence text)
    try:
        from src.modules.identity_tracking.behavioral_fingerprint import (
            LinguisticFingerprintAnalyzer,
        )

        analyzer = LinguisticFingerprintAnalyzer()
        texts = [
            ev.snippet for ev in report.evidence if ev.snippet and len(ev.snippet) > 20
        ]

        # Phase 6 Injection: add actual deep scraped texts
        if hasattr(result, "scraped_texts") and result.scraped_texts:
            texts.extend(result.scraped_texts)

        if texts:
            fp = analyzer.analyze_texts(texts[:50], subject_id=report.target)
            report.behavioral_fingerprint = fp
    except Exception as exc:
        logger.warning("Phase 5 behavioral fingerprint failed: %s", exc)

    # Pillar 4: Geospatial OSINT
    try:
        from src.modules.deep_scan.geo_osint import GeoOSINTEngine

        geo_engine = GeoOSINTEngine()
        location_events = geo_engine.build_location_timeline(report.evidence)
        if location_events:
            geo_clusters = geo_engine._cluster_events(location_events)
            report.geo_clusters = [
                c.model_dump() if hasattr(c, "model_dump") else c for c in geo_clusters
            ]
            if geo_clusters:
                report.briefing.geospatial_summary = (
                    f"{len(geo_clusters)} location cluster(s) identified. "
                    f"Primary cluster: {geo_clusters[0].label} "
                    f"({geo_clusters[0].evidence_count} evidence points, geohash {geo_clusters[0].geohash})."
                )
    except Exception as exc:
        logger.warning("Phase 5 geo OSINT failed: %s", exc)

    # Phase 6 Vision AI Injection
    try:
        if hasattr(result, "vision_scores") and result.vision_scores:
            avg_score = sum(result.vision_scores) / len(result.vision_scores)
            report.briefing.cia_bluf_plus = (
                (report.briefing.cia_bluf_plus or "")
                + f" [VISION AI: Identities correlated across profiles with {avg_score:.0%} confidence.]"
            )
    except Exception as exc:
        logger.warning("Phase 6 vision injection failed: %s", exc)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------
def _extract_evidence(result: Any) -> list[EvidenceItem]:
    """Walk all findings and pull out per-observation evidence from raw_data."""
    evidence: list[EvidenceItem] = []
    seen: set[tuple[str, str, str | None]] = set()

    for finding in result.findings:
        rd = finding.raw_data or {}
        source = finding.module or "unknown"
        reliability = rate_source(source)

        # Collect all identifiers present in raw_data (not just first match)
        identifiers_found: list[tuple[str, str]] = []
        for key, target_type in [
            ("username", "username"),
            ("email", "email"),
            ("phone", "phone"),
            ("nik", "nik"),
            ("address", "crypto"),
            ("domain", "domain"),
        ]:
            if key in rd:
                identifiers_found.append((str(rd[key]), target_type))

        # Walk platform lists (e.g., social_osint) — emit per-platform evidence
        if "platforms" in rd and isinstance(rd["platforms"], list):
            primary_ident = next(
                (rd.get(k) for k in ["username", "email"] if k in rd), None
            )
            for plat in rd["platforms"]:
                if not isinstance(plat, dict):
                    continue
                platform = plat.get("platform", "?")
                url = plat.get("url") or _build_platform_url(
                    platform, str(primary_ident or finding.title)
                )
                status = plat.get("status")
                exists = plat.get("exists")
                # Do not include non-existent accounts in the final report
                if exists is False:
                    continue
                ev_key = (str(url), source, platform)
                if ev_key in seen:
                    continue
                seen.add(ev_key)
                evidence.append(
                    EvidenceItem(
                        id=f"ev-{uuid.uuid4().hex[:8]}",
                        identifier_value=str(primary_ident or platform),
                        identifier_type="username" if primary_ident else "platform",
                        source=source,
                        source_reliability=reliability,
                        url=url,
                        http_status=int(status)
                        if isinstance(status, (int, float))
                        else None,
                        snippet="Profile confirmed active" if exists else "Profile visibility unconfirmed",
                        raw_data=plat,
                        confidence=0.9 if exists else 0.2,
                        notes=platform,
                    )
                )
            # Platforms also emit the identifier value itself
            if primary_ident:
                ident_key = (str(primary_ident), source, "username")
                if ident_key not in seen:
                    seen.add(ident_key)
                    evidence.append(
                        EvidenceItem(
                            id=f"ev-{uuid.uuid4().hex[:8]}",
                            identifier_value=str(primary_ident),
                            identifier_type="username",
                            source=source,
                            source_reliability=reliability,
                            url=rd.get("url"),
                            snippet=rd.get("snippet") or finding.description,
                            raw_data=rd,
                            confidence=0.7,
                        )
                    )

        # Emit evidence for each identifier found (non-platform case)
        else:
            for ident_value, ident_type in identifiers_found:
                ev_key = (ident_value, source, ident_type)
                if ev_key in seen:
                    continue
                seen.add(ev_key)
                evidence.append(
                    EvidenceItem(
                        id=f"ev-{uuid.uuid4().hex[:8]}",
                        identifier_value=ident_value,
                        identifier_type=ident_type,
                        source=source,
                        source_reliability=reliability,
                        url=rd.get("url") or rd.get("source_url"),
                        snippet=rd.get("snippet") or finding.description,
                        raw_data=rd,
                        confidence=0.7,
                    )
                )

            # Full structured record (breach / leak / people_finder rows)
            if rd and len(rd) > 1:
                primary = (
                    rd.get("email")
                    or rd.get("username")
                    or rd.get("phone")
                    or rd.get("name")
                    or rd.get("target")
                    or finding.title
                )
                record_key = (source, str(primary), "record")
                if record_key not in seen:
                    seen.add(record_key)
                    evidence.append(
                        EvidenceItem(
                            id=f"ev-{uuid.uuid4().hex[:8]}",
                            identifier_value=str(primary),
                            identifier_type="breach_record"
                            if source.startswith("source_")
                            else "record",
                            source=source,
                            source_reliability=reliability,
                            url=rd.get("source_url") or rd.get("url"),
                            snippet=finding.description or "",
                            raw_data=rd,
                            confidence=getattr(finding, "confidence", 0.7) or 0.7,
                            notes=rd.get("source") or rd.get("breach_name") or "",
                        )
                    )

    return evidence


def _build_source_blocks(result: Any) -> list[SourceIntelBlock]:
    """Group raw findings into presentable per-source blocks."""
    grouped: dict[str, list[dict[str, Any]]] = {}

    for finding in getattr(result, "findings", []) or []:
        module = getattr(finding, "module", None) or "unknown"
        rd = dict(getattr(finding, "raw_data", None) or {})
        title = getattr(finding, "title", "") or ""
        desc = getattr(finding, "description", "") or ""

        if "platforms" in rd and isinstance(rd["platforms"], list):
            grouped.setdefault(module, []).append(dict(rd))
            continue

        if rd:
            if title:
                rd.setdefault("_title", title)
            if desc:
                rd.setdefault("_detail", desc)
            grouped.setdefault(module, []).append(rd)
        elif title or desc:
            grouped.setdefault(module, []).append({"_title": title, "_detail": desc})

    blocks: list[SourceIntelBlock] = []
    for idx, module in enumerate(sorted(grouped.keys()), start=1):
        records = grouped[module]
        blocks.append(
            SourceIntelBlock(
                block_id=f"p{idx}",
                module=module,
                title=source_display_name(module),
                description=source_blurb(module),
                records=records,
            )
        )
    return blocks


def _build_platform_url(platform: str, value: str) -> str:
    """Reconstruct canonical platform URL when source didn't return one."""
    if not value:
        return ""
    p = (platform or "").lower()
    v = _slugify(value)
    urls = {
        "github": f"https://github.com/{v}",
        "gitlab": f"https://gitlab.com/{v}",
        "twitter": f"https://twitter.com/{v}",
        "instagram": f"https://instagram.com/{v}",
        "reddit": f"https://reddit.com/user/{v}",
        "linkedin": f"https://linkedin.com/in/{v}",
        "tiktok": f"https://tiktok.com/@{v}",
        "facebook": f"https://facebook.com/{v}",
        "youtube": f"https://youtube.com/@{v}",
    }
    return urls.get(p, "")


def _slugify(value: str) -> str:
    """Normalize a value for URL use: lowercase, remove spaces, strip special chars."""
    return re.sub(r"[^a-zA-Z0-9._-]", "", value.lower().replace(" ", ""))


# ---------------------------------------------------------------------------
# Confidence breakdown
# ---------------------------------------------------------------------------
def _compute_confidence(
    result: Any, evidence: list[EvidenceItem]
) -> dict[str, ConfidenceBreakdown]:
    by_value: dict[str, ConfidenceBreakdown] = {}

    # Group evidence by identifier value
    for ev in evidence:
        key = ev.identifier_value
        if not key:
            continue
        cb = by_value.setdefault(key, ConfidenceBreakdown())
        cb.existence = max(cb.existence, ev.confidence)
        cb.temporal = max(cb.temporal, 0.7)  # freshly captured

    # Count cross-module corroboration
    sources_per_value: Counter = Counter()
    for ev in evidence:
        sources_per_value[ev.identifier_value] += 1

    total_modules = max(1, len({ev.source for ev in evidence}))
    for value, count in sources_per_value.items():
        cb = by_value[value]
        cb.cross_module = min(1.0, count / max(1, total_modules))
        # Uniqueness heuristic: emails/phones more unique than usernames
        if "@" in value:
            cb.uniqueness = 0.9
        elif re.match(r"^\+?\d[\d\-\s]{6,}$", value):
            cb.uniqueness = 0.8
        elif re.match(r"^0x[a-fA-F0-9]{40}$", value):
            cb.uniqueness = 1.0
        else:
            cb.uniqueness = 0.4
        cb.compute()

    return by_value


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------
def _assess_risk(result: Any, evidence: list[EvidenceItem]) -> RiskAssessment:
    assessment = RiskAssessment()

    # Build identifier-value set for risk rules
    values = {ev.identifier_value for ev in evidence if ev.identifier_value}

    factors: list[RiskFactor] = []

    for rule_id, fn_name, desc, weight, level in _RISK_RULES:
        check = globals().get(fn_name, lambda vs: False)
        triggered = bool(check(values))
        factors.append(
            RiskFactor(
                rule=rule_id,
                description=desc,
                weight=weight,
                triggered=triggered,
            )
        )

    assessment.factors = factors

    # Compute risk score and level
    triggered = [f for f in factors if f.triggered]
    score = min(1.0, sum(f.weight for f in triggered))
    assessment.score = score

    if score >= 0.7:
        assessment.level = RiskLevel.CRITICAL
    elif score >= 0.5:
        assessment.level = RiskLevel.HIGH
    elif score >= 0.25:
        assessment.level = RiskLevel.MEDIUM
    elif score > 0:
        assessment.level = RiskLevel.LOW
    else:
        assessment.level = RiskLevel.NONE

    # Reasoning
    if triggered:
        assessment.reasoning = "; ".join(f.description for f in triggered)
    else:
        assessment.reasoning = "No high-risk indicators detected"

    return assessment


# --- Risk condition functions ---
def _has_nik_name_phone(values: set) -> bool:
    has_nik = any(re.match(r"^\d{16}$", v.replace(" ", "")) for v in values)
    has_phone = any(re.match(r"^\+?\d[\d\-\s]{6,}$", v) for v in values)
    has_name = any(" " in v and v.replace(" ", "").isalpha() for v in values)
    return has_nik and has_phone and has_name


def _has_nik(values: set) -> bool:
    return any(re.match(r"^\d{16}$", v.replace(" ", "")) for v in values)


def _has_mixer_tagged_crypto(values: set) -> bool:
    # Source would tag this; we can't infer from address alone
    return False


def _has_seed_phrase(values: set) -> bool:
    return any("seed" in v.lower() or "mnemonic" in v.lower() for v in values)


def _has_password(values: set) -> bool:
    return any("password" in v.lower() or "passwd" in v.lower() for v in values)


def _has_3plus_platforms(values: set) -> bool:
    return len(values) >= 3


def _has_phone(values: set) -> bool:
    return any(re.match(r"^\+?\d[\d\-\s]{6,}$", v) for v in values)


def _has_email(values: set) -> bool:
    return any("@" in v and "." in v for v in values)


def _has_nik_address_phone(values: set) -> bool:
    has_nik = any(re.match(r"^\d{16}$", v.replace(" ", "")) for v in values)
    has_phone = any(re.match(r"^\+?\d[\d\-\s]{6,}$", v) for v in values)
    has_address = any(
        ("street" in v.lower() or "jalan" in v.lower() or "address" in v.lower())
        for v in values
    )
    return has_nik and has_address and has_phone


def _has_multi_breach_password(values: set) -> bool:
    return any("breach" in v.lower() and "password" in v.lower() for v in values)


def _has_password_email(values: set) -> bool:
    has_pw = any("password" in v.lower() or "passwd" in v.lower() for v in values)
    has_email = any("@" in v and "." in v for v in values)
    return has_pw and has_email


def _has_dob_nik(values: set) -> bool:
    has_nik = any(re.match(r"^\d{16}$", v.replace(" ", "")) for v in values)
    has_dob = any(
        re.match(r"\d{4}[-/]\d{2}[-/]\d{2}", v)
        or re.match(r"\d{2}[-/]\d{2}[-/]\d{4}", v)
        for v in values
    )
    return has_dob and has_nik


def _has_crypto_key(values: set) -> bool:
    return any(
        "private_key" in v.lower()
        or "privatekey" in v.lower()
        or "seed phrase" in v.lower()
        or "mnemonic" in v.lower()
        or "0x" in v
        and len(v) == 66  # raw private key hex
        for v in values
    )


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
def _build_timeline(result: Any, evidence: list[EvidenceItem]) -> list[TimelineEntry]:
    from datetime import datetime, timezone
    from src.modules.deep_scan.timeline_builder import TimelineBuilder

    # Extract findings and breach records from result if available
    findings = getattr(result, "findings", []) or []
    scan_results = getattr(result, "scan_results", []) or []
    breach_records = []
    for sr in scan_results:
        if hasattr(sr, "breach_records"):
            breach_records.extend(sr.breach_records)

    # Build rich timeline entries
    entries = TimelineBuilder.build(findings, breach_records)

    # Create seen set based on timestamp and detail
    seen_keys = {
        (t.timestamp.isoformat() if t.timestamp else "", t.detail) for t in entries
    }

    # Fallback/complement: add evidence captured events
    for ev in evidence:
        ts = ev.captured_at
        detail = f"{ev.identifier_type}={ev.identifier_value} on {ev.source}" + (
            f" ({ev.url})" if ev.url else ""
        )
        key = (ts.isoformat() if ts else "", detail)
        if key not in seen_keys:
            seen_keys.add(key)
            entries.append(
                TimelineEntry(
                    timestamp=ts,
                    source=ev.source,
                    event="evidence_captured",
                    detail=detail,
                    confidence=ev.confidence,
                )
            )

    # Sort final timeline chronologically
    entries.sort(
        key=lambda x: (
            x.timestamp if x.timestamp else datetime.min.replace(tzinfo=timezone.utc)
        )
    )
    return entries


# ---------------------------------------------------------------------------
# Identity graph
# ---------------------------------------------------------------------------
def _build_graph(result: Any, evidence: list[EvidenceItem]) -> IdentityGraph:
    graph = IdentityGraph()

    # Central node: target
    target_id = "target"
    graph.nodes.append(
        IdentityNode(
            id=target_id,
            label=result.target,
            type="name",
            weight=1.0,
        )
    )

    seen_node_ids: set[str] = set()
    for ident in result.identifiers:
        node_id = f"ident-{ident.id_type.value}-{ident.value}"
        if node_id in seen_node_ids:
            continue
        seen_node_ids.add(node_id)
        graph.nodes.append(
            IdentityNode(
                id=node_id,
                label=ident.value
                if len(ident.value) <= 30
                else ident.value[:27] + "...",
                type=ident.id_type.value,
                weight=ident.confidence,
                metadata=ident.metadata or {},
            )
        )
        graph.edges.append(
            IdentityEdge(
                source_id=target_id,
                target_id=node_id,
                relationship="linked_to",
                weight=ident.confidence,
            )
        )

    # Platform nodes + edges from evidence
    for ev in evidence:
        if not ev.url:
            continue
        plat_id = f"plat-{ev.notes or ev.source}"
        if plat_id not in seen_node_ids:
            seen_node_ids.add(plat_id)
            graph.nodes.append(
                IdentityNode(
                    id=plat_id,
                    label=ev.notes or ev.source,
                    type="social",
                    weight=0.5,
                )
            )

        # Find which identifier this evidence is about
        ident_id = None
        for ident in result.identifiers:
            if ident.value == ev.identifier_value:
                ident_id = f"ident-{ident.id_type.value}-{ident.value}"
                break
        if not ident_id:
            ident_id = target_id

        graph.edges.append(
            IdentityEdge(
                source_id=ident_id,
                target_id=plat_id,
                relationship="found_on",
                weight=ev.confidence,
                evidence_ids=[ev.id],
            )
        )

    return graph


# ---------------------------------------------------------------------------
# Pivots
# ---------------------------------------------------------------------------
def _suggest_pivots(result: Any, evidence: list[EvidenceItem]) -> list[PivotSuggestion]:
    pivots: list[PivotSuggestion] = []
    seen: set[tuple[str, str]] = set()

    def _add(
        target_type: str, value: str, rationale: str, priority: int, sources: list[str]
    ):
        if not value or value.startswith(("http://", "https://")):
            return
        key = (target_type, value)
        if key in seen:
            return
        seen.add(key)
        pivots.append(
            PivotSuggestion(
                target_type=target_type,
                target_value=value,
                rationale=rationale,
                priority=priority,
                expected_sources=sources,
            )
        )

    for ident in result.identifiers:
        if ident.id_type == IdentifierType.USERNAME:
            if ident.value.startswith(("http://", "https://")):
                continue
            _add(
                "email",
                _guess_email(ident.value, result.target),
                f"Username '{ident.value}' likely has a Gravatar or GitHub email",
                priority=2,
                sources=["github", "gravatar", "hunter"],
            )
            _add(
                "phone",
                f"Username {ident.value} on phone lookup",
                f"Username '{ident.value}' may have associated phone",
                priority=3,
                sources=["truecaller", "leakcheck"],
            )
        elif ident.id_type == IdentifierType.EMAIL:
            user = ident.value.split("@")[0]
            _add(
                "username",
                user,
                f"Extract local-part '{user}' for username search",
                priority=1,
                sources=["github", "twitter", "instagram"],
            )
            _add(
                "domain",
                ident.value.split("@", 1)[1],
                f"Investigate domain {ident.value.split('@', 1)[1]}",
                priority=2,
                sources=["whois", "domain_recon"],
            )
        elif ident.id_type == IdentifierType.PHONE:
            _add(
                "email",
                f"phone:{ident.value}",
                f"Run reverse phone lookup for {ident.value}",
                priority=2,
                sources=["leakcheck", "dehashed"],
            )
        elif ident.id_type == IdentifierType.CRYPTO_ADDRESS:
            _add(
                "username",
                f"address:{ident.value[:10]}",
                f"Track funding source for {ident.value[:10]}...",
                priority=1,
                sources=["etherscan", "blockchain_info"],
            )

    return pivots


def _guess_email(username: str, target: str) -> str:
    user = re.sub(r"[^a-zA-Z0-9._-]", "", username.lower().replace(" ", ""))
    if user:
        return f"{user}@"
    return ""


# ---------------------------------------------------------------------------
# Summary + warnings
# ---------------------------------------------------------------------------
def _summarize(result: Any, evidence: list[EvidenceItem], risk: RiskAssessment) -> str:
    n_evidence = len(evidence)
    n_platforms = len({e.notes for e in evidence if e.notes})
    n_modules = len({e.source for e in evidence if e.source != "input"})
    parts = [
        f"Scan of '{result.target}' completed in {result.duration_sec:.1f}s "
        f"across {n_modules} module(s) and {result.iterations} iteration(s).",
        f"Collected {n_evidence} evidence item(s) from {n_platforms} distinct platform(s).",
        f"Overall risk: {risk.level.value.upper()} (score {risk.score:.2f}).",
    ]
    return " ".join(parts)


def _collect_warnings(result: Any, evidence: list[EvidenceItem]) -> list[str]:
    warnings: list[str] = []
    if result.errors:
        warnings.append(f"{len(result.errors)} module error(s) — see timeline")
    if not evidence:
        warnings.append("No evidence collected — all sources returned 0 results")
    low_conf = [e for e in evidence if e.confidence < 0.3]
    if low_conf:
        warnings.append(
            f"{len(low_conf)} low-confidence evidence item(s) — verify manually"
        )
    return warnings


# ---------------------------------------------------------------------------
# ZKIT correlation
# ---------------------------------------------------------------------------
def _build_correlation(zkit_result: Any) -> list[dict]:
    """Convert ZKIT CorrelationResult to serializable dicts for the report."""
    clusters: list[dict] = []
    for entity in getattr(zkit_result, "resolved_entities", []):
        clusters.append(
            {
                "entity_id": getattr(entity, "entity_id", ""),
                "zkit_hashes": getattr(entity, "zkit_hashes", []),
                "attribute_types": getattr(entity, "attribute_types", {}),
                "confidence": getattr(entity, "confidence", 0.0),
                "source_modules": getattr(entity, "source_modules", []),
                "evidence": getattr(entity, "correlation_evidence", []),
            }
        )
    return clusters
