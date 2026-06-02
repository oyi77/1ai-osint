"""Source adapter — bridges shared leak sources to the deep scan engine.

Converts RawLeak objects from breach/leak sources into structured
ScanResult objects with rich raw_data that the deep scan engine
and report generator can consume for intelligence-grade output.
"""

from __future__ import annotations
import json
import logging
import uuid
from typing import Any, Optional

from src.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# Sources that have search_for_address with structured API responses
_STRUCTURED_SOURCES = {
    "dehashed": {
        "api": "api.dehashed.com",
        "fields": ["email", "username", "password_hash", "phone", "domain", "ip_address", "name"],
    },
    "leakcheck": {
        "api": "leakcheck.io",
        "fields": ["email", "username", "phone", "domain"],
    },
    "snylla": {
        "api": "scylla.sh",
        "fields": ["email", "username", "password_hash", "phone", "domain", "ip_address"],
    },
    "snusbase": {
        "api": "snusbase.com",
        "fields": ["email", "username", "password_hash", "phone", "domain"],
    },
    "hibp": {
        "api": "haveibeenpwned.com",
        "fields": ["email", "breach_name", "breach_date", "data_classes"],
    },
    "intelx": {
        "api": "intelx.io",
        "fields": ["email", "username", "phone", "domain", "name", "address"],
    },
}


async def run_source_scan(source_name: str, target: str, source_instance: Any) -> Optional[ScanResult]:
    """Run a single breach/leak source scan and return a structured ScanResult.

    Args:
        source_name: Short source key (e.g. "dehashed", "snylla")
        target: Search target (email, username, etc.)
        source_instance: Instantiated source class with search_for_address()

    Returns:
        ScanResult with structured findings, or None on failure.
    """
    scan_id = f"source-{source_name}-{uuid.uuid4().hex[:8]}"
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        raw_leaks = await source_instance.search_for_address(target)
    except Exception as exc:
        logger.debug("Source %s error for '%s': %s", source_name, target, exc)
        return None

    if not raw_leaks:
        return None

    source_config = _STRUCTURED_SOURCES.get(source_name, {})

    for leak in raw_leaks:
        parsed = _parse_leak_data(leak.text, source_name, source_config)
        findings.append(Finding(
            id=f"find-{uuid.uuid4().hex[:8]}",
            module=f"source_{source_name}",
            title=f"{source_name}: {target}",
            description=f"Structured data from {source_config.get('api', source_name)}",
            severity=Severity.INFO,
            raw_data={
                "source": source_name,
                "source_url": leak.source_url,
                "target": target,
                **parsed,
            },
            confidence=_confidence_for_source(source_name, parsed),
        ))

    if not findings:
        return None

    return ScanResult(
        scan_id=scan_id,
        module=f"source_{source_name}",
        target=target,
        status="error" if errors else "ok",
        findings=findings,
    )


def _parse_leak_data(text: str, source_name: str, config: dict) -> dict[str, Any]:
    """Parse raw leak text into structured fields.

    Attempts JSON parsing first, then falls back to regex extraction.
    """
    result: dict[str, Any] = {}

    # Try JSON parse
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for field in config.get("fields", []):
                val = data.get(field) or data.get(field.capitalize())
                if val and isinstance(val, (str, int)):
                    result[field] = str(val)
            # Capture any extra fields
            for key in data:
                if key not in result and key not in ("_source", "_id"):
                    v = data[key]
                    if isinstance(v, (str, int, float, bool)):
                        result[key] = v
            return result
    except (json.JSONDecodeError, TypeError):
        pass

    # Try to parse table-prefixed format from snusbase
    if "\n" in text and ": " in text:
        for line in text.split("\n"):
            if ": " in line:
                key, _, val = line.partition(": ")
                key = key.strip().lower().replace(" ", "_")
                val = val.strip()
                if key and val and key not in ("table",):
                    result[key] = val

    return result


def _confidence_for_source(source_name: str, parsed: dict) -> float:
    """Compute confidence based on how many fields were extracted."""
    expected = _STRUCTURED_SOURCES.get(source_name, {}).get("fields", [])
    if not expected:
        return 0.5
    found = sum(1 for f in expected if f in parsed)
    ratio = found / len(expected)
    if ratio >= 0.5:
        return 0.7
    if ratio >= 0.25:
        return 0.5
    return 0.3
