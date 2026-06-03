"""Delta briefing — compare two intel reports."""

from __future__ import annotations

from typing import Any


def compute_intel_delta(previous: dict, current: dict) -> dict[str, Any]:
    """Return new evidence handles, emails, and breach count delta."""
    prev_ev = {e.get("identifier_value") for e in previous.get("evidence", [])}
    curr_ev = current.get("evidence", [])
    new_evidence = [e for e in curr_ev if e.get("identifier_value") not in prev_ev]
    prev_brief = previous.get("briefing", {})
    curr_brief = current.get("briefing", {})
    prev_emails = set(prev_brief.get("subject", {}).get("emails", []))
    curr_emails = set(curr_brief.get("subject", {}).get("emails", []))
    return {
        "new_evidence_count": len(new_evidence),
        "new_evidence": new_evidence[:50],
        "new_emails": sorted(curr_emails - prev_emails),
        "new_handles": sorted(
            set(curr_brief.get("subject", {}).get("known_handles", []))
            - set(prev_brief.get("subject", {}).get("known_handles", []))
        ),
        "breach_delta": len(curr_brief.get("breach_records", []))
        - len(prev_brief.get("breach_records", [])),
    }
