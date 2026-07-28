"""Change detection — delta intelligence between snapshots."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.modules.monitoring.models import (
    ChangeEvent,
    ChangeSeverity,
    ChangeType,
    WatchlistTarget,
)

logger = logging.getLogger(__name__)

# Risk score fields that trigger a severity bump when they change
_RISK_TRIGGER_FIELDS = frozenset({"risk_score", "risk_level", "criticality"})


class ChangeDetector:
    """Compare two intelligence snapshots and produce structured ChangeEvents.

    Handles:
    - New entity sets (emails, handles, domains, phones, crypto addresses)
    - New breach records
    - Risk score deltas
    - Field-level diffs on structured data
    - Confidence shifts
    """

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def detect_changes(
        self,
        previous: dict[str, Any] | None,
        current: dict[str, Any],
        *,
        target: str | None = None,
        watchlist_target: WatchlistTarget | None = None,
    ) -> list[ChangeEvent]:
        """Compare *previous* and *current* snapshots and return all changes.

        Parameters
        ----------
        previous : dict or None
            The previous intel snapshot.  ``None`` means first scan —
            all current items are reported as "new".
        current : dict
            The current (latest) intel snapshot.
        target : str, optional
            Human-readable name for the entity being compared.
        watchlist_target : WatchlistTarget, optional
            If provided, the watchlist entry's context may influence thresholding.

        Returns
        -------
        list[ChangeEvent]
            Zero or more detected change events.

        """
        events: list[ChangeEvent] = []
        subject = current.get("briefing", {}).get("subject", {})

        if previous is None:
            # First scan — everything is "new"
            events.extend(self._first_scan_events(current, target or subject.get("primary_name", "unknown")))
            return events

        prev_brief = previous.get("briefing", {})
        curr_brief = current.get("briefing", {})
        prev_subject = prev_brief.get("subject", {})
        curr_subject = curr_brief.get("subject", {})

        label = target or curr_subject.get("primary_name", "unknown")

        # Entity set changes
        events.extend(self._compare_set_changes(prev_subject, curr_subject, label))

        # Breach changes
        events.extend(self._compare_breach_changes(prev_brief, curr_brief, label))

        # Risk score changes
        events.extend(self._compare_risk_changes(prev_brief, curr_brief, label))

        # Field-level attribute changes
        events.extend(self._compare_attributes(prev_subject, curr_subject, label))

        return events

    # ------------------------------------------------------------------
    # first-scan helper
    # ------------------------------------------------------------------

    def _first_scan_events(self, current: dict[str, Any], label: str) -> list[ChangeEvent]:
        events: list[ChangeEvent] = []
        subject = current.get("briefing", {}).get("subject", {})

        for email in subject.get("emails", []):
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.NEW_EMAIL,
                    new_value=email,
                    source_module="monitoring",
                    severity=ChangeSeverity.MEDIUM,
                    description=f"Email discovered: {email}",
                )
            )
        for handle in subject.get("known_handles", []):
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.NEW_HANDLE,
                    new_value=handle,
                    source_module="monitoring",
                    severity=ChangeSeverity.LOW,
                    description=f"Handle discovered: {handle}",
                )
            )
        for domain in subject.get("domains", []):
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.NEW_DOMAIN,
                    new_value=domain,
                    source_module="monitoring",
                    severity=ChangeSeverity.LOW,
                    description=f"Domain discovered: {domain}",
                )
            )
        for phone in subject.get("phones", []):
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.NEW_PHONE,
                    new_value=phone,
                    source_module="monitoring",
                    severity=ChangeSeverity.MEDIUM,
                    description=f"Phone discovered: {phone}",
                )
            )
        for addr in subject.get("crypto_addresses", []):
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.NEW_CRYPTO_ADDRESS,
                    new_value=addr,
                    source_module="monitoring",
                    severity=ChangeSeverity.LOW,
                    description=f"Crypto address discovered: {addr[:16]}...",
                )
            )
        return events

    # ------------------------------------------------------------------
    # set comparison helpers
    # ------------------------------------------------------------------

    def _compare_set_changes(
        self,
        prev: dict[str, Any],
        curr: dict[str, Any],
        label: str,
    ) -> list[ChangeEvent]:
        events: list[ChangeEvent] = []
        set_fields: list[tuple[str, ChangeType, ChangeSeverity, str]] = [
            ("emails", ChangeType.NEW_EMAIL, ChangeSeverity.MEDIUM, "Email"),
            ("known_handles", ChangeType.NEW_HANDLE, ChangeSeverity.LOW, "Handle"),
            ("domains", ChangeType.NEW_DOMAIN, ChangeSeverity.LOW, "Domain"),
            ("phones", ChangeType.NEW_PHONE, ChangeSeverity.MEDIUM, "Phone"),
            ("crypto_addresses", ChangeType.NEW_CRYPTO_ADDRESS, ChangeSeverity.LOW, "Crypto address"),
        ]

        for field, ctype, default_sev, label_prefix in set_fields:
            old_set = set(prev.get(field, []))
            new_set = set(curr.get(field, []))
            added = new_set - old_set
            removed = old_set - new_set

            for item in sorted(added):
                sev = self._compute_severity(item, ctype, default_sev)
                events.append(
                    self._make_event(
                        target=label,
                        change_type=ctype,
                        new_value=item,
                        source_module="monitoring",
                        severity=sev,
                        description=f"{label_prefix} added: {item}",
                    )
                )
            for item in sorted(removed):
                events.append(
                    self._make_event(
                        target=label,
                        change_type=ChangeType.SOURCE_DISAPPEARED,
                        old_value=item,
                        source_module="monitoring",
                        severity=ChangeSeverity.INFO,
                        description=f"{label_prefix} disappeared: {item}",
                    )
                )

        return events

    def _compare_breach_changes(
        self,
        prev_brief: dict[str, Any],
        curr_brief: dict[str, Any],
        label: str,
    ) -> list[ChangeEvent]:
        events: list[ChangeEvent] = []
        prev_breaches = prev_brief.get("breach_records", [])
        curr_breaches = curr_brief.get("breach_records", [])

        prev_names: set[str] = set()
        curr_names: set[str] = set()
        for b in prev_breaches:
            if isinstance(b, dict):
                prev_names.add(b.get("breach_name", "") or "")
        for b in curr_breaches:
            if isinstance(b, dict):
                curr_names.add(b.get("breach_name", "") or "")

        added = curr_names - prev_names
        for name in sorted(added):
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.NEW_BREACH,
                    new_value=name,
                    source_module="monitoring",
                    severity=ChangeSeverity.HIGH,
                    description=f"New breach record: {name}",
                )
            )

        # Breach count delta
        delta = len(curr_breaches) - len(prev_breaches)
        if delta != 0:
            events.append(
                self._make_event(
                    target=label,
                    change_type=ChangeType.FIELD_CHANGE,
                    old_value=str(len(prev_breaches)),
                    new_value=str(len(curr_breaches)),
                    source_module="monitoring",
                    severity=ChangeSeverity.MEDIUM if abs(delta) > 2 else ChangeSeverity.LOW,
                    description=f"Breach count changed by {delta:+d} ({len(prev_breaches)} → {len(curr_breaches)})",
                )
            )

        return events

    def _compare_risk_changes(
        self,
        prev_brief: dict[str, Any],
        curr_brief: dict[str, Any],
        label: str,
    ) -> list[ChangeEvent]:
        events: list[ChangeEvent] = []
        prev_risk = prev_brief.get("risk", {}) or {}
        curr_risk = curr_brief.get("risk", {}) or {}

        for field in _RISK_TRIGGER_FIELDS:
            old_val = prev_risk.get(field)
            new_val = curr_risk.get(field)
            if old_val != new_val:
                events.append(
                    self._make_event(
                        target=label,
                        change_type=ChangeType.RISK_SCORE_CHANGE,
                        old_value=str(old_val) if old_val is not None else None,
                        new_value=str(new_val) if new_val is not None else None,
                        source_module="monitoring",
                        severity=ChangeSeverity.HIGH,
                        description=f"Risk {field} changed: {old_val} → {new_val}",
                    )
                )

        return events

    def _compare_attributes(
        self,
        prev_subject: dict[str, Any],
        curr_subject: dict[str, Any],
        label: str,
    ) -> list[ChangeEvent]:
        """Field-level diff on scalar subject attributes."""
        events: list[ChangeEvent] = []
        scalar_fields = {
            "primary_name",
            "confidence_score",
            "current_employer",
            "job_title",
            "city",
            "country",
        }
        for field in scalar_fields:
            old_val = prev_subject.get(field)
            new_val = curr_subject.get(field)
            if old_val != new_val and new_val is not None:
                events.append(
                    self._make_event(
                        target=label,
                        change_type=ChangeType.ATTRIBUTE_CHANGE,
                        old_value=str(old_val) if old_val is not None else None,
                        new_value=str(new_val),
                        source_module="monitoring",
                        severity=ChangeSeverity.LOW,
                        description=f"Attribute '{field}' changed: {old_val} → {new_val}",
                    )
                )
        return events

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _compute_severity(
        self,
        _item: str,
        change_type: ChangeType,
        default: ChangeSeverity,
    ) -> ChangeSeverity:
        """Override severity based on change type heuristics."""
        # For now use the default; can be extended with pattern matching
        return default

    def _make_event(
        self,
        *,
        target: str,
        change_type: ChangeType,
        source_module: str = "change_detector",
        old_value: str | None = None,
        new_value: str | None = None,
        severity: ChangeSeverity = ChangeSeverity.INFO,
        description: str = "",
    ) -> ChangeEvent:
        import uuid

        return ChangeEvent(
            event_id=f"ce-{uuid.uuid4().hex[:12]}",
            target=target,
            change_type=change_type,
            old_value=old_value,
            new_value=new_value,
            source_module=source_module,
            severity=severity,
            description=description,
            timestamp=datetime.now(timezone.utc),
        )
