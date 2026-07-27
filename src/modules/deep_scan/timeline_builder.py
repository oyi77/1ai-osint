"""Chronological footprint timeline builder."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from src.core.models import BreachRecord, Finding
from src.modules.deep_scan.models_report import TimelineEntry

logger = logging.getLogger(__name__)


def parse_datetime(dt_val: Any) -> Optional[datetime]:
    """Helper to parse raw date values into timezone-aware UTC datetime."""
    if not dt_val:
        return None
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            return dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(timezone.utc)
    if isinstance(dt_val, (int, float)):
        try:
            return datetime.fromtimestamp(dt_val, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(dt_val, str):
        # Clean up string slightly and try standard formats
        clean_str = dt_val.strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%Y/%m/%d",
        ):
            try:
                parsed = datetime.strptime(clean_str, fmt)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except ValueError:
                continue
    return None


class TimelineBuilder:
    """Builds a unified chronological timeline from findings and breach records."""

    @staticmethod
    def build(findings: List[Finding], breach_records: List[BreachRecord]) -> List[TimelineEntry]:
        """Aggregate, parse, and sort time-based events from findings and breach records."""
        entries: List[TimelineEntry] = []
        seen_events = set()

        # 1. Process breach records
        for record in breach_records:
            dt = (
                parse_datetime(record.breach_date)
                or parse_datetime(record.raw.get("breach_date"))
                or parse_datetime(record.raw.get("Date"))
            )
            if dt:
                source = record.source or "data_leaks"
                event = "Credential Leak"
                detail = f"Account breach detected in {record.source} dump. Affected: {record.email or record.username or record.domain}"

                # Check for duplicate events
                evt_key = (dt.isoformat(), source, detail)
                if evt_key not in seen_events:
                    seen_events.add(evt_key)
                    entries.append(
                        TimelineEntry(
                            timestamp=dt,
                            source=source,
                            event=event,
                            detail=detail,
                            confidence=0.9,
                        )
                    )

        # 2. Process findings (e.g. crypto transactions, social profiles, metadata)
        for finding in findings:
            # Check finding level timestamp
            dt = parse_datetime(finding.timestamp)
            if dt:
                source = finding.module or "osint"
                event = finding.title or "Discovery Event"
                detail = finding.description or finding.title

                # If it's a crypto finding, we can extract transaction details
                if finding.module == "crypto_tracer" and "transactions" in finding.raw_data:
                    for tx in finding.raw_data["transactions"]:
                        tx_dt = parse_datetime(tx.get("timestamp"))
                        if tx_dt:
                            tx_hash = tx.get("hash", "")[:10]
                            tx_detail = f"Tx {tx_hash}... From: {tx.get('from_entity')} To: {tx.get('to_entity')}"

                            tx_evt_key = (tx_dt.isoformat(), source, tx_detail)
                            if tx_evt_key not in seen_events:
                                seen_events.add(tx_evt_key)
                                entries.append(
                                    TimelineEntry(
                                        timestamp=tx_dt,
                                        source=source,
                                        event="Crypto Transaction",
                                        detail=tx_detail,
                                        confidence=1.0,
                                    )
                                )
                    continue  # Already handled transactions, skip base finding if duplicate

                evt_key = (dt.isoformat(), source, detail)
                if evt_key not in seen_events:
                    seen_events.add(evt_key)
                    entries.append(
                        TimelineEntry(
                            timestamp=dt,
                            source=source,
                            event=event,
                            detail=detail,
                            confidence=finding.confidence or 0.8,
                        )
                    )

        # Sort chronologically (oldest to newest)
        entries.sort(key=lambda x: x.timestamp)  # type: ignore[arg-type,return-value]
        return entries
