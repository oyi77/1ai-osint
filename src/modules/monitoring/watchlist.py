"""Persistent watchlist management — JSON-backed."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.config import Settings
from src.modules.monitoring.models import WatchlistTarget

logger = logging.getLogger(__name__)


class WatchlistManager:
    """Manage a persistent watchlist of targets for continuous monitoring.

    Persists to JSON file under investigations/watchlist/ so that
    state survives across agent sessions.
    """

    def __init__(self, storage_dir: Path | None = None):
        root = storage_dir or (Settings().project_root / "investigations" / "watchlist")
        self._storage_dir = Path(root)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._storage_dir / "index.json"
        self._targets: dict[str, WatchlistTarget] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # persistence helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._loaded:
            return
        if self._index_path.exists():
            try:
                raw = json.loads(self._index_path.read_text(encoding="utf-8"))
                self._targets = {k: WatchlistTarget(**v) for k, v in raw.items()}
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.warning("Corrupt watchlist index — starting fresh: %s", exc)
                self._targets = {}
        self._loaded = True

    def _save(self) -> None:
        raw = {k: v.model_dump(mode="json") for k, v in self._targets.items()}
        self._index_path.write_text(json.dumps(raw, indent=2, default=str), encoding="utf-8")

    def _normalise_target(self, target: str) -> str:
        """Lower-case and strip for consistent keying."""
        return target.strip().lower()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_target(
        self,
        target: str,
        target_type: str,
        *,
        tags: list[str] | None = None,
        interval_hours: int = 24,
        alert_channels: list[str] | None = None,
        severity_threshold: str = "medium",
        context: dict[str, Any] | None = None,
    ) -> WatchlistTarget:
        """Add or update a target on the watchlist.

        If the target already exists it is updated (last_scan preserved).
        """
        self._load()
        key = self._normalise_target(target)
        now = datetime.now(timezone.utc)

        obj = WatchlistTarget(
            target=target,
            target_type=target_type,
            tags=tags or [],
            interval_hours=max(interval_hours, 1),
            alert_channels=alert_channels or ["console"],
            severity_threshold=severity_threshold,
            context=context or {},
            created_at=self._targets[key].created_at if key in self._targets else now,
            updated_at=now,
            last_scan=self._targets[key].last_scan if key in self._targets else None,
        )
        self._targets[key] = obj
        self._save()
        logger.info("Watchlist: added/updated '%s' (%s)", target, target_type)
        return obj

    def remove_target(self, target: str) -> bool:
        """Remove a target from the watchlist. Returns True if it existed."""
        self._load()
        key = self._normalise_target(target)
        existed = key in self._targets
        if existed:
            del self._targets[key]
            self._save()
            logger.info("Watchlist: removed '%s'", target)
        return existed

    def list_targets(
        self,
        *,
        target_type: str | None = None,
        tag: str | None = None,
    ) -> list[WatchlistTarget]:
        """List all watchlist targets, optionally filtered."""
        self._load()
        targets = list(self._targets.values())
        if target_type:
            targets = [t for t in targets if t.target_type == target_type]
        if tag:
            targets = [t for t in targets if tag in t.tags]
        return sorted(targets, key=lambda t: t.target.lower())

    def get_target(self, target: str) -> WatchlistTarget | None:
        """Get a single target by identifier."""
        self._load()
        key = self._normalise_target(target)
        return self._targets.get(key)

    def get_due_targets(self, now: datetime | None = None) -> list[WatchlistTarget]:
        """Return targets whose next scan is due based on interval_hours."""
        self._load()
        now = now or datetime.now(timezone.utc)
        due: list[WatchlistTarget] = []
        for t in self._targets.values():
            if t.last_scan is None:
                due.append(t)
            else:
                elapsed = (now - t.last_scan).total_seconds() / 3600
                if elapsed >= t.interval_hours:
                    due.append(t)
        return sorted(due, key=lambda t: t.last_scan or datetime.min.replace(tzinfo=timezone.utc))

    def mark_scanned(self, target: str, at: datetime | None = None) -> None:
        """Update the last_scan timestamp for a target."""
        self._load()
        key = self._normalise_target(target)
        if key in self._targets:
            self._targets[key].last_scan = at or datetime.now(timezone.utc)
            self._targets[key].updated_at = datetime.now(timezone.utc)
            self._save()

    def count(self) -> int:
        """Return total number of watchlist entries."""
        self._load()
        return len(self._targets)

    def clear(self) -> int:
        """Remove all targets. Returns the count of removed entries."""
        self._load()
        count = len(self._targets)
        self._targets.clear()
        if self._index_path.exists():
            self._index_path.unlink()
        self._loaded = True
        logger.info("Watchlist: cleared %d entries", count)
        return count
