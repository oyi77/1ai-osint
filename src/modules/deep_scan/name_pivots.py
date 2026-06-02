"""Name → username pivot candidates for deep scan recursion."""
from __future__ import annotations

import re

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,50}$")


def slugify_username(value: str) -> str:
    """Normalize a display name for platform URL / handle use."""
    return re.sub(r"[^a-zA-Z0-9._-]", "", value.lower().replace(" ", ""))


def username_candidates_from_name(name: str) -> list[tuple[str, float]]:
    """Derive likely handles from a full name (highest confidence first)."""
    name = name.strip()
    if not name or "@" in name:
        return []

    parts = [p for p in re.split(r"\s+", name) if p]
    if not parts:
        return []

    candidates: list[tuple[str, float]] = []
    seen: set[str] = set()

    def add(handle: str, confidence: float) -> None:
        handle = handle.strip()
        if handle in seen or not _USERNAME_RE.match(handle):
            return
        seen.add(handle)
        candidates.append((handle, confidence))

    compact = slugify_username(name)
    add(compact, 0.95)

    if len(parts) >= 2:
        first, last = parts[0].lower(), parts[-1].lower()
        add(f"{first}{last}", 0.9)
        add(f"{first}_{last}", 0.85)
        add(f"{first}.{last}", 0.8)
        add(f"{last}{first}", 0.75)
        if first:
            add(f"{first[0]}{last}", 0.7)
            add(f"{first[0]}_{last}", 0.65)

    candidates.sort(key=lambda x: -x[1])
    return candidates


def primary_username_for_name(name: str) -> str:
    """Best single handle guess for modules that accept one username."""
    pivots = username_candidates_from_name(name)
    if pivots:
        return pivots[0][0]
    slug = slugify_username(name)
    return slug if slug else name.strip()
