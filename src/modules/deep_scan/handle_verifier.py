"""Handle existence verification across key platforms.

Quick HTTP checks to determine whether a suspected handle actually exists
on major platforms before trusting it as an identity anchor. Each platform
gets its own probe; combined confidence is returned.

This is the critical preventive check against the misattribution bug where
name-permuted handles were scanned without verifying they belong to the target.

Only platforms that reliably return HTTP 404 for non-existent handles are used:
GitHub, Telegram, GitLab. Instagram and LinkedIn both return HTTP 200 for
non-existent handles (login walls, "not found" pages), making them unreliable
for existence verification.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Timeout per platform probe (seconds)
_PROBE_TIMEOUT = 5.0

# Platforms that reliably return 404 for non-existent handles.
_PLATFORMS: dict[str, dict[str, str]] = {
    "github": {
        "type": "http_status",
        "url": "https://github.com/{handle}",
        "exists_on": "200",
    },
    "telegram": {
        "type": "http_status",
        "url": "https://t.me/{handle}",
        "exists_on": "200",
        "not_found_text": "If you have Telegram",
    },
    "gitlab": {
        "type": "http_status",
        "url": "https://gitlab.com/{handle}",
        "exists_on": "200",
    },
}

_PROBE_ORDER = ["github", "telegram", "gitlab"]


@dataclass
class HandlePlatformResult:
    """Result of checking a handle on a single platform."""

    platform: str
    exists: bool
    status: str  # "found", "not_found", "error", "authwall"
    detail: str = ""


@dataclass
class HandleVerification:
    """Complete verification result for one handle."""

    handle: str
    platforms: dict[str, HandlePlatformResult] = field(default_factory=dict)
    overall_confidence: float = 0.0
    found_count: int = 0
    queried_count: int = 0
    errors: list[str] = field(default_factory=list)


async def _probe_platform(
    client: httpx.AsyncClient,
    handle: str,
    platform: str,
    config: dict[str, str],
) -> HandlePlatformResult:
    """Probe a single platform for handle existence."""
    url = config["url"].format(handle=handle)
    exists_on = config["exists_on"]

    try:
        resp = await client.get(url, follow_redirects=True, timeout=_PROBE_TIMEOUT)

        if config["type"] == "http_status":
            if "999" in exists_on and resp.status_code == 999:
                return HandlePlatformResult(
                    platform=platform,
                    exists=True,
                    status="authwall",
                    detail="LinkedIn rate-limited (HTTP 999)",
                )
            if resp.status_code == 200:
                # Check for not_found_text body marker (platforms like Telegram
                # return HTTP 200 for non-existent handles with a "user not found" page)
                nft = config.get("not_found_text")
                if nft and nft in (resp.text or ""):
                    return HandlePlatformResult(
                        platform=platform,
                        exists=False,
                        status="not_found",
                        detail=f"Body matched '{nft}'",
                    )
                return HandlePlatformResult(
                    platform=platform,
                    exists=True,
                    status="found",
                    detail=f"HTTP {resp.status_code}",
                )
            if resp.status_code == 404:
                return HandlePlatformResult(
                    platform=platform,
                    exists=False,
                    status="not_found",
                    detail="HTTP 404",
                )
            if resp.status_code in (429, 403):
                return HandlePlatformResult(
                    platform=platform,
                    exists=False,
                    status="error",
                    detail=f"HTTP {resp.status_code} (rate-limited/blocked)",
                )

            return HandlePlatformResult(
                platform=platform,
                exists=False,
                status="error",
                detail=f"HTTP {resp.status_code}",
            )

        return HandlePlatformResult(
            platform=platform,
            exists=False,
            status="error",
            detail=f"Unknown probe type: {config['type']}",
        )

    except httpx.TimeoutException:
        return HandlePlatformResult(
            platform=platform,
            exists=False,
            status="error",
            detail="timeout",
        )
    except httpx.ConnectError:
        return HandlePlatformResult(
            platform=platform,
            exists=False,
            status="error",
            detail="connection error",
        )
    except Exception as e:
        return HandlePlatformResult(
            platform=platform,
            exists=False,
            status="error",
            detail=str(e),
        )


def _compute_overall_confidence(
    results: dict[str, HandlePlatformResult],
    queried_count: int,
) -> float:
    """Compute overall confidence that this handle belongs to a real person.

    Rules:
      - 0 platforms probed -> 0.0
      - Found on 3+ platforms -> 0.9 (strong cross-platform)
      - Found on 2 platforms -> 0.7
      - Found on 1 platform -> 0.5
      - Found on 0 platforms -> 0.1
      - All probes errored -> 0.0 (can't confirm existence at all)
      - All authoritative 404s -> 0.0 (handle doesn't exist)
    """
    if queried_count == 0:
        return 0.0

    found = sum(1 for r in results.values() if r.exists)
    errors = sum(1 for r in results.values() if r.status == "error")
    not_founds = sum(1 for r in results.values() if r.status == "not_found")

    # Every probe errored — network/blockage, not handle absence
    if errors == queried_count:
        return 0.0

    # Every probe returned definitive 404
    if not_founds == queried_count:
        return 0.0

    if found >= 3:
        return 0.9
    if found == 2:
        return 0.7
    if found == 1:
        return 0.5

    # Some not-found, some errors: handle might still exist
    if not_founds > 0 and found == 0:
        return 0.0

    # All errored (no 404s, no found)
    return 0.2 if errors > 0 else 0.1


async def verify_handle(
    handle: str,
    platforms: list[str] | None = None,
) -> HandleVerification:
    """Verify whether a handle actually exists across key platforms.

    Args:
        handle: Username/handle to verify.
        platforms: Subset of platforms to check. Defaults to [_PROBE_ORDER].

    Returns:
        HandleVerification with per-platform results and overall_confidence.

    """
    if platforms is None:
        platforms = _PROBE_ORDER

    result = HandleVerification(handle=handle)

    async with httpx.AsyncClient(
        timeout=_PROBE_TIMEOUT,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        },
    ) as client:
        tasks = []
        for platform in platforms:
            if platform not in _PLATFORMS:
                continue
            config = _PLATFORMS[platform]
            tasks.append(_probe_platform(client, handle, platform, config))

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in raw_results:
            if isinstance(r, HandlePlatformResult):
                result.platforms[r.platform] = r
                if r.exists:
                    result.found_count += 1

        result.queried_count = len([r for r in raw_results if isinstance(r, HandlePlatformResult)])
        result.errors = [r.detail for r in raw_results if isinstance(r, HandlePlatformResult) and r.status == "error"]

    result.overall_confidence = _compute_overall_confidence(result.platforms, result.queried_count)
    return result


async def batch_verify_handles(
    handles: list[str],
    platforms: list[str] | None = None,
    max_concurrency: int = 5,
) -> dict[str, HandleVerification]:
    """Verify multiple handles in parallel.

    Args:
        handles: List of handles to verify.
        platforms: Platforms to check per handle.
        max_concurrency: Max concurrent HTTP sessions.

    Returns:
        Dict mapping handle -> HandleVerification.

    """
    results: dict[str, HandleVerification] = {}
    sem = asyncio.Semaphore(max_concurrency)

    async def _verify_one(h: str) -> tuple[str, HandleVerification]:
        async with sem:
            v = await verify_handle(h, platforms=platforms)
            return (h, v)

    tasks = [_verify_one(h) for h in handles]
    for coro in asyncio.as_completed(tasks):
        try:
            handle, verification = await coro
            results[handle] = verification
        except Exception as e:
            logger.debug("Handle verification batch error: %s", e)

    return results
