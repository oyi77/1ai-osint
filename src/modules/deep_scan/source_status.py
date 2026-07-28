"""Quick reachability probes for external sources used in OSINT scanning.

Determines whether search engines, social platforms, and academic databases
are reachable from the current network, so modules can report "blocked"
instead of silently returning empty results.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import dns.resolver
import httpx

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT = 5.0


@dataclass
class SourceStatus:
    """Reachability result for one external source."""

    name: str
    reachable: bool
    detail: str = ""
    status_code: int | None = None

    is_blocked: bool = False
    blocked_reason: str = ""


@dataclass
class SourceStatusReport:
    """Complete source health report."""

    sources: dict[str, SourceStatus] = field(default_factory=dict)

    @property
    def all_reachable(self) -> bool:
        return all(s.reachable for s in self.sources.values() if s.name != "pdikti")

    @property
    def blocked_count(self) -> int:
        return sum(1 for s in self.sources.values() if s.is_blocked)

    def summary(self) -> str:
        lines = []
        for name, st in sorted(self.sources.items()):
            if st.is_blocked:
                lines.append(f"  [BLOCKED] {name}: {st.blocked_reason}")
            elif st.reachable:
                lines.append(f"  [OK]      {name}")
            else:
                lines.append(f"  [DOWN]    {name}: {st.detail}")
        return "\n".join(lines)


async def _check_http_source(
    client: httpx.AsyncClient,
    name: str,
    url: str,
) -> SourceStatus:
    """Probe an HTTP source for basic reachability."""
    try:
        resp = await client.get(url, follow_redirects=True, timeout=_PROBE_TIMEOUT)
        code = resp.status_code

        if code == 200:
            return SourceStatus(
                name=name,
                reachable=True,
                status_code=code,
            )

        # LinkedIn-specific
        if "linkedin" in name and code == 999:
            return SourceStatus(
                name=name,
                reachable=True,
                status_code=code,
                is_blocked=True,
                blocked_reason=("HTTP 999 rate limit (LinkedIn blocks automated access)"),
            )

        if code in (429, 403):
            return SourceStatus(
                name=name,
                reachable=False,
                status_code=code,
                is_blocked=True,
                blocked_reason=f"HTTP {code} (rate-limited or blocked)",
            )

        # Unexpected status but host is reachable
        return SourceStatus(
            name=name,
            reachable=True,
            status_code=code,
            detail=f"HTTP {code}",
        )

    except httpx.TimeoutException:
        return SourceStatus(
            name=name,
            reachable=False,
            detail="timeout",
        )
    except httpx.ConnectError:
        return SourceStatus(
            name=name,
            reachable=False,
            detail="connection refused",
        )
    except Exception as e:
        return SourceStatus(
            name=name,
            reachable=False,
            detail=str(e),
        )


async def _check_dns_source(name: str, domain: str) -> SourceStatus:
    """Check if a domain resolves (for geo-blocked/DNS-blocked sources)."""
    try:
        answers = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, lambda: dns.resolver.resolve(domain, "A")),
            timeout=_PROBE_TIMEOUT,
        )
        return SourceStatus(
            name=name,
            reachable=True,
            detail=f"DNS resolves to {answers[0]}",
        )
    except dns.resolver.NXDOMAIN:
        return SourceStatus(
            name=name,
            reachable=False,
            is_blocked=True,
            blocked_reason=("DNS NXDOMAIN (domain does not resolve, likely geo-blocked)"),
        )
    except dns.resolver.NoNameservers:
        return SourceStatus(
            name=name,
            reachable=False,
            is_blocked=True,
            blocked_reason="No DNS nameservers reachable",
        )
    except asyncio.TimeoutError:
        return SourceStatus(
            name=name,
            reachable=False,
            detail="DNS timeout",
        )
    except Exception as e:
        return SourceStatus(
            name=name,
            reachable=False,
            detail=str(e),
        )


async def check_sources(
    sources: list[str] | None = None,
) -> SourceStatusReport:
    """Check reachability of configured external sources.

    Args:
        sources: Subset of sources to check. Defaults to all known sources.

    Returns:
        SourceStatusReport with per-source status.

    """
    all_sources = {
        "duckduckgo": ("http", "https://duckduckgo.com/"),
        "google": ("http", "https://www.google.com/"),
        "bing": ("http", "https://www.bing.com/"),
        "linkedin": ("http", "https://www.linkedin.com/"),
        "github": ("http", "https://github.com/"),
        "pddikti": ("dns", "pddikti.kemdikbud.go.id"),
        "sinta": ("dns", "sinta.kemdikbud.go.id"),
    }

    if sources:
        all_sources = {k: v for k, v in all_sources.items() if k in sources}

    report = SourceStatusReport()

    async with httpx.AsyncClient(
        timeout=_PROBE_TIMEOUT,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml",
        },
    ) as client:
        tasks = []
        for name, (stype, target) in all_sources.items():
            if stype == "http":
                tasks.append(_check_http_source(client, name, target))
            elif stype == "dns":
                tasks.append(_check_dns_source(name, target))

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in raw_results:
            if isinstance(r, SourceStatus):
                report.sources[r.name] = r

    return report


def check_sources_sync(
    sources: list[str] | None = None,
) -> SourceStatusReport:
    """Synchronous wrapper around check_sources() for use in doctor.py.

    Runs the async check in a new event loop. Safe to call from sync code
    that has no existing event loop (e.g. from a CLI command).
    """
    return asyncio.run(check_sources(sources))
