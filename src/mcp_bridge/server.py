"""Minimal MCP server for 1ai-osint (blueprint Phase 1 — S3).

Exposes 1ai-osint's deep-scan + correlation pipeline as MCP tools so any
MCP-capable client (Claude Code/Desktop, other agents in the 1ai-hub
ecosystem) can drive investigations without re-implementing adapters.

Tools:
    search(target, source_filter) — run breach/leak sources + correlate
    list_sources()               — available sources with legal basis
    source_compliance(source)    — compliance metadata for one source

Run (stdio transport — default for Claude Code / Desktop):
    uv run python -m src.mcp_bridge.server

Or programmatically via the `server` object (in-process tests use
memory streams).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from src.core.compliance import get_compliance
from src.core.rbac import AccessTier
from src.modules.deep_scan.source_adapter import run_source_scan
from src.modules.identity_tracking.correlation import CrossModuleCorrelator
from src.modules.sources import discover_sources

logger = logging.getLogger(__name__)

# Deep-scan breach/leak sources that route through the source adapter
# (mirrors src/modules/deep_scan/_module_config.py:SOURCE_MODULES).
SOURCE_MODULES: set[str] = {"dehashed", "leakcheck", "snylla", "snusbase", "hibp", "intelx"}

server = FastMCP(
    "1ai-osint",
    instructions=("OSINT & ZKIT research platform — breach/leak lookup and " "cross-source identity correlation."),
)


# ── Tools ─────────────────────────────────────────────────────────────────────


async def _run_sources(
    target: str,
    source_filter: list[str] | None,
    requester: str,
    requester_tier: AccessTier,
) -> dict[str, dict[str, Any]]:
    """Run each requested source adapter and return module_name → ScanResult."""
    sources_map = discover_sources()
    if source_filter:
        requested = [s for s in source_filter if s in SOURCE_MODULES and s in sources_map]
        unknown = [s for s in source_filter if s not in SOURCE_MODULES]
        if unknown:
            logger.warning("Skipping unknown/non-adapter sources: %s", unknown)
    else:
        requested = sorted(SOURCE_MODULES & set(sources_map))

    results: dict[str, dict[str, Any]] = {}
    for source_name in requested:
        try:
            source_inst = sources_map[source_name]()
        except Exception as exc:
            logger.debug("Source %s init failed: %s", source_name, exc)
            results[source_name] = {"error": f"init failed: {exc}"}
            continue
        scan_result = await run_source_scan(
            source_name,
            target,
            source_inst,
            requester=requester,
            requester_tier=requester_tier,
        )
        if scan_result is None:
            continue
        results[source_name] = scan_result.model_dump(mode="json")
    return results


def _correlate_results(
    results: dict[str, dict[str, Any]],
    target: str,
) -> dict[str, Any]:
    """Run ZKIT cross-source correlation over collected scan results."""
    if not results:
        return {
            "resolved_entities": [],
            "graph_stats": {"node_count": 0, "edge_count": 0, "entity_count": 0, "unresolved_count": 0},
            "investigation_id": "",
        }

    from src.core.models import ScanResult

    correlator = CrossModuleCorrelator(
        salt=f"mcp-{uuid.uuid4().hex[:16]}",
        investigation_id=f"mcp-{target[:32]}",
    )
    module_results: dict[str, ScanResult] = {}
    for name, dumped in results.items():
        if dumped.get("error") is not None:
            continue
        try:
            module_results[name] = ScanResult.model_validate(dumped)
        except Exception as exc:
            logger.debug("Correlation ingest skip %s: %s", name, exc)

    ingested = correlator.ingest_scan_results(module_results)
    correlation = correlator.correlate()

    return {
        "ingested_records": ingested,
        "resolved_entities": [
            {
                "entity_id": e.entity_id,
                "confidence": e.confidence,
                "source_modules": e.source_modules,
                "correlation_evidence": e.correlation_evidence,
            }
            for e in correlation.resolved_entities
        ],
        "graph_stats": correlation.graph_stats,
        "investigation_id": correlation.investigation_id,
    }


@server.tool()
async def search(
    target: str,
    source_filter: list[str] | None = None,
    requester_tier: str = "admin",
) -> dict[str, Any]:
    """Run breach/leak source lookup on a target and correlate findings.

    Args:
        target: Search target (email, username, phone, or domain).
        source_filter: Optional list of source names to query (subset of
            dehashed, leakcheck, snylla, snusbase, hibp, intelx).
            Defaults to all configured sources.
        requester_tier: Caller's access tier (readonly/analyst/admin).
            Sources above the tier are blocked by the RBAC gate.

    Returns:
        {"target": ..., "sources": {name: ScanResult}, "correlation": {...}}
    """
    tier = AccessTier.from_str(requester_tier)
    results = await _run_sources(target, source_filter, requester="mcp", requester_tier=tier)
    correlation = _correlate_results(results, target)
    return {
        "target": target,
        "sources": results,
        "correlation": correlation,
    }


@server.tool()
async def list_sources() -> dict[str, Any]:
    """List breach/leak sources with compliance metadata (legal basis, retention)."""
    sources_map = discover_sources()
    available = sorted(SOURCE_MODULES & set(sources_map))
    return {
        "sources": [
            {
                "name": name,
                "legal_basis": get_compliance(name).legal_basis.value,
                "retention_days": get_compliance(name).retention_days,
                "requires_consent": get_compliance(name).requires_consent,
                "min_tier": get_compliance(name).min_tier.name,
                "requests_per_minute": get_compliance(name).requests_per_minute,
            }
            for name in available
        ]
    }


@server.tool()
async def source_compliance(source: str) -> dict[str, Any]:
    """Compliance metadata (legal basis, retention, consent) for one source.

    Args:
        source: Source name (e.g. "hibp", "dehashed").

    Returns:
        Compliance metadata for the source.
    """
    comp = get_compliance(source)
    return {
        "source": comp.source,
        "legal_basis": comp.legal_basis.value,
        "retention_days": comp.retention_days,
        "requires_consent": comp.requires_consent,
        "tos_notes": comp.tos_notes,
        "min_tier": comp.min_tier.name,
        "requests_per_minute": comp.requests_per_minute,
    }


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (default for Claude Code / Desktop)."""
    logging.basicConfig(level=logging.WARNING)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
