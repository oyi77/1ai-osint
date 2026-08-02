"""MCP server for 1ai-osint (blueprint Phase 1 — S3).

Exposes 1ai-osint's deep-scan + correlation pipeline as MCP tools so any
MCP-capable client (Claude Code/Desktop, other agents in the 1ai-hub
ecosystem) can drive investigations without re-implementing adapters.

Tools:
    search(target, source_filter) — run breach/leak sources + correlate
    list_sources()               — available sources with legal basis
    source_compliance(source)    — compliance metadata for one source

Resources:
    osint://sources             — JSON catalog of sources + compliance

Prompts:
    investigate(target, ...)    — guided multi-source investigation plan

Run (stdio transport — default for Claude Code / Desktop):
    uv run python -m src.mcp_bridge.server

Or programmatically via the `server` object (in-process tests use
memory streams).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from src.core.compliance import get_compliance
from src.core.rbac import AccessTier
from src.modules.deep_scan._module_config import SOURCE_MODULES
from src.modules.deep_scan.source_adapter import run_source_scan
from src.modules.identity_tracking.correlation import CrossModuleCorrelator
from src.modules.sources import discover_sources

logger = logging.getLogger(__name__)

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
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Run each requested source adapter.

    Returns ``(results, errors)``: ``results`` maps module_name → ScanResult
    dump for sources that succeeded; ``errors`` maps module_name → reason for
    sources that failed init or returned no result (blocked/empty/errored),
    so callers see per-source failures instead of silent drops.
    """
    sources_map = discover_sources()
    if source_filter:
        requested = [s for s in source_filter if s in SOURCE_MODULES and s in sources_map]
        unknown = [s for s in source_filter if s not in SOURCE_MODULES]
        if unknown:
            logger.warning("Skipping unknown/non-adapter sources: %s", unknown)
    else:
        requested = sorted(SOURCE_MODULES & set(sources_map))

    results: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    for source_name in requested:
        try:
            source_inst = sources_map[source_name]()
        except Exception as exc:
            logger.debug("Source %s init failed: %s", source_name, exc)
            errors[source_name] = f"init failed: {exc}"
            continue
        scan_result = await run_source_scan(
            source_name,
            target,
            source_inst,
            requester=requester,
            requester_tier=requester_tier,
        )
        if scan_result is None:
            # The adapter returns None for blocked (consent/RBAC/ToS),
            # empty, or errored scans — surface instead of dropping.
            errors[source_name] = "skipped: blocked by RBAC/consent/ToS, empty result, or source error"
            continue
        results[source_name] = scan_result.model_dump(mode="json")
    return results, errors


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
        investigation_id=f"mcp-{target[:32]}-{uuid.uuid4().hex[:8]}",
    )
    module_results: dict[str, ScanResult] = {}
    for name, dumped in results.items():
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
    requester_tier: str = "readonly",
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
        {"target": ..., "sources": {name: ScanResult}, "correlation": {...},
         "errors": {name: reason for sources that failed or were skipped}}
    """
    tier = AccessTier.from_str(requester_tier)
    results, errors = await _run_sources(target, source_filter, requester="mcp", requester_tier=tier)
    correlation = _correlate_results(results, target)
    return {
        "target": target,
        "sources": results,
        "correlation": correlation,
        "errors": errors,
    }


def _source_catalog() -> list[dict[str, Any]]:
    """Available adapter sources with compliance metadata (shared by tool/resource)."""
    sources_map = discover_sources()
    available = sorted(SOURCE_MODULES & set(sources_map))
    return [
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


@server.tool()
async def list_sources() -> dict[str, Any]:
    """List breach/leak sources with compliance metadata (legal basis, retention)."""
    return {"sources": _source_catalog()}


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


# ── Resources ─────────────────────────────────────────────────────────────────


@server.resource("osint://sources")
async def sources_resource() -> str:
    """JSON catalog of available breach/leak sources and their compliance metadata."""
    return json.dumps({"sources": _source_catalog()}, indent=2)


# ── Prompts ───────────────────────────────────────────────────────────────────


@server.prompt()
async def investigate(
    target: str,
    source_filter: str | None = None,
) -> list[dict[str, str | dict[str, str]]]:
    """Build a guided multi-source OSINT investigation plan for a target.

    Args:
        target: Search target (email, username, phone, or domain).
        source_filter: Comma-separated subset of sources to query (dehashed,
            leakcheck, snylla, snusbase, hibp, intelx). Defaults to all.

    Returns:
        Assistant briefing + user prompt that references the MCP tools.
    """
    sources = _source_catalog()
    names = [s["name"] for s in sources]
    chosen = [s.strip() for s in (source_filter or "").split(",") if s.strip()] or names
    unknown = sorted(set(chosen) - set(names))
    plan = (
        f"Investigation plan for target `{target}`:\n"
        f"- Sources to query: {', '.join(chosen) or 'none'}\n"
        f"- Available sources: {', '.join(names)}\n"
        "- Step 1: call `search` to run the breach/leak sources and get cross-source correlation.\n"
        "- Step 2: call `source_compliance` for any source whose legal basis or retention needs review.\n"
        "- Step 3: call `list_sources` (or read resource `osint://sources`) to refresh the source catalog.\n"
        f"- RBAC: sources gated above the caller's tier are skipped; default tier is `readonly`.\n"
    )
    if unknown:
        plan += f"- Note: unknown/unsupported sources ignored: {', '.join(unknown)}\n"
    return [
        {
            "role": "assistant",
            "content": {
                "type": "text",
                "text": "I have prepared a step-by-step investigation plan for the target. "
                "Use the 1ai-osint MCP tools to execute it.",
            },
        },
        {"role": "user", "content": {"type": "text", "text": plan}},
    ]


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (default for Claude Code / Desktop)."""
    logging.basicConfig(level=logging.WARNING)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
