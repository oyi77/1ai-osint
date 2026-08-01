"""Tests for the MCP bridge server (blueprint Phase 1 — S3).

Uses in-process memory streams (no network, no stdio subprocess) to
drive a real MCP handshake: initialize → list tools → call tools.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import anyio
import pytest
from mcp import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

import src.mcp_bridge.server as mcp_server


@pytest.mark.asyncio
async def test_tools_are_registered():
    """The three expected tools are registered on the FastMCP server."""
    from mcp.server.fastmcp.utilities.func_metadata import func_metadata  # noqa: F401

    tool_names = list(mcp_server.server._tool_manager._tools.keys())  # noqa: SLF001
    assert {"search", "list_sources", "source_compliance"} <= set(tool_names)


async def _run_server_in_background(streams):
    """Run the FastMCP server over the server-side memory streams."""
    read, write = streams
    await mcp_server.server._mcp_server.run(  # noqa: SLF001
        read,
        write,
        mcp_server.server._mcp_server.create_initialization_options(),  # noqa: SLF001
        raise_exceptions=True,
    )


@pytest.mark.asyncio
async def test_full_mcp_handshake_and_list_sources():
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                init = await session.initialize()
                assert init.serverInfo.name == "1ai-osint"

                tools = await session.list_tools()
                tool_names = [t.name for t in tools.tools]
                assert {"search", "list_sources", "source_compliance"} <= set(tool_names)

                # list_sources tool call
                result = await session.call_tool("list_sources", {})
                payload = json.loads(result.content[0].text)
                assert "sources" in payload
                assert any(s["name"] == "hibp" for s in payload["sources"])
                assert all("legal_basis" in s for s in payload["sources"])

            tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_source_compliance_tool():
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()
                result = await session.call_tool("source_compliance", {"source": "hibp"})
                payload = json.loads(result.content[0].text)
                assert payload["legal_basis"] == "public_api_tos"
                assert payload["requires_consent"] is False

            tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_search_tool_with_mocked_sources():
    """search() returns per-source results and correlation output."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()

                with (
                    patch("src.mcp_bridge.server.run_source_scan", new=AsyncMock(return_value=None)),
                    patch("src.mcp_bridge.server.discover_sources", return_value={"hibp": object}),
                ):
                    result = await session.call_tool(
                        "search",
                        {"target": "a@b.com", "source_filter": ["hibp"]},
                    )
                    payload = json.loads(result.content[0].text)
                    assert payload["target"] == "a@b.com"
                    assert "sources" in payload
                    assert "correlation" in payload


@pytest.mark.asyncio
async def test_search_tool_correlation_uses_real_correlator():
    """A real scan result flows into ZKIT correlation (no mocking of correlate)."""
    from src.core.models import Finding, ScanResult, Severity

    scan = ScanResult(
        scan_id="source-hibp-1",
        module="source_hibp",
        target="a@b.com",
        findings=[
            Finding(
                id="find-1",
                module="source_hibp",
                title="t",
                severity=Severity.INFO,
                raw_data={"email": "a@b.com"},
            )
        ],
    )

    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()

                with (
                    patch(
                        "src.mcp_bridge.server.run_source_scan",
                        new=AsyncMock(return_value=scan),
                    ),
                    patch("src.mcp_bridge.server.discover_sources", return_value={"hibp": object}),
                ):
                    result = await session.call_tool(
                        "search",
                        {"target": "a@b.com", "source_filter": ["hibp"]},
                    )
                    payload = json.loads(result.content[0].text)
                    assert payload["sources"]["hibp"]["module"] == "source_hibp"
                    corr = payload["correlation"]
                    assert "graph_stats" in corr
                    assert corr["graph_stats"]["node_count"] >= 1
                    assert "resolved_entities" in corr


@pytest.mark.asyncio
async def test_search_rejects_unknown_source_filter():
    """Unknown sources in filter are skipped without error."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()

                with (
                    patch("src.mcp_bridge.server.run_source_scan", new=AsyncMock(return_value=None)),
                    patch("src.mcp_bridge.server.discover_sources", return_value={"hibp": object}),
                ):
                    result = await session.call_tool(
                        "search",
                        {"target": "x@y.com", "source_filter": ["not_a_source"]},
                    )
                    payload = json.loads(result.content[0].text)
                    assert payload["sources"] == {}
                    assert payload["correlation"]["graph_stats"]["node_count"] == 0


@pytest.mark.asyncio
async def test_sources_resource_registered():
    """osint://sources resource lists the same catalog as the list_sources tool."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()

                resources = await session.list_resources()
                uris = [str(r.uri) for r in resources.resources]
                assert "osint://sources" in uris

                read = await session.read_resource("osint://sources")
                payload = json.loads(read.contents[0].text)
                assert "sources" in payload
                assert any(s["name"] == "hibp" for s in payload["sources"])
                assert all("legal_basis" in s for s in payload["sources"])

            tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_investigate_prompt():
    """investigate prompt returns a guided plan referencing the MCP tools."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as tg:
            tg.start_soon(_run_server_in_background, server_streams)

            client_read, client_write = client_streams
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()

                prompts = await session.list_prompts()
                assert any(p.name == "investigate" for p in prompts.prompts)

                result = await session.get_prompt(
                    "investigate",
                    {"target": "a@b.com", "source_filter": "hibp, nope"},
                )
                texts = [
                    msg.content.text for msg in result.messages if hasattr(msg.content, "text") and msg.content.text
                ]
                joined = "\n".join(texts)
                assert "a@b.com" in joined
                assert "hibp" in joined
                assert "nope" in joined  # flagged as unknown/unsupported
                assert "`search`" in joined
                assert "osint://sources" in joined

            tg.cancel_scope.cancel()
