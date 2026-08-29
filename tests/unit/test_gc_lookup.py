"""Tests for the gc-lookup module (GetContact CLI wrapper)."""

from pathlib import Path

import pytest

from src.modules.phone_finder.gc_lookup import GCLookupTool


@pytest.fixture
def fake_binary(tmp_path: Path) -> str:
    """Create a fake gc-lookup binary that returns canned JSON."""
    script = tmp_path / "fake-gc-lookup"
    script.write_text(
        """\
#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
if args[1:3] == ["--source", "profile"] and args[-1] == "+628123456789":
    json.dump({"name": "Test User", "phone": "+628123456789"}, sys.stdout)
    sys.exit(0)
elif args[1:3] == ["--source", "tags"] and args[-1] == "+628123456789":
    json.dump([{"name": "telegram", "value": "tguser"}], sys.stdout)
    sys.exit(0)
elif args == ["search", "--source", "profile", "+628111111111"]:
    json.dump({}, sys.stdout)  # empty profile
    sys.exit(0)
elif args == ["search", "--source", "tags", "+628111111111"]:
    sys.stdout.write("")  # no output
    sys.exit(0)
elif args == ["search", "--source", "profile", "+628222222222"]:
    # non-zero exit on profile
    sys.stderr.write("credential expired")
    sys.exit(1)
else:
    sys.stderr.write(f"unexpected: {args}")
    sys.exit(1)
""",
    )
    script.chmod(0o755)
    return str(script)


@pytest.fixture
def missing_binary(tmp_path: Path) -> str:
    return str(tmp_path / "nonexistent")


@pytest.fixture
def tool(fake_binary: str) -> GCLookupTool:
    return GCLookupTool(binary=fake_binary)


class TestGCLookupTool:
    async def test_module_name(self, tool: GCLookupTool):
        assert tool.name == "gc_lookup"
        assert tool.description.startswith("GetContact")

    async def test_non_phone_returns_partial(self, tool: GCLookupTool):
        result = await tool.search("not-a-phone")
        assert result.status == "partial"
        assert len(result.findings) == 0
        assert "not a valid phone number" in (result.metadata.get("note") or "")

    async def test_binary_not_found(self, missing_binary: str):
        tool = GCLookupTool(binary=missing_binary)
        result = await tool.search("+628123456789")
        assert result.status == "error"
        assert "binary not found" in (result.error or "")

    async def test_profile_and_tags(self, tool: GCLookupTool):
        result = await tool.search("+628123456789")
        assert result.status == "ok"
        assert len(result.findings) == 2
        titles = [f.title for f in result.findings]
        assert "GetContact profile" in titles
        assert "GetContact tags" in titles
        profile_finding = [f for f in result.findings if f.title == "GetContact profile"][0]
        assert profile_finding.raw_data.get("name") == "Test User"
        tags_finding = [f for f in result.findings if f.title == "GetContact tags"][0]
        assert "telegram" in str(tags_finding.raw_data)

    async def test_empty_profile_no_tags(self, tool: GCLookupTool):
        result = await tool.search("+628111111111")
        assert result.status == "partial"
        assert len(result.findings) == 0

    async def test_profile_error(self, tool: GCLookupTool):
        result = await tool.search("+628222222222")
        assert result.status == "error"
        assert "credential expired" in (result.error or "")

    async def test_scan_alias(self, tool: GCLookupTool):
        result = await tool.scan("+628123456789")
        assert result.status == "ok"
        assert len(result.findings) == 2

    async def test_rotate_passes_flag(self, tool: GCLookupTool):
        """rotate=True should pass --rotate to the binary."""
        rotate_tool = GCLookupTool(binary=tool.binary, rotate=True)
        result = await rotate_tool.search("+628123456789")
        assert result.status == "ok"
        assert len(result.findings) == 2
        profile = [f for f in result.findings if f.title == "GetContact profile"][0]
        assert profile.raw_data.get("name") == "Test User"

    async def test_rotate_true_with_non_phone(self, tool: GCLookupTool):
        rotate_tool = GCLookupTool(binary=tool.binary, rotate=True)
        result = await rotate_tool.search("not-a-phone")
        assert result.status == "partial"
        assert "not a valid phone number" in (result.metadata.get("note") or "")

    async def test_analyze_and_learn(self, tool: GCLookupTool):
        analysis = await tool.analyze({})
        assert "gc_lookup" in analysis.get("modules", [])
        # learn should not raise
        await tool.learn({})
