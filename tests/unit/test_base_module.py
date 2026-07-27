"""Tests for the base module class — BaseOSINTTool and ZKITNode."""

import hashlib
import re
from datetime import datetime

import pytest

from src.core.models import Finding, ScanResult
from src.modules.base.base import BaseOSINTTool, ZKITNode

# --- Concrete subclass for testing abstract base ---


class ConcreteTool(BaseOSINTTool):
    """Minimal concrete implementation for testing the abstract base."""

    name = "concrete"
    description = "test tool"
    version = "0.1.0"

    async def search(self, query: str, **kwargs) -> ScanResult:
        return ScanResult(
            scan_id=self._make_scan_id(),
            module=self.name,
            target=query,
            status="ok",
        )

    async def scan(self, target: str, **kwargs) -> ScanResult:
        return ScanResult(
            scan_id=self._make_scan_id(),
            module=self.name,
            target=target,
            status="ok",
        )

    async def analyze(self, data, **kwargs) -> dict:
        return {"analyzed": True, "data": data}

    async def learn(self, feedback: dict, **kwargs) -> None:
        pass


# --- BaseOSINTTool tests ---


class TestBaseOSINTToolInterface:
    """Test the abstract base class interface."""

    def test_cannot_instantiate_abstract(self):
        """BaseOSINTTool is abstract and cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseOSINTTool()

    def test_concrete_subclass_instantiates(self):
        tool = ConcreteTool()
        assert tool is not None
        assert tool.name == "concrete"

    def test_default_metadata(self):
        tool = ConcreteTool()
        assert tool.name == "concrete"
        assert tool.description == "test tool"
        assert tool.version == "0.1.0"

    def test_default_salt_empty_string(self):
        tool = ConcreteTool()
        assert tool._zkit_salt == ""

    def test_custom_salt(self):
        tool = ConcreteTool(zkit_salt="my-salt")
        assert tool._zkit_salt == "my-salt"


class TestBaseOSINTToolAbstractMethods:
    """Verify abstract methods require implementation."""

    def test_missing_search_raises(self):
        class Incomplete(BaseOSINTTool):
            async def scan(self, target, **kwargs):
                pass

            async def analyze(self, data, **kwargs):
                pass

            async def learn(self, feedback, **kwargs):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_missing_scan_raises(self):
        class Incomplete(BaseOSINTTool):
            async def search(self, query, **kwargs):
                pass

            async def analyze(self, data, **kwargs):
                pass

            async def learn(self, feedback, **kwargs):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_missing_analyze_raises(self):
        class Incomplete(BaseOSINTTool):
            async def search(self, query, **kwargs):
                pass

            async def scan(self, target, **kwargs):
                pass

            async def learn(self, feedback, **kwargs):
                pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_missing_learn_raises(self):
        class Incomplete(BaseOSINTTool):
            async def search(self, query, **kwargs):
                pass

            async def scan(self, target, **kwargs):
                pass

            async def analyze(self, data, **kwargs):
                pass

        with pytest.raises(TypeError):
            Incomplete()


@pytest.mark.asyncio
class TestBaseOSINTToolAsyncMethods:
    """Test async method interface via concrete subclass."""

    async def test_search_returns_scan_result(self):
        tool = ConcreteTool()
        result = await tool.search("test@example.com")
        assert isinstance(result, ScanResult)
        assert result.target == "test@example.com"
        assert result.module == "concrete"
        assert result.status == "ok"

    async def test_scan_returns_scan_result(self):
        tool = ConcreteTool()
        result = await tool.scan("https://example.com")
        assert isinstance(result, ScanResult)
        assert result.target == "https://example.com"

    async def test_analyze_returns_dict(self):
        tool = ConcreteTool()
        result = await tool.analyze({"key": "value"})
        assert isinstance(result, dict)
        assert result["analyzed"] is True

    async def test_learn_returns_none(self):
        tool = ConcreteTool()
        result = await tool.learn({"false_positives": ["f1"]})
        assert result is None


class TestBaseOSINTToolZKITHashing:
    """Test ZKIT identity hashing."""

    def test_hash_identity_deterministic(self):
        tool = ConcreteTool(zkit_salt="test-salt")
        h1 = tool.hash_identity("user@example.com")
        h2 = tool.hash_identity("user@example.com")
        assert h1 == h2

    def test_hash_identity_sha256_length(self):
        tool = ConcreteTool(zkit_salt="salt")
        h = tool.hash_identity("value")
        assert len(h) == 64

    def test_hash_identity_format(self):
        tool = ConcreteTool(zkit_salt="salt")
        h = tool.hash_identity("value")
        assert re.match(r"^[0-9a-f]{64}$", h)

    def test_hash_identity_different_inputs_different_hashes(self):
        tool = ConcreteTool(zkit_salt="salt")
        h1 = tool.hash_identity("user1@example.com")
        h2 = tool.hash_identity("user2@example.com")
        assert h1 != h2

    def test_hash_identity_different_salts_different_hashes(self):
        tool1 = ConcreteTool(zkit_salt="salt-a")
        tool2 = ConcreteTool(zkit_salt="salt-b")
        h1 = tool1.hash_identity("user@example.com")
        h2 = tool2.hash_identity("user@example.com")
        assert h1 != h2

    def test_hash_identity_salt_override(self):
        tool = ConcreteTool(zkit_salt="default-salt")
        h_default = tool.hash_identity("value")
        h_override = tool.hash_identity("value", salt="override-salt")
        assert h_default != h_override

    def test_hash_identity_matches_manual_sha256(self):
        tool = ConcreteTool(zkit_salt="my-salt")
        h = tool.hash_identity("test@example.com")
        expected = hashlib.sha256(b"my-salt:test@example.com").hexdigest()
        assert h == expected

    def test_hash_identity_empty_attribute(self):
        tool = ConcreteTool(zkit_salt="salt")
        h = tool.hash_identity("")
        assert len(h) == 64


class TestBaseOSINTToolZKITNode:
    """Test Finding -> ZKITNode conversion."""

    def test_to_zkit_node_basic(self):
        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(
            id="f1",
            module="mod",
            title="Test",
            raw_data={"email": "user@example.com"},
        )
        node = tool.to_zkit_node(finding, attribute_type="email")
        assert isinstance(node, ZKITNode)
        assert node.attribute_type == "email"
        assert len(node.zkit_hash) == 64
        assert "mod" in node.sources

    def test_to_zkit_node_prefers_email(self):
        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(
            id="f1",
            module="mod",
            title="Test",
            raw_data={"email": "a@b.com", "username": "user"},
        )
        node = tool.to_zkit_node(finding)
        expected_hash = tool.hash_identity("a@b.com")
        assert node.zkit_hash == expected_hash

    def test_to_zkit_node_fallback_to_username(self):
        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(
            id="f1",
            module="mod",
            title="Test",
            raw_data={"username": "someuser"},
        )
        node = tool.to_zkit_node(finding)
        expected_hash = tool.hash_identity("someuser")
        assert node.zkit_hash == expected_hash

    def test_to_zkit_node_fallback_to_title(self):
        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(id="f1", module="mod", title="Fallback Title")
        node = tool.to_zkit_node(finding)
        expected_hash = tool.hash_identity("Fallback Title")
        assert node.zkit_hash == expected_hash

    def test_to_zkit_node_metadata(self):
        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(id="f1", module="mod", title="My Title")
        node = tool.to_zkit_node(finding)
        assert node.metadata["finding_id"] == "f1"
        assert node.metadata["title"] == "My Title"

    def test_to_zkit_node_salt_fingerprint(self):
        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(id="f1", module="mod", title="T")
        node = tool.to_zkit_node(finding)
        assert len(node.salt_fingerprint) == 16
        expected_fp = hashlib.sha256(b"salt").hexdigest()[:16]
        assert node.salt_fingerprint == expected_fp


class TestBaseOSINTToolHelpers:
    """Test helper methods."""

    def test_make_scan_id_returns_uuid(self):
        tool = ConcreteTool()
        sid = tool._make_scan_id()
        assert isinstance(sid, str)
        assert len(sid) == 36  # UUID format
        assert sid.count("-") == 4

    def test_make_finding_id_returns_uuid(self):
        tool = ConcreteTool()
        fid = tool._make_finding_id()
        assert isinstance(fid, str)
        assert len(fid) == 36

    def test_make_scan_id_unique(self):
        tool = ConcreteTool()
        ids = {tool._make_scan_id() for _ in range(10)}
        assert len(ids) == 10

    def test_repr(self):
        tool = ConcreteTool()
        assert repr(tool) == "<ConcreteTool(name='concrete')>"


# --- ZKITNode model tests ---


class TestZKITNode:
    """Test the ZKITNode Pydantic model."""

    def test_create_minimal(self):
        node = ZKITNode(zkit_hash="abc123", attribute_type="email")
        assert node.zkit_hash == "abc123"
        assert node.attribute_type == "email"
        assert node.salt_fingerprint == ""
        assert node.correlation_id is None
        assert node.sources == []
        assert node.metadata == {}

    def test_create_full(self):
        node = ZKITNode(
            zkit_hash="hash123",
            attribute_type="username",
            salt_fingerprint="abcd1234efgh5678",
            correlation_id="corr-1",
            sources=["mod1", "mod2"],
            metadata={"key": "value"},
        )
        assert node.correlation_id == "corr-1"
        assert len(node.sources) == 2
        assert node.metadata["key"] == "value"

    def test_timestamps_default(self):
        node = ZKITNode(zkit_hash="h", attribute_type="t")
        assert isinstance(node.first_seen, datetime)
        assert isinstance(node.last_seen, datetime)
