"""Tests for AI prompt templates and response schemas."""

import pytest
from src.ai.prompts.entity_extraction import ENTITY_EXTRACTION_PROMPT
from src.ai.prompts.false_positive_filter import FALSE_POSITIVE_PROMPT
from src.ai.schemas.responses import (
    EntityType,
    ExtractedEntity,
    EntityExtractionResult,
    FindingAssessment,
    FalsePositiveResult,
    CorrelationResult,
)


class TestEntityExtractionPrompt:
    def test_prompt_is_string(self):
        assert isinstance(ENTITY_EXTRACTION_PROMPT, str)
        assert len(ENTITY_EXTRACTION_PROMPT) > 100

    def test_prompt_mentions_entity_types(self):
        for etype in ["email", "phone", "username", "domain", "ip"]:
            assert etype in ENTITY_EXTRACTION_PROMPT.lower()

    def test_prompt_mentions_json_format(self):
        assert "JSON" in ENTITY_EXTRACTION_PROMPT
        assert "entities" in ENTITY_EXTRACTION_PROMPT


class TestFalsePositivePrompt:
    def test_prompt_is_string(self):
        assert isinstance(FALSE_POSITIVE_PROMPT, str)
        assert len(FALSE_POSITIVE_PROMPT) > 100

    def test_prompt_mentions_false_positive(self):
        assert "false positive" in FALSE_POSITIVE_PROMPT.lower()

    def test_prompt_mentions_json_format(self):
        assert "JSON" in FALSE_POSITIVE_PROMPT
        assert "assessments" in FALSE_POSITIVE_PROMPT


class TestEntityType:
    def test_all_values(self):
        assert EntityType.EMAIL == "email"
        assert EntityType.PHONE == "phone"
        assert EntityType.USERNAME == "username"
        assert EntityType.DOMAIN == "domain"
        assert EntityType.IP == "ip"
        assert EntityType.HASH == "hash"
        assert len(EntityType) == 13


class TestExtractedEntity:
    def test_create(self):
        entity = ExtractedEntity(entity_type=EntityType.EMAIL, value="test@example.com", confidence=0.9)
        assert entity.entity_type == EntityType.EMAIL
        assert entity.value == "test@example.com"
        assert entity.confidence == 0.9
        assert entity.context == ""

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            ExtractedEntity(entity_type=EntityType.EMAIL, value="x", confidence=1.5)


class TestEntityExtractionResult:
    def test_create_empty(self):
        result = EntityExtractionResult()
        assert result.entities == []
        assert result.summary == ""

    def test_create_with_entities(self):
        entity = ExtractedEntity(entity_type=EntityType.EMAIL, value="a@b.com")
        result = EntityExtractionResult(entities=[entity], summary="Found 1 entity")
        assert len(result.entities) == 1


class TestFindingAssessment:
    def test_create(self):
        fa = FindingAssessment(finding_id="f1", is_false_positive=True, confidence=0.95, reasoning="test data")
        assert fa.finding_id == "f1"
        assert fa.is_false_positive is True
        assert fa.adjusted_severity is None


class TestFalsePositiveResult:
    def test_create(self):
        fpr = FalsePositiveResult(assessments=[], summary="No findings")
        assert fpr.assessments == []
        assert fpr.summary == "No findings"


class TestCorrelationResult:
    def test_create(self):
        cr = CorrelationResult(
            correlated_groups=[["hash1", "hash2"]],
            relationships=[{"from": "hash1", "to": "hash2", "type": "same_person"}],
            summary="Found 1 group",
        )
        assert len(cr.correlated_groups) == 1
        assert len(cr.relationships) == 1


class TestBaseOSINTTool:
    def test_hash_identity(self):
        from src.modules.base.base import BaseOSINTTool

        class ConcreteTool(BaseOSINTTool):
            name = "test"
            async def search(self, query, **kwargs): pass
            async def scan(self, target, **kwargs): pass
            async def analyze(self, data, **kwargs): pass
            async def learn(self, feedback, **kwargs): pass

        tool = ConcreteTool(zkit_salt="test-salt")
        h1 = tool.hash_identity("test@example.com")
        h2 = tool.hash_identity("test@example.com")
        assert h1 == h2
        assert len(h1) == 64

    def test_to_zkit_node(self):
        from src.modules.base.base import BaseOSINTTool
        from src.models import Finding

        class ConcreteTool(BaseOSINTTool):
            name = "test"
            async def search(self, query, **kwargs): pass
            async def scan(self, target, **kwargs): pass
            async def analyze(self, data, **kwargs): pass
            async def learn(self, feedback, **kwargs): pass

        tool = ConcreteTool(zkit_salt="salt")
        finding = Finding(id="f1", module="test", title="Test", raw_data={"email": "a@b.com"})
        node = tool.to_zkit_node(finding, attribute_type="email")
        assert node.attribute_type == "email"
        assert len(node.zkit_hash) == 64
        assert node.sources == ["test"]

    def test_make_ids(self):
        from src.modules.base.base import BaseOSINTTool

        class ConcreteTool(BaseOSINTTool):
            name = "test"
            async def search(self, query, **kwargs): pass
            async def scan(self, target, **kwargs): pass
            async def analyze(self, data, **kwargs): pass
            async def learn(self, feedback, **kwargs): pass

        tool = ConcreteTool()
        sid1 = tool._make_scan_id()
        sid2 = tool._make_scan_id()
        assert sid1 != sid2
        assert len(sid1) == 36  # UUID format

    def test_repr(self):
        from src.modules.base.base import BaseOSINTTool

        class ConcreteTool(BaseOSINTTool):
            name = "test"
            async def search(self, query, **kwargs): pass
            async def scan(self, target, **kwargs): pass
            async def analyze(self, data, **kwargs): pass
            async def learn(self, feedback, **kwargs): pass

        tool = ConcreteTool()
        assert "ConcreteTool" in repr(tool)
