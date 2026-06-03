"""Tests for correlation engine module."""

import json
from unittest.mock import MagicMock

import pytest

from src.ai.analyzers.correlation_engine import CorrelationEngine
from src.ai.schemas.responses import EntityExtractionResult, EntityType, ExtractedEntity


@pytest.fixture
def mock_client():
    """Provide a mocked OmniRouteClient."""
    return MagicMock()


@pytest.fixture
def engine(mock_client):
    """Provide a CorrelationEngine with mocked client."""
    return CorrelationEngine(client=mock_client)


@pytest.fixture
def sample_extraction():
    """Provide a sample EntityExtractionResult."""
    return EntityExtractionResult(
        entities=[
            ExtractedEntity(
                entity_type=EntityType.EMAIL,
                value="john@example.com",
                confidence=0.9,
                context="test",
            ),
            ExtractedEntity(
                entity_type=EntityType.USERNAME,
                value="johndoe",
                confidence=0.8,
                context="test",
            ),
            ExtractedEntity(
                entity_type=EntityType.EMAIL,
                value="john.doe@work.com",
                confidence=0.7,
                context="test",
            ),
        ],
        summary="Found 3 entities",
    )


class TestCorrelationEngine:
    def test_correlate_empty(self, engine):
        result = engine.correlate(EntityExtractionResult(entities=[]))
        assert result.summary == "No entities to correlate"

    def test_correlate_valid_response(self, engine, mock_client, sample_extraction):
        response = json.dumps(
            {
                "correlated_groups": [
                    {
                        "entities": ["john@example.com", "johndoe"],
                        "confidence": 0.9,
                        "reasoning": "Same name pattern",
                    }
                ],
                "relationships": [
                    {
                        "from_entity": "john@example.com",
                        "to_entity": "johndoe",
                        "relationship_type": "same_person",
                        "confidence": 0.9,
                    }
                ],
                "summary": "Found 1 group",
            }
        )
        mock_client.chat.return_value = response

        result = engine.correlate(sample_extraction)

        assert len(result.correlated_groups) == 1
        assert len(result.relationships) == 1
        assert result.summary == "Found 1 group"

    def test_correlate_invalid_json(self, engine, mock_client, sample_extraction):
        mock_client.chat.return_value = "not json"

        result = engine.correlate(sample_extraction)

        assert result.summary == "Invalid JSON response"

    def test_correlate_api_error(self, engine, mock_client, sample_extraction):
        mock_client.chat.side_effect = Exception("API down")

        result = engine.correlate(sample_extraction)

        assert "failed" in result.summary.lower()

    def test_correlate_cross_module(self, engine, mock_client):
        response = json.dumps(
            {"correlated_groups": [], "relationships": [], "summary": "No correlations"}
        )
        mock_client.chat.return_value = response

        module_results = {
            "leaks": EntityExtractionResult(
                entities=[
                    ExtractedEntity(
                        entity_type=EntityType.EMAIL, value="a@b.com", confidence=0.9
                    )
                ]
            ),
            "people": EntityExtractionResult(
                entities=[
                    ExtractedEntity(
                        entity_type=EntityType.NAME, value="John", confidence=0.8
                    )
                ]
            ),
        }

        result = engine.correlate_cross_module(module_results)
        assert result.summary == "No correlations"

    def test_correlate_cross_module_empty(self, engine):
        result = engine.correlate_cross_module({})
        assert result.summary == "No entities to correlate"

    def test_find_shared_attributes(self, engine):
        entities = [
            ExtractedEntity(
                entity_type=EntityType.EMAIL, value="test@example.com", confidence=0.9
            ),
            ExtractedEntity(
                entity_type=EntityType.EMAIL, value="TEST@EXAMPLE.COM", confidence=0.8
            ),
            ExtractedEntity(
                entity_type=EntityType.EMAIL, value="other@example.com", confidence=0.7
            ),
        ]

        shared = engine.find_shared_attributes(entities)

        # test@example.com and TEST@EXAMPLE.COM should be grouped
        key = "email:test@example.com"
        assert key in shared
        assert len(shared[key]) == 2

    def test_find_shared_attributes_none_shared(self, engine):
        entities = [
            ExtractedEntity(
                entity_type=EntityType.EMAIL, value="a@b.com", confidence=0.9
            ),
            ExtractedEntity(
                entity_type=EntityType.EMAIL, value="c@d.com", confidence=0.8
            ),
        ]

        shared = engine.find_shared_attributes(entities)
        assert len(shared) == 0
