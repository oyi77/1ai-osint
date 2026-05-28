"""Tests for entity extractor module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.ai.analyzers.entity_extractor import EntityExtractor
from src.ai.schemas.responses import EntityExtractionResult, EntityType


@pytest.fixture
def mock_client():
    """Provide a mocked OmniRouteClient."""
    return MagicMock()


@pytest.fixture
def extractor(mock_client):
    """Provide an EntityExtractor with mocked client."""
    return EntityExtractor(client=mock_client)


class TestEntityExtractor:
    def test_extract_empty_input(self, extractor):
        result = extractor.extract("")
        assert result.entities == []
        assert "Empty input" in result.summary

    def test_extract_whitespace_input(self, extractor):
        result = extractor.extract("   ")
        assert result.entities == []
        assert "Empty input" in result.summary

    def test_extract_valid_response(self, extractor, mock_client):
        response = json.dumps({
            "entities": [
                {
                    "entity_type": "email",
                    "value": "john@example.com",
                    "confidence": 0.95,
                    "context": "Contact: john@example.com"
                },
                {
                    "entity_type": "phone",
                    "value": "+1234567890",
                    "confidence": 0.8,
                    "context": "Phone: +1234567890"
                }
            ],
            "summary": "Found email and phone"
        })
        mock_client.extract_entities.return_value = response

        result = extractor.extract("Contact: john@example.com, Phone: +1234567890")

        assert len(result.entities) == 2
        assert result.entities[0].entity_type == EntityType.EMAIL
        assert result.entities[0].value == "john@example.com"
        assert result.entities[1].entity_type == EntityType.PHONE
        assert result.summary == "Found email and phone"

    def test_extract_invalid_json(self, extractor, mock_client):
        mock_client.extract_entities.return_value = "not valid json"

        result = extractor.extract("some text")

        assert result.entities == []
        assert "Invalid JSON" in result.summary

    def test_extract_api_error(self, extractor, mock_client):
        mock_client.extract_entities.side_effect = Exception("API error")

        result = extractor.extract("some text")

        assert result.entities == []
        assert "failed" in result.summary.lower()

    def test_extract_unknown_entity_type(self, extractor, mock_client):
        response = json.dumps({
            "entities": [
                {"entity_type": "unknown_type", "value": "test", "confidence": 0.5}
            ],
            "summary": ""
        })
        mock_client.extract_entities.return_value = response

        result = extractor.extract("test")

        assert len(result.entities) == 1
        assert result.entities[0].entity_type == EntityType.OTHER

    def test_extract_from_findings(self, extractor, mock_client):
        response = json.dumps({
            "entities": [
                {"entity_type": "email", "value": "test@example.com", "confidence": 0.9}
            ],
            "summary": "Found email"
        })
        mock_client.extract_entities.return_value = response

        findings = [
            {"title": "Leak found", "description": "Email: test@example.com", "raw_data": {"email": "test@example.com"}},
            {"title": "Another leak", "description": "Same email", "raw_data": {"email": "test@example.com"}},
        ]

        result = extractor.extract_from_findings(findings)

        assert len(result.entities) == 1  # deduplicated
        assert result.entities[0].value == "test@example.com"

    def test_extract_from_findings_empty(self, extractor):
        result = extractor.extract_from_findings([])
        assert result.entities == []
        assert "0 unique entities" in result.summary

    def test_finding_to_text(self):
        finding = {
            "title": "Test Finding",
            "description": "Found something",
            "raw_data": {"email": "test@example.com", "count": 5}
        }
        text = EntityExtractor._finding_to_text(finding)

        assert "Title: Test Finding" in text
        assert "Description: Found something" in text
        assert "email: test@example.com" in text
