"""LLM-based entity extraction from OSINT data."""

import json
import logging
from typing import Any

from src.ai.omniroute_client import OmniRouteClient
from src.ai.schemas.responses import EntityExtractionResult, EntityType, ExtractedEntity

logger = logging.getLogger(__name__)


class EntityExtractor:
    """Extract entities from raw OSINT text using LLM-based analysis."""

    def __init__(self, client: OmniRouteClient | None = None):
        self._client = client or OmniRouteClient()

    def extract(self, text: str) -> EntityExtractionResult:
        """Extract entities from raw OSINT text.

        Args:
            text: Raw text to extract entities from.

        Returns:
            EntityExtractionResult with extracted entities.

        """
        if not text or not text.strip():
            return EntityExtractionResult(entities=[], summary="Empty input")

        try:
            raw_response = self._client.extract_entities(text)
            return self._parse_response(raw_response)
        except Exception as e:
            logger.error("Entity extraction failed: %s", e)
            return EntityExtractionResult(
                entities=[],
                summary=f"Extraction failed: {e}",
                raw_response="",
            )

    def extract_from_findings(self, findings: list[dict[str, Any]]) -> EntityExtractionResult:
        """Extract entities from a list of finding dicts (batch mode).

        Args:
            findings: List of finding dictionaries with 'title', 'description', 'raw_data'.

        Returns:
            Aggregated EntityExtractionResult.

        """
        all_entities: list[ExtractedEntity] = []
        summaries: list[str] = []

        for finding in findings:
            text = self._finding_to_text(finding)
            if text:
                result = self.extract(text)
                all_entities.extend(result.entities)
                if result.summary:
                    summaries.append(result.summary)

        # Deduplicate by (type, value)
        seen: set[tuple[str, str]] = set()
        deduped: list[ExtractedEntity] = []
        for entity in all_entities:
            key = (entity.entity_type.value, entity.value.lower())
            if key not in seen:
                seen.add(key)
                deduped.append(entity)

        return EntityExtractionResult(
            entities=deduped,
            summary=f"Extracted {len(deduped)} unique entities from {len(findings)} findings",
            raw_response="",
        )

    def _parse_response(self, raw_response: str) -> EntityExtractionResult:
        """Parse LLM JSON response into EntityExtractionResult."""
        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError:
            logger.warning("Failed to parse entity extraction response as JSON")
            return EntityExtractionResult(
                entities=[],
                summary="Invalid JSON response",
                raw_response=raw_response,
            )

        entities: list[ExtractedEntity] = []
        for item in data.get("entities", []):
            try:
                entity_type = EntityType(item.get("entity_type", "other"))
            except ValueError:
                entity_type = EntityType.OTHER

            entities.append(
                ExtractedEntity(
                    entity_type=entity_type,
                    value=str(item.get("value", "")),
                    confidence=self._parse_confidence(item.get("confidence")),
                    context=str(item.get("context", "")),
                )
            )

        return EntityExtractionResult(
            entities=entities,
            summary=data.get("summary", ""),
            raw_response=raw_response,
        )

    @staticmethod
    def _parse_confidence(value: Any) -> float:
        """Parse an LLM-supplied confidence value into a clamped float.

        LLM responses are not guaranteed to return a numeric confidence
        (e.g. "high", "0.85/1.0", null). A malformed value must not abort
        the whole extraction — it degrades to the default 0.5 instead.
        """
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.5
        return min(1.0, max(0.0, confidence))

    @staticmethod
    def _finding_to_text(finding: dict[str, Any]) -> str:
        """Convert a finding dict to text for entity extraction."""
        parts: list[str] = []
        if finding.get("title"):
            parts.append(f"Title: {finding['title']}")
        if finding.get("description"):
            parts.append(f"Description: {finding['description']}")
        raw = finding.get("raw_data", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                if value and isinstance(value, (str, int, float)):
                    parts.append(f"{key}: {value}")
        return "\n".join(parts)
