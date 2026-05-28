"""Cross-module entity linking and correlation engine."""

import json
import logging
from typing import Any, Optional

from src.ai.omniroute_client import OmniRouteClient
from src.ai.schemas.responses import (
    CorrelationResult,
    EntityExtractionResult,
    ExtractedEntity,
    EntityType,
)

logger = logging.getLogger(__name__)

_CORRELATION_PROMPT = """You are an OSINT identity correlation specialist.
Given a list of extracted entities from multiple sources, identify which entities
likely refer to the same real-world person or organization.

Group entities by likely identity. For each group, provide:
- The entity values that belong together
- A confidence score (0.0 to 1.0)
- A brief explanation of why they are correlated

Common correlation indicators:
- Same email domain + same username pattern
- Same phone number appearing with different names
- Matching physical addresses
- Consistent naming conventions across sources
- Same organization appearing with different contacts

Respond in JSON format:
{
    "correlated_groups": [
        {
            "entities": ["entity1", "entity2", ...],
            "confidence": 0.85,
            "reasoning": "These entities share..."
        }
    ],
    "relationships": [
        {
            "from_entity": "entity1",
            "to_entity": "entity2",
            "relationship_type": "same_person|associated|colleague|family",
            "confidence": 0.8
        }
    ],
    "summary": "Brief summary of correlations found"
}
"""


class CorrelationEngine:
    """Link and correlate entities across multiple OSINT modules."""

    def __init__(self, client: Optional[OmniRouteClient] = None):
        self._client = client or OmniRouteClient()

    def correlate(self, extraction_result: EntityExtractionResult) -> CorrelationResult:
        """
        Correlate entities from an extraction result.

        Args:
            extraction_result: Result from EntityExtractor.
        Returns:
            CorrelationResult with grouped entities and relationships.
        """
        if not extraction_result.entities:
            return CorrelationResult(summary="No entities to correlate")

        entities_text = self._format_entities(extraction_result.entities)
        return self._call_llm(entities_text)

    def correlate_cross_module(
        self, module_results: dict[str, EntityExtractionResult]
    ) -> CorrelationResult:
        """
        Correlate entities across multiple module extraction results.

        Args:
            module_results: Dict mapping module name to its EntityExtractionResult.
        Returns:
            Aggregated CorrelationResult.
        """
        all_entities: list[ExtractedEntity] = []
        for module_name, result in module_results.items():
            for entity in result.entities:
                all_entities.append(entity)

        if not all_entities:
            return CorrelationResult(summary="No entities to correlate")

        entities_text = self._format_entities(all_entities)
        return self._call_llm(entities_text)

    def find_shared_attributes(
        self, entities: list[ExtractedEntity]
    ) -> dict[str, list[ExtractedEntity]]:
        """
        Group entities by shared attribute values (deterministic, no LLM).

        Args:
            entities: List of extracted entities.
        Returns:
            Dict mapping normalized values to entities sharing that value.
        """
        value_map: dict[str, list[ExtractedEntity]] = {}
        for entity in entities:
            key = f"{entity.entity_type.value}:{entity.value.lower()}"
            value_map.setdefault(key, []).append(entity)
        return {k: v for k, v in value_map.items() if len(v) > 1}

    def _format_entities(self, entities: list[ExtractedEntity]) -> str:
        """Format entities into a text block for the LLM."""
        lines: list[str] = []
        for i, entity in enumerate(entities, 1):
            lines.append(
                f"{i}. [{entity.entity_type.value}] {entity.value} "
                f"(confidence: {entity.confidence:.2f}, context: {entity.context[:100]})"
            )
        return "\n".join(lines)

    def _call_llm(self, entities_text: str) -> CorrelationResult:
        """Call LLM for correlation analysis."""
        try:
            messages = [
                {"role": "system", "content": _CORRELATION_PROMPT},
                {"role": "user", "content": entities_text},
            ]
            raw_response = self._client.chat(messages)
            return self._parse_response(raw_response)
        except Exception as e:
            logger.error("Correlation analysis failed: %s", e)
            return CorrelationResult(
                summary=f"Correlation failed: {e}",
            )

    def _parse_response(self, raw_response: str) -> CorrelationResult:
        """Parse LLM JSON response into CorrelationResult."""
        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError:
            logger.warning("Failed to parse correlation response as JSON")
            return CorrelationResult(summary="Invalid JSON response")

        groups: list[list[str]] = []
        for group in data.get("correlated_groups", []):
            if isinstance(group, dict):
                entities = group.get("entities", [])
                groups.append(entities)
            elif isinstance(group, list):
                groups.append(group)

        return CorrelationResult(
            correlated_groups=groups,
            relationships=data.get("relationships", []),
            summary=data.get("summary", ""),
        )
