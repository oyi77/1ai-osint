"""Profile correlation using vision + text analysis via OmniRoute.

Rewritten to use OmniRouteClient instead of hardcoded OpenAI endpoint.
Keeps Jaccard similarity fallback and image URL passing for multimodal models.
"""

import json
import logging
from typing import Any

from src.ai.omniroute_client import OmniRouteClient

logger = logging.getLogger(__name__)

_PROFILE_CORRELATION_SYSTEM_PROMPT = (
    "You are an OSINT profile correlation specialist. "
    "Analyze these two profiles and determine the likelihood they belong to the same person. "
    'Return only valid JSON in the format {"confidence": 0.0-1.0, "reasoning": "..."}.'
)


class VisionCorrelator:
    """Correlate profiles using text analysis and optional image comparison.

    Uses OmniRouteClient for LLM calls with automatic retry + fallback.
    Falls back to Jaccard similarity when LLM is unavailable.
    """

    def __init__(self, client: OmniRouteClient | None = None):
        self._client = client or OmniRouteClient()

    @staticmethod
    def _calculate_jaccard_similarity(text1: str, text2: str) -> float:
        """Calculate Jaccard similarity between two text strings."""
        if not text1 and not text2:
            return 0.0
        set1 = set(text1.lower().split())
        set2 = set(text2.lower().split())
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        if not union:
            return 0.0
        return len(intersection) / len(union)

    async def correlate_profiles(
        self,
        profile_a: dict[str, Any],
        profile_b: dict[str, Any],
    ) -> float:
        """Correlate two profiles, returning a confidence score 0.0-1.0.

        Uses OmniRouteClient async multimodal for LLM analysis, with
        deterministic fallback (Jaccard similarity + name matching).

        Args:
            profile_a: First profile dict with 'text_content' and optional
                       'profile_picture_url'.
            profile_b: Second profile dict with 'text_content' and optional
                       'profile_picture_url'.

        Returns:
            Float confidence score between 0.0 and 1.0.

        """
        text_a = profile_a.get("text_content", "")
        text_b = profile_b.get("text_content", "")
        url_a = profile_a.get("profile_picture_url")
        url_b = profile_b.get("profile_picture_url")

        # Try LLM-based correlation
        try:
            image_urls: list[str] = []
            if url_a:
                image_urls.append(url_a)
            if url_b:
                image_urls.append(url_b)

            content_text = (
                "Please analyze these two profiles and determine if "
                "they belong to the same person.\n"
                f"Profile A Text: {text_a}\n"
                f"Profile B Text: {text_b}"
            )

            raw_response = await self._client.async_chat_multimodal(
                text_content=content_text,
                system_prompt=_PROFILE_CORRELATION_SYSTEM_PROMPT,
                image_urls=image_urls or None,
            )

            result = json.loads(raw_response)
            return float(result.get("confidence", 0.0))
        except Exception as e:
            logger.warning("LLM profile correlation failed: %s. Falling back.", e)

        # Deterministic fallback
        target_name = text_a.lower().replace("full name:", "").strip()
        target_words = [w for w in target_name.split() if len(w) > 2]
        if target_words and all(w in text_b.lower() for w in target_words):
            return 0.7

        similarity = self._calculate_jaccard_similarity(text_a, text_b)
        return 0.6 if similarity > 0.3 else 0.2
