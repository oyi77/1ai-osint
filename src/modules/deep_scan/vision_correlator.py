import os
import json
import logging
import httpx
from typing import Dict, Any

logger = logging.getLogger(__name__)


class VisionCorrelator:
    def __init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.omniroute_api_key = os.getenv("OMNIROUTE_API_KEY")

    def _calculate_jaccard_similarity(self, text1: str, text2: str) -> float:
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
        self, profile_a: Dict[str, Any], profile_b: Dict[str, Any]
    ) -> float:
        api_key = self.openai_api_key or self.omniroute_api_key

        text_a = profile_a.get("text_content", "")
        url_a = profile_a.get("profile_picture_url")

        text_b = profile_b.get("text_content", "")
        url_b = profile_b.get("profile_picture_url")

        if api_key:
            try:
                return await self._correlate_with_llm(
                    api_key, text_a, url_a, text_b, url_b
                )
            except Exception as e:
                logger.warning(
                    f"LLM correlation failed: {e}. Falling back to deterministic."
                )

        # Deterministic fallback
        target_name = text_a.lower().replace("full name:", "").strip()
        target_words = [w for w in target_name.split() if len(w) > 2]
        if target_words and all(w in text_b.lower() for w in target_words):
            return 0.7
        similarity = self._calculate_jaccard_similarity(text_a, text_b)
        return 0.6 if similarity > 0.3 else 0.2

    async def _correlate_with_llm(
        self, api_key: str, text_a: str, url_a: str, text_b: str, url_b: str
    ) -> float:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        api_url = "https://api.openai.com/v1/chat/completions"

        content = [
            {
                "type": "text",
                "text": (
                    "Please analyze these two profiles and determine if they belong to the same person. "
                    'Return only JSON in the format {"confidence": 0.0-1.0, "reasoning": "..."}.\n'
                    f"Profile A Text: {text_a}\n"
                    f"Profile B Text: {text_b}"
                ),
            }
        ]

        if url_a:
            content.append({"type": "image_url", "image_url": {"url": url_a}})

        if url_b:
            content.append({"type": "image_url", "image_url": {"url": url_b}})

        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": content}],
            "response_format": {"type": "json_object"},
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                api_url, headers=headers, json=payload, timeout=30.0
            )
            response.raise_for_status()

            data = response.json()
            result_text = data["choices"][0]["message"]["content"]
            result_json = json.loads(result_text)
            return float(result_json.get("confidence", 0.0))
