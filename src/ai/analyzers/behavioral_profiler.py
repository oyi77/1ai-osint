"""Behavioral profiling analyzer for OSINT entities.

Builds behavioral profiles from OSINT data including language pattern analysis,
activity timing patterns, and platform preferences.
"""

import json
import logging
from collections import Counter
from datetime import datetime
from typing import Any

from src.ai.omniroute_client import OmniRouteClient
from src.ai.schemas.responses import (
    ActivityTimes,
    BehavioralAnalysisResult,
    BehavioralProfile,
    LanguageStyle,
)

logger = logging.getLogger(__name__)


class BehavioralProfiler:
    """Build behavioral profiles from OSINT data using AI analysis with deterministic fallback.

    Analyzes language patterns, activity timing, and platform preferences to
    construct a behavioral profile for monitored entities.
    """

    def __init__(self, client: OmniRouteClient | None = None):
        self._client = client or OmniRouteClient()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def analyze_entity(
        self,
        entity_data: list[dict[str, Any]],
        entity_key: str = "default",
    ) -> BehavioralAnalysisResult:
        """Build a behavioral profile from entity text samples.

        Args:
            entity_data: List of dicts with 'text', 'source', 'timestamp' keys.
            entity_key: Identifier for this entity in the result.

        Returns:
            BehavioralAnalysisResult with the profile.

        """
        if not entity_data:
            return BehavioralAnalysisResult(
                profiles={},
                summary="No data to analyze",
            )

        # Try LLM-based analysis first
        try:
            texts = [d.get("text", "") for d in entity_data if d.get("text")]
            combined_text = "\n---\n".join(texts) if texts else ""
            if combined_text:
                return self._llm_analysis(combined_text, entity_key)

            # Fallback to deterministic if no text content
            profile = self._deterministic_profile(entity_data)
            return BehavioralAnalysisResult(
                profiles={entity_key: profile},
                summary=f"Deterministic profile built for {entity_key}",
            )
        except Exception as e:
            logger.warning("LLM behavioral analysis failed: %s. Using deterministic.", e)
            profile = self._deterministic_profile(entity_data)
            return BehavioralAnalysisResult(
                profiles={entity_key: profile},
                summary=f"Deterministic fallback for {entity_key}",
            )

    def analyze_text(self, text: str, entity_key: str = "default") -> BehavioralAnalysisResult:
        """Analyze a single text sample for behavioral patterns.

        Args:
            text: Text content to analyze.
            entity_key: Identifier for this entity.

        Returns:
            BehavioralAnalysisResult.

        """
        if not text or not text.strip():
            return BehavioralAnalysisResult(
                profiles={},
                summary="Empty text provided",
            )

        try:
            return self._llm_analysis(text, entity_key)
        except Exception as e:
            logger.warning("LLM text analysis failed: %s. Using deterministic.", e)
            profile = self._deterministic_from_text(text)
            return BehavioralAnalysisResult(
                profiles={entity_key: profile},
                summary=f"Deterministic text analysis for {entity_key}",
            )

    # ------------------------------------------------------------------ #
    #  LLM-based analysis
    # ------------------------------------------------------------------ #

    def _llm_analysis(self, text: str, entity_key: str) -> BehavioralAnalysisResult:
        """Use LLM to perform behavioral profiling."""
        from src.ai.prompts.behavioral_analysis import BEHAVIORAL_ANALYSIS_PROMPT

        messages = [
            {"role": "system", "content": BEHAVIORAL_ANALYSIS_PROMPT},
            {"role": "user", "content": text},
        ]
        raw_response = self._client.chat(messages)
        return self._parse_llm_response(raw_response, entity_key)

    def _parse_llm_response(
        self,
        raw_response: str,
        entity_key: str,
    ) -> BehavioralAnalysisResult:
        """Parse LLM JSON response into BehavioralAnalysisResult."""
        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError:
            logger.warning("Failed to parse behavioral analysis response as JSON")
            return BehavioralAnalysisResult(
                profiles={},
                summary="Invalid JSON response from LLM",
                raw_response=raw_response,
            )

        lang_data = data.get("language_style", {})
        activity_data = data.get("activity_times", {})
        platform_data = data.get("platform_preferences", {})

        profile = BehavioralProfile(
            language_style=LanguageStyle(
                formality_level=float(lang_data.get("formality_level", 0.5)),
                common_phrases=lang_data.get("common_phrases", []),
                writing_complexity=float(lang_data.get("writing_complexity", 0.5)),
                sentiment_tendency=float(lang_data.get("sentiment_tendency", 0.5)),
            ),
            activity_times=ActivityTimes(
                active_hours=activity_data.get("active_hours", []),
                active_days=activity_data.get("active_days", []),
                typical_frequency=activity_data.get("typical_frequency"),
            ),
            platform_preferences=platform_data,
            confidence=float(data.get("confidence", 0.5)),
            sample_count=1,
            summary=data.get("summary", ""),
        )

        return BehavioralAnalysisResult(
            profiles={entity_key: profile},
            summary=data.get("summary", "Behavioral profile built"),
            raw_response=raw_response,
        )

    # ------------------------------------------------------------------ #
    #  Deterministic fallback
    # ------------------------------------------------------------------ #

    @staticmethod
    def _deterministic_profile(entity_data: list[dict[str, Any]]) -> BehavioralProfile:
        """Build a profile using deterministic heuristics."""
        all_text = " ".join(str(d.get("text", "")) for d in entity_data if d.get("text"))
        language_style = BehavioralProfiler._analyze_language_style(all_text)
        activity_times = BehavioralProfiler._analyze_activity_times(entity_data)
        platforms = BehavioralProfiler._analyze_platforms(entity_data)

        return BehavioralProfile(
            language_style=language_style,
            activity_times=activity_times,
            platform_preferences=platforms,
            confidence=0.4,
            sample_count=len(entity_data),
            summary=f"Deterministic profile from {len(entity_data)} samples",
        )

    @staticmethod
    def _deterministic_from_text(text: str) -> BehavioralProfile:
        """Build a minimal profile from a single text sample."""
        language_style = BehavioralProfiler._analyze_language_style(text)
        return BehavioralProfile(
            language_style=language_style,
            confidence=0.3,
            sample_count=1,
            summary="Profile from single text sample",
        )

    @staticmethod
    def _analyze_language_style(text: str) -> LanguageStyle:
        """Analyze language style using heuristics."""
        if not text:
            return LanguageStyle()

        words = text.split()
        word_count = len(words)
        if word_count == 0:
            return LanguageStyle()

        # Formality: check for formal indicators
        formal_indicators = [
            "regarding",
            "furthermore",
            "nevertheless",
            "however",
            "therefore",
            "consequently",
            "accordingly",
            "hence",
            "thus",
            "moreover",
            "subsequently",
            "pursuant",
        ]
        informal_indicators = [
            "yeah",
            "gonna",
            "wanna",
            "gotta",
            "nah",
            "dunno",
            "lol",
            "lmao",
            "tbh",
            "idk",
        ]
        formal_count = sum(1 for w in words if w.lower().rstrip(".,!?") in formal_indicators)
        informal_count = sum(1 for w in words if w.lower().rstrip(".,!?") in informal_indicators)
        total = formal_count + informal_count
        formality = 0.5
        if total > 0:
            formality = formal_count / total

        # Writing complexity: avg word length as simple heuristic
        avg_word_len = sum(len(w) for w in words) / word_count
        complexity = min(1.0, max(0.0, (avg_word_len - 3.0) / 6.0))

        # Common phrases: repeating n-grams of length 2-3
        phrases: list[str] = []
        if word_count >= 4:
            bigrams = [" ".join(words[i : i + 2]) for i in range(word_count - 1)]
            phrase_counts = Counter(bigrams)
            phrases = [p for p, c in phrase_counts.most_common(5) if c > 1]

        # Sentiment: simple keyword-based
        positive_words = {
            "good",
            "great",
            "excellent",
            "amazing",
            "love",
            "happy",
            "wonderful",
            "best",
            "beautiful",
            "fantastic",
            "awesome",
        }
        negative_words = {
            "bad",
            "terrible",
            "awful",
            "hate",
            "worst",
            "horrible",
            "ugly",
            "sad",
            "angry",
            "poor",
            "disgusting",
        }
        pos_count = sum(1 for w in words if w.lower().rstrip(".,!?") in positive_words)
        neg_count = sum(1 for w in words if w.lower().rstrip(".,!?") in negative_words)
        total_sentiment = pos_count + neg_count
        sentiment = 0.5
        if total_sentiment > 0:
            sentiment = pos_count / total_sentiment

        return LanguageStyle(
            formality_level=round(formality, 2),
            common_phrases=phrases,
            writing_complexity=round(complexity, 2),
            sentiment_tendency=round(sentiment, 2),
        )

    @staticmethod
    def _analyze_activity_times(entity_data: list[dict[str, Any]]) -> ActivityTimes:
        """Extract timing patterns from entity data."""
        hours: list[int] = []
        days: list[str] = []

        for d in entity_data:
            ts = d.get("timestamp")
            if ts:
                try:
                    if isinstance(ts, (int, float)):
                        dt = datetime.fromtimestamp(ts)
                    elif isinstance(ts, str):
                        dt = datetime.fromisoformat(ts)
                    else:
                        continue
                    hours.append(dt.hour)
                    days.append(dt.strftime("%A"))
                except (ValueError, TypeError):
                    continue

        hour_counts = Counter(hours)
        day_counts = Counter(days)

        peak_hours = [h for h, c in hour_counts.most_common(3) if c > 0]
        peak_days = [d for d, c in day_counts.most_common(3) if c > 0]

        total_samples = len(entity_data)
        if total_samples >= 10:
            frequency = "daily"
        elif total_samples >= 3:
            frequency = "weekly"
        else:
            frequency = "sporadic"

        return ActivityTimes(
            active_hours=sorted(peak_hours),
            active_days=peak_days,
            typical_frequency=frequency,
        )

    @staticmethod
    def _analyze_platforms(entity_data: list[dict[str, Any]]) -> dict[str, float]:
        """Score platform activity from entity data."""
        platform_scores: Counter[str] = Counter()
        for d in entity_data:
            source = str(d.get("source", "unknown")).lower()
            if source:
                platform_scores[source] += 1

        total = sum(platform_scores.values())
        if total == 0:
            return {}

        return {platform: round(count / total, 2) for platform, count in platform_scores.most_common()}
