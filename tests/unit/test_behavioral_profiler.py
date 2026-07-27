"""Tests for BehavioralProfiler — LLM path, deterministic fallback,
language analysis, timing analysis."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.ai.analyzers.behavioral_profiler import BehavioralProfiler
from src.ai.schemas.responses import (
    ActivityTimes,
    BehavioralAnalysisResult,
    BehavioralProfile,
    LanguageStyle,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def profiler() -> BehavioralProfiler:
    return BehavioralProfiler(client=MagicMock())


@pytest.fixture
def sample_entity_data() -> list[dict]:
    return [
        {"text": "Great work everyone! Love this project.", "source": "github",
         "timestamp": "2025-06-01T14:30:00"},
        {"text": "yeah im gonna fix this bug later lol tbh", "source": "github",
         "timestamp": "2025-06-02T15:00:00"},
        {"text": "This is a formal request regarding the aforementioned issue.",
         "source": "email", "timestamp": "2025-06-03T09:00:00"},
    ]


@pytest.fixture
def sample_texts_only() -> list[dict]:
    """Entity data without timestamps, for platform-only analysis."""
    return [
        {"text": "Hello world", "source": "twitter"},
        {"text": "Another post", "source": "twitter"},
    ]


# ------------------------------------------------------------------
# analyze_entity — empty / edge cases
# ------------------------------------------------------------------

class TestAnalyzeEntity:
    def test_empty_entity_data(self, profiler: BehavioralProfiler):
        result = profiler.analyze_entity([])
        assert result.profiles == {}
        assert result.summary == "No data to analyze"

    def test_no_text_fields(self, profiler: BehavioralProfiler):
        """Entity data with only non-text entries triggers deterministic fallback."""
        data = [{"source": "github"}, {"source": "twitter"}]
        result = profiler.analyze_entity(data)
        assert "default" in result.profiles
        assert result.profiles["default"].summary.startswith("Deterministic")

    def test_no_text_content(self, profiler: BehavioralProfiler):
        """Empty text entries."""
        data = [{"text": "", "source": "github"}]
        result = profiler.analyze_entity(data, entity_key="empty_test")
        # Deterministic fallback because combined_text is empty
        assert "empty_test" in result.profiles
        assert result.profiles["empty_test"].sample_count == 1


# ------------------------------------------------------------------
# analyze_entity — LLM path
# ------------------------------------------------------------------

class TestAnalyzeEntityLLM:
    def test_llm_success(self, profiler: BehavioralProfiler, sample_entity_data: list[dict]):
        llm_response = json.dumps({
            "language_style": {
                "formality_level": 0.7,
                "common_phrases": ["good work"],
                "writing_complexity": 0.6,
                "sentiment_tendency": 0.8,
            },
            "activity_times": {
                "active_hours": [14, 15],
                "active_days": ["Monday", "Tuesday"],
                "typical_frequency": "daily",
            },
            "platform_preferences": {"github": 0.8, "email": 0.2},
            "confidence": 0.75,
            "summary": "Moderate activity profile",
        })
        profiler._client.chat = MagicMock(return_value=llm_response)

        result = profiler.analyze_entity(sample_entity_data, entity_key="test_user")
        assert "test_user" in result.profiles
        profile = result.profiles["test_user"]
        assert profile.confidence == 0.75
        assert profile.language_style.formality_level == 0.7
        assert profile.language_style.writing_complexity == 0.6
        assert profile.activity_times.typical_frequency == "daily"
        assert profile.platform_preferences == {"github": 0.8, "email": 0.2}
        assert profile.sample_count == 1  # default when LLM provides it
        assert result.raw_response == llm_response

    def test_llm_failure_fallback(self, profiler: BehavioralProfiler, sample_entity_data: list[dict]):
        profiler._client.chat = MagicMock(side_effect=Exception("API error"))

        result = profiler.analyze_entity(sample_entity_data, entity_key="test_user")
        assert "test_user" in result.profiles
        profile = result.profiles["test_user"]
        assert profile.confidence == 0.4  # deterministic confidence
        assert profile.sample_count == 3
        assert "Deterministic fallback" in result.summary

    def test_llm_invalid_json(self, profiler: BehavioralProfiler, sample_entity_data: list[dict]):
        profiler._client.chat = MagicMock(return_value="not valid json")

        result = profiler.analyze_entity(sample_entity_data, entity_key="test_user")
        # _llm_analysis calls _parse_llm_response which returns empty on parse failure
        # Since chat doesn't raise, this path does NOT hit the deterministic fallback
        # so profiles is empty
        assert result.profiles == {}
        assert "Invalid JSON response" in result.summary


# ------------------------------------------------------------------
# analyze_text
# ------------------------------------------------------------------

class TestAnalyzeText:
    def test_empty_text(self, profiler: BehavioralProfiler):
        result = profiler.analyze_text("")
        assert result.profiles == {}
        assert "Empty text" in result.summary

    def test_whitespace_text(self, profiler: BehavioralProfiler):
        result = profiler.analyze_text("   ")
        assert result.profiles == {}
        assert "Empty text" in result.summary

    def test_llm_success(self, profiler: BehavioralProfiler):
        llm_response = json.dumps({
            "language_style": {
                "formality_level": 0.9,
                "common_phrases": [],
                "writing_complexity": 0.8,
                "sentiment_tendency": 0.3,
            },
            "activity_times": {
                "active_hours": [],
                "active_days": [],
                "typical_frequency": None,
            },
            "platform_preferences": {},
            "confidence": 0.6,
            "summary": "Formal writing style",
        })
        profiler._client.chat = MagicMock(return_value=llm_response)

        result = profiler.analyze_text("This is a formal message regarding the situation.", entity_key="text_sample")
        assert "text_sample" in result.profiles
        assert result.profiles["text_sample"].language_style.formality_level == 0.9

    def test_llm_failure_fallback(self, profiler: BehavioralProfiler):
        profiler._client.chat = MagicMock(side_effect=Exception("API error"))

        result = profiler.analyze_text("Hello! This is some sample text.", entity_key="fallback_test")
        assert "fallback_test" in result.profiles
        profile = result.profiles["fallback_test"]
        assert profile.confidence == 0.3  # deterministic from text
        assert profile.sample_count == 1
        assert "Deterministic text" in result.summary


# ------------------------------------------------------------------
# _parse_llm_response
# ------------------------------------------------------------------

class TestParseLLMResponse:
    def test_valid_json(self, profiler: BehavioralProfiler):
        response = json.dumps({
            "language_style": {"formality_level": 0.8, "common_phrases": ["hello"], "writing_complexity": 0.4, "sentiment_tendency": 0.6},
            "activity_times": {"active_hours": [9, 10], "active_days": ["Monday"], "typical_frequency": "weekly"},
            "platform_preferences": {"twitter": 1.0},
            "confidence": 0.9,
            "summary": "Test profile",
        })
        result = profiler._parse_llm_response(response, "test_key")
        assert "test_key" in result.profiles
        assert result.profiles["test_key"].confidence == 0.9
        assert result.profiles["test_key"].activity_times.active_hours == [9, 10]

    def test_invalid_json(self, profiler: BehavioralProfiler):
        result = profiler._parse_llm_response("{bad json}", "test_key")
        assert result.profiles == {}
        assert "Invalid JSON" in result.summary

    def test_empty_fields(self, profiler: BehavioralProfiler):
        response = json.dumps({})
        result = profiler._parse_llm_response(response, "test_key")
        assert "test_key" in result.profiles
        profile = result.profiles["test_key"]
        assert profile.language_style.formality_level == 0.5  # defaults
        assert profile.activity_times.active_hours == []
        assert profile.platform_preferences == {}

    def test_llm_response_with_optional_missing(self, profiler: BehavioralProfiler):
        """Missing optional fields should use defaults."""
        response = json.dumps({
            "language_style": {},
            "activity_times": {},
        })
        result = profiler._parse_llm_response(response, "k")
        profile = result.profiles["k"]
        assert profile.language_style.formality_level == 0.5
        assert profile.activity_times.typical_frequency is None
        assert profile.confidence == 0.5


# ------------------------------------------------------------------
# Deterministic language analysis
# ------------------------------------------------------------------

class TestDeterministicLanguageAnalysis:
    def test_analyze_language_style_empty(self):
        style = BehavioralProfiler._analyze_language_style("")
        assert style.formality_level == 0.5
        assert style.common_phrases == []

    def test_analyze_language_style_formal(self):
        text = "Furthermore, this is a formal request regarding the aforementioned matter. However, we must consider the consequences."
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.formality_level > 0.5  # should be more formal

    def test_analyze_language_style_informal(self):
        text = "yeah gonna fix this lol dunno tbh wanna grab lunch"
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.formality_level < 0.5  # should be less formal

    def test_analyze_language_style_neutral(self):
        text = "The cat sat on the mat. It was a sunny day."
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.formality_level == 0.5  # no indicators
        assert style.sentiment_tendency == 0.5

    def test_analyze_language_style_positive_sentiment(self):
        text = "This is great work! I love it. Amazing job, awesome results."
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.sentiment_tendency > 0.5

    def test_analyze_language_style_negative_sentiment(self):
        text = "This is terrible. I hate it. Worst experience ever."
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.sentiment_tendency < 0.5

    def test_analyze_language_style_complexity(self):
        text = "extraordinarily incomprehensible terminology manifestation"
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.writing_complexity > 0.5  # long words

    def test_analyze_language_style_simple(self):
        text = "the cat sat on the mat and ate"
        style = BehavioralProfiler._analyze_language_style(text)
        assert style.writing_complexity < 0.5  # short words

    def test_analyze_language_style_repeated_phrases(self):
        text = "thank you thank you please help please help come here come here"
        style = BehavioralProfiler._analyze_language_style(text)
        assert len(style.common_phrases) > 0
        assert "thank you" in style.common_phrases


# ------------------------------------------------------------------
# Deterministic activity times
# ------------------------------------------------------------------

class TestDeterministicActivityTimes:
    def test_activity_times_with_int_timestamps(self):
        data = [
            {"text": "a", "timestamp": 1717200000},  # 2024-06-01
            {"text": "b", "timestamp": 1717286400},  # 2024-06-02
        ]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert len(times.active_hours) > 0
        assert len(times.active_days) > 0
        assert times.typical_frequency == "sporadic"  # < 3 samples

    def test_activity_times_with_float_timestamp(self):
        data = [{"text": "a", "timestamp": 1717200000.5}]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert len(times.active_hours) <= 3
        assert times.typical_frequency == "sporadic"

    def test_activity_times_with_string_timestamps(self):
        data = [
            {"text": "a", "timestamp": "2025-06-01T14:30:00"},
            {"text": "b", "timestamp": "2025-06-02T15:30:00"},
            {"text": "c", "timestamp": "2025-06-03T14:30:00"},
        ]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert 14 in times.active_hours or 15 in times.active_hours
        assert times.typical_frequency == "weekly"  # >= 3 samples

    def test_activity_times_daily_frequency(self):
        data = [{"text": "a", "timestamp": f"2025-06-{d:02d}T12:00:00"} for d in range(1, 11)]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert times.typical_frequency == "daily"  # >= 10 samples

    def test_activity_times_no_timestamps(self):
        data = [{"text": "a"}, {"text": "b"}]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert times.active_hours == []
        assert times.active_days == []
        assert times.typical_frequency == "sporadic"

    def test_activity_times_invalid_timestamp(self):
        data = [{"text": "a", "timestamp": "not-a-date"}]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert times.active_hours == []
        assert times.active_days == []

    def test_activity_times_mixed_valid_and_invalid(self):
        data = [
            {"text": "a", "timestamp": "2025-06-01T14:30:00"},
            {"text": "b", "timestamp": "bad"},
            {"text": "c", "timestamp": 1717200000},
        ]
        times = BehavioralProfiler._analyze_activity_times(data)
        assert len(times.active_hours) > 0  # at least from valid ones


# ------------------------------------------------------------------
# Deterministic platform analysis
# ------------------------------------------------------------------

class TestDeterministicPlatforms:
    def test_platform_analysis(self):
        data = [
            {"text": "a", "source": "github"},
            {"text": "b", "source": "github"},
            {"text": "c", "source": "twitter"},
        ]
        platforms = BehavioralProfiler._analyze_platforms(data)
        assert "github" in platforms
        assert "twitter" in platforms
        assert platforms["github"] == 0.67  # 2/3
        assert platforms["twitter"] == 0.33  # 1/3

    def test_platform_analysis_no_source(self):
        data = [{"text": "a"}, {"text": "b"}]
        platforms = BehavioralProfiler._analyze_platforms(data)
        assert "unknown" in platforms
        assert platforms["unknown"] == 1.0

    def test_platform_analysis_empty_data(self):
        platforms = BehavioralProfiler._analyze_platforms([])
        assert platforms == {}


# ------------------------------------------------------------------
# Deterministic profile builder
# ------------------------------------------------------------------

class TestDeterministicProfile:
    def test_deterministic_profile_from_data(self):
        data = [
            {"text": "Great work everyone! Love this.", "source": "github",
             "timestamp": "2025-06-01T14:00:00"},
            {"text": "yeah gonna fix this later lol", "source": "github",
             "timestamp": "2025-06-02T15:00:00"},
        ]
        profile = BehavioralProfiler._deterministic_profile(data)
        assert isinstance(profile, BehavioralProfile)
        assert profile.confidence == 0.4
        assert profile.sample_count == 2
        assert profile.platform_preferences.get("github", 0) > 0
        assert profile.language_style.formality_level is not None

    def test_deterministic_from_text_minimal(self):
        profile = BehavioralProfiler._deterministic_from_text("Just a simple message.")
        assert isinstance(profile, BehavioralProfile)
        assert profile.confidence == 0.3
        assert profile.sample_count == 1
        assert profile.activity_times.active_hours == []
