"""Tests for AnomalyDetector — z-score, timing anomalies, statistical
anomalies, platform anomalies, LLM enrichment."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.ai.analyzers.anomaly_detector import AnomalyDetector
from src.ai.schemas.responses import (
    ActivityTimes,
    BehavioralProfile,
    DetectedAnomaly,
    LanguageStyle,
)

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def detector() -> AnomalyDetector:
    return AnomalyDetector(client=None)


@pytest.fixture
def detector_with_llm() -> AnomalyDetector:
    return AnomalyDetector(client=MagicMock())


@pytest.fixture
def baseline_profile() -> BehavioralProfile:
    return BehavioralProfile(
        language_style=LanguageStyle(
            formality_level=0.7,
            writing_complexity=0.5,
            sentiment_tendency=0.6,
        ),
        activity_times=ActivityTimes(
            active_hours=[9, 10, 11, 14, 15, 16],
            active_days=["Monday", "Tuesday", "Wednesday"],
            typical_frequency="daily",
        ),
        platform_preferences={"github": 0.8, "twitter": 0.2},
        confidence=0.8,
        sample_count=50,
        summary="Baseline profile for testing",
    )


@pytest.fixture
def baseline_with_simple_language() -> BehavioralProfile:
    """Baseline with low complexity — short expected word length ~4.0."""
    return BehavioralProfile(
        language_style=LanguageStyle(
            formality_level=0.5,
            writing_complexity=0.17,  # expected_aww = 3.0 + 0.17*6.0 ≈ 4.0
            sentiment_tendency=0.5,
        ),
        activity_times=ActivityTimes(
            active_hours=[9, 10, 11, 14, 15, 16],
            active_days=["Monday", "Tuesday"],
            typical_frequency="daily",
        ),
        platform_preferences={"github": 0.8, "twitter": 0.2},
        confidence=0.8,
        sample_count=50,
        summary="Simple language baseline",
    )


@pytest.fixture
def normal_data() -> list[dict]:
    """Data within the baseline profile — includes source to avoid platform anomaly."""
    return [
        {"text": "Normal work day", "source": "github", "timestamp": "2025-06-02T10:00:00"},
        {"text": "Reviewing PRs", "source": "github", "timestamp": "2025-06-02T15:00:00"},
    ]


# ------------------------------------------------------------------
# detect — empty / edge cases
# ------------------------------------------------------------------


class TestDetect:
    def test_empty_entity_data(self, detector: AnomalyDetector):
        result = detector.detect([], entity_key="empty")
        assert result.reports == {}
        assert "No data to analyze" in result.summary

    def test_no_baseline_no_anomalies(self, detector: AnomalyDetector, normal_data: list[dict]):
        """Without a baseline, timing/platform/statistical anomalies are not detected."""
        result = detector.detect(normal_data, baseline=None, entity_key="test")
        assert "test" in result.reports
        report = result.reports["test"]
        assert len(report.detected_anomalies) == 0
        assert report.overall_severity == 0.0

    def test_no_anomalies_with_baseline_and_in_range_text(
        self,
        detector: AnomalyDetector,
        baseline_with_simple_language: BehavioralProfile,
    ):
        """Baseline with expected_aww=4.0; text with avg word length ~5.0 is in range (5/4=1.25 < 1.5 and > 0.67)."""
        data = [
            {"text": "simple testing data for this function", "source": "github", "timestamp": "2025-06-02T10:00:00"}
        ]
        result = detector.detect(data, baseline=baseline_with_simple_language, entity_key="test")
        report = result.reports["test"]
        assert len(report.detected_anomalies) == 0


# ------------------------------------------------------------------
# statistical_anomaly (z-score)
# ------------------------------------------------------------------


class TestStatisticalAnomaly:
    def test_z_score_normal(self, detector: AnomalyDetector):
        values = [10.0, 12.0, 11.0, 9.0, 10.5]
        z = detector.statistical_anomaly(values, 11.0)
        assert z < 2.0  # within normal range

    def test_z_score_anomalous(self, detector: AnomalyDetector):
        values = [10.0, 12.0, 11.0, 9.0, 10.5]
        z = detector.statistical_anomaly(values, 30.0)
        assert z > 2.0  # far outside

    def test_z_score_empty_values(self, detector: AnomalyDetector):
        assert detector.statistical_anomaly([], 10.0) == 0.0

    def test_z_score_single_value(self, detector: AnomalyDetector):
        assert detector.statistical_anomaly([5.0], 10.0) == 0.0

    def test_z_score_zero_variance(self, detector: AnomalyDetector):
        """When all values are identical, std_dev is 1.0 (clamped)."""
        values = [5.0, 5.0, 5.0, 5.0]
        z = detector.statistical_anomaly(values, 5.0)
        assert z == 0.0
        z2 = detector.statistical_anomaly(values, 10.0)
        assert z2 == 5.0  # (10-5)/1.0


# ------------------------------------------------------------------
# Timing anomalies
# ------------------------------------------------------------------


class TestTimingAnomalies:
    def test_off_hour_detected(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Data at 3am is outside baseline hours (9-16)."""
        data = [
            {"text": "night post", "source": "github", "timestamp": "2025-06-02T03:00:00"},
            {"text": "another night post", "source": "github", "timestamp": "2025-06-02T04:00:00"},
        ]
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "timing_anomaly"
        assert "2/2" in anomalies[0].description
        assert anomalies[0].severity > 0.0

    def test_no_timing_anomaly_when_within_hours(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [{"text": "day post", "source": "github", "timestamp": "2025-06-02T10:00:00"}]
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 0

    def test_no_timing_anomaly_without_baseline(self, detector: AnomalyDetector):
        data = [{"text": "test", "timestamp": "2025-06-02T03:00:00"}]
        anomalies = detector._detect_timing_anomalies(data, None)
        assert len(anomalies) == 0

    def test_timing_requires_2_off_hours(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Only 1 off-hour observation should not trigger."""
        data = [{"text": "test", "timestamp": "2025-06-02T03:00:00"}]
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 0

    def test_timing_with_mixed_hours(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Even mix — off-hour ratio must be > 0.5 and >= 2."""
        data = [
            {"text": "a", "timestamp": "2025-06-02T10:00:00"},
            {"text": "b", "timestamp": "2025-06-02T03:00:00"},
            {"text": "c", "timestamp": "2025-06-02T04:00:00"},
        ]
        # 2 off-hours out of 3 = 0.67 > 0.5, so it should trigger
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 1

    def test_timing_with_int_timestamps(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [
            {"text": "a", "timestamp": 1717200000},  # around 00:00 UTC
            {"text": "b", "timestamp": 1717203600},  # around 01:00 UTC
        ]
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 1

    def test_timing_invalid_timestamp_ignored(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [{"text": "a", "timestamp": "not-a-date"}]
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 0

    def test_timing_no_timestamp_field(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [{"text": "a"}]
        anomalies = detector._detect_timing_anomalies(data, baseline_profile)
        assert len(anomalies) == 0


# ------------------------------------------------------------------
# Statistical anomalies
# ------------------------------------------------------------------


class TestStatisticalDetect:
    def test_style_change_detected(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Complex text far outside baseline should trigger style change."""
        data = [
            {
                "text": "extraordinarily incomprehensible terminology manifestation "
                "constitutional notwithstanding nevertheless"
            },
        ]
        anomalies = detector._detect_statistical_anomalies(data, baseline_profile)
        style = [a for a in anomalies if a.anomaly_type == "style_change"]
        assert len(style) == 1

    def test_style_change_not_detected(
        self, detector: AnomalyDetector, baseline_with_simple_language: BehavioralProfile
    ):
        """Text with avg word length in safe range should not trigger style change.
        Baseline expected_aww ≈ 4.0, text avg ≈ 5.0, ratio 5/4=1.25 (between 0.67 and 1.5)."""
        data = [{"text": "simple testing data for this function check"}]
        anomalies = detector._detect_statistical_anomalies(data, baseline_with_simple_language)
        style = [a for a in anomalies if a.anomaly_type == "style_change"]
        assert len(style) == 0

    def test_no_baseline_returns_empty(self, detector: AnomalyDetector):
        data = [{"text": "any text"}]
        anomalies = detector._detect_statistical_anomalies(data, None)
        assert len(anomalies) == 0

    def test_frequency_spike_detected(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """5+ distinct dates from same source triggers frequency spike."""
        data = [{"text": "a", "source": "github", "timestamp": f"2025-06-{d:02d}T10:00:00"} for d in range(1, 6)]
        anomalies = detector._detect_statistical_anomalies(data, baseline_profile)
        freq = [a for a in anomalies if a.anomaly_type == "frequency_spike"]
        assert len(freq) == 1
        assert freq[0].dimension == "frequency"

    def test_frequency_below_threshold(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """4 distinct dates should not trigger (threshold is 5)."""
        data = [{"text": "a", "source": "github", "timestamp": f"2025-06-{d:02d}T10:00:00"} for d in range(1, 5)]
        anomalies = detector._detect_statistical_anomalies(data, baseline_profile)
        freq = [a for a in anomalies if a.anomaly_type == "frequency_spike"]
        assert len(freq) == 0

    def test_frequency_multiple_sources(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = []
        for d in range(1, 8):
            data.append({"text": "a", "source": "github", "timestamp": f"2025-06-{d:02d}T10:00:00"})
        for d in range(1, 4):
            data.append({"text": "b", "source": "twitter", "timestamp": f"2025-06-{d:02d}T11:00:00"})
        anomalies = detector._detect_statistical_anomalies(data, baseline_profile)
        freq = [a for a in anomalies if a.anomaly_type == "frequency_spike"]
        # github has 7 dates (>=5), twitter has 3 (<5)
        assert len(freq) == 1
        assert "github" in freq[0].description


# ------------------------------------------------------------------
# Platform anomalies
# ------------------------------------------------------------------


class TestPlatformAnomalies:
    def test_new_platform_detected(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [{"text": "a", "source": "reddit"}]
        anomalies = detector._detect_platform_anomalies(data, baseline_profile)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "new_platform"
        assert anomalies[0].observed_value == "reddit"
        assert anomalies[0].severity == 0.7

    def test_no_new_platform(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [{"text": "a", "source": "github"}]
        anomalies = detector._detect_platform_anomalies(data, baseline_profile)
        assert len(anomalies) == 0

    def test_no_baseline_returns_empty(self, detector: AnomalyDetector):
        data = [{"text": "a", "source": "reddit"}]
        anomalies = detector._detect_platform_anomalies(data, None)
        assert len(anomalies) == 0

    def test_empty_baseline_platforms_is_not_checked(self, detector: AnomalyDetector):
        """When baseline.platform_preferences is empty (falsy), no platform anomalies detected."""
        profile = BehavioralProfile()  # platform_preferences defaults to {}
        data = [{"text": "a", "source": "twitter"}]
        anomalies = detector._detect_platform_anomalies(data, profile)
        # platform_preferences is empty dict → falsy → skip
        assert len(anomalies) == 0

    def test_mixed_known_and_new(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        data = [
            {"text": "a", "source": "github"},
            {"text": "b", "source": "reddit"},
            {"text": "c", "source": "linkedin"},
        ]
        anomalies = detector._detect_platform_anomalies(data, baseline_profile)
        assert len(anomalies) == 2
        platforms = {a.observed_value for a in anomalies}
        assert platforms == {"reddit", "linkedin"}


# ------------------------------------------------------------------
# LLM enrichment
# ------------------------------------------------------------------


class TestLLMEnrichment:
    def test_llm_enrichment_success(
        self, detector_with_llm: AnomalyDetector, baseline_with_simple_language: BehavioralProfile
    ):
        """Use a baseline that won't trigger deterministic anomalies so only
        the LLM anomaly appears in the report."""
        llm_response = json.dumps(
            {
                "detected_anomalies": [
                    {
                        "anomaly_type": "style_change",
                        "description": "Sudden language shift detected",
                        "severity": 0.8,
                        "confidence": 0.7,
                        "dimension": "language",
                        "baseline_value": "formal",
                        "observed_value": "informal",
                    }
                ],
                "summary": "One anomaly detected",
            }
        )
        # Patch chat at the module level to avoid MagicMock attribute issues
        with patch.object(detector_with_llm._client, "chat", return_value=llm_response):
            data = [
                {
                    "text": "a typical observation with moderate length",
                    "source": "github",
                    "timestamp": "2025-06-02T10:00:00",
                }
            ]
            result = detector_with_llm.detect(
                data, baseline=baseline_with_simple_language, entity_key="test", use_llm=True
            )
        report = result.reports["test"]
        assert len(report.detected_anomalies) == 1
        assert report.detected_anomalies[0].anomaly_type == "style_change"

    def test_llm_enrichment_no_client(
        self, detector: AnomalyDetector, baseline_with_simple_language: BehavioralProfile
    ):
        """Without LLM client, only deterministic anomalies appear. Baseline has
        simple language so no style_change; data has source=github which is known."""
        data = [
            {"text": "a typical sentence with normal words", "source": "github", "timestamp": "2025-06-02T10:00:00"}
        ]
        result = detector.detect(data, baseline=baseline_with_simple_language, entity_key="test", use_llm=True)
        report = result.reports["test"]
        assert len(report.detected_anomalies) == 0

    def test_llm_enrichment_failure_ignored(
        self, detector_with_llm: AnomalyDetector, baseline_with_simple_language: BehavioralProfile
    ):
        """LLM failure is caught and logged; deterministic anomalies still work."""
        with patch.object(detector_with_llm._client, "chat", side_effect=Exception("LLM error")):
            data = [
                {"text": "simple chat about work testing tasks", "source": "github", "timestamp": "2025-06-02T10:00:00"}
            ]
            result = detector_with_llm.detect(
                data, baseline=baseline_with_simple_language, entity_key="test", use_llm=True
            )
        report = result.reports["test"]
        # No LLM anomalies, and no deterministic anomalies either with
        # simple language baseline and known platform
        assert len(report.detected_anomalies) == 0

    def test_llm_no_text_data_returns_empty(self, detector_with_llm: AnomalyDetector):
        with patch.object(detector_with_llm._client, "chat", return_value='{"detected_anomalies": []}'):
            anomalies = detector_with_llm._llm_enrichment(
                [{"source": "github"}],  # no text field
                None,
            )
        assert anomalies == []

    def test_llm_no_client_returns_empty(self, detector: AnomalyDetector):
        anomalies = detector._llm_enrichment([{"text": "hi"}], None)
        assert anomalies == []


# ------------------------------------------------------------------
# _parse_llm_anomalies
# ------------------------------------------------------------------


class TestParseLLMAnomalies:
    def test_valid_json(self, detector: AnomalyDetector):
        response = json.dumps(
            {
                "detected_anomalies": [
                    {
                        "anomaly_type": "style_change",
                        "description": "test",
                        "severity": 0.5,
                        "confidence": 0.6,
                        "dimension": "language",
                    },
                ]
            }
        )
        anomalies = detector._parse_llm_anomalies(response)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "style_change"

    def test_invalid_json(self, detector: AnomalyDetector):
        anomalies = detector._parse_llm_anomalies("not json")
        assert anomalies == []

    def test_empty_anomalies(self, detector: AnomalyDetector):
        response = json.dumps({"detected_anomalies": []})
        anomalies = detector._parse_llm_anomalies(response)
        assert anomalies == []

    def test_malformed_item_skipped(self, detector: AnomalyDetector):
        response = json.dumps(
            {
                "detected_anomalies": [
                    {"anomaly_type": "good", "description": "ok"},
                    {"anomaly_type": 123, "description": None},
                ]
            }
        )
        anomalies = detector._parse_llm_anomalies(response)
        # Both should parse (str(123) = "123", str(None) = "None")
        assert len(anomalies) == 2

    def test_incomplete_item_defaults(self, detector: AnomalyDetector):
        response = json.dumps({"detected_anomalies": [{}]})
        anomalies = detector._parse_llm_anomalies(response)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "other"
        assert anomalies[0].severity == 0.5
        assert anomalies[0].confidence == 0.5


# ------------------------------------------------------------------
# Deduplication
# ------------------------------------------------------------------


class TestDedup:
    def test_dedup_by_type_and_description(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Identical platform names in a set yield one anomaly."""
        data = [
            {"text": "a", "source": "reddit"},
            {"text": "b", "source": "reddit"},  # same platform appears twice
        ]
        anomalies = detector._detect_platform_anomalies(data, baseline_profile)
        # Each entry adds "reddit" to the set, but since it's a set, it's only once
        assert len(anomalies) == 1

    def test_dedup_integration(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Within a detect() call, dedup means 2 identical platform events give 1."""
        data = [
            {"text": "a", "source": "linkedin"},
            {"text": "b", "source": "linkedin"},
        ]
        result = detector.detect(data, baseline=baseline_profile, entity_key="test")
        report = result.reports["test"]
        platform_anomalies = [a for a in report.detected_anomalies if a.anomaly_type == "new_platform"]
        assert len(platform_anomalies) == 1


# ------------------------------------------------------------------
# _build_summary
# ------------------------------------------------------------------


class TestBuildSummary:
    def test_empty_anomalies(self, detector: AnomalyDetector):
        summary = detector._build_summary([])
        assert "No anomalies detected" in summary

    def test_single_anomaly_type(self, detector: AnomalyDetector):
        anomalies = [
            DetectedAnomaly(anomaly_type="timing_anomaly", description="late night"),
            DetectedAnomaly(anomaly_type="timing_anomaly", description="another late night"),
        ]
        summary = detector._build_summary(anomalies)
        assert "2 anomalies" in summary
        assert "timing_anomaly: 2" in summary

    def test_multiple_types(self, detector: AnomalyDetector):
        anomalies = [
            DetectedAnomaly(anomaly_type="timing_anomaly", description="a"),
            DetectedAnomaly(anomaly_type="style_change", description="b"),
            DetectedAnomaly(anomaly_type="new_platform", description="c"),
        ]
        summary = detector._build_summary(anomalies)
        assert "3 anomalies" in summary
        for t in ["timing_anomaly", "style_change", "new_platform"]:
            assert t in summary


# ------------------------------------------------------------------
# Integration: detect with all anomaly types
# ------------------------------------------------------------------


class TestDetectIntegration:
    def test_multiple_anomaly_types(self, detector: AnomalyDetector, baseline_profile: BehavioralProfile):
        """Entity data that triggers timing, style, and platform anomalies."""
        data = [
            # Off-hour post (3am, outside baseline 9-16)
            {"text": "Night posting activity check", "source": "github", "timestamp": "2025-06-02T03:00:00"},
            # Another off-hour post
            {"text": "More night activity test", "source": "github", "timestamp": "2025-06-02T04:00:00"},
            # New platform
            {"text": "First reddit post content", "source": "reddit", "timestamp": "2025-06-02T10:00:00"},
        ]
        result = detector.detect(data, baseline=baseline_profile, entity_key="test")
        report = result.reports["test"]
        assert len(report.detected_anomalies) >= 2  # timing + platform
        types = {a.anomaly_type for a in report.detected_anomalies}
        assert "timing_anomaly" in types
        assert "new_platform" in types
        assert report.overall_severity > 0.0
        assert report.overall_confidence > 0.0
