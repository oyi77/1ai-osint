"""Anomaly detection analyzer for OSINT entity behavior.

Flags unusual behavior in monitored entities using statistical methods
(z-score), temporal analysis, and cross-platform comparison.
"""

import logging
import math
from datetime import datetime
from typing import Any

from src.ai.analyzers._anomaly_utils import build_summary, parse_llm_anomalies
from src.ai.omniroute_client import OmniRouteClient
from src.ai.schemas.responses import (
    AnomalyDetectionResult,
    AnomalyReport,
    BehavioralProfile,
    DetectedAnomaly,
)

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect anomalous behavior in monitored OSINT entities.

    Primary detection methods are deterministic (statistical, temporal).
    Optional LLM enrichment provides deeper semantic analysis.
    """

    def __init__(self, client: OmniRouteClient | None = None):
        self._client = client

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def detect(
        self,
        entity_data: list[dict[str, Any]],
        baseline: BehavioralProfile | None = None,
        entity_key: str = "default",
        use_llm: bool = False,
    ) -> AnomalyDetectionResult:
        """Detect anomalies in entity behavior data.

        Args:
            entity_data: New observations to check for anomalies.
            baseline: Optional BehavioralProfile to compare against.
            entity_key: Entity identifier for the report.
            use_llm: Whether to enrich detection with LLM analysis.

        Returns:
            AnomalyDetectionResult with detected anomalies.

        """
        if not entity_data:
            return AnomalyDetectionResult(
                reports={},
                summary="No data to analyze",
            )

        anomalies: list[DetectedAnomaly] = []

        # 1. Temporal anomaly detection
        timing_anomalies = self._detect_timing_anomalies(entity_data, baseline)
        anomalies.extend(timing_anomalies)

        # 2. Statistical anomaly detection
        stat_anomalies = self._detect_statistical_anomalies(entity_data, baseline)
        anomalies.extend(stat_anomalies)

        # 3. Cross-platform anomaly detection
        platform_anomalies = self._detect_platform_anomalies(entity_data, baseline)
        anomalies.extend(platform_anomalies)

        # 4. Optional LLM enrichment
        if use_llm and self._client:
            try:
                llm_anomalies = self._llm_enrichment(entity_data, baseline)
                anomalies.extend(llm_anomalies)
            except Exception as e:
                logger.warning("LLM anomaly enrichment failed: %s", e)

        # Build report
        if anomalies:
            overall_severity = max(a.severity for a in anomalies)
            avg_confidence = sum(a.confidence for a in anomalies) / len(anomalies)
        else:
            overall_severity = 0.0
            avg_confidence = 0.0

        # Deduplicate by description
        seen: set[str] = set()
        deduped: list[DetectedAnomaly] = []
        for a in anomalies:
            key = f"{a.anomaly_type}:{a.description}"
            if key not in seen:
                seen.add(key)
                deduped.append(a)

        report = AnomalyReport(
            detected_anomalies=deduped,
            overall_severity=round(overall_severity, 2),
            overall_confidence=round(avg_confidence, 2),
            summary=self._build_summary(deduped),
        )

        return AnomalyDetectionResult(
            reports={entity_key: report},
            summary=report.summary,
        )

    def statistical_anomaly(self, values: list[float], new_value: float) -> float:
        """Calculate z-score for a new value against a population.

        Args:
            values: Historical values (baseline population).
            new_value: New observation to test.

        Returns:
            Absolute z-score. Values > 2.0 are anomalous, > 3.0 highly anomalous.

        """
        if not values:
            return 0.0

        n = len(values)
        if n < 2:
            return 0.0

        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
        std_dev = math.sqrt(variance) if variance > 0 else 1.0

        z_score = abs(new_value - mean) / std_dev
        return round(z_score, 2)

    # ------------------------------------------------------------------ #
    #  Timing anomaly detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _detect_timing_anomalies(
        entity_data: list[dict[str, Any]],
        baseline: BehavioralProfile | None,
    ) -> list[DetectedAnomaly]:
        """Detect anomalies in posting/activity timing."""
        anomalies: list[DetectedAnomaly] = []

        if not baseline or not baseline.activity_times.active_hours:
            return anomalies

        baseline_hours = set(baseline.activity_times.active_hours)

        # Check if new data falls outside baseline hours
        off_hour_count = 0
        total_with_time = 0
        for d in entity_data:
            ts = d.get("timestamp")
            if not ts:
                continue
            try:
                if isinstance(ts, (int, float)):
                    dt = datetime.fromtimestamp(ts)
                elif isinstance(ts, str):
                    dt = datetime.fromisoformat(ts)
                else:
                    continue
                total_with_time += 1
                if dt.hour not in baseline_hours:
                    off_hour_count += 1
            except (ValueError, TypeError):
                continue

        if total_with_time > 0:
            off_hour_ratio = off_hour_count / total_with_time
            if off_hour_ratio > 0.5 and off_hour_count >= 2:
                anomalies.append(
                    DetectedAnomaly(
                        anomaly_type="timing_anomaly",
                        description=(
                            f"{off_hour_count}/{total_with_time} observations " f"outside baseline active hours"
                        ),
                        severity=min(1.0, off_hour_ratio),
                        confidence=min(1.0, 0.5 + off_hour_ratio * 0.3),
                        dimension="timing",
                        baseline_value=f"hours={sorted(baseline_hours)}",
                        observed_value=f"{off_hour_count} off-hours",
                    )
                )

        return anomalies

    # ------------------------------------------------------------------ #
    #  Statistical anomaly detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _detect_statistical_anomalies(
        entity_data: list[dict[str, Any]],
        baseline: BehavioralProfile | None,
    ) -> list[DetectedAnomaly]:
        """Detect anomalies using statistical methods."""
        anomalies: list[DetectedAnomaly] = []

        if not baseline:
            return anomalies

        # Language style deviation
        if baseline.language_style:
            texts = [d.get("text", "") for d in entity_data if d.get("text")]
            if texts:
                combined = " ".join(texts)
                words = combined.split()
                if words:
                    avg_word_len = sum(len(w) for w in words) / len(words)
                    baseline_complexity = baseline.language_style.writing_complexity
                    # Expected avg word length from baseline complexity
                    expected_aww = 3.0 + baseline_complexity * 6.0
                    observed_aww = avg_word_len

                    if expected_aww > 0:
                        ratio = observed_aww / expected_aww
                        if ratio > 1.5 or ratio < 0.67:
                            anomalies.append(
                                DetectedAnomaly(
                                    anomaly_type="style_change",
                                    description=(
                                        f"Writing complexity shift: "
                                        f"avg word length {observed_aww:.1f} "
                                        f"vs expected {expected_aww:.1f}"
                                    ),
                                    severity=min(1.0, abs(ratio - 1.0)),
                                    confidence=0.5,
                                    dimension="language",
                                    baseline_value=f"~{expected_aww:.1f} chars/word",
                                    observed_value=f"{observed_aww:.1f} chars/word",
                                )
                            )

        # Frequency anomaly
        source_dates: dict[str, set[str]] = {}
        for d in entity_data:
            source = str(d.get("source", "unknown"))
            ts = d.get("timestamp")
            if ts:
                try:
                    if isinstance(ts, (int, float)):
                        date_key = datetime.fromtimestamp(ts).date().isoformat()
                    elif isinstance(ts, str):
                        date_key = datetime.fromisoformat(ts).date().isoformat()
                    else:
                        continue
                    source_dates.setdefault(source, set()).add(date_key)
                except (ValueError, TypeError):
                    continue

        for source, dates in source_dates.items():
            if len(dates) >= 5:
                anomalies.append(
                    DetectedAnomaly(
                        anomaly_type="frequency_spike",
                        description=(f"High activity volume from {source}: " f"{len(dates)} distinct dates"),
                        severity=min(1.0, len(dates) / 20.0),
                        confidence=0.6,
                        dimension="frequency",
                        observed_value=f"{len(dates)} active dates",
                    )
                )

        return anomalies

    # ------------------------------------------------------------------ #
    #  Cross-platform anomaly detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _detect_platform_anomalies(
        entity_data: list[dict[str, Any]],
        baseline: BehavioralProfile | None,
    ) -> list[DetectedAnomaly]:
        """Detect new/unusual platform appearances."""
        anomalies: list[DetectedAnomaly] = []

        observed_platforms = set()
        for d in entity_data:
            source = str(d.get("source", "unknown")).lower()
            if source:
                observed_platforms.add(source)

        if baseline and baseline.platform_preferences:
            known_platforms = set(baseline.platform_preferences.keys())
            new_platforms = observed_platforms - known_platforms

            for platform in new_platforms:
                anomalies.append(
                    DetectedAnomaly(
                        anomaly_type="new_platform",
                        description=f"Entity appeared on new platform: {platform}",
                        severity=0.7,
                        confidence=0.6,
                        entity="",
                        dimension="platform",
                        observed_value=platform,
                    )
                )

        return anomalies

    # ------------------------------------------------------------------ #
    #  LLM enrichment
    # ------------------------------------------------------------------ #

    def _llm_enrichment(
        self,
        entity_data: list[dict[str, Any]],
        baseline: BehavioralProfile | None,
    ) -> list[DetectedAnomaly]:
        """Use LLM to detect semantic anomalies."""
        if not self._client:
            return []

        from src.ai.prompts.anomaly_detection import ANOMALY_DETECTION_PROMPT

        texts = [d.get("text", "") for d in entity_data if d.get("text")]
        if not texts:
            return []

        observations = "\n---\n".join(texts)

        language_baseline = "No baseline available"
        activity_baseline = "No baseline available"
        if baseline:
            if baseline.language_style:
                language_baseline = baseline.language_style.model_dump_json()
            if baseline.activity_times:
                activity_baseline = baseline.activity_times.model_dump_json()

        prompt = ANOMALY_DETECTION_PROMPT.format(
            language_baseline=language_baseline,
            activity_baseline=activity_baseline,
            new_observations=observations,
        )

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Analyze these observations for anomalies."},
        ]

        try:
            raw_response = self._client.chat(messages)
            return self._parse_llm_anomalies(raw_response)
        except Exception as e:
            logger.warning("LLM anomaly detection failed: %s", e)
            return []

    @staticmethod
    def _parse_llm_anomalies(raw_response: str) -> list[DetectedAnomaly]:
        """Parse LLM JSON response into DetectedAnomaly list."""
        return parse_llm_anomalies(raw_response)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_summary(anomalies: list[DetectedAnomaly]) -> str:
        """Build human-readable summary."""
        return build_summary(anomalies)
