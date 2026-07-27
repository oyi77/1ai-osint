"""Shared anomaly detection utility functions."""

from collections import Counter

from src.ai.schemas.responses import DetectedAnomaly


def build_summary(anomalies: list[DetectedAnomaly]) -> str:
    """Build human-readable summary."""
    if not anomalies:
        return "No anomalies detected"

    by_type: Counter[str] = Counter()
    for a in anomalies:
        by_type[a.anomaly_type] += 1

    parts = [f"Detected {len(anomalies)} anomalies:"]
    for atype, count in by_type.most_common():
        parts.append(f"  - {atype}: {count}")

    return "\n".join(parts)


def parse_llm_anomalies(raw_response: str) -> list[DetectedAnomaly]:
    """Parse LLM JSON response into DetectedAnomaly list."""
    import json

    try:
        data = json.loads(raw_response)
    except json.JSONDecodeError:
        return []

    anomalies: list[DetectedAnomaly] = []
    for item in data.get("detected_anomalies", []):
        try:
            anomalies.append(
                DetectedAnomaly(
                    anomaly_type=str(item.get("anomaly_type", "other")),
                    description=str(item.get("description", "")),
                    severity=float(item.get("severity", 0.5)),
                    confidence=float(item.get("confidence", 0.5)),
                    dimension=str(item.get("dimension", "")),
                    baseline_value=str(item.get("baseline_value", "") or None),
                    observed_value=str(item.get("observed_value", "") or None),
                )
            )
        except (ValueError, TypeError):
            continue

    return anomalies
