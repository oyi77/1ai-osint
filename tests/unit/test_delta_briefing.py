from src.modules.deep_scan.delta_briefing import compute_intel_delta


def test_delta_new_evidence():
    prev = {"evidence": [{"identifier_value": "old@x.com"}], "briefing": {"subject": {"emails": ["old@x.com"], "known_handles": []}, "breach_records": []}}
    curr = {
        "evidence": [{"identifier_value": "old@x.com"}, {"identifier_value": "new@y.com"}],
        "briefing": {"subject": {"emails": ["old@x.com", "new@y.com"], "known_handles": ["h1"]}, "breach_records": [{"a": 1}]},
    }
    d = compute_intel_delta(prev, curr)
    assert d["new_evidence_count"] == 1
    assert "new@y.com" in d["new_emails"]
    assert d["breach_delta"] == 1
