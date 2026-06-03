"""Tests for doctor health checks."""

from src.doctor import run_doctor


def test_doctor_runs():
    results = run_doctor()
    assert len(results) >= 5
    names = {r.name for r in results}
    assert "python" in names
