"""Tests for deep scan collection profiles."""

from src.modules.deep_scan.scan_profiles import resolve_scan_profile


def test_fast_profile():
    p = resolve_scan_profile("fast")
    assert p.name == "fast"
    assert p.fast_mode is True
    assert "social_osint" in p.modules


def test_deep_profile_more_iterations_than_fast():
    fast = resolve_scan_profile("fast")
    deep = resolve_scan_profile("deep")
    assert deep.max_iterations > fast.max_iterations
    assert "email_osint" in deep.modules


def test_unknown_profile_raises():
    try:
        resolve_scan_profile("invalid")
        assert False
    except ValueError:
        pass
