from src.modules.deep_scan.module_discovery import list_breach_modules, list_scan_modules, module_accepts


def test_lists_non_empty():
    mods = list_scan_modules()
    assert "social_osint" in mods
    assert "people_finder" in mods
    assert list_breach_modules()


def test_module_accepts_email():
    assert module_accepts("email_osint", "email") is True
    assert module_accepts("social_osint", "email") is False


def test_module_accepts_invalid_type():
    assert module_accepts("email_osint", "not_a_type") is False
