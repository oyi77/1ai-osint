from src.utils.phone_normalize import normalize_phone_e164


def test_indonesia_local_to_e164():
    assert normalize_phone_e164("081234567890") == "+6281234567890"


def test_already_international():
    assert normalize_phone_e164("+14155552671") == "+14155552671"


def test_empty_and_short():
    assert normalize_phone_e164("") is None
    assert normalize_phone_e164("12345") is None
    assert normalize_phone_e164("1234567") is None


def test_double_zero_prefix():
    assert normalize_phone_e164("0044123456789") == "+44123456789"
