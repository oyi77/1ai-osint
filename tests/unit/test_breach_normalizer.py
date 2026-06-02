from src.modules.deep_scan.breach_normalizer import normalize_breach_record


def test_normalize_email_and_breach():
    raw = {"user_email": "a@b.com", "database": "ExampleLeak", "passwd": "secret"}
    out = normalize_breach_record(raw)
    assert out["email"] == "a@b.com"
    assert out["breach_name"] == "ExampleLeak"
    assert out["password"] == "secret"
