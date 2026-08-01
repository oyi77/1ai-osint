"""Unit tests for the source transport registry (0-API mode)."""

from src.core.source_registry import (
    _REGISTRY,
    can_run_keyless,
    key_env,
    keyless_source_names,
    kind_of,
    no_api_metrics,
    requires_key,
    transport_priority,
)


def test_kind_of_classifies_known_kinds() -> None:
    assert kind_of("crtsh") == "re"
    assert kind_of("duckduckgo") == "scrape"
    assert kind_of("dehashed") == "api"
    assert kind_of("nmap") == "tool"


def test_kind_of_unknown_defaults_to_api() -> None:
    assert kind_of("totally_unknown_source") == "api"


def test_requires_key() -> None:
    assert requires_key("dehashed")
    assert requires_key("leakcheck")
    assert requires_key("hibp")
    assert not requires_key("shodan")  # keyless InternetDB fallback
    assert not requires_key("etherscan")  # keyless public endpoint
    assert not requires_key("crtsh")
    assert not requires_key("social_osint")


def test_can_run_keyless() -> None:
    keyless = {
        "crtsh",
        "duckduckgo",
        "nmap",
        "social_osint",
        "crypto_balance",
        "shodan",
        "etherscan",
        "otx",
        "github",
    }
    for name in keyless:
        assert can_run_keyless(name), f"{name} should run keyless"
    for name in {"dehashed", "leakcheck", "snylla", "snusbase", "hibp", "intelx", "virustotal"}:
        assert not can_run_keyless(name), f"{name} must require a key"
    assert not can_run_keyless("totally_unknown_source")


def test_transport_priority_orders_re_first() -> None:
    # RE(0) < SCRAPE(1) < keyless API(2) < keyed API(3) < TOOL(4)
    assert transport_priority("crtsh") < transport_priority("duckduckgo")
    assert transport_priority("duckduckgo") < transport_priority("shodan")
    assert transport_priority("shodan") < transport_priority("dehashed")
    assert transport_priority("dehashed") < transport_priority("nmap")
    # Unknown defaults to the same tier as keyed APIs.
    assert transport_priority("totally_unknown_source") == transport_priority("dehashed")


def test_keyless_source_names() -> None:
    names = keyless_source_names()
    assert names
    assert "dehashed" not in names
    assert "leakcheck" not in names
    assert "crtsh" in names
    assert "shodan" in names
    # RE sources sort ahead of SCRAPE sources.
    assert names.index("crtsh") < names.index("duckduckgo")


def test_key_env() -> None:
    assert key_env("dehashed") == "DEHASHED_API_KEY"
    assert key_env("leakcheck") == "LEAKCHECK_API_KEY"
    assert key_env("crtsh") == ""
    assert key_env("totally_unknown_source") == ""


def test_no_api_metrics() -> None:
    metrics = no_api_metrics()
    assert metrics["total_sources"] == len(_REGISTRY) > 0
    assert metrics["keyless_capable"] > metrics["keyless_only"] > 0
