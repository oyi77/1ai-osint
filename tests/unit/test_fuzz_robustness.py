"""Robustness / property tests for pure, high-risk data-processing code.

These are dependency-free fuzz-style checks (seeded PRNG, no external
property-testing library) that pin down invariants an OSINT pipeline
cannot afford to violate on adversarial input:

* phone normalization must never raise and must be a fixed point;
* NIK validation must be total (bool for every input, no exceptions);
* NIK parsing may raise only documented ``ValueError``/``TypeError``;
* the inbound :class:`RequestLimiter` must never go negative and must
  never over-admit beyond its burst under concurrency.

Every test is deterministic and completes in well under 10 seconds.
"""

import asyncio
import random
import string

import pytest

from src.core.rate_limiter import RequestLimiter
from src.modules.deep_scan.extractor import _is_valid_nik, _parse_nik
from src.utils.phone_normalize import (
    ID_CARRIER_PREFIXES,
    lookup_id_carrier,
    normalize_phone_e164,
)

_SEED = 0xC0FFEE


def _garbage(rng: random.Random, max_len: int = 96) -> str:
    """Deterministic adversarial string: digits, ASCII, unicode, punctuation."""
    pools = [
        string.digits,
        string.ascii_letters,
        string.punctuation,
        string.whitespace,
        "éèêëàâäôöûüçñ€£¥§°µ©®™±",
        "汉字한국어ひらがな💥",
        "\x00\x01\x02\x07\x1b\x7f",
        "\ud800\udfff",  # lone surrogates
    ]
    kind = rng.randrange(len(pools) + 2)
    if kind < len(pools):
        pool = pools[kind]
        return "".join(rng.choice(pool) for _ in range(rng.randrange(0, max_len)))
    if kind == len(pools):
        return f"+{rng.randrange(10**11, 10**13)}"
    # Truncated international / double-zero edge
    return rng.choice(["+", "+0", "+00", "00", "0", "", "  ", "+62"])


# --------------------------------------------------------------------------
# normalize_phone_e164 — totality + fixed-point
# --------------------------------------------------------------------------


@pytest.mark.parametrize("round", range(8))
def test_normalize_phone_e164_never_raises_on_garbage(round: int) -> None:
    rng = random.Random(_SEED + round)
    for _ in range(400):
        raw = _garbage(rng)
        result = normalize_phone_e164(raw)
        assert result is None or (result.startswith("+") and result[1:].isdigit())


@pytest.mark.parametrize("round", range(8))
def test_normalize_phone_e164_fixed_point(round: int) -> None:
    """Normalization is idempotent except for the documented double-zero case."""
    rng = random.Random(_SEED + 1000 + round)
    for _ in range(400):
        raw = _garbage(rng)
        once = normalize_phone_e164(raw)
        if once is None or once[1:].startswith("00"):
            continue  # "00"-prefixed results are not a fixed point by design
        assert normalize_phone_e164(once) == once


def test_normalize_phone_e164_encoding_bombs() -> None:
    """Multi-megabyte, null-laden and non-UTF8-ish strings never crash it."""
    bombs = [
        "8" * 1_000_000,
        "\x00" * 1_000_000,
        "0" * 1_000_000,
        ("\x00\x00+" * 200_000),
        "\ud800" * 100_000,
        b"\xff\xfe\x00\x00" * 100_000,  # type: ignore[arg-type]
        b"1\x002\x00" * 100_000,  # type: ignore[arg-type]
    ]
    for bomb in bombs:
        result = normalize_phone_e164(bomb)  # type: ignore[arg-type]
        assert result is None or isinstance(result, str)


def test_lookup_id_carrier_garbage_safe() -> None:
    rng = random.Random(_SEED + 2000)
    known = set(ID_CARRIER_PREFIXES.values())
    for _ in range(2000):
        raw = _garbage(rng)
        assert lookup_id_carrier(raw) is None or lookup_id_carrier(raw) in known


# --------------------------------------------------------------------------
# NIK validation / parsing — totality + documented-exceptions-only
# --------------------------------------------------------------------------


@pytest.mark.parametrize("round", range(8))
def test_is_valid_nik_is_total(round: int) -> None:
    """_is_valid_nik must return a bool for every conceivable string."""
    rng = random.Random(_SEED + 3000 + round)
    for _ in range(400):
        raw = _garbage(rng, max_len=32)
        assert isinstance(_is_valid_nik(raw), bool)


def test_is_valid_nik_non_digit_16_char_is_false() -> None:
    # Regression: previously raised ValueError from int() on non-digit input.
    assert _is_valid_nik("A" * 16) is False
    assert _is_valid_nik("1234567890ABCDEF") is False
    assert _is_valid_nik("12345678901234 5") is False


def test_is_valid_nik_borderline_ranges() -> None:
    assert _is_valid_nik("1101990101990001") is True  # province 11
    assert _is_valid_nik("9901990101990001") is True  # province 99
    assert _is_valid_nik("1001990101990001") is False  # province 10 (below min)
    assert _is_valid_nik("1200990101990001") is False  # city 00 (below min)
    assert _is_valid_nik("1299990101990001") is True  # city 99
    assert _is_valid_nik("120199010199000") is False  # 15 digits
    assert _is_valid_nik("12019901019900012") is False  # 17 digits


def test_parse_nik_only_documented_exceptions() -> None:
    rng = random.Random(_SEED + 4000)
    for _ in range(800):
        raw = _garbage(rng, max_len=32)
        try:
            parsed = _parse_nik(raw)
        except (ValueError, TypeError):
            continue
        except Exception as exc:  # pragma: no cover - failure path
            pytest.fail(f"_parse_nik({raw!r}) raised unexpected {type(exc).__name__}: {exc}")
        else:
            # If it did not raise, the shape must still be complete.
            assert set(parsed) >= {
                "province_code",
                "city_code",
                "region_code",
                "birth_day",
                "birth_month",
                "birth_year",
                "gender",
            }
            assert parsed["gender"] in ("male", "female")


def test_parse_nik_valid_roundtrip() -> None:
    nik = "3201255101010001"  # female (day 51 -> 11), born 2001-01-01, West Java
    parsed = _parse_nik(nik)
    assert parsed == {
        "province_code": "32",
        "city_code": "01",
        "region_code": "25",
        "birth_day": 11,
        "birth_month": 1,
        "birth_year": 2001,
        "gender": "female",
    }
    # Consistent with validation: any NIK _is_valid_nik accepts must parse.
    rng = random.Random(_SEED + 5000)
    for _ in range(200):
        digits = "".join(rng.choice(string.digits) for _ in range(16))
        if _is_valid_nik(digits):
            assert isinstance(_parse_nik(digits), dict)


# --------------------------------------------------------------------------
# RequestLimiter — token-bucket invariants under load
# --------------------------------------------------------------------------


def test_request_limiter_serial_drain_exact_burst() -> None:
    limiter = RequestLimiter(requests_per_minute=60, burst=30)
    allowed = sum(1 for _ in range(35) if limiter.allow())
    # 35 back-to-back calls complete in microseconds; refill (< 1 token) is
    # impossible, so exactly `burst` may pass.
    assert allowed == 30


def test_request_limiter_never_negative_tokens() -> None:
    limiter = RequestLimiter(requests_per_minute=1, burst=2)
    for _ in range(200):
        limiter.allow()
        for tokens, _last in limiter._buckets.values():
            assert tokens >= -1e-9


def test_request_limiter_concurrent_no_over_admission() -> None:
    async def storm() -> int:
        limiter = RequestLimiter(requests_per_minute=60, burst=30)

        async def probe() -> bool:
            # Interleave at the event loop so arrivals mimic concurrent
            # requests; allow() itself is synchronous and atomic (no await
            # points), so buckets cannot be corrupted mid-call.
            await asyncio.sleep(0)
            return limiter.allow()

        results = await asyncio.gather(*(probe() for _ in range(1000)))
        allowed = sum(1 for r in results if r)
        assert all(isinstance(r, bool) for r in results)
        # No token bucket may ever hold a negative balance.
        for tokens, _last in limiter._buckets.values():
            assert tokens >= -1e-9
        return allowed

    allowed = asyncio.run(storm())
    # 1000 arrivals on the same tick admit at most `burst`; keep +1 slack
    # for scheduler granularity on slow CI runners.
    assert allowed <= 31


def test_request_limiter_edge_construction() -> None:
    for rpm, burst in ((0, 0), (0, 1), (1, 0), (-5, -5)):
        limiter = RequestLimiter(requests_per_minute=rpm, burst=burst)
        assert limiter.rate > 0.0
        assert limiter.burst >= 1
        assert limiter.allow() in (True, False)
        limiter.reset("x")
        limiter.reset()
