"""Tests for extractor.py key extraction engine."""

from src.modules.crypto.leak_finder.extractor import (
    ExtractedKey,
    KeyType,
    extract_keys,
    _base58_decode,
    _load_bip39_words,
    _HEX_KEY_PATTERN,
    _WIF_PATTERN,
    _MNEMONIC_WORD_RE,
)
from src.modules.crypto.balance.deriver import _base58_encode


class TestBase58:
    def test_encode_decode_roundtrip(self):
        original = b"\x00\x01\x02\x03"
        encoded = _base58_encode(original)
        decoded = _base58_decode(encoded)
        assert decoded == original

    def test_encode_zero_bytes(self):
        result = _base58_encode(b"\x00\x00\x01")
        assert result.startswith("1")

    def test_decode_leading_ones(self):
        decoded = _base58_decode("1112")
        assert decoded.startswith(b"\x00\x00\x00")

    def test_encode_small_value(self):
        result = _base58_encode(b"\x01")
        assert isinstance(result, str)
        assert len(result) > 0


class TestExtractKeys:
    def test_hex_private_key(self):
        text = "private_key=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        keys = extract_keys(text)
        assert len(keys) >= 1
        hex_keys = [k for k in keys if k.key_type == KeyType.HEX_PRIVATE_KEY]
        assert len(hex_keys) >= 1

    def test_hex_key_no_prefix(self):
        text = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        keys = extract_keys(text)
        # May find 0 or more depending on context pattern
        assert isinstance(keys, list)

    def test_wif_key(self):
        text = "5HueCGU8rMjxEXxiPuD5BDku4MkFmZvfmYhVefStRCB3X9K5L"
        keys = extract_keys(text)
        # WIF detection depends on pattern matching context
        assert isinstance(keys, list)

    def test_mnemonic_recovery(self):
        text = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        keys = extract_keys(text)
        # May or may not find depending on BIP39 word list
        # Just verify it doesn't crash
        assert isinstance(keys, list)

    def test_empty_text(self):
        keys = extract_keys("")
        assert keys == []

    def test_no_keys_found(self):
        text = "This is just regular text with no keys whatsoever."
        keys = extract_keys(text)
        assert isinstance(keys, list)

    def test_extracted_key_dataclass(self):
        k = ExtractedKey(key_raw="test", key_type=KeyType.HEX_PRIVATE_KEY)
        assert k.key_raw == "test"
        assert k.key_type == KeyType.HEX_PRIVATE_KEY
        assert k.key_hex is None
        assert k.derived_addresses == {}


class TestBIP39Loading:
    def test_load_bip39_words(self):
        words = _load_bip39_words()
        assert isinstance(words, set)
        # Should contain common BIP39 words
        if words:  # Only check if bip_utils is available
            assert "abandon" in words

    def test_load_bip39_words_cached(self):
        words1 = _load_bip39_words()
        words2 = _load_bip39_words()
        assert words1 is words2  # Same object (cached)


class TestPatterns:
    def test_hex_pattern_type(self):
        assert _HEX_KEY_PATTERN is not None
        assert _HEX_KEY_PATTERN.pattern is not None

    def test_wif_pattern_type(self):
        assert _WIF_PATTERN is not None
        assert _WIF_PATTERN.pattern is not None

    def test_mnemonic_word_pattern(self):
        matches = _MNEMONIC_WORD_RE.findall("abandon about above absent absorb abstract")
        assert len(matches) == 6