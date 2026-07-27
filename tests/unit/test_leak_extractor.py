"""Tests for the crypto key extractor."""

from unittest.mock import patch

from src.modules.crypto.leak_finder.extractor import (
    _BASE58_SOLANA_PATTERN,
    _HEX_KEY_PATTERN,
    _WIF_PATTERN,
    ExtractedKey,
    KeyType,
    _find_contextual_hex_keys,
    extract_keys,
)


class TestHexKeyExtraction:
    def test_contextual_hex_key_with_label(self):
        key_hex = "a" * 64
        text = f'PRIVATE_KEY="{key_hex}"'
        keys = extract_keys(text)
        hex_keys = [k for k in keys if k.key_type == KeyType.HEX_PRIVATE_KEY]
        assert len(hex_keys) == 1
        assert hex_keys[0].key_hex == key_hex.lower()

    def test_hex_key_with_0x_prefix(self):
        key_hex = "deadbeef" * 8
        text = f"secret_key: 0x{key_hex}"
        keys = extract_keys(text)
        hex_keys = [k for k in keys if k.key_type == KeyType.HEX_PRIVATE_KEY]
        assert len(hex_keys) >= 1
        assert hex_keys[0].key_hex == key_hex.lower()

    def test_standalone_hex_without_context_ignored(self):
        text = "SHA256 hash: " + "ab" * 32
        keys = extract_keys(text)
        hex_keys = [k for k in keys if k.key_type == KeyType.HEX_PRIVATE_KEY]
        assert len(hex_keys) == 0

    def test_hex_key_too_short_ignored(self):
        text = 'PRIVATE_KEY="abcdef1234567890"'
        keys = extract_keys(text)
        hex_keys = [k for k in keys if k.key_type == KeyType.HEX_PRIVATE_KEY]
        assert len(hex_keys) == 0

    def test_duplicate_hex_deduplicated(self):
        key_hex = "aa" * 32
        text = f'PRIVATE_KEY="{key_hex}"\nSECRET_KEY="{key_hex}"'
        keys = extract_keys(text)
        hex_keys = [k for k in keys if k.key_type == KeyType.HEX_PRIVATE_KEY]
        assert len(hex_keys) == 1


class TestWIFExtraction:
    def test_wif_pattern_matches_prefix_5(self):
        assert _WIF_PATTERN.search("5" + "H" * 50) is not None

    def test_wif_pattern_matches_prefix_K(self):
        assert _WIF_PATTERN.search("K" + "w" * 51) is not None

    def test_wif_pattern_matches_prefix_L(self):
        assert _WIF_PATTERN.search("L" + "1" * 50) is not None

    def test_wif_pattern_rejects_wrong_prefix(self):
        assert _WIF_PATTERN.search("A" + "H" * 50) is None


class TestBase58SolanaExtraction:
    def test_base58_solana_pattern_match(self):
        key = "2" + "a" * 86
        match = _BASE58_SOLANA_PATTERN.search(key)
        assert match is not None
        assert match.group(1) == key

    def test_base58_too_short_ignored(self):
        assert _BASE58_SOLANA_PATTERN.search("2" + "a" * 80) is None

    def test_base58_starts_with_1_ignored(self):
        assert _BASE58_SOLANA_PATTERN.search("1" + "a" * 86) is None


class TestMnemonicExtraction:
    @patch("src.modules.crypto.leak_finder.extractor._load_bip39_words")
    @patch("src.modules.crypto.leak_finder.extractor._validate_mnemonic")
    @patch("src.modules.crypto.leak_finder.extractor._derive_mnemonic_addresses")
    def test_12_word_mnemonic_extracted(self, mock_derive, mock_validate, mock_load):
        words = set("abandon ability able about above absent absorb abstract absurd abuse access accident".split())
        mock_load.return_value = words
        mock_validate.return_value = True
        mock_derive.return_value = {"Ethereum": "0x123"}
        mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        keys = extract_keys(mnemonic)
        mnemonic_keys = [k for k in keys if k.key_type == KeyType.MNEMONIC]
        assert len(mnemonic_keys) == 1
        assert mnemonic_keys[0].key_raw == mnemonic

    @patch("src.modules.crypto.leak_finder.extractor._load_bip39_words")
    def test_empty_wordlist_disables_mnemonic(self, mock_load):
        mock_load.return_value = set()
        text = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        keys = extract_keys(text)
        assert len([k for k in keys if k.key_type == KeyType.MNEMONIC]) == 0


class TestRegexPatterns:
    def test_hex_pattern_matches_64_chars(self):
        assert _HEX_KEY_PATTERN.search("a" * 64) is not None

    def test_hex_pattern_with_0x_prefix(self):
        assert _HEX_KEY_PATTERN.search("0x" + "b" * 64) is not None

    def test_hex_pattern_rejects_short(self):
        assert _HEX_KEY_PATTERN.search("a" * 63) is None

    def test_contextual_hex_key_detection(self):
        text = 'private_key="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"'
        results = _find_contextual_hex_keys(text)
        assert len(results) >= 1
        assert results[0][0] == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


class TestExtractedKey:
    def test_default_values(self):
        key = ExtractedKey(key_raw="test", key_type=KeyType.HEX_PRIVATE_KEY)
        assert key.key_hex is None
        assert key.derived_addresses == {}

    def test_with_addresses(self):
        key = ExtractedKey(
            key_raw="test",
            key_type=KeyType.MNEMONIC,
            derived_addresses={"Ethereum": "0x123", "Bitcoin": "bc1abc"},
        )
        assert len(key.derived_addresses) == 2
