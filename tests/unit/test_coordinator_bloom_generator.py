"""Tests for scanner_coordinator, bloom, and smart_generator modules."""

import pytest

from src.modules.crypto.balance.bloom import BloomFilter
from src.modules.crypto.balance.smart_generator import SmartMnemonicGenerator
from src.modules.crypto.balance.scanner_coordinator import ScannerCoordinator


# --- BloomFilter Tests ---


class TestBloomFilter:
    def test_add_and_check(self):
        bf = BloomFilter(capacity=100, error_rate=0.01)
        bf.add("hello")
        assert bf.check("hello") is True

    def test_check_missing(self):
        bf = BloomFilter(capacity=100, error_rate=0.01)
        bf.add("hello")
        # May produce false positive, but check should return a boolean
        result = bf.check("world")
        assert isinstance(result, bool)

    def test_empty_filter(self):
        bf = BloomFilter(capacity=100, error_rate=0.01)
        assert bf.check("anything") is False

    def test_multiple_adds(self):
        bf = BloomFilter(capacity=100, error_rate=0.01)
        items = ["item1", "item2", "item3", "item4", "item5"]
        for item in items:
            bf.add(item)
        for item in items:
            assert bf.check(item) is True

    def test_large_capacity(self):
        bf = BloomFilter(capacity=10000, error_rate=0.001)
        for i in range(100):
            bf.add(f"item-{i}")
        assert bf.check("item-50") is True
        assert bf.check("item-99") is True


# --- SmartMnemonicGenerator Tests ---


class TestSmartMnemonicGenerator:
    def test_init_defaults(self):
        gen = SmartMnemonicGenerator()
        assert gen is not None

    def test_generate_returns_string(self):
        gen = SmartMnemonicGenerator()
        mnemonic = gen.generate()
        assert isinstance(mnemonic, str)
        assert len(mnemonic.split()) >= 12

    def test_generate_multiple_unique(self):
        gen = SmartMnemonicGenerator()
        mnemonics = [gen.generate() for _ in range(5)]
        # Each should be unique
        assert len(set(mnemonics)) >= 4  # At least most should be unique

    def test_word_count(self):
        gen = SmartMnemonicGenerator()
        mnemonic = gen.generate()
        words = mnemonic.split()
        # Standard BIP-39 mnemonic lengths: 12, 15, 18, 21, 24
        assert len(words) in (12, 15, 18, 21, 24)


# --- ScannerCoordinator Tests ---


class TestScannerCoordinator:
    def test_init_defaults(self):
        coord = ScannerCoordinator(chains=[])
        assert coord is not None

    def test_hash_mnemonic_deterministic(self):
        hash1 = ScannerCoordinator.hash_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        hash2 = ScannerCoordinator.hash_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        assert hash1 == hash2

    def test_hash_mnemonic_different_inputs(self):
        hash1 = ScannerCoordinator.hash_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        hash2 = ScannerCoordinator.hash_mnemonic(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        )
        assert hash1 != hash2

    def test_hash_mnemonic_length(self):
        h = ScannerCoordinator.hash_mnemonic("test mnemonic phrase")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest
