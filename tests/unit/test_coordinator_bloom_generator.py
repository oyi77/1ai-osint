"""Tests for scanner_coordinator, bloom, and smart_generator modules."""

from src.modules.crypto.balance.bloom import BloomFilter
from src.modules.crypto.balance.scanner_coordinator import ScannerCoordinator
from src.modules.crypto.balance.smart_generator import SmartMnemonicGenerator

# --- BloomFilter Tests ---


class TestBloomFilter:
    def test_add_and_check(self):
        bf = BloomFilter(expected_items=100, fp_rate=0.01)
        bf.add("hello")
        assert bf.contains("hello") is True

    def test_check_missing(self):
        bf = BloomFilter(expected_items=100, fp_rate=0.01)
        bf.add("hello")
        # May produce false positive, but check should return a boolean
        result = bf.contains("world")
        assert isinstance(result, bool)

    def test_empty_filter(self):
        bf = BloomFilter(expected_items=100, fp_rate=0.01)
        assert bf.contains("anything") is False

    def test_multiple_adds(self):
        bf = BloomFilter(expected_items=100, fp_rate=0.01)
        items = ["item1", "item2", "item3", "item4", "item5"]
        for item in items:
            bf.add(item)
        for item in items:
            assert bf.contains(item) is True

    def test_large_capacity(self):
        bf = BloomFilter(expected_items=10000, fp_rate=0.001)
        for i in range(100):
            bf.add(f"item-{i}")
        assert bf.contains("item-50") is True
        assert bf.contains("item-99") is True


# --- SmartMnemonicGenerator Tests ---


class TestSmartMnemonicGenerator:
    def _make_gen(self):
        from src.modules.crypto.balance.ai_analyzer import WordFrequencyAnalyzer

        analyzer = WordFrequencyAnalyzer()
        return SmartMnemonicGenerator(analyzer)

    def test_init_defaults(self):
        gen = self._make_gen()
        assert gen is not None

    def test_generate_returns_string(self):
        gen = self._make_gen()
        mnemonic = gen.generate()
        assert isinstance(mnemonic, str)
        assert len(mnemonic.split()) >= 12

    def test_generate_multiple_unique(self):
        gen = self._make_gen()
        mnemonics = [gen.generate() for _ in range(5)]
        assert len(set(mnemonics)) >= 4

    def test_word_count(self):
        gen = self._make_gen()
        mnemonic = gen.generate()
        words = mnemonic.split()
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
        hash2 = ScannerCoordinator.hash_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
        assert hash1 != hash2

    def test_hash_mnemonic_length(self):
        h = ScannerCoordinator.hash_mnemonic("test mnemonic phrase")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest
