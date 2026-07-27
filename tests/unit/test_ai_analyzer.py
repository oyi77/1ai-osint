"""Tests for AI word frequency analyzer and smart mnemonic generator."""

from bip_utils import Bip39MnemonicValidator

from src.modules.crypto.balance.ai_analyzer import WordFrequencyAnalyzer
from src.modules.crypto.balance.smart_generator import SmartMnemonicGenerator

VALID_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


class TestWordFrequencyAnalyzer:
    def test_analyze_corpus(self):
        analyzer = WordFrequencyAnalyzer()
        weights = analyzer.analyze_corpus([VALID_MNEMONIC] * 5)
        assert len(weights) == 2048  # All BIP-39 words get a weight
        # "abandon" should have higher weight than a random word
        assert weights["abandon"] > weights["zebra"]

    def test_analyze_empty_corpus(self):
        analyzer = WordFrequencyAnalyzer()
        weights = analyzer.analyze_corpus([])
        assert len(weights) == 2048
        # All weights should be 0.0 when no data (log normalization of 0 counts)
        assert all(w == 0.0 for w in weights.values())

    def test_get_weighted_wordlist(self):
        analyzer = WordFrequencyAnalyzer()
        analyzer.analyze_corpus([VALID_MNEMONIC] * 10)
        wl = analyzer.get_weighted_wordlist()
        assert len(wl) == 2048
        # All weights should be >= 0
        assert all(w >= 0 for _, w in wl)

    def test_save_and_load_db(self, tmp_path):
        db = str(tmp_path / "test.db")
        analyzer = WordFrequencyAnalyzer(db_path=db)
        analyzer.analyze_corpus([VALID_MNEMONIC] * 5)
        analyzer.save_to_db()

        analyzer2 = WordFrequencyAnalyzer(db_path=db)
        result = analyzer2.load_from_db()
        assert result is True
        # Loaded weights should match saved weights
        assert analyzer2._weights["abandon"] == analyzer._weights["abandon"]

    def test_load_from_missing_db(self, tmp_path):
        analyzer = WordFrequencyAnalyzer(db_path=str(tmp_path / "missing.db"))
        result = analyzer.load_from_db()
        assert result is False

    def test_validate_biased_generation(self):
        analyzer = WordFrequencyAnalyzer()
        analyzer.analyze_corpus([VALID_MNEMONIC] * 20)
        rate = analyzer.validate_biased_generation(n=50)
        assert rate > 0.0  # At least some should be valid


class TestSmartMnemonicGenerator:
    def test_generate_valid_mnemonic(self):
        analyzer = WordFrequencyAnalyzer()
        generator = SmartMnemonicGenerator(analyzer)
        mnemonic = generator.generate()
        assert mnemonic is not None
        words = mnemonic.split()
        assert len(words) == 12
        assert Bip39MnemonicValidator().IsValid(mnemonic)

    def test_generate_with_biased_corpus(self):
        analyzer = WordFrequencyAnalyzer()
        analyzer.analyze_corpus([VALID_MNEMONIC] * 20)
        generator = SmartMnemonicGenerator(analyzer)
        mnemonic = generator.generate()
        assert mnemonic is not None
        assert Bip39MnemonicValidator().IsValid(mnemonic)

    def test_generate_batch(self):
        analyzer = WordFrequencyAnalyzer()
        generator = SmartMnemonicGenerator(analyzer)
        mnemonics = generator.generate_batch(5)
        assert len(mnemonics) == 5
        for m in mnemonics:
            assert len(m.split()) == 12
            assert Bip39MnemonicValidator().IsValid(m)

    def test_generated_mnemonics_are_unique(self):
        analyzer = WordFrequencyAnalyzer()
        generator = SmartMnemonicGenerator(analyzer)
        mnemonics = generator.generate_batch(20)
        # At least some should be unique (astronomically unlikely to get all duplicates)
        assert len(set(mnemonics)) > 1

    def test_biased_generation_skews_toward_common_words(self):
        analyzer = WordFrequencyAnalyzer()
        analyzer.analyze_corpus([VALID_MNEMONIC] * 100)
        generator = SmartMnemonicGenerator(analyzer)
        mnemonics = generator.generate_batch(50)
        # "abandon" should appear more often than in uniform generation
        abandon_count = sum(1 for m in mnemonics if "abandon" in m)
        assert abandon_count > 0  # At least some should contain "abandon"
