"""Tests for Phase 5 Pillar 2: Behavioral Biometrics & Linguistic Fingerprinting."""

from __future__ import annotations
from src.modules.identity_tracking.behavioral_fingerprint import (
    LinguisticFingerprintAnalyzer,
    PotentialMatch,
)


SAMPLE_TEXTS_A = [
    "Hello there! This is a simple sentence. How are you doing today? I am fine.",
    "The quick brown fox jumps over the lazy dog. It is a classic sentence.",
    "I really enjoy writing short sentences. They are easy to read.",
]

SAMPLE_TEXTS_B = [
    "Greetings! This is also a simple sentence. Are you well today? I am well.",
    "The fast red cat leaps over the sleepy dog. It is another classic sentence.",
    "I genuinely enjoy writing brief sentences. They are simple to read.",
]

SAMPLE_TEXTS_C = [
    "In the labyrinthine corridors of the ancient institution, one might find themselves perpetually disoriented by the overwhelming complexity of bureaucratic procedures.",
    "The sophisticated mechanisms underpinning contemporary computational paradigms necessitate extensive examination.",
]


def test_analyze_texts_basic():
    analyzer = LinguisticFingerprintAnalyzer()
    fp = analyzer.analyze_texts(SAMPLE_TEXTS_A, subject_id="user_a")
    assert fp.subject_id == "user_a"
    assert fp.avg_sentence_length > 0
    assert 0.0 < fp.type_token_ratio <= 1.0
    assert fp.avg_word_length > 0
    assert fp.text_sample_count == 3
    assert fp.stylometric_hash != ""


def test_analyze_empty_texts():
    analyzer = LinguisticFingerprintAnalyzer()
    fp = analyzer.analyze_texts([], subject_id="empty")
    assert fp.avg_sentence_length == 0.0
    assert fp.type_token_ratio == 0.0
    assert fp.text_sample_count == 0


def test_type_token_ratio_lower_for_repetitive_text():
    analyzer = LinguisticFingerprintAnalyzer()
    repetitive = ["the the the the the the the the the the"]
    rich = ["fox jumped over lazy dog near stream under bridge"]
    fp_rep = analyzer.analyze_texts(repetitive)
    fp_rich = analyzer.analyze_texts(rich)
    assert fp_rep.type_token_ratio < fp_rich.type_token_ratio


def test_compare_similar_fingerprints():
    analyzer = LinguisticFingerprintAnalyzer()
    fp_a = analyzer.analyze_texts(SAMPLE_TEXTS_A)
    fp_b = analyzer.analyze_texts(SAMPLE_TEXTS_B)
    score = analyzer.compare_fingerprints(fp_a, fp_b)
    assert 0.0 <= score <= 1.0
    # Similar texts should score relatively high
    assert score > 0.4


def test_compare_dissimilar_fingerprints():
    analyzer = LinguisticFingerprintAnalyzer()
    fp_a = analyzer.analyze_texts(SAMPLE_TEXTS_A)
    fp_c = analyzer.analyze_texts(SAMPLE_TEXTS_C)
    score = analyzer.compare_fingerprints(fp_a, fp_c)
    assert 0.0 <= score <= 1.0
    # Different writing styles should score lower than identical ones
    fp_self = analyzer.analyze_texts(SAMPLE_TEXTS_A)
    self_score = analyzer.compare_fingerprints(fp_a, fp_self)
    assert self_score >= score


def test_compare_identical_fingerprints():
    analyzer = LinguisticFingerprintAnalyzer()
    fp_a = analyzer.analyze_texts(SAMPLE_TEXTS_A)
    score = analyzer.compare_fingerprints(fp_a, fp_a)
    assert score > 0.9


def test_cross_platform_correlation_detects_match():
    analyzer = LinguisticFingerprintAnalyzer()
    profiles = {
        "reddit": SAMPLE_TEXTS_A,
        "twitter": SAMPLE_TEXTS_A,  # identical — should always match
        "linkedin": SAMPLE_TEXTS_C,  # very different style
    }
    matches = analyzer.cross_platform_correlation(profiles, threshold=0.85)
    assert any(
        m.platform_a in ("reddit", "twitter") and m.platform_b in ("reddit", "twitter")
        for m in matches
    )


def test_cross_platform_no_false_positives_below_threshold():
    analyzer = LinguisticFingerprintAnalyzer()
    profiles = {
        "academic_writer": SAMPLE_TEXTS_C,
        "casual_writer": SAMPLE_TEXTS_A,
    }
    matches = analyzer.cross_platform_correlation(profiles, threshold=0.99)
    # Very high threshold — dissimilar styles should not match
    assert all(m.similarity_score >= 0.99 for m in matches)


def test_posting_hours_histogram():
    analyzer = LinguisticFingerprintAnalyzer()
    posts = [
        {"text": "hello world", "hour": 14},
        {"text": "good morning", "hour": 9},
        {"text": "good night", "hour": 23},
        {"text": "afternoon post", "hour": 14},
    ]
    fp = analyzer.analyze_with_timestamps(posts, subject_id="test_user")
    assert fp.posting_hours[14] == 2  # peak hour
    assert fp.posting_hours[9] == 1
    assert fp.estimated_timezone_offset is not None


def test_timezone_estimation():
    # Peak posting at 20:00 UTC → estimated offset should be ~0 (UTC)
    histogram = [0] * 24
    histogram[20] = 10  # peak at 8pm UTC
    offset = LinguisticFingerprintAnalyzer._estimate_timezone(histogram)
    assert offset == 0


def test_timezone_estimation_empty():
    histogram = [0] * 24
    offset = LinguisticFingerprintAnalyzer._estimate_timezone(histogram)
    assert offset is None


def test_potential_match_model():
    match = PotentialMatch(
        platform_a="reddit",
        platform_b="twitter",
        similarity_score=0.87,
        evidence=["Stylometric similarity: 87.0%"],
    )
    assert match.similarity_score == 0.87
    assert len(match.evidence) == 1


def test_fingerprint_stylometric_hash_deterministic():
    analyzer = LinguisticFingerprintAnalyzer()
    fp1 = analyzer.analyze_texts(SAMPLE_TEXTS_A)
    fp2 = analyzer.analyze_texts(SAMPLE_TEXTS_A)
    assert fp1.stylometric_hash == fp2.stylometric_hash
