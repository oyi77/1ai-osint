"""Behavioral Biometrics & Linguistic Fingerprinting — Phase 5 Pillar 2.

Analyzes writing style, vocabulary patterns, and posting behavior to produce
a behavioral fingerprint that can correlate identities across platforms without
requiring traditional PII.

All processing is local — no external API calls.
"""

from __future__ import annotations

import hashlib
import re
import statistics
from collections import Counter
from typing import Optional

from pydantic import BaseModel, Field


# Common function words (English) used as stylometric features
_FUNCTION_WORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "but",
        "or",
        "nor",
        "for",
        "yet",
        "so",
        "in",
        "on",
        "at",
        "to",
        "for",
        "of",
        "with",
        "by",
        "from",
        "as",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "shall",
        "can",
        "not",
        "no",
        "that",
        "this",
        "it",
        "he",
        "she",
        "they",
        "we",
        "you",
        "i",
        "me",
        "him",
        "her",
        "them",
    }
)


class PotentialMatch(BaseModel):
    """A potential cross-platform identity match based on behavioral similarity."""

    platform_a: str
    platform_b: str
    similarity_score: float  # [0.0, 1.0]
    evidence: list[str] = Field(default_factory=list)


class BehavioralFingerprint(BaseModel):
    """Behavioral/linguistic fingerprint of a subject."""

    subject_id: str = ""
    avg_sentence_length: float = 0.0
    type_token_ratio: float = 0.0  # vocabulary richness
    function_word_freq: dict[str, float] = Field(default_factory=dict)
    avg_word_length: float = 0.0
    punct_rate: float = 0.0  # punctuation per 100 chars
    capitals_rate: float = 0.0  # uppercase letters per 100 chars
    posting_hours: list[int] = Field(default_factory=lambda: [0] * 24)  # hour histogram
    estimated_timezone_offset: Optional[int] = None  # hours from UTC
    stylometric_hash: str = ""  # privacy-preserving fingerprint
    text_sample_count: int = 0


class LinguisticFingerprintAnalyzer:
    """Compute and compare behavioral fingerprints."""

    def analyze_texts(
        self, texts: list[str], subject_id: str = ""
    ) -> BehavioralFingerprint:
        """Analyze a list of text samples and produce a BehavioralFingerprint."""
        if not texts:
            return BehavioralFingerprint(subject_id=subject_id)

        all_sentences = []
        all_words: list[str] = []
        total_chars = 0
        total_punct = 0
        total_caps = 0

        for text in texts:
            sentences = re.split(r"[.!?]+", text)
            sentences = [s.strip() for s in sentences if s.strip()]
            all_sentences.extend(sentences)
            words = re.findall(r"[a-zA-Z']+", text)
            all_words.extend(words)
            total_chars += len(text)
            total_punct += sum(1 for c in text if c in ".,!?;:'\"()-")
            total_caps += sum(1 for c in text if c.isupper())

        # Sentence length
        sent_lengths = [len(re.findall(r"[a-zA-Z']+", s)) for s in all_sentences if s]
        avg_sentence_length = statistics.mean(sent_lengths) if sent_lengths else 0.0

        # Type-token ratio (vocabulary richness)
        lower_words = [w.lower() for w in all_words]
        type_token_ratio = len(set(lower_words)) / max(len(lower_words), 1)

        # Function word frequencies
        func_word_counts = Counter(w for w in lower_words if w in _FUNCTION_WORDS)
        total_words = max(len(lower_words), 1)
        function_word_freq = {
            w: func_word_counts.get(w, 0) / total_words
            for w in list(_FUNCTION_WORDS)[:20]
        }

        # Average word length
        avg_word_length = (
            statistics.mean([len(w) for w in all_words]) if all_words else 0.0
        )

        # Punctuation and caps rates
        punct_rate = (total_punct / max(total_chars, 1)) * 100
        capitals_rate = (total_caps / max(total_chars, 1)) * 100

        # Stylometric hash (rounded features for privacy)
        fingerprint_str = (
            f"{round(avg_sentence_length, 1)}|"
            f"{round(type_token_ratio, 2)}|"
            f"{round(avg_word_length, 1)}|"
            f"{round(punct_rate, 1)}"
        )
        stylometric_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

        return BehavioralFingerprint(
            subject_id=subject_id,
            avg_sentence_length=round(avg_sentence_length, 2),
            type_token_ratio=round(type_token_ratio, 3),
            function_word_freq={
                k: round(v, 4) for k, v in list(function_word_freq.items())[:15]
            },
            avg_word_length=round(avg_word_length, 2),
            punct_rate=round(punct_rate, 2),
            capitals_rate=round(capitals_rate, 2),
            stylometric_hash=stylometric_hash,
            text_sample_count=len(texts),
        )

    def analyze_with_timestamps(
        self, posts: list[dict], subject_id: str = ""
    ) -> BehavioralFingerprint:
        """Analyze posts with timestamp metadata for temporal patterns.

        Each post dict should have: text (str), hour (int 0-23, optional).
        """
        texts = [p.get("text", "") for p in posts if p.get("text")]
        fp = self.analyze_texts(texts, subject_id=subject_id)

        # Posting hour histogram
        hours = [
            p["hour"]
            for p in posts
            if isinstance(p.get("hour"), int) and 0 <= p["hour"] <= 23
        ]
        if hours:
            histogram = [0] * 24
            for h in hours:
                histogram[h] += 1
            fp.posting_hours = histogram
            fp.estimated_timezone_offset = self._estimate_timezone(histogram)

        return fp

    @staticmethod
    def _estimate_timezone(hour_histogram: list[int]) -> Optional[int]:
        """Estimate UTC timezone offset from posting hour histogram.

        Assumes people post most between 8am-11pm local time.
        Finds the hour with peak activity and estimates offset from UTC noon.
        """
        if not any(hour_histogram):
            return None
        peak_hour = hour_histogram.index(max(hour_histogram))
        # Assume peak activity around 8pm local (hour 20)
        offset = (20 - peak_hour) % 24
        if offset > 12:
            offset -= 24
        return int(offset)

    def compare_fingerprints(
        self, a: BehavioralFingerprint, b: BehavioralFingerprint
    ) -> float:
        """Compute similarity score between two fingerprints. Returns [0.0, 1.0]."""
        if not a or not b:
            return 0.0

        # Feature deltas (normalized)
        def norm_diff(x: float, y: float, scale: float = 1.0) -> float:
            return 1.0 - min(abs(x - y) / max(scale, 0.001), 1.0)

        sent_sim = norm_diff(a.avg_sentence_length, b.avg_sentence_length, scale=15.0)
        ttr_sim = norm_diff(a.type_token_ratio, b.type_token_ratio, scale=0.3)
        word_sim = norm_diff(a.avg_word_length, b.avg_word_length, scale=2.0)
        punct_sim = norm_diff(a.punct_rate, b.punct_rate, scale=5.0)
        caps_sim = norm_diff(a.capitals_rate, b.capitals_rate, scale=5.0)

        # Function word vector similarity (cosine-like)
        common_keys = set(a.function_word_freq) & set(b.function_word_freq)
        if common_keys:
            diffs = [
                abs(a.function_word_freq[k] - b.function_word_freq[k])
                for k in common_keys
            ]
            fw_sim = 1.0 - min(statistics.mean(diffs) * 20, 1.0)
        else:
            fw_sim = 0.5

        score = (
            0.20 * sent_sim
            + 0.20 * ttr_sim
            + 0.15 * word_sim
            + 0.15 * punct_sim
            + 0.10 * caps_sim
            + 0.20 * fw_sim
        )
        return round(min(max(score, 0.0), 1.0), 3)

    def cross_platform_correlation(
        self,
        profiles: dict[str, list[str]],
        threshold: float = 0.75,
    ) -> list[PotentialMatch]:
        """Identify potential cross-platform identity matches.

        Args:
            profiles: dict mapping platform_name -> list of text samples
            threshold: minimum similarity score to flag as potential match
        """
        platforms = list(profiles.keys())
        fingerprints = {
            p: self.analyze_texts(texts, subject_id=p) for p, texts in profiles.items()
        }

        matches = []
        for i, pa in enumerate(platforms):
            for pb in platforms[i + 1 :]:
                score = self.compare_fingerprints(fingerprints[pa], fingerprints[pb])
                if score >= threshold:
                    evidence = [
                        f"Stylometric similarity: {score:.1%}",
                        f"Type-token ratio: {fingerprints[pa].type_token_ratio:.3f} vs {fingerprints[pb].type_token_ratio:.3f}",
                        f"Avg sentence length: {fingerprints[pa].avg_sentence_length:.1f} vs {fingerprints[pb].avg_sentence_length:.1f}",
                    ]
                    matches.append(
                        PotentialMatch(
                            platform_a=pa,
                            platform_b=pb,
                            similarity_score=score,
                            evidence=evidence,
                        )
                    )

        return sorted(matches, key=lambda m: m.similarity_score, reverse=True)
