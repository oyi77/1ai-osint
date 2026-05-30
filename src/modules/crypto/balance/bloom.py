"""Simple bloom filter for bounded-memory deduplication.

Uses multiple hash functions on a bit array. False positive rate
decreases with more bits and hash functions.

For 1M entries with 0.1% false positive rate: ~1.8MB memory.
For 10M entries with 1% false positive rate: ~12MB memory.
"""

from __future__ import annotations

import hashlib
import math
from typing import Optional


class BloomFilter:
    """Space-efficient probabilistic set for membership testing.

    Guarantees no false negatives (if item was added, contains() returns True).
    May have false positives (contains() may return True for items never added).
    """

    def __init__(self, expected_items: int = 1_000_000, fp_rate: float = 0.001):
        """Initialize bloom filter.

        Args:
            expected_items: Expected number of items to store.
            fp_rate: Desired false positive rate (0.0 to 1.0).
        """
        self._expected = expected_items
        self._fp_rate = fp_rate
        # Calculate optimal bit array size and hash count
        self._size = self._optimal_size(expected_items, fp_rate)
        self._hash_count = self._optimal_hash_count(self._size, expected_items)
        self._bits = bytearray(self._size // 8 + 1)
        self._count = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """Calculate optimal bit array size."""
        return int(-n * math.log(p) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        """Calculate optimal number of hash functions."""
        return max(1, int((m / n) * math.log(2)))

    def _hash_indices(self, item: str) -> list[int]:
        """Generate k hash indices for an item."""
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha256(item.encode()).hexdigest(), 16)
        return [(h1 + i * h2) % self._size for i in range(self._hash_count)]

    def add(self, item: str) -> None:
        """Add an item to the bloom filter."""
        for idx in self._hash_indices(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self._bits[byte_idx] |= (1 << bit_idx)
        self._count += 1

    def contains(self, item: str) -> bool:
        """Check if an item might be in the set.

        Returns True if item is PROBABLY in the set (may be false positive).
        Returns False if item is DEFINITELY NOT in the set.
        """
        for idx in self._hash_indices(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    @property
    def count(self) -> int:
        """Number of items added."""
        return self._count

    @property
    def estimated_fp_rate(self) -> float:
        """Estimated current false positive rate."""
        if self._count == 0:
            return 0.0
        return (1 - math.exp(-self._hash_count * self._count / self._size)) ** self._hash_count

    def clear(self) -> None:
        """Reset the filter."""
        self._bits = bytearray(self._size // 8 + 1)
        self._count = 0
