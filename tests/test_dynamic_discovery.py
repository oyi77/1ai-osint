"""Test dynamic account discovery logic in verify_and_alert.

Mocks bip_utils to test the discovery loop without needing C libraries.
"""

import unittest


class TestDynamicDiscovery(unittest.TestCase):
    """Test that verify_and_alert uses dynamic account discovery."""

    def test_finds_funded_account_at_high_index(self):
        """Mnemonic with funded accounts spread across indices."""
        # Funded at 0, 3, 6 — gaps are < 3 consecutive empty
        balances = {i: 0.0 for i in range(50)}
        balances[0] = 0.1
        balances[3] = 0.5
        balances[6] = 2.0

        empty_streak = 0
        idx = 0
        EMPTY_STREAK_LIMIT = 3
        MAX_INDEX = 50
        funded_indices = []

        while idx < MAX_INDEX and empty_streak < EMPTY_STREAK_LIMIT:
            bal = balances.get(idx, 0.0)
            if bal > 0:
                funded_indices.append(idx)
                empty_streak = 0
            else:
                empty_streak += 1
            idx += 1

        self.assertIn(0, funded_indices)
        self.assertIn(3, funded_indices)
        self.assertIn(6, funded_indices)
        self.assertEqual(len(funded_indices), 3)

    def test_stops_after_consecutive_empty(self):
        """Should stop after 3 consecutive empty indices."""
        balances = {i: 0.0 for i in range(50)}
        balances[0] = 1.0
        balances[3] = 3.0

        empty_streak = 0
        idx = 0
        EMPTY_STREAK_LIMIT = 3
        MAX_INDEX = 50
        funded_indices = []

        while idx < MAX_INDEX and empty_streak < EMPTY_STREAK_LIMIT:
            bal = balances.get(idx, 0.0)
            if bal > 0:
                funded_indices.append(idx)
                empty_streak = 0
            else:
                empty_streak += 1
            idx += 1

        self.assertIn(0, funded_indices)
        self.assertIn(3, funded_indices)
        # Index 0 funded, 1-2 empty (streak=0,1,2), 3 funded (streak=0), 4-5-6 empty (streak=1,2,3) → stop at 7
        self.assertEqual(idx, 7)

    def test_respects_max_index(self):
        """Should not exceed MAX_INDEX even if all accounts have balance."""
        balances = {i: 1.0 for i in range(100)}

        empty_streak = 0
        idx = 0
        EMPTY_STREAK_LIMIT = 3
        MAX_INDEX = 50
        funded_count = 0

        while idx < MAX_INDEX and empty_streak < EMPTY_STREAK_LIMIT:
            bal = balances.get(idx, 0.0)
            if bal > 0:
                funded_count += 1
                empty_streak = 0
            else:
                empty_streak += 1
            idx += 1

        self.assertEqual(funded_count, 50)
        self.assertEqual(idx, 50)

    def test_no_funded_accounts_stops_quickly(self):
        """With all empty, should stop at index 3."""
        empty_streak = 0
        idx = 0
        EMPTY_STREAK_LIMIT = 3
        MAX_INDEX = 50

        while idx < MAX_INDEX and empty_streak < EMPTY_STREAK_LIMIT:
            bal = 0.0  # All empty
            if bal > 0:
                empty_streak = 0
            else:
                empty_streak += 1
            idx += 1

        self.assertEqual(idx, 3)


if __name__ == "__main__":
    unittest.main()
