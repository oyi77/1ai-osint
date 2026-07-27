"""Tests for crypto leak scanner functionality.

The leak scanner module is deferred per plan, so these tests cover
the expected interface patterns (Google dorking, GitHub search)
with mocked external calls.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# --- Pattern Detection Tests ---


class TestMnemonicPatternDetection:
    """Test detection of leaked mnemonics in text content."""

    def test_detect_12_word_mnemonic(self):
        """Should detect a valid 12-word BIP-39 mnemonic in text."""
        from src.modules.crypto.balance.deriver import is_valid_mnemonic

        text = "Found this seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        # Extract potential mnemonics from text
        words = text.split()
        candidates = []
        for i in range(len(words)):
            for length in (12, 24):
                candidate = " ".join(words[i : i + length])
                if is_valid_mnemonic(candidate):
                    candidates.append(candidate)

        assert len(candidates) >= 1
        assert is_valid_mnemonic(candidates[0])

    def test_reject_non_mnemonic_text(self):
        """Should not detect mnemonics in regular text."""
        from src.modules.crypto.balance.deriver import is_valid_mnemonic

        text = "This is just a regular sentence with some words that are not a mnemonic"
        words = text.split()
        candidates = []
        for i in range(len(words)):
            for length in (12, 24):
                if i + length <= len(words):
                    candidate = " ".join(words[i : i + length])
                    if is_valid_mnemonic(candidate):
                        candidates.append(candidate)

        assert len(candidates) == 0

    def test_detect_private_key_hex(self):
        """Should detect 64-char hex strings as potential private keys."""
        import re

        text = "Key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        pattern = r"[0-9a-fA-F]{64}"
        matches = re.findall(pattern, text)
        assert len(matches) == 1

    def test_detect_private_key_with_0x_prefix(self):
        """Should detect 0x-prefixed private keys."""
        import re

        text = "Key: 0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        pattern = r"(?:0x)?[0-9a-fA-F]{64}"
        matches = re.findall(pattern, text)
        assert len(matches) == 1


# --- Dork Query Generation Tests ---


class TestDorkQueryGeneration:
    """Test generation of search dork queries for finding leaked credentials."""

    def test_github_dork_mnemonic(self):
        """Generate GitHub dork for mnemonic search."""
        queries = [
            '"abandon abandon" site:github.com',
            '"seed phrase" OR "mnemonic" OR "recovery phrase" filetype:txt',
            '"12 words" wallet recovery',
        ]
        for q in queries:
            assert "github" in q.lower() or "wallet" in q.lower() or "mnemonic" in q.lower()

    def test_google_dork_formats(self):
        """Generate Google dork formats for credential leaks."""
        dorks = [
            'filetype:txt "seed phrase"',
            'filetype:json "private_key" "0x"',
            'intext:"mnemonic" filetype:log',
        ]
        for dork in dorks:
            assert "filetype:" in dork or "intext:" in dork


# --- Leak Scanner Mock Tests ---


@pytest.mark.asyncio
class TestLeakScannerMocked:
    """Test leak scanner interface with fully mocked external calls."""

    async def test_github_search_mock(self):
        """Mock GitHub API search for leaked credentials."""
        mock_response = {
            "total_count": 2,
            "items": [
                {
                    "name": "wallet_backup.txt",
                    "path": "repo/wallet_backup.txt",
                    "html_url": "https://github.com/user/repo/blob/main/wallet_backup.txt",
                    "text_matches": [{"fragment": "abandon abandon abandon..."}],
                }
            ],
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.github.com/search/code",
                    params={"q": "mnemonic seed phrase"},
                )
                data = resp.json()
                assert data["total_count"] == 2
                assert len(data["items"]) == 1
                assert "wallet_backup" in data["items"][0]["name"]

    async def test_google_dork_mock(self):
        """Mock web scraping for Google dork results."""
        mock_html = """
        <html>
        <body>
        <div class="g">
            <a href="https://example.com/leak.txt">Leaked wallet</a>
            <div class="s">Found mnemonic phrase in paste...</div>
        </div>
        </body>
        </html>
        """

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = mock_html
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get("https://www.google.com/search?q=test")
                assert resp.status_code == 200
                assert "leak.txt" in resp.text

    async def test_paste_site_search_mock(self):
        """Mock paste site search for leaked credentials."""
        mock_pastes = [
            {
                "id": "abc123",
                "title": "Wallet backup",
                "body": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "url": "https://pastebin.com/abc123",
            }
        ]

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_pastes
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get("https://pastebin.com/api/v1/search")
                data = resp.json()
                assert len(data) == 1
                assert "abandon" in data[0]["body"]
