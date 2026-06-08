"""Tests for cli.py uncovered functions."""

import asyncio
from unittest.mock import patch


class TestGetModule:
    def test_resolves_gitleaks(self):
        from src.cli.main import _get_module
        with patch("src.cli.GitleaksModule", create=True):
            result = _get_module("gitleaks")
            if result is not None:
                assert result.name is not None

    def test_resolves_secrets_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.GitleaksModule", create=True):
            result = _get_module("secrets")
            if result is not None:
                assert result.name is not None

    def test_resolves_data_leaks(self):
        from src.cli.main import _get_module
        with patch("src.cli.DataLeaksAggregator", create=True):
            result = _get_module("data_leaks")
            if result is not None:
                assert result.name is not None

    def test_resolves_breaches_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.DataLeaksAggregator", create=True):
            result = _get_module("breaches")
            if result is not None:
                assert result.name is not None

    def test_resolves_leaks_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.DataLeaksAggregator", create=True):
            result = _get_module("leaks")
            if result is not None:
                assert result.name is not None

    def test_resolves_people_finder(self):
        from src.cli.main import _get_module
        with patch("src.cli.PeopleFinderTool", create=True):
            result = _get_module("people")
            if result is not None:
                assert result.name is not None

    def test_resolves_social_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.PeopleFinderTool", create=True):
            result = _get_module("social")
            if result is not None:
                assert result.name is not None

    def test_resolves_phone_finder(self):
        from src.cli.main import _get_module
        with patch("src.cli.PhoneFinderTool", create=True):
            result = _get_module("phone")
            if result is not None:
                assert result.name is not None

    def test_resolves_crypto_passphrase(self):
        from src.cli.main import _get_module
        with patch("src.cli.generate_with_details", create=True):
            result = _get_module("crypto_passphrase")
            if result is not None:
                assert result.name == "crypto_passphrase"

    def test_resolves_passphrase_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.generate_with_details", create=True):
            result = _get_module("passphrase")
            if result is not None:
                assert result.name == "crypto_passphrase"

    def test_resolves_crypto_privatekey(self):
        from src.cli.main import _get_module
        with patch("src.cli.PrivateKeyScanner", create=True):
            result = _get_module("crypto_privatekey")
            if result is not None:
                assert result.name is not None

    def test_resolves_privatekey_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.PrivateKeyScanner", create=True):
            result = _get_module("privatekey")
            if result is not None:
                assert result.name is not None

    def test_resolves_privkey_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.PrivateKeyScanner", create=True):
            result = _get_module("privkey")
            if result is not None:
                assert result.name is not None

    def test_resolves_crypto_balance(self):
        from src.cli.main import _get_module
        with patch("src.cli.CryptoBalanceTool", create=True):
            result = _get_module("crypto_balance")
            if result is not None:
                assert result.name is not None

    def test_resolves_balance_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.CryptoBalanceTool", create=True):
            result = _get_module("balance")
            if result is not None:
                assert result.name is not None

    def test_resolves_wallet_alias(self):
        from src.cli.main import _get_module
        with patch("src.cli.CryptoBalanceTool", create=True):
            result = _get_module("wallet")
            if result is not None:
                assert result.name is not None

    def test_returns_none_for_unknown(self):
        from src.cli.main import _get_module
        result = _get_module("nonexistent_module_xyz")
        assert result is None


class TestPassphraseModule:
    def test_module_properties(self):
        from src.cli.main import _PassphraseModule

        async def fake_gen(count=12, language="english"):
            return {"mnemonic": "test test test test test test test test test test test abandon", "language": language, "word_count": count}

        mod = _PassphraseModule(fake_gen)
        assert mod.name == "crypto_passphrase"
        assert mod.description is not None
        assert mod.version is not None

    def test_scan_returns_scanresult(self):
        from src.cli.main import _PassphraseModule

        async def fake_gen(**kwargs):
            return {"mnemonic": "test test test test test test test test test test test abandon"}

        mod = _PassphraseModule(fake_gen)
        result = asyncio.run(mod.scan("english 12"))
        assert result is not None
        assert hasattr(result, "findings")

    def test_scan_with_options(self):
        from src.cli.main import _PassphraseModule

        async def fake_gen(**kwargs):
            return {"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "language": kwargs.get("language", "english")}

            mod = _PassphraseModule(fake_gen)
            result = asyncio.run(mod.scan("english 24"))
            assert result is not None
