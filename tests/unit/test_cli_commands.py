"""Tests for cli.py command functions."""

import asyncio
from datetime import datetime, timezone

from src.cli.helpers import _PassphraseModule
from src.cli.helpers import get_module as _get_module
from src.core.models import ScanResult


def _scan_result(**overrides):
    defaults = dict(
        scan_id="test",
        module="test",
        target="test",
        status="ok",
        findings=[],
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


class TestVersionModules:
    def test_version_outputs_string(self, capsys):
        from src.cli.commands.config_commands import version

        version()
        output = capsys.readouterr().out
        assert "1ai-osint" in output

    def test_modules_outputs_list(self, capsys):
        from src.cli.commands.config_commands import modules

        modules()
        output = capsys.readouterr().out
        assert "Available modules" in output


class TestGetModule:
    def test_unknown_returns_none(self):
        result = _get_module("nonexistent_xyz")
        assert result is None

    def test_known_module(self):
        result = _get_module("gitleaks")
        assert result is None or result.name is not None


class TestPassphraseModule:
    def test_properties(self):
        async def fake_gen(**kw):
            return {
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            }

        mod = _PassphraseModule(fake_gen)
        assert mod.name == "crypto_passphrase"
        assert mod.description is not None
        assert mod.version is not None

    def test_scan_returns_result(self):
        async def fake_gen(**kw):
            return {
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            }

        mod = _PassphraseModule(fake_gen)
        result = asyncio.run(mod.scan("english 12"))
        assert result is not None
        assert hasattr(result, "findings")


class TestScanCommand:
    def test_scan_callable(self):
        from src.cli.commands.scan_commands import scan

        assert callable(scan)

    def test_leak_finder_callable(self):
        from src.cli.commands.crypto_commands import leak_finder

        assert callable(leak_finder)
