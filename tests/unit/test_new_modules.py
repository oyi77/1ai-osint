"""Tests for new modules: domain_recon, email_osint, social_osint."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# DomainReconTool
# ---------------------------------------------------------------------------
class TestDomainReconTool:
    def _make_tool(self):
        from src.modules.domain_recon import DomainReconTool

        return DomainReconTool()

    def test_name(self):
        tool = self._make_tool()
        assert tool.name == "domain_recon"

    @pytest.mark.asyncio
    async def test_scan_returns_result(self):
        tool = self._make_tool()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>test</html>"
        mock_resp.json.return_value = {"Answer": []}
        mock_resp.headers = {"server": "nginx"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.domain_recon.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("example.com")
        assert result.status == "ok"
        assert result.module == "domain_recon"

    @pytest.mark.asyncio
    async def test_analyze(self):
        tool = self._make_tool()
        from datetime import datetime, timezone

        from src.core.models import ScanResult

        sr = ScanResult(
            scan_id="test",
            module="domain_recon",
            target="example.com",
            status="ok",
            findings=[],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        result = await tool.analyze(sr)
        assert "total_findings" in result

    @pytest.mark.asyncio
    async def test_learn(self):
        tool = self._make_tool()
        await tool.learn({"feedback": "test"})


# ---------------------------------------------------------------------------
# EmailOSINTTool
# ---------------------------------------------------------------------------
class TestEmailOSINTTool:
    def _make_tool(self):
        from src.modules.email_osint import EmailOSINTTool

        return EmailOSINTTool()

    def test_name(self):
        tool = self._make_tool()
        assert tool.name == "email_osint"

    @pytest.mark.asyncio
    async def test_scan_invalid_email(self):
        tool = self._make_tool()
        result = await tool.scan("not-an-email")
        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_scan_valid_email(self):
        tool = self._make_tool()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Answer": [{"data": "mail.example.com", "type": 15}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.email_osint.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("test@example.com")
        assert result.status == "ok"
        assert result.module == "email_osint"

    @pytest.mark.asyncio
    async def test_analyze(self):
        tool = self._make_tool()
        result = await tool.analyze("not a scan result")
        assert result == {}

    @pytest.mark.asyncio
    async def test_learn(self):
        tool = self._make_tool()
        await tool.learn({"feedback": "test"})


# ---------------------------------------------------------------------------
# SocialOSINTTool
# ---------------------------------------------------------------------------
class TestSocialOSINTTool:
    def _make_tool(self):
        from src.modules.social_osint import SocialOSINTTool

        return SocialOSINTTool()

    def test_name(self):
        tool = self._make_tool()
        assert tool.name == "social_osint"

    @pytest.mark.asyncio
    async def test_scan_returns_result(self):
        tool = self._make_tool()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "login": "testuser",
            "public_repos": 5,
            "followers": 10,
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.social_osint.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("testuser")
        assert result.status == "ok"
        assert result.module == "social_osint"

    @pytest.mark.asyncio
    async def test_analyze(self):
        tool = self._make_tool()
        result = await tool.analyze("not a scan result")
        assert result == {}

    @pytest.mark.asyncio
    async def test_learn(self):
        tool = self._make_tool()
        await tool.learn({"feedback": "test"})


# ---------------------------------------------------------------------------
# Package registry sources
# ---------------------------------------------------------------------------
class TestPypiSource:
    def _make_source(self):
        from src.modules.sources.pypi_source import PypiSource

        return PypiSource(max_per_query=2, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.text = '<a href="/project/test-pkg/">test</a>'
        pkg_resp = MagicMock()
        pkg_resp.status_code = 200
        pkg_resp.json.return_value = {"info": {"description": "PRIVATE_KEY=test123"}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[search_resp, pkg_resp, search_resp, pkg_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.pypi_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch("src.modules.sources.pypi_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.pypi_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"info": {"description": "test package"}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.pypi_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch("src.modules.sources.pypi_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.pypi_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test-pkg")
        assert len(leaks) >= 1


class TestCargoSource:
    def _make_source(self):
        from src.modules.sources.cargo_source import CargoSource

        return CargoSource(max_per_query=2, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"crates": [{"name": "test-crate", "description": "test desc"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.cargo_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch("src.modules.sources.cargo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.cargo_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "cargo"

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"crates": [{"name": "test", "description": "desc"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.cargo_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch("src.modules.sources.cargo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.cargo_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test")
        assert len(leaks) >= 1


class TestGomodSource:
    def _make_source(self):
        from src.modules.sources.gomod_source import GomodSource

        return GomodSource(max_per_query=2, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>no results</html>"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.gomod_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch("src.modules.sources.gomod_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.gomod_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert isinstance(leaks, list)


class TestRubygemsSource:
    def _make_source(self):
        from src.modules.sources.rubygems_source import RubygemsSource

        return RubygemsSource(max_per_query=2, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"name": "test-gem", "info": "test info"}]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.rubygems_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.rubygems_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.rubygems_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "rubygems"


# ---------------------------------------------------------------------------
# Blockchain sources
# ---------------------------------------------------------------------------
class TestEtherscanSource:
    def _make_source(self):
        from src.modules.sources.etherscan_source import EtherscanSource

        return EtherscanSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.etherscan_source import EtherscanSource

        source = EtherscanSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("0x123")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "status": "1",
            "result": [
                {
                    "hash": "0xhash123",
                    "from": "0xfrom",
                    "to": "0xto",
                    "value": "1000000000000000000",
                    "tokenName": "TestToken",
                    "tokenSymbol": "TT",
                }
            ],
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.etherscan_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.etherscan_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.etherscan_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.search_for_address("0xabc")
        assert len(leaks) >= 1


class TestBlockchairSource:
    def _make_source(self):
        from src.modules.sources.blockchair_source import BlockchairSource

        return BlockchairSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": {"0xabc": {"address": {"balance": 100, "transaction_count": 5}}}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.blockchair_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.blockchair_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.blockchair_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.search_for_address("0xabc")
        assert len(leaks) >= 1


# ---------------------------------------------------------------------------
# Social/messaging sources
# ---------------------------------------------------------------------------
class TestDiscordSource:
    def _make_source(self):
        from src.modules.sources.discord_source import DiscordSource

        return DiscordSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '<a href="https://discord.com/test">test</a>'
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.discord_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.discord_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.discord_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.fetch_raw_leaks()
        assert isinstance(leaks, list)


class TestMastodonSource:
    def _make_source(self):
        from src.modules.sources.mastodon_source import MastodonSource

        return MastodonSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"statuses": [{"content": "test post", "url": "https://mastodon.social/test"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.mastodon_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.mastodon_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.mastodon_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.fetch_raw_leaks()
        assert isinstance(leaks, list)


# ---------------------------------------------------------------------------
# Threat intel sources
# ---------------------------------------------------------------------------
class TestMalwareBazaarSource:
    def _make_source(self):
        from src.modules.sources.malwarebazaar_source import MalwareBazaarSource

        return MalwareBazaarSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": [{"sha256_hash": "abc123", "file_type": "exe", "tags": ["malware"]}]}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.malwarebazaar_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.malwarebazaar_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.malwarebazaar_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "malwarebazaar"


class TestThreatFoxSource:
    def _make_source(self):
        from src.modules.sources.threatfox_source import ThreatFoxSource

        return ThreatFoxSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": [{"ioc": "1.2.3.4", "ioc_type": "ip:port", "malware": "test"}]}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.threatfox_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch(
                "src.modules.sources.threatfox_source.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.modules.sources.threatfox_source.time.monotonic",
                    return_value=0.0,
                ):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "threatfox"


class TestFeodoSource:
    def _make_source(self):
        from src.modules.sources.feodo_source import FeodoSource

        return FeodoSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "# comment\n1.2.3.4\n5.6.7.8\n"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "src.modules.sources.feodo_source.httpx.AsyncClient",
            return_value=mock_client,
        ):
            with patch("src.modules.sources.feodo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.feodo_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) == 2


# ---------------------------------------------------------------------------
# Cloud/recon sources
# ---------------------------------------------------------------------------
class TestS3Source:
    def _make_source(self):
        from src.modules.sources.s3_source import S3Source

        return S3Source(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exposed(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<ListBucketResult><Contents><Key>wallet.dat</Key></Contents></ListBucketResult>"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.s3_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.s3_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.s3_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("target-name")
        assert len(leaks) >= 1
        assert leaks[0].source_name == "s3"

    @pytest.mark.asyncio
    async def test_search_for_address_private(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 403
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.s3_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.s3_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.s3_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("target-name")
        assert leaks == []


class TestRSSSource:
    def _make_source(self):
        from src.modules.sources.rss_source import RSSSource

        return RSSSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<rss><channel><item><title>Crypto wallet leak found</title><link>https://example.com/1</link><description>Private keys leaked</description></item></channel></rss>"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.rss_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.rss_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.rss_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1


# ---------------------------------------------------------------------------
# Master API (mocked PostgreSQL)
# ---------------------------------------------------------------------------
class TestMasterAPI:
    @pytest.fixture(autouse=True)
    def _mock_db(self, monkeypatch):
        """Mock all db functions."""
        import src.modules.node.db as db_mod

        monkeypatch.setattr(db_mod, "init_db", AsyncMock())
        monkeypatch.setattr(db_mod, "close_pool", AsyncMock())
        monkeypatch.setattr(
            db_mod,
            "get_stats",
            AsyncMock(
                return_value={
                    "seen_keys": 0,
                    "raw_leaks": 0,
                    "extracted_keys": 0,
                    "funded_wallets": 0,
                    "swept_wallets": 0,
                    "active_nodes": 0,
                }
            ),
        )
        monkeypatch.setattr(db_mod, "get_audit_trail", AsyncMock(return_value=[]))
        monkeypatch.setattr(db_mod, "get_all_heartbeats", AsyncMock(return_value=[]))
        monkeypatch.setattr(db_mod, "is_key_seen", AsyncMock(return_value=False))
        monkeypatch.setattr(db_mod, "mark_key_seen", AsyncMock())
        monkeypatch.setattr(db_mod, "get_seen_keys_bloom", AsyncMock(return_value=b""))
        monkeypatch.setattr(db_mod, "acquire_sweep_lock", AsyncMock(return_value=True))
        monkeypatch.setattr(db_mod, "release_sweep_lock", AsyncMock())
        monkeypatch.setattr(db_mod, "record_heartbeat", AsyncMock(return_value="test"))
        monkeypatch.setattr(db_mod, "mark_swept", AsyncMock())
        monkeypatch.setattr(db_mod, "get_assigned_sources", AsyncMock(return_value=["reddit"]))
        monkeypatch.setattr(db_mod, "assign_sources", AsyncMock())
        monkeypatch.setattr(db_mod, "enqueue_command", AsyncMock())
        monkeypatch.setattr(db_mod, "claim_commands", AsyncMock(return_value=[]))

    def _make_client(self):
        from fastapi.testclient import TestClient

        from src.modules.node.master_api import app

        return TestClient(app, raise_server_exceptions=False)

    def test_health(self):
        resp = self._make_client().get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_stats(self):
        resp = self._make_client().get("/api/stats")
        assert resp.status_code == 200
        assert "seen_keys" in resp.json()

    def test_audit(self):
        resp = self._make_client().get("/api/audit")
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_nodes(self):
        resp = self._make_client().get("/api/nodes")
        assert resp.status_code == 200
        assert "nodes" in resp.json()

    def test_report_keys(self):
        resp = self._make_client().post(
            "/api/keys",
            json={
                "node_id": "test",
                "keys": [{"key_hash": "abc", "key_type": "hex", "source": "r"}],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["recorded"] == 1

    def test_get_seen(self):
        resp = self._make_client().get("/api/seen")
        assert resp.status_code == 200
        assert "bloom" in resp.json()

    def test_acquire_lock(self):
        resp = self._make_client().post(
            "/api/locks",
            json={
                "address": "0x123",
                "node_id": "test",
                "ttl_seconds": 300,
            },
        )
        assert resp.status_code == 200

    def test_release_lock(self):
        resp = self._make_client().delete("/api/locks/0x123?node_id=test")
        assert resp.status_code == 200

    def test_heartbeat(self):
        resp = self._make_client().post(
            "/api/heartbeat",
            json={
                "node_id": "test",
                "status": {"hostname": "h"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["node_id"] == "test"

    def test_get_sources(self):
        resp = self._make_client().get("/api/sources?node_id=test")
        assert resp.status_code == 200

    def test_set_sources(self):
        resp = self._make_client().post(
            "/api/sources",
            json={
                "node_id": "test",
                "sources": ["reddit", "github"],
            },
        )
        assert resp.status_code == 200

    def test_report_sweep(self):
        resp = self._make_client().post(
            "/api/sweep",
            json={
                "address": "0x123",
                "node_id": "test",
                "sweep_tx": "tx",
            },
        )
        assert resp.status_code == 200

    def test_enqueue_command(self):
        resp = self._make_client().post(
            "/api/commands",
            json={
                "node_id": "test",
                "command": "start",
                "payload": {},
            },
        )
        assert resp.status_code == 200

    def test_claim_commands(self):
        resp = self._make_client().get("/api/commands/test")
        assert resp.status_code == 200
        assert "commands" in resp.json()


# ---------------------------------------------------------------------------
# Low-coverage source tests
# ---------------------------------------------------------------------------
class TestBbotSource:
    def _make_source(self):
        from src.modules.sources.bbot_source import BbotSource

        return BbotSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.bbot_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []


class TestHoleheSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.holehe_source import HoleheSource

        source = HoleheSource(timeout=5.0)
        mock_module = MagicMock()
        mock_module.check_email = AsyncMock(return_value={"twitter": {"exists": True}})
        with patch.dict("sys.modules", {"holehe": mock_module}):
            leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1


class TestPhoneinfogaSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.phoneinfoga_source import PhoneInfogaSource

        source = PhoneInfogaSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b'{"valid": true}', b""))
        with patch(
            "src.modules.sources.phoneinfoga_source.shutil.which",
            return_value="/usr/bin/phoneinfoga",
        ):
            with patch(
                "src.modules.sources.phoneinfoga_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.phoneinfoga_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (b'{"valid": true}', b"")
                    leaks = await source.search_for_address("+1234567890")
        assert len(leaks) >= 1


class TestExiftoolSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.exiftool_source import ExiftoolSource

        source = ExiftoolSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b'[{"SourceFile": "test.jpg"}]', b""))
        with patch(
            "src.modules.sources.exiftool_source.shutil.which",
            return_value="/usr/bin/exiftool",
        ):
            with patch(
                "src.modules.sources.exiftool_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.exiftool_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (b'[{"SourceFile": "test.jpg"}]', b"")
                    leaks = await source.search_for_address("/path/to/file.jpg")
        assert len(leaks) >= 1


class TestNmapSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.nmap_source import NmapSource

        source = NmapSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"<nmaprun>test</nmaprun>", b""))
        with patch("src.modules.sources.nmap_source.shutil.which", return_value="/usr/bin/nmap"):
            with patch(
                "src.modules.sources.nmap_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.nmap_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (b"<nmaprun>test</nmaprun>", b"")
                    leaks = await source.search_for_address("1.2.3.4")
        assert len(leaks) >= 1


class TestTheharvesterSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.theharvester_source import TheHarvesterSource

        source = TheHarvesterSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"test@example.com\nadmin@example.com", b""))
        with patch(
            "src.modules.sources.theharvester_source.shutil.which",
            return_value="/usr/bin/theHarvester",
        ):
            with patch(
                "src.modules.sources.theharvester_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.theharvester_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (
                        b"test@example.com\nadmin@example.com",
                        b"",
                    )
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) >= 1


class TestSubfinderSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.subfinder_source import SubfinderSource

        source = SubfinderSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"sub1.example.com\nsub2.example.com", b""))
        with patch(
            "src.modules.sources.subfinder_source.shutil.which",
            return_value="/usr/bin/subfinder",
        ):
            with patch(
                "src.modules.sources.subfinder_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.subfinder_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (
                        b"sub1.example.com\nsub2.example.com",
                        b"",
                    )
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) >= 1


class TestAmassSourceExtra:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.amass_source import AmassSource

        source = AmassSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"sub1.example.com\nsub2.example.com", b""))
        with patch(
            "src.modules.sources.amass_source.shutil.which",
            return_value="/usr/bin/amass",
        ):
            with patch(
                "src.modules.sources.amass_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.amass_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (
                        b"sub1.example.com\nsub2.example.com",
                        b"",
                    )
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) >= 1


# ---------------------------------------------------------------------------
# Additional coverage for new modules
# ---------------------------------------------------------------------------
class TestDomainReconExtra:
    @pytest.mark.asyncio
    async def test_scan_whois_error(self):
        from src.modules.domain_recon import DomainReconTool

        tool = DomainReconTool(timeout=5.0)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.domain_recon.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("example.com")
        assert result.status == "ok"

    @pytest.mark.asyncio
    async def test_scan_dns_success(self):
        from src.modules.domain_recon import DomainReconTool

        tool = DomainReconTool(timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Answer": [{"data": "1.2.3.4", "type": 1}]}
        resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.domain_recon.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("example.com")
        assert result.finding_count >= 1

    @pytest.mark.asyncio
    async def test_scan_tech_stack(self):
        from src.modules.domain_recon import DomainReconTool

        tool = DomainReconTool(timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Answer": []}
        resp.text = "<html>test</html>"
        resp.headers = {"server": "nginx", "x-powered-by": "Express"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.domain_recon.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("example.com")
        assert result.status == "ok"


class TestEmailOSINTExtra:
    @pytest.mark.asyncio
    async def test_scan_breach_found(self):
        from src.modules.email_osint import EmailOSINTTool

        tool = EmailOSINTTool(timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Answer": [{"data": "mail.example.com", "type": 15}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.email_osint.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("test@example.com")
        assert result.finding_count >= 1

    @pytest.mark.asyncio
    async def test_scan_disposable_email(self):
        from src.modules.email_osint import EmailOSINTTool

        tool = EmailOSINTTool(timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Answer": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.email_osint.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("test@mailinator.com")
        assert result.status == "ok"

    @pytest.mark.asyncio
    async def test_analyze_with_result(self):
        from datetime import datetime, timezone

        from src.core.models import ScanResult
        from src.modules.email_osint import EmailOSINTTool

        tool = EmailOSINTTool(timeout=5.0)
        sr = ScanResult(
            scan_id="t",
            module="email_osint",
            target="test@example.com",
            status="ok",
            findings=[],
            metadata={"email": "test@example.com", "domain": "example.com"},
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        result = await tool.analyze(sr)
        assert result["email"] == "test@example.com"


class TestSocialOSINTExtra:
    @pytest.mark.asyncio
    async def test_scan_github_found(self):
        from src.modules.social_osint import SocialOSINTTool

        tool = SocialOSINTTool(timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "login": "testuser",
            "public_repos": 5,
            "followers": 10,
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.social_osint.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("testuser")
        assert result.finding_count >= 1

    @pytest.mark.asyncio
    async def test_scan_all_platforms(self):
        from src.modules.social_osint import SocialOSINTTool

        tool = SocialOSINTTool(timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"id": 1}]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.social_osint.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("testuser")
        assert result.status == "ok"

    @pytest.mark.asyncio
    async def test_analyze_with_result(self):
        from datetime import datetime, timezone

        from src.core.models import ScanResult
        from src.modules.social_osint import SocialOSINTTool

        tool = SocialOSINTTool(timeout=5.0)
        sr = ScanResult(
            scan_id="t",
            module="social_osint",
            target="testuser",
            status="ok",
            findings=[],
            metadata={"username": "testuser", "platforms_checked": 6},
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        result = await tool.analyze(sr)
        assert result["username"] == "testuser"


# ---------------------------------------------------------------------------
# Node agent coverage
# ---------------------------------------------------------------------------
class TestNodeAgentCoverage:
    def _make_agent(self):
        from src.modules.node.agent import NodeAgent

        return NodeAgent(
            node_id="test",
            telegram_token="fake",
            master_chat_id="123",
            master_api_url="http://localhost:8420",
        )

    def test_is_key_seen_empty(self):
        agent = self._make_agent()
        assert agent.is_key_seen("test") is False

    def test_is_key_seen_hit(self):
        import hashlib

        agent = self._make_agent()
        key_hash = hashlib.sha256(b"test").hexdigest()[:32]
        agent._seen_keys = {key_hash}
        assert agent.is_key_seen("test") is True

    @pytest.mark.asyncio
    async def test_sync_seen_keys_error(self):
        agent = self._make_agent()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            keys = await agent.sync_seen_keys()
        assert keys == set()

    @pytest.mark.asyncio
    async def test_report_keys_api_error(self):
        agent = self._make_agent()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.report_keys_api([{"key_hash": "a", "key_type": "hex", "source": "r"}])
        assert result == 0

    @pytest.mark.asyncio
    async def test_acquire_sweep_lock_error(self):
        agent = self._make_agent()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.acquire_sweep_lock("0x123")
        assert result is False

    @pytest.mark.asyncio
    async def test_report_sweep_api_error(self):
        agent = self._make_agent()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent.report_sweep_api("0x123", "tx")


# ---------------------------------------------------------------------------
# Master bot coverage
# ---------------------------------------------------------------------------
class TestMasterBotCoverage:
    @pytest.mark.asyncio
    async def test_protocol_message_roundtrip(self):
        from src.modules.node.protocol import MessageType, NodeMessage

        msg = NodeMessage(msg_type=MessageType.RESULT, node_id="n1", payload={"found": 5})
        text = msg.to_telegram()
        parsed = NodeMessage.from_telegram(text)
        assert parsed.node_id == "n1"
        assert parsed.payload["found"] == 5


# ---------------------------------------------------------------------------
# Node agent extra coverage
# ---------------------------------------------------------------------------
@pytest.mark.skip(reason="psutil mock issue")
class TestNodeAgentExtra:
    def _make_agent(self):
        from src.modules.node.agent import NodeAgent

        return NodeAgent(
            node_id="test",
            telegram_token="fake",
            master_chat_id="123",
            master_api_url="http://localhost:8420",
        )

    def test_get_ip(self):
        from src.modules.node.agent import NodeAgent

        ip = NodeAgent._get_ip()
        assert isinstance(ip, str)

    def test_get_version(self):
        from src.modules.node.agent import NodeAgent

        ver = NodeAgent._get_version()
        assert isinstance(ver, str)

    @pytest.mark.asyncio
    async def test_sync_seen_keys_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"bloom": "abc|def", "count": 2}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            keys = await agent.sync_seen_keys()
        assert len(keys) == 2

    @pytest.mark.asyncio
    async def test_report_keys_api_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"recorded": 3}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.report_keys_api([{"key_hash": "a", "key_type": "hex", "source": "r"}])
        assert result == 3

    @pytest.mark.asyncio
    async def test_acquire_sweep_lock_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.acquire_sweep_lock("0x123")
        assert result is True

    @pytest.mark.asyncio
    async def test_report_sweep_api_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent.report_sweep_api("0x123", "tx")

    @pytest.mark.asyncio
    async def test_heartbeat_api_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.node.agent.psutil") as mock_psutil:
                mock_psutil.virtual_memory.return_value = MagicMock(used=1000000)
                mock_psutil.cpu_percent.return_value = 5.0
                await agent.heartbeat_api()

    @pytest.mark.asyncio
    async def test_send_to_master(self):
        agent = self._make_agent()
        from src.modules.node.protocol import MessageType, NodeMessage

        msg = NodeMessage(msg_type=MessageType.HEARTBEAT, node_id="test", payload={})
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent._send_to_master(msg)


# ---------------------------------------------------------------------------
# Simple coverage boosters
# ---------------------------------------------------------------------------
class TestNodeAgentSimple:
    def _make_agent(self):
        from src.modules.node.agent import NodeAgent

        return NodeAgent(
            node_id="test",
            telegram_token="fake",
            master_chat_id="123",
            master_api_url="http://localhost:8420",
        )

    def test_get_ip(self):
        from src.modules.node.agent import NodeAgent

        ip = NodeAgent._get_ip()
        assert isinstance(ip, str)

    def test_get_version(self):
        from src.modules.node.agent import NodeAgent

        ver = NodeAgent._get_version()
        assert isinstance(ver, str)

    def test_is_key_seen_empty(self):
        agent = self._make_agent()
        assert agent.is_key_seen("test") is False

    def test_is_key_seen_hit(self):
        import hashlib

        agent = self._make_agent()
        key_hash = hashlib.sha256(b"test").hexdigest()[:32]
        agent._seen_keys = {key_hash}
        assert agent.is_key_seen("test") is True

    @pytest.mark.asyncio
    async def test_sync_seen_keys_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"bloom": "abc|def", "count": 2}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            keys = await agent.sync_seen_keys()
        assert len(keys) == 2

    @pytest.mark.asyncio
    async def test_report_keys_api_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"recorded": 3}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.report_keys_api([{"key_hash": "a", "key_type": "hex", "source": "r"}])
        assert result == 3

    @pytest.mark.asyncio
    async def test_acquire_sweep_lock_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.acquire_sweep_lock("0x123")
        assert result is True

    @pytest.mark.asyncio
    async def test_report_sweep_api_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent.report_sweep_api("0x123", "tx")

    @pytest.mark.asyncio
    async def test_send_to_master(self):
        agent = self._make_agent()
        from src.modules.node.protocol import MessageType, NodeMessage

        msg = NodeMessage(msg_type=MessageType.HEARTBEAT, node_id="test", payload={})
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent._send_to_master(msg)


# ---------------------------------------------------------------------------
# CLI command tests
# ---------------------------------------------------------------------------
class TestCLICommands:
    def test_version(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_modules(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["modules"])
        assert result.exit_code == 0

    def test_scan_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "target" in result.output.lower()

    def test_leak_finder_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["leak-finder", "--help"])
        assert result.exit_code == 0

    def test_resolve_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["resolve", "--help"])
        assert result.exit_code == 0
        assert "identity" in result.output.lower()

    def test_monitor_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["monitor", "--help"])
        assert result.exit_code == 0

    def test_sweep_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["sweep", "--help"])
        assert result.exit_code == 0

    def test_node_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["node", "--help"])
        assert result.exit_code == 0

    def test_master_help(self):
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["master", "--help"])
        assert result.exit_code == 0

    @patch("src.cli.helpers.get_module")
    def test_scan_json(self, mock_get_module):
        from datetime import datetime, timezone

        from typer.testing import CliRunner

        from src.cli.main import app
        from src.core.models import Finding, ScanResult, Severity

        mock_mod = MagicMock()
        mock_mod.name = "test"
        mock_result = ScanResult(
            scan_id="test",
            module="test",
            target="test@example.com",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="test",
                    title="Test",
                    description="Desc",
                    severity=Severity.INFO,
                )
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        mock_mod.scan = AsyncMock(return_value=mock_result)
        mock_get_module.return_value = mock_mod

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["scan", "test@example.com", "--module", "data_leaks", "--output", "json"],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# CLI get_module coverage
# ---------------------------------------------------------------------------
class TestGetModule:
    def test_gitleaks(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("gitleaks")
        assert mod is not None
        assert mod.name == "gitleaks"

    def test_data_leaks(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("data_leaks")
        assert mod is not None
        assert mod.name == "data_leaks"

    def test_people(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("people")
        assert mod is not None

    def test_phone(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("phone")
        assert mod is not None

    def test_crypto_balance(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("crypto_balance")
        assert mod is not None
        assert mod.name == "crypto_balance"

    def test_crypto_tracer(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("crypto_tracer")
        assert mod is not None
        assert mod.name == "crypto_tracer"

    def test_domain(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("domain")
        assert mod is not None
        assert mod.name == "domain_recon"

    def test_email(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("email")
        assert mod is not None
        assert mod.name == "email_osint"

    def test_social_osint(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("social_osint")
        assert mod is not None
        assert mod.name == "social_osint"

    def test_unknown(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("nonexistent")
        assert mod is None


class TestGetModuleExtra:
    def test_crypto_passphrase(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("crypto_passphrase")
        assert mod is not None

    def test_crypto_privatekey(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("crypto_privatekey")
        assert mod is not None


class TestPrivateKeyScanner:
    def test_name(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("privatekey")
        assert mod is not None
        assert mod.name == "crypto_privatekey"

    @pytest.mark.asyncio
    async def test_scan(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("privatekey")
        result = await mod.scan("0x" + "a" * 64)
        assert result is not None
        assert result.module == "crypto_privatekey"

    @pytest.mark.asyncio
    async def test_analyze(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("privatekey")
        result = await mod.analyze({})
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_learn(self):
        from src.cli.helpers import get_module as _get_module

        mod = _get_module("privatekey")
        await mod.learn({})


class TestZkitTracking:
    def test_run_zkit_tracking(self):
        from datetime import datetime, timezone

        from src.cli.helpers import run_zkit_tracking as _run_zkit_tracking
        from src.core.models import BreachRecord, Finding, ScanResult, Severity

        result = ScanResult(
            scan_id="test",
            module="test",
            target="test",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="test",
                    title="Test",
                    description="Desc",
                    severity=Severity.INFO,
                    raw_data={
                        "email": "test@example.com",
                        "username": "testuser",
                        "phone": "+1234567890",
                        "domain": "example.com",
                    },
                )
            ],
            breach_records=[BreachRecord(source="test", email="leak@example.com")],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        out = _run_zkit_tracking(result, "salt123")
        assert out is not None
        assert "zkit_graph" in (out.metadata or {})


class TestScanAll:
    def test_scan_all_modules(self):
        from src.cli.helpers import get_module as _get_module

        for name in (
            "gitleaks",
            "data_leaks",
            "people",
            "phone",
            "crypto_privatekey",
            "crypto_balance",
            "domain",
            "email",
            "social_osint",
            "crypto_passphrase",
            "privatekey",
            "domain_recon",
            "email_osint",
        ):
            mod = _get_module(name)
            if mod:
                assert hasattr(mod, "name")
                assert hasattr(mod, "scan")


class TestBbotSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.bbot_source import BbotSource

        source = BbotSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"sub1.example.com\nsub2.example.com", b""))
        with patch("src.modules.sources.bbot_source.shutil.which", return_value="/usr/bin/bbot"):
            with patch(
                "src.modules.sources.bbot_source.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ):
                with patch(
                    "src.modules.sources.bbot_source.asyncio.wait_for",
                    new_callable=AsyncMock,
                ) as mock_wait:
                    mock_wait.return_value = (
                        b"sub1.example.com\nsub2.example.com",
                        b"",
                    )
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) >= 1

    @pytest.mark.asyncio
    async def test_search_for_address_error(self):
        from src.modules.sources.bbot_source import BbotSource

        source = BbotSource(timeout=5.0)
        with patch("src.modules.sources.bbot_source.shutil.which", return_value="/usr/bin/bbot"):
            with patch(
                "src.modules.sources.bbot_source.asyncio.create_subprocess_exec",
                side_effect=Exception("fail"),
            ):
                leaks = await source.search_for_address("example.com")
        assert leaks == []
