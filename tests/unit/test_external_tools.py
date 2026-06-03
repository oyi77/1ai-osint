"""Tests for the external tool adapters (Sherlock, Maigret, theHarvester)."""

import os
import json
import csv
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone

from src.core.models import Finding
from src.modules.vendor.external_tools import ExternalToolIntel


class TestExternalToolIntel:
    @patch("shutil.which")
    def test_check_installed_tools(self, mock_which):
        # Case 1: All tools installed
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        intel = ExternalToolIntel()
        assert intel.has_sherlock is True
        assert intel.has_maigret is True
        assert intel.has_theharvester is True

        # Case 2: No tools installed
        mock_which.side_effect = lambda cmd: None
        intel2 = ExternalToolIntel()
        assert intel2.has_sherlock is False
        assert intel2.has_maigret is False
        assert intel2.has_theharvester is False

    @patch("shutil.which", return_value="/usr/bin/tool")
    @patch.object(ExternalToolIntel, "_run_sherlock", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_scan_username_sherlock(self, mock_sherlock, mock_which):
        mock_sherlock.return_value = [
            Finding(
                id="f1",
                title="GitHub Profile",
                description="Profile found",
                module="social_osint",
                timestamp=datetime.now(timezone.utc),
                raw_data={"platform": "github", "url": "https://github.com/user"},
            )
        ]
        intel = ExternalToolIntel()
        res = await intel.scan_username("user")
        assert res.module == "external_tools_username"
        assert len(res.findings) == 1
        assert res.findings[0].title == "GitHub Profile"
        mock_sherlock.assert_awaited_once_with("user")

    @patch("shutil.which")
    @patch.object(ExternalToolIntel, "_run_maigret", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_scan_username_maigret(self, mock_maigret, mock_which):
        # Case where sherlock is missing but maigret exists
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/maigret" if cmd == "maigret" else None
        )
        mock_maigret.return_value = [
            Finding(
                id="f2",
                title="Twitter Profile",
                description="Profile found",
                module="social_osint",
                timestamp=datetime.now(timezone.utc),
                raw_data={"platform": "twitter", "url": "https://twitter.com/user"},
            )
        ]
        intel = ExternalToolIntel()
        res = await intel.scan_username("user")
        assert len(res.findings) == 1
        assert res.findings[0].title == "Twitter Profile"
        mock_maigret.assert_awaited_once_with("user")

    @patch("shutil.which", return_value=None)
    @pytest.mark.asyncio
    async def test_scan_username_no_tools(self, mock_which):
        intel = ExternalToolIntel()
        res = await intel.scan_username("user")
        assert len(res.findings) == 0
        assert "No username OSINT tools installed" in res.error

    @patch("shutil.which", return_value="/usr/bin/theHarvester")
    @patch.object(ExternalToolIntel, "_run_theharvester", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_scan_domain(self, mock_harvester, mock_which):
        mock_harvester.return_value = [
            Finding(
                id="f3",
                title="Email Discovered: admin@example.com",
                description="Harvester email",
                module="domain_osint",
                timestamp=datetime.now(timezone.utc),
                raw_data={"type": "email", "address": "admin@example.com"},
            )
        ]
        intel = ExternalToolIntel()
        res = await intel.scan_domain("example.com")
        assert res.module == "external_tools_domain"
        assert len(res.findings) == 1
        assert "admin@example.com" in res.findings[0].title

    @patch("shutil.which", return_value=None)
    @pytest.mark.asyncio
    async def test_scan_domain_no_tools(self, mock_which):
        intel = ExternalToolIntel()
        res = await intel.scan_domain("example.com")
        assert len(res.findings) == 0
        assert "No domain OSINT tools installed" in res.error

    @patch("subprocess.run")
    @pytest.mark.asyncio
    async def test_run_sherlock_success(self, mock_run):
        intel = ExternalToolIntel()

        def mock_subprocess_run(cmd, **kwargs):
            tmpdir = cmd[4]
            username = cmd[1]
            csv_path = os.path.join(tmpdir, f"{username}.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "username_queried",
                        "site_name",
                        "url_main",
                        "url_user",
                        "exists",
                        "http_status",
                        "response_time_s",
                    ]
                )
                writer.writerow(
                    [
                        username,
                        "GitHub",
                        "https://github.com",
                        "https://github.com/test",
                        "yes",
                        "200",
                        "0.5",
                    ]
                )
                writer.writerow(
                    [
                        username,
                        "Twitter",
                        "https://twitter.com",
                        "https://twitter.com/test",
                        "no",
                        "404",
                        "0.2",
                    ]
                )

            mock_res = MagicMock()
            mock_res.returncode = 0
            return mock_res

        mock_run.side_effect = mock_subprocess_run
        findings = await intel._run_sherlock("test")
        assert len(findings) == 1
        assert findings[0].title == "GitHub Profile"
        assert findings[0].raw_data["platform"] == "github"
        assert findings[0].raw_data["url"] == "https://github.com/test"

    @patch("subprocess.run", side_effect=ValueError("Sherlock exception test"))
    @pytest.mark.asyncio
    async def test_run_sherlock_exception(self, mock_run):
        intel = ExternalToolIntel()
        findings = await intel._run_sherlock("test")
        assert len(findings) == 0

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_maigret_success(self, mock_exec):
        intel = ExternalToolIntel()

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_exec.return_value = mock_proc

        def mock_exec_side_effect(*args, **kwargs):
            tmpdir = args[5]
            username = args[1]
            json_path = os.path.join(tmpdir, f"report_{username}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        username: {
                            "GitLab": {
                                "url_user": "https://gitlab.com/test",
                                "status": "Found",
                            },
                            "FakeSite": {"status": "Missing"},
                        }
                    },
                    f,
                )
            return mock_proc

        mock_exec.side_effect = mock_exec_side_effect

        findings = await intel._run_maigret("test")
        assert len(findings) == 1
        assert findings[0].title == "GitLab Profile"
        assert findings[0].raw_data["platform"] == "gitlab"
        assert findings[0].raw_data["url"] == "https://gitlab.com/test"

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_maigret_timeout(self, mock_exec):
        intel = ExternalToolIntel()

        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        # Mock communicate to raise TimeoutError
        mock_proc.communicate.side_effect = asyncio.TimeoutError("timeout test")
        mock_exec.return_value = mock_proc

        findings = await intel._run_maigret("test")
        assert len(findings) == 0
        mock_proc.kill.assert_called_once()

    @patch(
        "asyncio.create_subprocess_exec",
        side_effect=RuntimeError("Maigret generic error"),
    )
    @pytest.mark.asyncio
    async def test_run_maigret_exception(self, mock_exec):
        intel = ExternalToolIntel()
        findings = await intel._run_maigret("test")
        assert len(findings) == 0

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_theharvester_success(self, mock_exec):
        intel = ExternalToolIntel()

        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_exec.return_value = mock_proc

        def mock_exec_side_effect(*args, **kwargs):
            json_path = args[6]
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "emails": ["info@domain.com", "sales@domain.com"],
                        "hosts": ["www.domain.com", "mail.domain.com"],
                    },
                    f,
                )
            return mock_proc

        mock_exec.side_effect = mock_exec_side_effect

        findings = await intel._run_theharvester("domain.com")
        assert len(findings) == 4
        emails = [f for f in findings if f.raw_data.get("type") == "email"]
        subdomains = [f for f in findings if f.raw_data.get("type") == "subdomain"]
        assert len(emails) == 2
        assert len(subdomains) == 2
        assert {e.raw_data["address"] for e in emails} == {
            "info@domain.com",
            "sales@domain.com",
        }
        assert {s.raw_data["hostname"] for s in subdomains} == {
            "www.domain.com",
            "mail.domain.com",
        }

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_theharvester_timeout(self, mock_exec):
        intel = ExternalToolIntel()

        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError("timeout test")
        mock_exec.return_value = mock_proc

        findings = await intel._run_theharvester("domain.com")
        assert len(findings) == 0
        mock_proc.kill.assert_called_once()

    @patch(
        "asyncio.create_subprocess_exec",
        side_effect=RuntimeError("theHarvester generic error"),
    )
    @pytest.mark.asyncio
    async def test_run_theharvester_exception(self, mock_exec):
        intel = ExternalToolIntel()
        findings = await intel._run_theharvester("domain.com")
        assert len(findings) == 0

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_socialanalyzer(self, mock_exec):
        intel = ExternalToolIntel()
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            json.dumps(
                [{"status": "found", "site": "Facebook", "url": "http"}]
            ).encode(),
            b"",
        )
        mock_exec.return_value = mock_proc
        findings = await intel._run_socialanalyzer("test")
        assert len(findings) == 1

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_ghunt(self, mock_exec):
        intel = ExternalToolIntel()
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            json.dumps({"profile_url": "http://google.com/test"}).encode(),
            b"",
        )
        mock_exec.return_value = mock_proc
        findings = await intel._run_ghunt("test")
        assert len(findings) == 1

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_leakosint(self, mock_exec):
        intel = ExternalToolIntel()
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            json.dumps({"leaks": [{"name": "breach1"}]}).encode(),
            b"",
        )
        mock_exec.return_value = mock_proc
        findings = await intel._run_leakosint("test")
        assert len(findings) == 1

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_webcheck(self, mock_exec):
        intel = ExternalToolIntel()
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            json.dumps({"ports": [80, 443]}).encode(),
            b"",
        )
        mock_exec.return_value = mock_proc
        findings = await intel._run_webcheck("test")
        assert len(findings) == 2

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_worldmonitor(self, mock_exec):
        intel = ExternalToolIntel()
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            json.dumps({"technologies": ["React", "Node"]}).encode(),
            b"",
        )
        mock_exec.return_value = mock_proc
        findings = await intel._run_worldmonitor("test")
        assert len(findings) == 2

    @patch("asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_run_crucix(self, mock_exec):
        intel = ExternalToolIntel()
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            json.dumps({"subdomains": ["api.test", "www.test"]}).encode(),
            b"",
        )
        mock_exec.return_value = mock_proc
        findings = await intel._run_crucix("test")
        assert len(findings) == 2
