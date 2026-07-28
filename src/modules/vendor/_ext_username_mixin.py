"""Username-specific external OSINT tool mixin.

Sherlock, Maigret, Social-Analyzer, GHUNT, LeakOSINT.
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone

from src.core.models import Finding

logger = logging.getLogger(__name__)


class ExternalToolUsernameMixin:
    """Mixin providing username-focused external tool runners."""

    async def _run_command(self, cmd: list[str], timeout: float = 180.0) -> bytes:
        """Run an external command — provided by ExternalToolCoordinator."""
        raise NotImplementedError  # pragma: no cover

    async def _run_sherlock(self, username: str) -> list[Finding]:
        """Execute Sherlock and parse CSV output."""
        import shutil
        import subprocess

        findings = []
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, f"{username}.csv")

            sherlock_bin = shutil.which("sherlock") or "sherlock"

            cmd = [
                sherlock_bin,
                username,
                "--csv",
                "--folderoutput",
                tmpdir,
                "--no-txt",
            ]

            try:
                logger.info("Running Sherlock for %s...", username)

                # Run synchronously in a thread to avoid pipe buffer deadlocks
                def run_cmd():
                    return subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=180.0,
                    )

                await asyncio.to_thread(run_cmd)

                if os.path.exists(csv_path):
                    with open(csv_path, encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            site_name = row.get("name") or row.get("site_name") or "Unknown"
                            is_claimed = row.get("exists", "").lower() in (
                                "yes",
                                "claimed",
                            )
                            if is_claimed or row.get("http_status") == "200":
                                platform = site_name.lower()
                                url = row.get("url_user", "")
                                if url:
                                    findings.append(
                                        Finding(
                                            id=uuid.uuid4().hex,
                                            title=f"{site_name} Profile",
                                            description=f"Discovered active profile on {site_name}",
                                            module="social_osint",
                                            timestamp=datetime.now(timezone.utc),
                                            raw_data={
                                                "type": "social_account",
                                                "platform": platform,
                                                "url": url,
                                                "username": username,
                                                "source": "sherlock",
                                            },
                                        )
                                    )
            except Exception as e:
                logger.error("Sherlock execution failed: %s", e)

        return findings

    async def _run_maigret(self, username: str) -> list[Finding]:
        """Execute Maigret and parse JSON output."""
        findings = []
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ["maigret", username, "--json", "simple", "--folderoutput", tmpdir]

            try:
                logger.info("Running Maigret for %s...", username)
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    await asyncio.wait_for(process.communicate(), timeout=180.0)
                except asyncio.TimeoutError:
                    process.kill()

                for f in os.listdir(tmpdir):
                    if f.endswith(".json"):
                        with open(os.path.join(tmpdir, f), encoding="utf-8") as jf:
                            data = json.load(jf)
                            user_data = data.get(username, {})
                            for site, info in user_data.items():
                                if info.get("status") == "Found" or "url_user" in info:
                                    url = info.get("url_user")
                                    if url:
                                        findings.append(
                                            Finding(
                                                id=uuid.uuid4().hex,
                                                title=f"{site} Profile",
                                                description=f"Discovered active profile on {site}",
                                                module="social_osint",
                                                timestamp=datetime.now(timezone.utc),
                                                raw_data={
                                                    "type": "social_account",
                                                    "platform": site.lower(),
                                                    "url": url,
                                                    "username": username,
                                                    "source": "maigret",
                                                },
                                            )
                                        )
            except Exception as e:
                logger.error("Maigret execution failed: %s", e)

        return findings

    async def _run_socialanalyzer(self, username: str) -> list[Finding]:
        """Execute Social-Analyzer and parse output."""
        findings = []
        cmd = ["social-analyzer", "--username", username, "--output", "json"]
        try:
            logger.info("Running Social-Analyzer for %s...", username)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    for entry in data:
                        if entry.get("status") == "found":
                            findings.append(
                                Finding(
                                    id=uuid.uuid4().hex,
                                    title=f"Social-Analyzer: {entry.get('site')} Profile",
                                    description=f"Discovered active profile on {entry.get('site')}",
                                    module="social_osint",
                                    timestamp=datetime.now(timezone.utc),
                                    raw_data={
                                        "type": "social_account",
                                        "platform": entry.get("site").lower(),
                                        "url": entry.get("url"),
                                        "username": username,
                                        "source": "social-analyzer",
                                    },
                                )
                            )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Social-Analyzer failed: %s", e)
        return findings

    async def _run_ghunt(self, target: str) -> list[Finding]:
        """Execute GHUNT for target (email/username)."""
        findings = []
        cmd = ["ghunt", "email", target, "--json"] if "@" in target else ["ghunt", "gaia", target, "--json"]
        try:
            logger.info("Running GHUNT for %s...", target)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    profile_url = data.get("profile_url")
                    if profile_url:
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title="GHUNT Google Profile",
                                description="Discovered Google services profile",
                                module="social_osint",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "social_account",
                                    "platform": "google",
                                    "url": profile_url,
                                    "username": target,
                                    "source": "ghunt",
                                },
                            )
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("GHUNT failed: %s", e)
        return findings

    async def _run_leakosint(self, target: str) -> list[Finding]:
        """Execute LeakOSINT."""
        findings = []
        cmd = ["leakosint", target, "--json"]
        try:
            logger.info("Running LeakOSINT for %s...", target)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    for leak in data.get("leaks", []):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title=f"LeakOSINT Breach: {leak.get('name')}",
                                description="Discovered data breach entry",
                                module="data_leaks",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "leak",
                                    "breach_name": leak.get("name"),
                                    "target": target,
                                    "source": "leakosint",
                                },
                            )
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("LeakOSINT failed: %s", e)
        return findings
