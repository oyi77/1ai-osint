"""Domain-specific external OSINT tool mixin.

theHarvester, Web-check, WorldMonitor, Crucix, Amass, Subfinder.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone

from src.core.models import Finding

logger = logging.getLogger(__name__)


class ExternalToolDomainMixin:
    """Mixin providing domain-focused external tool runners.

    Expects self._run_command(cmd, timeout) and self.has_* flags.
    """

    async def _run_command(self, cmd: list[str], timeout: float = 180.0) -> bytes:
        """Run an external command — provided by ExternalToolCoordinator."""
        raise NotImplementedError  # pragma: no cover

    async def _run_theharvester(self, domain: str) -> list[Finding]:
        """Execute theHarvester and parse JSON output."""
        findings = []
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, f"{domain}.json")

            cmd = ["theHarvester", "-d", domain, "-b", "all", "-f", json_path]

            try:
                logger.info("Running theHarvester for %s...", domain)
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    await asyncio.wait_for(process.communicate(), timeout=300.0)
                except asyncio.TimeoutError:
                    process.kill()
                    logger.warning("theHarvester timeout for %s", domain)

                if os.path.exists(json_path):
                    with open(json_path, encoding="utf-8") as jf:
                        data = json.load(jf)

                        for email in data.get("emails", []):
                            findings.append(
                                Finding(
                                    id=uuid.uuid4().hex,
                                    title=f"Email Discovered: {email}",
                                    description="theHarvester discovered email on domain",
                                    module="domain_osint",
                                    timestamp=datetime.now(timezone.utc),
                                    raw_data={
                                        "type": "email",
                                        "address": email,
                                        "source": "theHarvester",
                                    },
                                )
                            )

                        for host in data.get("hosts", []):
                            findings.append(
                                Finding(
                                    id=uuid.uuid4().hex,
                                    title=f"Host Discovered: {host}",
                                    description="theHarvester discovered subdomain/host",
                                    module="domain_osint",
                                    timestamp=datetime.now(timezone.utc),
                                    raw_data={
                                        "type": "subdomain",
                                        "hostname": host,
                                        "source": "theHarvester",
                                    },
                                )
                            )
            except Exception as e:
                logger.error("theHarvester execution failed: %s", e)

        return findings

    async def _run_webcheck(self, domain: str) -> list[Finding]:
        """Execute Web-check."""
        findings = []
        cmd = ["web-check", domain, "--json"]
        try:
            logger.info("Running Web-check for %s...", domain)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    for port in data.get("ports", []):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title=f"Web-check Open Port: {port}",
                                description="Discovered open port on domain",
                                module="domain_osint",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "port",
                                    "port": port,
                                    "domain": domain,
                                    "source": "web-check",
                                },
                            )
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Web-check failed: %s", e)
        return findings

    async def _run_worldmonitor(self, domain: str) -> list[Finding]:
        """Execute WorldMonitor."""
        findings = []
        cmd = ["worldmonitor", "scan", domain, "--json"]
        try:
            logger.info("Running WorldMonitor for %s...", domain)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    for tech in data.get("technologies", []):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title=f"WorldMonitor Tech: {tech}",
                                description="Discovered technology stack",
                                module="domain_osint",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "technology",
                                    "name": tech,
                                    "domain": domain,
                                    "source": "worldmonitor",
                                },
                            )
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("WorldMonitor failed: %s", e)
        return findings

    async def _run_crucix(self, domain: str) -> list[Finding]:
        """Execute Crucix."""
        findings = []
        cmd = ["crucix", "-d", domain, "-j"]
        try:
            logger.info("Running Crucix for %s...", domain)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    for sub in data.get("subdomains", []):
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title=f"Crucix Subdomain: {sub}",
                                description="Discovered subdomain",
                                module="domain_osint",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "subdomain",
                                    "hostname": sub,
                                    "domain": domain,
                                    "source": "crucix",
                                },
                            )
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Crucix failed: %s", e)
        return findings

    async def _run_amass(self, domain: str) -> list[Finding]:
        """Execute Amass."""
        findings = []
        cmd = ["amass", "enum", "-d", domain, "-json", "amass_out.json"]
        try:
            logger.info("Running Amass for %s...", domain)
            await self._run_command(cmd, timeout=300.0)
            if os.path.exists("amass_out.json"):
                with open("amass_out.json") as f:
                    for line in f:
                        data = json.loads(line)
                        name = data.get("name")
                        if name:
                            findings.append(
                                Finding(
                                    id=uuid.uuid4().hex,
                                    title=f"Amass Subdomain: {name}",
                                    description="Discovered subdomain",
                                    module="domain_osint",
                                    timestamp=datetime.now(timezone.utc),
                                    raw_data={
                                        "type": "subdomain",
                                        "hostname": name,
                                        "domain": domain,
                                        "source": "amass",
                                    },
                                )
                            )
                os.remove("amass_out.json")
        except Exception as e:
            logger.debug("Amass failed: %s", e)
        return findings

    async def _run_subfinder(self, domain: str) -> list[Finding]:
        """Execute Subfinder."""
        findings = []
        cmd = ["subfinder", "-d", domain, "-silent", "-json"]
        try:
            logger.info("Running Subfinder for %s...", domain)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                for line in stdout.decode().strip().split("\\n"):
                    if line:
                        data = json.loads(line)
                        host = data.get("host")
                        if host:
                            findings.append(
                                Finding(
                                    id=uuid.uuid4().hex,
                                    title=f"Subfinder Subdomain: {host}",
                                    description="Discovered subdomain",
                                    module="domain_osint",
                                    timestamp=datetime.now(timezone.utc),
                                    raw_data={
                                        "type": "subdomain",
                                        "hostname": host,
                                        "domain": domain,
                                        "source": "subfinder",
                                    },
                                )
                            )
        except Exception as e:
            logger.debug("Subfinder failed: %s", e)
        return findings
