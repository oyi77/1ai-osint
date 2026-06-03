"""External Open-Source Tool Adapters (Sherlock, Maigret, theHarvester, etc).

Orchestrates external CLI tools to enhance OSINT capabilities without
rewriting the entire tools from scratch.
"""

import os
import csv
import json
import logging
import asyncio
import tempfile
from typing import List
from datetime import datetime, timezone

from src.core.models import ScanResult, Finding
import uuid

logger = logging.getLogger(__name__)


class ExternalToolIntel:
    """Wrapper to run installed OSINT CLI tools."""

    def __init__(self):
        self._check_installed_tools()

    def _check_installed_tools(self):
        """Check which tools are available in the system PATH."""
        import shutil

        self.has_sherlock = shutil.which("sherlock") is not None
        self.has_maigret = shutil.which("maigret") is not None
        self.has_theharvester = shutil.which("theHarvester") is not None
        self.has_leakosint = shutil.which("leakosint") is not None
        self.has_worldmonitor = shutil.which("worldmonitor") is not None
        self.has_webcheck = shutil.which("web-check") is not None
        self.has_socialanalyzer = shutil.which("social-analyzer") is not None
        self.has_ghunt = shutil.which("ghunt") is not None
        self.has_crucix = shutil.which("crucix") is not None
        self.has_bbot = shutil.which("bbot") is not None
        self.has_spiderfoot = shutil.which("spiderfoot") is not None
        self.has_chiasmodon = shutil.which("chiasmodon") is not None
        self.has_amass = shutil.which("amass") is not None
        self.has_subfinder = shutil.which("subfinder") is not None

        logger.info(
            "External tools detected: Sherlock=%s, Maigret=%s, theHarvester=%s, LeakOSINT=%s, WorldMonitor=%s, Web-check=%s, Social-Analyzer=%s, GHUNT=%s, Crucix=%s, Bbot=%s, Spiderfoot=%s, Chiasmodon=%s, Amass=%s, Subfinder=%s",
            self.has_sherlock,
            self.has_maigret,
            self.has_theharvester,
            self.has_leakosint,
            self.has_worldmonitor,
            self.has_webcheck,
            self.has_socialanalyzer,
            self.has_ghunt,
            self.has_crucix,
            self.has_bbot,
            self.has_spiderfoot,
            self.has_chiasmodon,
            self.has_amass,
            self.has_subfinder,
        )

    async def scan_username(self, username: str) -> ScanResult:
        """Scan a username using Sherlock or Maigret."""
        import uuid

        result = ScanResult(
            scan_id=f"ext-{uuid.uuid4().hex[:8]}",
            module="external_tools_username",
            target=username,
        )

        if self.has_sherlock:
            sherlock_findings = await self._run_sherlock(username)
            result.findings.extend(sherlock_findings)
        if self.has_maigret:
            maigret_findings = await self._run_maigret(username)
            result.findings.extend(maigret_findings)
        if self.has_socialanalyzer:
            sa_findings = await self._run_socialanalyzer(username)
            result.findings.extend(sa_findings)
        if self.has_ghunt:
            ghunt_findings = await self._run_ghunt(username)
            result.findings.extend(ghunt_findings)
        if self.has_leakosint:
            leakosint_findings = await self._run_leakosint(username)
            result.findings.extend(leakosint_findings)

        if self.has_bbot:
            bbot_findings = await self._run_bbot(username)
            result.findings.extend(bbot_findings)
        if self.has_spiderfoot:
            sf_findings = await self._run_spiderfoot(username)
            result.findings.extend(sf_findings)
        if self.has_chiasmodon:
            cm_findings = await self._run_chiasmodon(username)
            result.findings.extend(cm_findings)

        if not any(
            [
                self.has_sherlock,
                self.has_maigret,
                self.has_socialanalyzer,
                self.has_ghunt,
                self.has_leakosint,
                self.has_bbot,
                self.has_spiderfoot,
                self.has_chiasmodon,
            ]
        ):
            result.status = "error"
            result.error = "No username OSINT tools installed (Sherlock/Maigret/Social-Analyzer/GHUNT/LeakOSINT/Bbot/Spiderfoot/Chiasmodon)."

        return result

    async def scan_domain(self, domain: str) -> ScanResult:
        """Scan a domain using theHarvester."""
        import uuid

        result = ScanResult(
            scan_id=f"ext-{uuid.uuid4().hex[:8]}",
            module="external_tools_domain",
            target=domain,
        )

        if self.has_theharvester:
            harvester_findings = await self._run_theharvester(domain)
            result.findings.extend(harvester_findings)
        if self.has_webcheck:
            webcheck_findings = await self._run_webcheck(domain)
            result.findings.extend(webcheck_findings)
        if self.has_worldmonitor:
            worldmonitor_findings = await self._run_worldmonitor(domain)
            result.findings.extend(worldmonitor_findings)
        if self.has_crucix:
            crucix_findings = await self._run_crucix(domain)
            result.findings.extend(crucix_findings)

        if self.has_bbot:
            bbot_findings = await self._run_bbot(domain)
            result.findings.extend(bbot_findings)
        if self.has_spiderfoot:
            sf_findings = await self._run_spiderfoot(domain)
            result.findings.extend(sf_findings)
        if self.has_amass:
            amass_findings = await self._run_amass(domain)
            result.findings.extend(amass_findings)
        if self.has_subfinder:
            subfinder_findings = await self._run_subfinder(domain)
            result.findings.extend(subfinder_findings)

        if not any(
            [
                self.has_theharvester,
                self.has_webcheck,
                self.has_worldmonitor,
                self.has_crucix,
                self.has_bbot,
                self.has_spiderfoot,
                self.has_amass,
                self.has_subfinder,
            ]
        ):
            result.status = "error"
            result.error = "No domain OSINT tools installed (theHarvester/Web-check/WorldMonitor/Crucix/Bbot/Spiderfoot/Amass/Subfinder)."

        return result

    async def _run_command(self, cmd: list[str], timeout: float = 180.0) -> bytes:
        """Helper to run a subprocess command and return stdout."""
        try:
            import logging
            logger = logging.getLogger(__name__)
            logger.debug("Running command: %s", " ".join(cmd))
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return stdout
        except asyncio.TimeoutError:
            try:
                process.kill()
            except Exception:
                pass
            return b""
        except Exception as e:
            return b""

    async def _run_sherlock(self, username: str) -> List[Finding]:
        """Execute Sherlock and parse CSV output."""
        import subprocess
        import shutil

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
                    with open(csv_path, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # e.g., username,name,url_main,url_user,exists,http_status,response_time_s
                            # or username_queried,site_name,url_main,url_user,exists,http_status,response_time_s
                            site_name = (
                                row.get("name") or row.get("site_name") or "Unknown"
                            )
                            # In Sherlock, exists could be "yes" or "Claimed"
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
                                            module="social_osint",  # Map to social_osint so DossierCompiler picks it up
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

    async def _run_maigret(self, username: str) -> List[Finding]:
        """Execute Maigret and parse JSON output."""
        findings = []
        with tempfile.TemporaryDirectory() as tmpdir:
            # maigret username --json json --folderoutput /tmp/...
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

                # Find the JSON file
                for f in os.listdir(tmpdir):
                    if f.endswith(".json"):
                        with open(os.path.join(tmpdir, f), "r", encoding="utf-8") as jf:
                            data = json.load(jf)
                            # Maigret simple JSON format: {"username": {"site1": {"url_user": "...", "status": "Found"}, ...}}
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

    async def _run_theharvester(self, domain: str) -> List[Finding]:
        """Execute theHarvester and parse JSON output."""
        findings = []
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, f"{domain}.json")

            # theHarvester -d domain -b all -f /tmp/.../domain.json
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

                # Check for output JSON
                if os.path.exists(json_path):
                    with open(json_path, "r", encoding="utf-8") as jf:
                        data = json.load(jf)

                        # Extract emails
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

                        # Extract hosts/subdomains
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

    async def _run_socialanalyzer(self, username: str) -> List[Finding]:
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

    async def _run_ghunt(self, target: str) -> List[Finding]:
        """Execute GHUNT for target (email/username)."""
        findings = []
        cmd = (
            ["ghunt", "email", target, "--json"]
            if "@" in target
            else ["ghunt", "gaia", target, "--json"]
        )
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

    async def _run_leakosint(self, target: str) -> List[Finding]:
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

    async def _run_webcheck(self, domain: str) -> List[Finding]:
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

    async def _run_worldmonitor(self, domain: str) -> List[Finding]:
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

    async def _run_crucix(self, domain: str) -> List[Finding]:
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

    async def _run_bbot(self, target: str) -> List[Finding]:
        """Execute Bbot."""
        findings = []
        cmd = ["bbot", "-t", target, "-f", "json"]
        try:
            logger.info("Running Bbot for %s...", target)
            stdout = await self._run_command(cmd, timeout=300.0)
            if stdout:
                for line in stdout.decode().strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        event_type = data.get("type", "")
                        if event_type in ("DNS_NAME", "IP_ADDRESS", "OPEN_PORT"):
                            findings.append(
                                Finding(
                                    id=uuid.uuid4().hex,
                                    title=f"Bbot {event_type}: {data.get('data', '')}",
                                    description="Discovered infrastructure entity",
                                    module="domain_osint",
                                    timestamp=datetime.now(timezone.utc),
                                    raw_data={
                                        "type": event_type.lower(),
                                        "value": data.get("data", ""),
                                        "target": target,
                                        "source": "bbot",
                                    },
                                )
                            )
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.debug("Bbot failed: %s", e)
        return findings

    async def _run_spiderfoot(self, target: str) -> List[Finding]:
        """Execute Spiderfoot CLI."""
        findings = []
        # Spiderfoot is complex, usually requires a config for API keys.
        # This is a stub calling the CLI.
        cmd = ["spiderfoot", "-s", target, "-q"]
        try:
            logger.info("Running Spiderfoot for %s...", target)
            stdout = await self._run_command(cmd, timeout=300.0)
            if stdout:
                for line in stdout.decode().strip().split("\n"):
                    if line.strip() and " " in line:
                        parts = line.strip().split(" ", 1)
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title=f"Spiderfoot Finding: {parts[0]}",
                                description=parts[1] if len(parts) > 1 else "Discovered entity",
                                module="domain_osint",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "spiderfoot_entity",
                                    "value": line.strip(),
                                    "target": target,
                                    "source": "spiderfoot",
                                },
                            )
                        )
        except Exception as e:
            logger.debug("Spiderfoot failed: %s", e)
        return findings

    async def _run_chiasmodon(self, target: str) -> List[Finding]:
        """Execute Chiasmodon CLI."""
        findings = []
        cmd = ["chiasmodon", "--target", target, "--json"]
        try:
            logger.info("Running Chiasmodon for %s...", target)
            stdout = await self._run_command(cmd, timeout=180.0)
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    results = data if isinstance(data, list) else data.get("results", [])
                    for item in results:
                        findings.append(
                            Finding(
                                id=uuid.uuid4().hex,
                                title=f"Chiasmodon Finding",
                                description="Discovered associated asset",
                                module="domain_osint",
                                timestamp=datetime.now(timezone.utc),
                                raw_data={
                                    "type": "chiasmodon_entity",
                                    "data": item,
                                    "target": target,
                                    "source": "chiasmodon",
                                },
                            )
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Chiasmodon failed: %s", e)
        return findings

    async def _run_amass(self, domain: str) -> List[Finding]:
        """Execute Amass."""
        findings = []
        cmd = ["amass", "enum", "-d", domain, "-json", "amass_out.json"]
        try:
            logger.info("Running Amass for %s...", domain)
            stdout = await self._run_command(cmd, timeout=300.0)
            if os.path.exists("amass_out.json"):
                with open("amass_out.json", "r") as f:
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

    async def _run_subfinder(self, domain: str) -> List[Finding]:
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
