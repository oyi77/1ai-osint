"""External Open-Source Tool Adapters (Sherlock, Maigret, theHarvester, etc).

Orchestrates external CLI tools to enhance OSINT capabilities without
rewriting the entire tools from scratch.
"""

import asyncio
import logging
import shutil
import uuid

from src.core.models import ScanResult
from src.modules.vendor._ext_domain_mixin import ExternalToolDomainMixin
from src.modules.vendor._ext_recon_mixin import ExternalToolReconMixin
from src.modules.vendor._ext_username_mixin import ExternalToolUsernameMixin

logger = logging.getLogger(__name__)


class ExternalToolIntel(ExternalToolUsernameMixin, ExternalToolDomainMixin, ExternalToolReconMixin):
    """Wrapper to run installed OSINT CLI tools."""

    def __init__(self):
        self._check_installed_tools()

    def _check_installed_tools(self):
        """Check which tools are available in the system PATH."""
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
        except Exception:
            return b""
