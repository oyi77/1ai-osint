"""Multi-purpose recon external OSINT tool mixin.

Bbot, Spiderfoot, Chiasmodon — tools that can scan both usernames and domains.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from src.core.models import Finding

logger = logging.getLogger(__name__)


class ExternalToolReconMixin:
    """Mixin providing multi-purpose recon tool runners.

    Expects self._run_command(cmd, timeout) and self.has_* flags.
    """

    async def _run_command(self, cmd: list[str], timeout: float = 180.0) -> bytes:
        """Run an external command — provided by ExternalToolCoordinator."""
        raise NotImplementedError  # pragma: no cover

    async def _run_bbot(self, target: str) -> list[Finding]:
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

    async def _run_spiderfoot(self, target: str) -> list[Finding]:
        """Execute Spiderfoot CLI."""
        findings = []
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

    async def _run_chiasmodon(self, target: str) -> list[Finding]:
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
                                title="Chiasmodon Finding",
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
