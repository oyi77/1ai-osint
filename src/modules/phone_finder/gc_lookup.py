"""GetContact lookup via the gc-lookup CLI (Go port of gtc.py).

The `gc-lookup` binary (github.com/oyi77/gc-lookup) implements the GetContact
protocol — DH key exchange + AES-256-ECB + HMAC-SHA256 — and stores account
credentials at $GTC_CONFIG_DIR/credentials.json (default ~/.config/gtc/). This
module shells out to that binary and parses the JSON profile/tags output.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Any

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.utils.phone_normalize import normalize_phone_e164

logger = logging.getLogger(__name__)


class GCLookupTool(BaseOSINTTool):
    """GetContact phone profile and tag lookup via the gc-lookup CLI."""

    name = "gc_lookup"
    description = "GetContact phone profile and tag lookup (gc-lookup CLI)"
    version = "0.1.0"

    def __init__(
        self,
        binary: str = "gc-lookup",
        config_dir: str | None = None,
        timeout: float = 30.0,
        rotate: bool = False,
        zkit_salt: str | None = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.binary = shutil.which(binary) or binary
        self.config_dir = config_dir or os.environ.get("GTC_CONFIG_DIR")
        self.timeout = timeout
        self.rotate = rotate

    def _search_args(self, source: str, phone: str) -> list[str]:
        """Build the gc-lookup search argv (--rotate rotates across accounts)."""
        args = ["search", "--source", source]
        if self.rotate:
            args.append("--rotate")
        args.append(phone)
        return args

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.config_dir:
            env["GTC_CONFIG_DIR"] = self.config_dir
        return env

    async def _run(self, args: list[str]) -> tuple[int, str, str]:
        """Run the gc-lookup binary; return (exit_code, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env(),
            )
        except FileNotFoundError:
            return 127, "", f"binary not found: {self.binary}"
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return 124, "", f"timed out after {self.timeout}s"
        return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    def _done(
        self,
        scan_id: str,
        target: str,
        started_at: datetime,
        findings: list[Finding],
        phone: str,
        status: str = "ok",
        note: str | None = None,
    ) -> ScanResult:
        metadata: dict[str, Any] = {"binary": self.binary, "phone": phone}
        if note:
            metadata["note"] = note
        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status=status,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            metadata=metadata,
        )

    def _fail(self, scan_id: str, target: str, started_at: datetime, error: str) -> ScanResult:
        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="error",
            findings=[],
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            error=error,
        )

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Look up a phone number's GetContact profile and linked tags."""
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        normalized = normalize_phone_e164(query, default_region="ID")
        phone = normalized or query

        # Only invoke the binary for a valid phone number; never fabricate a
        # finding for arbitrary input (username/URL/etc.).
        if not normalized:
            return self._done(
                scan_id,
                query,
                started_at,
                [],
                phone,
                status="partial",
                note="Target is not a valid phone number; gc-lookup not invoked",
            )

        profile_code, profile_out, profile_err = await self._run(self._search_args("profile", phone))
        if profile_code == 127:
            return self._fail(
                scan_id,
                query,
                started_at,
                f"gc-lookup binary not found: {self.binary}. "
                "Install it (go install github.com/oyi77/gc-lookup/cmd/gc-lookup) or pass binary=...",
            )
        if profile_code != 0:
            return self._fail(
                scan_id,
                query,
                started_at,
                f"gc-lookup search (profile) failed: {profile_err.strip()}",
            )

        tags_code, tags_out, tags_err = await self._run(self._search_args("tags", phone))

        if profile_out.strip():
            try:
                profile = json.loads(profile_out)
            except json.JSONDecodeError:
                profile = None
            if isinstance(profile, dict) and profile:
                findings.append(
                    Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        scan_id=scan_id,
                        title="GetContact profile",
                        description=f"GetContact profile for {phone}",
                        severity=Severity.INFO,
                        raw_data=profile,
                        confidence=0.9,
                        tags=["getcontact", "phone"],
                    )
                )

        if tags_code == 0 and tags_out.strip():
            try:
                tags = json.loads(tags_out)
            except json.JSONDecodeError:
                tags = None
            if isinstance(tags, list) and tags:
                findings.append(
                    Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        scan_id=scan_id,
                        title="GetContact tags",
                        description="Linked-account tags from GetContact",
                        severity=Severity.INFO,
                        raw_data={"tags": tags},
                        confidence=0.8,
                        tags=["getcontact", "phone", "tags"],
                    )
                )

        status = "ok" if findings else "partial"
        return self._done(scan_id, query, started_at, findings, phone, status=status)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Alias for search."""
        return await self.search(target, **kwargs)

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze gc-lookup findings."""
        return {"modules": [self.name]}

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """No learning model; nothing to update."""
        pass
