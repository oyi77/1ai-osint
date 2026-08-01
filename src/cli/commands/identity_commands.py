"""Identity resolution commands."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from typing import Any

import typer

from ..app import app


@app.command()
def resolve(
    input: str = typer.Argument(..., help="Identifier to resolve (email, username, phone, crypto address)"),
    output: str = typer.Option("json", help="Output format: json, sarif, pdf"),
    ai: bool = typer.Option(False, help="Enable AI analysis"),
    sources: str = typer.Option("all", help="Comma-separated source names or 'all'"),
    timeout: int = typer.Option(300, help="Timeout in seconds"),
) -> None:
    """Resolve an identity — find all connected entities across all sources."""

    async def _resolve() -> None:
        from src.core.compliance import min_tier_for, record_audit, source_allows_tier
        from src.core.rbac import AccessTier
        from src.modules.crypto.leak_finder.extractor import extract_keys
        from src.modules.output.pdf_export import format_pdf as _format_pdf
        from src.modules.output.sarif import format_sarif as _format_sarif
        from src.modules.sources import RawLeak, discover_sources

        typer.echo(f"Resolving identity: {input}", err=True)

        # Determine which sources to use
        src_map = discover_sources()
        if sources == "all":
            source_names = list(src_map.keys())
        else:
            source_names = [s.strip() for s in sources.split(",")]

        # Gather leaks from all sources
        all_leaks: list[RawLeak] = []
        all_keys: list[Any] = []
        errors: list[str] = []

        for name in source_names:
            cls = src_map.get(name)
            if not cls:
                continue
            # RBAC tier gate (Layer 3): block sources the requester may not query.
            if not source_allows_tier(name, AccessTier.ADMIN):
                errors.append(f"{name}: blocked — requires tier {min_tier_for(name).name.lower()}")
                record_audit(source=name, target=input, requester="cli", outcome="blocked")
                continue
            try:
                source = cls()
                # Try search_for_address first, fall back to fetch_raw_leaks
                if hasattr(source, "search_for_address"):
                    leaks = await asyncio.wait_for(
                        source.search_for_address(input),
                        timeout=timeout,
                    )
                else:
                    leaks = await asyncio.wait_for(
                        source.fetch_raw_leaks(),
                        timeout=timeout,
                    )
                all_leaks.extend(leaks)

                # Extract keys from leaks
                for leak in leaks:
                    keys = extract_keys(leak.text)
                    all_keys.extend(keys)
            except asyncio.TimeoutError:
                errors.append(f"{name}: timeout")
            except Exception as exc:
                errors.append(f"{name}: {exc}")

        # Build result
        from src.core.models import Finding, ScanResult, Severity

        scan_id = f"resolve-{uuid.uuid4().hex[:8]}"
        findings: list[Finding] = []
        for i, leak in enumerate(all_leaks):
            findings.append(
                Finding(
                    id=f"leak-{i}",
                    module=leak.source_name,
                    scan_id=scan_id,
                    title=f"Leak from {leak.source_name}",
                    description=leak.text[:500],
                    severity=Severity.MEDIUM,
                    raw_data={"source_url": leak.source_url, "preview": leak.text[:200]},
                    confidence=0.5,
                    tags=["leak"],
                )
            )
        for i, key in enumerate(all_keys):
            findings.append(
                Finding(
                    id=f"key-{i}",
                    module="crypto_leak_finder",
                    scan_id=scan_id,
                    title=f"Extracted {key.key_type.value} key",
                    description="Crypto key material found in leak text",
                    severity=Severity.HIGH,
                    raw_data={"addresses": key.derived_addresses},
                    confidence=0.7,
                    tags=["crypto", "secret"],
                )
            )

        result = ScanResult(
            scan_id=scan_id,
            module="identity_resolve",
            target=input,
            status="partial" if errors else "ok",
            findings=findings,
            metadata={
                "sources_queried": len(source_names),
                "leaks_found": len(all_leaks),
                "keys_extracted": len(all_keys),
                "errors": errors,
            },
        )

        # Output
        if output == "json":
            typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        elif output == "sarif":
            typer.echo(_format_sarif([result]))
        elif output == "pdf":
            sys.stdout.buffer.write(_format_pdf([result]))
            typer.echo("", err=True)  # newline on stderr so terminal stays clean

    asyncio.run(_resolve())
