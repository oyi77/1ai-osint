"""Identity resolution commands."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
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
        result: dict[str, Any] = {
            "input": input,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources_queried": len(source_names),
            "leaks_found": len(all_leaks),
            "keys_extracted": len(all_keys),
            "identities": [],
            "errors": errors,
        }

        # Group leaks by source
        for leak in all_leaks:
            result["identities"].append(
                {
                    "source": leak.source_name,
                    "url": leak.source_url,
                    "text_preview": leak.text[:200],
                }
            )

        # Add extracted keys
        for key in all_keys:
            result.setdefault("crypto_keys", []).append(
                {
                    "type": key.key_type.value,
                    "addresses": key.derived_addresses,
                }
            )

        # Output
        if output == "json":
            typer.echo(json.dumps(result, indent=2, default=str))
        elif output == "sarif":
            typer.echo(_format_sarif(result))  # type: ignore[arg-type]
        elif output == "pdf":
            typer.echo(_format_pdf(result))  # type: ignore[arg-type]

    asyncio.run(_resolve())
