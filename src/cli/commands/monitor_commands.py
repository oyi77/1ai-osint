"""Monitor command — continuously monitor identities for new connections and leaks."""

from __future__ import annotations

import asyncio
import hashlib
import os

import typer

from ..app import app


@app.command()
def monitor(
    target: str = typer.Argument(..., help="Identifier to monitor (email, username, crypto address)"),
    interval: int = typer.Option(300, help="Check interval in seconds"),
    sources: str = typer.Option("all", help="Comma-separated source names or 'all'"),
    telegram: bool = typer.Option(False, help="Send alerts via Telegram"),
) -> None:
    """Continuously monitor an identity for new connections and leaks."""

    async def _monitor() -> None:
        from src.core.compliance import min_tier_for, record_audit, source_allows_tier
        from src.core.rbac import AccessTier
        from src.modules.crypto.leak_finder.extractor import extract_keys
        from src.modules.sources import discover_sources

        typer.echo(f"Monitoring: {target} (interval: {interval}s)", err=True)

        src_map = discover_sources()
        if sources == "all":
            source_names = list(src_map.keys())
        else:
            source_names = [s.strip() for s in sources.split(",")]

        seen_leaks: set[str] = set()
        iteration = 0

        while True:
            iteration += 1
            typer.echo(f"\n--- Iteration {iteration} ---", err=True)

            new_leaks = 0
            new_keys = 0

            for name in source_names:
                cls = src_map.get(name)
                if not cls:
                    continue
                # RBAC tier gate (Layer 3): block sources the requester may not query.
                # Local CLI = trusted operator: always run at ADMIN tier (no interactive auth flow).
                if not source_allows_tier(name, AccessTier.ADMIN):
                    typer.echo(f"  [{name}] Blocked (requires tier {min_tier_for(name).name.lower()})", err=True)
                    record_audit(source=name, target=target, requester="cli_monitor", outcome="blocked")
                    continue
                try:
                    source = cls()
                    if hasattr(source, "search_for_address"):
                        leaks = await asyncio.wait_for(
                            source.search_for_address(target),
                            timeout=60,
                        )
                    else:
                        leaks = await asyncio.wait_for(
                            source.fetch_raw_leaks(),
                            timeout=60,
                        )

                    for leak in leaks:
                        # Dedup fingerprint only — not a security hash.
                        leak_hash = hashlib.sha1(
                            leak.text[:500].encode("utf-8", errors="replace"), usedforsecurity=False
                        ).hexdigest()
                        if leak_hash not in seen_leaks:
                            seen_leaks.add(leak_hash)
                            new_leaks += 1

                            keys = extract_keys(leak.text)
                            new_keys += len(keys)

                            typer.echo(f"  [{name}] New leak: {leak.source_url or leak.text[:80]}")

                            if telegram and keys:
                                import httpx

                                bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
                                chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
                                if bot_token and chat_id:
                                    key_summary = ", ".join(k.key_type.value for k in keys[:5])
                                    msg = (
                                        f"\U0001f50d [{name}] {len(keys)} key(s) found: {key_summary}\n"
                                        f"{leak.source_url or leak.text[:200]}"
                                    )
                                    try:
                                        async with httpx.AsyncClient() as client:
                                            await client.post(
                                                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                                                json={
                                                    "chat_id": chat_id,
                                                    "text": msg,
                                                    "parse_mode": "HTML",
                                                },
                                                timeout=10,
                                            )
                                    except Exception as exc:
                                        typer.echo(f"  Telegram alert failed: {exc}", err=True)
                except asyncio.TimeoutError:
                    typer.echo(f"  [{name}] Timeout", err=True)
                except Exception as exc:
                    typer.echo(f"  [{name}] Error: {exc}", err=True)

            typer.echo(f"  Summary: {new_leaks} new leaks, {new_keys} new keys " f"(total seen: {len(seen_leaks)})")

            await asyncio.sleep(interval)

    asyncio.run(_monitor())
