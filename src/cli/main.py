"""1ai-osint CLI entry point."""

import asyncio
import json
import os
import socket
import sys
from datetime import datetime, timezone

import typer

from src.modules.output.pdf_export import format_pdf as _format_pdf
from src.modules.output.sarif import format_sarif as _format_sarif

app = typer.Typer(
    help="1ai-osint -- AI-Powered OSINT & ZKIT Research Platform",
    add_completion=False,
)

# Valid module names for the scan command
SCAN_MODULES = (
    "gitleaks",
    "data_leaks",
    "people",
    "phone",
    "crypto_passphrase",
    "crypto_privatekey",
    "crypto_balance",
    "domain",
    "email",
    "social",
    "all",
)
OUTPUT_FORMATS = ("json", "sarif", "pdf")


@app.command()
def version():
    """Show version."""
    from src import __version__

    typer.echo(f"1ai-osint v{__version__}")


@app.command()
def doctor():
    """Check environment: Python, sherlock, breach API keys, providers."""
    from src.doctor import format_doctor_report, run_doctor

    results = run_doctor()
    typer.echo(format_doctor_report(results))
    hard_fail = [r for r in results if not r.ok and not r.name.startswith("breach:")]
    if hard_fail:
        raise typer.Exit(code=1)


@app.command()
def modules():
    """List all available OSINT modules."""
    from src.modules import list_modules

    registered = list_modules()
    typer.echo("Available modules:")
    for name in sorted(registered):
        typer.echo(f"  - {name}")
    typer.echo(f"\nTotal: {len(registered)} modules")

    # Also show modules available via _get_module but not in registry
    extra = [m for m in SCAN_MODULES if m not in registered and m != "all"]
    if extra:
        typer.echo(f"\nAlso available via --module: {', '.join(extra)}")


def _get_module(name: str, zkit_salt: str = ""):
    """Resolve a module name to its tool instance."""
    if name in ("gitleaks", "secrets"):
        from src.modules.gitleaks.scanner import GitleaksModule

        return GitleaksModule(zkit_salt=zkit_salt)
    elif name in ("data_leaks", "breaches", "leaks"):
        from src.modules.data_leaks.aggregator import DataLeaksAggregator

        return DataLeaksAggregator(zkit_salt=zkit_salt)
    elif name in ("people", "people_finder", "social"):
        from src.modules.people_finder.search import PeopleFinderSearch

        return PeopleFinderSearch(zkit_salt=zkit_salt)
    elif name in ("phone", "phone_finder"):
        from src.modules.phone_finder import PhoneFinderTool

        return PhoneFinderTool(zkit_salt=zkit_salt)
    elif name in ("crypto_passphrase", "passphrase"):
        from src.modules.crypto.passphrase.generator import generate_with_details

        return _PassphraseModule(generate_with_details, zkit_salt=zkit_salt)
    elif name in ("crypto_privatekey", "privatekey", "privkey"):
        from src.modules.crypto.privatekey.scanner import PrivateKeyScanner

        return PrivateKeyScanner(zkit_salt=zkit_salt)
    elif name in ("crypto_balance", "balance", "wallet"):
        from src.modules.crypto.balance import CryptoBalanceTool

        return CryptoBalanceTool(zkit_salt=zkit_salt)
    elif name in ("domain", "domain_recon"):
        from src.modules.domain_recon import DomainReconTool

        return DomainReconTool(zkit_salt=zkit_salt)
    elif name in ("email", "email_osint"):
        from src.modules.email_osint import EmailOSINTTool

        return EmailOSINTTool(zkit_salt=zkit_salt)
    elif name in ("social", "social_osint"):
        from src.modules.social_osint import SocialOSINTTool

        return SocialOSINTTool(zkit_salt=zkit_salt)
    elif name in ("vuln", "vuln_scanner"):
        from src.modules.vuln_scanner import VulnScannerTool

        return VulnScannerTool()
    return None


class _PassphraseModule:
    """Thin adapter wrapping the passphrase generator as a scannable module."""

    name = "crypto_passphrase"
    description = "BIP-39 mnemonic passphrase generation and analysis"
    version = "0.1.0"

    def __init__(self, gen_func, zkit_salt: str = ""):
        self._gen_func = gen_func
        self.zkit_salt = zkit_salt

    async def scan(self, target: str, **kwargs):
        from src.core.models import Finding, ScanResult, Severity

        scan_id = f"passphrase-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        started_at = datetime.now(timezone.utc)
        findings = []

        try:
            details = self._gen_func(word_count=24, language="english")
            findings.append(
                Finding(
                    id=f"fp-{scan_id}",
                    module=self.name,
                    title="BIP-39 mnemonic generated",
                    description=f"Generated {details['word_count']}-word mnemonic ({details['entropy_bits']} bits entropy)",
                    severity=Severity.INFO,
                    raw_data=details,
                    confidence=1.0,
                    tags=["crypto", "passphrase", "bip39"],
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    id=f"fp-err-{scan_id}",
                    module=self.name,
                    title="Passphrase generation error",
                    description=str(e),
                    severity=Severity.HIGH,
                    raw_data={"error": str(e)},
                    confidence=1.0,
                    tags=["crypto", "passphrase", "error"],
                )
            )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            metadata={"word_count": 24},
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )


def _run_with_ai(result, ai_enabled: bool):
    """Optionally run AI analysis on scan results."""
    if not ai_enabled:
        return result

    try:
        from src.ai.orchestrator import AnalysisOrchestrator

        orchestrator = AnalysisOrchestrator()
        report = asyncio.run(orchestrator.run(scan_results=[result]))
        result.metadata["ai_report"] = report
    except Exception as e:
        result.metadata["ai_error"] = str(e)

    return result


def _run_zkit_tracking(result, zkit_salt: str):
    """Run ZKIT identity tracking on scan results, adding identity graph metadata."""
    if not zkit_salt:
        return result

    try:
        from src.modules.identity_tracking.identity_graph import IdentityGraph, NodeType

        graph = IdentityGraph(salt=zkit_salt)

        for finding in result.findings:
            raw = finding.raw_data or {}
            # Extract identity attributes from findings
            email = raw.get("email") or raw.get("Email")
            username = raw.get("username") or raw.get("Username")
            phone = raw.get("phone")
            domain = raw.get("domain") or raw.get("Domain")

            attrs = []
            if email:
                attrs.append((email, NodeType.EMAIL_HASH))
            if username:
                attrs.append((username, NodeType.USERNAME_HASH))
            if phone:
                attrs.append((phone, NodeType.PHONE_HASH))
            if domain:
                attrs.append((domain, NodeType.DOMAIN_HASH))

            # Add nodes
            for raw_val, node_type in attrs:
                graph.add_raw_attribute(raw_val, node_type, source=result.module)

            # Add co-occurrence edges between attributes in the same finding
            for i in range(len(attrs)):
                for j in range(i + 1, len(attrs)):
                    graph.add_co_occurrence(
                        attrs[i][0],
                        attrs[i][1],
                        attrs[j][0],
                        attrs[j][1],
                        source=result.module,
                    )

        result.metadata["zkit_graph"] = {
            "nodes": graph.node_count,
            "edges": graph.edge_count,
        }
    except Exception as e:
        result.metadata["zkit_error"] = str(e)

    return result


@app.command()
def scan(
    target: str = typer.Argument(
        "random", help="Target: URL, path, email, mnemonic, or 'random' for random scan"
    ),
    module: str = typer.Option(
        "all", help=f"Module to use ({', '.join(SCAN_MODULES)})"
    ),
    output: str = typer.Option(
        "json", help=f"Output format ({', '.join(OUTPUT_FORMATS)})"
    ),
    ai: bool = typer.Option(False, "--ai", help="Enable AI analysis via orchestrator"),
    zkit: bool = typer.Option(False, "--zkit", help="Enable ZKIT identity tracking"),
    cloak: bool = typer.Option(
        False, "--cloak", help="Enforce CloakBrowser for anti-detect scraping"
    ),
    zkit_salt: str = typer.Option(
        "", help="ZKIT salt for privacy-preserving identity hashing"
    ),
    timeout: int = typer.Option(300, help="Scan timeout in seconds"),
    # crypto_balance specific options
    scan_mode: str = typer.Option(
        "",
        help="Scan mode for crypto_balance: 'random', 'targeted', 'leak', or 'smart' (auto-detected if omitted)",
    ),
    workers: int = typer.Option(
        20, help="Number of concurrent workers for random scan"
    ),
    duration: int = typer.Option(
        0, help="Duration in seconds for random scan (0 = use iterations)"
    ),
    account_count: int = typer.Option(1, help="Number of accounts to derive per chain"),
    min_balance: float = typer.Option(
        0.0, help="Minimum balance threshold for random scan hits"
    ),
):
    """Run an OSINT scan against a target.

    For crypto_balance module with 'random' target, generates random mnemonics.
    For crypto_balance with a mnemonic target, derives and checks balances.
    """
    import os

    from src.core.config import settings

    if cloak:
        os.environ["FORCE_CLOAKBROWSER"] = "1"

    effective_salt = zkit_salt or settings.zkit_salt

    if output not in OUTPUT_FORMATS:
        typer.echo(
            f"Error: Unknown output format '{output}'. Use: {', '.join(OUTPUT_FORMATS)}",
            err=True,
        )
        raise typer.Exit(1)

    modules_to_run = []
    if module == "all":
        for name in ("gitleaks", "data_leaks", "people", "phone", "crypto_privatekey"):
            mod = _get_module(name, effective_salt)
            if mod:
                modules_to_run.append(mod)
    else:
        mod = _get_module(module, effective_salt)
        if not mod:
            typer.echo(f"Error: Unknown module '{module}'", err=True)
            raise typer.Exit(1)
        modules_to_run.append(mod)

    all_results = []
    for mod in modules_to_run:
        typer.echo(f"Running {mod.name} on {target}...", err=True)
        try:
            # Build kwargs for crypto_balance module
            extra_kwargs: dict = {"timeout": timeout}
            if mod.name == "crypto_balance":
                extra_kwargs["scan_mode"] = scan_mode
                extra_kwargs["workers"] = workers
                extra_kwargs["duration"] = duration if duration > 0 else None
                extra_kwargs["account_count"] = account_count
                extra_kwargs["min_balance"] = min_balance

            result = asyncio.run(mod.scan(target, **extra_kwargs))

            # Apply ZKIT identity tracking if enabled
            if zkit and effective_salt:
                result = _run_zkit_tracking(result, effective_salt)

            # Apply AI analysis if enabled
            result = _run_with_ai(result, ai)

            all_results.append(result)
            typer.echo(
                f"  {mod.name}: {result.finding_count} findings "
                f"({result.critical_count} critical)",
                err=True,
            )
        except Exception as e:
            typer.echo(f"  {mod.name}: Error - {e}", err=True)

    # Output results
    if output == "json":
        output_data = [r.model_dump() for r in all_results]
        typer.echo(json.dumps(output_data, indent=2, default=str))
    elif output == "sarif":
        sarif_json = _format_sarif(all_results)
        typer.echo(sarif_json)
    elif output == "pdf":
        pdf_bytes = _format_pdf(all_results)
        sys.stdout.buffer.write(pdf_bytes)
        typer.echo("", err=True)  # newline on stderr so terminal stays clean


@app.command()
def leak_finder(
    continuous: bool = typer.Option(
        False, "--continuous", "-c", help="Run in continuous mode (periodic scans)"
    ),
    address: str = typer.Option(
        "", "--address", "-a", help="Search for a specific wallet address"
    ),
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
    github_token: str = typer.Option(
        "", help="GitHub API token for authenticated search (higher rate limits)"
    ),
):
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
            f"Error: Unknown source(s): {', '.join(invalid)}. "
            f"Valid sources: {', '.join(ALL_SOURCES)}",
            err=True,
        )
        raise typer.Exit(1)

    import os

    coordinator = LeakFinderCoordinator(
        sources=source_list,
        github_token=github_token or os.getenv("GITHUB_TOKEN") or None,
    )

    async def _run():
        await coordinator.start()
        try:
            if address:
                typer.echo(f"Searching for address: {address}", err=True)
                result = await coordinator.search_address(address)
                typer.echo(
                    f"Search complete: {result.raw_leaks_fetched} raw leaks, "
                    f"{result.keys_deduplicated} keys found"
                )
            elif continuous:
                typer.echo(
                    f"Starting continuous leak finder "
                    f"(sources: {', '.join(source_list)}, interval: {interval}s)",
                    err=True,
                )
                await coordinator.run_continuous(interval_sec=interval)
            else:
                typer.echo(
                    f"Running leak finder (sources: {', '.join(source_list)})", err=True
                )
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
def resolve(
    input: str = typer.Argument(
        ..., help="Identifier to resolve (email, username, phone, crypto address)"
    ),
    output: str = typer.Option("json", help="Output format: json, sarif, pdf"),
    ai: bool = typer.Option(False, help="Enable AI analysis"),
    sources: str = typer.Option("all", help="Comma-separated source names or 'all'"),
    timeout: int = typer.Option(300, help="Timeout in seconds"),
):
    """Resolve an identity — find all connected entities across all sources."""

    async def _resolve():
        from src.modules.crypto.leak_finder.extractor import extract_keys
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
        all_keys = []
        errors = []

        for name in source_names:
            cls = src_map.get(name)
            if not cls:
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
        result = {
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
            typer.echo(_format_sarif(result))
        elif output == "pdf":
            typer.echo(_format_pdf(result))

    asyncio.run(_resolve())


@app.command()
def monitor(
    target: str = typer.Argument(
        ..., help="Identifier to monitor (email, username, crypto address)"
    ),
    interval: int = typer.Option(300, help="Check interval in seconds"),
    sources: str = typer.Option("all", help="Comma-separated source names or 'all'"),
    telegram: bool = typer.Option(False, help="Send alerts via Telegram"),
):
    """Continuously monitor an identity for new connections and leaks."""

    async def _monitor():
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
                        leak_hash = hash(leak.text[:500])
                        if leak_hash not in seen_leaks:
                            seen_leaks.add(leak_hash)
                            new_leaks += 1

                            keys = extract_keys(leak.text)
                            new_keys += len(keys)

                            typer.echo(
                                f"  [{name}] New leak: {leak.source_url or leak.text[:80]}"
                            )

                            if telegram and keys:
                                # TODO: send Telegram alert
                                pass
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass

            typer.echo(
                f"  Summary: {new_leaks} new leaks, {new_keys} new keys "
                f"(total seen: {len(seen_leaks)})"
            )

            await asyncio.sleep(interval)

    asyncio.run(_monitor())


@app.command()
def sweep(
    auto: bool = typer.Option(
        False, help="Auto-sweep all funded wallets from discovered keys"
    ),
    key: str = typer.Option(None, help="Specific private key to sweep"),
    mnemonic: str = typer.Option(None, help="Specific mnemonic to sweep"),
    chain: str = typer.Option(
        "all", help="Chain to sweep: all, ethereum, solana, bitcoin"
    ),
    dry_run: bool = typer.Option(
        False, help="Dry run — show what would be swept without executing"
    ),
):
    """Sweep funds from leaked wallets to destination addresses."""

    async def _sweep():
        from src.modules.crypto.balance.sweeper import Sweeper

        sweeper = Sweeper()
        await sweeper.start()

        try:
            if mnemonic:
                typer.echo(f"Sweeping mnemonic: {mnemonic[:20]}...")
                result = await sweeper.sweep_from_mnemonic(
                    mnemonic, chain=chain, dry_run=dry_run
                )
                typer.echo(json.dumps(result, indent=2, default=str))
            elif key:
                typer.echo(f"Sweeping key: {key[:10]}...")
                result = await sweeper.sweep_from_key(key, chain=chain, dry_run=dry_run)
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
            await sweeper.stop()

    asyncio.run(_sweep())


# --- Node / Master Commands ---


@app.command()
def node(
    action: str = typer.Argument(..., help="Action: start, status"),
    node_id: str = typer.Option(socket.gethostname(), help="Node identifier"),
    master_chat_id: str = typer.Option("", help="Master Telegram chat ID"),
    api_port: int = typer.Option(8420, help="HTTP API port"),
):
    """Run as a worker node, connecting to master via Telegram."""

    async def _run_node():
        import os

        token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        chat_id = master_chat_id or os.getenv("MASTER_CHAT_ID", "")

        if not token or not chat_id:
            typer.echo(
                "Error: TELEGRAM_BOT_TOKEN and MASTER_CHAT_ID required", err=True
            )
            raise typer.Exit(1)

        from src.modules.node.agent import NodeAgent

        agent = NodeAgent(
            node_id=node_id,
            telegram_token=token,
            master_chat_id=chat_id,
            api_port=api_port,
        )

        if action == "start":
            typer.echo(f"Starting node '{node_id}'...", err=True)
            await agent.start()
        elif action == "status":
            status = agent._get_status()
            typer.echo(json.dumps(status.to_dict(), indent=2))
        else:
            typer.echo(f"Unknown action: {action}", err=True)
            raise typer.Exit(1)

    asyncio.run(_run_node())


@app.command()
def master(
    action: str = typer.Argument(..., help="Action: start, status"),
    allowed_chat_ids: str = typer.Option(
        "", help="Comma-separated allowed Telegram chat IDs"
    ),
):
    """Run as the master bot, controlling all nodes via Telegram."""

    async def _run_master():
        import os

        token = os.getenv("TELEGRAM_BOT_TOKEN", "")

        if not token:
            typer.echo("Error: TELEGRAM_BOT_TOKEN required", err=True)
            raise typer.Exit(1)

        chat_ids = [c.strip() for c in allowed_chat_ids.split(",") if c.strip()]
        if not chat_ids:
            chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
            if chat_id:
                chat_ids = [chat_id]

        from src.modules.node.master import MasterBot

        bot = MasterBot(telegram_token=token, allowed_chat_ids=chat_ids)

        if action == "start":
            typer.echo("Starting master bot...", err=True)
            await bot.start()
        elif action == "status":
            typer.echo(f"Nodes: {len(bot.nodes)}")
            for nid, node in bot.nodes.items():
                typer.echo(f"  {nid}: {node.hostname} ({node.ip})")
        else:
            typer.echo(f"Unknown action: {action}", err=True)
            raise typer.Exit(1)

    asyncio.run(_run_master())


@app.command()
def report(
    target: str = typer.Argument(..., help="Target to generate report for"),
    output: str = typer.Option("html", help="Output format: html, json"),
    module: str = typer.Option("all", help="Module to scan first, or 'all'"),
):
    """Generate a comprehensive OSINT report for a target."""
    from src.modules.report_engine import ReportEngine
    from src.modules.report_engine.html_template import render_html

    async def _report():
        typer.echo(f"Generating report for: {target}", err=True)

        # Run scan first
        effective_salt = ""
        results = []
        if module == "all":
            for name in (
                "data_leaks",
                "people",
                "phone",
                "social_osint",
                "email_osint",
                "domain_recon",
            ):
                mod = _get_module(name, effective_salt)
                if mod:
                    try:
                        result = await mod.scan(target)
                        results.append(result)
                        typer.echo(
                            f"  {name}: {result.finding_count} findings", err=True
                        )
                    except Exception as exc:
                        typer.echo(f"  {name}: error - {exc}", err=True)
        else:
            mod = _get_module(module, effective_salt)
            if mod:
                result = await mod.scan(target)
                results.append(result)

        # Generate report
        engine = ReportEngine()
        report_data = engine.from_scan_results(target, results)

        os.makedirs("output", exist_ok=True)
        if output == "html":
            html = render_html(report_data)
            outfile = f"output/report_{target.replace(' ', '_').replace('@', '_at_')}.html"
            with open(outfile, "w") as f:
                f.write(html)
            typer.echo(f"Report saved to: {outfile}", err=True)
        else:
            typer.echo(json.dumps(report_data.to_dict(), indent=2, default=str))

    asyncio.run(_report())


@app.command()
def deep_scan(
    target: str = typer.Argument(
        ..., help="Target to investigate (name, email, username, phone, NIK)"
    ),
    report_format: str = typer.Option(
        "html", "--format", "-f", help="Output format: html, json, stix"
    ),
    output_file: str = typer.Option("", "--output", "-o", help="Output file path"),
    max_iterations: int = typer.Option(5, help="Max recursive scan iterations"),
    timeout: int = typer.Option(30, help="Timeout per module in seconds"),
    fast: bool = typer.Option(
        False,
        "--fast",
        help="Shortcut for --profile fast",
    ),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Collection profile: fast, standard, deep (see docs/INTEL_STANDARD.md)",
    ),
    case_id: str = typer.Option(
        "", "--case", help="Investigation case ID (persists under investigations/)"
    ),
    use_ai: bool = typer.Option(
        False, "--ai", help="Enhance BLUF with AI when API key configured"
    ),
    pdf: bool = typer.Option(False, "--pdf", help="Also write briefing PDF"),
    budget: float = typer.Option(
        15.0, "--budget", help="Execution budget for external APIs (0 = unlimited)"
    ),
    cloak: bool = typer.Option(
        False, "--cloak", help="Enforce CloakBrowser for anti-detect scraping"
    ),
):
    """Deep scan — recursive identity investigation across all modules."""
    from src.investigations.case_manager import CaseManager
    from src.modules.deep_scan.engine import DeepScanEngine
    from src.modules.deep_scan.exports import export_report
    from src.modules.deep_scan.report_generator import generate_intel_report_with_ai
    from src.modules.deep_scan.scan_profiles import resolve_scan_profile

    async def _deep_scan():
        import os

        if cloak:
            os.environ["FORCE_CLOAKBROWSER"] = "1"

        profile_name = "fast" if fast else profile
        try:
            prof = resolve_scan_profile(profile_name)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc

        typer.echo(f"Deep scanning [profile={prof.name}]: {target}", err=True)
        eff_timeout = float(timeout) if timeout != 30 else prof.timeout_per_module
        engine = DeepScanEngine(
            max_iterations=min(max_iterations, prof.max_iterations),
            timeout_per_module=eff_timeout,
            modules=list(prof.modules),
            profile_config=prof,
            budget=budget,
        )
        typer.echo(
            f"Profile: {len(engine._get_active_modules())} modules, "
            f"{engine.max_iterations} iterations, {engine.timeout_per_module}s/module cap",
            err=True,
        )
        result = await engine.scan(target)

        typer.echo(
            f"Results: {result.identifier_count} identifiers, {result.finding_count} findings, {result.iterations} iterations, {result.duration_sec:.1f}s",
            err=True,
        )

        intel = generate_intel_report_with_ai(result, use_ai=use_ai)
        typer.echo(
            f"Intel report: {len(intel.evidence)} evidence, risk={intel.risk.level.value}",
            err=True,
        )

        if case_id:
            prev = CaseManager().load_previous_intel(case_id)
            if prev:
                import json as _json

                from src.modules.deep_scan.delta_briefing import compute_intel_delta

                delta = compute_intel_delta(
                    prev, _json.loads(export_report(intel, fmt="json"))
                )
                typer.echo(
                    f"Delta vs prior run: +{delta['new_evidence_count']} evidence, "
                    f"+{len(delta['new_emails'])} emails, breach Δ{delta['breach_delta']}",
                    err=True,
                )

        os.makedirs("output", exist_ok=True)
        base = (
            output_file or f"output/deep_scan_{target.replace(' ', '_').replace('@', '_at_')}"
        )
        for ext in (".html", ".json", ".stix"):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        html_path = f"{base}.html"
        json_path = f"{base}.json"
        with open(html_path, "w") as f:
            f.write(export_report(intel, fmt="html"))
        json_body = export_report(intel, fmt="json")
        with open(json_path, "w") as f:
            f.write(json_body)
        typer.echo(f"HTML report: {html_path}", err=True)
        typer.echo(f"JSON report: {json_path}", err=True)

        # Compile dossier
        from src.modules.deep_scan.dossier_compiler import DossierCompiler

        all_findings = []
        for sr in result.scan_results:
            all_findings.extend(sr.findings)

        result.dossier = DossierCompiler().compile(
            target,
            social_findings=[f for f in all_findings if f.module == "social_osint"],
            deep_scan_result=result,
        )

        if hasattr(result, "dossier") and result.dossier:
            dossier_html_path = f"{base}_dossier.html"
            dossier_json_path = f"{base}_dossier.json"
            from src.modules.deep_scan.exports.dossier_html import export_dossier_html

            with open(dossier_html_path, "w") as f:
                f.write(export_dossier_html(result.dossier))
            with open(dossier_json_path, "w") as f:
                f.write(result.dossier.model_dump_json(indent=2))
            typer.echo(f"Dossier HTML: {dossier_html_path}", err=True)
            typer.echo(f"Dossier JSON: {dossier_json_path}", err=True)
        if pdf:
            pdf_path = f"{base}.pdf"
            pdf_bytes = export_report(intel, fmt="pdf")
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)
            typer.echo(f"PDF briefing: {pdf_path}", err=True)
        if case_id:
            stix_body = ""
            if report_format == "stix":
                stix_body = export_report(intel, fmt="stix")
            CaseManager().save_run(
                case_id,
                target,
                result,
                intel,
                html=export_report(intel, fmt="html"),
                json_report=json_body,
                stix=stix_body,
                pdf_bytes=export_report(intel, fmt="pdf") if pdf else None,
            )
            typer.echo(f"Case saved: investigations/{case_id}", err=True)
        if report_format == "stix":
            stix_path = f"{base}.stix.json"
            with open(stix_path, "w") as f:
                f.write(export_report(intel, fmt="stix"))
            typer.echo(f"STIX bundle: {stix_path}", err=True)

    asyncio.run(_deep_scan())


@app.command()
def report_from_file(
    report_file: str = typer.Argument(..., help="Path to JSON report file"),
    output: str = typer.Option("html", help="Output format: html, json"),
):
    """Generate report from an existing JSON report file."""
    from src.modules.report_engine import ReportEngine
    from src.modules.report_engine.html_template import render_html

    engine = ReportEngine()
    with open(report_file) as f:
        report_data = engine.parse_report_json(f.read())

    os.makedirs("output", exist_ok=True)
    if output == "html":
        html = render_html(report_data)
        outfile = report_file.replace(".json", ".html")
        if not outfile.startswith("output/"):
            outfile = os.path.join("output", os.path.basename(outfile))
        with open(outfile, "w") as f:
            f.write(html)
        typer.echo(f"Report saved to: {outfile}")
    else:
        typer.echo(json.dumps(report_data.to_dict(), indent=2, default=str))


@app.command(name="zkit-deep-scan")
def zkit_deep_scan(
    target: str = typer.Argument(
        ..., help="Target identifier (Name, Username, Email, Phone, Domain)"
    ),
    max_iterations: int = typer.Option(5, help="Maximum recursive search depth"),
    fast: bool = typer.Option(
        False, "--fast", help="Use fast profile mode (lower timeouts, fewer handles)"
    ),
    output: str = typer.Option("json", help="Output format: json, html"),
    zkit_salt: str = typer.Option(
        "", help="Optional fixed ZKIT salt for stable output"
    ),
):
    """Run a recursive Deep Scan on an identity target, using the ZKIT Engine."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table

    from src.modules.deep_scan.engine import DeepScanEngine

    console = Console()
    console.print(
        Panel(
            f"[bold cyan]1ai-osint Deep Scan[/bold cyan]\nTarget: [bold yellow]{target}[/bold yellow]",
            border_style="cyan",
        )
    )

    engine = DeepScanEngine(
        max_iterations=max_iterations,
        fast=fast,
    )

    # We run it manually inside the async loop with Rich Progress
    async def _run_deep_scan():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(f"Running deep scan on {target}...", total=None)

            # The engine already does internal logging, but the progress bar looks nice.
            try:
                result = await engine.scan(target)
                progress.update(
                    task_id, description="[bold green]Scan complete![/bold green]"
                )
                return result
            except Exception as e:
                progress.update(
                    task_id, description=f"[bold red]Scan failed: {e}[/bold red]"
                )
                raise

    try:
        result = asyncio.run(_run_deep_scan())
    except Exception:
        raise typer.Exit(1)

    # Print Summary Table
    table = Table(title="OSINT Findings Summary")
    table.add_column("Module", style="cyan")
    table.add_column("Title", style="magenta")
    table.add_column("Verified", justify="right", style="green")

    for f in result.findings:
        verified = f.raw_data.get("verified")
        ver_text = "Yes" if verified is True else ("No" if verified is False else "-")
        table.add_row(f.module, f.title[:50], ver_text)

    console.print(table)

    # Output the full result to a file
    import json

    if output == "json":
        outfile = f"output/deep_scan_{target.replace(' ', '_')}.json"
        with open(outfile, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        console.print(f"Full JSON report saved to: [bold]{outfile}[/bold]")
    elif output == "html":
        from src.modules.report_engine import ReportEngine
        from src.modules.report_engine.html_template import render_html

        rep_engine = ReportEngine()
        report_data = rep_engine.from_deep_scan(result)
        html = render_html(report_data)
        outfile = f"output/deep_scan_{target.replace(' ', '_')}.html"
        with open(outfile, "w") as f:
            f.write(html)
        console.print(f"HTML report saved to: [bold]{outfile}[/bold]")


if __name__ == "__main__":
    app()
