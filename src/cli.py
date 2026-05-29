"""1ai-osint CLI entry point."""

import asyncio
import json
import sys
from datetime import datetime

import typer

app = typer.Typer(
    help="1ai-osint -- AI-Powered OSINT & ZKIT Research Platform",
    add_completion=False,
)

# Valid module names for the scan command
SCAN_MODULES = ("gitleaks", "data_leaks", "people", "phone", "crypto_passphrase", "crypto_privatekey", "crypto_balance", "all")
OUTPUT_FORMATS = ("json", "sarif", "pdf")


@app.command()
def version():
    """Show version."""
    from src import __version__

    typer.echo(f"1ai-osint v{__version__}")


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
        from src.modules.people_finder import PeopleFinderTool

        return PeopleFinderTool(zkit_salt=zkit_salt)
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
        from src.models import Finding, ScanResult, Severity

        scan_id = f"passphrase-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        started_at = datetime.utcnow()
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
            completed_at=datetime.utcnow(),
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
                graph.add_raw_attribute(
                    raw_val, node_type, source=result.module
                )

            # Add co-occurrence edges between attributes in the same finding
            for i in range(len(attrs)):
                for j in range(i + 1, len(attrs)):
                    graph.add_co_occurrence(
                        attrs[i][0], attrs[i][1],
                        attrs[j][0], attrs[j][1],
                        source=result.module,
                    )

        result.metadata["zkit_graph"] = {
            "nodes": graph.node_count,
            "edges": graph.edge_count,
        }
    except Exception as e:
        result.metadata["zkit_error"] = str(e)

    return result


def _format_sarif(results: list) -> str:
    """Format scan results as SARIF 2.1.0."""
    sarif_runs = []
    all_rules = []
    all_results = []

    for scan_result in results:
        for finding in (scan_result.findings or []):
            rule_id = finding.id
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

            # Map to SARIF level
            level = "none"
            if severity in ("critical", "high"):
                level = "error"
            elif severity == "medium":
                level = "warning"
            elif severity == "low":
                level = "note"

            all_rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {"level": level},
            })

            raw = finding.raw_data or {}
            all_results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.description},
                "properties": {
                    "module": finding.module,
                    "confidence": finding.confidence,
                    "tags": finding.tags,
                },
            })

    sarif_runs.append({
        "tool": {
            "driver": {
                "name": "1ai-osint",
                "version": "0.1.0",
                "rules": all_rules,
            }
        },
        "results": all_results,
    })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": sarif_runs,
    }
    return json.dumps(sarif, indent=2, default=str)


def _format_pdf(results: list) -> bytes:
    """Format scan results as a PDF report."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from io import BytesIO

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("1ai-osint Scan Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    elements.append(Spacer(1, 24))

    for scan_result in results:
        elements.append(Paragraph(f"Module: {scan_result.module}", styles["Heading2"]))
        elements.append(Paragraph(f"Target: {scan_result.target}", styles["Normal"]))
        elements.append(Paragraph(f"Status: {scan_result.status}", styles["Normal"]))
        elements.append(Paragraph(f"Findings: {scan_result.finding_count}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        if scan_result.findings:
            table_data = [["Severity", "Title", "Confidence"]]
            for f in scan_result.findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                table_data.append([sev, f.title[:60], f"{f.confidence:.0%}"])

            table = Table(table_data, colWidths=[80, 300, 70])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                    ]
                )
            )
            elements.append(table)
            elements.append(Spacer(1, 24))

    doc.build(elements)
    return buffer.getvalue()


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
    zkit_salt: str = typer.Option("", help="ZKIT salt for privacy-preserving identity hashing"),
    timeout: int = typer.Option(300, help="Scan timeout in seconds"),
    # crypto_balance specific options
    scan_mode: str = typer.Option(
        "", help="Scan mode for crypto_balance: 'random', 'targeted', 'leak', or 'smart' (auto-detected if omitted)"
    ),
    workers: int = typer.Option(20, help="Number of concurrent workers for random scan"),
    duration: int = typer.Option(0, help="Duration in seconds for random scan (0 = use iterations)"),
    account_count: int = typer.Option(1, help="Number of accounts to derive per chain"),
    min_balance: float = typer.Option(0.0, help="Minimum balance threshold for random scan hits"),
):
    """Run an OSINT scan against a target.

    For crypto_balance module with 'random' target, generates random mnemonics.
    For crypto_balance with a mnemonic target, derives and checks balances.
    """
    from src.config import settings

    effective_salt = zkit_salt or settings.zkit_salt

    if output not in OUTPUT_FORMATS:
        typer.echo(f"Error: Unknown output format '{output}'. Use: {', '.join(OUTPUT_FORMATS)}", err=True)
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
        "github,paste,telegram,tgstat",
        "--sources", "-s",
        help="Comma-separated list of sources: github, paste, telegram, tgstat",
    ),
    interval: int = typer.Option(
        300, "--interval", "-i", help="Seconds between runs in continuous mode (default: 300)"
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
        LeakFinderCoordinator,
        ALL_SOURCES,
    )

    source_list = [s.strip() for s in sources.split(",") if s.strip()]
    invalid = [s for s in source_list if s not in ALL_SOURCES]
    if invalid:
        typer.echo(
            f"Error: Unknown source(s): {', '.join(invalid)}. "
            f"Valid sources: {', '.join(ALL_SOURCES)}",
            err=True,
        )
        raise typer.Exit(1)

    coordinator = LeakFinderCoordinator(
        sources=source_list,
        github_token=github_token or None,
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


if __name__ == "__main__":
    app()
