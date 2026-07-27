"""Scan-related commands — scan, deep-scan, zkit-deep-scan, report, report-from-file."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, cast

import typer

from ..app import app
from ..helpers import get_module, run_with_ai, run_zkit_tracking

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
def scan(
    target: str = typer.Argument("random", help="Target: URL, path, email, mnemonic, or 'random' for random scan"),
    module: str = typer.Option("all", help=f"Module to use ({', '.join(SCAN_MODULES)})"),
    output: str = typer.Option("json", help=f"Output format ({', '.join(OUTPUT_FORMATS)})"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI analysis via orchestrator"),
    zkit: bool = typer.Option(False, "--zkit", help="Enable ZKIT identity tracking"),
    zkit_salt: str = typer.Option("", help="ZKIT salt for privacy-preserving identity hashing"),
    timeout: int = typer.Option(300, help="Scan timeout in seconds"),
    # crypto_balance specific options
    scan_mode: str = typer.Option(
        "",
        help="Scan mode for crypto_balance: 'random', 'targeted', 'leak', or 'smart' (auto-detected if omitted)",
    ),
    workers: int = typer.Option(20, help="Number of concurrent workers for random scan"),
    duration: int = typer.Option(0, help="Duration in seconds for random scan (0 = use iterations)"),
    account_count: int = typer.Option(1, help="Number of accounts to derive per chain"),
    min_balance: float = typer.Option(0.0, help="Minimum balance threshold for random scan hits"),
) -> None:
    """Run an OSINT scan against a target.

    For crypto_balance module with 'random' target, generates random mnemonics.
    For crypto_balance with a mnemonic target, derives and checks balances.
    """

    from src.core.config import settings

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
            mod = get_module(name, effective_salt)
            if mod:
                modules_to_run.append(mod)
    else:
        mod = get_module(module, effective_salt)
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
                result = run_zkit_tracking(result, effective_salt)

            # Apply AI analysis if enabled
            result = run_with_ai(result, ai)

            all_results.append(result)
            typer.echo(
                f"  {mod.name}: {result.finding_count} findings " f"({result.critical_count} critical)",
                err=True,
            )
        except Exception as e:
            typer.echo(f"  {mod.name}: Error - {e}", err=True)

    # Output results
    if output == "json":
        output_data = [r.model_dump() for r in all_results]
        typer.echo(json.dumps(output_data, indent=2, default=str))
    elif output == "sarif":
        from src.modules.output.sarif import format_sarif as _format_sarif

        sarif_json = _format_sarif(all_results)
        typer.echo(sarif_json)
    elif output == "pdf":
        from src.modules.output.pdf_export import format_pdf as _format_pdf

        pdf_bytes = _format_pdf(all_results)
        sys.stdout.buffer.write(pdf_bytes)
        typer.echo("", err=True)  # newline on stderr so terminal stays clean


@app.command()
def deep_scan(
    target: str = typer.Argument(..., help="Target to investigate (name, email, username, phone, NIK)"),
    report_format: str = typer.Option("html", "--format", "-f", help="Output format: html, json, stix"),
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
    case_id: str = typer.Option("", "--case", help="Investigation case ID (persists under investigations/)"),
    use_ai: bool = typer.Option(False, "--ai", help="Enhance BLUF with AI when API key configured"),
    pdf: bool = typer.Option(False, "--pdf", help="Also write briefing PDF"),
    budget: float = typer.Option(15.0, "--budget", help="Execution budget for external APIs (0 = unlimited)"),
) -> None:
    """Deep scan — recursive identity investigation across all modules."""
    import json as _json

    from src.investigations.case_manager import CaseManager
    from src.modules.deep_scan.engine import DeepScanEngine
    from src.modules.deep_scan.exports import export_report
    from src.modules.deep_scan.report_generator import generate_intel_report_with_ai
    from src.modules.deep_scan.scan_profiles import resolve_scan_profile

    async def _deep_scan() -> None:
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
            f"Results: {result.identifier_count} identifiers, {result.finding_count} findings, "
            f"{result.iterations} iterations, {result.duration_sec:.1f}s",
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
                from src.modules.deep_scan.delta_briefing import compute_intel_delta

                delta = compute_intel_delta(prev, _json.loads(export_report(intel, fmt="json")))
                typer.echo(
                    f"Delta vs prior run: +{delta['new_evidence_count']} evidence, "
                    f"+{len(delta['new_emails'])} emails, breach \u0394{delta['breach_delta']}",
                    err=True,
                )

        os.makedirs("output", exist_ok=True)
        base = output_file or f"output/deep_scan_{target.replace(' ', '_').replace('@', '_at_')}"
        for ext in (".html", ".json", ".stix"):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        html_path = f"{base}.html"
        json_path = f"{base}.json"
        with open(html_path, "w") as f:
            f.write(cast(str, export_report(intel, fmt="html")))
        json_body = cast(str, export_report(intel, fmt="json"))
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
            pdf_bytes = cast(bytes, export_report(intel, fmt="pdf"))
            with open(pdf_path, "wb") as fw:
                fw.write(pdf_bytes)
            typer.echo(f"PDF briefing: {pdf_path}", err=True)
        if case_id:
            stix_body: str = ""
            if report_format == "stix":
                stix_body = cast(str, export_report(intel, fmt="stix"))
            CaseManager().save_run(
                case_id,
                target,
                result,
                intel,
                html=cast(str, export_report(intel, fmt="html")),
                json_report=json_body,
                stix=stix_body,
                pdf_bytes=cast(bytes, export_report(intel, fmt="pdf")) if pdf else None,
            )
            typer.echo(f"Case saved: investigations/{case_id}", err=True)
        if report_format == "stix":
            stix_path = f"{base}.stix.json"
            with open(stix_path, "w") as f:
                f.write(cast(str, export_report(intel, fmt="stix")))
            typer.echo(f"STIX bundle: {stix_path}", err=True)

    asyncio.run(_deep_scan())


@app.command()
def report(
    target: str = typer.Argument(..., help="Target to generate report for"),
    output: str = typer.Option("html", help="Output format: html, json"),
    module: str = typer.Option("all", help="Module to scan first, or 'all'"),
) -> None:
    """Generate a comprehensive OSINT report for a target."""
    from src.modules.report_engine import ReportEngine
    from src.modules.report_engine.html_template import render_html

    async def _report() -> None:
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
                mod = get_module(name, effective_salt)
                if mod:
                    try:
                        result = await mod.scan(target)
                        results.append(result)
                        typer.echo(f"  {name}: {result.finding_count} findings", err=True)
                    except Exception as exc:
                        typer.echo(f"  {name}: error - {exc}", err=True)
        else:
            mod = get_module(module, effective_salt)
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
def report_from_file(
    report_file: str = typer.Argument(..., help="Path to JSON report file"),
    output: str = typer.Option("html", help="Output format: html, json"),
) -> None:
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
    target: str = typer.Argument(..., help="Target identifier (Name, Username, Email, Phone, Domain)"),
    max_iterations: int = typer.Option(5, help="Maximum recursive search depth"),
    fast: bool = typer.Option(False, "--fast", help="Use fast profile mode (lower timeouts, fewer handles)"),
    output: str = typer.Option("json", help="Output format: json, html"),
    zkit_salt: str = typer.Option("", help="Optional fixed ZKIT salt for stable output"),
) -> None:
    """Run a recursive Deep Scan on an identity target, using the ZKIT Engine."""
    import json as _json

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
    async def _run_deep_scan() -> Any:
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
                progress.update(task_id, description="[bold green]Scan complete![/bold green]")
                return result
            except Exception as e:
                progress.update(task_id, description=f"[bold red]Scan failed: {e}[/bold red]")
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
    if output == "json":
        outfile = f"output/deep_scan_{target.replace(' ', '_')}.json"
        with open(outfile, "w") as f:
            _json.dump(result.to_dict(), f, indent=2, default=str)
        console.print(f"Full JSON report saved to: [bold]{outfile}[/bold]")
    elif output == "html":
        from src.modules.report_engine import ReportEngine
        from src.modules.report_engine.html_template import render_html

        rep_engine = ReportEngine()
        report_data = rep_engine.from_deep_scan(result)  # type: ignore[attr-defined]
        html = render_html(report_data)
        outfile = f"output/deep_scan_{target.replace(' ', '_')}.html"
        with open(outfile, "w") as f:
            f.write(html)
        console.print(f"HTML report saved to: [bold]{outfile}[/bold]")
