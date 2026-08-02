"""Configuration, version, and utility commands."""

from __future__ import annotations

import typer

from ..app import SCAN_MODULES, app


@app.command()
def version() -> None:
    """Show version."""
    from src import __version__

    typer.echo(f"1ai-osint v{__version__}")


@app.command()
def doctor() -> None:
    """Check environment: Python, sherlock, breach API keys, providers."""
    from src.doctor import format_doctor_report, run_doctor

    results = run_doctor()
    typer.echo(format_doctor_report(results))
    hard_fail = [r for r in results if not r.ok and not r.name.startswith("breach:")]
    if hard_fail:
        raise typer.Exit(code=1)


@app.command()
def modules() -> None:
    """List all available OSINT modules."""
    from src.modules import list_modules

    registered = list_modules()
    typer.echo("Available modules:")
    for name in sorted(registered):
        typer.echo(f"  - {name}")
    typer.echo(f"\nTotal: {len(registered)} modules")

    # Also show modules available via get_module but not in registry
    extra = [m for m in SCAN_MODULES if m not in registered and m != "all"]
    if extra:
        typer.echo(f"\nAlso available via --module: {', '.join(extra)}")


@app.command()
def plugins() -> None:
    """List all registered plugins."""
    from src.cli.helpers import init_plugins

    registry = init_plugins()
    all_plugins = registry.list()

    if not all_plugins:
        typer.echo("No plugins registered.")
        return

    typer.echo("Registered plugins:")
    for p in all_plugins:
        hooks_str = ", ".join(p.hooks) if p.hooks else "(none)"
        typer.echo(f"  {p.name} v{p.version}")
        if p.description:
            typer.echo(f"    {p.description}")
        typer.echo(f"    hooks: [{hooks_str}]")
    typer.echo(f"\nTotal: {len(all_plugins)} plugin(s)")


@app.command()
def install(
    package: str = typer.Argument(
        ..., help="pip package name (or local path) exposing a 1ai_osint.plugins entry point"
    ),
    upgrade: bool = typer.Option(False, "--upgrade", help="Pass --upgrade to pip"),
) -> None:
    """Install a plugin package and register it with the plugin registry.

    Installs *package* via pip (into the active environment), then
    re-discovers plugins so the newly installed entry points are picked up.
    Any distribution exposing a ``1ai_osint.plugins`` entry point group
    (declared in its ``[project.entry-points."1ai_osint.plugins"]`` section)
    is loaded automatically — no code changes needed.

    Example:
        osint install socmint-twitter-pro
    """
    import subprocess
    import sys

    from src.plugin import PluginRegistry, reset_plugins

    pip_args = [sys.executable, "-m", "pip", "install"]
    if upgrade:
        pip_args.append("--upgrade")
    pip_args.append(package)

    typer.echo(f"Installing {package} ...")
    proc = subprocess.run(pip_args, capture_output=True, text=True)
    if proc.returncode != 0:
        typer.echo(proc.stderr.strip(), err=True)
        raise typer.Exit(code=1)
    typer.echo(proc.stdout.strip())

    # Force a fresh discovery so the new package's entry points are visible.
    reset_plugins()
    registry = PluginRegistry()
    discovered = registry.discover()
    new_names = [p.name for p in discovered]
    if new_names:
        typer.echo(f"Registered plugin(s): {', '.join(new_names)}")
    else:
        typer.echo(
            f"Installed {package}, but no 1ai_osint.plugins entry points were "
            "found. The package may not be a 1ai-osint plugin.",
        )
        raise typer.Exit(code=2)


@app.command()
def web(
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind the web server to"),
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Host address to bind to"),
) -> None:
    """Start the 1ai-osint Web UI dashboard server.

    Launches a FastAPI web application with a dashboard, entity browser,
    report viewer, and timeline visualization.
    """
    import uvicorn

    from src.web.app import create_app

    typer.echo(f"Starting 1ai-osint Web UI on {host}:{port}...")
    web_app = create_app()
    uvicorn.run(web_app, host=host, port=port)
