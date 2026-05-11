"""1ai-osint CLI entry point."""

import typer
from typing import Optional

app = typer.Typer(
    help="1ai-osint — AI-Powered OSINT & ZKIT Research Platform",
    add_completion=False,
)


@app.command()
def version():
    """Show version."""
    from src import __version__
    typer.echo(f"1ai-osint v{__version__}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target: URL, path, or query"),
    module: str = typer.Option("all", help="Module to use (gitleaks, data_leaks, people, phone, crypto, zkit)"),
    output: str = typer.Option("json", help="Output format (json, sarif, pdf)"),
    ai: bool = typer.Option(True, help="Enable AI analysis via LangGraph"),
):
    """Run an OSINT scan."""
    typer.echo(f"Scanning {target} with module={module}, output={output}")
    # TODO: implement actual scanning logic


if __name__ == "__main__":
    app()