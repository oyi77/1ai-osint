"""1ai-osint CLI entry point."""

from __future__ import annotations

import typer

# Load .env before any src.* import so settings (API keys, paths) are read
# from the environment even when the CLI runs outside `uv run`.
from dotenv import load_dotenv  # noqa: E402

load_dotenv()  # noqa: E402

from src.cli.app import app  # noqa: E402
from src.core.logging_config import setup_logging as _setup_logging  # noqa: E402

# ---------------------------------------------------------------------------
# Import command modules — triggers @app.command() decorators during import
# ---------------------------------------------------------------------------
from .commands import (  # noqa: E402
    config_commands,  # noqa: F401
    crypto_commands,  # noqa: F401
    identity_commands,  # noqa: F401
    monitor_commands,  # noqa: F401
    node_commands,  # noqa: F401
    scan_commands,  # noqa: F401
)

_LogFormatChoice = typer.Option("text", "--log-format", help="Log output format: text or json.", case_sensitive=False)
_LogLevelOption = typer.Option(
    "INFO", "--log-level", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).", case_sensitive=False
)


@app.callback(invoke_without_command=True)
def _main_callback(
    log_format: str = _LogFormatChoice,
    log_level: str = _LogLevelOption,
) -> None:
    """Global options applied before any sub-command."""
    _setup_logging(level=log_level, json_format=(log_format.lower() == "json"))


if __name__ == "__main__":
    app()
