"""Shared Typer app instance — imported by main.py and command modules."""

from __future__ import annotations

import typer

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
