"""Tests for src.web.main — entry point module."""

from __future__ import annotations

from fastapi import FastAPI


def test_main_creates_fastapi_app() -> None:
    """Verify main.app is a FastAPI instance."""
    from src.web.main import app

    assert isinstance(app, FastAPI)
