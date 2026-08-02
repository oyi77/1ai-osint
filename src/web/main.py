# src/web/main.py
"""Entry point for the 1ai-osint Web UI server."""

from __future__ import annotations

import os

import uvicorn

from src.web.app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("WEB_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=8080)
