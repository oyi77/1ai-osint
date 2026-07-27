# src/web/main.py
"""Entry point for the 1ai-osint Web UI server."""

from __future__ import annotations

import uvicorn
from src.web.app import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
