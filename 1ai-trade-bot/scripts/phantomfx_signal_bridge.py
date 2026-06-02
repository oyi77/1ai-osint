#!/usr/bin/env python3
"""
PhantomFX Signal Bridge
Lightweight HTTP server — connects PhantomFX Connector → MT5 EA

EA polls GET /signal every 3 seconds.
Connector POSTs signals to POST /signal.

Usage:
    python3 phantomfx_signal_bridge.py
    python3 phantomfx_signal_bridge.py --port 8765 --host 0.0.0.0
"""

import argparse
import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("phantomfx-bridge")


class SignalStore:
    """Thread-safe signal queue for MT5 EA polling."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending_signal = None  # Latest pending signal
        self._last_signal_id = None
        self._signal_history = []  # Last 100 signals
        self._max_history = 100

    def put(self, signal: dict) -> str:
        """Store a new signal. Returns signal_id."""
        signal_id = signal.get("signal_id") or f"pfx_{int(time.time() * 1000)}"
        signal["signal_id"] = signal_id
        signal["created_at"] = datetime.now(timezone.utc).isoformat()

        with self._lock:
            self._pending_signal = signal
            self._last_signal_id = signal_id
            self._signal_history.append(signal)
            if len(self._signal_history) > self._max_history:
                self._signal_history = self._signal_history[-self._max_history:]

        logger.info(f"Signal queued: {signal_id} | {signal.get('symbol')} {signal.get('action')}")
        return signal_id

    def get_pending(self) -> dict | None:
        """Get current pending signal (EA polling endpoint)."""
        with self._lock:
            if self._pending_signal is None:
                return None
            return dict(self._pending_signal)

    def ack(self, signal_id: str) -> bool:
        """Acknowledge signal as processed. Clears pending if matches."""
        with self._lock:
            if self._pending_signal and self._pending_signal.get("signal_id") == signal_id:
                logger.info(f"Signal acknowledged: {signal_id}")
                self._pending_signal = None
                return True
        return False

    def status(self) -> dict:
        """Get bridge status."""
        with self._lock:
            return {
                "pending": self._pending_signal is not None,
                "pending_id": self._pending_signal.get("signal_id") if self._pending_signal else None,
                "history_count": len(self._signal_history),
                "last_signal_id": self._last_signal_id,
            }


store = SignalStore()


class SignalHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the signal bridge."""

    def log_message(self, format, *args):
        """Suppress default HTTP logging (we have our own)."""
        logger.debug(format % args)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/signal":
            # EA polling endpoint
            signal = store.get_pending()
            if signal:
                # Return signal as JSON
                self._send_json(signal, 200)
            else:
                self._send_json({}, 200)

        elif self.path == "/status":
            self._send_json(store.status(), 200)

        elif self.path == "/health":
            self._send_json({"status": "ok", "service": "phantomfx-signal-bridge"}, 200)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"error": "invalid json"}, 400)
            return

        if self.path == "/signal":
            # Connector sends signal here
            signal_id = store.put(data)
            self._send_json({"status": "queued", "signal_id": signal_id}, 201)

        elif self.path.startswith("/ack/"):
            # EA acknowledges signal
            signal_id = self.path.split("/")[-1]
            ok = store.ack(signal_id)
            self._send_json({"status": "acked" if ok else "not_found"}, 200 if ok else 404)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description="PhantomFX Signal Bridge")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Listen port (default: 8765)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), SignalHandler)

    logger.info("=" * 55)
    logger.info("⚡ PhantomFX Signal Bridge v4.1")
    logger.info(f"   Listening: http://{args.host}:{args.port}")
    logger.info(f"   EA polls:  GET  http://{args.host}:{args.port}/signal")
    logger.info(f"   Connector: POST http://{args.host}:{args.port}/signal")
    logger.info(f"   Status:    GET  http://{args.host}:{args.port}/status")
    logger.info("=" * 55)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
