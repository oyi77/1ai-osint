#!/usr/bin/env python3
"""
PhantomFX Connector
Bridge between OpenClaw PhantomFX analysis output → MT5 Router + Telegram

Usage:
    # Pipe OpenClaw/PhantomFX output directly:
    echo '{"action":"BUY","symbol":"XAUUSD",...}' | python3 phantomfx_connector.py

    # Or from file:
    python3 phantomfx_connector.py --input phantomfx_output.txt

    # Direct JSON:
    python3 phantomfx_connector.py --json '{"action":"BUY",...}'

    # Send Telegram signal only (no MT5):
    python3 phantomfx_connector.py --telegram-only --json '...'

    # Dry run (no execution):
    python3 phantomfx_connector.py --dry-run --input output.txt

Architecture:
    OpenClaw/PhantomFX → phantomfx_connector.py → MT5 Router API (:8080)
                                                  → Telegram Bot
                                                  → Trade Log (SQLite)

Environment Variables:
    MT5_ROUTER_URL: MT5 Router API base URL (default: http://localhost:8080)
    MT5_ROUTER_API_KEY: API key for MT5 Router
    MT5_INSTANCE_ID: MT5 instance ID for trade execution
    TELEGRAM_BOT_TOKEN: Bot token for @berkahkaryaforexbotbot
    TELEGRAM_CHAT_ID: Target chat ID for signals (default: @berkahkaryaforexbotbot)
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import requests

# ─── Config ───────────────────────────────────────────────────────────────
PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_DIR / "logs"
DATA_DIR = PROJECT_DIR / "data" / "phantomfx"
DB_PATH = DATA_DIR / "trades.db"

# Auto-load .env from multiple locations
def _load_env():
    """Load .env file if present."""
    env_paths = [
        PROJECT_DIR / "strategies" / "phantomfx" / ".env",
        PROJECT_DIR / ".env",
        Path.home() / ".phantomfx.env",
    ]
    for env_path in env_paths:
        if env_path.exists():
            try:
                from dotenv import load_dotenv
                load_dotenv(env_path)
                break
            except ImportError:
                # Manual dotenv parsing
                with open(env_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, _, val = line.partition('=')
                            os.environ.setdefault(key.strip(), val.strip())
                break

_load_env()

MT5_ROUTER_URL = os.environ.get("MT5_ROUTER_URL", "http://localhost:8080")
MT5_ROUTER_API_KEY = os.environ.get("MT5_ROUTER_API_KEY", "")
MT5_INSTANCE_ID = os.environ.get("MT5_INSTANCE_ID", "mt5-default")

# Telegram config
TELEGRAM_BOT_TOKEN = os.environ.get("PHANTOMFX_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("PHANTOMFX_TELEGRAM_CHAT_ID", "@berkahkaryaforexbotbot")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "phantomfx_connector.log"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("phantomfx")


def ensure_dirs():
    """Create required directories."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def init_db():
    """Initialize SQLite trade log database."""
    ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cycle_id TEXT,
            timestamp TEXT NOT NULL,
            session TEXT,
            combat_style TEXT,
            symbol TEXT NOT NULL,
            action TEXT NOT NULL,
            entry REAL,
            sl REAL,
            tp REAL,
            sl_pips REAL,
            tp_pips REAL,
            rr_ratio TEXT,
            skc_total REAL,
            skc_zone TEXT,
            risk_tier TEXT,
            grade TEXT,
            confidence REAL,
            mt5_ticket INTEGER,
            mt5_status TEXT,
            telegram_sent INTEGER DEFAULT 0,
            raw_json TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


def parse_phantomfx_output(text: str) -> Optional[Dict[str, Any]]:
    """Parse PhantomFX output, extracting the system JSON block."""
    # Try to find JSON block enclosed in ```json ... ```
    json_match = re.search(r'```json\s*\n(.*?)\n```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find raw JSON object
    json_match = re.search(r'\{[^{}]*"system"\s*:\s*"PhantomFX[^}]*\}', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # Try parsing entire text as JSON
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from first { to last }
    try:
        start = text.index('{')
        end = text.rindex('}') + 1
        return json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        pass

    logger.error("Failed to parse PhantomFX JSON from output")
    return None


def extract_telegram_signal(text: str) -> Optional[str]:
    """Extract Telegram signal block from PhantomFX output."""
    match = re.search(
        r'---TELEGRAM_SIGNAL_START---\n(.*?)\n---TELEGRAM_SIGNAL_END---',
        text, re.DOTALL
    )
    if match:
        return match.group(1).strip()
    return None


def extract_killzone_broadcast(text: str) -> Optional[str]:
    """Extract killzone broadcast block."""
    match = re.search(
        r'---TELEGRAM_KILLZONE_START---\n(.*?)\n---TELEGRAM_KILLZONE_END---',
        text, re.DOTALL
    )
    if match:
        return match.group(1).strip()
    return None


def extract_circuit_alert(text: str) -> Optional[str]:
    """Extract circuit breaker alert block."""
    match = re.search(
        r'---TELEGRAM_CIRCUIT_START---\n(.*?)\n---TELEGRAM_CIRCUIT_END---',
        text, re.DOTALL
    )
    if match:
        return match.group(1).strip()
    return None


def send_telegram(message: str, parse_mode: str = "MarkdownV2") -> bool:
    """Send message to Telegram bot."""
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set, skipping Telegram send")
        return False

    # Escape special characters for MarkdownV2 if needed
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("Telegram message sent successfully")
            return True
        else:
            # Try without parse_mode if Markdown fails
            if parse_mode:
                payload["parse_mode"] = ""
                resp2 = requests.post(url, json=payload, timeout=10)
                if resp2.status_code == 200:
                    logger.info("Telegram message sent (plain text fallback)")
                    return True
            logger.error(f"Telegram send failed: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Telegram send error: {e}")
        return False


def send_to_mt5_router(parsed: Dict[str, Any]) -> Tuple[bool, str]:
    """Send trade signal to MT5 Router API."""
    if not parsed.get("mt5_webhook", {}).get("ready"):
        return False, "MT5 webhook not ready"

    webhook = parsed["mt5_webhook"]
    action = parsed.get("action", "HOLD").upper()

    if action == "HOLD" or webhook.get("type") == "SKIP":
        return False, "Signal is HOLD/SKIP"

    # Map to MT5 Router order format
    order = {
        "symbol": webhook.get("symbol", parsed.get("symbol", "XAUUSD")),
        "order_type": "OP_BUY" if action == "BUY" else "OP_SELL",
        "volume": 0.01,  # Default, risk-based sizing done by EA
        "sl": webhook.get("sl", parsed.get("sl", 0)),
        "tp": webhook.get("tp", parsed.get("tp", 0)),
        "comment": webhook.get("comment", f"PhantomFX_{parsed.get('combat_style','AUTO')}"),
    }

    headers = {"Content-Type": "application/json"}
    if MT5_ROUTER_API_KEY:
        headers["X-API-Key"] = MT5_ROUTER_API_KEY

    # Try MT5 Router webhook endpoint first
    url = f"{MT5_ROUTER_URL}/api/v1/webhooks/receive"
    payload = {
        "event_type": "phantomfx_signal",
        "payload": {
            "symbol": order["symbol"],
            "action": "BUY" if order["order_type"] == "OP_BUY" else "SELL",
            "volume": order["volume"],
            "sl": order["sl"],
            "tp": order["tp"],
            "comment": order["comment"],
        },
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        logger.info(f"MT5 webhook response: {resp.status_code} {resp.text}")
        if resp.status_code in (200, 201):
            return True, f"Webhook accepted: {resp.json().get('status', 'ok')}"
        else:
            return False, f"Webhook failed: {resp.status_code}"
    except requests.exceptions.ConnectionError:
        # Try direct trading API as fallback
        logger.info("Webhook endpoint unreachable, trying direct trading API...")
        try:
            trade_url = f"{MT5_ROUTER_URL}/api/v1/trading/orders?instance_id={MT5_INSTANCE_ID}"
            resp = requests.post(trade_url, json=order, headers=headers, timeout=10)
            logger.info(f"MT5 trading API response: {resp.status_code}")
            if resp.status_code in (200, 201):
                data = resp.json()
                ticket = data.get("ticket", "unknown")
                return True, f"Order placed: ticket {ticket}"
            return False, f"Trading API failed: {resp.status_code} {resp.text}"
        except Exception as e:
            return False, f"Trading API error: {e}"
    except Exception as e:
        return False, f"MT5 Router error: {e}"


def log_trade(parsed: Dict[str, Any], status: str, result: str):
    """Log trade to SQLite database."""
    conn = init_db()
    try:
        webhook = parsed.get("mt5_webhook", {})
        skc = parsed.get("skc_score", {})
        conn.execute("""
            INSERT INTO trades (
                cycle_id, timestamp, session, combat_style, symbol, action,
                entry, sl, tp, sl_pips, tp_pips, rr_ratio,
                skc_total, skc_zone, risk_tier, grade, confidence,
                mt5_status, telegram_sent, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            parsed.get("cycle_id", ""),
            datetime.now(timezone.utc).isoformat(),
            parsed.get("session", ""),
            parsed.get("combat_style", ""),
            parsed.get("symbol", ""),
            parsed.get("action", ""),
            parsed.get("entry", 0),
            parsed.get("sl", 0),
            parsed.get("tp", 0),
            parsed.get("sl_pips", 0),
            parsed.get("tp_pips", 0),
            parsed.get("rr_ratio", ""),
            skc.get("total", 0),
            skc.get("zone", ""),
            parsed.get("risk_tier", ""),
            parsed.get("grade", ""),
            parsed.get("confidence", 0),
            f"{status}: {result}",
            1 if TELEGRAM_BOT_TOKEN else 0,
            json.dumps(parsed),
        ))
        conn.commit()
        logger.info(f"Trade logged: {parsed.get('symbol')} {parsed.get('action')}")
    except Exception as e:
        logger.error(f"Failed to log trade: {e}")
    finally:
        conn.close()


def process_output(text: str, dry_run: bool = False, telegram_only: bool = False) -> Dict[str, Any]:
    """Process full PhantomFX output text."""
    result = {
        "parsed": False,
        "mt5_sent": False,
        "telegram_sent": False,
        "killzone_sent": False,
        "circuit_sent": False,
        "details": "",
    }

    # Parse JSON
    parsed = parse_phantomfx_output(text)
    if not parsed:
        result["details"] = "Failed to parse PhantomFX JSON"
        return result

    result["parsed"] = True
    action = parsed.get("action", "HOLD").upper()

    # Send Telegram signal
    if parsed.get("notify_telegram", False) or action != "HOLD":
        signal_msg = extract_telegram_signal(text)
        if signal_msg:
            if not dry_run:
                if send_telegram(signal_msg):
                    result["telegram_sent"] = True

    # Send killzone broadcast
    killzone_msg = extract_killzone_broadcast(text)
    if killzone_msg:
        if not dry_run:
            if send_telegram(killzone_msg):
                result["killzone_sent"] = True

    # Send circuit breaker alert (highest priority)
    circuit_msg = extract_circuit_alert(text)
    if circuit_msg:
        if not dry_run:
            if send_telegram(circuit_msg):
                result["circuit_sent"] = True
        result["details"] = "Circuit breaker active — no trades executed"
        log_trade(parsed, "circuit_breaker", "HOLD")
        return result

    # Send to MT5
    if not telegram_only and action != "HOLD":
        if dry_run:
            logger.info(f"DRY RUN: Would send {action} {parsed.get('symbol')} "
                        f"@ {parsed.get('entry')} SL:{parsed.get('sl')} TP:{parsed.get('tp')}")
            result["mt5_sent"] = True
            result["details"] = "Dry run — no trade executed"
        else:
            success, detail = send_to_mt5_router(parsed)
            result["mt5_sent"] = success
            result["details"] = detail
            log_trade(parsed, "success" if success else "failed", detail)
    else:
        result["details"] = f"Signal {action} — {'telegram only' if telegram_only else 'HOLD/mt5 skipped'}"

    return result


def main():
    parser = argparse.ArgumentParser(description="PhantomFX Connector — OpenClaw → MT5 + Telegram")
    parser.add_argument("--input", "-i", type=str, help="Input file (PhantomFX output)")
    parser.add_argument("--json", "-j", type=str, help="Direct JSON input string")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Dry run (no execution)")
    parser.add_argument("--telegram-only", "-t", action="store_true", help="Send Telegram only, skip MT5")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get input
    if args.json:
        text = args.json
    elif args.input:
        text = Path(args.input).read_text()
    else:
        # Read from stdin
        if sys.stdin.isatty():
            print("PhantomFX Connector — waiting for input on stdin...", file=sys.stderr)
            print("Usage: echo '{json}' | phantomfx_connector.py", file=sys.stderr)
            sys.exit(1)
        text = sys.stdin.read()

    if not text.strip():
        logger.error("No input provided")
        sys.exit(1)

    ensure_dirs()

    result = process_output(text, dry_run=args.dry_run, telegram_only=args.telegram_only)

    # Output result
    print(json.dumps(result, indent=2))

    if result["parsed"]:
        logger.info(f"Processed: MT5={'✓' if result['mt5_sent'] else '✗'} "
                    f"TG={'✓' if result['telegram_sent'] else '✗'} "
                    f"Details: {result['details']}")
    else:
        logger.error(f"Failed: {result['details']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
