#!/usr/bin/env python3
"""24/7 Crypto Balance Scanner — random mnemonic scanning with Telegram alerts.

Runs continuously, generating random BIP-39 mnemonics and checking balances
across BTC/ETH/BSC/Polygon/SOL. Sends Telegram notification on any hit (balance > 0).

Usage:
    python run_scanner.py                  # Run with defaults (20 workers)
    python run_scanner.py --workers 50     # Custom worker count
    python run_scanner.py --duration 3600  # Run for 1 hour, then stop
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import httpx

# --- Load .env if present ---
def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

_load_dotenv()

# --- Config ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE = os.environ.get("LOG_FILE", "scanner.log")

# --- Logging ---
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a"),
    ],
)
logger = logging.getLogger("scanner")


async def send_telegram_alert(message: str) -> bool:
    """Send a Telegram notification. Returns True on success."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram not configured (missing token or chat_id)")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown",
            })
            resp.raise_for_status()
            logger.info("Telegram alert sent successfully")
            return True
    except Exception as e:
        logger.error("Telegram alert failed: %s", e)
        return False


def format_hit_alert(mnemonic: str, addresses: list, balances: list) -> str:
    """Format a hit into a Telegram alert message."""
    lines = ["🪙 *WALLET WITH BALANCE FOUND!*", ""]
    lines.append(f"*Mnemonic:* `{mnemonic}`")
    lines.append("")
    for _, bal in zip(addresses, balances):
        if bal and bal.get("balance", 0) > 0:
            lines.append(
                f"*{bal['chain']}*: `{bal['balance']:.8f}` {bal['symbol']}"
            )
            if bal.get("usd_value", 0) > 0:
                lines.append(f"  (~${bal['usd_value']:,.2f})")
            lines.append(f"  Address: `{bal['address']}`")
            lines.append("")
    lines.append(f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    return "\n".join(lines)


async def run_scanner(workers: int = 20, duration: int | None = None) -> None:
    """Run the random scanner continuously with Telegram alerts on hits."""
    from src.modules.crypto.balance.scanner_engine import RandomScanner
    from src.modules.crypto.balance.chains import ALL_CHAINS
    from src.modules.crypto.balance.hit_logger import HitLogger

    logger.info("=" * 60)
    logger.info("  24/7 Crypto Balance Scanner Starting")
    logger.info("=" * 60)
    logger.info(f"  Workers:   {workers}")
    logger.info(f"  Chains:    {', '.join(c.symbol for c in ALL_CHAINS)}")
    logger.info(f"  Duration:  {duration}s" if duration else "  Duration:  unlimited")
    logger.info(f"  Telegram:  {'configured' if TELEGRAM_BOT_TOKEN else 'NOT configured'}")
    logger.info(f"  Log file:  {LOG_FILE}")
    logger.info("=" * 60)

    # Send startup notification
    await send_telegram_alert(
        "🚀 *Crypto Balance Scanner Started*\n\n"
        f"Workers: {workers}\n"
        f"Chains: {', '.join(c.symbol for c in ALL_CHAINS)}\n"
        f"Duration: {'unlimited' if duration else f'{duration}s'}"
    )

    # Create hit logger with alert callback
    hit_logger = HitLogger(
        db_path="wallet_hits.db",
        telegram_token=TELEGRAM_BOT_TOKEN,
        telegram_chat_id=TELEGRAM_CHAT_ID,
    )

    # Create scanner
    scanner = RandomScanner(
        workers=workers,
        chains=list(ALL_CHAINS),
        hit_logger=hit_logger,
    )

    # Graceful shutdown
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _signal_handler():
        logger.info("Shutdown signal received, stopping gracefully...")
        shutdown_event.set()
        scanner._shutdown = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    # Override scanner's stop event
    scanner.__dict__["_stop_event"] = shutdown_event

    start_time = time.monotonic()

    try:
        stats = await scanner.run(duration_sec=duration)
    except Exception as e:
        logger.error("Scanner crashed: %s", e)
        await send_telegram_alert(f"❌ *Scanner crashed:*\n`{e}`")
        raise

    elapsed = time.monotonic() - start_time
    logger.info("=" * 60)
    logger.info("  Scanner Stopped")
    logger.info("=" * 60)
    logger.info(f"  Elapsed:         {elapsed:.1f}s")
    logger.info(f"  Mnemonics:       {stats.mnemonics_generated}")
    logger.info(f"  Addresses:       {stats.addresses_checked}")
    logger.info(f"  Hits:            {stats.hits_found}")
    logger.info(f"  API errors:      {stats.api_errors}")
    logger.info(f"  Throughput:      {stats.mnemonics_per_sec:.1f}/sec")
    logger.info("=" * 60)

    # Send shutdown notification
    await send_telegram_alert(
        "⏹ *Crypto Balance Scanner Stopped*\n\n"
        f"Duration: {elapsed:.0f}s\n"
        f"Mnemonics: {stats.mnemonics_generated}\n"
        f"Addresses: {stats.addresses_checked}\n"
        f"Hits: {stats.hits_found}\n"
        f"Throughput: {stats.mnemonics_per_sec:.1f}/sec"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="24/7 Crypto Balance Scanner")
    parser.add_argument("--workers", type=int, default=20, help="Number of async workers (default: 20)")
    parser.add_argument("--duration", type=int, default=None, help="Duration in seconds (default: unlimited)")
    args = parser.parse_args()

    try:
        asyncio.run(run_scanner(workers=args.workers, duration=args.duration))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
