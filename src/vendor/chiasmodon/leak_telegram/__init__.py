import asyncio
import os
from typing import Any

from src.vendor.chiasmodon.base import OSINTTool


class TelegramLeakTool(OSINTTool):
    """Telegram leak scanner wrapper.

    Delegates to TelegramLeakScanner from the balance leak scanner module.
    Requires TELEGRAM_BOT_TOKEN in environment.
    """

    name = "telegramleak"

    def search(self, query: str, **kwargs) -> dict[str, Any]:
        return {"status": "stub", "tool": self.name, "query": query, "result": []}

    def scan(self, query: str, **kwargs) -> dict[str, Any]:
        """Scan Telegram channels for leaked credentials.

        Args:
            query: Ignored — scans all configured channels.
            **kwargs: max_messages (int), channel_ids (list[str]).

        Returns:
            Dict with scan results including findings count.
        """
        try:
            from src.modules.crypto.balance.leak_scanner import TelegramLeakScanner
            from src.modules.crypto.balance.hit_logger import HitLogger

            bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
            if not bot_token:
                return {"status": "skipped", "tool": self.name, "error": "TELEGRAM_BOT_TOKEN not set"}

            max_messages = kwargs.get("max_messages", 100)
            channel_ids = kwargs.get("channel_ids", [])

            scanner = TelegramLeakScanner(
                bot_token=bot_token,
                channel_ids=channel_ids,
            )

            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in an async context — use a new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    findings = pool.submit(
                        asyncio.run, scanner.scan(max_messages=max_messages)
                    ).result(timeout=120)
            else:
                findings = loop.run_until_complete(scanner.scan(max_messages=max_messages))

            return {
                "status": "ok",
                "tool": self.name,
                "findings_count": len(findings),
                "mnemonics": [f.mnemonic_candidate for f in findings if f.source_type == "mnemonic"],
                "private_keys": [f.mnemonic_candidate[:16] + "..." for f in findings if f.source_type == "private_key"],
            }
        except ImportError:
            return {"status": "error", "tool": self.name, "error": "leak_scanner module not available"}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}

    def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        return {"note": "Not implemented"}

    def learn(self, feedback: Any, **kwargs) -> None:
        pass
