"""Node agent — runs on each worker node, communicates with master via Telegram."""
from __future__ import annotations
import asyncio
import logging
import socket
import subprocess
import time
from typing import Any, Optional

import httpx

from src.modules.node.protocol import (
    NodeMessage, NodeStatus, MessageType, CommandType,
)

logger = logging.getLogger(__name__)


class NodeAgent:
    """Worker node agent. Registers with master, heartbeats, executes commands."""

    def __init__(
        self,
        node_id: str,
        telegram_token: str,
        master_chat_id: str,
        role: str = "worker",
        heartbeat_interval: int = 30,
        api_port: int = 8420,
    ):
        self.node_id = node_id
        self.telegram_token = telegram_token
        self.master_chat_id = master_chat_id
        self.role = role
        self.heartbeat_interval = heartbeat_interval
        self.api_port = api_port
        self._start_time = time.monotonic()
        self._scan_count = 0
        self._scanner_process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    async def start(self):
        """Register with master and start heartbeat loop."""
        self._running = True
        logger.info("Node '%s' starting (role=%s)", self.node_id, self.role)

        # Register with master
        await self._send_to_master(NodeMessage(
            msg_type=MessageType.REGISTER,
            node_id=self.node_id,
            payload={
                "hostname": socket.gethostname(),
                "ip": self._get_ip(),
                "version": self._get_version(),
                "role": self.role,
            },
        ))

        # Start heartbeat loop
        while self._running:
            try:
                await self._heartbeat()
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)
                await asyncio.sleep(5)

    async def stop(self):
        """Stop the agent."""
        self._running = False
        if self._scanner_process:
            self._scanner_process.terminate()
            await self._scanner_process.wait()

    async def _heartbeat(self):
        """Send heartbeat to master."""
        import psutil
        mem = psutil.virtual_memory()
        status = NodeStatus(
            node_id=self.node_id,
            hostname=socket.gethostname(),
            ip=self._get_ip(),
            version=self._get_version(),
            role=self.role,
            scanner_running=self._scanner_process is not None and self._scanner_process.returncode is None,
            scan_count=self._scan_count,
            uptime_sec=time.monotonic() - self._start_time,
            memory_mb=mem.used / (1024 * 1024),
            cpu_percent=psutil.cpu_percent(interval=0.1),
        )
        await self._send_to_master(NodeMessage(
            msg_type=MessageType.HEARTBEAT,
            node_id=self.node_id,
            payload=status.to_dict(),
        ))

    async def handle_command(self, command: CommandType, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a command from master."""
        logger.info("Node '%s' executing command: %s", self.node_id, command.value)

        if command == CommandType.START:
            return await self._cmd_start_scanner(payload)
        elif command == CommandType.STOP:
            return await self._cmd_stop_scanner()
        elif command == CommandType.RESTART:
            await self._cmd_stop_scanner()
            return await self._cmd_start_scanner(payload)
        elif command == CommandType.SYNC:
            return await self._cmd_sync()
        elif command == CommandType.STATUS:
            return self._get_status().to_dict()
        elif command == CommandType.SCAN_ONCE:
            return await self._cmd_scan_once(payload)
        else:
            return {"error": f"Unknown command: {command.value}"}

    async def _cmd_start_scanner(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Start the leak-finder scanner."""
        if self._scanner_process and self._scanner_process.returncode is None:
            return {"status": "already_running"}

        sources = payload.get("sources", "all")
        interval = payload.get("interval", 300)

        cmd = [
            "python", "-m", "src.cli", "leak-finder",
            "--sources", str(sources),
            "--continuous", "--interval", str(interval),
        ]

        self._scanner_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        logger.info("Scanner started (PID: %d)", self._scanner_process.pid)
        return {"status": "started", "pid": self._scanner_process.pid}

    async def _cmd_stop_scanner(self) -> dict[str, Any]:
        """Stop the scanner."""
        if not self._scanner_process or self._scanner_process.returncode is not None:
            return {"status": "not_running"}

        self._scanner_process.terminate()
        await self._scanner_process.wait()
        pid = self._scanner_process.pid
        self._scanner_process = None
        logger.info("Scanner stopped (PID: %d)", pid)
        return {"status": "stopped", "pid": pid}

    async def _cmd_sync(self) -> dict[str, Any]:
        """Pull latest code from git and restart."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "pull",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode().strip()

            # Restart scanner if it was running
            was_running = self._scanner_process and self._scanner_process.returncode is None
            if was_running:
                await self._cmd_stop_scanner()
                await self._cmd_start_scanner({})

            return {"status": "synced", "output": output, "restarted": was_running}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    async def _cmd_scan_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run a single scan cycle."""
        sources = payload.get("sources", "all")
        try:
            proc = await asyncio.create_subprocess_exec(
                "python", "-m", "src.cli", "leak-finder",
                "--sources", str(sources),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            self._scan_count += 1
            return {
                "status": "completed",
                "output": stdout.decode()[-2000:],
                "scan_count": self._scan_count,
            }
        except asyncio.TimeoutError:
            return {"status": "timeout"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    async def report_result(self, result: dict[str, Any]):
        """Report scan results to master."""
        await self._send_to_master(NodeMessage(
            msg_type=MessageType.RESULT,
            node_id=self.node_id,
            payload=result,
        ))

    def _get_status(self) -> NodeStatus:
        """Get current node status."""
        import psutil
        mem = psutil.virtual_memory()
        return NodeStatus(
            node_id=self.node_id,
            hostname=socket.gethostname(),
            ip=self._get_ip(),
            version=self._get_version(),
            role=self.role,
            scanner_running=self._scanner_process is not None and self._scanner_process.returncode is None,
            scan_count=self._scan_count,
            uptime_sec=time.monotonic() - self._start_time,
            memory_mb=mem.used / (1024 * 1024),
            cpu_percent=psutil.cpu_percent(interval=0.1),
        )

    async def _send_to_master(self, msg: NodeMessage):
        """Send a message to master via Telegram."""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(url, json={
                    "chat_id": self.master_chat_id,
                    "text": f"[1ai-node]\n{msg.to_telegram()}",
                    "parse_mode": None,
                })
        except Exception as exc:
            logger.debug("Failed to send to master: %s", exc)

    @staticmethod
    def _get_ip() -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "unknown"

    @staticmethod
    def _get_version() -> str:
        """Get git version."""
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=5,
            )
            return proc.stdout.strip() or "unknown"
        except Exception:
            return "unknown"
