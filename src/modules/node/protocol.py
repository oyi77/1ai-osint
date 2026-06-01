"""Message protocol for master-node communication."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import json


class MessageType(str, Enum):
    REGISTER = "register"
    HEARTBEAT = "heartbeat"
    COMMAND = "command"
    RESULT = "result"
    STATUS = "status"
    ERROR = "error"
    LOG = "log"


class CommandType(str, Enum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    SYNC = "sync"
    CONFIG = "config"
    STATUS = "status"
    SCAN_ONCE = "scan_once"


@dataclass
class NodeMessage:
    msg_type: MessageType
    node_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_telegram(self) -> str:
        """Serialize for Telegram message (compact JSON)."""
        return json.dumps({
            "t": self.msg_type.value,
            "n": self.node_id,
            "p": self.payload,
            "ts": self.timestamp,
        }, separators=(",", ":"))

    @classmethod
    def from_telegram(cls, text: str) -> NodeMessage | None:
        """Deserialize from Telegram message."""
        try:
            data = json.loads(text)
            return cls(
                msg_type=MessageType(data["t"]),
                node_id=data["n"],
                payload=data.get("p", {}),
                timestamp=data.get("ts", ""),
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None


@dataclass
class NodeStatus:
    node_id: str
    hostname: str
    ip: str
    version: str
    role: str = "worker"  # worker or master
    scanner_running: bool = False
    sources_count: int = 0
    scan_count: int = 0
    last_scan: str = ""
    uptime_sec: float = 0
    memory_mb: float = 0
    cpu_percent: float = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "version": self.version,
            "role": self.role,
            "scanner_running": self.scanner_running,
            "sources_count": self.sources_count,
            "scan_count": self.scan_count,
            "last_scan": self.last_scan,
            "uptime_sec": self.uptime_sec,
            "memory_mb": self.memory_mb,
            "cpu_percent": self.cpu_percent,
            "errors": self.errors,
        }
