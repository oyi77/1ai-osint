"""Shared leak source base class and data types."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class RawLeak:
    text: str
    source_name: str
    source_url: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)


class BaseLeakSource(ABC):
    @abstractmethod
    async def fetch_raw_leaks(self) -> list[RawLeak]: ...

    async def search_for_address(self, address: str) -> list[RawLeak]:
        return []
