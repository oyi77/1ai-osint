"""Paste site source adapter for crypto leak discovery."""

from __future__ import annotations

import asyncio
import logging
import re

import httpx
from bs4 import BeautifulSoup

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class PasteSource:
    SOURCES = [
        ("pastebin", "https://pastebin.com/archive", "https://pastebin.com/raw/{id}"),
        ("dpaste", "https://dpaste.org/archive/", "https://dpaste.org/{id}.txt"),
        ("rentry", "https://rentry.co/", "https://rentry.co/{id}/raw"),
    ]

    def __init__(
        self,
        max_pastes_per_source: int = 50,
        request_delay: float = 1.0,
        timeout: float = 30.0,
    ):
        self.max_pastes_per_source = max_pastes_per_source
        self.request_delay = request_delay
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        all_leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        ) as client:
            for name, archive_url, raw_tpl in self.SOURCES:
                try:
                    paste_ids = await self._get_paste_ids(client, archive_url, name)
                    for pid in paste_ids[: self.max_pastes_per_source]:
                        raw_url = raw_tpl.format(id=pid)
                        try:
                            await asyncio.sleep(self.request_delay)
                            resp = await client.get(raw_url)
                            if resp.status_code == 200 and resp.text.strip():
                                all_leaks.append(
                                    RawLeak(
                                        text=resp.text,
                                        source_name=name,
                                        source_url=raw_url,
                                    )
                                )
                        except httpx.HTTPError:
                            pass
                except Exception as exc:
                    logger.error("Error fetching from %s: %s", name, exc)
        return all_leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        pattern = re.compile(re.escape(address), re.IGNORECASE)
        return [
            leak for leak in await self.fetch_raw_leaks() if pattern.search(leak.text)
        ]

    async def _get_paste_ids(
        self, client: httpx.AsyncClient, archive_url: str, source_name: str
    ) -> list[str]:
        resp = await client.get(archive_url)
        resp.raise_for_status()
        if source_name == "pastebin":
            return self._parse_pastebin_ids(resp.text)
        elif source_name == "dpaste":
            return self._parse_dpaste_ids(resp.text)
        elif source_name == "rentry":
            return self._parse_rentry_ids(resp.text)
        return []

    @staticmethod
    def _parse_pastebin_ids(html: str) -> list[str]:
        ids = re.findall(r'href="/([a-zA-Z0-9]{8,10})"', html)
        excluded = {
            "archive",
            "signup",
            "login",
            "contact",
            "tools",
            "languages",
            "faq",
            "pro",
            "dmca",
            "trending",
        }
        return [pid for pid in dict.fromkeys(ids) if pid.lower() not in excluded]

    @staticmethod
    def _parse_dpaste_ids(html: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        ids = []
        for link in soup.find_all("a", href=True):
            match = re.search(r"/([a-zA-Z0-9]{5,8})(?:\.|$)", link["href"])
            if match:
                ids.append(match.group(1))
        return list(dict.fromkeys(ids))

    @staticmethod
    def _parse_rentry_ids(html: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        ids = []
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.startswith("/") and len(href) > 1:
                slug = href.strip("/").split("/")[0]
                if slug and slug not in ("api", "login", "new", "edit", "raw"):
                    ids.append(slug)
        return list(dict.fromkeys(ids))
