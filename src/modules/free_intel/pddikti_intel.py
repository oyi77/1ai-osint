"""PDDIKTI Intelligence — searches Indonesian student database via DuckDuckGo."""

import logging
import re

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class StudentRecord(BaseModel):
    name: str = ""
    university: str = ""
    major: str = ""
    student_id: str = ""


class PDDIKTIIntel:
    """Uses DuckDuckGo to search the PDDIKTI database."""

    ENDPOINTS = ["https://html.duckduckgo.com/html/"]

    async def search(self, name: str) -> list[StudentRecord]:
        query = f'"{name}" site:pddikti.kemdikbud.go.id'
        results = []

        async with httpx.AsyncClient(
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        ) as client:
            try:
                resp = await client.post(self.ENDPOINTS[0], data={"q": query})
                if resp.status_code == 200:
                    text = resp.text
                    snippets = re.findall(
                        r'class="result__snippet"[^>]*>(.*?)</a', text, re.DOTALL
                    )
                    for snippet in snippets:
                        clean = " ".join(
                            re.sub(r"<[^>]+>", " ", snippet).strip().split()
                        )
                        # Snippets often look like: "Nama: Fikri Izzuddin, PT: Universitas Indonesia, Prodi: Ilmu Komputer, NIM: 12345"
                        # Or they just mention the university and name.
                        rec = StudentRecord(name=name)

                        # Heuristics for university
                        if "PT :" in clean or "Perguruan Tinggi :" in clean:
                            match = re.search(
                                r"(?:PT|Perguruan Tinggi)\s*:\s*([^,-]+)", clean
                            )
                            if match:
                                rec.university = match.group(1).strip()
                        elif (
                            "Universitas" in clean
                            or "Institut" in clean
                            or "Politeknik" in clean
                        ):
                            match = re.search(
                                r"(Universitas [A-Za-z ]+|Institut [A-Za-z ]+|Politeknik [A-Za-z ]+)",
                                clean,
                            )
                            if match:
                                rec.university = match.group(1).strip()

                        # Heuristics for major
                        if "Prodi :" in clean or "Program Studi :" in clean:
                            match = re.search(
                                r"(?:Prodi|Program Studi)\s*:\s*([^,-]+)", clean
                            )
                            if match:
                                rec.major = match.group(1).strip()

                        if rec.university or rec.major:
                            results.append(rec)

            except Exception as e:
                logger.debug("PDDIKTI search failed: %s", e)

        # Deduplicate
        unique = []
        seen = set()
        for r in results:
            k = f"{r.university}-{r.major}"
            if k not in seen:
                seen.add(k)
                unique.append(r)

        return unique
