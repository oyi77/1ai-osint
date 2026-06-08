"""AI Snippet Enricher — extracts structured Work/Education data from unstructured search snippets."""

import json
import logging
import os

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class WorkHistoryItem(BaseModel):
    company: str = ""
    title: str = ""
    source: str = ""
    confidence: float = 0.0


class EducationItem(BaseModel):
    institution: str = ""
    degree: str = ""
    source: str = ""


class EnrichedDossierData(BaseModel):
    current_employer: str = ""
    job_title: str = ""
    location: str = ""
    work_history: list[WorkHistoryItem] = Field(default_factory=list)
    education: list[EducationItem] = Field(default_factory=list)


class AIExtractor:
    """Uses LLMs to structure messy dork snippets into Dossier data."""

    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get(
            "OMNIROUTE_API_KEY", ""
        )
        self.base_url = os.environ.get(
            "OMNIROUTE_BASE_URL", "https://api.openai.com/v1"
        )
        self.model = os.environ.get("OMNIROUTE_MODEL", "gpt-4o-mini")

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def extract_from_snippets(
        self, target_name: str, snippets: list[str]
    ) -> EnrichedDossierData:
        """Extract structured employment and education from search snippets."""
        if not self.is_available() or not snippets:
            return EnrichedDossierData()

        combined = "\n".join(snippets)
        if not combined.strip():
            return EnrichedDossierData()

        system = (
            "You are an expert OSINT analyst. Extract structured intelligence from raw search snippets."
            "Return JSON only."
        )
        user_msg = f"""Analyze these search snippets for target "{target_name}".
Extract their current employer, job title, location, past work history, and education.

Snippets:
{combined[:3000]}

Format JSON exactly as:
{{
  "current_employer": "string",
  "job_title": "string",
  "location": "string",
  "work_history": [
    {{"company": "string", "title": "string", "source": "LinkedIn/etc", "confidence": 0.8}}
  ],
  "education": [
    {{"institution": "string", "degree": "string", "source": "string"}}
  ]
}}"""

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user_msg},
                        ],
                        "response_format": {"type": "json_object"},
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()["choices"][0]["message"]["content"]
                    parsed = json.loads(data)

                    work = [
                        WorkHistoryItem(**w)
                        for w in parsed.get("work_history", [])
                        if isinstance(w, dict)
                    ]
                    edu = [
                        EducationItem(**e)
                        for e in parsed.get("education", [])
                        if isinstance(e, dict)
                    ]

                    return EnrichedDossierData(
                        current_employer=parsed.get("current_employer", ""),
                        job_title=parsed.get("job_title", ""),
                        location=parsed.get("location", ""),
                        work_history=work,
                        education=edu,
                    )
        except Exception as e:
            logger.warning("AI extraction failed: %s", e)

        return EnrichedDossierData()
