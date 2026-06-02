"""Optional AI enhancement for briefing (evidence-cited only)."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def enhance_briefing_with_ai(report: Any, scan_result: Any) -> Any:
    """Augment key_judgments using AI when Omniroute/OpenAI is configured."""
    try:
        from src.ai.orchestrator import AnalysisOrchestrator
        from src.config import Settings

        settings = Settings()
        if not settings.effective_openai_api_key:
            return report

        import asyncio

        orchestrator = AnalysisOrchestrator()
        ai_report = asyncio.run(orchestrator.run(scan_results=scan_result.scan_results))
        if not ai_report:
            return report

        summary = ai_report.get("summary") or ai_report.get("executive_summary")
        if summary and isinstance(summary, str):
            report.briefing.key_judgments.insert(
                0,
                f"[AI] {summary[:500]} (verify against evidence register)",
            )
    except Exception as exc:
        logger.debug("AI briefing enhancement skipped: %s", exc)
    return report
