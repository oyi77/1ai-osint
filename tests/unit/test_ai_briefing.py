from unittest.mock import MagicMock, patch

from src.modules.deep_scan.ai_briefing import enhance_briefing_with_ai
from src.modules.deep_scan.models_report import (
    IntelReport,
    OperationalBriefing,
    SubjectProfile,
)


def _minimal_report():
    return IntelReport(
        target="t",
        briefing=OperationalBriefing(
            bluf="x",
            subject=SubjectProfile(primary_name="t"),
        ),
    )


def test_enhance_skips_without_api_key():
    report = _minimal_report()
    scan = MagicMock(scan_results=[])
    out = enhance_briefing_with_ai(report, scan)
    assert out is report
    assert not report.briefing.key_judgments


def test_enhance_adds_judgment_when_ai_returns():
    report = _minimal_report()
    scan = MagicMock(scan_results=[{"module": "x"}])

    async def fake_run(**_kwargs):
        return {"summary": "Subject has public GitHub presence."}

    with patch("src.core.config.Settings") as mock_settings:
        mock_settings.return_value.effective_openai_api_key = "sk-test"
        with patch("src.ai.orchestrator.AnalysisOrchestrator") as orch:
            orch.return_value.run = fake_run
            out = enhance_briefing_with_ai(report, scan)
    assert out.briefing.key_judgments
    assert "[AI]" in out.briefing.key_judgments[0]
