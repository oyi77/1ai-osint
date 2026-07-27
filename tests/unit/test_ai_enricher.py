import os
from unittest.mock import AsyncMock, patch

import pytest

from src.modules.free_intel.ai_enricher import AIExtractor, EnrichedDossierData


@pytest.mark.asyncio
async def test_ai_extractor_not_available():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "", "OMNIROUTE_API_KEY": ""}):
        extractor = AIExtractor()
        assert not extractor.is_available()
        result = await extractor.extract_from_snippets("John Doe", ["snippet 1"])
        assert isinstance(result, EnrichedDossierData)
        assert result.current_employer == ""


@pytest.mark.asyncio
async def test_ai_extractor_empty_snippets():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "dummy_key"}):
        extractor = AIExtractor()
        assert extractor.is_available()
        result = await extractor.extract_from_snippets("John Doe", [])
        assert result.current_employer == ""

        result_empty_str = await extractor.extract_from_snippets("John Doe", ["   ", ""])
        assert result_empty_str.current_employer == ""


@pytest.mark.asyncio
async def test_ai_extractor_success():
    with patch.dict(
        os.environ,
        {
            "OPENAI_API_KEY": "dummy_key",
            "OMNIROUTE_BASE_URL": "https://api.openai.com/v1",
        },
    ):
        extractor = AIExtractor()
        mock_json = '{"current_employer": "Google", "job_title": "Engineer", "location": "Jakarta", "work_history": [{"company": "TechCo", "title": "Dev", "source": "LinkedIn", "confidence": 0.9}], "education": [{"institution": "UI", "degree": "CS", "source": "PDDIKTI"}]}'
        with patch.object(extractor._client, "async_chat", new=AsyncMock(return_value=mock_json)):
            result = await extractor.extract_from_snippets("John Doe", ["John Doe works at Google"])
            assert result.current_employer == "Google"
            assert result.job_title == "Engineer"
            assert result.location == "Jakarta"
            assert len(result.work_history) == 1
            assert result.work_history[0].company == "TechCo"
            assert len(result.education) == 1
            assert result.education[0].institution == "UI"


@pytest.mark.asyncio
async def test_ai_extractor_exception():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "dummy_key"}):
        extractor = AIExtractor()
        with patch.object(
            extractor._client,
            "async_chat",
            new=AsyncMock(side_effect=Exception("API limit")),
        ):
            result = await extractor.extract_from_snippets("John Doe", ["John Doe at Google"])
            assert result.current_employer == ""
