import pytest
from unittest.mock import patch, MagicMock
from src.modules.deep_scan.vision_correlator import VisionCorrelator


@pytest.fixture
def sample_profiles():
    return (
        {
            "text_content": "Software Engineer at Google. Love hiking and AI.",
            "profile_picture_url": "http://example.com/a.jpg",
        },
        {
            "text_content": "Software Engineer at Google. Enjoy hiking and AI development.",
            "profile_picture_url": "http://example.com/b.jpg",
        },
    )


@pytest.fixture
def different_profiles():
    return (
        {
            "text_content": "Software Engineer at Google. Love hiking and AI.",
            "profile_picture_url": "http://example.com/a.jpg",
        },
        {
            "text_content": "Chef at a local restaurant. Baking is my passion.",
            "profile_picture_url": "http://example.com/c.jpg",
        },
    )


@pytest.mark.asyncio
async def test_fallback_similar(sample_profiles):
    correlator = VisionCorrelator()
    correlator.openai_api_key = None
    correlator.omniroute_api_key = None

    score = await correlator.correlate_profiles(sample_profiles[0], sample_profiles[1])
    assert score == 0.6


@pytest.mark.asyncio
async def test_fallback_different(different_profiles):
    correlator = VisionCorrelator()
    correlator.openai_api_key = None
    correlator.omniroute_api_key = None

    score = await correlator.correlate_profiles(
        different_profiles[0], different_profiles[1]
    )
    assert score == 0.2


@pytest.mark.asyncio
async def test_fallback_name_match():
    correlator = VisionCorrelator()
    correlator.openai_api_key = None
    correlator.omniroute_api_key = None

    profile_a = {"text_content": "Full Name: John Doe"}
    profile_b = {
        "text_content": "This profile page belongs to John Doe, who works as a developer."
    }

    score = await correlator.correlate_profiles(profile_a, profile_b)
    assert score == 0.7


@pytest.mark.asyncio
@patch("src.modules.deep_scan.vision_correlator.httpx.AsyncClient.post")
async def test_llm_success(mock_post, sample_profiles):
    correlator = VisionCorrelator()
    correlator.openai_api_key = "fake_key"

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": '{"confidence": 0.85, "reasoning": "Look similar"}'
                }
            }
        ]
    }
    mock_post.return_value = mock_response

    score = await correlator.correlate_profiles(sample_profiles[0], sample_profiles[1])
    assert score == 0.85


@pytest.mark.asyncio
@patch("src.modules.deep_scan.vision_correlator.httpx.AsyncClient.post")
async def test_llm_failure_fallback(mock_post, sample_profiles):
    correlator = VisionCorrelator()
    correlator.openai_api_key = "fake_key"

    mock_post.side_effect = Exception("API error")

    score = await correlator.correlate_profiles(sample_profiles[0], sample_profiles[1])
    assert score == 0.6
