"""Tests for VisionCorrelator - profile correlation using OmniRoute."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
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
    # When async_chat_multimodal raises, fallback kicks in
    mock_client = MagicMock()
    mock_client.async_chat_multimodal = AsyncMock(
        side_effect=Exception("No API key")
    )
    correlator._client = mock_client

    score = await correlator.correlate_profiles(sample_profiles[0], sample_profiles[1])
    assert score == 0.6


@pytest.mark.asyncio
async def test_fallback_different(different_profiles):
    correlator = VisionCorrelator()
    mock_client = MagicMock()
    mock_client.async_chat_multimodal = AsyncMock(
        side_effect=Exception("No API key")
    )
    correlator._client = mock_client

    score = await correlator.correlate_profiles(
        different_profiles[0], different_profiles[1]
    )
    assert score == 0.2


@pytest.mark.asyncio
async def test_fallback_name_match():
    correlator = VisionCorrelator()

    profile_a = {"text_content": "Full Name: John Doe"}
    profile_b = {
        "text_content": "This profile page belongs to John Doe, who works as a developer."
    }

    # Simulate LLM failure so we test deterministic fallback
    mock_client = MagicMock()
    mock_client.async_chat_multimodal = AsyncMock(
        side_effect=Exception("No API key")
    )
    correlator._client = mock_client

    score = await correlator.correlate_profiles(profile_a, profile_b)
    assert score == 0.7


@pytest.mark.asyncio
async def test_llm_success(sample_profiles):
    """LLM returns confidence 0.85."""
    correlator = VisionCorrelator()

    mock_client = MagicMock()
    mock_client.async_chat_multimodal = AsyncMock(
        return_value='{"confidence": 0.85, "reasoning": "Look similar"}'
    )
    correlator._client = mock_client

    score = await correlator.correlate_profiles(sample_profiles[0], sample_profiles[1])
    assert score == 0.85


@pytest.mark.asyncio
async def test_llm_failure_fallback(sample_profiles):
    """LLM error falls back to deterministic."""
    correlator = VisionCorrelator()

    mock_client = MagicMock()
    mock_client.async_chat_multimodal = AsyncMock(
        side_effect=Exception("API error")
    )
    correlator._client = mock_client

    score = await correlator.correlate_profiles(sample_profiles[0], sample_profiles[1])
    assert score == 0.6
