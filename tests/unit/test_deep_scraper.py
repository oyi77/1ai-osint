"""Tests for the production-grade DeepScraperEngine."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.modules.deep_scan.deep_scraper import (
    DeepScraperEngine,
    DeepScraperResult,
)


@pytest.fixture
def mock_httpx_client():
    """Return a mock AsyncClient that yields successful HTML responses."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False

    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.text = (
        "<html><head><title>Test Title</title>"
        '<meta name="description" content="A test page">'
        '<meta property="og:image" content="https://example.com/avatar.png">'
        "</head><body>"
        "<h1>Profile</h1>"
        "<p>Hello</p>"
        "<p>World</p>"
        "<p>This is a test bio.</p>"
        "</body></html>"
    )
    response.headers = {"content-type": "text/html; charset=utf-8"}
    client.get = AsyncMock(return_value=response)
    return client


@pytest.fixture
def engine(mock_httpx_client, tmp_path):
    """DeepScraperEngine with mocked HTTP client and isolated cache dir."""
    eng = DeepScraperEngine(
        max_retries=1,
        max_depth=0,
        cache_ttl=3600,
        cache_dir=str(tmp_path / "cache"),
    )
    eng._get_client = AsyncMock(return_value=mock_httpx_client)
    return eng


# ---------------------------------------------------------------------------
# scrape_profile — backward-compatible dict API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scrape_profile_success(engine, mock_httpx_client):
    """scrape_profile returns a dict with url, title, text_content, profile_picture_url."""
    result = await engine.scrape_profile("https://example.com")

    assert result["url"] == "https://example.com"
    assert result["title"] == "Test Title"
    assert "Hello" in result["text_content"]
    assert "World" in result["text_content"]
    assert result["profile_picture_url"] == "https://example.com/avatar.png"

    mock_httpx_client.get.assert_called_once()
    call_args, call_kwargs = mock_httpx_client.get.call_args
    assert call_args[0] == "https://example.com"
    assert "User-Agent" in call_kwargs["headers"]
    assert call_kwargs["headers"]["User-Agent"].startswith("Mozilla/5.0")


@pytest.mark.asyncio
async def test_scrape_profile_uses_cache(engine, mock_httpx_client):
    """Second call to the same URL uses the cached result."""
    # First call — populates cache
    result1 = await engine.scrape_profile("https://example.com")
    assert result1["title"] == "Test Title"

    # Reset mock to detect if get is called again
    mock_httpx_client.get.reset_mock()

    # Second call — should hit cache
    result2 = await engine.scrape_profile("https://example.com")
    assert result2["title"] == "Test Title"
    mock_httpx_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_scrape_profile_http_error(engine, mock_httpx_client):
    """scrape_profile handles HTTP errors gracefully."""
    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 404
    mock_httpx_client.get.side_effect = httpx.HTTPStatusError(
        "Not Found", request=MagicMock(), response=error_response
    )

    result = await engine.scrape_profile("https://example.com/notfound")
    assert result["url"] == "https://example.com/notfound"
    assert result["title"] == ""
    assert result["profile_picture_url"] == ""


@pytest.mark.asyncio
async def test_scrape_profile_timeout(engine, mock_httpx_client):
    """scrape_profile handles timeouts gracefully."""
    mock_httpx_client.get.side_effect = httpx.TimeoutException(
        "Connection timed out"
    )

    result = await engine.scrape_profile("https://example.com/slow")
    assert result["url"] == "https://example.com/slow"
    assert result["title"] == ""
    assert result["profile_picture_url"] == ""


# ---------------------------------------------------------------------------
# scrape — typed DeepScraperResult API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scrape_returns_typed_result(engine):
    """scrape returns a DeepScraperResult with proper fields."""
    result = await engine.scrape("https://example.com")
    assert isinstance(result, DeepScraperResult)
    assert result.url == "https://example.com"
    assert result.title == "Test Title"
    assert result.status == "ok"
    assert result.elapsed_ms > 0
    assert result.metadata["content_type"] == "html"


@pytest.mark.asyncio
async def test_scrape_cache_hit(engine, mock_httpx_client):
    """Second call returns cached result."""
    await engine.scrape("https://example.com")
    mock_httpx_client.get.reset_mock()
    await engine.scrape("https://example.com")
    # Should use cache, not HTTP
    mock_httpx_client.get.assert_not_called()


# ---------------------------------------------------------------------------
# Content type detection
# ---------------------------------------------------------------------------


def test_detect_content_type():
    """_detect_content_type correctly classifies responses."""
    engine = DeepScraperEngine()
    assert engine._detect_content_type("text/html; charset=utf-8") == "html"
    assert engine._detect_content_type("application/json") == "json"
    assert engine._detect_content_type("application/pdf") == "pdf"
    assert engine._detect_content_type("image/png") == "image"
    assert engine._detect_content_type("text/plain") == "text"


# ---------------------------------------------------------------------------
# UA pool
# ---------------------------------------------------------------------------


def test_user_agent_pool():
    """User-Agent pool contains realistic values and _random_ua picks one."""
    engine = DeepScraperEngine()
    ua = engine._random_ua()
    assert ua.startswith("Mozilla/5.0")
    assert "Chrome" in ua or "Firefox" in ua or "Safari" in ua or "Edg" in ua


# ---------------------------------------------------------------------------
# HTML extraction
# ---------------------------------------------------------------------------


def test_extract_html_content_title():
    """_extract_html_content extracts the <title> tag."""
    engine = DeepScraperEngine()
    html = "<html><head><title>My Page</title></head><body></body></html>"
    result = engine._extract_html_content(html)
    assert result["title"] == "My Page"


def test_extract_html_content_meta():
    """_extract_html_content extracts meta description and OG tags."""
    engine = DeepScraperEngine()
    html = """
    <html><head>
        <meta name="description" content="A test page">
        <meta property="og:title" content="OG Test">
    </head><body></body></html>
    """
    result = engine._extract_html_content(html)
    assert result["metadata"].get("description") == "A test page"
    assert result["metadata"].get("og:title") == "OG Test"


def test_extract_html_content_body():
    """_extract_html_content extracts text from <p> and <h1>-<h6> tags."""
    engine = DeepScraperEngine()
    html = """
    <html><body>
        <h1>Main Heading</h1>
        <p>First paragraph with content.</p>
        <p>Second paragraph.</p>
    </body></html>
    """
    result = engine._extract_html_content(html)
    assert "Main Heading" in result["text_content"]
    assert "First paragraph" in result["text_content"]
    assert "Second paragraph" in result["text_content"]


# ---------------------------------------------------------------------------
# Retry / backoff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_on_timeout(tmp_path):
    """Engine retries on timeout with configurable max_retries."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False
    client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    eng = DeepScraperEngine(max_retries=2, cache_dir=str(tmp_path / "cache2"))
    eng._get_client = AsyncMock(return_value=client)

    result = await eng.scrape("https://retry.example.com")
    assert result.status == "error"
    assert client.get.call_count == 2  # retried once


@pytest.mark.asyncio
async def test_no_retry_on_non_http_error(tmp_path):
    """Engine does NOT retry on non-HTTP errors (e.g. ValueError)."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False
    client.get = AsyncMock(side_effect=ValueError("something broke"))

    eng = DeepScraperEngine(max_retries=3, cache_dir=str(tmp_path / "cache3"))
    eng._get_client = AsyncMock(return_value=client)

    result = await eng.scrape("https://valueerr.example.com")
    assert result.status == "error"
    assert client.get.call_count == 1  # no retry on unexpected errors


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_context_manager(tmp_path):
    """DeepScraperEngine can be used as an async context manager."""
    async with DeepScraperEngine(
        max_retries=1, cache_ttl=0, cache_dir=str(tmp_path / "cache4")
    ) as eng:
        assert isinstance(eng, DeepScraperEngine)
