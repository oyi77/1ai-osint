"""Tests for OmniRouteClient."""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from openai import APITimeoutError, APIConnectionError, RateLimitError


@pytest.fixture
def mock_openai_cls():
    """Mock the OpenAI class so all client instances are MagicMock."""
    with patch("src.ai.omniroute_client.OpenAI") as mock_cls:
        primary = MagicMock()
        fallback = MagicMock()
        mock_cls.side_effect = [primary, fallback]
        yield mock_cls, primary, fallback


@pytest.fixture
def mock_settings():
    with patch("src.ai.omniroute_client.settings") as mock:
        mock.effective_openai_base_url = "http://test-omniroute:3000/v1"
        mock.effective_openai_api_key = "test-key"
        mock.openai_api_key = "direct-key"
        mock.openai_base_url = "https://api.openai.com/v1"
        mock.omniroute_base_url = "http://test-omniroute:3000/v1"
        yield mock


@pytest.fixture
def client(mock_openai_cls, mock_settings):
    from src.ai.omniroute_client import OmniRouteClient
    return OmniRouteClient(model="test-model", max_retries=2)


class TestClientInit:
    def test_init_default_model(self, mock_openai_cls, mock_settings):
        from src.ai.omniroute_client import OmniRouteClient
        c = OmniRouteClient()
        assert c.model == "gpt-4o-mini"
        assert c.max_retries == 3

    def test_init_custom_model(self, mock_openai_cls, mock_settings):
        from src.ai.omniroute_client import OmniRouteClient
        c = OmniRouteClient(model="gpt-4", max_retries=5)
        assert c.model == "gpt-4"
        assert c.max_retries == 5

    def test_init_with_explicit_params(self, mock_openai_cls, mock_settings):
        from src.ai.omniroute_client import OmniRouteClient
        c = OmniRouteClient(base_url="http://custom:9999/v1", api_key="custom-key")
        assert c._primary_client is not None

    def test_fallback_client_created_when_urls_differ(self, mock_openai_cls, mock_settings):
        mock_settings.openai_base_url = "https://api.openai.com/v1"
        mock_settings.omniroute_base_url = "http://omniroute:3000/v1"
        mock_settings.openai_api_key = "direct-key"
        from src.ai.omniroute_client import OmniRouteClient
        c = OmniRouteClient()
        assert c._fallback_client is not None

    def test_no_fallback_when_same_url(self, mock_openai_cls, mock_settings):
        mock_settings.openai_base_url = "http://same:3000/v1"
        mock_settings.omniroute_base_url = "http://same:3000/v1"
        mock_settings.openai_api_key = ""
        from src.ai.omniroute_client import OmniRouteClient
        c = OmniRouteClient()
        assert c._fallback_client is None


class TestCallWithRetry:
    def test_success_first_try(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Hello!"))]
        primary.chat.completions.create.return_value = mock_response

        result = client._call_with_retry(primary, [{"role": "user", "content": "hi"}])
        assert result == "Hello!"

    def test_retry_on_timeout(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="OK"))]

        primary.chat.completions.create.side_effect = [
            APITimeoutError(request=MagicMock()),
            mock_response,
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            result = client._call_with_retry(primary, [{"role": "user", "content": "hi"}])
        assert result == "OK"

    def test_retry_on_connection_error(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="OK"))]

        primary.chat.completions.create.side_effect = [
            APIConnectionError(request=MagicMock()),
            mock_response,
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            result = client._call_with_retry(primary, [{"role": "user", "content": "hi"}])
        assert result == "OK"

    def test_retry_on_rate_limit(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="OK"))]

        primary.chat.completions.create.side_effect = [
            RateLimitError(message="rate limited", response=MagicMock(status_code=429, headers={}), body=None),
            mock_response,
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            result = client._call_with_retry(primary, [{"role": "user", "content": "hi"}])
        assert result == "OK"

    def test_raises_after_max_retries(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        primary.chat.completions.create.side_effect = [
            APITimeoutError(request=MagicMock()),
            APITimeoutError(request=MagicMock()),
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            with pytest.raises(APITimeoutError):
                client._call_with_retry(primary, [{"role": "user", "content": "hi"}])

    def test_non_retryable_error_propagates(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        primary.chat.completions.create.side_effect = ValueError("bad request")

        with pytest.raises(ValueError, match="bad request"):
            client._call_with_retry(primary, [{"role": "user", "content": "hi"}])


class TestChat:
    def test_chat_success(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Response"))]
        primary.chat.completions.create.return_value = mock_response

        result = client.chat([{"role": "user", "content": "hello"}])
        assert result == "Response"

    def test_chat_fallback_on_primary_failure(self, client, mock_openai_cls):
        _, primary, fallback = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Fallback response"))]
        fallback.chat.completions.create.return_value = mock_response

        primary.chat.completions.create.side_effect = [
            APITimeoutError(request=MagicMock()),
            APITimeoutError(request=MagicMock()),
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            result = client.chat([{"role": "user", "content": "hello"}])
        assert result == "Fallback response"

    def test_chat_raises_when_no_fallback(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        client._fallback_client = None
        primary.chat.completions.create.side_effect = [
            APITimeoutError(request=MagicMock()),
            APITimeoutError(request=MagicMock()),
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            with pytest.raises(APITimeoutError):
                client.chat([{"role": "user", "content": "hello"}])

    def test_chat_raises_when_fallback_also_fails(self, client, mock_openai_cls):
        _, primary, fallback = mock_openai_cls
        primary.chat.completions.create.side_effect = [
            APITimeoutError(request=MagicMock()),
            APITimeoutError(request=MagicMock()),
        ]
        fallback.chat.completions.create.side_effect = [
            APITimeoutError(request=MagicMock()),
            APITimeoutError(request=MagicMock()),
        ]

        with patch("src.ai.omniroute_client.time.sleep"):
            with pytest.raises(APITimeoutError):
                client.chat([{"role": "user", "content": "hello"}])

    def test_chat_with_model_override(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="OK"))]
        primary.chat.completions.create.return_value = mock_response

        client.chat([{"role": "user", "content": "hi"}], model="gpt-4")
        call_kwargs = primary.chat.completions.create.call_args
        assert call_kwargs.kwargs.get("model") == "gpt-4"


class TestExtractEntities:
    def test_extract_entities(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content='{"entities": []}'))]
        primary.chat.completions.create.return_value = mock_response

        result = client.extract_entities("John Doe, john@example.com")
        assert isinstance(result, str)


class TestFilterFalsePositives:
    def test_filter_false_positives(self, client, mock_openai_cls):
        _, primary, _ = mock_openai_cls
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content='{"filtered": []}'))]
        primary.chat.completions.create.return_value = mock_response

        result = client.filter_false_positives('[{"id": "f1"}]')
        assert isinstance(result, str)
