"""OpenAI SDK client configured for OmniRoute gateway with retry and fallback.

Supports both sync and async calling patterns, plus multimodal content.
"""

import logging
import time
from typing import Any

from openai import APIConnectionError, APITimeoutError, AsyncOpenAI, OpenAI, RateLimitError

from src.core.config import settings

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gpt-4o-mini"
_MAX_RETRIES = 3
_RETRY_DELAY = 1.0  # seconds, doubles each retry


class OmniRouteClient:
    """OpenAI-compatible client pointing at OmniRoute with retry and provider fallback.

    Supports both synchronous (chat) and asynchronous (async_chat) calls,
    plus multimodal messages with image URLs.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        max_retries: int = _MAX_RETRIES,
    ):
        self.model = model
        self.max_retries = max_retries

        base = base_url or settings.effective_openai_base_url
        key = api_key or settings.effective_openai_api_key or "not-set"

        # Sync client
        self._primary_client = OpenAI(base_url=base, api_key=key)

        # Async client
        self._async_primary = AsyncOpenAI(base_url=base, api_key=key)

        # Fallback: direct OpenAI (only if OmniRoute differs and direct key exists)
        self._fallback_client: OpenAI | None = None
        self._async_fallback: AsyncOpenAI | None = None
        if settings.openai_api_key and settings.openai_base_url != settings.omniroute_base_url:
            self._fallback_client = OpenAI(
                base_url=settings.openai_base_url,
                api_key=settings.openai_api_key,
            )
            self._async_fallback = AsyncOpenAI(
                base_url=settings.openai_base_url,
                api_key=settings.openai_api_key,
            )

    # ------------------------------------------------------------------ #
    #  Sync helpers
    # ------------------------------------------------------------------ #

    def _call_with_retry(
        self,
        client: OpenAI,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> str:
        """Send a chat completion request with exponential backoff retry."""
        delay = _RETRY_DELAY
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = client.chat.completions.create(
                    model=kwargs.pop("model", self.model),
                    messages=messages,  # type: ignore[arg-type]
                    **kwargs,
                )
                return response.choices[0].message.content or ""
            except (APITimeoutError, APIConnectionError, RateLimitError) as e:
                last_error = e
                logger.warning(
                    "OmniRoute attempt %d/%d failed: %s. Retrying in %.1fs",
                    attempt,
                    self.max_retries,
                    e,
                    delay,
                )
                time.sleep(delay)
                delay *= 2

        raise last_error  # type: ignore[misc]

    # ------------------------------------------------------------------ #
    #  Async helpers
    # ------------------------------------------------------------------ #

    async def _async_call_with_retry(
        self,
        client: AsyncOpenAI,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> str:
        """Send an async chat completion request with exponential backoff retry."""
        delay = _RETRY_DELAY
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await client.chat.completions.create(
                    model=kwargs.pop("model", self.model),
                    messages=messages,  # type: ignore[arg-type]
                    **kwargs,
                )
                return response.choices[0].message.content or ""
            except (APITimeoutError, APIConnectionError, RateLimitError) as e:
                last_error = e
                logger.warning(
                    "OmniRoute async attempt %d/%d failed: %s. Retrying in %.1fs",
                    attempt,
                    self.max_retries,
                    e,
                    delay,
                )
                await _async_sleep(delay)
                delay *= 2

        raise last_error  # type: ignore[misc]

    # ------------------------------------------------------------------ #
    #  Public sync API
    # ------------------------------------------------------------------ #

    def chat(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a chat completion request (sync). Falls back to direct OpenAI if OmniRoute fails.

        Args:
            messages: Chat messages in OpenAI format.
            model: Model override (defaults to self.model).
            **kwargs: Additional parameters passed to completions.create().

        Returns:
            Assistant response text.

        """
        call_kwargs = dict(kwargs)
        if model:
            call_kwargs["model"] = model

        try:
            return self._call_with_retry(self._primary_client, messages, **call_kwargs)
        except Exception as primary_err:
            logger.error("OmniRoute failed after retries: %s", primary_err)
            if self._fallback_client:
                logger.info("Falling back to direct OpenAI endpoint")
                try:
                    return self._call_with_retry(self._fallback_client, messages, **call_kwargs)
                except Exception as fallback_err:
                    logger.error("OpenAI fallback also failed: %s", fallback_err)
                    raise fallback_err
            raise primary_err

    def extract_entities(self, text: str) -> str:
        """Use AI to extract entities from OSINT text (sync)."""
        from src.ai.prompts.entity_extraction import ENTITY_EXTRACTION_PROMPT

        messages = [
            {"role": "system", "content": ENTITY_EXTRACTION_PROMPT},
            {"role": "user", "content": text},
        ]
        return self.chat(messages)

    def filter_false_positives(self, findings_json: str) -> str:
        """Use AI to filter likely false positives from findings (sync)."""
        from src.ai.prompts.false_positive_filter import FALSE_POSITIVE_PROMPT

        messages = [
            {"role": "system", "content": FALSE_POSITIVE_PROMPT},
            {"role": "user", "content": findings_json},
        ]
        return self.chat(messages)

    # ------------------------------------------------------------------ #
    #  Public async API
    # ------------------------------------------------------------------ #

    async def async_chat(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a chat completion request (async). Falls back to direct OpenAI if OmniRoute fails.

        Args:
            messages: Chat messages in OpenAI format.
            model: Model override (defaults to self.model).
            **kwargs: Additional parameters passed to completions.create().

        Returns:
            Assistant response text.

        """
        call_kwargs = dict(kwargs)
        if model:
            call_kwargs["model"] = model

        try:
            return await self._async_call_with_retry(self._async_primary, messages, **call_kwargs)
        except Exception as primary_err:
            logger.error("OmniRoute async failed after retries: %s", primary_err)
            if self._async_fallback:
                logger.info("Falling back to direct OpenAI async endpoint")
                try:
                    return await self._async_call_with_retry(self._async_fallback, messages, **call_kwargs)
                except Exception as fallback_err:
                    logger.error("OpenAI async fallback also failed: %s", fallback_err)
                    raise fallback_err
            raise primary_err

    async def async_extract_entities(self, text: str) -> str:
        """Use AI to extract entities from OSINT text (async)."""
        from src.ai.prompts.entity_extraction import ENTITY_EXTRACTION_PROMPT

        messages = [
            {"role": "system", "content": ENTITY_EXTRACTION_PROMPT},
            {"role": "user", "content": text},
        ]
        return await self.async_chat(messages)

    async def async_filter_false_positives(self, findings_json: str) -> str:
        """Use AI to filter likely false positives from findings (async)."""
        from src.ai.prompts.false_positive_filter import FALSE_POSITIVE_PROMPT

        messages = [
            {"role": "system", "content": FALSE_POSITIVE_PROMPT},
            {"role": "user", "content": findings_json},
        ]
        return await self.async_chat(messages)

    def chat_multimodal(
        self,
        text_content: str,
        system_prompt: str = "",
        image_urls: list[str] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a multimodal chat request (text + optional images). Sync.

        Args:
            text_content: The user text message.
            system_prompt: Optional system prompt.
            image_urls: Optional list of image URLs to include.
            model: Model override.
            **kwargs: Additional chat parameters.

        Returns:
            Assistant response text.

        """
        content: list[dict[str, Any]] = [{"type": "text", "text": text_content}]
        if image_urls:
            for url in image_urls:
                content.append({"type": "image_url", "image_url": {"url": url}})

        messages: list[dict[str, Any]] = [{"role": "user", "content": content}]
        if system_prompt:
            messages.insert(0, {"role": "system", "content": system_prompt})

        return self.chat(messages, model=model, **kwargs)

    async def async_chat_multimodal(
        self,
        text_content: str,
        system_prompt: str = "",
        image_urls: list[str] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a multimodal chat request (text + optional images). Async.

        Args:
            text_content: The user text message.
            system_prompt: Optional system prompt.
            image_urls: Optional list of image URLs to include.
            model: Model override.
            **kwargs: Additional chat parameters.

        Returns:
            Assistant response text.

        """
        content: list[dict[str, Any]] = [{"type": "text", "text": text_content}]
        if image_urls:
            for url in image_urls:
                content.append({"type": "image_url", "image_url": {"url": url}})

        messages: list[dict[str, Any]] = [{"role": "user", "content": content}]
        if system_prompt:
            messages.insert(0, {"role": "system", "content": system_prompt})

        return await self.async_chat(messages, model=model, **kwargs)


async def _async_sleep(delay: float) -> None:
    """Async sleep helper (avoids asyncio import at module level)."""
    import asyncio

    await asyncio.sleep(delay)
