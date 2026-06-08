"""OpenAI SDK client configured for OmniRoute gateway with retry and fallback."""

import logging
import time
from typing import Optional

from openai import APIConnectionError, APITimeoutError, OpenAI, RateLimitError

from src.core.config import settings

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gpt-4o-mini"
_MAX_RETRIES = 3
_RETRY_DELAY = 1.0  # seconds, doubles each retry


class OmniRouteClient:
    """OpenAI-compatible client pointing at OmniRoute with retry and provider fallback."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: str = _DEFAULT_MODEL,
        max_retries: int = _MAX_RETRIES,
    ):
        self.model = model
        self.max_retries = max_retries

        # Primary: OmniRoute
        self._primary_client = OpenAI(
            base_url=base_url or settings.effective_openai_base_url,
            api_key=api_key or settings.effective_openai_api_key or "not-set",
        )

        # Fallback: direct OpenAI (only if OmniRoute differs and direct key exists)
        self._fallback_client: Optional[OpenAI] = None
        if (
            settings.openai_api_key
            and settings.openai_base_url != settings.omniroute_base_url
        ):
            self._fallback_client = OpenAI(
                base_url=settings.openai_base_url,
                api_key=settings.openai_api_key,
            )

    def _call_with_retry(
        self, client: OpenAI, messages: list[dict[str, str]], **kwargs
    ) -> str:
        """Send a chat completion request with exponential backoff retry."""
        delay = _RETRY_DELAY
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = client.chat.completions.create(
                    model=kwargs.pop("model", self.model),
                    messages=messages,
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

    def chat(
        self,
        messages: list[dict[str, str]],
        model: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        Send a chat completion request. Falls back to direct OpenAI if OmniRoute fails.

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
                    return self._call_with_retry(
                        self._fallback_client, messages, **call_kwargs
                    )
                except Exception as fallback_err:
                    logger.error("OpenAI fallback also failed: %s", fallback_err)
                    raise fallback_err
            raise primary_err

    def extract_entities(self, text: str) -> str:
        """Use AI to extract entities from OSINT text."""
        from src.ai.prompts.entity_extraction import ENTITY_EXTRACTION_PROMPT

        messages = [
            {"role": "system", "content": ENTITY_EXTRACTION_PROMPT},
            {"role": "user", "content": text},
        ]
        return self.chat(messages)

    def filter_false_positives(self, findings_json: str) -> str:
        """Use AI to filter likely false positives from findings."""
        from src.ai.prompts.false_positive_filter import FALSE_POSITIVE_PROMPT

        messages = [
            {"role": "system", "content": FALSE_POSITIVE_PROMPT},
            {"role": "user", "content": findings_json},
        ]
        return self.chat(messages)
