"""The LLM provider abstraction (ADR-010 / ADR-021).

Agents and the report builder depend only on the `LLMProvider` protocol —
never on a vendor SDK. Concrete providers live in `offensivex.llm.providers`
and are built from configuration by `get_llm_provider()`; tests substitute a
scripted object satisfying the same protocol.

Failure policy: a provider that cannot produce a *valid, schema-conforming*
answer raises an `LLMError`. There is no silent fallback to a canned or
invented answer anywhere — callers surface the failure (an agent run is
marked FAILED; a report records `ai_summary.status = "failed"`).
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from offensivex.core.config import LLMProviderName, Settings
from offensivex.core.errors import OffensiveXError


class LLMError(OffensiveXError):
    """Base for everything that can go wrong talking to a model."""

    status_code = 502
    title = "LLM error"


class LLMConfigurationError(LLMError):
    status_code = 503
    title = "LLM not configured"


class LLMProviderError(LLMError):
    """The provider was unreachable, rate-limited, timed out, or rejected the
    request — after the bounded retries were used up."""

    title = "LLM provider error"


class LLMOutputError(LLMError):
    """The model answered, but not with output that validates against the
    requested schema — after the bounded retries were used up."""

    title = "LLM output invalid"


class LLMPromptTooLargeError(LLMError):
    status_code = 422
    title = "LLM prompt too large"


@runtime_checkable
class LLMProvider(Protocol):
    """What every concrete provider must implement.

    One method: a prompt in, an instance of `schema` (a pydantic model class)
    out. The returned object has already been validated against `schema`.
    """

    name: LLMProviderName

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        """Return an instance of `schema` built from the model's output."""
        ...


def get_llm_provider(settings: Settings) -> LLMProvider:
    """Build the configured provider, or raise `LLMConfigurationError`.

    Required environment variables (all `OFFENSIVEX_`-prefixed, see
    `.env.example` and docs/architecture/llm-integration.md):
    `LLM_ENABLED=true`, `LLM_PROVIDER`, `LLM_MODEL`, and — except for
    `LLM_PROVIDER=local` — `LLM_API_KEY`. `LLM_BASE_URL` is optional.
    """
    if not settings.llm_enabled:
        raise LLMConfigurationError(
            "The LLM is disabled. Set OFFENSIVEX_LLM_ENABLED=true and configure "
            "OFFENSIVEX_LLM_PROVIDER, OFFENSIVEX_LLM_MODEL and OFFENSIVEX_LLM_API_KEY."
        )

    # Imported here so importing `offensivex.llm.base` never pulls in a vendor SDK.
    from offensivex.llm.providers.anthropic import AnthropicProvider
    from offensivex.llm.providers.openai_compat import OpenAICompatProvider

    api_key = settings.llm_api_key.get_secret_value() if settings.llm_api_key else None
    model = settings.llm_model or ""
    timeout = settings.llm_timeout_seconds
    retries = settings.llm_max_retries
    max_out = settings.llm_max_output_tokens
    max_prompt = settings.llm_max_prompt_chars
    if settings.llm_provider == "anthropic":
        return AnthropicProvider(
            api_key=api_key or "",
            base_url=settings.llm_base_url,
            model=model,
            timeout_seconds=timeout,
            max_retries=retries,
            max_output_tokens=max_out,
            max_prompt_chars=max_prompt,
        )
    if settings.llm_provider in ("openai", "local"):
        return OpenAICompatProvider(
            name=settings.llm_provider,
            api_key=api_key,
            base_url=settings.llm_base_url,
            model=model,
            timeout_seconds=timeout,
            max_retries=retries,
            max_output_tokens=max_out,
            max_prompt_chars=max_prompt,
        )
    if settings.llm_provider == "gemini":
        raise LLMConfigurationError(
            "There is no native Gemini provider. Use OFFENSIVEX_LLM_PROVIDER=openai with "
            "OFFENSIVEX_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/ "
            "(Google's OpenAI-compatible endpoint)."
        )
    raise LLMConfigurationError(f"Unsupported OFFENSIVEX_LLM_PROVIDER: {settings.llm_provider!r}.")


_UNTRUSTED_CLOSE = "</untrusted_data>"


def untrusted_block(payload: Any) -> str:
    """Fence data that came from the assessed target or a tool.

    The closing tag is neutralised inside the payload, so content from a
    scanned website cannot "close" the block and pose as our instructions.
    """
    text = json.dumps(payload, default=str).replace(_UNTRUSTED_CLOSE, "<\\/untrusted_data>")
    return f"<untrusted_data>\n{text}\n{_UNTRUSTED_CLOSE}"


def try_get_llm_provider(settings: Settings) -> LLMProvider | None:
    """The provider if the LLM is enabled, else None (no LLM features)."""
    return get_llm_provider(settings) if settings.llm_enabled else None
