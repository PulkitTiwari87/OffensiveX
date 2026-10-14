"""OpenAI-compatible chat-completions provider (httpx).

Works with OpenAI itself and any server speaking the same wire format
(Google's Gemini compatibility endpoint, vLLM, Ollama, LM Studio, ...), so
one implementation covers `OFFENSIVEX_LLM_PROVIDER=openai` and `=local`.
Structured output uses `response_format: json_schema`; the reply's JSON is
then validated by the shared layer.

Environment: `OFFENSIVEX_LLM_PROVIDER=openai|local`, `OFFENSIVEX_LLM_MODEL`,
`OFFENSIVEX_LLM_API_KEY` (optional for `local`), `OFFENSIVEX_LLM_BASE_URL`
(required for `local`; defaults to https://api.openai.com/v1 for `openai`).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from offensivex.core.config import LLMProviderName
from offensivex.llm.structured import (
    SYSTEM_PROMPT,
    MalformedOutput,
    PermanentLLMError,
    RawCompletion,
    StructuredProvider,
    TransientLLMError,
)

_DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
_RETRYABLE_STATUS = frozenset({408, 409, 429})


class OpenAICompatProvider(StructuredProvider):
    def __init__(
        self,
        *,
        name: LLMProviderName,
        api_key: str | None,
        model: str,
        timeout_seconds: float,
        max_retries: int,
        max_output_tokens: int,
        max_prompt_chars: int,
        base_url: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            model=model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_output_tokens=max_output_tokens,
            max_prompt_chars=max_prompt_chars,
        )
        self.name = name
        self._url = (base_url or _DEFAULT_OPENAI_URL).rstrip("/") + "/chat/completions"
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = http_client or httpx.Client(timeout=self._timeout)

    def _complete(
        self, prompt: str, json_schema: dict[str, Any], schema_name: str
    ) -> RawCompletion:
        # OpenAI's own models require max_completion_tokens; every other
        # OpenAI-compatible server (Gemini, vLLM, Ollama, ...) is safest with
        # the older max_tokens.
        is_openai_proper = self._url.startswith(_DEFAULT_OPENAI_URL)
        limit_key = "max_completion_tokens" if is_openai_proper else "max_tokens"
        payload = {
            "model": self.model,
            limit_key: self._max_output_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": json_schema, "strict": False},
            },
        }
        try:
            response = self._http.post(self._url, json=payload, headers=self._headers)
        except httpx.TimeoutException as exc:
            raise TransientLLMError(type(exc).__name__) from None
        except httpx.TransportError as exc:
            raise TransientLLMError(type(exc).__name__) from None

        if response.status_code in _RETRYABLE_STATUS or response.status_code >= 500:
            raise TransientLLMError("http_error", response.status_code)
        if response.status_code >= 400:
            raise PermanentLLMError("http_error", response.status_code)

        try:
            body = response.json()
            choice = body["choices"][0]
            if choice.get("finish_reason") == "length":
                raise MalformedOutput("truncated at max tokens")
            data = json.loads(choice["message"]["content"])
        except MalformedOutput:
            raise
        except (ValueError, KeyError, IndexError, TypeError):
            raise MalformedOutput("reply was not the expected JSON") from None
        if not isinstance(data, dict):
            raise MalformedOutput("reply JSON was not an object")
        usage = body.get("usage") or {}
        return RawCompletion(
            data=data,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )
