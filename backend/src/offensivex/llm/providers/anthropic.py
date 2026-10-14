"""Anthropic provider (official `anthropic` SDK).

Structured output uses forced tool use: the caller's JSON Schema becomes the
`input_schema` of a single tool and `tool_choice` forces the model to call it,
so the reply is a JSON object by construction rather than prose to be parsed.
The SDK's own retries are disabled (`max_retries=0`); the shared layer in
`offensivex.llm.structured` does the bounded retrying uniformly.

Environment: `OFFENSIVEX_LLM_PROVIDER=anthropic`, `OFFENSIVEX_LLM_API_KEY`,
`OFFENSIVEX_LLM_MODEL` (any Messages-API model id), optional
`OFFENSIVEX_LLM_BASE_URL` (a proxy/gateway).
"""

from __future__ import annotations

from typing import Any

import anthropic

from offensivex.core.config import LLMProviderName
from offensivex.llm.structured import (
    SYSTEM_PROMPT,
    MalformedOutput,
    PermanentLLMError,
    RawCompletion,
    StructuredProvider,
    TransientLLMError,
)

_TOOL_NAME = "submit_result"
_RETRYABLE_STATUS = frozenset({408, 409, 429})


class AnthropicProvider(StructuredProvider):
    name: LLMProviderName = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_retries: int,
        max_output_tokens: int,
        max_prompt_chars: int,
        base_url: str | None = None,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        super().__init__(
            model=model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_output_tokens=max_output_tokens,
            max_prompt_chars=max_prompt_chars,
        )
        self._client = client or anthropic.Anthropic(
            api_key=api_key, base_url=base_url, timeout=self._timeout, max_retries=0
        )

    def _complete(
        self, prompt: str, json_schema: dict[str, Any], schema_name: str
    ) -> RawCompletion:
        try:
            message = self._client.messages.create(
                model=self.model,
                max_tokens=self._max_output_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                tools=[
                    {
                        "name": _TOOL_NAME,
                        "description": f"Submit the {schema_name} result.",
                        "input_schema": json_schema,
                    }
                ],
                tool_choice={"type": "tool", "name": _TOOL_NAME},
            )
        except anthropic.APIStatusError as exc:
            if exc.status_code in _RETRYABLE_STATUS or exc.status_code >= 500:
                raise TransientLLMError("http_error", exc.status_code) from None
            raise PermanentLLMError("http_error", exc.status_code) from None
        except anthropic.APIConnectionError as exc:  # includes APITimeoutError
            raise TransientLLMError(type(exc).__name__) from None

        if message.stop_reason == "max_tokens":
            raise MalformedOutput("truncated at max_tokens")
        for block in message.content:
            if block.type == "tool_use" and block.name == _TOOL_NAME:
                if not isinstance(block.input, dict):
                    raise MalformedOutput("tool input was not an object")
                return RawCompletion(
                    data=block.input,
                    input_tokens=message.usage.input_tokens,
                    output_tokens=message.usage.output_tokens,
                )
        raise MalformedOutput("no tool call in reply")
