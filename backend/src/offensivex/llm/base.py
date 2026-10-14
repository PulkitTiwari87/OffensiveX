"""The LLM provider abstraction — interface only, per ADR-010/ADR-021.

Phase 0 defines the *shape* so that later phases (the agent framework,
Phase 5 onward) are not coupled to one vendor, and so configuration
(offensivex.core.config.Settings.llm_*) has a stable contract to point at.
No provider is implemented here, no network call is made, and no agent
logic exists yet — the first provider/model is intentionally undecided
(see docs/Memory.md, "Unresolved questions").

Concrete providers (Gemini / OpenAI / Anthropic / a local model) are built
starting Phase 5, each in its own module under `offensivex/llm/providers/`,
implementing this protocol.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from offensivex.core.config import LLMProviderName, Settings


@runtime_checkable
class LLMProvider(Protocol):
    """What every concrete provider must implement.

    Deliberately minimal for Phase 0: one method, structured in/structured
    out. Grounding/validation, evidence citation, and the agent-facing
    context builder belong to docs/architecture/security-boundary.md and
    are built alongside the agent framework (Phase 5+), not here.
    """

    name: LLMProviderName

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        """Return an instance of `schema` built from the model's output."""
        ...


def get_llm_provider(settings: Settings) -> LLMProvider:
    """Resolve the configured provider.

    Phase 0 has no providers to resolve. This exists so later phases have a
    single place to wire provider selection into, and so that an
    accidental, premature call (e.g. from code written ahead of Phase 5)
    fails loudly instead of silently doing nothing.
    """
    raise NotImplementedError(
        "LLM providers are not implemented until the agent framework phase "
        "(see docs/roadmap/roadmap.md, P5). "
        f"Requested provider: {settings.llm_provider!r}."
    )
