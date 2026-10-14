"""Centralized, validated application configuration.

Settings are read from environment variables prefixed ``OFFENSIVEX_`` (ADR-017
in docs/Decision.md). Nothing here is read from a committed file; see
``.env.example`` at the repository root for local development.

Phase 0 scope: environment, secrets, database connection, logging, API
configuration, and *placeholder* fields for execution limits, sandbox
configuration, and the LLM provider abstraction (docs/llm/* and the Tool
Registry/Sandbox are not implemented until later phases — these fields exist
only so later phases have a stable place to read configuration from).
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LLMProviderName = Literal["gemini", "openai", "anthropic", "local"]

# Secret values that must never be accepted in a production environment.
# Deliberately short/obvious so a developer cannot accidentally ship them.
_WEAK_SECRETS = {"", "changeme", "change-me", "secret", "insecure", "dev"}
_MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Application settings.

    Secret fields use ``SecretStr`` so they are never exposed by ``repr()``,
    ``str()``, or an accidental ``print(settings)`` — logs and error
    responses therefore cannot leak them. See docs/Guardrail.md section 3
    ("never expose secrets in ... logs ... or error messages").
    """

    model_config = SettingsConfigDict(
        env_prefix="OFFENSIVEX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application environment -------------------------------------------------
    environment: Environment = "development"

    # --- Security / secrets --------------------------------------------------
    # Session/cookie signing key (consumed starting Phase 2, when auth lands).
    secret_key: SecretStr = SecretStr("")

    # --- Database connection --------------------------------------------------
    database_url: str = "postgresql+psycopg://offensivex:offensivex@localhost:5433/offensivex"
    # Used only by the integration test suite; falls back to database_url
    # with a different database name if not set.
    test_database_url: str | None = None

    # --- API configuration -----------------------------------------------------
    # Binding to all interfaces is intentional: this process runs inside a
    # container (docker-compose.yml) where 0.0.0.0 is required for the host
    # to reach it; it is not exposed directly on a developer's machine.
    api_host: str = "0.0.0.0"  # noqa: S104
    api_port: int = 8000
    api_cors_origins: list[str] = Field(default_factory=list)

    # --- Logging ---------------------------------------------------------------
    log_level: str = "INFO"

    # --- Execution limits (placeholder; consumed starting the Tool Registry,
    # Phase 3, and the Sandbox, Phase 4 — see docs/architecture/execution-model.md) ---
    tool_execution_timeout_seconds: int = 30
    max_concurrent_tool_executions: int = 2

    # --- Sandbox configuration (placeholder; consumed starting Phase 4,
    # see docs/tools/sandbox.md) -------------------------------------------------
    sandbox_image: str = "offensivex-sandbox:latest"

    # --- Scope validation (Phase 2; docs/Guardrail.md section 2.7) -------------
    # "Loopback, link-local, private-range, and cloud-metadata destinations ...
    # are denied unless they are explicitly listed in scope AND the deployment
    # permits private targets." Default-deny: false unless a developer/lab
    # deployment explicitly opts in.
    allow_private_targets: bool = False

    # --- LLM provider configuration (placeholder; consumed starting the agent
    # framework, Phase 5 — see docs/architecture/agent-architecture.md and
    # backend/src/offensivex/llm/base.py). No provider is implemented in Phase 0;
    # the first provider/model is intentionally undecided. ----------------------
    llm_enabled: bool = False
    llm_provider: LLMProviderName | None = None
    llm_model: str | None = None
    llm_api_key: SecretStr | None = None

    @model_validator(mode="after")
    def _validate_production_safety(self) -> Settings:
        """Fail fast rather than start insecurely.

        Carries forward the original design's rule (ADR-017, Guardrail section 3):
        a production deployment must not run with a default/empty/weak
        secret key. This is a startup-time check, not a runtime one — an
        insecure production configuration must never serve a single request.
        """
        if self.environment == "production":
            secret = self.secret_key.get_secret_value()
            if secret.lower() in _WEAK_SECRETS or len(secret) < _MIN_SECRET_LENGTH:
                raise ValueError(
                    "OFFENSIVEX_SECRET_KEY must be set to a random value of at "
                    f"least {_MIN_SECRET_LENGTH} characters when "
                    "OFFENSIVEX_ENVIRONMENT=production. Refusing to start."
                )
        return self

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Defensive: even though SecretStr already redacts, make the intent
        # explicit so a future field added without SecretStr doesn't leak
        # silently through the default dataclass-style repr.
        return (
            f"Settings(environment={self.environment!r}, "
            f"database_url={self.database_url!r}, "
            "secret_key=SecretStr('**********'), "
            f"llm_provider={self.llm_provider!r}, "
            "llm_api_key="
            f"{'SecretStr(**********)' if self.llm_api_key else None})"
        )


def get_settings() -> Settings:
    """Construct Settings from the environment.

    Not cached at module import time: tests construct their own Settings
    instances (see tests/conftest.py) so environment-variable changes
    between tests are respected.
    """
    return Settings()
