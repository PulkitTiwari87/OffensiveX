from __future__ import annotations

import pytest

from offensivex.core.config import Settings


def test_development_defaults_load_without_error() -> None:
    settings = Settings(environment="development")
    assert settings.environment == "development"


@pytest.mark.parametrize("weak_secret", ["", "changeme", "secret", "x" * 10])
def test_production_rejects_weak_secret(weak_secret: str) -> None:
    with pytest.raises(ValueError, match="OFFENSIVEX_SECRET_KEY"):
        Settings(environment="production", secret_key=weak_secret)


def test_production_accepts_strong_secret() -> None:
    settings = Settings(environment="production", secret_key="a" * 40)
    assert settings.environment == "production"


def test_repr_never_contains_secret_value() -> None:
    settings = Settings(
        environment="production",
        secret_key="supersecretvalue1234567890abcdefgh",
        llm_api_key="another-real-looking-secret-value",
    )
    rendered = repr(settings)
    assert "supersecretvalue1234567890abcdefgh" not in rendered
    assert "another-real-looking-secret-value" not in rendered


def test_str_never_contains_secret_value() -> None:
    secret = "supersecretvalue1234567890abcdef"  # 33 chars, clears the production minimum
    settings = Settings(environment="production", secret_key=secret)
    assert secret not in str(settings.secret_key)
    assert str(settings.secret_key) != secret


def test_llm_disabled_by_default() -> None:
    settings = Settings()
    assert settings.llm_enabled is False
    assert settings.llm_provider is None
