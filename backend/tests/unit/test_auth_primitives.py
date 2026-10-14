"""Unit tests for the auth building blocks that need no database."""

from __future__ import annotations

import pytest

from offensivex.auth import sessions
from offensivex.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    WeakPasswordError,
    hash_password,
    needs_rehash,
    verify_password,
)
from offensivex.auth.permissions import ROLE_PERMISSIONS, Permission, has_permission
from offensivex.core.config import Settings
from offensivex.db.models import UserRole
from offensivex.services.audit import scrub

GOOD_PASSWORD = "a-long-enough-test-password"  # noqa: S105


def test_hash_is_argon2id_and_never_the_password() -> None:
    hashed = hash_password(GOOD_PASSWORD)
    assert hashed.startswith("$argon2id$")
    assert GOOD_PASSWORD not in hashed
    assert hash_password(GOOD_PASSWORD) != hashed  # random salt
    assert not needs_rehash(hashed)


def test_verify_accepts_right_and_rejects_wrong_password() -> None:
    hashed = hash_password(GOOD_PASSWORD)
    assert verify_password(GOOD_PASSWORD, hashed) is True
    assert verify_password("not-the-password-at-all", hashed) is False


def test_verify_with_no_hash_is_false_and_does_not_raise() -> None:
    # The "unknown username" path: must be False (and cost a real hash check).
    assert verify_password(GOOD_PASSWORD, None) is False
    assert verify_password(GOOD_PASSWORD, "not-a-valid-hash") is False


def test_password_length_bounds() -> None:
    with pytest.raises(WeakPasswordError):
        hash_password("x" * (MIN_PASSWORD_LENGTH - 1))
    with pytest.raises(WeakPasswordError):
        hash_password("x" * (MAX_PASSWORD_LENGTH + 1))
    assert verify_password("x" * (MAX_PASSWORD_LENGTH + 1), hash_password(GOOD_PASSWORD)) is False


def test_session_token_hash_is_stable_and_not_the_token() -> None:
    token = "some-raw-token"  # noqa: S105
    assert sessions.hash_token(token) == sessions.hash_token(token)
    assert sessions.hash_token(token) != token
    assert len(sessions.hash_token(token)) == 64


def test_viewer_is_read_only() -> None:
    assert ROLE_PERMISSIONS[UserRole.VIEWER] == {Permission.DATA_READ}


def test_analyst_cannot_decide_scope_manage_users_or_read_audit() -> None:
    for permission in (
        Permission.AUTHORIZATIONS_DECIDE,
        Permission.USERS_MANAGE,
        Permission.AUDIT_READ,
    ):
        assert not has_permission(UserRole.ANALYST, permission)
    assert has_permission(UserRole.ANALYST, Permission.FINDINGS_OVERRIDE)


def test_admin_holds_every_permission_and_no_permission_is_orphaned() -> None:
    assert set(Permission) == ROLE_PERMISSIONS[UserRole.ADMIN]
    for permission in Permission:
        assert any(permission in held for held in ROLE_PERMISSIONS.values())


def test_roles_are_strictly_nested() -> None:
    assert ROLE_PERMISSIONS[UserRole.VIEWER] < ROLE_PERMISSIONS[UserRole.ANALYST]
    assert ROLE_PERMISSIONS[UserRole.ANALYST] < ROLE_PERMISSIONS[UserRole.ADMIN]


def test_unknown_role_has_no_permissions() -> None:
    assert not has_permission("superuser", Permission.DATA_READ)  # type: ignore[arg-type]


def test_scrub_drops_secret_keys_recursively_and_truncates() -> None:
    cleaned = scrub(
        {
            "password": "hunter2",
            "nested": {"api_key": "k", "session_token": "t", "ok": "fine"},
            "list": [{"authorization": "Bearer x", "keep": 1}],
            "long": "z" * 5000,
        }
    )
    assert "password" not in cleaned
    assert cleaned["nested"] == {"ok": "fine"}
    assert cleaned["list"] == [{"keep": 1}]
    assert len(cleaned["long"]) < 600


def test_scrub_strips_nul_characters_that_jsonb_cannot_store() -> None:
    assert scrub({"reason": "bad\x00reason"}) == {"reason": "badreason"}


def test_wildcard_cors_is_refused_because_sessions_are_cookies() -> None:
    with pytest.raises(ValueError, match="explicit origins"):
        Settings(environment="test", api_cors_origins=["*"])
    assert Settings(environment="test", api_cors_origins=["https://ui.example"])


def test_cookie_secure_flag_only_relaxes_in_development_and_test() -> None:
    assert Settings(environment="development").session_cookie_secure is False
    assert Settings(environment="test").session_cookie_secure is False
    production = Settings(environment="production", secret_key="s" * 40)
    assert production.session_cookie_secure is True
