"""Password hashing — argon2id via argon2-cffi (ADR-012).

The library's defaults are its maintainers' current recommendation (RFC 9106
low-memory profile); parameters live inside each stored hash, so raising
them later needs no migration — `needs_rehash` lets login upgrade old hashes.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from offensivex.core.errors import OffensiveXError

MIN_PASSWORD_LENGTH = 12
# Bounds the work an unauthenticated caller can make the server do.
MAX_PASSWORD_LENGTH = 256

_hasher = PasswordHasher()
# Verified against when the username doesn't exist, so "no such user" and
# "wrong password" cost the same time (no user-enumeration timing oracle).
_DUMMY_HASH = _hasher.hash("offensivex-timing-equalizer")


class WeakPasswordError(OffensiveXError):
    status_code = 422
    title = "Password does not meet requirements"


def validate_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPasswordError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")


def hash_password(password: str) -> str:
    validate_password_strength(password)
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """False for a wrong password, a malformed hash, or no hash at all."""
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        matched = _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return matched and password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)
