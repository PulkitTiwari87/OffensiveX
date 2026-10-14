"""Structured JSON logging (ADR-014 in docs/Decision.md).

Every log line is a JSON object with at least `event`, `level`, and
`timestamp`. A redaction processor runs on every log call so that a secret
accidentally bound into a log context (e.g. `log.info("x", password=...)`)
never reaches the output — this is the one safety net behind the "never log
secrets" rule in docs/Guardrail.md section 3/section 4, which later phases
(Tool Registry audit logging, agent activity logging) depend on.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

# Keys whose values are always replaced, regardless of where they appear in
# the event dict (top-level or nested). Matched case-insensitively and by
# substring so e.g. "db_password", "apiKey", "Authorization" are all caught.
_SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "cookie",
)
_REDACTED = "***REDACTED***"


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_SUBSTRINGS)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _is_sensitive_key(k) else _redact_value(v)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    return value


def redact_sensitive_data(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """A structlog processor: redact any key that looks sensitive.

    Runs before the renderer on every single log call, so there is no code
    path that can "forget" to redact — it is not opt-in per call site.
    """
    for key in list(event_dict.keys()):
        if _is_sensitive_key(key):
            event_dict[key] = _REDACTED
        else:
            event_dict[key] = _redact_value(event_dict[key])
    return event_dict


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structlog + stdlib logging to emit redacted JSON lines.

    Idempotent: safe to call more than once (e.g. once from the app
    factory, once from a test fixture) — structlog.configure() simply
    replaces the prior configuration.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            redact_sensitive_data,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
