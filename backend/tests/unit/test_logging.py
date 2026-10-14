from __future__ import annotations

import json

import pytest

from offensivex.core.logging import configure_logging, get_logger, redact_sensitive_data


def test_redact_processor_masks_known_sensitive_keys() -> None:
    event = {
        "event": "login",
        "password": "hunter2",
        "api_key": "sk-abcdef",
        "Authorization": "Bearer xyz",
        "username": "alice",
    }
    result = redact_sensitive_data(None, "info", dict(event))

    assert result["password"] == "***REDACTED***"
    assert result["api_key"] == "***REDACTED***"
    assert result["Authorization"] == "***REDACTED***"
    assert result["username"] == "alice"  # not sensitive, left intact


def test_redact_processor_masks_nested_dicts() -> None:
    event = {"event": "x", "context": {"db_password": "hunter2", "host": "localhost"}}
    result = redact_sensitive_data(None, "info", dict(event))

    assert result["context"]["db_password"] == "***REDACTED***"
    assert result["context"]["host"] == "localhost"


@pytest.mark.parametrize("marker", ["password", "secret", "token", "credential", "cookie"])
def test_redact_processor_covers_every_documented_marker(marker: str) -> None:
    event = {"event": "x", marker: "real-value"}
    result = redact_sensitive_data(None, "info", dict(event))
    assert result[marker] == "***REDACTED***"


def test_configured_logger_emits_json_and_redacts(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    log = get_logger("test")
    log.info("user.login", password="hunter2", user_id=42)

    captured = capsys.readouterr()
    line = captured.out.strip().splitlines()[-1]
    payload = json.loads(line)

    assert payload["event"] == "user.login"
    assert payload["password"] == "***REDACTED***"
    assert payload["user_id"] == 42
    assert "hunter2" not in captured.out
