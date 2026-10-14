"""Unit tests for FixtureReplaySandbox — no Docker required."""

from __future__ import annotations

import json

import pytest

from offensivex.sandbox.container import FixtureNotFoundError, FixtureReplaySandbox, SandboxResult


def test_run_returns_recorded_fixture() -> None:
    sandbox = FixtureReplaySandbox(
        {
            ("echo", "hello"): SandboxResult(
                exit_status=0, stdout=b"hello\n", stderr=b"", timed_out=False, killed=False
            )
        }
    )
    result = sandbox.run(["echo", "hello"])
    assert result.exit_status == 0
    assert result.stdout == b"hello\n"


def test_unrecorded_argv_raises() -> None:
    sandbox = FixtureReplaySandbox({})
    with pytest.raises(FixtureNotFoundError):
        sandbox.run(["echo", "nothing-recorded"])


def test_from_json_file_round_trips(tmp_path) -> None:  # type: ignore[no-untyped-def]
    fixture_path = tmp_path / "fixtures.json"
    fixture_path.write_text(
        json.dumps(
            [
                {
                    "argv": ["dig", "+short", "example.test"],
                    "exit_status": 0,
                    "stdout": "203.0.113.5\n",
                    "stderr": "",
                    "timed_out": False,
                    "killed": False,
                }
            ]
        ),
        encoding="utf-8",
    )
    sandbox = FixtureReplaySandbox.from_json_file(fixture_path)
    result = sandbox.run(["dig", "+short", "example.test"])
    assert result.stdout == b"203.0.113.5\n"
    assert result.exit_status == 0
    assert result.timed_out is False
