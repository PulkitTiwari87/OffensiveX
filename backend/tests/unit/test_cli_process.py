"""The CLI as an operator runs it: the registered `offensivex` executable in a real
subprocess, plus the HTTP/session behaviour tested against a mock transport (no server)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from offensivex import cli

EXE = Path(sys.executable).parent / ("offensivex.exe" if os.name == "nt" else "offensivex")


def run(*args: str, home: Path, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "OFFENSIVEX_CLI_HOME": str(home)}
    env.pop("OFFENSIVEX_API_URL", None)
    return subprocess.run(  # noqa: S603 - fixed argv, our own executable
        [str(EXE), *args], capture_output=True, text=True, env=env, input=stdin, timeout=60
    )


needs_exe = pytest.mark.skipif(
    not EXE.exists(), reason="offensivex is not installed (pip install -e .)"
)


@needs_exe
def test_registered_entry_point_help_and_exit_codes(tmp_path: Path) -> None:
    helped = run("--help", home=tmp_path)
    assert helped.returncode == 0 and "assessment" in helped.stdout and "report" in helped.stdout
    assert run("target", "--help", home=tmp_path).returncode == 0

    assert run("bogus", home=tmp_path).returncode == cli.EXIT_USAGE
    missing_include = run("authorization", "submit", "t", "--attestation", "a", home=tmp_path)
    assert missing_include.returncode == cli.EXIT_USAGE

    not_logged_in = run("target", "list", home=tmp_path)
    assert not_logged_in.returncode == cli.EXIT_AUTH and "offensivex login" in not_logged_in.stderr

    unreachable = run("--api-url", "http://127.0.0.1:9", "status", home=tmp_path)
    assert unreachable.returncode == cli.EXIT_SERVER
    assert "Is the backend running" in unreachable.stderr


@needs_exe
def test_admin_help_is_reachable_through_the_entry_point(tmp_path: Path) -> None:
    result = run("admin", "--help", home=tmp_path)
    assert result.returncode == 0 and "create-user" in result.stdout
    create = run("admin", "create-user", "--help", home=tmp_path)
    assert "--password-stdin" in create.stdout  # a password is never an argument
    assert "--password " not in create.stdout.replace("--password-stdin", "")


def _api(handler, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> cli.Api:
    monkeypatch.setenv("OFFENSIVEX_CLI_HOME", str(tmp_path))
    return cli.Api(httpx.Client(transport=httpx.MockTransport(handler)), "http://api.test")


def test_login_stores_only_tokens_and_logout_removes_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(
                200,
                json={
                    "user": {"id": "1", "username": "alice", "role": "admin"},
                    "csrf_token": "CSRF-TOKEN",
                    "expires_at": "2099-01-01T00:00:00Z",
                },
                headers={"set-cookie": "ofx_session=SESSION-TOKEN; HttpOnly; Path=/"},
            )
        return httpx.Response(204)

    monkeypatch.setattr("sys.stdin", io.StringIO("hunter2-password\n"))
    monkeypatch.setenv("OFFENSIVEX_CLI_HOME", str(tmp_path))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    code = cli.main(
        ["--api-url", "http://api.test", "login", "--username", "alice", "--password-stdin"],
        client_factory=lambda: client,
    )
    assert code == 0
    saved = (tmp_path / "session.json").read_text()
    assert "SESSION-TOKEN" in saved and "CSRF-TOKEN" in saved
    assert "hunter2-password" not in saved
    out = capsys.readouterr()
    assert "hunter2-password" not in out.out + out.err
    assert "SESSION-TOKEN" not in out.out + out.err
    if os.name != "nt":
        assert (tmp_path / "session.json").stat().st_mode & 0o777 == 0o600

    client2 = httpx.Client(transport=httpx.MockTransport(handler))
    assert cli.main(["--api-url", "http://api.test", "logout"], client_factory=lambda: client2) == 0
    assert not (tmp_path / "session.json").exists()
    logout = seen[-1]
    assert logout.method == "POST" and logout.headers["x-csrf-token"] == "CSRF-TOKEN"
    assert "ofx_session=SESSION-TOKEN" in logout.headers["cookie"]


def test_session_for_another_server_is_never_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "session.json").write_text(
        json.dumps(
            {"api_url": "http://other.test", "cookie_name": "c", "token": "T", "csrf_token": "X"}
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("request must not be sent without a session for this server")

    api = _api(handler, tmp_path, monkeypatch)
    with pytest.raises(cli.CliError) as exc:
        api.request("GET", "/api/v1/targets")
    assert exc.value.exit_code == cli.EXIT_AUTH


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (401, {"detail": "Authentication required."}, cli.EXIT_AUTH),
        (403, {"detail": "nope"}, cli.EXIT_DENIED),
        (404, {"detail": "gone"}, cli.EXIT_NOT_FOUND),
        (409, {"detail": "already started"}, cli.EXIT_FAILED),
        (
            422,
            {"errors": [{"loc": ["body", "pattern"], "msg": "bad", "type": "x"}]},
            cli.EXIT_FAILED,
        ),
        (500, {"detail": "boom"}, cli.EXIT_SERVER),
        (503, {"detail": "no llm"}, cli.EXIT_SERVER),
    ],
)
def test_http_errors_map_to_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int, body: dict, code: int
) -> None:
    (tmp_path / "session.json").write_text(
        json.dumps(
            {"api_url": "http://api.test", "cookie_name": "c", "token": "T", "csrf_token": "X"}
        )
    )
    api = _api(lambda r: httpx.Response(status, json=body), tmp_path, monkeypatch)
    with pytest.raises(cli.CliError) as exc:
        api.request("POST", "/api/v1/anything", json_body={})
    assert exc.value.exit_code == code
    if status == 401:  # an expired session is forgotten so the next command says "log in"
        assert not (tmp_path / "session.json").exists()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "domain:localhost@8000-8100",
            {"rule_type": "domain", "pattern": "localhost", "ports": "8000-8100"},
        ),
        ("cidr:10.0.0.0/24", {"rule_type": "cidr", "pattern": "10.0.0.0/24"}),
        (
            "cidr:2001:db8::/32@443",
            {"rule_type": "cidr", "pattern": "2001:db8::/32", "ports": "443"},
        ),
    ],
)
def test_scope_rule_syntax(text: str, expected: dict) -> None:
    assert cli._parse_rule(text, exclusion=True) == {**expected, "is_exclusion": True}


@pytest.mark.parametrize("bad", ["localhost", ":x", "domain:", "@80"])
def test_bad_scope_rules_are_usage_errors(bad: str) -> None:
    with pytest.raises(cli.CliError) as exc:
        cli._parse_rule(bad, exclusion=False)
    assert exc.value.exit_code == cli.EXIT_USAGE
