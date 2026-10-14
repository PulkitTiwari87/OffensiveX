"""The operator CLI end to end: real CLI code -> real FastAPI app -> real PostgreSQL ->
real agent pipeline -> a real local lab HTTP server. Only the LLM is a scripted stand-in
(no external provider is ever called), and every CLI invocation gets a brand-new HTTP
client so nothing but the CLI's own saved session can authenticate it.
"""

from __future__ import annotations

import io
import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from offensivex import cli
from offensivex.agents.runtime import AgentStep
from offensivex.core.config import Settings
from offensivex.main import create_app

pytestmark = pytest.mark.integration

PASSWORD = "correct-horse-battery-staple"  # noqa: S105 - throwaway test credential
API = "http://testserver"


@pytest.fixture
def settings() -> Settings:
    base = Settings(environment="test")
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=base.test_database_url or base.database_url,
        allow_private_targets=True,  # the lab target is on localhost
    )


@pytest.fixture
def db_url(settings: Settings) -> str:
    engine = create_engine(settings.database_url, connect_args={"connect_timeout": 2})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable ({exc.__class__.__name__}).")
    finally:
        engine.dispose()
    return settings.database_url


@pytest.fixture
def lab():
    """A local lab target that sets no security headers -> three findings."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"lab")

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


def _call(capability: str, **request: Any) -> AgentStep:
    return AgentStep(action="call_tool", capability=capability, request=request)


def _finish(**output: Any) -> AgentStep:
    return AgentStep(action="finish", output=output)


class LabModel:
    """Plays each agent's role by reading its prompt (no network, no provider)."""

    name = "scripted"
    model = "scripted-model"

    def __init__(self, url: str) -> None:
        self.url = url

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        if prompt.startswith("Write an executive summary"):
            cited = re.findall(r'"evidence_id": "([0-9a-f-]{36})"', prompt)
            return schema(summary="Three missing headers were found.", cited_evidence_ids=cited[:1])
        turn = int(re.search(r"\(turn (\d+) of", prompt).group(1))  # type: ignore[union-attr]
        if prompt.startswith("You are the Recon Agent"):
            plan = [
                _call("http_probe", url=self.url),
                _finish(assets_discovered=1, summary="mapped"),
            ]
        elif prompt.startswith("You are the Vulnerability Agent"):
            plan = [
                _call("security_header_scan", url=self.url),
                _finish(findings_discovered=3, summary="scanned"),
            ]
        elif prompt.startswith("You are the Investigation Agent"):
            plan = [
                _call("security_header_scan", url=self.url),
                _finish(still_present=True, notes="rechecked"),
            ]
        else:
            raise AssertionError("validation was not requested")
        return plan[turn - 1]


class Cli:
    """Runs `offensivex ...` in-process against the test app."""

    def __init__(self, app: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
        self.app = app
        self.mp = monkeypatch
        self.capsys = capsys

    def run(self, *argv: str, stdin: str | None = None) -> tuple[int, str, str]:
        if stdin is not None:
            self.mp.setattr("sys.stdin", io.StringIO(stdin))
        code = cli.main(
            ["--api-url", API, *argv], client_factory=lambda: TestClient(self.app, base_url=API)
        )
        captured = self.capsys.readouterr()
        return code, captured.out, captured.err

    def json(self, *argv: str) -> Any:
        code, out, err = self.run("--json", *argv)
        assert code == 0, f"{argv} -> {code}: {err}{out}"
        # In-process, the server's own log lines share stdout; the CLI's document is the
        # indented block that starts on a line of its own.
        lines = out.splitlines()
        start = next(i for i, line in enumerate(lines) if line in ("{", "[", "{}", "[]"))
        return json.loads("\n".join(lines[start:]))

    def login(self, username: str) -> None:
        code, _, err = self.run("login", "--username", username, "--password-stdin", stdin=PASSWORD)
        assert code == 0, err


@pytest.fixture
def op(monkeypatch, capsys, tmp_path: Path, settings: Settings, db_url: str, lab: int) -> Cli:
    monkeypatch.setenv("OFFENSIVEX_CLI_HOME", str(tmp_path / "cli-home"))
    # `offensivex admin ...` talks to the database directly: point it at the test database.
    monkeypatch.setenv("OFFENSIVEX_DATABASE_URL", db_url)
    monkeypatch.setenv("OFFENSIVEX_ENVIRONMENT", "test")
    app = create_app(settings)
    app.state.llm_provider = LabModel(f"http://localhost:{lab}/")
    return Cli(app, monkeypatch, capsys)


def _make_user(op: Cli, role: str) -> str:
    username = f"{role}-{uuid.uuid4().hex[:8]}"
    code, out, err = op.run(
        "admin",
        "create-user",
        "--username",
        username,
        "--role",
        role,
        "--password-stdin",
        stdin=PASSWORD + "\n",
    )
    assert code == 0, err
    assert "Created" in out
    return username


def _submit(op: Cli, name: str, lab: int, attestation: str = "I operate this lab") -> dict:
    result: dict = op.json(
        "authorization",
        "submit",
        name,
        "--include",
        f"domain:localhost@{lab}",
        "--attestation",
        attestation,
        "--valid-days",
        "1",
    )
    return result


def test_full_operator_workflow_with_rbac(op: Cli, lab: int, tmp_path: Path) -> None:
    admin = _make_user(op, "admin")
    analyst = _make_user(op, "analyst")
    viewer = _make_user(op, "viewer")

    # Not logged in: everything protected is refused with the "not logged in" code.
    code, _, err = op.run("target", "list")
    assert code == cli.EXIT_AUTH and "offensivex login" in err

    # A wrong password is a clean failure that leaves nothing behind.
    code, _, err = op.run("login", "--username", analyst, "--password-stdin", stdin="wrong\n")
    assert code == cli.EXIT_AUTH
    assert not (tmp_path / "cli-home" / "session.json").exists()

    op.login(analyst)
    session_file = tmp_path / "cli-home" / "session.json"
    assert PASSWORD not in session_file.read_text()  # only tokens are kept, never the password

    name = f"lab-{uuid.uuid4().hex[:8]}"
    entry = f"http://localhost:{lab}/"
    target = op.json("target", "create", "--name", name, "--entry-point", entry)
    assert target["entry_point"] == entry

    # Scope shows hosts AND ports; a pending authorization cannot start an assessment.
    assert _submit(op, name, lab)["status"] == "pending"
    code, _, err = op.run("assessment", "create", name)
    assert code == cli.EXIT_FAILED and "authorization" in err.lower()
    shown = op.json("authorization", "list", name)
    assert shown[0]["scope_rules"][0]["ports"] == str(lab)
    code, out, _ = op.run("target", "show", name)
    assert code == 0 and f"domain:localhost  ports: {lab}" in out

    # Restricted operations are refused for the wrong roles — enforced by the server.
    assert op.run("authorization", "approve", name, "1")[0] == cli.EXIT_DENIED  # analyst
    op.login(viewer)
    assert op.run("target", "create", "--name", "nope")[0] == cli.EXIT_DENIED
    assert op.run("authorization", "approve", name, "1")[0] == cli.EXIT_DENIED
    assert op.run("audit", "list")[0] == cli.EXIT_DENIED
    assert op.run("assessment", "run", str(uuid.uuid4()))[0] == cli.EXIT_DENIED
    assert op.run("target", "list")[0] == 0  # but reading is allowed

    # An admin who is also the submitter may not approve their own scope.
    op.login(admin)
    own = f"own-{uuid.uuid4().hex[:8]}"
    op.json("target", "create", "--name", own, "--entry-point", entry)
    _submit(op, own, lab, "mine")
    code, _, err = op.run("authorization", "approve", own, "1")
    assert code == cli.EXIT_DENIED and "yourself" in err

    # A different person (the admin, not the analyst submitter) approves the analyst's scope.
    assert op.json("authorization", "approve", name, "1")["status"] == "approved"

    # Analyst creates and runs the assessment; the server runs the agent pipeline.
    op.login(analyst)
    assessment = op.json("assessment", "create", name)
    aid = assessment["id"]
    assert assessment["status"] == "running"
    code, out, err = op.run("assessment", "run", aid, "--wait", "--interval", "0.1")
    assert code == 0, err + out
    assert "completed" in out
    assert op.run("assessment", "run", aid)[0] == cli.EXIT_FAILED  # a run starts only once

    final = op.json("assessment", "show", aid)
    assert final["status"] == "completed" and final["finding_count"] == 3
    assert all(r["status"] == "succeeded" and r["error"] is None for r in final["agent_runs"])

    findings = op.json("finding", "list", "--assessment", aid)
    assert {f["affected_component"] for f in findings} == {
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    }
    detail = op.json("finding", "show", findings[0]["id"])
    assert detail["evidence"] and detail["risk_score"] is not None  # real evidence + real score
    assert detail["status"] == "investigating"  # validation was not opted in -> not confirmed
    code, out, _ = op.run("finding", "show", findings[0]["id"])
    assert code == 0 and "Evidence (" in out

    # Reports: JSON + Markdown, written to files, retrievable again later.
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    code, _, err = op.run("report", "generate", aid, "--format", "both", "-o", str(md))
    assert code == 0, err
    only_json = op.json("report", "generate", aid, "--format", "json")
    assert only_json["formats"] == ["json"]
    code, _, err = op.run("report", "get", only_json["id"], "--format", "markdown", "-o", str(md))
    assert code == cli.EXIT_NOT_FOUND and "no Markdown" in err  # asks for what isn't there
    md.write_text("", encoding="utf-8")
    op.run("report", "generate", aid, "--format", "both", "-o", str(md))
    assert "X-Frame-Options" in md.read_text(encoding="utf-8")
    listed = op.json("report", "list", aid)
    assert len(listed) == 3
    code, _, err = op.run("report", "get", listed[0]["id"], "--format", "json", "-o", str(js))
    assert code == 0, err
    assert json.loads(js.read_text(encoding="utf-8"))  # valid JSON content

    # The CLI sees exactly what the API persisted.
    http = TestClient(op.app, base_url=API)
    login = http.post("/api/v1/auth/login", json={"username": analyst, "password": PASSWORD})
    assert login.status_code == 200
    api_findings = http.get(f"/api/v1/findings?assessment_id={aid}").json()
    assert {f["id"] for f in api_findings} == {f["id"] for f in findings}

    # The audit log (admin only) recorded the launch and the scope decision.
    op.login(admin)
    actions = {e["action"] for e in op.json("audit", "list", "--limit", "200")}
    assert {"pipeline.run", "authorization.approve", "report.generate"} <= actions

    op.run("logout")
    assert not session_file.exists()
    assert op.run("target", "list")[0] == cli.EXIT_AUTH


def test_run_without_an_llm_explains_how_to_fix_it(op: Cli, lab: int) -> None:
    admin, analyst = _make_user(op, "admin"), _make_user(op, "analyst")
    op.login(analyst)
    name = f"lab-{uuid.uuid4().hex[:8]}"
    op.json("target", "create", "--name", name, "--entry-point", f"http://localhost:{lab}/")
    _submit(op, name, lab)
    op.login(admin)
    op.json("authorization", "approve", name, "1")
    op.login(analyst)
    aid = op.json("assessment", "create", name)["id"]

    op.app.state.llm_provider = None  # LLM disabled
    code, _, err = op.run("assessment", "run", aid)
    assert code == cli.EXIT_SERVER and "OFFENSIVEX_LLM_ENABLED" in err
    # Nothing was started: the assessment is still runnable.
    assert op.json("assessment", "show", aid)["status"] == "running"


def test_a_failed_run_shows_why_in_the_cli(op: Cli, lab: int) -> None:
    from offensivex.llm.base import LLMProviderError

    class Down:
        name = "scripted"
        model = "down"

        async def generate_structured(self, **params: Any) -> Any:
            raise LLMProviderError("provider unavailable")

    admin, analyst = _make_user(op, "admin"), _make_user(op, "analyst")
    op.login(analyst)
    name = f"lab-{uuid.uuid4().hex[:8]}"
    op.json("target", "create", "--name", name, "--entry-point", f"http://localhost:{lab}/")
    _submit(op, name, lab)
    op.login(admin)
    op.json("authorization", "approve", name, "1")
    op.login(analyst)
    aid = op.json("assessment", "create", name)["id"]

    op.app.state.llm_provider = Down()
    code, out, err = op.run("assessment", "run", aid, "--wait", "--interval", "0.1")
    assert code == cli.EXIT_RUN_ERRORS, err + out
    assert "failed" in out and "LLMProviderError" in out  # the reason, not just the status
    stored = op.json("assessment", "show", aid)
    assert stored["status"] == "failed"
    assert any(r["status"] == "failed" and r["error"] for r in stored["agent_runs"])


def test_usage_errors_and_unreachable_server(op: Cli) -> None:
    assert op.run("authorization", "submit", "x", "--attestation", "a")[0] == cli.EXIT_USAGE
    assert op.run("no-such-command")[0] == cli.EXIT_USAGE
    assert op.run("--help")[0] == 0
    assert cli.main(["--api-url", "http://127.0.0.1:9", "status"]) == cli.EXIT_SERVER
