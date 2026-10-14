"""API contracts the dashboard and CLI depend on, against real PostgreSQL, with isolated
users/targets created per test and a scripted stand-in for the LLM (no provider is called)."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, text

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.llm.base import LLMProviderError
from offensivex.main import create_app
from tests.integration.auth_support import TEST_PASSWORD, create_user, login
from tests.integration.test_cli_workflow import LabModel

pytestmark = pytest.mark.integration

NO_DASHBOARD = "does-not-exist"


def _settings(**over: Any) -> Settings:
    base = Settings(environment="test")
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=base.test_database_url or base.database_url,
        allow_private_targets=True,
        dashboard_dir=NO_DASHBOARD,
        **over,
    )


@pytest.fixture
def settings() -> Settings:
    s = _settings()
    engine = create_engine(s.database_url, connect_args={"connect_timeout": 2})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable ({exc.__class__.__name__}).")
    finally:
        engine.dispose()
    return s


@pytest.fixture
def lab():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"lab")

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


class World:
    """One app plus a logged-in client per role, all brand new for this test."""

    def __init__(self, settings: Settings, lab_port: int) -> None:
        self.settings = settings
        self.lab = lab_port
        self.app = create_app(settings)
        self.app.state.llm_provider = LabModel(f"http://localhost:{lab_port}/")
        self.clients: dict[str, TestClient] = {}
        self.names: dict[str, str] = {}
        for role in ("viewer", "analyst", "admin"):
            user = create_user(settings, role=models.UserRole(role))
            client = TestClient(self.app)
            login(client, user.username)
            self.clients[role] = client
            self.names[role] = user.username

    def __getitem__(self, role: str) -> TestClient:
        return self.clients[role]

    def approved_target(self, rules: list[dict] | None = None, *, entry: bool = True) -> dict:
        name = f"t-{uuid.uuid4().hex[:8]}"
        body: dict[str, Any] = {"name": name, "type": "web_application"}
        if entry:
            body["entry_point"] = f"http://localhost:{self.lab}/"
        created = self["analyst"].post("/api/v1/targets", json=body)
        assert created.status_code == 201, created.text
        target = created.json()
        now = datetime.now(UTC)
        submitted = self["analyst"].post(
            f"/api/v1/targets/{target['id']}/authorizations",
            json={
                "scope_rules": rules
                or [{"rule_type": "domain", "pattern": "localhost", "ports": str(self.lab)}],
                "attestation": "lab",
                "valid_from": (now - timedelta(minutes=1)).isoformat(),
                "valid_until": (now + timedelta(days=1)).isoformat(),
            },
        )
        assert submitted.status_code == 201, submitted.text
        approved = self["admin"].post(f"/api/v1/targets/{target['id']}/authorizations/1/approve")
        assert approved.status_code == 200, approved.text
        return target

    def assessment(self, target: dict, **body: Any) -> dict:
        created = self["analyst"].post(
            "/api/v1/assessments", json={"target_id": target["id"], **body}
        )
        assert created.status_code == 201, created.text
        return created.json()


@pytest.fixture
def world(settings: Settings, lab: int) -> World:
    return World(settings, lab)


# --- list endpoints and the permission boundaries -------------------------------------


def test_list_endpoints_return_persisted_state_for_every_role(world: World) -> None:
    target = world.approved_target()
    assessment = world.assessment(target)
    assert world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/run").status_code == 202
    report = world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/reports", json={})
    assert report.status_code == 201

    for role in ("viewer", "analyst", "admin"):
        c = world[role]
        assert target["id"] in {t["id"] for t in c.get("/api/v1/targets").json()}
        auths = c.get(f"/api/v1/targets/{target['id']}/authorizations").json()
        assert auths[0]["status"] == "approved"
        assert auths[0]["scope_rules"][0]["ports"] == str(world.lab)
        items = c.get(f"/api/v1/assessments?target_id={target['id']}").json()
        assert [i["id"] for i in items] == [assessment["id"]] and items[0]["finding_count"] == 3
        findings = c.get(f"/api/v1/findings?assessment_id={assessment['id']}").json()
        assert len(findings) == 3 and all(
            f["asset_identifier"].startswith("http") for f in findings
        )
        reports = c.get(f"/api/v1/assessments/{assessment['id']}/reports").json()
        assert [r["id"] for r in reports] == [report.json()["id"]]
        overview = c.get("/api/v1/overview").json()
        assert overview["targets"] >= 1 and "completed" in overview["assessments_by_status"]

    # Filters narrow by severity and unknown assessments are empty, not an error.
    c = world["viewer"]
    assert (
        c.get(f"/api/v1/findings?assessment_id={assessment['id']}&severity=critical").json() == []
    )
    assert c.get(f"/api/v1/findings?assessment_id={uuid.uuid4()}").json() == []
    assert c.get(f"/api/v1/targets/{uuid.uuid4()}/authorizations").status_code == 404


def test_role_boundaries(world: World) -> None:
    target = world.approved_target()
    assessment = world.assessment(target)
    aid = assessment["id"]

    viewer = world["viewer"]
    assert viewer.post("/api/v1/targets", json={"name": "x", "type": "web"}).status_code == 403
    assert viewer.post("/api/v1/assessments", json={"target_id": target["id"]}).status_code == 403
    assert viewer.post(f"/api/v1/assessments/{aid}/run").status_code == 403
    assert viewer.post(f"/api/v1/assessments/{aid}/reports", json={}).status_code == 403
    assert viewer.get("/api/v1/audit-log").status_code == 403

    analyst = world["analyst"]
    assert (
        analyst.post(f"/api/v1/targets/{target['id']}/authorizations/1/approve").status_code == 403
    )
    assert analyst.get("/api/v1/audit-log").status_code == 403

    assert world["admin"].get("/api/v1/audit-log").status_code == 200
    anonymous = TestClient(world.app)
    for path in (
        "/api/v1/targets",
        "/api/v1/overview",
        "/api/v1/system/status",
        "/api/v1/findings",
    ):
        assert anonymous.get(path).status_code == 401


# --- launching ------------------------------------------------------------------------


def test_launch_requires_approved_in_scope_authorization(world: World) -> None:
    # Pending (never approved) scope: no assessment can be created at all.
    name = f"t-{uuid.uuid4().hex[:8]}"
    t = world["analyst"].post("/api/v1/targets", json={"name": name, "type": "web"}).json()
    refused = world["analyst"].post("/api/v1/assessments", json={"target_id": t["id"]})
    assert refused.status_code == 422 and "authorization" in refused.json()["detail"].lower()

    # An entry point outside the submitted scope (wrong port) is rejected at submission.
    other = (
        world["analyst"]
        .post(
            "/api/v1/targets",
            json={
                "name": f"t-{uuid.uuid4().hex[:8]}",
                "type": "web",
                "entry_point": "http://localhost:1/",
            },
        )
        .json()
    )
    now = datetime.now(UTC)
    out_of_scope = world["analyst"].post(
        f"/api/v1/targets/{other['id']}/authorizations",
        json={
            "scope_rules": [
                {"rule_type": "domain", "pattern": "localhost", "ports": str(world.lab)}
            ],
            "attestation": "x",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    )
    assert out_of_scope.status_code == 422


def test_run_is_refused_without_an_llm_and_changes_nothing(world: World) -> None:
    assessment = world.assessment(world.approved_target())
    world.app.state.llm_provider = None
    refused = world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/run")
    assert refused.status_code == 503 and "OFFENSIVEX_LLM_ENABLED" in refused.json()["detail"]
    after = world["viewer"].get(f"/api/v1/assessments/{assessment['id']}").json()
    assert after["status"] == "running" and all(
        r["status"] == "queued" for r in after["agent_runs"]
    )


def test_a_run_cannot_be_started_twice_or_after_cancellation(world: World) -> None:
    first = world.assessment(world.approved_target())
    assert world["analyst"].post(f"/api/v1/assessments/{first['id']}/run").status_code == 202
    again = world["analyst"].post(f"/api/v1/assessments/{first['id']}/run")
    assert again.status_code == 409
    done = world["viewer"].get(f"/api/v1/assessments/{first['id']}").json()
    assert done["status"] == "completed"
    # one recon + one vulnerability + three investigations: the second call added nothing
    assert len(done["agent_runs"]) == 5

    second = world.assessment(world.approved_target())
    assert world["analyst"].post(f"/api/v1/assessments/{second['id']}/cancel").status_code == 200
    cancelled = world["analyst"].post(f"/api/v1/assessments/{second['id']}/run")
    assert cancelled.status_code == 409

    # A run already executing in this process is refused even before any agent row exists.
    third = world.assessment(world.approved_target())
    world.app.state.running_assessments.add(uuid.UUID(third["id"]))
    assert world["analyst"].post(f"/api/v1/assessments/{third['id']}/run").status_code == 409


def test_failures_carry_a_useful_reason(world: World) -> None:
    class Down:
        name = "scripted"
        model = "down"

        async def generate_structured(self, **params: Any) -> Any:
            raise LLMProviderError("provider unavailable")

    assessment = world.assessment(world.approved_target())
    world.app.state.llm_provider = Down()
    assert world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/run").status_code == 202
    stored = world["viewer"].get(f"/api/v1/assessments/{assessment['id']}").json()
    assert stored["status"] == "failed"
    failed = [r for r in stored["agent_runs"] if r["status"] == "failed"]
    assert failed and "LLMProviderError" in failed[0]["error"]
    assert world["viewer"].get(f"/api/v1/findings?assessment_id={assessment['id']}").json() == []


# --- status endpoint ------------------------------------------------------------------


def test_status_endpoint_never_leaks_secrets(lab: int) -> None:
    settings = _settings(
        llm_enabled=True,
        llm_provider="openai",
        llm_model="some-model",
        llm_api_key=SecretStr("sk-super-secret-key-123"),
        llm_base_url="https://llm.example.test/v1/token-in-url-abc",
    )
    world = World(settings, lab)
    response = world["viewer"].get("/api/v1/system/status")
    body = response.text
    assert response.status_code == 200
    for secret in (
        "sk-super-secret-key-123",
        "token-in-url-abc",
        settings.secret_key.get_secret_value(),
    ):
        assert secret not in body
    assert response.json()["llm"] == {"enabled": True, "provider": "openai", "model": "some-model"}
    assert set(response.json()) == {
        "environment",
        "llm",
        "allow_private_targets",
        "allow_self_approval",
        "session_ttl_minutes",
    }


# --- reports preserve the authorized scope ---------------------------------------------


def test_reports_preserve_scope_ports_in_json_and_markdown(world: World) -> None:
    rules = [
        {"rule_type": "domain", "pattern": "localhost", "ports": "8000-8100,9443"},
        {"rule_type": "domain", "pattern": "web.localhost"},  # include, no ports -> 80/443 default
        {"rule_type": "domain", "pattern": "admin.localhost", "is_exclusion": True},  # all ports
        {"rule_type": "domain", "pattern": "db.localhost", "is_exclusion": True, "ports": "5432"},
    ]
    target = world.approved_target(rules, entry=False)
    assessment = world.assessment(target)
    report = world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/reports", json={})
    assert report.status_code == 201
    data = report.json()

    by_pattern = {r["pattern"]: r for r in data["content_json"]["scope"]["scope_rules"]}
    assert by_pattern["localhost"]["ports"] == "8000-8100,9443"
    assert by_pattern["web.localhost"]["ports"] is None
    assert not by_pattern["web.localhost"]["is_exclusion"]
    assert by_pattern["admin.localhost"]["ports"] is None
    assert by_pattern["admin.localhost"]["is_exclusion"]
    assert by_pattern["db.localhost"]["ports"] == "5432"

    lines = [
        line
        for line in data["content_markdown"].splitlines()
        if line.startswith(("- include", "- exclude"))
    ]

    def line_for(host: str) -> str:
        return next(
            line
            for line in lines
            if f"`{host}`" in line or f"`{host.replace('.', chr(92) + '.')}`" in line
        )

    assert "8000" in line_for("localhost") and "9443" in line_for("localhost")
    assert "80, 443" in line_for("web.localhost") and "default" in line_for("web.localhost")
    assert line_for("admin.localhost").startswith("- exclude") and "all ports" in line_for(
        "admin.localhost"
    )
    assert "5432" in line_for("db.localhost")

    # The stored report reads back identically (consistent persisted state).
    stored = world["viewer"].get(f"/api/v1/reports/{data['id']}").json()
    assert stored["content_json"]["scope"] == data["content_json"]["scope"]


# --- audit trail ------------------------------------------------------------------------


def test_security_sensitive_operations_are_audited(world: World) -> None:
    target = world.approved_target()
    assessment = world.assessment(target)
    world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/run")
    world["analyst"].post(f"/api/v1/assessments/{assessment['id']}/reports", json={})
    world["viewer"].post(f"/api/v1/assessments/{assessment['id']}/run")  # denied
    # self-approval is refused and audited
    name = f"t-{uuid.uuid4().hex[:8]}"
    mine = world["admin"].post("/api/v1/targets", json={"name": name, "type": "web"}).json()
    now = datetime.now(UTC)
    world["admin"].post(
        f"/api/v1/targets/{mine['id']}/authorizations",
        json={
            "scope_rules": [{"rule_type": "domain", "pattern": "localhost"}],
            "attestation": "x",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    )
    denied = world["admin"].post(f"/api/v1/targets/{mine['id']}/authorizations/1/approve")
    assert denied.status_code == 403

    entries = world["admin"].get("/api/v1/audit-log?limit=500").json()
    seen = {(e["action"], e["outcome"], e["actor_username"]) for e in entries}
    analyst, viewer, admin = (world.names[r] for r in ("analyst", "viewer", "admin"))
    for expected in (
        ("target.create", "success", analyst),
        ("authorization.submit", "success", analyst),
        ("authorization.approve", "success", admin),
        ("assessment.create", "success", analyst),
        ("pipeline.run", "success", analyst),
        ("report.generate", "success", analyst),
        ("authz.denied", "denied", viewer),
        ("authorization.approve", "denied", admin),
    ):
        assert expected in seen, expected
    # no credentials or tokens are ever written to the log
    blob = str(entries)
    assert TEST_PASSWORD not in blob
    for client in world.clients.values():
        assert client.headers["X-CSRF-Token"] not in blob


# --- dashboard static mount ---------------------------------------------------------------


def test_dashboard_is_served_when_a_build_exists(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<html>dashboard-shell</html>", encoding="utf-8")
    (tmp_path / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    client = TestClient(create_app(_settings().model_copy(update={"dashboard_dir": str(tmp_path)})))

    assert "dashboard-shell" in client.get("/dashboard/").text
    assert "dashboard-shell" in client.get("/dashboard/targets/abc").text  # SPA deep link / reload
    assert client.get("/dashboard/assets/app.js").text == "console.log(1)"
    assert client.get("/dashboard/assets/missing.js").status_code == 404
    redirect = client.get("/", follow_redirects=False)
    assert redirect.status_code in (302, 307) and redirect.headers["location"] == "/dashboard/"
    # The API is unaffected: unknown API paths are still JSON problems, data still needs a login.
    missing = client.get("/api/v1/does-not-exist")
    assert missing.status_code == 404 and "json" in missing.headers["content-type"]
    assert client.get("/api/v1/targets").status_code == 401


def test_backend_runs_normally_without_a_dashboard_build() -> None:
    client = TestClient(create_app(_settings()))
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/dashboard/").status_code == 404
    assert client.get("/", follow_redirects=False).status_code == 404
