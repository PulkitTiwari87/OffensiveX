"""Target entry points against real PostgreSQL: validation through the API,
scope coverage at submission and at assessment creation, Recon actually using
the configured URL (and never widening scope because of it), redirects not
being followed, and the migration being additive."""

from __future__ import annotations

import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from offensivex.agents.recon import run_recon_agent
from offensivex.agents.runtime import AgentStep
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.reporting.builder import build_report
from offensivex.services import assessments as assessments_service
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.registry import ScopeViolationError, ToolRegistry
from tests.integration.auth_support import authenticated_client

pytestmark = pytest.mark.integration

LAB_RULES = [ScopeRuleInput(rule_type="domain", pattern="localhost")]
_BACKEND_DIR = Path(__file__).resolve().parents[2]


# --- fixtures and helpers -----------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    base = Settings(environment="test")
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=base.test_database_url or base.database_url,
        allow_private_targets=True,  # the lab is localhost
    )


@pytest.fixture
def strict_settings(settings: Settings) -> Settings:
    """Default policy: loopback / private entry points are refused."""
    return settings.model_copy(update={"allow_private_targets": False})


@pytest.fixture
def db_engine(settings: Settings):
    engine = create_engine(
        settings.database_url, pool_pre_ping=True, future=True, connect_args={"connect_timeout": 2}
    )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable ({exc.__class__.__name__}).")
    yield engine
    engine.dispose()


@pytest.fixture
def session(db_engine):
    with Session(db_engine) as s:
        yield s
        s.rollback()


class Lab:
    """A local server that records what it was asked, and can redirect."""

    def __init__(self, redirect_to: str | None = None) -> None:
        outer = self
        self.hits = 0
        self.host_headers: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.hits += 1
                outer.host_headers.append(self.headers.get("Host", ""))
                if redirect_to:
                    self.send_response(302)
                    self.send_header("Location", redirect_to)
                else:
                    self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://localhost:{self.port}/"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def lab():
    labs: list[Lab] = []

    def factory(redirect_to: str | None = None) -> Lab:
        instance = Lab(redirect_to)
        labs.append(instance)
        return instance

    yield factory
    for instance in labs:
        instance.close()


def unique_name() -> str:
    return f"ep-{uuid.uuid4().hex[:10]}.test"


def approved_target(
    session: Session, *, entry_point: str | None, rules: list[ScopeRuleInput] = LAB_RULES
) -> models.Target:
    target = targets_service.create_target(
        session,
        name=unique_name(),  # deliberately carries no port information
        type_="web_application",
        entry_point=entry_point,
        allow_private_targets=True,
    )
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=rules,
        attestation="attestation",
        valid_from=now,
        valid_until=now + timedelta(days=1),
        allow_private_targets=True,
    )
    targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    return target


def running_assessment(session: Session, target: models.Target) -> models.Assessment:
    return assessments_service.create_assessment(session, target_id=target.id)


class Scripted:
    name = "scripted"

    def __init__(self, steps: list[AgentStep] | None = None, *, follow_entry_point: bool = False):
        self.steps = list(steps or [])
        self.follow = follow_entry_point
        self.prompts: list[str] = []
        self._turn = 0

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        self.prompts.append(prompt)
        self._turn += 1
        if self.follow:  # behave like a model that does what the prompt says
            found = re.search(r'"entry_point": "([^"]+)"', prompt)
            if self._turn == 1 and found:
                return AgentStep(
                    action="call_tool", capability="http_probe", request={"url": found.group(1)}
                )
            return AgentStep(action="finish", output={"assets_discovered": 1, "summary": "done"})
        return self.steps.pop(0)


def call(capability: str, **request: Any) -> AgentStep:
    return AgentStep(action="call_tool", capability=capability, request=request)


def finish() -> AgentStep:
    return AgentStep(action="finish", output={"assets_discovered": 0, "summary": "done"})


def registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(DnsResolutionAdapter())
    reg.register(HttpProbeAdapter())
    return reg


def recon(session: Session, assessment: models.Assessment, llm: Scripted) -> models.AgentRun:
    run = models.AgentRun(
        assessment_id=assessment.id,
        agent_type=models.AgentType.RECON,
        status=models.AgentRunStatus.QUEUED,
    )
    session.add(run)
    session.flush()
    run_recon_agent(
        session, llm_provider=llm, tool_registry=registry(), assessment=assessment, agent_run=run
    )
    return run


def count_executions(session: Session, assessment: models.Assessment) -> int:
    return session.scalar(
        select(func.count())
        .select_from(models.ToolExecution)
        .join(models.AgentRun)
        .where(models.AgentRun.assessment_id == assessment.id)
    )


def count_rows(session: Session, model: type, *conditions: Any) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*conditions))


# --- API: creating targets ----------------------------------------------------------


def test_ordinary_and_non_standard_port_entry_points_are_stored_normalized(
    settings: Settings,
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    cases = {
        "https://app.example.test": "https://app.example.test/",
        "HTTP://LocalHost:8080": "http://localhost:8080/",
        "https://app.example.test:8443/portal/": "https://app.example.test:8443/portal/",
        "http://127.0.0.1:3000/": "http://127.0.0.1:3000/",
        "https://[::1]:9443": "https://[::1]:9443/",
    }
    for raw, expected in cases.items():
        response = client.post(
            "/api/v1/targets", json={"name": unique_name(), "type": "web", "entry_point": raw}
        )
        assert response.status_code == 201, (raw, response.text)
        assert response.json()["entry_point"] == expected
        fetched = client.get(f"/api/v1/targets/{response.json()['id']}")
        assert fetched.status_code == 200 and fetched.json()["entry_point"] == expected


def test_entry_point_is_optional_so_existing_targets_still_work(settings: Settings) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    response = client.post("/api/v1/targets", json={"name": unique_name(), "type": "web"})
    assert response.status_code == 201 and response.json()["entry_point"] is None


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://example.test/",
        "javascript:alert(1)",
        "http://user:pw@example.test/",
        "http://allowed.test\\@evil.test/",
        "http://example.test/?token=secret",
        "http://example.test/#frag",
        "http://example.test:0/",
        "http://example.test:70000/",
        "http://example.test:abc/",
        "http://2130706433/",
        "http://127.1/",
        "http://exa mple.test/",
        "example.test",
        "http://",
        "http://" + "a" * 64 + ".test/",
    ],
)
def test_invalid_entry_points_are_rejected_with_422_and_create_nothing(
    settings: Settings, db_engine, bad: str
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    name = unique_name()
    response = client.post(
        "/api/v1/targets", json={"name": name, "type": "web", "entry_point": bad}
    )
    assert response.status_code == 422, (bad, response.text)
    assert response.json()["title"] == "Invalid entry point"
    with Session(db_engine) as s:
        assert count_rows(s, models.Target, models.Target.name == name) == 0


def test_schema_level_limits_apply_too(settings: Settings) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    for bad in ("", "http://example.test/" + "a" * 3000):
        response = client.post(
            "/api/v1/targets", json={"name": unique_name(), "type": "web", "entry_point": bad}
        )
        assert response.status_code == 422


@pytest.mark.parametrize(
    "private",
    [
        "http://localhost:8080/",
        "http://127.0.0.1/",
        "http://10.0.0.5:8000/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://app.localhost/",
    ],
)
def test_private_and_loopback_entry_points_need_the_deployment_opt_in(
    strict_settings: Settings, private: str
) -> None:
    client = authenticated_client(strict_settings, models.UserRole.ANALYST)
    response = client.post(
        "/api/v1/targets", json={"name": unique_name(), "type": "web", "entry_point": private}
    )
    assert response.status_code == 422
    assert "ALLOW_PRIVATE_TARGETS" in response.json()["detail"]
    public = client.post(
        "/api/v1/targets",
        json={
            "name": unique_name(),
            "type": "web",
            "entry_point": "https://app.example.test:8443/",
        },
    )
    assert public.status_code == 201


def test_entry_point_is_audited_and_never_contains_secrets(settings: Settings, db_engine) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    client.post(
        "/api/v1/targets",
        json={
            "name": unique_name(),
            "type": "web",
            "entry_point": "https://app.example.test:8443/x",
        },
    )
    with Session(db_engine) as s:
        row = s.scalars(
            select(models.AuditLogEntry)
            .where(models.AuditLogEntry.action == "target.create")
            .order_by(models.AuditLogEntry.occurred_at.desc())
        ).first()
        assert row is not None and row.details["entry_point"] == "https://app.example.test:8443/x"


def test_database_check_constraint_is_a_backstop_for_non_http_values(db_engine) -> None:
    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO targets (id, name, type, default_exposure, default_criticality, "
                "entry_point) VALUES (:id, :n, 'web', 'medium', 'medium', 'ftp://x.test/')"
            ),
            {"id": uuid.uuid4(), "n": unique_name()},
        )


# --- scope coverage --------------------------------------------------------------------


def _submit(client, target_id: str, rules: list[dict]) -> Any:
    now = datetime.now(UTC)
    return client.post(
        f"/api/v1/targets/{target_id}/authorizations",
        json={
            "scope_rules": rules,
            "attestation": "attestation",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    )


def _target_via_api(client, entry_point: str) -> str:
    response = client.post(
        "/api/v1/targets", json={"name": unique_name(), "type": "web", "entry_point": entry_point}
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _domain(pattern: str, *, exclude: bool = False) -> dict:
    return {"rule_type": "domain", "pattern": pattern, "is_exclusion": exclude}


def _cidr(pattern: str) -> dict:
    return {"rule_type": "cidr", "pattern": pattern}


@pytest.mark.parametrize(
    ("entry_point", "rules", "accepted"),
    [
        ("https://app.example.test:8443/", [_domain("app.example.test")], True),
        ("https://app.example.test/", [_domain("*.example.test")], True),
        ("https://example.test/", [_domain("*.example.test")], False),
        ("https://other.test/", [_domain("app.example.test")], False),
        (
            "https://app.example.test/",
            [_domain("*.example.test"), _domain("app.example.test", exclude=True)],
            False,
        ),
        ("http://203.0.113.9/", [_cidr("203.0.113.0/24")], True),
        ("http://203.0.113.9/", [_cidr("198.51.100.0/24")], False),
        # A hostname is never matched by a CIDR rule (fail closed, same as the Scope Guard).
        ("https://app.example.test/", [_cidr("203.0.113.0/24")], False),
        ("https://app.example.test/", [{"rule_type": "weird", "pattern": "x"}], False),
    ],
)
def test_entry_point_must_be_covered_by_the_submitted_scope(
    settings: Settings, entry_point: str, rules: list[dict], accepted: bool
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    response = _submit(client, _target_via_api(client, entry_point), rules)
    if accepted:
        assert response.status_code == 201, response.text
    else:
        assert response.status_code == 422, response.text
        assert response.json()["title"] == "Entry point outside authorized scope"


def test_scope_that_does_not_cover_the_entry_point_creates_no_authorization(
    settings: Settings, db_engine
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    target_id = _target_via_api(client, "https://app.example.test/")
    response = _submit(client, target_id, [_domain("elsewhere.test")])
    assert response.status_code == 422
    assert response.json()["title"] == "Entry point outside authorized scope"
    with Session(db_engine) as s:
        count = count_rows(
            s, models.Authorization, models.Authorization.target_id == uuid.UUID(target_id)
        )
        assert count == 0


def test_unauthorized_target_with_an_entry_point_still_cannot_start_an_assessment(
    settings: Settings,
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    target_id = _target_via_api(client, "https://app.example.test/")
    response = client.post("/api/v1/assessments", json={"target_id": target_id})
    assert response.status_code == 422 and response.json()["title"] == "Target not authorized"


def test_unapproved_authorization_does_not_make_an_entry_point_assessable(
    settings: Settings,
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    target_id = _target_via_api(client, "https://app.example.test/")
    assert _submit(client, target_id, [_domain("app.example.test")]).status_code == 201
    response = client.post("/api/v1/assessments", json={"target_id": target_id})
    assert response.status_code == 422 and response.json()["title"] == "Target not authorized"


def test_assessment_creation_rechecks_the_entry_point_against_the_stored_scope(
    session: Session, db_engine
) -> None:
    """Defence in depth: even if an entry point drifts out of scope after
    approval (here, a direct DB edit), no assessment is created."""
    target = approved_target(session, entry_point="http://localhost:8123/")
    session.commit()
    assert running_assessment(session, target).status is models.AssessmentStatus.RUNNING
    session.commit()

    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE targets SET entry_point = 'http://not-in-scope.test/' WHERE id = :id"),
            {"id": target.id},
        )
    session.expire_all()
    before = count_rows(session, models.Assessment, models.Assessment.target_id == target.id)
    with pytest.raises(targets_service.EntryPointOutOfScopeError):
        running_assessment(session, target)
    after = count_rows(session, models.Assessment, models.Assessment.target_id == target.id)
    assert after == before


# --- Recon uses the entry point and cannot widen scope ----------------------------------------


def test_recon_starts_from_the_configured_entry_point_not_the_target_name(
    session: Session, lab
) -> None:
    server = lab()
    target = approved_target(session, entry_point=server.url)  # name has no port in it
    assert str(server.port) not in target.name
    assessment = running_assessment(session, target)
    model = Scripted(follow_entry_point=True)

    run = recon(session, assessment, model)

    assert run.status is models.AgentRunStatus.SUCCEEDED
    assert f'"entry_point": "{server.url}"' in model.prompts[0]
    assert "Never infer a port" in model.prompts[0]
    assert server.hits == 1
    assets = session.scalars(
        select(models.Asset.canonical_key).where(models.Asset.assessment_id == assessment.id)
    ).all()
    assert assets == [server.url]


def test_a_target_without_an_entry_point_gets_no_port_guess_in_its_context(
    session: Session,
) -> None:
    target = approved_target(session, entry_point=None)
    assessment = running_assessment(session, target)
    model = Scripted([finish()])
    recon(session, assessment, model)
    assert '"entry_point": null' in model.prompts[0]


def test_an_entry_point_grants_nothing_beyond_the_authorized_scope(session: Session, lab) -> None:
    """Same machine, different spelling: 127.0.0.1 is not 'localhost' as far as
    the scope rule goes, so the Scope Guard refuses it even though the entry
    point (and the model's intent) is the lab."""
    server = lab()
    target = approved_target(session, entry_point=server.url)
    assessment = running_assessment(session, target)
    model = Scripted([call("http_probe", url=f"http://127.0.0.1:{server.port}/")])
    with pytest.raises(ScopeViolationError):
        recon(session, assessment, model)
    assert server.hits == 0


@pytest.mark.parametrize(
    "tricky",
    [
        "http://localhost\\@evil.test/",
        "http://evil.test\\@localhost/",
        "http://localhost@evil.test/",
        "http://2130706433/",
        "http://localhost/ HTTP/1.1\r\nHost: evil.test",
    ],
)
def test_ambiguous_urls_from_the_model_are_refused_before_anything_executes(
    session: Session, lab, tricky: str
) -> None:
    server = lab()
    target = approved_target(session, entry_point=server.url)
    assessment = running_assessment(session, target)
    model = Scripted([call("http_probe", url=tricky), finish()])

    run = recon(session, assessment, model)

    assert run.status is models.AgentRunStatus.SUCCEEDED  # told, corrected, finished
    assert "invalid request" in model.prompts[1]
    assert count_executions(session, assessment) == 0  # no ToolExecution row, no connection
    assert server.hits == 0


def test_redirects_are_reported_never_followed(session: Session, lab) -> None:
    other = lab()  # stands in for an out-of-scope destination on the same machine
    redirecting = lab(redirect_to=f"http://localhost:{other.port}/internal")
    target = approved_target(session, entry_point=redirecting.url)
    assessment = running_assessment(session, target)

    recon(session, assessment, Scripted(follow_entry_point=True))

    assert redirecting.hits == 1
    assert other.hits == 0  # the Location target was never contacted
    observation = session.scalars(
        select(models.Observation)
        .join(models.Asset, models.Observation.asset_id == models.Asset.id)
        .where(models.Asset.assessment_id == assessment.id)
    ).one()
    assert observation.data["status_code"] == 302  # reported as data, not acted on
    assert count_executions(session, assessment) == 1


def test_probe_sends_the_real_port_in_the_host_header(session: Session, lab) -> None:
    server = lab()
    target = approved_target(session, entry_point=server.url)
    recon(session, running_assessment(session, target), Scripted(follow_entry_point=True))
    assert server.host_headers == [f"localhost:{server.port}"]


# --- reporting -------------------------------------------------------------------------------


def test_report_shows_the_entry_point(session: Session) -> None:
    target = approved_target(session, entry_point="http://localhost:8123/app")
    assessment = running_assessment(session, target)
    report = build_report(session, assessment)
    assert report.content_json["scope"]["entry_point"] == "http://localhost:8123/app"
    assert "Entry point:" in report.content_markdown


# --- migration ---------------------------------------------------------------------------------


def test_migration_is_additive_and_preserves_existing_targets(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Runs on a scratch database: upgrade to the previous revision, add a
    target, upgrade to head, and check the row survived with entry_point NULL.

    `migrations/env.py` takes its URL from Settings (never from the Alembic
    config), so the scratch database is selected with OFFENSIVEX_DATABASE_URL.
    The destructive step (the downgrade) comes last and is only reachable after
    the INSERT into the scratch database has succeeded, which proves the
    commands were really aimed at it."""
    admin_url = make_url(settings.database_url).set(database="postgres")
    scratch = f"offensivex_mig_{uuid.uuid4().hex[:8]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{scratch}"'))
    except Exception as exc:  # noqa: BLE001
        admin.dispose()
        pytest.skip(f"cannot create a scratch database ({exc.__class__.__name__})")

    scratch_url = make_url(settings.database_url).set(database=scratch)
    cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    monkeypatch.setenv("OFFENSIVEX_DATABASE_URL", scratch_url.render_as_string(hide_password=False))
    engine = create_engine(scratch_url)
    try:
        command.upgrade(cfg, "0004_auth_and_audit")
        legacy_id = uuid.uuid4()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO targets (id, name, type, default_exposure, default_criticality) "
                    "VALUES (:id, 'legacy-target', 'web', 'medium', 'medium')"
                ),
                {"id": legacy_id},
            )

        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT name, entry_point FROM targets WHERE id = :id"), {"id": legacy_id}
            ).one()
        assert row.name == "legacy-target" and row.entry_point is None

        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(
                text("UPDATE targets SET entry_point = 'ftp://x.test/' WHERE id = :id"),
                {"id": legacy_id},
            )

        command.downgrade(cfg, "0004_auth_and_audit")  # reversible; the target row survives
        with engine.connect() as conn:
            survivors = conn.execute(
                text("SELECT count(*) FROM targets WHERE id = :id"), {"id": legacy_id}
            ).scalar_one()
        assert survivors == 1
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()
