"""Integration tests for ADR-024: explicit port scope and connection-time network
policy, enforced by the real Tool Registry against a real PostgreSQL.

Everything that connects goes to a loopback server this file starts itself, or to a
fake that records the attempt; nothing contacts a third-party system.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.services import assessments as assessments_service
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput, ScopeValidationError
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.adapters.security_header_scan import SecurityHeaderScanAdapter
from offensivex.tools.adapters.security_header_validation import SecurityHeaderValidationCheck
from offensivex.tools.registry import ScopeViolationError, ToolRegistry
from offensivex.tools.scope_guard import check_destination
from tests.integration.auth_support import authenticated_client

pytestmark = pytest.mark.integration

_BACKEND_DIR = Path(__file__).resolve().parents[2]
PUBLIC = "93.184.216.34"


# --- fixtures and helpers ----------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    base = Settings(environment="test")
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=base.test_database_url or base.database_url,
    )


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
    """A loopback server that counts requests and can redirect."""

    def __init__(self, redirect_to: str | None = None) -> None:
        outer = self
        self.hits = 0

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib-mandated name
                outer.hits += 1
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

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def lab():
    started: list[Lab] = []

    def factory(redirect_to: str | None = None) -> Lab:
        instance = Lab(redirect_to)
        started.append(instance)
        return instance

    yield factory
    for instance in started:
        instance.close()


def unique_name() -> str:
    return f"net-{uuid.uuid4().hex[:10]}.test"


def assessment_with(
    session: Session,
    rules: list[ScopeRuleInput],
    *,
    entry_point: str | None = None,
    validation: bool = False,
) -> models.Assessment:
    target = targets_service.create_target(
        session,
        name=unique_name(),
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
    return assessments_service.create_assessment(
        session, target_id=target.id, validation_enabled=validation
    )


class FakeDns:
    def __init__(self, *addresses: str) -> None:
        self._addresses = list(addresses)
        self.lookups: list[str] = []

    def __call__(self, hostname: str) -> list[str]:
        self.lookups.append(hostname)
        return list(self._addresses)


class NoConnect:
    """A connector that fails the test if anything tries to connect."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def __call__(self, address: tuple[str, int], timeout: float) -> Any:
        self.calls.append(address)
        raise AssertionError(f"unexpected connection to {address}")


def registry_for(*adapters: Any, allow_private: bool = False) -> ToolRegistry:
    reg = ToolRegistry(allow_private_targets=allow_private)
    for adapter in adapters:
        reg.register(adapter)
    return reg


def probe(
    session: Session,
    reg: ToolRegistry,
    assessment: models.Assessment,
    url: str,
    capability: str = "http_probe",
) -> Any:
    return reg.execute(session, capability=capability, request={"url": url}, assessment=assessment)


def last_execution(session: Session) -> models.ToolExecution:
    row = session.scalars(
        select(models.ToolExecution).order_by(models.ToolExecution.created_at.desc())
    ).first()
    assert row is not None
    return row


# --- port scope through the registry ----------------------------------------------------------


def test_host_only_rule_authorizes_default_ports_but_not_other_ports(session: Session) -> None:
    assessment = assessment_with(session, [ScopeRuleInput("domain", "app.example.test")])
    connector = NoConnect()
    reg = registry_for(HttpProbeAdapter(FakeDns(PUBLIC), connector=connector))

    with pytest.raises(ScopeViolationError, match="this port is not"):
        probe(session, reg, assessment, "https://app.example.test:8443/")
    with pytest.raises(ScopeViolationError, match="this port is not"):
        probe(session, reg, assessment, "http://app.example.test:8080/")
    assert connector.calls == []  # refused before anything resolved or connected


def test_denied_probe_is_audited_with_host_and_port(session: Session) -> None:
    assessment = assessment_with(session, [ScopeRuleInput("domain", "app.example.test")])
    reg = registry_for(HttpProbeAdapter(FakeDns(PUBLIC), connector=NoConnect()))
    with pytest.raises(ScopeViolationError):
        probe(session, reg, assessment, "http://app.example.test:8080/x")
    row = last_execution(session)
    assert row.scope_decision is models.ScopeDecision.DENIED
    assert row.status is models.ToolExecutionStatus.DENIED
    assert row.argv["destinations"] == ["app.example.test"] and row.argv["ports"] == [8080]


def test_default_port_probe_passes_the_scope_step_for_a_host_only_rule(session: Session) -> None:
    assessment = assessment_with(session, [ScopeRuleInput("domain", "app.example.test")])
    dns = FakeDns("203.0.113.1")  # a non-global range -> refused later, at connect time
    reg = registry_for(HttpProbeAdapter(dns, connector=NoConnect()))
    # The refusal below is the *address* policy: it proves the port/host scope step passed.
    with pytest.raises(ScopeViolationError, match="resolves to 203.0.113.1"):
        probe(session, reg, assessment, "https://app.example.test/")
    assert dns.lookups == ["app.example.test"]


def test_explicit_ports_are_enforced_for_every_http_capability(session: Session, lab) -> None:
    allowed, other = lab(), lab()
    assessment = assessment_with(
        session,
        [ScopeRuleInput("domain", "localhost", ports=str(allowed.port))],
        validation=True,
    )
    reg = registry_for(
        HttpProbeAdapter(),
        SecurityHeaderScanAdapter(),
        SecurityHeaderValidationCheck(),
        allow_private=True,
    )
    # the allowed port works for http_probe and security_header_scan:
    for capability in ("http_probe", "security_header_scan"):
        result = probe(session, reg, assessment, f"http://localhost:{allowed.port}/", capability)
        assert result.data["status_code"] == 200
    # the same host on any other port is refused for all three capabilities:
    for capability in ("http_probe", "security_header_scan", "security_header_validation_check"):
        request: dict[str, Any] = {"url": f"http://localhost:{other.port}/"}
        if capability == "security_header_validation_check":
            request["header"] = "X-Frame-Options"
        with pytest.raises(ScopeViolationError):
            reg.execute(session, capability=capability, request=request, assessment=assessment)
    assert other.hits == 0


def test_port_limited_exclusion_wins_over_a_wide_include(session: Session, lab) -> None:
    open_lab, blocked = lab(), lab()
    assessment = assessment_with(
        session,
        [
            ScopeRuleInput("domain", "localhost", ports="1024-65535"),
            ScopeRuleInput("domain", "localhost", is_exclusion=True, ports=str(blocked.port)),
        ],
    )
    reg = registry_for(HttpProbeAdapter(), allow_private=True)
    assert probe(session, reg, assessment, f"http://localhost:{open_lab.port}/").data
    with pytest.raises(ScopeViolationError, match="exclude rule"):
        probe(session, reg, assessment, f"http://localhost:{blocked.port}/")
    assert blocked.hits == 0


def test_dns_resolution_is_a_host_only_check(session: Session) -> None:
    assessment = assessment_with(
        session, [ScopeRuleInput("domain", "app.example.test", ports="8443")]
    )
    reg = registry_for(DnsResolutionAdapter(lambda host: [PUBLIC]))
    result = reg.execute(
        session,
        capability="dns_resolution",
        request={"hostname": "app.example.test"},
        assessment=assessment,
    )
    assert result.data["addresses"] == [PUBLIC]
    with pytest.raises(ScopeViolationError):
        reg.execute(
            session,
            capability="dns_resolution",
            request={"hostname": "other.example.test"},
            assessment=assessment,
        )


# --- connection-time address policy through the registry -------------------------------------


@pytest.mark.parametrize(
    "answer", [["169.254.169.254"], ["10.0.0.5"], ["127.0.0.1"], [PUBLIC, "10.0.0.5"]]
)
def test_hostname_resolving_to_a_forbidden_address_is_denied_and_recorded(
    session: Session, answer: list[str]
) -> None:
    assessment = assessment_with(session, [ScopeRuleInput("domain", "app.example.test")])
    reg = registry_for(HttpProbeAdapter(FakeDns(*answer), connector=NoConnect()))
    with pytest.raises(ScopeViolationError):
        probe(session, reg, assessment, "http://app.example.test/")
    row = last_execution(session)
    assert row.scope_decision is models.ScopeDecision.DENIED
    assert row.status is models.ToolExecutionStatus.DENIED


def test_private_targets_stay_denied_unless_the_deployment_opts_in(session: Session, lab) -> None:
    server = lab()
    assessment = assessment_with(
        session, [ScopeRuleInput("domain", "localhost", ports=str(server.port))]
    )
    url = f"http://localhost:{server.port}/"
    with pytest.raises(ScopeViolationError, match="ALLOW_PRIVATE_TARGETS"):
        probe(session, registry_for(HttpProbeAdapter()), assessment, url)  # default: deny
    assert server.hits == 0
    ok = probe(session, registry_for(HttpProbeAdapter(), allow_private=True), assessment, url)
    assert ok.data["status_code"] == 200 and server.hits == 1  # existing local-lab flow works


def test_lab_hostname_pointing_at_loopback_needs_an_explicit_cidr_rule(
    session: Session, lab
) -> None:
    server = lab()
    domain_only = assessment_with(
        session, [ScopeRuleInput("domain", "lab.example.test", ports=str(server.port))]
    )
    reg = registry_for(HttpProbeAdapter(FakeDns("127.0.0.1")), allow_private=True)
    url = f"http://lab.example.test:{server.port}/"
    with pytest.raises(ScopeViolationError, match="does not explicitly cover"):
        probe(session, reg, domain_only, url)
    with_cidr = assessment_with(
        session,
        [
            ScopeRuleInput("domain", "lab.example.test", ports=str(server.port)),
            ScopeRuleInput("cidr", "127.0.0.0/8", ports=str(server.port)),
        ],
    )
    assert probe(session, reg, with_cidr, url).data["pinned_ip"] == "127.0.0.1"
    assert server.hits == 1


# --- redirects ----------------------------------------------------------------------


def test_redirect_to_an_unauthorized_port_is_reported_and_refused_as_a_new_request(
    session: Session, lab
) -> None:
    other = lab()
    first = lab(redirect_to=f"http://localhost:{other.port}/admin")
    assessment = assessment_with(
        session, [ScopeRuleInput("domain", "localhost", ports=str(first.port))]
    )
    reg = registry_for(HttpProbeAdapter(), allow_private=True)

    result = probe(session, reg, assessment, f"http://localhost:{first.port}/")
    assert result.data["status_code"] == 302
    location = result.data["headers"]["location"]
    assert other.hits == 0  # not followed
    with pytest.raises(ScopeViolationError):  # an agent re-requesting it is refused
        probe(session, reg, assessment, location)
    assert other.hits == 0


def test_redirect_to_an_unauthorized_host_is_reported_and_refused_as_a_new_request(
    session: Session, lab
) -> None:
    first = lab(redirect_to="http://evil.example.test/")
    assessment = assessment_with(
        session, [ScopeRuleInput("domain", "localhost", ports=str(first.port))]
    )
    reg = registry_for(HttpProbeAdapter(), allow_private=True)
    result = probe(session, reg, assessment, f"http://localhost:{first.port}/")
    assert result.data["headers"]["location"] == "http://evil.example.test/"
    with pytest.raises(ScopeViolationError):
        probe(session, reg, assessment, result.data["headers"]["location"])


# --- authorization API / service ----------------------------------------------------------------


def _submit(client: Any, target_id: str, rules: list[dict[str, Any]]) -> Any:
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


def _new_target(client: Any, entry_point: str | None = None) -> str:
    body: dict[str, Any] = {"name": unique_name(), "type": "web"}
    if entry_point:
        body["entry_point"] = entry_point
    response = client.post("/api/v1/targets", json=body)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _latest_audit(db_engine: Any, action: str) -> dict[str, Any]:
    with Session(db_engine) as s:
        row = s.scalars(
            select(models.AuditLogEntry)
            .where(models.AuditLogEntry.action == action)
            .order_by(models.AuditLogEntry.occurred_at.desc())
        ).first()
        assert row is not None
        return dict(row.details)


def test_ports_are_validated_normalized_and_stored(settings: Settings, db_engine) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    target_id = _new_target(client)
    response = _submit(
        client,
        target_id,
        [
            {
                "rule_type": "domain",
                "pattern": "app.example.test",
                "ports": "8443, 80,8000-8100,8050",
            },
            {"rule_type": "domain", "pattern": "legacy.example.test"},  # host-only form
        ],
    )
    assert response.status_code == 201, response.text
    with Session(db_engine) as s:
        stored = {
            r.pattern: r.ports
            for r in s.scalars(
                select(models.ScopeRule).where(
                    models.ScopeRule.authorization_id == uuid.UUID(response.json()["id"])
                )
            )
        }
    assert stored == {"app.example.test": "80,8000-8100,8443", "legacy.example.test": None}
    audit = _latest_audit(db_engine, "authorization.submit")
    assert audit["scope_rules"][0]["ports"] == "8443, 80,8000-8100,8050"  # as submitted


@pytest.mark.parametrize("bad", ["0", "70000", "80-", "abc", "443;80", "90-80", "1-65535", ""])
def test_invalid_ports_are_rejected_with_422_and_create_nothing(
    settings: Settings, db_engine, bad: str
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    target_id = _new_target(client)
    response = _submit(
        client, target_id, [{"rule_type": "domain", "pattern": "app.example.test", "ports": bad}]
    )
    assert response.status_code == 422, (bad, response.text)
    with Session(db_engine) as s:
        rows = s.scalars(
            select(models.Authorization).where(
                models.Authorization.target_id == uuid.UUID(target_id)
            )
        ).all()
        assert rows == []


def test_service_rejects_invalid_ports_before_writing_anything(session: Session) -> None:
    target = targets_service.create_target(session, name=unique_name(), type_="web")
    now = datetime.now(UTC)
    with pytest.raises(ScopeValidationError, match="invalid ports"):
        targets_service.submit_authorization(
            session,
            target_id=target.id,
            scope_rules=[ScopeRuleInput("domain", "app.example.test", ports="nope")],
            attestation="a",
            valid_from=now,
            valid_until=now + timedelta(days=1),
            allow_private_targets=False,
        )


def test_entry_point_port_must_be_covered_by_the_submitted_ports(settings: Settings) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    target_id = _new_target(client, "https://app.example.test:8443/")
    host_only = _submit(client, target_id, [{"rule_type": "domain", "pattern": "app.example.test"}])
    assert host_only.status_code == 422
    assert host_only.json()["title"] == "Entry point outside authorized scope"
    explicit = _submit(
        client,
        target_id,
        [{"rule_type": "domain", "pattern": "app.example.test", "ports": "8443"}],
    )
    assert explicit.status_code == 201, explicit.text


def test_legacy_host_only_authorization_with_a_non_default_entry_point_fails_closed(
    session: Session, db_engine
) -> None:
    """A target/authorization created before ADR-024 whose entry point is on a
    non-default port: nothing is silently widened — assessment creation is refused
    until a new authorization version lists the port."""
    assessment = assessment_with(session, [ScopeRuleInput("domain", "app.example.test")])
    session.commit()
    target = assessment.target
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE targets SET entry_point = 'https://app.example.test:8443/' WHERE id = :i"),
            {"i": target.id},
        )
    session.expire_all()
    with pytest.raises(targets_service.EntryPointOutOfScopeError, match="this port is not"):
        assessments_service.create_assessment(session, target_id=target.id)


# --- migration ----------------------------------------------------------------------


def test_migration_0006_is_additive_and_legacy_rules_keep_their_host_only_meaning(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scratch database: upgrade to 0005, insert a legacy target / approved
    authorization / include + exclude rules, upgrade to head, check nothing was lost or
    widened, then downgrade and check the rows survive.

    `migrations/env.py` takes its URL from Settings, so the scratch database is
    selected with OFFENSIVEX_DATABASE_URL; the INSERT must succeed against it before
    any destructive step (the downgrade) is reachable."""
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
        command.upgrade(cfg, "0005_target_entry_point")
        target_id, auth_id = uuid.uuid4(), uuid.uuid4()
        include_id, exclude_id = uuid.uuid4(), uuid.uuid4()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO targets (id, name, type, default_exposure, default_criticality, "
                    "entry_point) VALUES (:id, 'legacy', 'web', 'medium', 'medium', "
                    "'https://app.example.test:8443/')"
                ),
                {"id": target_id},
            )
            conn.execute(
                text(
                    "INSERT INTO authorizations (id, target_id, version, attestation, valid_from, "
                    "valid_until, status) VALUES (:id, :t, 1, 'legacy attestation', now(), "
                    "now() + interval '1 day', 'approved')"
                ),
                {"id": auth_id, "t": target_id},
            )
            for rule_id, pattern, excl in (
                (include_id, "*.example.test", False),
                (exclude_id, "admin.example.test", True),
            ):
                conn.execute(
                    text(
                        "INSERT INTO scope_rules (id, authorization_id, rule_type, pattern, "
                        "is_exclusion) VALUES (:id, :a, 'domain', :p, :e)"
                    ),
                    {"id": rule_id, "a": auth_id, "p": pattern, "e": excl},
                )

        command.upgrade(cfg, "head")

        with Session(engine) as s:
            rules = list(
                s.scalars(
                    select(models.ScopeRule).where(models.ScopeRule.authorization_id == auth_id)
                )
            )
            assert len(rules) == 2 and all(r.ports is None for r in rules)  # nothing rewritten
            # Legacy semantics, now explicit: include = 80/443 only; exclude = every port.
            assert check_destination("app.example.test", rules, 443).allowed is True
            assert check_destination("app.example.test", rules, 8443).allowed is False
            for port in (80, 443, 8443):
                assert check_destination("admin.example.test", rules, port).allowed is False
            authorization = s.get(models.Authorization, auth_id)
            assert authorization is not None and authorization.status.value == "approved"

        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(
                text("UPDATE scope_rules SET ports = 'not-a-port-list' WHERE id = :id"),
                {"id": include_id},
            )
        with engine.begin() as conn:  # a well-formed list is accepted
            conn.execute(
                text("UPDATE scope_rules SET ports = '8443,9000-9010' WHERE id = :id"),
                {"id": include_id},
            )

        command.downgrade(cfg, "0005_target_entry_point")  # reversible; rows survive
        with engine.connect() as conn:
            survivors = conn.execute(
                text("SELECT count(*) FROM scope_rules WHERE authorization_id = :a"), {"a": auth_id}
            ).scalar_one()
        assert survivors == 2
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()
