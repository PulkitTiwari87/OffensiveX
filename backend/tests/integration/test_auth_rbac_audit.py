"""Authentication, RBAC and audit logging against real PostgreSQL.

What this proves: valid/invalid/expired/revoked credentials behave correctly,
CSRF is enforced, every route is classified and enforced by role (and any new
unclassified route fails the inventory test), sensitive actions leave audit
rows with an actor and request id and no secrets, the audit table is
append-only at the database level, and the self-approval rule holds.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from offensivex import admin
from offensivex.auth import sessions
from offensivex.auth.permissions import Permission, has_permission
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.main import create_app
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.services import users as users_service
from tests.integration.auth_support import (
    TEST_PASSWORD,
    authenticated_client,
    create_user,
    login,
)

pytestmark = pytest.mark.integration

UID = "00000000-0000-0000-0000-000000000001"
ROLES = (models.UserRole.VIEWER, models.UserRole.ANALYST, models.UserRole.ADMIN)

# (method, route path, required permission, request body). Bodies are
# deliberately invalid or point at ids that do not exist, so a role that IS
# allowed gets 404/422 — never a state change — while a role that is not
# allowed must get 403.
MATRIX: list[tuple[str, str, Permission, dict | None]] = [
    ("POST", "/api/v1/targets", Permission.TARGETS_WRITE, {}),
    ("GET", "/api/v1/targets/{target_id}", Permission.DATA_READ, None),
    ("POST", "/api/v1/targets/{target_id}/authorizations", Permission.TARGETS_WRITE, {}),
    (
        "POST",
        "/api/v1/targets/{target_id}/authorizations/{version}/approve",
        Permission.AUTHORIZATIONS_DECIDE,
        None,
    ),
    (
        "POST",
        "/api/v1/targets/{target_id}/authorizations/{version}/reject",
        Permission.AUTHORIZATIONS_DECIDE,
        None,
    ),
    ("POST", "/api/v1/assessments", Permission.ASSESSMENTS_WRITE, {"target_id": UID}),
    ("GET", "/api/v1/assessments/{assessment_id}", Permission.DATA_READ, None),
    ("POST", "/api/v1/assessments/{assessment_id}/cancel", Permission.ASSESSMENTS_WRITE, None),
    ("GET", "/api/v1/assessments/{assessment_id}/assets", Permission.DATA_READ, None),
    ("GET", "/api/v1/assessments/{assessment_id}/findings", Permission.DATA_READ, None),
    ("GET", "/api/v1/assessments/{assessment_id}/attack-paths", Permission.DATA_READ, None),
    ("GET", "/api/v1/findings/{finding_id}", Permission.DATA_READ, None),
    ("GET", "/api/v1/findings/{finding_id}/ml-advisory", Permission.DATA_READ, None),
    (
        "PATCH",
        "/api/v1/findings/{finding_id}/status",
        Permission.FINDINGS_OVERRIDE,
        {"status": "confirmed"},
    ),
    ("POST", "/api/v1/assessments/{assessment_id}/reports", Permission.REPORTS_GENERATE, None),
    ("GET", "/api/v1/reports/{report_id}", Permission.DATA_READ, None),
    ("POST", "/api/v1/users", Permission.USERS_MANAGE, {}),
    ("GET", "/api/v1/users", Permission.USERS_MANAGE, None),
    ("PATCH", "/api/v1/users/{user_id}", Permission.USERS_MANAGE, {"is_active": True}),
    ("GET", "/api/v1/audit-log", Permission.AUDIT_READ, None),
    ("GET", "/api/v1/targets", Permission.DATA_READ, None),
    ("GET", "/api/v1/targets/{target_id}/authorizations", Permission.DATA_READ, None),
    ("GET", "/api/v1/assessments", Permission.DATA_READ, None),
    ("POST", "/api/v1/assessments/{assessment_id}/run", Permission.ASSESSMENTS_WRITE, None),
    ("GET", "/api/v1/assessments/{assessment_id}/reports", Permission.DATA_READ, None),
    ("GET", "/api/v1/findings", Permission.DATA_READ, None),
    ("GET", "/api/v1/system/status", Permission.DATA_READ, None),
    ("GET", "/api/v1/overview", Permission.DATA_READ, None),
]
# Any authenticated user (no specific permission): checked for 401 only.
AUTH_ONLY = {("GET", "/api/v1/auth/me"), ("POST", "/api/v1/auth/logout")}
PUBLIC = {("GET", "/healthz"), ("GET", "/readyz"), ("POST", "/api/v1/auth/login")}


def _fill(path: str) -> str:
    return re.sub(r"\{[a-z_]+\}", UID, path.replace("{version}", "1"))


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
def anon(settings: Settings, db_engine) -> TestClient:
    return TestClient(create_app(settings))


def _audit(db_engine, action: str, actor_username: str | None = None) -> list[models.AuditLogEntry]:
    with Session(db_engine) as session:
        query = select(models.AuditLogEntry).where(models.AuditLogEntry.action == action)
        if actor_username is not None:
            query = query.where(models.AuditLogEntry.actor_username == actor_username)
        rows = list(session.scalars(query.order_by(models.AuditLogEntry.occurred_at)))
        session.expunge_all()
        return rows


def _me(client: TestClient) -> dict:
    return client.get("/api/v1/auth/me").json()["user"]


# --- authentication ----------------------------------------------------------


def test_login_sets_httponly_samesite_cookie_and_stores_only_a_hash(
    settings: Settings, db_engine, anon: TestClient
) -> None:
    user = create_user(settings, role=models.UserRole.ANALYST)
    response = anon.post(
        "/api/v1/auth/login", json={"username": user.username, "password": TEST_PASSWORD}
    )
    assert response.status_code == 200
    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "samesite=strict" in set_cookie
    assert "; secure" not in set_cookie  # relaxed only in test/development
    body = response.json()
    assert body["user"]["role"] == "analyst" and body["csrf_token"]
    assert "password" not in response.text.lower()

    raw = anon.cookies.get(settings.session_cookie_name)
    with Session(db_engine) as session:
        stored = session.scalar(
            select(models.AuthSession).where(
                models.AuthSession.token_hash == hashlib.sha256(raw.encode()).hexdigest()
            )
        )
        assert stored is not None and stored.user_id == user.id
        assert (
            session.scalar(select(models.AuthSession).where(models.AuthSession.token_hash == raw))
            is None
        )  # the raw token itself is never stored


def test_cookie_is_secure_in_production(settings: Settings, db_engine) -> None:
    user = create_user(settings, role=models.UserRole.VIEWER)
    prod = Settings(
        environment="production", secret_key="p" * 40, database_url=settings.database_url
    )
    response = TestClient(create_app(prod)).post(
        "/api/v1/auth/login", json={"username": user.username, "password": TEST_PASSWORD}
    )
    assert response.status_code == 200
    assert "; secure" in response.headers["set-cookie"].lower()


def test_api_docs_are_not_exposed_in_production(settings: Settings, db_engine) -> None:
    prod = Settings(
        environment="production", secret_key="p" * 40, database_url=settings.database_url
    )
    client = TestClient(create_app(prod))
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_wrong_password_and_unknown_user_are_indistinguishable_and_audited(
    settings: Settings, db_engine, anon: TestClient
) -> None:
    user = create_user(settings, role=models.UserRole.ANALYST)
    ghost = f"ghost-{uuid.uuid4().hex[:8]}"
    wrong = anon.post(
        "/api/v1/auth/login", json={"username": user.username, "password": "wrong-password-123"}
    )
    unknown = anon.post(
        "/api/v1/auth/login", json={"username": ghost, "password": "wrong-password-123"}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]
    assert "set-cookie" not in wrong.headers

    for name in (user.username, ghost):
        rows = _audit(db_engine, "auth.login", name)
        assert len(rows) == 1 and rows[0].outcome is models.AuditOutcome.FAILURE
        assert rows[0].actor_user_id is None


def test_repeated_failures_are_throttled(settings: Settings, db_engine) -> None:
    strict = settings.model_copy(update={"login_max_failures": 3})
    user = create_user(strict, role=models.UserRole.ANALYST)
    client = TestClient(create_app(strict))
    for _ in range(3):
        bad = client.post(
            "/api/v1/auth/login", json={"username": user.username, "password": "nope-nope-nope"}
        )
        assert bad.status_code == 401
    # Even the right password is refused while throttled.
    blocked = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": TEST_PASSWORD}
    )
    assert blocked.status_code == 429
    throttled = _audit(db_engine, "auth.login.throttled", user.username)
    assert throttled and throttled[0].outcome is models.AuditOutcome.DENIED


def test_unauthenticated_and_garbage_cookie_are_401(settings: Settings, anon: TestClient) -> None:
    assert anon.get("/api/v1/auth/me").status_code == 401
    anon.cookies.set(settings.session_cookie_name, "not-a-real-session-token")
    assert anon.get("/api/v1/auth/me").status_code == 401


def test_expired_session_is_rejected(settings: Settings, db_engine, anon: TestClient) -> None:
    user = create_user(settings, role=models.UserRole.ANALYST)
    with Session(db_engine) as session:
        raw, _ = sessions.create_session(
            session,
            user=session.get(models.User, user.id),
            ttl_minutes=1,
            now=datetime.now(UTC) - timedelta(hours=1),
        )
        session.commit()
    anon.cookies.set(settings.session_cookie_name, raw)
    assert anon.get("/api/v1/auth/me").status_code == 401


def test_logout_revokes_the_session_server_side(
    settings: Settings, db_engine, anon: TestClient
) -> None:
    user = create_user(settings, role=models.UserRole.ANALYST)
    login(anon, user.username)
    stolen_cookie = anon.cookies.get(settings.session_cookie_name)
    assert anon.post("/api/v1/auth/logout").status_code == 204
    # Replaying the old cookie must fail — the session is dead on the server.
    replay = TestClient(create_app(settings))
    replay.cookies.set(settings.session_cookie_name, stolen_cookie)
    assert replay.get("/api/v1/auth/me").status_code == 401
    assert _audit(db_engine, "auth.logout", user.username)


def test_deactivated_user_loses_access_immediately(settings: Settings) -> None:
    admin_client = authenticated_client(settings, models.UserRole.ADMIN)
    victim = authenticated_client(settings, models.UserRole.ANALYST)
    victim_id = _me(victim)["id"]
    assert victim.get("/api/v1/auth/me").status_code == 200
    assert (
        admin_client.patch(f"/api/v1/users/{victim_id}", json={"is_active": False}).status_code
        == 200
    )
    assert victim.get("/api/v1/auth/me").status_code == 401


def test_password_change_ends_existing_sessions(settings: Settings, db_engine) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    user_id = uuid.UUID(_me(client)["id"])
    with Session(db_engine) as session:
        users_service.set_password(session, user_id=user_id, new_password="a-brand-new-password-1")
        session.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_validation_errors_never_echo_the_submitted_password(anon: TestClient) -> None:
    secret = "p" * 300  # over the 256-char limit, so the body fails validation
    response = anon.post("/api/v1/auth/login", json={"username": "someone", "password": secret})
    assert response.status_code == 422
    assert secret not in response.text
    assert all(set(error) <= {"loc", "msg", "type"} for error in response.json()["errors"])


@pytest.mark.parametrize("bad_id", ["x" * 200, "has spaces and\ttabs", "semi;colon", "éé"])
def test_hostile_request_ids_are_replaced_not_stored(
    settings: Settings, db_engine, bad_id: str
) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    username = _me(client)["username"]
    try:
        response = client.post(
            "/api/v1/targets",
            json={"name": f"rid-{uuid.uuid4().hex[:8]}.test", "type": "web_application"},
            headers={"X-Request-ID": bad_id},
        )
    except UnicodeEncodeError:
        pytest.skip("client refuses to send a non-latin-1 header")
    assert response.status_code == 201  # was a 500 before: varchar(64) overflow in audit_log
    sent_back = response.headers["X-Request-ID"]
    assert sent_back != bad_id and re.fullmatch(r"[0-9a-f-]{36}", sent_back)
    assert _audit(db_engine, "target.create", username)[-1].request_id == sent_back


# --- CSRF ----------------------------------------------------------------------


def test_state_changing_requests_require_the_csrf_token(settings: Settings, db_engine) -> None:
    client = authenticated_client(settings, models.UserRole.ANALYST)
    username = _me(client)["username"]
    payload = {"name": f"csrf-{uuid.uuid4().hex[:8]}.test", "type": "web_application"}

    good_token = client.headers.pop("X-CSRF-Token")
    missing = client.post("/api/v1/targets", json=payload)
    wrong = client.post("/api/v1/targets", json=payload, headers={"X-CSRF-Token": "wrong"})
    assert missing.status_code == wrong.status_code == 403
    assert client.get("/api/v1/auth/me").status_code == 200  # safe methods need no token

    assert _audit(db_engine, "authz.csrf_rejected", username)
    ok = client.post("/api/v1/targets", json=payload, headers={"X-CSRF-Token": good_token})
    assert ok.status_code == 201


# --- RBAC ----------------------------------------------------------------------


def test_every_route_is_classified(settings: Settings, db_engine) -> None:
    paths = create_app(settings).openapi()["paths"]
    seen = {(method.upper(), path) for path, operations in paths.items() for method in operations}
    classified = {(m, p) for m, p, _, _ in MATRIX} | AUTH_ONLY | PUBLIC
    assert seen == classified, (
        f"unclassified: {sorted(seen - classified)}; stale: {sorted(classified - seen)}"
    )


def test_every_protected_route_rejects_anonymous_callers(anon: TestClient) -> None:
    protected = [(m, p) for m, p, _, _ in MATRIX] + sorted(AUTH_ONLY)
    for method, path in protected:
        response = anon.request(method, _fill(path), json={} if method != "GET" else None)
        assert response.status_code == 401, f"{method} {path} -> {response.status_code}"


def test_rbac_matrix_is_enforced_for_every_role(settings: Settings) -> None:
    clients = {role: authenticated_client(settings, role) for role in ROLES}
    for method, path, permission, body in MATRIX:
        for role, client in clients.items():
            response = client.request(method, _fill(path), json=body)
            label = f"{role.value} {method} {path} -> {response.status_code}"
            if has_permission(role, permission):
                assert response.status_code not in (401, 403), label
            else:
                assert response.status_code == 403, label


def test_denied_authorization_decision_is_audited(settings: Settings, db_engine) -> None:
    viewer = authenticated_client(settings, models.UserRole.VIEWER)
    username = _me(viewer)["username"]
    response = viewer.post("/api/v1/targets", json={"name": "x.test", "type": "web_application"})
    assert response.status_code == 403
    rows = _audit(db_engine, "authz.denied", username)
    assert len(rows) == 1
    assert rows[0].outcome is models.AuditOutcome.DENIED
    assert rows[0].details["permission"] == "targets:write"
    assert rows[0].request_id == response.json()["request_id"]


# --- user management ---------------------------------------------------------


def test_admin_creates_users_and_responses_never_expose_hashes(settings: Settings) -> None:
    admin_client = authenticated_client(settings, models.UserRole.ADMIN)
    name = f"  New-User-{uuid.uuid4().hex[:8]}  "
    created = admin_client.post(
        "/api/v1/users", json={"username": name, "password": TEST_PASSWORD, "role": "analyst"}
    )
    assert created.status_code == 201
    assert created.json()["username"] == name.strip().lower()
    assert "password" not in created.text.lower()
    assert "argon2" not in created.text.lower()

    duplicate = admin_client.post(
        "/api/v1/users", json={"username": name, "password": TEST_PASSWORD, "role": "viewer"}
    )
    assert duplicate.status_code == 409
    weak = admin_client.post(
        "/api/v1/users",
        json={"username": f"weak-{uuid.uuid4().hex[:6]}", "password": "short", "role": "viewer"},
    )
    assert weak.status_code == 422

    new_user = TestClient(create_app(settings))
    login(new_user, created.json()["username"])
    assert new_user.get("/api/v1/auth/me").json()["user"]["role"] == "analyst"
    listing = admin_client.get("/api/v1/users")
    assert listing.status_code == 200 and "password" not in listing.text.lower()


def test_user_cannot_escalate_their_own_privileges(settings: Settings) -> None:
    analyst = authenticated_client(settings, models.UserRole.ANALYST)
    me = _me(analyst)["id"]
    assert analyst.patch(f"/api/v1/users/{me}", json={"role": "admin"}).status_code == 403

    admin_client = authenticated_client(settings, models.UserRole.ADMIN)
    admin_id = _me(admin_client)["id"]
    # Even an admin cannot change their own role or active state.
    assert (
        admin_client.patch(f"/api/v1/users/{admin_id}", json={"role": "viewer"}).status_code == 403
    )
    assert (
        admin_client.patch(f"/api/v1/users/{admin_id}", json={"is_active": False}).status_code
        == 403
    )


def test_role_change_takes_effect_by_ending_the_users_sessions(settings: Settings) -> None:
    admin_client = authenticated_client(settings, models.UserRole.ADMIN)
    analyst = authenticated_client(settings, models.UserRole.ANALYST)
    analyst_user = _me(analyst)
    changed = admin_client.patch(f"/api/v1/users/{analyst_user['id']}", json={"role": "viewer"})
    assert changed.status_code == 200 and changed.json()["role"] == "viewer"
    assert analyst.get("/api/v1/auth/me").status_code == 401  # old privileges gone
    relogin = TestClient(create_app(settings))
    login(relogin, analyst_user["username"])
    assert relogin.get("/api/v1/auth/me").json()["user"]["role"] == "viewer"


# --- authorization approval workflow ---------------------------------------------


def _submit(client: TestClient) -> tuple[str, int]:
    name = f"sa-{uuid.uuid4().hex[:8]}.test"
    target = client.post("/api/v1/targets", json={"name": name, "type": "web_application"}).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/targets/{target['id']}/authorizations",
        json={
            "scope_rules": [{"rule_type": "domain", "pattern": name}],
            "attestation": "attestation",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    ).json()
    return target["id"], authorization["version"]


def test_admin_cannot_approve_their_own_submission(settings: Settings, db_engine) -> None:
    submitter = authenticated_client(settings, models.UserRole.ADMIN)
    target_id, version = _submit(submitter)
    url = f"/api/v1/targets/{target_id}/authorizations/{version}"

    refused = submitter.post(f"{url}/approve")
    assert refused.status_code == 403
    assert refused.json()["title"] == "Self-approval not allowed"
    denied = [
        r
        for r in _audit(db_engine, "authorization.approve", _me(submitter)["username"])
        if r.outcome is models.AuditOutcome.DENIED
    ]
    assert denied and denied[0].details["reason"] == "self_approval"

    # A different admin can; both identities are recorded on the row.
    approver = authenticated_client(settings, models.UserRole.ADMIN)
    approved = approver.post(f"{url}/approve")
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    with Session(db_engine) as session:
        row = session.scalar(
            select(models.Authorization).where(models.Authorization.id == approved.json()["id"])
        )
        assert str(row.submitted_by_id) == _me(submitter)["id"]
        assert str(row.decided_by_id) == _me(approver)["id"]


def test_self_approval_can_be_enabled_for_single_user_labs(settings: Settings) -> None:
    lab = settings.model_copy(update={"allow_self_approval": True})
    solo = authenticated_client(lab, models.UserRole.ADMIN)
    target_id, version = _submit(solo)
    response = solo.post(f"/api/v1/targets/{target_id}/authorizations/{version}/approve")
    assert response.status_code == 200


def test_only_admins_decide_scope_and_rejection_is_audited(settings: Settings, db_engine) -> None:
    analyst = authenticated_client(settings, models.UserRole.ANALYST)
    target_id, version = _submit(analyst)
    url = f"/api/v1/targets/{target_id}/authorizations/{version}"
    assert analyst.post(f"{url}/approve").status_code == 403
    assert analyst.post(f"{url}/reject").status_code == 403

    reviewer = authenticated_client(settings, models.UserRole.ADMIN)
    rejected = reviewer.post(f"{url}/reject")
    assert rejected.status_code == 200 and rejected.json()["status"] == "rejected"
    assert _audit(db_engine, "authorization.reject", _me(reviewer)["username"])
    # A rejected version cannot then be approved (state machine still holds).
    assert reviewer.post(f"{url}/approve").status_code == 422


# --- audit log -------------------------------------------------------------------


def _seed_finding(settings: Settings, assessment_id: str) -> uuid.UUID:
    engine = create_engine(settings.database_url, future=True)
    try:
        with Session(engine) as session:
            asset = get_or_create_asset(
                session,
                assessment_id=uuid.UUID(assessment_id),
                asset_type=models.AssetType.ENDPOINT,
                canonical_key="http://localhost:1/",
                attributes={},
            )
            finding, _ = get_or_create_finding(
                session,
                assessment_id=uuid.UUID(assessment_id),
                asset_id=asset.id,
                title="Missing security header: X-Frame-Options",
                severity=models.FindingSeverity.MEDIUM,
                confidence=1.0,
                source="security_header_scan",
                affected_component="X-Frame-Options",
            )
            finding.status = models.FindingStatus.INVESTIGATING
            session.commit()
            return finding.id
    finally:
        engine.dispose()


def test_sensitive_actions_are_audited_without_secrets(settings: Settings, db_engine) -> None:
    analyst = authenticated_client(settings, models.UserRole.ANALYST)
    approver = authenticated_client(settings, models.UserRole.ADMIN)
    analyst_name, approver_name = _me(analyst)["username"], _me(approver)["username"]
    rid = f"req-{uuid.uuid4().hex[:8]}"

    target_id, version = _submit(analyst)
    approver.post(f"/api/v1/targets/{target_id}/authorizations/{version}/approve")
    assessment = analyst.post(
        "/api/v1/assessments", json={"target_id": target_id}, headers={"X-Request-ID": rid}
    ).json()
    finding_id = _seed_finding(settings, assessment["id"])
    override = analyst.patch(
        f"/api/v1/findings/{finding_id}/status",
        json={"status": "rejected", "reason": "false positive confirmed by hand"},
    )
    assert override.status_code == 200
    analyst.post(f"/api/v1/assessments/{assessment['id']}/reports")
    analyst.post(f"/api/v1/assessments/{assessment['id']}/cancel")

    expected = {
        "target.create": analyst_name,
        "authorization.submit": analyst_name,
        "authorization.approve": approver_name,
        "assessment.create": analyst_name,
        "finding.status_override": analyst_name,
        "report.generate": analyst_name,
        "assessment.cancel": analyst_name,
    }
    collected: list[models.AuditLogEntry] = []
    for action, actor in expected.items():
        rows = _audit(db_engine, action, actor)
        assert rows, f"no audit row for {action} by {actor}"
        assert all(r.outcome is models.AuditOutcome.SUCCESS and r.request_id for r in rows)
        collected.extend(rows)

    created = _audit(db_engine, "assessment.create", analyst_name)
    assert created[-1].request_id == rid
    override_row = _audit(db_engine, "finding.status_override", analyst_name)[-1]
    assert override_row.details == {
        "from": "investigating",
        "to": "rejected",
        "reason": "false positive confirmed by hand",
    }
    assert override_row.target_id == str(finding_id)

    blob = json.dumps([r.details for r in collected]).lower()
    for secret in (
        TEST_PASSWORD,
        analyst.cookies.get(settings.session_cookie_name),
        analyst.headers["X-CSRF-Token"],
        "argon2",
    ):
        assert secret.lower() not in blob


def test_audit_log_is_append_only_in_the_database(settings: Settings, db_engine) -> None:
    client = authenticated_client(settings, models.UserRole.ADMIN)  # writes an auth.login row
    assert _audit(db_engine, "auth.login", _me(client)["username"])

    for statement in (
        "UPDATE audit_log SET action = 'tampered'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ):
        with pytest.raises(DBAPIError), db_engine.begin() as conn:
            conn.execute(text(statement))
    assert _audit(db_engine, "tampered") == []


def test_audit_log_api_is_admin_only_and_filterable(settings: Settings) -> None:
    admin_client = authenticated_client(settings, models.UserRole.ADMIN)
    analyst = authenticated_client(settings, models.UserRole.ANALYST)
    assert analyst.get("/api/v1/audit-log").status_code == 403

    response = admin_client.get("/api/v1/audit-log", params={"action": "auth.login", "limit": 5})
    assert response.status_code == 200
    entries = response.json()
    assert 0 < len(entries) <= 5 and all(e["action"] == "auth.login" for e in entries)
    assert admin_client.get("/api/v1/audit-log", params={"limit": 501}).status_code == 422


# --- operator CLI -----------------------------------------------------------------


def test_cli_creates_the_first_admin_with_an_audit_row(
    settings: Settings, db_engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OFFENSIVEX_DATABASE_URL", settings.database_url)
    username = f"cli-admin-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr("sys.stdin", io.StringIO(TEST_PASSWORD + "\n"))
    code = admin.main(
        ["create-user", "--username", username, "--role", "admin", "--password-stdin"]
    )
    assert code == 0

    client = TestClient(create_app(settings))
    login(client, username)
    assert client.get("/api/v1/auth/me").json()["user"]["role"] == "admin"
    rows = _audit(db_engine, "user.create", None)
    assert any(
        r.details.get("username") == username and r.actor_username.startswith("cli:") for r in rows
    )


def test_cli_ignores_a_utf8_bom_on_piped_passwords(
    settings: Settings, db_engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows PowerShell pipes a BOM before the text; it must not become part
    of the stored password (found by a real CLI + real HTTP smoke test)."""
    monkeypatch.setenv("OFFENSIVEX_DATABASE_URL", settings.database_url)
    username = f"bom-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr("sys.stdin", io.StringIO("﻿" + TEST_PASSWORD + "\r\n"))
    assert (
        admin.main(["create-user", "--username", username, "--role", "viewer", "--password-stdin"])
        == 0
    )
    client = TestClient(create_app(settings))
    login(client, username)  # logs in with the plain password, no BOM
    assert client.get("/api/v1/auth/me").status_code == 200


def test_cli_rejects_a_weak_password(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OFFENSIVEX_DATABASE_URL", settings.database_url)
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    code = admin.main(
        ["create-user", "--username", "weak-cli", "--role", "viewer", "--password-stdin"]
    )
    assert code == 1
    assert "at least" in capsys.readouterr().err
