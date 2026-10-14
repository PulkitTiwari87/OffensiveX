"""Phase 1 domain model: the canonical entities from
docs/roadmap/implementation-blueprint.md section 3 (refining
docs/data/data-model.md).

Scope deliberately matches the blueprint's MVP entity list exactly — no
additional tables, no speculative fields. Two vocabulary gaps the
documentation leaves open for later phases are resolved here with the
smallest reasonable choice, called out explicitly rather than silently:

* `ImpactLevel` (criticality/exposure): the docs commit to these fields
  existing but not to a scale. A four-tier LOW/MEDIUM/HIGH/CRITICAL scale
  is used for both; this is a placeholder subject to confirmation when the
  Risk Agent's formula is finalized (P13, see docs/security/risk-analysis.md).
* `AttackPath.edge_ids`: stored as an ordered JSONB array of `AttackEdge`
  ids rather than a join table, per data-model.md's "relational plus
  in-memory graph library" storage decision (ADR-003) — a path is a
  recomputed query result, not independently mutable state.

State-machine enforcement (CLAUDE.md section 8: "invalid transitions
should be rejected") is defined in `offensivex.db.transitions` and is
wired into write paths starting with the services that own each
transition (Assessment lifecycle - P2, Investigation - P9, Validation -
P10, the agent runtime - P5). This module defines the shape; it does not
itself refuse an invalid UPDATE, since no code writes these rows yet.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy.types import DateTime, Float, Integer, String, Text, Uuid

from offensivex.db.base import Base


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _updated_at() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# --- Enums -------------------------------------------------------------------
# Status enums map 1:1 to the lifecycles in docs/roadmap/implementation-blueprint.md
# section 3 and docs/data/findings.md. Valid transitions between these values
# live in offensivex.db.transitions, not here.


class ImpactLevel(enum.StrEnum):
    """Shared placeholder scale for Target/Asset criticality and exposure.

    See module docstring — not yet confirmed against the Risk Agent's
    formula (P13).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    # "expired" is derived from valid_until, not a stored transition target —
    # see docs/roadmap/implementation-blueprint.md section 3.


class ScanMode(enum.StrEnum):
    """docs/security/validation.md — quick/standard/deep."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class AssessmentStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssetType(enum.StrEnum):
    """docs/data/data-model.md: "host, port, service, application,
    endpoint, or cloud resource"."""

    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    CLOUD_RESOURCE = "cloud_resource"


class AssetScopeState(enum.StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


class ObservationType(enum.StrEnum):
    """docs/data/observations.md — planned vocabulary; grows deliberately,
    not ad hoc, as capabilities are implemented."""

    HOST_DISCOVERED = "host_discovered"
    PORT_DISCOVERED = "port_discovered"
    SERVICE_DISCOVERED = "service_discovered"
    TECHNOLOGY_DISCOVERED = "technology_discovered"
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    VULNERABILITY_SIGNAL_DISCOVERED = "vulnerability_signal_discovered"
    OUT_OF_SCOPE = "out_of_scope"


class FindingSeverity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(enum.StrEnum):
    """docs/data/findings.md lifecycle diagram, exactly."""

    DISCOVERED = "discovered"
    SUSPECTED = "suspected"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REPORTED = "reported"


class EvidenceKind(enum.StrEnum):
    REQUEST_RESPONSE = "request_response"
    HEADER = "header"
    SCREENSHOT = "screenshot"
    SOURCE_LOCATION = "source_location"
    SCANNER_OUTPUT = "scanner_output"
    COMMAND_OUTPUT = "command_output"
    BROWSER_OBSERVATION = "browser_observation"
    VALIDATION_RESULT = "validation_result"


class AgentType(enum.StrEnum):
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    INVESTIGATION = "investigation"
    VALIDATION = "validation"
    ATTACK_GRAPH = "attack_graph"
    RISK = "risk"
    REPORTING = "reporting"


class AgentRunStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScopeDecision(enum.StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class ToolExecutionStatus(enum.StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    KILLED = "killed"
    DENIED = "denied"


class AttackRelationship(enum.StrEnum):
    """docs/data/attack-graph.md edge types."""

    EXPOSES = "exposes"
    RUNS = "runs"
    AUTHENTICATES_TO = "authenticates_to"
    HAS_ACCESS = "has_access"
    CAN_REACH = "can_reach"
    EXPLOITS = "exploits"
    ESCALATES_TO = "escalates_to"
    TRUSTS = "trusts"
    LEADS_TO = "leads_to"


class AttackEdgeCauseType(enum.StrEnum):
    FINDING = "finding"
    RELATIONSHIP = "relationship"


class EvidenceLevel(enum.StrEnum):
    """docs/data/attack-graph.md — a path's level is its weakest edge."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    POTENTIAL = "potential"
    VERIFIED = "verified"


class ReportFormat(enum.StrEnum):
    """SARIF/PDF are FUTURE per docs/roadmap/implementation-blueprint.md
    section 9 — not added here."""

    JSON = "json"
    MARKDOWN = "markdown"


class UserRole(enum.StrEnum):
    """ADR-013's three coarse roles. Which permissions each role holds
    lives in `offensivex.auth.permissions`, not here."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AuditOutcome(enum.StrEnum):
    SUCCESS = "success"
    DENIED = "denied"  # an authorization decision said no
    FAILURE = "failure"  # e.g. a failed login


def _pg_enum(enum_cls: type[enum.StrEnum], name: str) -> SAEnum:
    """A Postgres-native ENUM column for a `StrEnum`, storing/reading its
    *value* (e.g. "medium") rather than SQLAlchemy's default of the
    member's *name* (e.g. "MEDIUM") — the migration (0002_domain_model)
    creates the Postgres type with the lowercase values, matching
    `StrEnum.value`, not `Enum.name`.
    """
    return SAEnum(enum_cls, name=name, values_callable=lambda e: [m.value for m in e])


# Shared instances for types used on more than one column. A Postgres ENUM
# type is created once per distinct `name=`; passing a *new* SAEnum(...)
# object per column for the same name works for a single CREATE TABLE but
# breaks a multi-table DDL run (CREATE TYPE issued more than once). Reusing
# one instance avoids that for ImpactLevel (4 columns) and EvidenceLevel (2
# columns) — every other enum below is used on exactly one column, so a
# fresh `_pg_enum(..., name=...)` call there is fine.
_IMPACT_LEVEL = _pg_enum(ImpactLevel, "impact_level")
_EVIDENCE_LEVEL = _pg_enum(EvidenceLevel, "evidence_level")


# --- Entities ------------------------------------------------------------


class Target(Base):
    """What may be assessed, and under what scope/authorization."""

    __tablename__ = "targets"
    __table_args__ = (
        CheckConstraint(
            "entry_point IS NULL OR entry_point LIKE 'http://%' OR entry_point LIKE 'https://%'",
            name="ck_targets_entry_point_http",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Where assessment starts: a normalized http(s) URL (scheme, host, explicit
    # non-default port, path; never userinfo, query or fragment — see
    # offensivex.core.urls). Nullable for targets created before this field
    # existed; Recon then only knows hostnames. It is a starting point, not
    # permission: the Authorization's scope rules still decide what may be touched.
    entry_point: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    default_exposure: Mapped[ImpactLevel] = mapped_column(
        _IMPACT_LEVEL, nullable=False, default=ImpactLevel.MEDIUM
    )
    default_criticality: Mapped[ImpactLevel] = mapped_column(
        _IMPACT_LEVEL, nullable=False, default=ImpactLevel.MEDIUM
    )
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()

    authorizations: Mapped[list[Authorization]] = relationship(back_populates="target")
    assessments: Mapped[list[Assessment]] = relationship(back_populates="target")


class Authorization(Base):
    """The approved scope + attestation that makes a target assessable.

    See docs/Guardrail.md section 2: "every scan has an explicit scope. No
    scope -> no scan." `status` only ever moves between the values in
    offensivex.db.transitions.AUTHORIZATION_TRANSITIONS; "expired" is a
    derived read (valid_until < now), never a stored transition target.
    """

    __tablename__ = "authorizations"
    __table_args__ = (UniqueConstraint("target_id", "version", name="uq_authorization_version"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    attestation: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[AuthorizationStatus] = mapped_column(
        _pg_enum(AuthorizationStatus, "authorization_status"),
        nullable=False,
        default=AuthorizationStatus.PENDING,
    )
    # Who submitted this version, and who approved or rejected it (ADR-013's
    # self-approval rule). Nullable: rows created by internal/test code paths
    # have no human actor.
    submitted_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()

    target: Mapped[Target] = relationship(back_populates="authorizations")
    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="authorization", cascade="all, delete-orphan"
    )


class ScopeRule(Base):
    """One include/exclude rule within an Authorization's scope.

    `rule_type`/`pattern` are kept as free strings rather than a closed
    enum: docs/Guardrail.md section 2 does not commit to a fixed rule
    vocabulary (domain, CIDR, URL prefix, ...), and inventing one here
    would be premature generalization ahead of the Tool Registry (P3),
    which is what actually consumes these rules via the Scope Guard.
    """

    __tablename__ = "scope_rules"

    id: Mapped[uuid.UUID] = _uuid_pk()
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("authorizations.id", ondelete="CASCADE"), nullable=False
    )
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)
    pattern: Mapped[str] = mapped_column(String(500), nullable=False)
    is_exclusion: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[datetime] = _created_at()

    authorization: Mapped[Authorization] = relationship(back_populates="scope_rules")


class Assessment(Base):
    """One run of the full lifecycle against one target."""

    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = _uuid_pk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    # Snapshot, not a live reference: an Authorization may later be revoked
    # or superseded by a new version without retroactively changing what an
    # already-running assessment was approved under.
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("authorizations.id"), nullable=False
    )
    scan_mode: Mapped[ScanMode] = mapped_column(
        _pg_enum(ScanMode, "scan_mode"), nullable=False, default=ScanMode.STANDARD
    )
    validation_enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    status: Mapped[AssessmentStatus] = mapped_column(
        _pg_enum(AssessmentStatus, "assessment_status"),
        nullable=False,
        default=AssessmentStatus.PENDING,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()

    target: Mapped[Target] = relationship(back_populates="assessments")
    authorization: Mapped[Authorization] = relationship()
    assets: Mapped[list[Asset]] = relationship(back_populates="assessment")
    findings: Mapped[list[Finding]] = relationship(back_populates="assessment")
    agent_runs: Mapped[list[AgentRun]] = relationship(back_populates="assessment")


class Asset(Base):
    """A discovered host/port/service/application/endpoint/cloud resource."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("assessment_id", "asset_type", "canonical_key", name="uq_asset_identity"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    asset_type: Mapped[AssetType] = mapped_column(_pg_enum(AssetType, "asset_type"), nullable=False)
    # The stable key that makes an asset the "same" asset across tool runs
    # within one assessment (e.g. a hostname, or "host:port").
    canonical_key: Mapped[str] = mapped_column(String(500), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    criticality: Mapped[ImpactLevel | None] = mapped_column(_IMPACT_LEVEL, nullable=True)
    exposure: Mapped[ImpactLevel | None] = mapped_column(_IMPACT_LEVEL, nullable=True)
    scope_state: Mapped[AssetScopeState] = mapped_column(
        _pg_enum(AssetScopeState, "asset_scope_state"),
        nullable=False,
        default=AssetScopeState.IN_SCOPE,
    )
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()

    assessment: Mapped[Assessment] = relationship(back_populates="assets")
    observations: Mapped[list[Observation]] = relationship(back_populates="asset")


class Observation(Base):
    """A normalized, typed fact produced from a ToolExecution's parsed
    output. Immutable once written (docs/data/observations.md)."""

    __tablename__ = "observations"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_observation_confidence"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    type: Mapped[ObservationType] = mapped_column(
        _pg_enum(ObservationType, "observation_type"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    tool_execution_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tool_executions.id"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = _created_at()

    asset: Mapped[Asset] = relationship(back_populates="observations")


class Finding(Base):
    """A candidate or confirmed weakness, correlated from one or more
    observations. See docs/data/findings.md for the lifecycle."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_finding_confidence"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[FindingSeverity] = mapped_column(
        _pg_enum(FindingSeverity, "finding_severity"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(300), nullable=True)
    affected_component: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        _pg_enum(FindingStatus, "finding_status"),
        nullable=False,
        default=FindingStatus.DISCOVERED,
    )
    # Written only by the Risk Agent (P13) — never by agent prose, per
    # CLAUDE.md: "Risk scores are computed only by the deterministic Risk
    # Agent."
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_breakdown: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    risk_model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessment: Mapped[Assessment] = relationship(back_populates="findings")
    asset: Mapped[Asset] = relationship()
    evidence: Mapped[list[Evidence]] = relationship(back_populates="finding")


class Evidence(Base):
    """A specific artifact backing a finding. Immutable once written.

    `excerpt` is sanitized/size-capped by the writer (the agent/service
    that captured it) — see docs/data/evidence-model.md: "evidence is
    untrusted content", never treated as instructions or rendered as
    anything but text. Enforcing the exact cap is the writer's
    responsibility, not a DB constraint here (the cap value is a tool/
    agent concern introduced with the Tool Registry, P3+).
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[EvidenceKind] = mapped_column(
        _pg_enum(EvidenceKind, "evidence_kind"), nullable=False
    )
    tool_execution_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tool_executions.id"), nullable=False
    )
    excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class AgentRun(Base):
    """One execution of one agent."""

    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    agent_type: Mapped[AgentType] = mapped_column(_pg_enum(AgentType, "agent_type"), nullable=False)
    status: Mapped[AgentRunStatus] = mapped_column(
        _pg_enum(AgentRunStatus, "agent_run_status"),
        nullable=False,
        default=AgentRunStatus.QUEUED,
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input_ref: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    output_ref: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()

    assessment: Mapped[Assessment] = relationship(back_populates="agent_runs")
    tool_executions: Mapped[list[ToolExecution]] = relationship(back_populates="agent_run")


class ToolExecution(Base):
    """One tool call made through the Tool Registry."""

    __tablename__ = "tool_executions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    # Nullable: not every tool call is made on behalf of an agent (e.g. a
    # one-off adapter proof call) per docs/roadmap/implementation-blueprint.md
    # section 3: "agent_run_id (nullable for non-agent calls)".
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=True
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    capability: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_decision: Mapped[ScopeDecision] = mapped_column(
        _pg_enum(ScopeDecision, "scope_decision"), nullable=False
    )
    status: Mapped[ToolExecutionStatus] = mapped_column(
        _pg_enum(ToolExecutionStatus, "tool_execution_status"),
        nullable=False,
        default=ToolExecutionStatus.PLANNED,
    )
    argv: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    artifact_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exit_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()

    agent_run: Mapped[AgentRun | None] = relationship(back_populates="tool_executions")


class AttackNode(Base):
    """`(asset, access_level)` graph vertex. `access_level` is kept as a
    free string rather than a closed enum: docs/data/attack-graph.md's own
    examples (`unauthenticated_access`, `data_read`, ...) are asset-type-
    specific and not presented as an exhaustive, fixed list."""

    __tablename__ = "attack_nodes"
    __table_args__ = (
        UniqueConstraint("assessment_id", "asset_id", "access_level", name="uq_attack_node"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    access_level: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class AttackEdge(Base):
    """A graph edge with cause and evidence level.

    `cause_id` is a loose reference (typically a `Finding.id` when
    `cause_type == FINDING`), not a hard foreign key: it is polymorphic by
    `cause_type`, and a rule-derived relationship edge may have no single
    Finding to point to at all.
    """

    __tablename__ = "attack_edges"

    id: Mapped[uuid.UUID] = _uuid_pk()
    src_node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False
    )
    dst_node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[AttackRelationship] = mapped_column(
        _pg_enum(AttackRelationship, "attack_relationship"), nullable=False
    )
    cause_type: Mapped[AttackEdgeCauseType] = mapped_column(
        _pg_enum(AttackEdgeCauseType, "attack_edge_cause_type"), nullable=False
    )
    cause_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    evidence_level: Mapped[EvidenceLevel] = mapped_column(_EVIDENCE_LEVEL, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class AttackPath(Base):
    """A persisted, bounded-search result: entry -> target.

    `edge_ids` is an ordered JSONB array of `AttackEdge.id` values (the
    steps), not a join table — see module docstring. Recomputed per Attack
    Graph Agent pass; not independently mutable.
    """

    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    entry_node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False
    )
    target_node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False
    )
    edge_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    path_risk: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_level: Mapped[EvidenceLevel] = mapped_column(_EVIDENCE_LEVEL, nullable=False)
    rules_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class Report(Base):
    """An immutable, generated snapshot of an assessment's results.
    Regeneration creates a new row rather than mutating an existing one.

    `content_json`/`content_markdown` (Phase 14) hold the actual rendered
    output — the deterministic sections are reproducible from assessment
    data alone, but the AI-authored executive summary is not (a fresh LLM
    call could word it differently), so the generated content is
    persisted rather than reconstructed on every read.
    """

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    formats: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    included_scan_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    content_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    content_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# --- Authentication, RBAC, audit (ADR-012 / ADR-013) -------------------------


class User(Base):
    """A local account. Never deleted (audit rows reference it) — an account
    is retired by setting `is_active = False`."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    # argon2id encoded hash (includes salt + parameters). Never the password.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(_pg_enum(UserRole, "user_role"), nullable=False)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class AuthSession(Base):
    """A server-side login session. Only the SHA-256 of the session token is
    stored, so a database read cannot be replayed as a cookie."""

    __tablename__ = "auth_sessions"
    __table_args__ = (Index("ix_auth_sessions_user_id", "user_id"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Synchronizer CSRF token (ADR-012): returned to the client at login and
    # required in `X-CSRF-Token` on every state-changing request. Useless
    # without the HttpOnly session cookie, so it is stored as-is.
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = _created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship()


class AuditLogEntry(Base):
    """Append-only record of a security-relevant action. A Postgres trigger
    (migration 0004) rejects UPDATE/DELETE/TRUNCATE, so history cannot be
    rewritten through the application. `details` must never hold secrets —
    see `offensivex.services.audit`."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_occurred_at", "occurred_at"),
        Index("ix_audit_log_action", "action"),
        Index("ix_audit_log_actor_user_id", "actor_user_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Nullable: a failed login has no authenticated actor. No ON DELETE
    # action (users are never deleted), so the audit trail can't be edited
    # indirectly through a user delete.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    outcome: Mapped[AuditOutcome] = mapped_column(
        _pg_enum(AuditOutcome, "audit_outcome"), nullable=False
    )
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
