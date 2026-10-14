"""The deterministic graph-construction engine + bounded path search —
Phase 12.

docs/roadmap/architecture-risks.md risk #9 warns against building rules
for all nine relationship types (docs/data/attack-graph.md) before the
engine itself is proven: "P12 ships with the minimal rule set that makes
the vertical slice's one finding class produce one correct edge." This
module ships exactly one curated rule, for the one finding class that
exists (missing security headers, Phase 8) — specifically the
X-Frame-Options case, because it is the one of the three checked headers
with a plausible, honestly-describable escalation (clickjacking can
coerce an already-authenticated victim into performing an action). The
other two checked headers (Strict-Transport-Security,
X-Content-Type-Options) deliberately have no rule yet — they are real
hardening gaps but do not, on their own, grant reachable access the way
this project's attack graph models it. A rule is added when a finding/
asset class actually justifies it, never speculatively (CLAUDE.md
section 20).

Evidence level follows docs/security/attack-path-analysis.md's four-level
model directly from the causing `Finding`'s status: `CONFIRMED` (only
ever reached via the Validation Agent's checked outcome or an explicit
analyst override, Phase 10) maps to `verified`; a `SUSPECTED`/
`INVESTIGATING` finding with reasonably high confidence maps to
`potential` ("well-evidenced suspected findings," per
docs/agents/attack-graph-agent.md); `REJECTED` or low-confidence findings
produce no edge at all. No rule here ever produces `observed` or
`inferred` — this engine has no asset-relationship data (e.g. real IAM
trust edges) to derive those from yet; claiming otherwise would be
exactly the fabrication Guardrail.md section 3 forbids.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.db import models

ENTRY_ACCESS_LEVEL = "unauthenticated_access"

# Confidence floor for a non-CONFIRMED finding to still produce a
# "potential" edge. No document specifies an exact number; 0.8 is the
# smallest reasonable reading of "well-evidenced" (docs/agents/
# attack-graph-agent.md) given every finding class built so far reports
# confidence 1.0 or not at all (deterministic header checks) — revisit
# once a probabilistic finding class exists to calibrate against.
_POTENTIAL_CONFIDENCE_FLOOR = 0.8

_EVIDENCE_RANK: dict[models.EvidenceLevel, int] = {
    models.EvidenceLevel.POTENTIAL: 0,
    models.EvidenceLevel.INFERRED: 1,
    models.EvidenceLevel.OBSERVED: 2,
    models.EvidenceLevel.VERIFIED: 3,
}


@dataclass(frozen=True)
class AttackGraphRule:
    rule_id: str
    affected_component: str
    relationship: models.AttackRelationship
    target_access_level: str


RULES: list[AttackGraphRule] = [
    AttackGraphRule(
        rule_id="missing-x-frame-options-clickjacking-v1",
        affected_component="X-Frame-Options",
        relationship=models.AttackRelationship.EXPLOITS,
        target_access_level="clickjacking_assisted_action",
    ),
]

_RULES_BY_COMPONENT = {rule.affected_component: rule for rule in RULES}


def _evidence_level_for_finding(finding: models.Finding) -> models.EvidenceLevel | None:
    if finding.status is models.FindingStatus.CONFIRMED:
        return models.EvidenceLevel.VERIFIED
    if (
        finding.status in (models.FindingStatus.SUSPECTED, models.FindingStatus.INVESTIGATING)
        and finding.confidence >= _POTENTIAL_CONFIDENCE_FLOOR
    ):
        return models.EvidenceLevel.POTENTIAL
    return None  # REJECTED, DISCOVERED, or below the confidence floor


def _get_or_create_node(
    session: Session, *, assessment_id: UUID, asset_id: UUID, access_level: str
) -> models.AttackNode:
    existing = session.scalar(
        select(models.AttackNode).where(
            models.AttackNode.assessment_id == assessment_id,
            models.AttackNode.asset_id == asset_id,
            models.AttackNode.access_level == access_level,
        )
    )
    if existing is not None:
        return existing
    node = models.AttackNode(
        assessment_id=assessment_id, asset_id=asset_id, access_level=access_level
    )
    session.add(node)
    session.flush()
    return node


def _get_or_create_edge(
    session: Session,
    *,
    src_node_id: UUID,
    dst_node_id: UUID,
    relationship_type: models.AttackRelationship,
    cause_id: UUID,
    rule_id: str,
    evidence_level: models.EvidenceLevel,
) -> models.AttackEdge:
    existing = session.scalar(
        select(models.AttackEdge).where(
            models.AttackEdge.src_node_id == src_node_id,
            models.AttackEdge.dst_node_id == dst_node_id,
            models.AttackEdge.cause_id == cause_id,
        )
    )
    if existing is not None:
        # The causing finding's status may have changed (e.g. DISCOVERED
        # -> CONFIRMED) since the last build pass — refresh, don't
        # duplicate.
        existing.evidence_level = evidence_level
        session.flush()
        return existing
    edge = models.AttackEdge(
        src_node_id=src_node_id,
        dst_node_id=dst_node_id,
        relationship_type=relationship_type,
        cause_type=models.AttackEdgeCauseType.FINDING,
        cause_id=cause_id,
        rule_id=rule_id,
        evidence_level=evidence_level,
    )
    session.add(edge)
    session.flush()
    return edge


def build_attack_graph(session: Session, assessment: models.Assessment) -> list[models.AttackEdge]:
    """Deterministic: the same findings always produce the same edges.
    Idempotent: re-running after new findings appear only adds to, or
    refreshes, what's already there."""
    findings = session.scalars(
        select(models.Finding).where(models.Finding.assessment_id == assessment.id)
    ).all()

    edges: list[models.AttackEdge] = []
    for finding in findings:
        rule = _RULES_BY_COMPONENT.get(finding.affected_component or "")
        if rule is None:
            continue
        evidence_level = _evidence_level_for_finding(finding)
        if evidence_level is None:
            continue

        entry_node = _get_or_create_node(
            session,
            assessment_id=assessment.id,
            asset_id=finding.asset_id,
            access_level=ENTRY_ACCESS_LEVEL,
        )
        target_node = _get_or_create_node(
            session,
            assessment_id=assessment.id,
            asset_id=finding.asset_id,
            access_level=rule.target_access_level,
        )
        edge = _get_or_create_edge(
            session,
            src_node_id=entry_node.id,
            dst_node_id=target_node.id,
            relationship_type=rule.relationship,
            cause_id=finding.id,
            rule_id=rule.rule_id,
            evidence_level=evidence_level,
        )
        edges.append(edge)
    return edges


def find_attack_paths(
    session: Session,
    assessment: models.Assessment,
    *,
    max_depth: int = 5,
    rules_version: str = "v1",
) -> list[models.AttackPath]:
    """Bounded reachability search from every entry node
    (`access_level == ENTRY_ACCESS_LEVEL`) to every node reachable within
    `max_depth` hops, per docs/security/attack-path-analysis.md: "If an
    attacker compromises this component, what can they reach next?"

    Recomputed every pass, not incrementally maintained — "a path is a
    query result, not independently mutable state" (Phase 1's
    `AttackPath` docstring) — so existing rows for this assessment are
    replaced, not appended to.
    """
    nodes = session.scalars(
        select(models.AttackNode).where(models.AttackNode.assessment_id == assessment.id)
    ).all()
    node_ids = {node.id for node in nodes}
    edges = session.scalars(
        select(models.AttackEdge).where(models.AttackEdge.src_node_id.in_(node_ids))
    ).all()

    adjacency: dict[UUID, list[models.AttackEdge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.src_node_id, []).append(edge)

    entry_nodes = [node for node in nodes if node.access_level == ENTRY_ACCESS_LEVEL]

    discovered: list[tuple[UUID, UUID, list[models.AttackEdge]]] = []
    for entry in entry_nodes:
        stack: list[tuple[UUID, list[models.AttackEdge], frozenset[UUID]]] = [
            (entry.id, [], frozenset({entry.id}))
        ]
        while stack:
            current_id, path_edges, visited = stack.pop()
            if len(path_edges) >= max_depth:
                continue
            for edge in adjacency.get(current_id, []):
                if edge.dst_node_id in visited:
                    continue  # no cycles in a bounded search
                new_path_edges = [*path_edges, edge]
                new_visited = visited | {edge.dst_node_id}
                discovered.append((entry.id, edge.dst_node_id, new_path_edges))
                stack.append((edge.dst_node_id, new_path_edges, new_visited))

    session.query(models.AttackPath).filter_by(assessment_id=assessment.id).delete()
    session.flush()

    result: list[models.AttackPath] = []
    for entry_id, target_id, path_edges in discovered:
        weakest = min(path_edges, key=lambda e: _EVIDENCE_RANK[e.evidence_level])
        attack_path = models.AttackPath(
            assessment_id=assessment.id,
            entry_node_id=entry_id,
            target_node_id=target_id,
            edge_ids=[str(edge.id) for edge in path_edges],
            evidence_level=weakest.evidence_level,
            rules_version=rules_version,
        )
        session.add(attack_path)
        result.append(attack_path)
    session.flush()
    return result
