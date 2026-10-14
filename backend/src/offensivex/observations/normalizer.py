"""The generalized tool -> observation normalizer — Phase 7.

`ObservationNormalizer` is a capability -> handler registry; each agent
module registers a small function per capability it uses, rather than
every agent re-deriving the Asset-upsert-then-Observation-write pattern.
`get_or_create_asset`/`write_observation` are the two building blocks
every handler needs — extracted from Phase 6's Recon-specific version
(`offensivex.agents.recon`), which now registers its two handlers here
instead of hardcoding its own dispatch.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.db import models
from offensivex.tools.registry import ParsedResult

NormalizerHandler = Callable[[Session, models.Assessment, dict[str, Any], ParsedResult], None]


class NoNormalizerRegisteredError(ValueError):
    pass


class ObservationNormalizer:
    def __init__(self) -> None:
        self._handlers: dict[str, NormalizerHandler] = {}

    def register(self, capability: str, handler: NormalizerHandler) -> None:
        self._handlers[capability] = handler

    def normalize(
        self,
        session: Session,
        assessment: models.Assessment,
        capability: str,
        request: dict[str, Any],
        result: ParsedResult,
    ) -> None:
        handler = self._handlers.get(capability)
        if handler is None:
            raise NoNormalizerRegisteredError(
                f"No normalizer registered for capability {capability!r}."
            )
        handler(session, assessment, request, result)


def get_or_create_asset(
    session: Session,
    *,
    assessment_id: UUID,
    asset_type: models.AssetType,
    canonical_key: str,
    attributes: dict[str, Any],
) -> models.Asset:
    """Dedupes on the same `(assessment_id, asset_type, canonical_key)`
    unique constraint the schema already enforces (Phase 1) — a second
    observation about the same asset merges its attributes in rather than
    creating a duplicate row."""
    existing = session.scalar(
        select(models.Asset).where(
            models.Asset.assessment_id == assessment_id,
            models.Asset.asset_type == asset_type,
            models.Asset.canonical_key == canonical_key,
        )
    )
    if existing is not None:
        existing.attributes = {**existing.attributes, **attributes}
        session.flush()
        return existing
    asset = models.Asset(
        assessment_id=assessment_id,
        asset_type=asset_type,
        canonical_key=canonical_key,
        attributes=attributes,
    )
    session.add(asset)
    session.flush()
    return asset


def get_or_create_finding(
    session: Session,
    *,
    assessment_id: UUID,
    asset_id: UUID,
    title: str,
    severity: models.FindingSeverity,
    confidence: float,
    source: str,
    affected_component: str,
) -> tuple[models.Finding, bool]:
    """Dedupe/fingerprint key: `(assessment_id, asset_id, source,
    affected_component)` — docs/data/findings.md doesn't name an exact
    fingerprint algorithm, so this is the smallest reasonable one: the
    same source re-reporting the same affected component on the same
    asset, within the same assessment, is the same finding rediscovered,
    not a new one. Rediscovery bumps `last_seen` rather than creating a
    duplicate row. Returns `(finding, created)`.
    """
    existing = session.scalar(
        select(models.Finding).where(
            models.Finding.assessment_id == assessment_id,
            models.Finding.asset_id == asset_id,
            models.Finding.source == source,
            models.Finding.affected_component == affected_component,
        )
    )
    if existing is not None:
        existing.last_seen = datetime.now(UTC)
        session.flush()
        return existing, False

    finding = models.Finding(
        assessment_id=assessment_id,
        asset_id=asset_id,
        title=title,
        severity=severity,
        confidence=confidence,
        source=source,
        affected_component=affected_component,
        status=models.FindingStatus.DISCOVERED,
    )
    session.add(finding)
    session.flush()
    return finding, True


def write_observation(
    session: Session,
    *,
    observation_type: models.ObservationType,
    source: str,
    asset: models.Asset,
    tool_execution_id: UUID | None,
    confidence: float,
    data: dict[str, Any],
) -> models.Observation:
    observation = models.Observation(
        type=observation_type,
        source=source,
        asset_id=asset.id,
        tool_execution_id=tool_execution_id,
        confidence=confidence,
        data=data,
    )
    session.add(observation)
    session.flush()
    return observation
