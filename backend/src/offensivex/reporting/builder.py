"""Report assembly — Phase 14.

`build_report_data()` is the deterministic part: every section comes
straight from stored rows, so it can never drift from what was actually
found (docs/reporting/reporting.md). `generate_executive_summary()` is
the one AI-authored section, grounded (every cited evidence ID must
actually exist — `UngroundedCitationError` otherwise) and always labeled
`ai_generated: True` in the output. `render_markdown()` escapes every
untrusted string (finding titles, asset keys, evidence excerpts) before
it goes anywhere near Markdown syntax — "all evidence rendered into any
format is treated as untrusted and escaped" (same document).

Sections shipped for the MVP (docs/reporting/reporting.md's 11-section
list, trimmed to what this repository can honestly populate so far):
Scope, Attack Surface, Findings, Confirmed Vulnerabilities, Evidence,
Attack Paths, Risk Analysis, Executive Summary, Technical Appendix.
**Technologies** and **Remediation** are deliberately minimal — no
technology-fingerprinting capability exists yet (that is a Recon
capability this project hasn't built), and remediation is one fixed,
deterministic sentence per the one finding class that exists, not
LLM-authored prose (keeping remediation deterministic, unlike the
original design's looser framing, avoids citing evidence for advice that
isn't really grounded in anything finding-specific yet).
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.core.errors import OffensiveXError
from offensivex.db import models
from offensivex.llm.base import LLMProvider
from offensivex.risk.engine import RISK_MODEL_VERSION
from offensivex.services.findings import mark_finding_reported

_REMEDIATION_BY_COMPONENT = {
    "Strict-Transport-Security": (
        "Set the Strict-Transport-Security response header to instruct browsers to "
        "only ever connect over HTTPS."
    ),
    "X-Content-Type-Options": (
        "Set the X-Content-Type-Options response header to 'nosniff' to stop browsers "
        "from MIME-sniffing a response away from its declared content type."
    ),
    "X-Frame-Options": (
        "Set the X-Frame-Options response header (or a frame-ancestors Content-Security-"
        "Policy directive) to prevent the page from being framed by another origin."
    ),
}


class UngroundedCitationError(OffensiveXError):
    status_code = 422
    title = "Ungrounded citation"


class ExecutiveSummaryOutput(BaseModel):
    summary: str
    cited_evidence_ids: list[str]


def _escape_markdown(text: str) -> str:
    """Backslash-escape Markdown's special characters so untrusted
    content (a finding title, an asset key) can never be interpreted as
    formatting syntax."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!>|])", r"\\\1", text)


def _indented_code_block(text: str) -> str:
    """A 4-space-indented block has no delimiter sequence to escape or
    break out of (unlike a fenced ``` block, where the content could
    contain its own triple-backtick) — the safest way to render an
    untrusted excerpt verbatim."""
    return "\n".join(f"    {line}" for line in text.splitlines()) or "    (empty)"


def build_report_data(session: Session, assessment: models.Assessment) -> dict[str, Any]:
    target = assessment.target
    scope_rules = assessment.authorization.scope_rules

    assets = list(
        session.scalars(select(models.Asset).where(models.Asset.assessment_id == assessment.id))
    )
    findings = list(
        session.scalars(select(models.Finding).where(models.Finding.assessment_id == assessment.id))
    )
    evidence = list(
        session.scalars(
            select(models.Evidence)
            .join(models.Finding)
            .where(models.Finding.assessment_id == assessment.id)
        )
    )
    attack_paths = list(
        session.scalars(
            select(models.AttackPath).where(models.AttackPath.assessment_id == assessment.id)
        )
    )
    agent_runs = list(
        session.scalars(
            select(models.AgentRun).where(models.AgentRun.assessment_id == assessment.id)
        )
    )

    confirmed = [f for f in findings if f.status is models.FindingStatus.CONFIRMED]

    return {
        "assessment_id": str(assessment.id),
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": {
            "target_id": str(target.id),
            "target_name": target.name,
            "scope_rules": [
                {"rule_type": r.rule_type, "pattern": r.pattern, "is_exclusion": r.is_exclusion}
                for r in scope_rules
            ],
        },
        "attack_surface": [
            {
                "asset_id": str(a.id),
                "asset_type": a.asset_type.value,
                "canonical_key": a.canonical_key,
            }
            for a in assets
        ],
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value,
                "status": f.status.value,
                "confidence": f.confidence,
                "affected_component": f.affected_component,
                "risk_score": f.risk_score,
                "risk_band": (f.risk_breakdown or {}).get("risk_band"),
            }
            for f in findings
        ],
        "confirmed_vulnerabilities": [str(f.id) for f in confirmed],
        "evidence": [
            {
                "id": str(e.id),
                "finding_id": str(e.finding_id),
                "kind": e.kind.value,
                "excerpt": e.excerpt,
                "captured_at": e.captured_at.isoformat(),
            }
            for e in evidence
        ],
        "attack_paths": [
            {
                "id": str(p.id),
                "entry_node_id": str(p.entry_node_id),
                "target_node_id": str(p.target_node_id),
                "evidence_level": p.evidence_level.value,
                "edge_count": len(p.edge_ids),
            }
            for p in attack_paths
        ],
        "risk_analysis": {
            "model_version": RISK_MODEL_VERSION,
            "scored_findings": sum(1 for f in findings if f.risk_score is not None),
            "band_counts": {
                band: sum(1 for f in findings if (f.risk_breakdown or {}).get("risk_band") == band)
                for band in ("critical", "high", "medium", "low")
            },
        },
        "remediation": [
            {"affected_component": f.affected_component, "advice": advice}
            for f in confirmed
            if (advice := _REMEDIATION_BY_COMPONENT.get(f.affected_component or ""))
        ],
        "technical_appendix": {
            "agent_run_ids": [str(r.id) for r in agent_runs],
            "risk_model_version": RISK_MODEL_VERSION,
        },
    }


def generate_executive_summary(
    llm_provider: LLMProvider, report_data: dict[str, Any]
) -> dict[str, Any]:
    """Grounded: every ID in `cited_evidence_ids` must be one of this
    report's actual evidence IDs, or this raises rather than ship an
    unverifiable citation (Guardrail.md section 5's grounding rule,
    applied here exactly as it is to agent reasoning elsewhere).
    """
    valid_ids = {item["id"] for item in report_data["evidence"]}
    prompt = (
        "Write a short executive summary of this security assessment, grounded only "
        "in the data below. Cite the evidence IDs your claims are based on.\n\n"
        f"{report_data}"
    )
    output: ExecutiveSummaryOutput = asyncio.run(
        llm_provider.generate_structured(prompt=prompt, schema=ExecutiveSummaryOutput)
    )

    ungrounded = set(output.cited_evidence_ids) - valid_ids
    if ungrounded:
        raise UngroundedCitationError(
            f"Executive summary cited evidence ID(s) not present in this report: {ungrounded}"
        )

    return {
        "text": output.summary,
        "ai_generated": True,
        "cited_evidence_ids": output.cited_evidence_ids,
    }


def render_markdown(report_data: dict[str, Any]) -> str:
    lines: list[str] = [f"# Security Assessment Report — {report_data['assessment_id']}", ""]

    summary = report_data.get("executive_summary")
    if summary is not None:
        lines += ["## Executive Summary (AI-generated)", _escape_markdown(summary["text"]), ""]

    lines += ["## Scope", f"Target: {_escape_markdown(report_data['scope']['target_name'])}", ""]
    for rule in report_data["scope"]["scope_rules"]:
        prefix = "exclude" if rule["is_exclusion"] else "include"
        lines.append(f"- {prefix}: `{_escape_markdown(rule['pattern'])}` ({rule['rule_type']})")
    lines.append("")

    lines.append("## Attack Surface")
    for asset in report_data["attack_surface"]:
        lines.append(f"- {asset['asset_type']}: {_escape_markdown(asset['canonical_key'])}")
    lines.append("")

    lines.append("## Findings")
    for finding in report_data["findings"]:
        lines.append(
            f"- [{finding['status'].upper()}] {_escape_markdown(finding['title'])} "
            f"(severity={finding['severity']}, risk_score={finding['risk_score']})"
        )
    lines.append("")

    lines.append("## Confirmed Vulnerabilities")
    confirmed_ids = set(report_data["confirmed_vulnerabilities"])
    for finding in report_data["findings"]:
        if finding["id"] in confirmed_ids:
            lines.append(f"- {_escape_markdown(finding['title'])}")
    if not confirmed_ids:
        lines.append("- None.")
    lines.append("")

    lines.append("## Evidence")
    for item in report_data["evidence"]:
        lines.append(f"### `{item['id']}` ({item['kind']})")
        lines.append(_indented_code_block(item["excerpt"]))
        lines.append("")

    lines.append("## Attack Paths")
    for path in report_data["attack_paths"]:
        lines.append(f"- {path['id']} (evidence_level={path['evidence_level']})")
    if not report_data["attack_paths"]:
        lines.append("- None.")
    lines.append("")

    lines.append("## Risk Analysis")
    for band, count in report_data["risk_analysis"]["band_counts"].items():
        lines.append(f"- {band}: {count}")
    lines.append("")

    lines.append("## Remediation")
    for item in report_data["remediation"]:
        lines.append(f"- **{item['affected_component']}**: {_escape_markdown(item['advice'])}")
    if not report_data["remediation"]:
        lines.append("- None.")
    lines.append("")

    lines.append("## Technical Appendix")
    lines.append(
        f"- Risk model version: `{report_data['technical_appendix']['risk_model_version']}`"
    )
    lines.append(f"- Agent runs: {len(report_data['technical_appendix']['agent_run_ids'])}")

    return "\n".join(lines)


def build_report(
    session: Session,
    assessment: models.Assessment,
    *,
    formats: list[str] | None = None,
    llm_provider: LLMProvider | None = None,
) -> models.Report:
    """Assembles the report, marks every included finding REPORTED (the
    last lifecycle edge, Phase 11), and persists an immutable `Report`
    row. `llm_provider=None` (the default — no concrete provider is
    wired yet, see docs/roadmap/current-status.md) skips the executive
    summary entirely rather than fabricate one.
    """
    formats = formats or ["json", "markdown"]
    report_data = build_report_data(session, assessment)

    if llm_provider is not None:
        report_data["executive_summary"] = generate_executive_summary(llm_provider, report_data)
    else:
        report_data["executive_summary"] = None

    findings = session.scalars(
        select(models.Finding).where(models.Finding.assessment_id == assessment.id)
    ).all()
    for finding in findings:
        if finding.status is not models.FindingStatus.REPORTED:
            mark_finding_reported(session, finding.id)

    report = models.Report(
        assessment_id=assessment.id,
        formats=formats,
        provenance={
            "risk_model_version": RISK_MODEL_VERSION,
            "generated_at": report_data["generated_at"],
            "ai_generated_executive_summary": llm_provider is not None,
        },
        content_json=report_data if "json" in formats else None,
        content_markdown=render_markdown(report_data) if "markdown" in formats else None,
    )
    session.add(report)
    session.flush()
    return report
