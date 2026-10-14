"""Unit tests for report rendering/grounding — no DB (Phase 14)."""

from __future__ import annotations

from typing import Any

import pytest

from offensivex.reporting.builder import (
    ExecutiveSummaryOutput,
    UngroundedCitationError,
    _escape_markdown,
    generate_executive_summary,
    render_markdown,
)


class _ScriptedProvider:
    name = "scripted"

    def __init__(self, output: ExecutiveSummaryOutput) -> None:
        self._output = output

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        return self._output


def _data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "assessment_id": "a1",
        "scope": {"target_name": "t", "scope_rules": []},
        "attack_surface": [],
        "findings": [],
        "confirmed_vulnerabilities": [],
        "evidence": [{"id": "e1", "finding_id": "f1", "kind": "validation_result", "excerpt": "x"}],
        "attack_paths": [],
        "risk_analysis": {"band_counts": {"high": 0}},
        "remediation": [],
        "technical_appendix": {"risk_model_version": "v1", "agent_run_ids": []},
        "executive_summary": None,
    }
    data.update(overrides)
    return data


def test_escape_markdown_neutralizes_formatting_characters() -> None:
    escaped = _escape_markdown("# [click](http://evil) `x` *b*")
    for ch in "#[]()`*":
        assert f"\\{ch}" in escaped


def test_untrusted_finding_title_cannot_inject_markdown() -> None:
    data = _data(
        findings=[
            {
                "id": "f1",
                "title": "# Injected heading",
                "status": "confirmed",
                "severity": "medium",
                "risk_score": 1.0,
            }
        ]
    )
    md = render_markdown(data)
    assert "\n## Injected" not in md
    assert "\\# Injected heading" in md


def test_evidence_excerpt_with_code_fence_cannot_break_out() -> None:
    data = _data(
        evidence=[{"id": "e1", "kind": "x", "excerpt": "```\n# Owned\n<script>x</script>"}]
    )
    md = render_markdown(data)
    # Every excerpt line is indented as a code block, so none starts a heading.
    assert "\n# Owned" not in md
    assert "    # Owned" in md


def test_executive_summary_is_labeled_ai_generated() -> None:
    provider = _ScriptedProvider(ExecutiveSummaryOutput(summary="ok", cited_evidence_ids=["e1"]))
    summary = generate_executive_summary(provider, _data())  # type: ignore[arg-type]
    assert summary["ai_generated"] is True
    md = render_markdown(_data(executive_summary=summary))
    assert "## Executive Summary (AI-generated)" in md


def test_ungrounded_citation_is_rejected() -> None:
    provider = _ScriptedProvider(
        ExecutiveSummaryOutput(summary="claim", cited_evidence_ids=["does-not-exist"])
    )
    with pytest.raises(UngroundedCitationError):
        generate_executive_summary(provider, _data())  # type: ignore[arg-type]


def test_no_summary_section_without_a_provider() -> None:
    assert "Executive Summary" not in render_markdown(_data())
