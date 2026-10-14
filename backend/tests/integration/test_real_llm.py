"""Opt-in tests against a REAL language model. They cost money and need network
access, so they are skipped unless you configure a provider and ask for them:

    # PowerShell (or put the same variables in backend/.env)
    $env:OFFENSIVEX_LLM_ENABLED = "true"
    $env:OFFENSIVEX_LLM_PROVIDER = "anthropic"          # or openai / local
    $env:OFFENSIVEX_LLM_MODEL = "<model id>"
    $env:OFFENSIVEX_LLM_API_KEY = "<your key>"
    pytest -m real_llm tests/integration/test_real_llm.py -v

Nothing here needs PostgreSQL. They check what mocks cannot: that the real
provider returns schema-valid output, that a real model follows the agent-step
contract and the trusted/untrusted prompt layout, and that a real summary
passes the evidence-grounding check. Until you have run them with your own
key, the real-provider path is *implemented* but not *verified*.
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import BaseModel

from offensivex.agents.recon import RECON_AGENT_DEFINITION
from offensivex.agents.runtime import AgentStep, _build_prompt
from offensivex.core.config import Settings
from offensivex.llm.base import LLMProvider, get_llm_provider
from offensivex.reporting.builder import generate_executive_summary

pytestmark = pytest.mark.real_llm

# Read the real configuration at import (collection) time, before the test
# suite's own isolation fixture runs. A bad configuration must not break
# collection of the rest of the suite, so it is reported when a test runs.
try:
    _REAL_SETTINGS: Settings | None = Settings()
    _CONFIG_ERROR = ""
except ValueError as exc:
    _REAL_SETTINGS, _CONFIG_ERROR = None, str(exc)


@pytest.fixture(scope="module")
def provider() -> LLMProvider:
    if _REAL_SETTINGS is None:
        pytest.skip(f"OFFENSIVEX_LLM_* configuration is invalid: {_CONFIG_ERROR}")
    if not _REAL_SETTINGS.llm_enabled:
        pytest.skip(
            "Real-LLM tests are opt-in: set OFFENSIVEX_LLM_ENABLED=true and the "
            "OFFENSIVEX_LLM_PROVIDER / _MODEL / _API_KEY variables (see this file's docstring)."
        )
    return get_llm_provider(_REAL_SETTINGS)


class Arithmetic(BaseModel):
    answer: int


def test_provider_returns_schema_valid_output(provider: LLMProvider) -> None:
    result = asyncio.run(
        provider.generate_structured(
            prompt="What is 2 + 2? Put the number in `answer`.", schema=Arithmetic
        )
    )
    assert isinstance(result, Arithmetic) and result.answer == 4


def test_real_model_follows_the_agent_step_contract(provider: LLMProvider) -> None:
    prompt = _build_prompt(
        RECON_AGENT_DEFINITION,
        [],
        turn=1,
        task_context={
            "target": "lab",  # deliberately no hint of the port in the name
            "entry_point": "http://lab.example:8443/",
            "in_scope": [{"type": "domain", "pattern": "lab.example"}],
            "excluded": [],
        },
    )
    # A model is nondeterministic, so judge the contract over several draws:
    # every draw must be a valid step that stays inside the toolset and the
    # authorized scope, and the model must actually act on at least one.
    steps = [
        asyncio.run(provider.generate_structured(prompt=prompt, schema=AgentStep)) for _ in range(3)
    ]
    assert all(isinstance(step, AgentStep) for step in steps)
    calls = [step for step in steps if step.action == "call_tool"]
    for step in calls:
        assert step.capability in RECON_AGENT_DEFINITION.allowed_capabilities
        assert "lab.example" in str(step.request)  # nothing outside the scope it was given
    assert calls, f"the model never chose to act in {len(steps)} draws: {steps}"
    # It must use the configured entry point's port rather than guess one.
    probes = [step for step in calls if step.capability == "http_probe"]
    assert probes, f"the model never probed HTTP in {len(steps)} draws: {steps}"
    assert any("lab.example:8443" in str(step.request) for step in probes), probes


def test_real_summary_is_grounded_in_the_reports_own_evidence(provider: LLMProvider) -> None:
    evidence_id = "11111111-1111-1111-1111-111111111111"
    report_data = {
        "scope": {"target_name": "lab.example"},
        "attack_surface": [{"asset_type": "endpoint", "canonical_key": "https://lab.example/"}],
        "findings": [
            {
                "id": "f1",
                "title": "Missing security header: X-Frame-Options",
                "severity": "medium",
                "status": "confirmed",
                "affected_component": "X-Frame-Options",
                "risk_score": 4.2,
                "risk_band": "medium",
            }
        ],
        "attack_paths": [],
        "risk_analysis": {"band_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0}},
        "evidence": [
            {
                "id": evidence_id,
                "finding_id": "f1",
                "kind": "validation_result",
                "excerpt": "Validation check on 'https://lab.example/': 'X-Frame-Options' "
                "confirmed missing.",
            }
        ],
    }
    summary = generate_executive_summary(provider, report_data)
    assert summary["ai_generated"] is True
    assert set(summary["cited_evidence_ids"]) <= {evidence_id}
