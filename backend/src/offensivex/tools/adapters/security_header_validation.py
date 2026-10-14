"""The one registered non-destructive validation check for the missing-
security-header finding class — Phase 10.

docs/agents/validation-agent.md: "a single inert request that proves a
condition exists without exfiltrating data or changing state ... one
check per class, defined and reviewed ahead of time." For this class,
docs/roadmap/implementation-blueprint.md section 10 names it exactly:
"re-request and verify the header is still absent, nothing more
invasive." That is the same request `SecurityHeaderScanAdapter` already
makes — composed here, not reimplemented — under a *different*
capability name so it carries its own `requires_validation_mode=True`
tag. That tag is what makes the Tool Registry's existing validation gate
(Phase 3, `offensivex.tools.registry`) actually refuse this specific
capability when an assessment hasn't opted into validation — the
discovery/investigation uses of the identical HTTP request are
deliberately a *different* capability (`security_header_scan`,
`requires_validation_mode=False`) because discovery and investigation are
not gated the same way validation is (docs/security/validation.md).
"""

from __future__ import annotations

from typing import Any

from offensivex.tools.adapters.security_header_scan import SecurityHeaderScanAdapter
from offensivex.tools.registry import (
    AdapterMeta,
    ExecutionPlan,
    IntegrationStatus,
    Intrusiveness,
    ParsedResult,
)


class SecurityHeaderValidationCheck:
    """`request = {"url": ..., "header": "Strict-Transport-Security"}` —
    `header` is the specific finding's `affected_component`, naming which
    one check's outcome this call establishes (a validation check proves
    or disproves one specific condition, never a batch of them)."""

    def __init__(self, scanner: SecurityHeaderScanAdapter | None = None) -> None:
        self._scanner = scanner or SecurityHeaderScanAdapter()
        self.meta = AdapterMeta(
            name="security_header_validation_check",
            capability="security_header_validation_check",
            intrusiveness=Intrusiveness.LOW,
            requires_validation_mode=True,
            status=IntegrationStatus.IMPLEMENTED,
        )

    def plan(self, request: dict[str, Any]) -> ExecutionPlan:
        scan_plan = self._scanner.plan({"url": request["url"]})
        return ExecutionPlan(
            capability=self.meta.capability, destinations=scan_plan.destinations, request=request
        )

    def run(self, plan: ExecutionPlan) -> bytes:
        scan_plan = self._scanner.plan({"url": plan.request["url"]})
        return self._scanner.run(scan_plan)

    def parse(self, raw_artifact: bytes) -> ParsedResult:
        scan_result = self._scanner.parse(raw_artifact)
        return ParsedResult(capability=self.meta.capability, data=scan_result.data)
