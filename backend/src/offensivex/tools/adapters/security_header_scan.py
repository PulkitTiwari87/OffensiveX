"""Security header scan — the Phase 8 vertical-slice vulnerability check.

docs/roadmap/implementation-blueprint.md section 10 picks exactly this
finding class for the project's first vertical slice: "a missing/
misconfigured security header ... genuinely low-risk to validate non-
destructively," specifically to keep the first end-to-end proof focused
on the *architecture* (recon -> vulnerability -> investigation ->
validation -> evidence -> finding -> graph -> risk -> report) rather than
on scanner breadth or exploit sophistication.

Reuses `HttpProbeAdapter`'s real IP-pinned GET (one real, passive request)
rather than a second, separate HTTP client — this capability's own job is
only the *evaluation* of the response headers already fetched, which is
exactly what a template-based scanner (the "candidate" Nuclei,
docs/tools/tool-registry.md) would also be doing under the hood for this
specific check class. No new dependency.
"""

from __future__ import annotations

from typing import Any

from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.registry import (
    AdapterMeta,
    ExecutionPlan,
    IntegrationStatus,
    Intrusiveness,
    ParsedResult,
)

# header (lowercase, as HTTP header names are matched case-insensitively) ->
# display name. A small, well-known set — not exhaustive; additional
# headers are added deliberately, each justified by an actual finding
# class being added, not speculatively (CLAUDE.md section 20).
CHECKED_HEADERS: dict[str, str] = {
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
}


class SecurityHeaderScanAdapter:
    """`request = {"url": "https://example.com/"}` — the same shape
    `HttpProbeAdapter` takes, since this *is* an HTTP probe, evaluated
    differently."""

    def __init__(self, http_probe: HttpProbeAdapter | None = None) -> None:
        self._http_probe = http_probe or HttpProbeAdapter()
        self.meta = AdapterMeta(
            name="security_header_scan",
            capability="security_header_scan",
            intrusiveness=Intrusiveness.LOW,  # one GET request, same as http_probe
            requires_validation_mode=False,
            status=IntegrationStatus.IMPLEMENTED,
        )

    def plan(self, request: dict[str, Any]) -> ExecutionPlan:
        probe_plan = self._http_probe.plan(request)
        return ExecutionPlan(
            capability=self.meta.capability,
            destinations=probe_plan.destinations,
            request=request,
        )

    def run(self, plan: ExecutionPlan) -> bytes:
        probe_plan = self._http_probe.plan(plan.request)
        return self._http_probe.run(probe_plan)

    def parse(self, raw_artifact: bytes) -> ParsedResult:
        probe_result = self._http_probe.parse(raw_artifact)
        present = {key.lower() for key in probe_result.data.get("headers", {})}
        missing_headers = [
            display_name
            for header_key, display_name in CHECKED_HEADERS.items()
            if header_key not in present
        ]
        return ParsedResult(
            capability=self.meta.capability,
            data={
                "status_code": probe_result.data.get("status_code"),
                "missing_headers": missing_headers,
            },
        )
