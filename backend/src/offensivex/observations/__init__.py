"""The tool -> observation normalization path — Phase 7.

docs/data/observations.md: "Tool -> Observation -> Correlation ->
Investigation -> Finding." The `Observation` model itself is Phase 1;
this package is the generalized, agent-agnostic normalizer extracted from
Phase 6's Recon-specific version, so later agents (Vulnerability, Phase 8+)
register their own capability handlers rather than re-deriving the
Asset-upsert-then-Observation-write pattern each time.
"""
