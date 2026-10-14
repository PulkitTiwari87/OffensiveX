"""The Sandbox — Phase 4.

Containerized execution for tool adapters, per docs/tools/sandbox.md: one
container per tool execution, non-root, read-only filesystem, no network
by default, a wall-clock timeout that kills the whole container (not just
a client process), and a fixture-replay mode that needs no Docker at all.

Not yet wired into any adapter (docs/roadmap/implementation-blueprint.md
section 11's P4 row: "none new" DB/API/agent) — the DNS resolution adapter
from Phase 3 is a stdlib call, not a subprocess, so there is nothing for
it to containerize. This becomes the execution primitive real tool
adapters (Nmap, Nuclei, ...) call starting Phase 6+.
"""
