"""The agent framework — Phase 5.

Gives an LLM session (a) a specific objective, (b) a bounded, named
toolset it may call through the Tool Registry, and (c) a typed output
contract it must satisfy — per docs/architecture/agent-architecture.md
section 1 and the "bounded agency" rule in docs/architecture/
security-boundary.md.

No concrete LLM provider is wired yet — see
backend/src/offensivex/llm/base.py and docs/roadmap/current-status.md's
queued-access note (an LLM API key is needed to exercise a real agent
call; the framework itself is proven here against a scripted/fake
provider, same as a real one would be driven).
"""
