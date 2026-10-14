"""The Reporting Agent — Phase 14.

docs/reporting/reporting.md: deterministic sections are assembled
directly from stored data, never paraphrased by an LLM; only the
executive summary is AI-authored, and even that must cite evidence IDs
that actually exist and is always labeled as AI-generated. This agent
makes no tool calls at all ("Tools: None against the target",
docs/agents/reporting-agent.md) — unlike every other agent, there is no
AgentSession/toolset here, just one optional, single-shot LLM call for
the prose section.
"""
