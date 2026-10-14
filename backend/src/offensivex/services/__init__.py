"""Domain services: the layer between API routes and the ORM.

Per CLAUDE.md section 14 ("API rules"): REST/gRPC handlers hold no business
logic; they call a service function, which reads/writes through the ORM.
Phase 2 introduces this layer for the first three entities with a real
lifecycle (Target, Authorization, Assessment) plus the Orchestrator's
initial scheduling decision.
"""
