# The Sandbox proof image — Phase 4. Minimal on purpose: no tool binaries
# are integrated yet (Nmap/Nuclei/etc. start Phase 6+), so this image only
# needs enough to prove the containerization mechanics themselves
# (timeouts, process-tree kill, no-shell argv invocation, non-root,
# read-only filesystem) — see docs/tools/sandbox.md and
# backend/src/offensivex/sandbox/container.py.
FROM alpine:3.20

RUN addgroup -g 1000 sandbox \
    && adduser -D -u 1000 -G sandbox sandbox

USER sandbox

# No ENTRYPOINT/CMD: every invocation supplies its own argv list
# (ContainerSandbox.run()) — there is nothing to shell-expand or default.
