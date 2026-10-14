# Network safety: port scope and connection-time address policy

**Status: IMPLEMENTED and VERIFIED** (Guardrail §7 vocabulary; the verification is listed in [../roadmap/current-status.md](../roadmap/current-status.md#network-safety-port-scope-and-dns-pinning-verified-before-p15)). Decision: [ADR-024](../Decision.md). Guardrail rules this implements: [§2.7 and §2.8](../Guardrail.md#2-scope-mandatory-default-deny).

A hostname is only a label. Authorizing `app.example.com` says nothing about *which address* it resolves to or *which port* may be contacted. Two enforcement points close that gap; both apply to **every** tool execution regardless of what the model asked for, because they live in the Tool Registry and the connecting adapter, not in an agent.

```
agent request ──► adapter.plan()  ── host + port from ONE strict URL parse
                       │
                       ▼
              Scope Guard (registry)  ── host rule AND port rule, default-deny, exclude wins
                       │ allowed
                       ▼
              adapter.run()  ── resolve ONCE ─► validate EVERY address ─► connect to the
                                IP literal ─► verify the peer ─► (TLS vs original hostname)
```

## 1. Port scope

`scope_rules.ports` (nullable) is a comma-separated list of ports and ranges, e.g. `80,443,8000-8100`. Each entry is within 1–65535; `1-65535` (every port) is rejected as a catch-all, like `0.0.0.0/0`. The list is validated and normalized when an authorization is submitted (`422 Invalid scope rule` otherwise) and stored canonical (`8443, 80,8000-8100` → `80,8000-8100,8443`).

| Rule | `ports` omitted (legacy / host-only) | `ports` given |
|---|---|---|
| **include** | the web defaults **80 and 443 only** | exactly those ports (the defaults are *not* added) |
| **exclude** | **every** port on the host | only those ports |

There is no "all ports" form for an include rule: a hostname grant never silently authorizes every port. Exclude still wins over include, per port.

The port that is checked is the one the adapter will connect to, taken from the same normalized URL as the host (`https://h/` → 443, `http://h/` → 80, explicit ports as written). `ExecutionPlan.ports` carries it; the registry passes it to the Scope Guard together with the host. A capability that never connects to the destination (DNS resolution) declares no port and is checked on the host only: includes match on the host, and only a host-wide exclusion applies.

**Where it is enforced:** `tools/scope_guard.py` (`check_destination(host, rules, port)`), called by `ToolRegistry.execute()` for `http_probe`, `security_header_scan` and `security_header_validation_check`; at authorization submission and at assessment creation for the target's entry point (`services/targets.py`).

### Compatibility and migration (migration `0006_scope_rule_ports`)

- The migration is **additive**: one nullable column plus a shape CHECK. No row is rewritten, renamed or deleted, and downgrade keeps every rule (it only drops the port lists).
- Existing rules all get `ports = NULL`, so they keep their host but are **narrower** than before: includes now cover 80/443 only (before, the Scope Guard ignored ports, so they covered everything). Nothing is widened by the upgrade. Existing exclusions keep excluding the host everywhere.
- A target that is assessed on a non-default port (including any target whose `entry_point` has one) fails closed after the upgrade: assessment creation is refused with `Entry point outside authorized scope` and a probe is denied with a message naming the port. The fix is a **new authorization version** whose rule lists the port; the old version stays untouched as the audit record. The migration does not invent a port grant for existing authorizations.
- API: `POST /targets/{id}/authorizations` accepts an optional `ports` on each rule; clients that do not send it behave as the host-only form above. The audit row records the rules as submitted.

## 2. Connection-time address policy

Implemented in `tools/network_guard.py`, used by `tools/adapters/http_probe.py` (and, through it, the two security-header capabilities).

1. **Resolve once.** The hostname is resolved a single time per request. An IP-literal host is not resolved at all.
2. **Validate every answer** (`check_resolved_addresses`). One bad answer rejects the whole resolution; a mixed public/private answer is *not* filtered down to its public part.
   - **Never allowed, with any setting or rule:** cloud-metadata addresses (`169.254.169.254`, `169.254.170.2`, `168.63.129.16`, `100.100.100.200`, `192.0.0.192`, `fd00:ec2::254`) and IPv6 forms that wrap them; an unparseable answer; an empty answer.
   - **Denied by an exclude rule** matching the address and port (CIDR exclusions apply to the *resolved* address too).
   - **Allowed:** a globally routable unicast address — the hostname's own scope rule authorized the name.
   - **Everything else** (loopback, private, link-local, unspecified, multicast, reserved, carrier-grade NAT, documentation ranges, and `::ffff:a.b.c.d` / NAT64 / 6to4 forms that embed such an IPv4) is allowed **only if** the deployment sets `OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true` **and** the scope explicitly covers that address: an include `cidr` rule matching address *and port*, or the destination *is* that exact IP literal, or it is a loopback-by-definition name (`localhost`, `*.localhost`) resolving to a loopback address. A public-looking hostname that resolves to `127.0.0.1` therefore needs an explicit `cidr` rule even in a lab.
3. **Connect to the approved IP literal, never the name.** The adapter calls `socket.create_connection((ip, port))`, so no second lookup exists that could be rebound. Candidates are tried in resolver order (dual-stack fallback) but only from the approved list.
4. **Verify the peer.** `getpeername()` must equal the approved address, else the connection is dropped and the request denied.
5. **TLS and Host.** For `https` the socket is wrapped with `server_hostname=<original hostname>` and a default verifying context (certificate chain **and** hostname checked; there is no way to turn verification off). The `Host:` header is the original name, with the port when it is not the scheme default.
6. **No context, no connection.** `ToolRegistry` attaches a `NetworkContext` (the authorization's rules and the deployment's private-target switch) after the Scope Guard passes; an adapter that is not given one refuses to connect.

A refusal at step 2 or 4 is a **scope refusal**: the `ToolExecution` row is recorded `DENIED` and `ScopeViolationError` is raised (the same outcome as an out-of-scope hostname), not a generic tool failure.

`OFFENSIVEX_ALLOW_PRIVATE_TARGETS` previously only governed what could be *written* into scope rules and entry points. It now also governs what the tools may *connect to*: `ToolRegistry(allow_private_targets=...)`, set from settings by the CLI pipeline (`build_default_registry`). A registry built without it denies non-public destinations (default-deny).

### Redirects

The HTTP probe **reports redirects and never follows them.** A `3xx` response and its `Location` header are returned as data. Because nothing is followed, a redirect cannot take the probe to a host, port or address that was not authorized. To contact the redirect target an agent must request it as a new `http_probe`, which passes the Scope Guard and the address policy like any other request (verified: a redirect to an unauthorized port or host is refused as a new request, and the target server records zero hits).

## 3. Remaining limits (not hidden)

- **Redirect following is not implemented.** If a capability needs it, each hop must re-run the Scope Guard (host and port), the address policy and the pinned connect; that is a deliberate future feature, not a one-line change.
- **`dns_resolution` is an observation, not a connection.** It reports whatever the resolver returned, including private or metadata addresses, as data; it connects to nothing. The policy bites when something connects.
- **Only the HTTP probe family connects today.** Any future adapter that opens a connection must declare `ExecutionPlan.ports` and use `check_resolved_addresses` + `verify_peer`; the registry cannot infer that an adapter forgot. An adapter that omits `ports` is checked on the host only.
- **Resolver trust.** The system resolver answers the one lookup; a malicious resolver can return a wrong-but-public address, which stays inside the *hostname's* authorization (the address policy bounds *what class* of address, not that the resolver is honest). DNSSEC / DoH pinning is not implemented.
- **Port scope covers TCP ports of HTTP(S) requests.** There is no UDP, no per-path scope, and no scheme-vs-port check (`http` to 443 is allowed if 443 is in scope).
- **The adapter runs in-process**, not yet inside the sandbox ([../tools/sandbox.md](../tools/sandbox.md)), so there is no network-namespace egress filter as a second layer.
- **TLS tests need the `openssl` CLI** to generate a throwaway certificate; without it those three tests skip (they ran in the verification below).
