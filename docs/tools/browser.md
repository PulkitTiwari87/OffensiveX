# Browser Automation

Status: PLANNED
Related: [tool-registry.md](tool-registry.md) · [sandbox.md](sandbox.md)

## Why a browser tool exists

Some web-application behavior (client-side rendering, multi-step flows, JavaScript-driven state) cannot be observed with a plain HTTP client. A browser-automation capability lets the Investigation and Validation agents observe what actually renders and capture screenshots/DOM state as evidence, rather than guessing from raw HTML.

## Planned capability

| Capability | Candidate implementation | Status |
|---|---|---|
| Headless browser navigation, interaction, screenshot capture | Playwright | PLANNED |
| Proxy/interception (observe requests a page actually makes) | mitmproxy or equivalent, routed through the sandbox | PLANNED |

## Constraints

Runs inside the same sandbox as every other tool (see [sandbox.md](sandbox.md)): no access to the operator's own browser profile/cookies/credentials, a fresh isolated browser context per invocation, network egress restricted to in-scope destinations, and every navigation target scope-checked before it's requested — a page redirecting to an out-of-scope origin is not followed. Screenshots and DOM captures become `Evidence` ([../data/evidence-model.md](../data/evidence-model.md)), never raw unretained artifacts.
