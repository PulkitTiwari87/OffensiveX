"""Port specifications for scope rules ("80,443,8000-8100").

Policy (docs/security/network-safety.md, ADR-024):

- An **include** rule with no `ports` authorizes the web default ports only
  (`DEFAULT_INCLUDE_PORTS`: 80 and 443). A hostname grant never silently means
  "every port"; wider access needs an explicit `ports` list.
- An **exclude** rule with no `ports` excludes the host on *every* port (exclude
  wins, and the fail-safe reading of an exclusion is the broad one). With `ports`
  it excludes only those ports.
- `ports` on a rule is a comma-separated list of single ports and `lo-hi`
  ranges, each within 1-65535. The whole range 1-65535 is a catch-all and is
  rejected, like `0.0.0.0/0` (Guardrail.md section 2.6).
"""

from __future__ import annotations

import re

DEFAULT_INCLUDE_PORTS = "80,443"
MAX_PORT_SPEC_LENGTH = 200
_ITEM = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?")

PortRanges = tuple[tuple[int, int], ...]


class InvalidPortSpecError(ValueError):
    """`ports` is not a valid port list."""


def parse_port_spec(spec: str) -> PortRanges:
    """Parse and validate a port list into sorted, merged `(lo, hi)` ranges."""
    if not isinstance(spec, str) or not spec.strip():
        raise InvalidPortSpecError("Port list is empty.")
    if len(spec) > MAX_PORT_SPEC_LENGTH:
        raise InvalidPortSpecError(f"Port list is longer than {MAX_PORT_SPEC_LENGTH} characters.")
    ranges: list[tuple[int, int]] = []
    for raw_item in spec.split(","):
        item = raw_item.strip()
        match = _ITEM.fullmatch(item)
        if match is None:
            raise InvalidPortSpecError(
                f"Invalid port entry {item!r}: use a port (443) or a range (8000-8100)."
            )
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) is not None else low
        if not (1 <= low <= 65535 and 1 <= high <= 65535):
            raise InvalidPortSpecError(f"Port entry {item!r} is outside 1-65535.")
        if low > high:
            raise InvalidPortSpecError(f"Port range {item!r} is backwards.")
        ranges.append((low, high))
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for low, high in ranges:
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    if merged == [(1, 65535)]:
        raise InvalidPortSpecError("The port list covers every port; that is a catch-all.")
    return tuple(merged)


def normalize_port_spec(spec: str) -> str:
    """Canonical text form of a valid port list (what is stored)."""
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in parse_port_spec(spec))


def port_in_spec(port: int, spec: str) -> bool:
    """True if `port` is in `spec`. An unparseable stored spec matches nothing
    (fail-closed); validation at submission means that cannot normally happen."""
    try:
        ranges = parse_port_spec(spec)
    except InvalidPortSpecError:
        return False
    return any(lo <= port <= hi for lo, hi in ranges)
