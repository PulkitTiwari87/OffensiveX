"""Containerized tool execution — Phase 4.

Implements the controls docs/tools/sandbox.md lists: one container per
invocation (`--rm`, unique `--name`), non-root, read-only filesystem
(`--read-only` + a `/tmp` tmpfs for anything that needs to write), no
network by default (`--network none`), resource limits (memory/CPU/PID
count), argv-list invocation only (never a shell, at either the `docker`
CLI layer or inside the container — there is no `ENTRYPOINT`/`CMD` to
shell-expand), and a wall-clock timeout that kills the *container*, not
just the `docker run` client process, which is what makes it an actual
process-tree kill rather than an orphaned background container.

**Known limitation, not hidden:** the output-size cap here truncates
*after* reading the full stdout/stderr into memory, not via a bounded
streaming read. docs/tools/sandbox.md's "resource limits" guarantee
(cannot exhaust host resources, e.g. a decompression-bomb response) is
therefore only partially met by this phase — fully bounding it requires
streaming the container's output with an enforced cap mid-read, which is
worth doing once a real tool adapter (Phase 6+) actually produces output
large enough for it to matter. Flagged here rather than claimed as solved.

Fixture-replay mode (`FixtureReplaySandbox`) needs no Docker at all and is
what lets this module's own tests, and future tool-adapter tests, run
deterministically without a live Docker daemon.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from offensivex.core.errors import OffensiveXError


class SandboxError(OffensiveXError):
    status_code = 503
    title = "Sandbox error"


class SandboxUnavailableError(SandboxError):
    title = "Sandbox unavailable"


class FixtureNotFoundError(SandboxError):
    status_code = 404
    title = "No fixture recorded"


@dataclass(frozen=True)
class SandboxResult:
    exit_status: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    killed: bool


class ContainerSandbox:
    """One container per `run()` call. Requires a working Docker daemon
    (`docker info` reachable) — construction does not check this;
    `run()` raises `SandboxUnavailableError` if the `docker` binary is
    missing or the daemon is unreachable, the same "fail loudly rather
    than silently do nothing" convention as
    offensivex.llm.base.get_llm_provider.
    """

    def __init__(
        self,
        image: str,
        *,
        timeout_seconds: int = 30,
        memory_limit: str = "256m",
        cpu_limit: float = 1.0,
        pids_limit: int = 128,
        network: str = "none",
        output_cap_bytes: int = 10_000_000,
        docker_binary: str = "docker",
    ) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.network = network
        self.output_cap_bytes = output_cap_bytes
        self._docker_binary = docker_binary

    def _docker_run_command(self, name: str, argv: list[str]) -> list[str]:
        return [
            self._docker_binary,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            self.network,
            "--memory",
            self.memory_limit,
            "--cpus",
            str(self.cpu_limit),
            "--pids-limit",
            str(self.pids_limit),
            "--read-only",
            "--tmpfs",
            "/tmp",  # noqa: S108 - a mount target *inside* the container, not a host path
            "--security-opt",
            "no-new-privileges",
            self.image,
            *argv,
        ]

    def run(self, argv: list[str]) -> SandboxResult:
        name = f"offensivex-sandbox-{uuid.uuid4().hex[:12]}"
        command = self._docker_run_command(name, argv)

        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, never shell=True
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailableError(
                f"Docker binary {self._docker_binary!r} not found."
            ) from exc

        timed_out = False
        killed = False
        try:
            stdout, stderr = proc.communicate(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            # Kill the *container*, not just this client process — a bare
            # client-side kill would leave the container running, detached
            # from anything that could ever clean it up.
            subprocess.run(  # noqa: S603
                [self._docker_binary, "kill", name], capture_output=True, check=False
            )
            stdout, stderr = proc.communicate()
            timed_out = True
            killed = True

        exit_status = proc.returncode if proc.returncode is not None else -1
        return SandboxResult(
            exit_status=exit_status,
            stdout=stdout[: self.output_cap_bytes],
            stderr=stderr[: self.output_cap_bytes],
            timed_out=timed_out,
            killed=killed,
        )


class FixtureReplaySandbox:
    """Returns a prerecorded `SandboxResult` for a given argv. No Docker
    required — see module docstring.
    """

    def __init__(self, fixtures: dict[tuple[str, ...], SandboxResult]) -> None:
        self._fixtures = fixtures

    @classmethod
    def from_json_file(cls, path: str | Path) -> FixtureReplaySandbox:
        """Fixture file shape: a JSON list of objects, each
        `{"argv": [...], "exit_status": 0, "stdout": "...", "stderr": "",
        "timed_out": false, "killed": false}` — `stdout`/`stderr` are
        UTF-8 text (sufficient for every fixture recorded so far; binary
        tool output can add a `stdout_base64` variant when a real adapter
        actually needs one, not before).
        """
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        fixtures: dict[tuple[str, ...], SandboxResult] = {}
        for entry in raw:
            key = tuple(entry["argv"])
            fixtures[key] = SandboxResult(
                exit_status=entry["exit_status"],
                stdout=entry.get("stdout", "").encode("utf-8"),
                stderr=entry.get("stderr", "").encode("utf-8"),
                timed_out=entry.get("timed_out", False),
                killed=entry.get("killed", False),
            )
        return cls(fixtures)

    def run(self, argv: list[str]) -> SandboxResult:
        key = tuple(argv)
        result = self._fixtures.get(key)
        if result is None:
            raise FixtureNotFoundError(f"No fixture recorded for argv {argv!r}.")
        return result
