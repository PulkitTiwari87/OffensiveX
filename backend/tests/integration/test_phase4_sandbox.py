"""Integration tests for the Phase 4 Sandbox: require a working Docker
daemon and the `offensivex-sandbox:latest` image
(`docker build -t offensivex-sandbox:latest backend/sandbox`). Skip
gracefully, same convention as the Postgres-dependent tests, rather than
fail when Docker isn't available.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from offensivex.sandbox.container import ContainerSandbox

pytestmark = pytest.mark.integration

_IMAGE = "offensivex-sandbox:latest"


@pytest.fixture(scope="module", autouse=True)
def _require_docker_and_image() -> None:
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker is not reachable ({exc.__class__.__name__}).")

    inspect = subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True, timeout=5)
    if inspect.returncode != 0:
        pytest.skip(
            f"{_IMAGE!r} is not built. Build it with: "
            "docker build -t offensivex-sandbox:latest backend/sandbox"
        )


def test_run_echo_returns_stdout_and_zero_exit() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    result = sandbox.run(["echo", "hello from sandbox"])
    assert result.exit_status == 0
    assert result.stdout == b"hello from sandbox\n"
    assert result.timed_out is False
    assert result.killed is False


def test_runs_as_non_root() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    result = sandbox.run(["id", "-u"])
    assert result.stdout.strip() == b"1000"


def test_filesystem_is_read_only() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    result = sandbox.run(["touch", "/this-should-fail"])
    assert result.exit_status != 0


def test_tmp_is_writable_despite_read_only_root() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    result = sandbox.run(["touch", "/tmp/scratch"])
    assert result.exit_status == 0


def test_network_is_disabled_by_default() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    # busybox wget is present on alpine; with --network none it cannot
    # resolve or connect anywhere, so it must fail, fast, not hang.
    result = sandbox.run(["wget", "-T", "3", "-O", "/dev/null", "http://example.test"])
    assert result.exit_status != 0


def test_timeout_kills_a_long_running_container() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=2)
    start = time.monotonic()
    result = sandbox.run(["sleep", "30"])
    elapsed = time.monotonic() - start

    assert result.timed_out is True
    assert result.killed is True
    assert elapsed < 10  # nowhere near the full 30s sleep
    # No leaked container: `docker ps` should show nothing from this run.
    ps = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=offensivex-sandbox-", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert ps.stdout.strip() == ""


def test_argv_is_never_shell_interpreted() -> None:
    """A value that would be dangerous if ever concatenated into a shell
    string must come through as a single literal argv element, not be
    expanded/split/executed."""
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    result = sandbox.run(["echo", "$(id); rm -rf /; `whoami`"])
    assert result.stdout == b"$(id); rm -rf /; `whoami`\n"
    assert result.exit_status == 0


def test_each_run_is_a_fresh_container_no_state_persists() -> None:
    sandbox = ContainerSandbox(_IMAGE, timeout_seconds=10)
    sandbox.run(["touch", "/tmp/leftover"])
    result = sandbox.run(["test", "-f", "/tmp/leftover"])
    assert result.exit_status != 0  # the file from the first run is gone
