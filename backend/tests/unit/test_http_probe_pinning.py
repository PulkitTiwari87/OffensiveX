"""Connection-level tests for HttpProbeAdapter: the address it connects to is the one
that was validated, never a second lookup; TLS is verified against the original
hostname; the Host header is the original name; redirects are not followed.

DNS is a deterministic fake. Servers are local, ephemeral-port, loopback-only
(`127.0.0.1`) — nothing here touches a third-party system. TLS tests generate a
throwaway certificate with the `openssl` CLI and skip if it is not installed.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.network_guard import NetworkContext, NetworkPolicyError
from offensivex.tools.scope_guard import check_destination

PUBLIC = "93.184.216.34"
LAB_NAME = "lab.example.test"


@dataclass(frozen=True)
class Rule:
    rule_type: str
    pattern: str
    is_exclusion: bool = False
    ports: str | None = None


class FakeDns:
    """Answers from a script, one answer per call; records every lookup."""

    def __init__(self, *answers: list[str]) -> None:
        self._answers = list(answers)
        self.lookups: list[str] = []

    def __call__(self, hostname: str) -> list[str]:
        self.lookups.append(hostname)
        if len(self._answers) > 1:
            return self._answers.pop(0)
        return self._answers[0]


class RecordingConnector:
    """Wraps the real connector and records what it was asked to connect to."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def __call__(self, address: tuple[str, int], timeout: float) -> socket.socket:
        self.calls.append(address)
        return socket.create_connection(address, timeout=timeout)


def planned(adapter: HttpProbeAdapter, url: str, network: NetworkContext | None) -> Any:
    return replace(adapter.plan({"url": url}), network=network)


def lab_network(port: int, *, allow_private: bool = True) -> NetworkContext:
    spec = str(port)
    return NetworkContext(
        rules=(
            Rule("domain", LAB_NAME, ports=spec),
            Rule("cidr", "127.0.0.0/8", ports=spec),
        ),
        allow_private_targets=allow_private,
    )


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib-mandated name
        self.server.seen.append(dict(self.headers))  # type: ignore[attr-defined]
        target = self.server.redirect_to  # type: ignore[attr-defined]
        if target:
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        body = b"hello from the lab"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class Lab:
    def __init__(self, redirect_to: str | None = None, tls: ssl.SSLContext | None = None) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.server.seen = []  # type: ignore[attr-defined]
        self.server.redirect_to = redirect_to  # type: ignore[attr-defined]
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port: int = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def seen(self) -> list[dict[str, str]]:
        return self.server.seen  # type: ignore[attr-defined,no-any-return]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def lab() -> Iterator[Any]:
    started: list[Lab] = []

    def start(**kwargs: Any) -> Lab:
        instance = Lab(**kwargs)
        started.append(instance)
        return instance

    yield start
    for instance in started:
        instance.close()


# --- pinning ------------------------------------------------------------------------------


def test_connects_to_the_validated_address_and_sends_the_original_host_header(lab: Any) -> None:
    server = lab()
    dns = FakeDns(["127.0.0.1"])
    connector = RecordingConnector()
    adapter = HttpProbeAdapter(dns, connector=connector)

    url = f"http://{LAB_NAME}:{server.port}/index?x=1"
    raw = adapter.run(planned(adapter, url, lab_network(server.port)))
    result = adapter.parse(raw)

    assert dns.lookups == [LAB_NAME]  # resolved exactly once
    assert connector.calls == [("127.0.0.1", server.port)]  # an IP literal, never the name
    assert result.data["pinned_ip"] == "127.0.0.1"
    assert result.data["status_code"] == 200
    assert result.data["body_excerpt"] == "hello from the lab"
    assert server.seen[0]["Host"] == f"{LAB_NAME}:{server.port}"  # original name + port


class _FakeSocket:
    """A socket stand-in: reports a fixed peer, records what is sent."""

    def __init__(self, peer: tuple[str, int]) -> None:
        self._peer = peer
        self.sent: list[bytes] = []
        self.closed = False

    def getpeername(self) -> tuple[str, int]:
        return self._peer

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _n: int) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True


def test_default_port_host_header_omits_the_port() -> None:
    sock = _FakeSocket((PUBLIC, 80))
    adapter = HttpProbeAdapter(FakeDns([PUBLIC]), connector=lambda a, t: sock)  # type: ignore[arg-type,return-value]
    adapter.run(planned(adapter, "http://app.example.test/", NetworkContext(rules=())))
    assert b"Host: app.example.test\r\n" in sock.sent[0]


def test_dns_change_between_validation_and_connection_cannot_redirect_the_connection() -> None:
    # First answer is public (passes validation); any *second* lookup would return
    # loopback. The adapter must not do a second lookup, so the connection can only
    # go to the validated public address.
    dns = FakeDns([PUBLIC], ["127.0.0.1"])
    connected: list[tuple[str, int]] = []

    def connector(address: tuple[str, int], timeout: float) -> _FakeSocket:
        connected.append(address)
        return _FakeSocket(address)

    adapter = HttpProbeAdapter(dns, connector=connector)  # type: ignore[arg-type]
    adapter.run(planned(adapter, "http://app.example.test/", NetworkContext(rules=())))
    assert dns.lookups == ["app.example.test"]
    assert connected == [(PUBLIC, 80)]


@pytest.mark.parametrize(
    "answer",
    [
        ["10.0.0.5"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["::1"],
        ["::ffff:127.0.0.1"],
        [PUBLIC, "10.0.0.5"],  # mixed public/private
        ["192.168.1.10", PUBLIC],
        [PUBLIC, "169.254.169.254"],
    ],
)
def test_public_hostname_resolving_to_private_or_metadata_is_refused_before_any_connect(
    answer: list[str],
) -> None:
    connector = RecordingConnector()
    adapter = HttpProbeAdapter(FakeDns(answer), connector=connector)
    plan = planned(adapter, "http://app.example.test/", NetworkContext(rules=()))
    with pytest.raises(NetworkPolicyError):
        adapter.run(plan)
    assert connector.calls == []


def test_private_resolution_is_refused_even_with_the_switch_when_scope_has_no_cidr_for_it() -> None:
    connector = RecordingConnector()
    adapter = HttpProbeAdapter(FakeDns(["127.0.0.1"]), connector=connector)
    network = NetworkContext(
        rules=(Rule("domain", LAB_NAME, ports="8000"),), allow_private_targets=True
    )
    with pytest.raises(NetworkPolicyError, match="does not explicitly cover"):
        adapter.run(planned(adapter, f"http://{LAB_NAME}:8000/", network))
    assert connector.calls == []


def test_lab_workflow_works_when_private_targets_are_permitted_and_scope_covers_them(
    lab: Any,
) -> None:
    server = lab()
    adapter = HttpProbeAdapter(FakeDns(["127.0.0.1"]))
    raw = adapter.run(
        planned(adapter, f"http://{LAB_NAME}:{server.port}/", lab_network(server.port))
    )
    assert adapter.parse(raw).data["status_code"] == 200


def test_localhost_lab_workflow_with_the_real_resolver(lab: Any) -> None:
    server = lab()
    network = NetworkContext(
        rules=(Rule("domain", "localhost", ports=str(server.port)),), allow_private_targets=True
    )
    adapter = HttpProbeAdapter()  # system resolver, real connector
    raw = adapter.run(planned(adapter, f"http://localhost:{server.port}/", network))
    assert adapter.parse(raw).data["pinned_ip"] in {"127.0.0.1", "::1"}
    # ... and the same request is refused when the deployment does not permit it.
    with pytest.raises(NetworkPolicyError, match="ALLOW_PRIVATE_TARGETS"):
        adapter.run(
            planned(
                adapter,
                f"http://localhost:{server.port}/",
                replace(network, allow_private_targets=False),
            )
        )


def test_ip_literal_destination_is_not_resolved_and_follows_the_same_rules(lab: Any) -> None:
    server = lab()
    dns = FakeDns(["203.0.113.7"])  # would be wrong if consulted
    adapter = HttpProbeAdapter(dns)
    raw = adapter.run(
        planned(adapter, f"http://127.0.0.1:{server.port}/", lab_network(server.port))
    )
    assert adapter.parse(raw).data["pinned_ip"] == "127.0.0.1"
    assert dns.lookups == []
    with pytest.raises(NetworkPolicyError, match="ALLOW_PRIVATE_TARGETS"):
        adapter.run(
            planned(
                adapter,
                f"http://127.0.0.1:{server.port}/",
                lab_network(server.port, allow_private=False),
            )
        )


def test_metadata_ip_literal_is_refused_even_with_every_permission() -> None:
    network = NetworkContext(
        rules=(Rule("cidr", "169.254.169.254/32", ports="80"),), allow_private_targets=True
    )
    connector = RecordingConnector()
    adapter = HttpProbeAdapter(connector=connector)
    with pytest.raises(NetworkPolicyError, match="cloud-metadata"):
        adapter.run(planned(adapter, "http://169.254.169.254/latest/meta-data/", network))
    assert connector.calls == []


def test_connection_that_lands_on_a_different_peer_is_dropped() -> None:
    wrong_peer = _FakeSocket(("127.0.0.1", 80))  # not the approved PUBLIC address
    adapter = HttpProbeAdapter(FakeDns([PUBLIC]), connector=lambda a, t: wrong_peer)  # type: ignore[arg-type,return-value]
    plan = planned(adapter, "http://app.example.test/", NetworkContext(rules=()))
    with pytest.raises(NetworkPolicyError, match="not the approved address"):
        adapter.run(plan)
    assert wrong_peer.closed is True and wrong_peer.sent == []


def test_run_without_a_network_context_refuses_to_connect() -> None:
    dns = FakeDns([PUBLIC])
    connector = RecordingConnector()
    adapter = HttpProbeAdapter(dns, connector=connector)
    with pytest.raises(NetworkPolicyError, match="No network policy context"):
        adapter.run(planned(adapter, "http://app.example.test/", None))
    assert dns.lookups == [] and connector.calls == []


def test_plan_declares_the_effective_port_for_the_scope_guard() -> None:
    adapter = HttpProbeAdapter()
    assert adapter.plan({"url": "http://a.example.test/"}).ports == [80]
    assert adapter.plan({"url": "https://a.example.test/"}).ports == [443]
    assert adapter.plan({"url": "https://a.example.test:8443/x"}).ports == [8443]


# --- redirects ----------------------------------------------------------------------------


def test_redirects_are_reported_not_followed(lab: Any) -> None:
    other = lab()  # an unauthorized second server (different port)
    first = lab(redirect_to=f"http://127.0.0.1:{other.port}/admin")
    adapter = HttpProbeAdapter(FakeDns(["127.0.0.1"]))
    raw = adapter.run(planned(adapter, f"http://{LAB_NAME}:{first.port}/", lab_network(first.port)))
    data = adapter.parse(raw).data
    assert data["status_code"] == 302
    assert data["headers"]["location"] == f"http://127.0.0.1:{other.port}/admin"
    assert other.seen == []  # no connection was ever made to the redirect target
    # And asking for the redirect target as a new request is refused by the Scope Guard:
    rules = list(lab_network(first.port).rules)
    assert check_destination("127.0.0.1", rules, other.port).allowed is False


def test_redirect_to_an_unauthorized_host_is_not_followed(lab: Any) -> None:
    first = lab(redirect_to="http://evil.example.test/steal")
    dns = FakeDns(["127.0.0.1"])
    adapter = HttpProbeAdapter(dns)
    raw = adapter.run(planned(adapter, f"http://{LAB_NAME}:{first.port}/", lab_network(first.port)))
    assert adapter.parse(raw).data["status_code"] == 302
    assert dns.lookups == [LAB_NAME]  # the redirect host was never even resolved


# --- TLS ----------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Any:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("the openssl CLI is not installed; cannot create a test certificate")
    directory = tmp_path_factory.mktemp("tls")

    def make(name: str) -> tuple[Path, Path]:
        cert, key = directory / f"{name}.pem", directory / f"{name}.key"
        subprocess.run(  # noqa: S603 - fixed argv, no untrusted input
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-subj",
                f"/CN={name}",
                "-addext",
                f"subjectAltName=DNS:{name}",
            ],  # fmt: skip
            check=True,
            capture_output=True,
        )
        return cert, key

    return make


def server_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    return context


def client_context_trusting(cert: Path) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.load_verify_locations(str(cert))
    return context


def test_tls_is_verified_against_the_original_hostname_while_connecting_to_the_pinned_ip(
    lab: Any, certs: Any
) -> None:
    cert, key = certs(LAB_NAME)
    server = lab(tls=server_context(cert, key))
    connector = RecordingConnector()
    adapter = HttpProbeAdapter(
        FakeDns(["127.0.0.1"]), connector=connector, ssl_context=client_context_trusting(cert)
    )
    raw = adapter.run(
        planned(adapter, f"https://{LAB_NAME}:{server.port}/", lab_network(server.port))
    )
    assert adapter.parse(raw).data["status_code"] == 200
    assert connector.calls == [("127.0.0.1", server.port)]
    assert server.seen[0]["Host"] == f"{LAB_NAME}:{server.port}"


def test_tls_certificate_for_a_different_name_is_rejected(lab: Any, certs: Any) -> None:
    # The pinned IP serves a certificate for another name: connecting by IP must not
    # weaken verification — it still has to match the hostname that was authorized.
    cert, key = certs("other.example.test")
    server = lab(tls=server_context(cert, key))
    adapter = HttpProbeAdapter(FakeDns(["127.0.0.1"]), ssl_context=client_context_trusting(cert))
    plan = planned(adapter, f"https://{LAB_NAME}:{server.port}/", lab_network(server.port))
    with pytest.raises(ssl.SSLCertVerificationError):
        adapter.run(plan)


def test_default_tls_context_rejects_an_untrusted_certificate(lab: Any, certs: Any) -> None:
    cert, key = certs(LAB_NAME)
    server = lab(tls=server_context(cert, key))
    adapter = HttpProbeAdapter(FakeDns(["127.0.0.1"]))  # production default context
    plan = planned(adapter, f"https://{LAB_NAME}:{server.port}/", lab_network(server.port))
    with pytest.raises(ssl.SSLCertVerificationError):
        adapter.run(plan)
