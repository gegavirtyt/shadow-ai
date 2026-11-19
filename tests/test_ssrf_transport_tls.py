"""Transport-level SSRF evidence using real sockets, real TLS and controlled DNS.

All traffic stays on the loopback interface. "Public" IP addresses appear only as
resolver *answers*; no connection to them is ever attempted (asserted via a
recording wrapper around the underlying socket connect).
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
import tempfile
import threading

import httpcore
import httpx
import pytest
import trustme
from fastapi import FastAPI

from shadow_ai_gateway.ssrf import create_upstream_client, ip_rejection_reason
from tests.conftest import RunningServer


def fixed_resolver(answers: dict[str, list[str]], calls: list[str] | None = None):
    async def resolve(host: str, port: int):
        if calls is not None:
            calls.append(host)
        ips = answers[host]
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    return resolve


@pytest.fixture
def recorded_connects(monkeypatch):
    calls: list[tuple[str, int]] = []
    original = httpcore.AnyIOBackend.connect_tcp

    async def recording(self, host, port, *args, **kwargs):
        calls.append((host, port))
        return await original(self, host, port, *args, **kwargs)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", recording)
    return calls


def _hello_app() -> FastAPI:
    app = FastAPI()

    @app.get("/")
    async def root():
        return {"ok": True}

    return app


@pytest.fixture(scope="module")
def tls_ca():
    return trustme.CA()


def _tls_server(ca: trustme.CA, cert_host: str) -> RunningServer:
    chain = os.path.join(tempfile.mkdtemp(), "chain.pem")
    ca.issue_cert(cert_host).private_key_and_cert_chain_pem.write_to_path(chain)
    return RunningServer(_hello_app(), ssl_certfile=chain, ssl_keyfile=chain)


def _client(ca, resolver, allowed, *, allow_local_mock=True) -> httpx.AsyncClient:
    ca_file = os.path.join(tempfile.mkdtemp(), "ca.pem")
    ca.cert_pem.write_to_path(ca_file)
    return create_upstream_client(
        allowed_hosts=allowed,
        allow_local_mock=allow_local_mock,
        connect_timeout=3,
        read_timeout=3,
        write_timeout=3,
        pool_timeout=3,
        max_connections=4,
        max_keepalive=0,
        ca_bundle=ca_file,
        resolver=resolver,
    )


def test_ip_pinning_preserves_hostname_tls_verification(tls_ca, recorded_connects):
    """Socket connects to the validated IP literal, while TLS verifies the *hostname* (SNI + cert)."""
    with _tls_server(tls_ca, "upstream.test") as server:
        resolver = fixed_resolver({"upstream.test": ["127.0.0.1"]})

        async def go():
            async with _client(tls_ca, resolver, {"upstream.test"}) as client:
                return await client.get(f"https://upstream.test:{server.port}/")

        resp = asyncio.run(go())
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    assert recorded_connects == [("127.0.0.1", server.port)]


def test_certificate_for_other_hostname_is_rejected(tls_ca, recorded_connects):
    """IP pinning must not weaken certificate validation: a valid cert for another name fails."""
    with _tls_server(tls_ca, "other.test") as server:
        resolver = fixed_resolver({"upstream.test": ["127.0.0.1"]})

        async def go():
            async with _client(tls_ca, resolver, {"upstream.test"}) as client:
                await client.get(f"https://upstream.test:{server.port}/")

        with pytest.raises(httpx.ConnectError) as exc:
            asyncio.run(go())
    assert "CERTIFICATE_VERIFY_FAILED" in str(exc.value) or "certificate" in str(exc.value).lower()


def test_untrusted_ca_is_rejected(tls_ca):
    other_ca = trustme.CA()
    with _tls_server(other_ca, "upstream.test") as server:
        resolver = fixed_resolver({"upstream.test": ["127.0.0.1"]})

        async def go():
            async with _client(tls_ca, resolver, {"upstream.test"}) as client:
                await client.get(f"https://upstream.test:{server.port}/")

        with pytest.raises(httpx.ConnectError):
            asyncio.run(go())


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["10.0.0.5"],
        ["93.184.216.34", "192.168.1.10"],  # mixed public/private answer
        ["169.254.169.254"],
        ["::ffff:169.254.169.254"],
        ["64:ff9b::a9fe:a9fe"],  # NAT64-embedded IMDS
        ["fd00:ec2::254"],
    ],
)
def test_forbidden_dns_answers_block_before_any_connect(tls_ca, recorded_connects, answers):
    resolver = fixed_resolver({"api.example.test": answers})

    async def go():
        async with _client(tls_ca, resolver, {"api.example.test"}, allow_local_mock=False) as client:
            await client.get("https://api.example.test/")

    with pytest.raises(httpx.ConnectError, match="SSRF blocked"):
        asyncio.run(go())
    assert recorded_connects == []


def test_dns_rebinding_between_check_and_connect_is_ineffective(tls_ca, recorded_connects):
    """A resolver that answers 'public' first and 'loopback' afterwards (classic rebinding).

    A pre-flight check would see the public address; the transport performs its own
    resolution at connect time, validates *that* answer and blocks. No socket is opened.
    """
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])
    calls: list[str] = []

    async def rebinding(host, port):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in next(answers)]

    async def go():
        assert (await rebinding("api.example.test", 443))[0][4][0] == "93.184.216.34"  # attacker-controlled "pre-flight"
        async with _client(tls_ca, rebinding, {"api.example.test"}, allow_local_mock=False) as client:
            await client.get("https://api.example.test/")

    with pytest.raises(httpx.ConnectError, match="Loopback"):
        asyncio.run(go())
    assert calls == ["api.example.test", "api.example.test"]
    assert recorded_connects == []


def test_transport_refuses_non_allowlisted_host(tls_ca, recorded_connects):
    resolver = fixed_resolver({"evil.test": ["127.0.0.1"]})

    async def go():
        async with _client(tls_ca, resolver, {"upstream.test"}) as client:
            await client.get("http://evil.test/")

    with pytest.raises(httpx.ConnectError, match="not allowlisted"):
        asyncio.run(go())
    assert recorded_connects == []


def test_environment_proxies_and_netrc_are_ignored(monkeypatch, tls_ca):
    """HTTP(S)_PROXY must not divert gateway traffic (trust_env=False)."""
    proxy_hits: list[bytes] = []
    proxy_sock = socket.socket()
    proxy_sock.bind(("127.0.0.1", 0))
    proxy_sock.listen()
    proxy_sock.settimeout(0.2)
    proxy_port = proxy_sock.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        while not stop.is_set():
            try:
                conn, _ = proxy_sock.accept()
            except OSError:
                continue
            proxy_hits.append(conn.recv(1024))
            conn.close()

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy_port}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    try:
        with RunningServer(_hello_app()) as server:

            async def go():
                async with _client(tls_ca, None, {"127.0.0.1"}) as client:
                    return await client.get(f"http://127.0.0.1:{server.port}/")

            resp = asyncio.run(go())
    finally:
        stop.set()
        t.join(timeout=2)
        proxy_sock.close()
    assert resp.status_code == 200
    assert proxy_hits == []


def test_connect_falls_back_across_validated_addresses(tls_ca, recorded_connects):
    """If the first validated address refuses the connection, the next validated one is tried."""
    if not socket.has_ipv6:
        pytest.skip("IPv6 not available on this host")
    with RunningServer(_hello_app()) as server:  # listens on 127.0.0.1 only; nothing on [::1]
        resolver = fixed_resolver({"localhost": ["::1", "127.0.0.1"]})

        async def go():
            async with _client(tls_ca, resolver, {"localhost"}) as client:
                return await client.get(f"http://localhost:{server.port}/")

        assert asyncio.run(go()).status_code == 200
    assert recorded_connects == [("::1", server.port), ("127.0.0.1", server.port)]


@pytest.mark.parametrize(
    "ip,allowed_prod",
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),
        ("::1", False),
        ("10.1.2.3", False),
        ("172.31.255.1", False),
        ("192.168.0.1", False),
        ("100.64.0.1", False),  # CGNAT
        ("198.18.0.1", False),
        ("0.0.0.0", False),
        ("169.254.169.254", False),
        ("169.254.170.2", False),  # ECS task metadata
        ("100.100.100.200", False),  # Alibaba metadata
        ("fe80::1", False),
        ("fd00:ec2::254", False),
        ("::ffff:127.0.0.1", False),
        ("::ffff:169.254.169.254", False),
        ("::169.254.169.254", False),  # IPv4-compatible
        ("64:ff9b::a9fe:a9fe", False),  # NAT64 -> 169.254.169.254
        ("64:ff9b::0a00:0001", False),  # NAT64 -> 10.0.0.1
        ("2002:a9fe:a9fe::1", False),  # 6to4 -> 169.254.169.254
        ("2002:0a00:0001::1", False),  # 6to4 -> 10.0.0.1
        ("2001:0:4136:e378:8000:63bf:f5ff:fffe", False),  # Teredo, client 10.0.0.1 (obfuscated)
        ("224.0.0.1", False),
        ("ff02::1", False),
        ("240.0.0.1", False),
    ],
)
def test_ip_policy_matrix(ip, allowed_prod):
    reason = ip_rejection_reason(ipaddress.ip_address(ip), allow_local_mock=False)
    assert (reason is None) is allowed_prod, reason


@pytest.mark.parametrize("ip", ["169.254.169.254", "fe80::1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "0.0.0.0"])
def test_metadata_and_link_local_blocked_even_in_mock_mode(ip):
    assert ip_rejection_reason(ipaddress.ip_address(ip), allow_local_mock=True) is not None


def test_ssl_context_is_strict():
    from shadow_ai_gateway.ssrf import build_ssl_context

    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
