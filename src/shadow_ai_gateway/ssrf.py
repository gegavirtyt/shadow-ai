"""Outbound destination policy and SSRF-resistant HTTP transport.

Security properties (each covered by tests in tests/test_ssrf_*.py):

1. The upstream destination is operator-configured. Clients cannot choose it.
2. The transport refuses to connect to any host that is not on the allowlist,
   even if some code path were to construct such a request (defence in depth).
3. DNS is resolved *inside* the connection backend. Every resolved address is
   validated; if any address is forbidden the connection is refused (mixed
   public/private answers are rejected). The socket then connects to one of the
   validated IP literals, so there is no second resolution an attacker could rebind.
4. TLS still verifies the certificate against the original *hostname*: httpcore
   passes the URL host as ``server_hostname`` to ``start_tls`` independently of the
   IP literal used for ``connect_tcp``. (This is IP pinning, not certificate pinning.)
5. Redirects are never followed. Environment proxies and ``.netrc`` are ignored
   (``trust_env=False``), so ``HTTP(S)_PROXY`` cannot divert or observe traffic.
6. IPv6 transition forms that embed an IPv4 address (IPv4-mapped, IPv4-compatible,
   6to4, Teredo, NAT64) are unwrapped and the embedded IPv4 address is validated too.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
import urllib.parse
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any

import certifi
import httpcore
import httpx

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

METADATA_HOSTNAMES = frozenset(
    {"169.254.169.254", "metadata.google.internal", "metadata", "instance-data", "fd00:ec2::254", "100.100.100.200"}
)
METADATA_IPS = frozenset(
    {ipaddress.ip_address(a) for a in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254")}
)

# Always forbidden, even in local mock mode.
ALWAYS_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "169.254.0.0/16",  # IPv4 link-local (cloud metadata)
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved
        "255.255.255.255/32",
        "::/128",
        "fe80::/10",  # IPv6 link-local
        "ff00::/8",  # IPv6 multicast
    )
)

# Forbidden unless ALLOW_LOCAL_MOCK=true (local test infrastructure only).
PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",  # TEST-NET-1
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "::1/128",
        "fc00::/7",  # unique local (includes fd00:ec2::254)
        "2001:db8::/32",  # documentation
        "100::/64",  # discard-only
    )
)

NAT64_NETWORKS = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def embedded_ipv4(ip: IPAddress) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses embedded in IPv6 transition formats."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)  # (server, client)
    if ip in ipaddress.ip_network("::/96") and int(ip) > 1:  # IPv4-compatible (deprecated)
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if any(ip in net for net in NAT64_NETWORKS):
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def ip_rejection_reason(ip: IPAddress, allow_local_mock: bool) -> str | None:
    """Return why ``ip`` is a forbidden destination, or ``None`` if it is allowed."""
    for candidate in [ip, *embedded_ipv4(ip)]:
        if candidate in METADATA_IPS:
            return f"Cloud metadata destination IP {ip} is strictly prohibited."
        if any(candidate in net for net in ALWAYS_BLOCKED_NETWORKS) or candidate.is_link_local:
            if candidate.is_link_local:
                return f"Link-local destination IP {ip} is strictly prohibited (IMDS protection)."
            return f"Reserved or multicast destination IP {ip} is prohibited."
        if candidate.is_loopback:
            # Checked before is_reserved: Python classifies ::/8 (which contains ::1) as reserved.
            if not allow_local_mock:
                return f"Loopback destination IP {ip} is prohibited in production mode."
            continue
        if candidate.is_multicast or candidate.is_unspecified or candidate.is_reserved:
            return f"Reserved or multicast destination IP {ip} is prohibited."
        if not allow_local_mock:
            if any(candidate in net for net in PRIVATE_NETWORKS) or candidate.is_private:
                return f"Private network destination IP {ip} is prohibited in production mode."
            if not candidate.is_global:
                return f"Non-global destination IP {ip} is prohibited in production mode."
    return None


def _evaluate_destination_ip_rules(
    addr_infos: Iterable[Any], allow_local_mock: bool = False
) -> tuple[bool, str | None, str | None]:
    """Validate ``getaddrinfo`` results. Returns ``(ok, reason, first_validated_ip)``."""
    validated = validated_addresses(addr_infos, allow_local_mock)
    if isinstance(validated, str):
        return False, validated, None
    return True, None, validated[0] if validated else None


def validated_addresses(addr_infos: Iterable[Any], allow_local_mock: bool) -> list[str] | str:
    """Return validated IP strings (deduplicated, resolver order) or a rejection reason string."""
    ips: list[str] = []
    for info in addr_infos:
        ip_str = str(info[4][0]).split("%", 1)[0]  # drop IPv6 zone id
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"Invalid IP address format '{ip_str}'"
        reason = ip_rejection_reason(ip, allow_local_mock)
        if reason:
            return reason
        if ip_str not in ips:
            ips.append(ip_str)
    if not ips:
        return "DNS resolution returned no addresses"
    return ips


def _env_allow_local_mock() -> bool:
    return os.getenv("ALLOW_LOCAL_MOCK", "false").strip().lower() in ("true", "1", "yes", "on")


def validate_url_policy(
    url_str: str, allowed_hosts: Iterable[str], allow_local_mock: bool
) -> tuple[bool, str | None, str | None, int | None]:
    """Scheme, syntax, metadata-hostname and allowlist checks (no DNS)."""
    try:
        parts = urllib.parse.urlsplit(url_str)
        port = parts.port
    except ValueError as exc:
        return False, f"Malformed URL syntax: {exc}", None, None
    if parts.scheme not in ("http", "https"):
        return False, f"Prohibited URL scheme '{parts.scheme}'. Only HTTP and HTTPS are permitted.", None, None
    host = parts.hostname
    if not host:
        return False, "Destination URL is missing a valid hostname.", None, None
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url_str):
        return False, "Destination URL contains control or whitespace characters.", None, None
    if parts.username is not None or parts.password is not None:
        return False, "Destination URL must not contain userinfo.", None, None
    host = host.lower()
    if host in METADATA_HOSTNAMES:
        return False, f"Prohibited access to cloud metadata service ({host}).", None, None
    if host not in {h.lower() for h in allowed_hosts}:
        return False, f"Destination host '{host}' is not in the authorized upstream allowlist.", None, None
    return True, None, host, port or (443 if parts.scheme == "https" else 80)


LEGACY_ALLOWED_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "bedrock-runtime.us-east-1.amazonaws.com",
        "bedrock-runtime.us-west-2.amazonaws.com",
    }
)


def default_allowed_hosts(allow_local_mock: bool) -> set[str]:
    """Allowlist used by the standalone validation helpers (v3-compatible default).

    The running gateway does not use this: it validates against ``Settings``.
    """
    hosts = set(LEGACY_ALLOWED_HOSTS)
    env_hosts = os.getenv("ALLOWED_UPSTREAM_HOSTS", "")
    hosts |= {h.strip().lower() for h in env_hosts.split(",") if h.strip()}
    if allow_local_mock:
        hosts |= {"127.0.0.1", "localhost", "::1"}
    return hosts


def validate_upstream_destination(
    url_str: str, allow_local_mock: bool | None = None, allowed_hosts: Iterable[str] | None = None
) -> tuple[bool, str | None]:
    """Synchronous destination validation (URL policy + DNS + IP policy)."""
    if allow_local_mock is None:
        allow_local_mock = _env_allow_local_mock()
    hosts = allowed_hosts if allowed_hosts is not None else default_allowed_hosts(allow_local_mock)
    ok, reason, host, port = validate_url_policy(url_str, hosts, allow_local_mock)
    if not ok:
        return False, reason
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as exc:
        return False, f"DNS resolution failure for upstream host '{host}': {type(exc).__name__}"
    result = validated_addresses(infos, allow_local_mock)
    if isinstance(result, str):
        return False, result
    return True, None


async def async_validate_upstream_destination(
    url_str: str, allow_local_mock: bool | None = None, allowed_hosts: Iterable[str] | None = None
) -> tuple[bool, str | None]:
    """Non-blocking variant of :func:`validate_upstream_destination`."""
    if allow_local_mock is None:
        allow_local_mock = _env_allow_local_mock()
    hosts = allowed_hosts if allowed_hosts is not None else default_allowed_hosts(allow_local_mock)
    ok, reason, host, port = validate_url_policy(url_str, hosts, allow_local_mock)
    if not ok:
        return False, reason
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as exc:
        return False, f"DNS resolution failure for upstream host '{host}': {type(exc).__name__}"
    result = validated_addresses(infos, allow_local_mock)
    if isinstance(result, str):
        return False, result
    return True, None


class SSRFBlockedError(httpcore.ConnectError):
    """Raised by the transport when a connection is refused by policy."""


Resolver = Callable[[str, int], Awaitable[list[Any]]]


async def system_resolver(host: str, port: int) -> list[Any]:
    """Non-blocking ``getaddrinfo`` (TCP only)."""
    return await asyncio.get_running_loop().getaddrinfo(host, port, proto=socket.IPPROTO_TCP)


class SSRFProtectedBackend(httpcore.AnyIOBackend):
    """Network backend that resolves, validates and pins the destination IP at connect time."""

    def __init__(
        self,
        allowed_hosts: Iterable[str] | None = None,
        allow_local_mock: bool | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        super().__init__()
        self._allowed_hosts = frozenset(h.lower() for h in allowed_hosts) if allowed_hosts is not None else None
        self._allow_local_mock = allow_local_mock
        self._resolver = resolver or system_resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        allow_mock = self._allow_local_mock if self._allow_local_mock is not None else _env_allow_local_mock()
        normalized_host = host.lower().strip("[]")
        if normalized_host in METADATA_HOSTNAMES:
            raise SSRFBlockedError(f"SSRF blocked: metadata hostname {normalized_host}")
        if self._allowed_hosts is not None and normalized_host not in self._allowed_hosts:
            raise SSRFBlockedError(f"SSRF blocked: host '{normalized_host}' is not allowlisted at the transport layer")
        try:
            infos = await self._resolver(normalized_host, port)
        except (OSError, UnicodeError) as exc:
            raise httpcore.ConnectError(f"DNS resolution failure for host '{normalized_host}': {type(exc).__name__}") from exc
        result = validated_addresses(infos, allow_mock)
        if isinstance(result, str):
            raise SSRFBlockedError(f"SSRF blocked: {result}")
        last_error: Exception | None = None
        for ip in result:  # every candidate was validated above
            try:
                return await super().connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        raise last_error or httpcore.ConnectError("no address could be connected")


def build_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_bundle or certifi.where())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class SSRFProtectedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses :class:`SSRFProtectedBackend`."""

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str] | None = None,
        allow_local_mock: bool | None = None,
        ssl_context: ssl.SSLContext | None = None,
        limits: httpx.Limits | None = None,
        http2: bool = False,
        resolver: Resolver | None = None,
    ) -> None:
        ctx = ssl_context or build_ssl_context()
        limits = limits or httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=30.0)
        super().__init__(verify=ctx, trust_env=False, limits=limits, retries=0)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ctx,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=http2,
            retries=0,
            network_backend=SSRFProtectedBackend(
                allowed_hosts=allowed_hosts, allow_local_mock=allow_local_mock, resolver=resolver
            ),
        )


def create_upstream_client(
    *,
    allowed_hosts: Sequence[str] | frozenset[str],
    allow_local_mock: bool,
    connect_timeout: float,
    read_timeout: float,
    write_timeout: float,
    pool_timeout: float,
    max_connections: int,
    max_keepalive: int,
    ca_bundle: str | None = None,
    resolver: Resolver | None = None,
) -> httpx.AsyncClient:
    transport = SSRFProtectedTransport(
        allowed_hosts=allowed_hosts,
        allow_local_mock=allow_local_mock,
        resolver=resolver,
        ssl_context=build_ssl_context(ca_bundle),
        limits=httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_keepalive, keepalive_expiry=30.0),
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(connect=connect_timeout, read=read_timeout, write=write_timeout, pool=pool_timeout),
        follow_redirects=False,
        trust_env=False,
    )
