"""
Test Suite: Server-Side Request Forgery (SSRF) & Destination Security.
Validates hostname allowlisting, DNS resolution checks, loopback/private/link-local restrictions,
IPv4-mapped IPv6 addresses, and anti-redirect policies.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.proxy_gateway import validate_upstream_destination


def test_ssrf_allowed_hostnames():
    """Authorized cloud provider hostnames must be accepted."""
    allowed_urls = [
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke",
        "https://bedrock-runtime.us-west-2.amazonaws.com/model/invoke",
    ]
    for url in allowed_urls:
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
        assert is_valid is True, f"Expected {url} to be allowed, got: {reason}"
        assert reason is None


def test_ssrf_unwhitelisted_domains_blocked():
    """Arbitrary external domains must be rejected by destination allowlist."""
    prohibited_urls = [
        "https://attacker-controlled.com/exfiltrate",
        "https://evil.org/api",
        "http://google.com/",
        "https://pastebin.com/raw/secret",
    ]
    for url in prohibited_urls:
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
        assert is_valid is False
        assert "not in the authorized upstream allowlist" in reason


def test_ssrf_prohibited_url_schemes():
    """Non-HTTP(S) schemes (file://, ftp://, gopher://) must be rejected."""
    bad_schemes = [
        "file:///etc/passwd",
        "ftp://ftp.example.com/files",
        "gopher://127.0.0.1:70/",
        "data:text/plain;base64,SGVsbG8=",
    ]
    for url in bad_schemes:
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
        assert is_valid is False
        assert "Prohibited URL scheme" in reason or "Malformed URL" in reason


def test_ssrf_imds_metadata_endpoints_blocked():
    """AWS and cloud metadata hostnames and IP addresses must be blocked unconditionally."""
    imds_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/api/token",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
    ]
    for url in imds_targets:
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=True)
        assert is_valid is False, f"Expected IMDS target {url} to be blocked"
        assert "metadata" in reason.lower() or "link-local" in reason.lower() or "allowlist" in reason.lower()


def test_ssrf_loopback_blocked_in_production():
    """Loopback addresses (127.0.0.1, localhost, [::1]) must be blocked when allow_local_mock is False."""
    loopback_urls = [
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.2:9000/internal",
        "http://localhost:5000/keys",
        "http://[::1]:8080/metrics",
    ]
    for url in loopback_urls:
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
        assert is_valid is False
        assert ("Loopback" in reason or "allowlist" in reason or "Prohibited" in reason)


def test_ssrf_ipv4_mapped_ipv6_imds_blocked():
    """IPv4-mapped IPv6 representation of IMDS ([::ffff:169.254.169.254]) must be blocked."""
    url = "http://[::ffff:169.254.169.254]/latest/meta-data/"
    is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
    assert is_valid is False
    assert ("Link-local" in reason or "allowlist" in reason or "prohibited" in reason.lower())


def test_ssrf_ipv6_link_local_blocked():
    """IPv6 link-local addresses (fe80::/10) must be rejected."""
    url = "http://[fe80::1]/service"
    is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
    assert is_valid is False
    assert ("Link-local" in reason or "allowlist" in reason)


def test_ssrf_missing_hostname_or_malformed():
    """Missing hostnames or unparseable URLs must be cleanly rejected."""
    malformed = [
        "http://",
        "http:///path/only",
        "://invalid-url",
        "",
    ]
    for url in malformed:
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
        assert is_valid is False
        assert reason is not None
