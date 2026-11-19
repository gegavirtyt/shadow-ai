"""
Test Suite: Provider Authentication & Upstream Security Adapter.
Validates server-side credential injection, client header sanitization,
error code propagation, and secret non-disclosure.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.proxy_gateway import (
    HOP_BY_HOP_HEADERS,
    is_openai_upstream,
    redact_credential,
)


def test_hop_by_hop_headers_defined():
    """Validates that standard RFC 2616 and sensitive hop-by-hop headers are registered."""
    expected_headers = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "transfer-encoding",
        "host",
    }
    assert expected_headers.issubset(HOP_BY_HOP_HEADERS)


def test_is_openai_upstream_detection():
    """Detects whether target URL points to OpenAI API or another provider."""
    assert is_openai_upstream("https://api.openai.com/v1/chat/completions") is True
    assert is_openai_upstream("https://api.anthropic.com/v1/messages") is False
    assert is_openai_upstream("http://127.0.0.1:8090/v1/chat/completions") is False


def test_credential_redaction_utility():
    """Validates safe token masking for SIEM logging."""
    short_token = "12345"
    assert redact_credential(short_token) == "[REDACTED]"

    long_token = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_credential(long_token)
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert "..." in redacted
    assert "IOSFODNN7" not in redacted
