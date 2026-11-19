"""
Test Suite: Workload Gateway Authentication & Authorization.
Validates authentication enforcement between internal AI workloads and the defensive proxy.
Supports 'X-Gateway-Key' header and 'Authorization: Bearer <token>' with constant-time verification.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.proxy_gateway import verify_gateway_authentication


class DummyRequest:
    def __init__(self, headers: dict, path: str = "/v1/chat/completions"):
        self.headers = headers
        self.url = type("URL", (), {"path": path})()


def test_gateway_authentication_disabled_when_key_empty(monkeypatch):
    """When GATEWAY_API_KEY is unset/empty, authentication passes by default."""
    monkeypatch.delenv("GATEWAY_API_KEY", raising=False)
    req = DummyRequest(headers={})
    is_auth, err = verify_gateway_authentication(req)
    assert is_auth is True
    assert err is None


def test_gateway_authentication_missing_credentials(monkeypatch):
    """When GATEWAY_API_KEY is configured, requests without headers must be rejected."""
    monkeypatch.setenv("GATEWAY_API_KEY", "secure-gateway-token-xyz-12345")
    req = DummyRequest(headers={})
    is_auth, err = verify_gateway_authentication(req)
    assert is_auth is False
    assert "Missing workload gateway authentication" in err


def test_gateway_authentication_invalid_credentials(monkeypatch):
    """Requests with wrong credentials must be rejected."""
    monkeypatch.setenv("GATEWAY_API_KEY", "secure-gateway-token-xyz-12345")

    # Wrong X-Gateway-Key
    req1 = DummyRequest(headers={"x-gateway-key": "wrong-key"})
    is_auth1, err1 = verify_gateway_authentication(req1)
    assert is_auth1 is False
    assert "Invalid workload gateway" in err1

    # Wrong Bearer token
    req2 = DummyRequest(headers={"authorization": "Bearer wrong-token"})
    is_auth2, err2 = verify_gateway_authentication(req2)
    assert is_auth2 is False
    assert "Invalid workload gateway" in err2


def test_gateway_authentication_valid_x_gateway_key(monkeypatch):
    """Valid X-Gateway-Key must be accepted."""
    test_key = "secure-gateway-token-xyz-12345"
    monkeypatch.setenv("GATEWAY_API_KEY", test_key)
    req = DummyRequest(headers={"x-gateway-key": test_key})
    is_auth, err = verify_gateway_authentication(req)
    assert is_auth is True
    assert err is None


def test_gateway_authentication_valid_bearer_token(monkeypatch):
    """Valid Bearer token must be accepted."""
    test_key = "secure-gateway-token-xyz-12345"
    monkeypatch.setenv("GATEWAY_API_KEY", test_key)
    req = DummyRequest(headers={"authorization": f"Bearer {test_key}"})
    is_auth, err = verify_gateway_authentication(req)
    assert is_auth is True
    assert err is None
