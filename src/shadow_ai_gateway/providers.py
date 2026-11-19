"""Upstream provider adapters: header construction and request defaults.

Request headers are built from an allowlist rather than by copying client headers:
client credentials, cookies, ``X-Forwarded-*`` and arbitrary custom headers are
never forwarded, and the provider credential is injected server-side only.
Response headers are likewise allowlisted; ``Content-Encoding``/``Content-Length``
are dropped because the body is decoded and re-framed by the gateway.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import Any

from . import __version__

PASS_THROUGH_REQUEST_HEADERS = {
    "openai": ("openai-beta",),
    "anthropic": ("anthropic-version", "anthropic-beta"),
    "generic": (),
}
PASS_THROUGH_RESPONSE_HEADERS = (
    "content-type",
    "retry-after",
    "openai-processing-ms",
    "openai-version",
    "anthropic-version",
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
)
GATEWAY_HEADER = "X-Proxy-Gateway"
GATEWAY_HEADER_VALUE = f"Shadow-AI-Defensive-Gateway/v{__version__}"


def is_openai_upstream(url: str, provider: str | None = None) -> bool:
    if provider is not None:
        return provider == "openai"
    try:
        return urllib.parse.urlsplit(url).hostname == "api.openai.com"
    except ValueError:
        return False


def build_upstream_headers(provider: str, api_key: str, incoming: Mapping[str, str], streaming: bool) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "accept": "text/event-stream" if streaming else "application/json",
        "user-agent": GATEWAY_HEADER_VALUE,
    }
    for name in PASS_THROUGH_REQUEST_HEADERS.get(provider, ()):
        value = incoming.get(name)
        if value and len(value) <= 256 and value.isprintable():
            headers[name] = value
    if provider == "openai" and api_key:
        headers["authorization"] = f"Bearer {api_key}"
    elif provider == "anthropic":
        headers.setdefault("anthropic-version", "2023-06-01")
        if api_key:
            headers["x-api-key"] = api_key
    return headers


def apply_request_defaults(provider: str, payload: dict[str, Any], default_model: str) -> bool:
    """Fill provider defaults in-place. Returns True if the payload was modified."""
    if provider == "openai" and not payload.get("model") and default_model:
        payload["model"] = default_model
        return True
    return False


def filter_response_headers(upstream: Mapping[str, str]) -> dict[str, str]:
    out = {name: upstream[name] for name in PASS_THROUGH_RESPONSE_HEADERS if name in upstream}
    if "x-request-id" in upstream:
        out["x-upstream-request-id"] = upstream["x-request-id"]
    return out
