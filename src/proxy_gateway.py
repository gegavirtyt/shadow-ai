"""Backward-compatible facade for the v3 single-module gateway API.

The implementation lives in the ``shadow_ai_gateway`` package (``src/shadow_ai_gateway``).
This module re-exports the v3 public names so existing imports such as
``from src.proxy_gateway import app, inspect_text_for_threats`` keep working, and
keeps ``uvicorn src.proxy_gateway:app`` usable. New code should import from
``shadow_ai_gateway`` directly.
"""

from __future__ import annotations

import os
import sys
import urllib.parse
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any, Protocol

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:  # allow running from a source checkout without installation
    sys.path.insert(0, str(_SRC))

from shadow_ai_gateway.app import app, create_app
from shadow_ai_gateway.audit import emit_siem_security_log
from shadow_ai_gateway.auth import WorkloadCredential, authenticate, extract_presented_key
from shadow_ai_gateway.config import Settings
from shadow_ai_gateway.detectors import (
    PROMPT_OVERRIDE_REGEX,
    SECRET_DETECTORS,
    scan_text_for_injection,
    scan_text_for_secrets,
)
from shadow_ai_gateway.entropy import calculate_shannon_entropy
from shadow_ai_gateway.inspection import (
    PayloadError,
    describe,
    inspect_egress_body,
    inspect_json,
    inspect_text,
    parse_json_strict,
)
from shadow_ai_gateway.normalization import (
    is_targeted_base64_candidate,
    normalize_text_pipeline,
    try_decode_base64,
)
from shadow_ai_gateway.ssrf import (
    SSRFProtectedBackend,
    SSRFProtectedTransport,
    _evaluate_destination_ip_rules,
    async_validate_upstream_destination,
    validate_upstream_destination,
)
from shadow_ai_gateway.streaming import (
    SSEParser,
    StreamGuard,
    StreamViolation,
    extract_event_text,
    guarded_sse,
    sse_error_event,
)

_DEFAULTS = Settings()
MAX_REQUEST_BODY_SIZE = int(
    os.getenv("MAX_REQUEST_BODY_SIZE", os.getenv("MAX_PAYLOAD_SIZE_BYTES", str(_DEFAULTS.max_request_body_bytes)))
)
STREAM_DLP_WINDOW_SIZE = int(os.getenv("STREAM_DLP_WINDOW_SIZE", str(_DEFAULTS.stream_lookback_chars)))
STREAMING_DELAY_WINDOW_CHARS = STREAM_DLP_WINDOW_SIZE
MAX_STREAM_BUFFER_CHARS = _DEFAULTS.stream_max_hold_chars

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-length", "host",
}


def redact_credential(secret: str) -> str:
    """Mask a token for display (first and last four characters)."""
    if len(secret) <= 8:
        return "[REDACTED]"
    return secret[:4] + "..." + secret[-4:]


def is_openai_upstream(url: str) -> bool:
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return False
    return host == "api.openai.com" or os.getenv("UPSTREAM_PROVIDER", "").lower() == "openai"


class _HasHeaders(Protocol):
    headers: Mapping[str, str]


def verify_gateway_authentication(request: _HasHeaders) -> tuple[bool, str | None]:
    """v3 API: validate against ``GATEWAY_API_KEY`` read from the environment on each call."""
    expected = os.getenv("GATEWAY_API_KEY", "").strip()
    if not expected:
        return True, None
    workload = WorkloadCredential.from_plaintext("default", expected)
    result = authenticate(extract_presented_key({k.lower(): v for k, v in request.headers.items()}), [workload])
    return result.ok, result.error


def _legacy_entropy(entropy_threshold: float | None) -> bool:
    # v3 accepted a numeric threshold; v4 uses a calibrated length-aware test, so the
    # value only toggles the detector (None disables it).
    return entropy_threshold is not None


def inspect_text_for_threats(text: str, entropy_threshold: float | None = 4.5) -> tuple[bool, str | None]:
    result = inspect_text(text, entropy=_legacy_entropy(entropy_threshold))
    if not result.blocked:
        return False, None
    return True, describe(result.primary) if result.primary else None


def inspect_payload_for_threats(body_bytes: bytes, entropy_threshold: float | None = 4.5) -> tuple[bool, str | None]:
    entropy = _legacy_entropy(entropy_threshold)
    try:
        data = parse_json_strict(body_bytes, max_depth=_DEFAULTS.max_json_depth)
    except PayloadError:
        text = body_bytes.decode("utf-8", errors="replace")
        if not text.strip():
            return False, None
        return inspect_text_for_threats(text, entropy_threshold)
    result = inspect_json(data, entropy=entropy)
    if not result.blocked:
        return False, None
    detail = describe(result.primary) if result.primary else ""
    return True, f"Field '{result.field_path}' violation -> {detail}"


def inspect_egress_payload_for_dlp(response_bytes: bytes, entropy_threshold: float | None = 4.5) -> tuple[bool, str | None]:
    result = inspect_egress_body(response_bytes, entropy=_legacy_entropy(entropy_threshold))
    if not result.blocked:
        return False, None
    return True, describe(result.primary, egress=True) if result.primary else None


class IncrementalSSEParser:
    """v3 API: ``feed`` returns ``(raw_event_text, delta)`` tuples.

    ``delta`` is ``None`` for ``[DONE]``, ``""`` for events without text, and the
    concatenated text contributions otherwise (raw data for non-JSON payloads).
    """

    def __init__(self, max_event_bytes: int = _DEFAULTS.stream_max_event_bytes) -> None:
        self._parser = SSEParser(max_event_bytes)

    @staticmethod
    def _convert(events: list[Any]) -> list[tuple[str, str | None]]:
        out: list[tuple[str, str | None]] = []
        for ev in events:
            raw = ev.raw.decode("utf-8", errors="replace")
            if ev.is_done:
                out.append((raw, None))
            elif ev.data is None:
                out.append((raw, ""))
            else:
                out.append((raw, "".join(text for _, text in extract_event_text(ev.data)[0])))
        return out

    def feed(self, chunk_bytes: bytes) -> list[tuple[str, str | None]]:
        return self._convert(self._parser.feed(chunk_bytes))

    def finalize(self) -> list[tuple[str, str | None]]:
        return self._convert(self._parser.finalize())


def extract_sse_delta_content(raw_chunk: bytes) -> str:
    parser = IncrementalSSEParser()
    events = parser.feed(raw_chunk) + parser.finalize()
    return "".join(delta for _, delta in events if delta)


class _StreamingUpstream(Protocol):
    def aiter_bytes(self) -> AsyncIterator[bytes]: ...

    async def aclose(self) -> None: ...


async def stream_with_dlp_inspection(
    upstream_resp: _StreamingUpstream,
    delay_window_chars: int = STREAM_DLP_WINDOW_SIZE,
    entropy_threshold: float | None = 4.5,
    client_ip: str = "streaming_client",
) -> AsyncIterator[bytes]:
    """v3 API: guarded SSE relay over an object exposing ``aiter_bytes``/``aclose``."""

    def on_violation(v: StreamViolation, guard: StreamGuard) -> bytes:
        message = (
            f"Outbound DLP Violation: {describe(v.finding, egress=True)} intercepted in model stream"
            if v.finding
            else v.message
        )
        return sse_error_event(v.code, message)

    try:
        async for raw in guarded_sse(
            upstream_resp.aiter_bytes(),
            lookback=delay_window_chars,
            max_hold_chars=max(_DEFAULTS.stream_max_hold_chars, 4 * delay_window_chars),
            entropy=_legacy_entropy(entropy_threshold),
            max_event_bytes=_DEFAULTS.stream_max_event_bytes,
            max_total_bytes=_DEFAULTS.stream_max_total_bytes,
            max_duration_s=_DEFAULTS.stream_max_duration_s,
            on_violation=on_violation,
        ):
            yield raw
    finally:
        await upstream_resp.aclose()


__all__ = [
    "HOP_BY_HOP_HEADERS",
    "MAX_REQUEST_BODY_SIZE",
    "PROMPT_OVERRIDE_REGEX",
    "SECRET_DETECTORS",
    "STREAM_DLP_WINDOW_SIZE",
    "IncrementalSSEParser",
    "SSRFProtectedBackend",
    "SSRFProtectedTransport",
    "Settings",
    "_evaluate_destination_ip_rules",
    "app",
    "async_validate_upstream_destination",
    "calculate_shannon_entropy",
    "create_app",
    "emit_siem_security_log",
    "extract_sse_delta_content",
    "inspect_egress_payload_for_dlp",
    "inspect_payload_for_threats",
    "inspect_text_for_threats",
    "is_openai_upstream",
    "is_targeted_base64_candidate",
    "normalize_text_pipeline",
    "redact_credential",
    "scan_text_for_injection",
    "scan_text_for_secrets",
    "stream_with_dlp_inspection",
    "try_decode_base64",
    "validate_upstream_destination",
    "verify_gateway_authentication",
]
