"""End-to-end tests: client -> gateway (real uvicorn) -> scriptable upstream (real uvicorn).

No mocks of the gateway internals are used; behaviour is observed at the HTTP level
and at the upstream (what was actually forwarded).
"""

from __future__ import annotations

import json
import logging
import socket
import time

import httpx
import pytest

from shadow_ai_gateway.app import create_app
from shadow_ai_gateway.audit import AUDIT_LOGGER_NAME
from shadow_ai_gateway.auth import WorkloadCredential, digest_key
from shadow_ai_gateway.config import ConfigError, Settings
from tests.conftest import RunningServer
from tests.upstreams import build_upstream, chat_json, content_events, sse_event

# Synthetic credentials assembled at runtime (keeps literal secret-shaped strings out of the repo).
AWS_KEY = "AKIA" + "QX7RZ2M4TB6YH3KD"
GH_TOKEN = "ghp_" + "Zq8RtY2uIoP4aSdF6gHjK9lZxC1vBnM3qW5e"
SERVER_KEY = "sk-" + "server-side-provider-credential-0001"
KEY_A = "wk-alpha-" + "6f1c2b9e8d7a4c3b2a1f0e9d"
KEY_A2 = "wk-alpha-rotated-" + "0a9b8c7d6e5f4a3b"
KEY_B = "wk-bravo-" + "1234abcd5678efgh9012ijkl"


class AuditCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())

    def events(self) -> list[dict]:
        return [json.loads(r) for r in self.records]


@pytest.fixture(scope="module")
def upstream():
    app = build_upstream()
    with RunningServer(app) as server:
        server.app = app
        yield server


@pytest.fixture(autouse=True)
def reset_upstream(upstream):
    upstream.app.state.script = {"kind": "json"}
    upstream.app.state.requests.clear()
    yield


@pytest.fixture
def audit():
    handler = AuditCapture()
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    logger.addHandler(handler)
    yield handler
    logger.removeHandler(handler)


def gateway_settings(upstream, **overrides) -> Settings:
    base = Settings(
        upstream_url=f"{upstream.url}/v1/chat/completions",
        upstream_provider="openai",
        upstream_api_key=SERVER_KEY,
        allow_local_mock=True,
        auth_mode="disabled",
    )
    return base.with_overrides(**overrides)


@pytest.fixture
def gateway(upstream):
    servers = []

    def _start(**overrides):
        server = RunningServer(create_app(gateway_settings(upstream, **overrides)))
        server.__enter__()
        servers.append(server)
        return server

    yield _start
    for s in servers:
        s.__exit__(None, None, None)


def post(gw, payload, *, headers=None, timeout=10.0, **kw) -> httpx.Response:
    return httpx.post(f"{gw.url}/v1/chat/completions", json=payload, headers=headers or {}, timeout=timeout, **kw)


MSG = {"messages": [{"role": "user", "content": "Summarise the architecture review."}]}


# ---------------------------------------------------------------------------
# Header hygiene and credential handling
# ---------------------------------------------------------------------------
def test_client_headers_are_not_forwarded_and_server_credential_is_injected(gateway, upstream):
    gw = gateway()
    resp = post(
        gw,
        MSG,
        headers={
            "Authorization": "Bearer client-supplied-token-should-not-pass",
            "Cookie": "session=abc",
            "X-Forwarded-For": "10.1.2.3",
            "X-Custom-Internal": "topology",
            "OpenAI-Beta": "assistants=v2",
        },
    )
    assert resp.status_code == 200
    sent = upstream.app.state.requests[-1]["headers"]
    assert sent["authorization"] == f"Bearer {SERVER_KEY}"
    for forbidden in ("cookie", "x-forwarded-for", "x-custom-internal", "x-gateway-key"):
        assert forbidden not in sent
    assert sent["openai-beta"] == "assistants=v2"  # explicit provider pass-through allowlist
    assert SERVER_KEY not in resp.text
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Request-ID"]


def test_request_body_forwarded_unmodified_when_no_defaults_needed(gateway, upstream):
    gw = gateway()
    payload = {"model": "gpt-4o-mini", **MSG}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    resp = httpx.post(f"{gw.url}/v1/chat/completions", content=raw, headers={"content-type": "application/json"}, timeout=10)
    assert resp.status_code == 200
    assert upstream.app.state.requests[-1]["body"] == raw


def test_default_model_injected_for_openai(gateway, upstream):
    gw = gateway(default_model="gpt-4o-mini")
    assert post(gw, MSG).status_code == 200
    assert json.loads(upstream.app.state.requests[-1]["body"])["model"] == "gpt-4o-mini"


def test_gzip_upstream_is_decoded_without_content_encoding_mismatch(gateway, upstream):
    gw = gateway()
    upstream.app.state.script = {"kind": "gzip_json"}
    resp = post(gw, MSG)
    assert resp.status_code == 200
    assert "content-encoding" not in resp.headers
    assert resp.json()["object"] == "chat.completion"


def test_health_does_not_disclose_configuration(gateway):
    gw = gateway()
    body = httpx.get(f"{gw.url}/health").json()
    assert body["status"] == "healthy"
    assert "upstream" not in json.dumps(body)
    assert httpx.get(f"{gw.url}/docs").status_code == 404
    assert httpx.get(f"{gw.url}/openapi.json").status_code == 404
    assert httpx.post(f"{gw.url}/test/ssrf-probe", json={"target_url": "x"}).status_code in (404, 405)


def test_request_id_is_sanitised(gateway):
    gw = gateway()
    ok = post(gw, MSG, headers={"X-Request-ID": "trace-123"})
    assert ok.headers["X-Request-ID"] == "trace-123"
    bad = post(gw, MSG, headers={"X-Request-ID": "x" * 200})
    assert bad.headers["X-Request-ID"] != "x" * 200


# ---------------------------------------------------------------------------
# Egress DLP: bypass attempts
# ---------------------------------------------------------------------------
def test_sse_response_to_non_streaming_request_is_still_inspected(gateway, upstream):
    """Upstream answers with SSE although the client did not ask for streaming."""
    gw = gateway()
    upstream.app.state.script = {
        "kind": "sse",
        "chunks": content_events(["The key is ", AWS_KEY[:6], AWS_KEY[6:], " ok"]) + [b"data: [DONE]\n\n"],
    }
    resp = post(gw, MSG)
    assert AWS_KEY not in resp.text
    assert "credential_leak" in resp.text


def test_secret_in_non_streaming_tool_call_arguments_is_blocked(gateway, upstream):
    gw = gateway()
    body = chat_json("")
    body["choices"][0]["message"]["tool_calls"] = [
        {"id": "call_1", "type": "function", "function": {"name": "upload", "arguments": json.dumps({"token": GH_TOKEN})}}
    ]
    upstream.app.state.script = {"kind": "json", "body": body}
    resp = post(gw, MSG)
    assert resp.status_code == 403
    assert GH_TOKEN not in resp.text


def test_secret_in_upstream_error_body_is_blocked(gateway, upstream):
    gw = gateway()
    upstream.app.state.script = {"kind": "json", "status": 400, "body": {"error": {"message": f"bad key {AWS_KEY}"}}}
    resp = post(gw, MSG)
    assert resp.status_code == 403
    assert AWS_KEY not in resp.text


def test_streaming_secret_split_across_tool_call_arguments_is_blocked(gateway, upstream):
    gw = gateway()
    events = [
        sse_event(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {"tool_calls": [{"index": 0, "id": "call_9", "function": {"name": "send", "arguments": ""}}]},
                    }
                ]
            }
        ),
    ]
    for piece in ['{"value": "', GH_TOKEN[:10], GH_TOKEN[10:25], GH_TOKEN[25:], '"}']:
        events.append(
            sse_event({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": piece}}]}}]})
        )
    upstream.app.state.script = {"kind": "sse", "chunks": events + [b"data: [DONE]\n\n"]}
    resp = post(gw, {**MSG, "stream": True})
    assert GH_TOKEN[:10] not in resp.text.replace("ghp_...", "")
    assert "credential_leak" in resp.text


def test_streaming_secret_split_across_interleaved_choices_is_blocked(gateway, upstream):
    gw = gateway()
    events = []
    for i, piece in enumerate([AWS_KEY[:5], AWS_KEY[5:12], AWS_KEY[12:]]):
        events.append(sse_event({"choices": [{"index": 0, "delta": {"content": f"word{i} "}}]}))
        events.append(sse_event({"choices": [{"index": 1, "delta": {"content": piece}}]}))
    upstream.app.state.script = {"kind": "sse", "chunks": events + [b"data: [DONE]\n\n"]}
    resp = post(gw, {**MSG, "stream": True})
    assert AWS_KEY not in resp.text and AWS_KEY[5:12] not in resp.text
    assert "credential_leak" in resp.text


def test_clean_stream_is_delivered_intact(gateway, upstream):
    gw = gateway()
    pieces = [f"token{i} " for i in range(60)]
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(pieces) + [b"data: [DONE]\n\n"]}
    resp = post(gw, {**MSG, "stream": True})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.content == b"".join(content_events(pieces)) + b"data: [DONE]\n\n"


# ---------------------------------------------------------------------------
# Resource limits and failure injection
# ---------------------------------------------------------------------------
def test_oversized_upstream_response_is_rejected(gateway, upstream):
    gw = gateway(max_response_body_bytes=100_000)
    upstream.app.state.script = {"kind": "huge", "size": 1_000_000}
    resp = post(gw, MSG)
    assert resp.status_code == 502


def test_stream_total_size_limit(gateway, upstream):
    gw = gateway(stream_max_total_bytes=4096)
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(["benign text " * 20] * 30)}
    resp = post(gw, {**MSG, "stream": True})
    assert "stream_size_limit_exceeded" in resp.text


def test_stream_duration_limit(gateway, upstream):
    gw = gateway(stream_max_duration_s=1.0)
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(["slow "] * 40), "delay": 0.05}
    resp = post(gw, {**MSG, "stream": True})
    assert "stream_duration_limit_exceeded" in resp.text


def test_upstream_read_timeout_mid_stream_discards_held_content(gateway, upstream):
    gw = gateway(upstream_read_timeout_s=0.5)
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(["partial ", AWS_KEY[:8]]), "hang_after": 3}
    resp = post(gw, {**MSG, "stream": True})
    assert "upstream_timeout" in resp.text
    assert AWS_KEY[:8] not in resp.text


def test_client_disconnect_closes_upstream_and_releases_slot(gateway, upstream):
    gw = gateway(max_concurrent_requests=1)
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(["hello world " * 8] * 3), "hang_after": 10}
    with httpx.stream("POST", f"{gw.url}/v1/chat/completions", json={**MSG, "stream": True}, timeout=10) as resp:
        assert resp.status_code == 200
        next(resp.iter_bytes())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not upstream.app.state.stream_closed.is_set():
        time.sleep(0.05)
    assert upstream.app.state.stream_closed.is_set(), "upstream stream was not closed after client disconnect"
    limiter = gw.server.config.app.state.gateway.limiter
    while time.monotonic() < deadline and limiter.active:
        time.sleep(0.05)
    assert limiter.active == 0
    upstream.app.state.script = {"kind": "json"}
    assert post(gw, MSG).status_code == 200


def test_concurrency_limit_rejects_excess_requests(gateway, upstream):
    gw = gateway(max_concurrent_requests=1)
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(["held open "] * 2), "hang_after": 3}
    with httpx.stream("POST", f"{gw.url}/v1/chat/completions", json={**MSG, "stream": True}, timeout=10) as first:
        assert first.status_code == 200
        second = post(gw, MSG)
        assert second.status_code == 503
        assert second.headers.get("Retry-After") == "1"


def test_rate_limit_per_workload(gateway):
    gw = gateway(rate_limit_per_minute=2)
    codes = [post(gw, MSG).status_code for _ in range(3)]
    assert codes[:2] == [200, 200]
    assert codes[2] == 429


def test_chunked_body_over_limit_is_rejected(gateway):
    gw = gateway(max_request_body_bytes=2048)

    def body():
        for _ in range(64):
            yield b"A" * 1024

    resp = httpx.post(f"{gw.url}/v1/chat/completions", content=body(), headers={"content-type": "application/json"}, timeout=10)
    assert resp.status_code == 413


def test_slow_body_times_out(gateway):
    gw = gateway(request_body_timeout_s=0.5)
    with socket.create_connection(("127.0.0.1", gw.port), timeout=5) as sock:
        sock.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"
        )
        sock.settimeout(5)
        data = sock.recv(4096)
    assert b" 408 " in data.split(b"\r\n", 1)[0]


@pytest.mark.parametrize(
    "raw,status",
    [
        (b'{"model": "a", "model": "b", "messages": []}', 400),  # duplicate keys (parser differential)
        (b"[" * 5000 + b"]" * 5000, 400),  # nesting bomb
        (b'"just a string"', 400),
        (b"\xff\xfe not utf8", 400),
        (b'{"messages": [', 400),
    ],
)
def test_malformed_payloads_are_rejected(gateway, raw, status):
    gw = gateway()
    resp = httpx.post(f"{gw.url}/v1/chat/completions", content=raw, headers={"content-type": "application/json"}, timeout=10)
    assert resp.status_code == status


def test_wrong_content_type_is_rejected(gateway):
    gw = gateway()
    resp = httpx.post(f"{gw.url}/v1/chat/completions", content=b"{}", headers={"content-type": "text/plain"}, timeout=10)
    assert resp.status_code == 415


def test_upstream_connection_refused_maps_to_502(upstream):
    port = __import__("tests.conftest", fromlist=["free_port"]).free_port()
    settings = gateway_settings(upstream, upstream_url=f"http://127.0.0.1:{port}/v1/chat/completions")
    with RunningServer(create_app(settings)) as gw:
        assert post(gw, MSG).status_code == 502


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------
def _workloads():
    alpha = WorkloadCredential("svc-alpha", (digest_key(KEY_A), digest_key(KEY_A2)), frozenset({"gpt-4o-mini"}))
    bravo = WorkloadCredential.from_plaintext("svc-bravo", KEY_B)
    return (alpha, bravo)


def test_authentication_and_rotation(gateway, audit):
    gw = gateway(auth_mode="required", workloads=_workloads())
    assert post(gw, MSG).status_code == 401
    wrong = post(gw, MSG, headers={"X-Gateway-Key": KEY_A + "x"})
    assert wrong.status_code == 401 and wrong.headers["WWW-Authenticate"] == "Bearer"
    assert post(gw, {**MSG, "model": "gpt-4o-mini"}, headers={"X-Gateway-Key": KEY_A}).status_code == 200
    assert post(gw, {**MSG, "model": "gpt-4o-mini"}, headers={"Authorization": f"Bearer {KEY_A2}"}).status_code == 200
    joined = "\n".join(audit.records)
    # Header *values* (presented credentials, valid or not) must never be logged.
    for value in (KEY_A, KEY_A + "x", KEY_A2):
        assert value not in joined


def test_model_authorization_is_least_privilege(gateway):
    gw = gateway(auth_mode="required", workloads=_workloads())
    denied = post(gw, {**MSG, "model": "gpt-4o"}, headers={"X-Gateway-Key": KEY_A})
    assert denied.status_code == 403 and denied.json()["policy"] == "SEC-GOV-LLM-AUTHZ-004"
    # svc-bravo has no per-workload restriction
    assert post(gw, {**MSG, "model": "gpt-4o"}, headers={"X-Gateway-Key": KEY_B}).status_code == 200


def test_global_model_allowlist(gateway):
    gw = gateway(allowed_models=frozenset({"gpt-4o-mini*"}))
    assert post(gw, {**MSG, "model": "gpt-4o-mini-2024"}).status_code == 200
    assert post(gw, {**MSG, "model": "o1-preview"}).status_code == 403


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")  # startup is expected to fail
def test_gateway_refuses_to_start_without_credentials_when_auth_required(upstream):
    settings = gateway_settings(upstream, auth_mode="required", workloads=())
    with pytest.raises(ConfigError):
        settings.validate()
    with pytest.raises(RuntimeError):
        with RunningServer(create_app(settings)):
            pass


# ---------------------------------------------------------------------------
# Audit logging does not become a secret store
# ---------------------------------------------------------------------------
def test_ingress_violation_audit_event_contains_no_secret(gateway, audit):
    gw = gateway()
    resp = post(gw, {"messages": [{"role": "user", "content": f"deploy with {AWS_KEY} now"}]})
    assert resp.status_code == 403
    assert AWS_KEY not in resp.text
    events = [e for e in audit.events() if e["event_type"] == "INGRESS_VIOLATION"]
    assert events, audit.records
    ev = events[-1]
    assert AWS_KEY not in json.dumps(ev)
    assert ev["detections"][0]["detector"] == "aws_access_key_id"
    assert len(ev["detections"][0]["value_fingerprint"]) == 32
    assert ev["payload_fingerprint"] and ev["request_id"] and ev["event_id"]


def test_egress_stream_violation_audit_event_contains_no_secret(gateway, upstream, audit):
    gw = gateway()
    upstream.app.state.script = {"kind": "sse", "chunks": content_events(["key ", GH_TOKEN, " end"]) + [b"data: [DONE]\n\n"]}
    resp = post(gw, {**MSG, "stream": True})
    assert "credential_leak" in resp.text
    joined = "\n".join(audit.records)
    assert GH_TOKEN not in joined and GH_TOKEN[4:20] not in joined
    assert any(e["event_type"] == "EGRESS_DLP_LEAK" for e in audit.events())


def test_same_secret_yields_same_fingerprint_with_deployment_key(gateway, audit):
    gw = gateway(audit_hmac_key=b"k" * 32)
    for _ in range(2):
        post(gw, {"messages": [{"role": "user", "content": f"x {AWS_KEY}"}]})
    fps = [e["detections"][0]["value_fingerprint"] for e in audit.events() if e["event_type"] == "INGRESS_VIOLATION"]
    assert len(fps) >= 2 and fps[-1] == fps[-2]
    assert all(e["fingerprint_scope"] == "deployment" for e in audit.events() if "fingerprint_scope" in e)


# ---------------------------------------------------------------------------
# Entropy heuristic enforcement modes
# ---------------------------------------------------------------------------
RANDOM_TOKEN = "Xq7" + "bT9kLm2PzR4wVn8cYh3JsD6fGa1"  # context-free random token (no provider prefix/keyword)


def test_entropy_heuristic_block_mode_blocks(gateway):
    gw = gateway(entropy_mode="block")
    assert post(gw, {"messages": [{"role": "user", "content": f"use {RANDOM_TOKEN} to log in"}]}).status_code == 403


def test_entropy_heuristic_log_mode_allows_and_audits(gateway, audit):
    gw = gateway(entropy_mode="log")
    resp = post(gw, {"messages": [{"role": "user", "content": f"use {RANDOM_TOKEN} to log in"}]})
    assert resp.status_code == 200
    events = [e for e in audit.events() if e["event_type"] == "ENTROPY_HEURISTIC"]
    assert events and events[-1]["decision"] == "allow"
    assert RANDOM_TOKEN not in "\n".join(audit.records)
    # Pattern detectors still block in log mode.
    assert post(gw, {"messages": [{"role": "user", "content": f"key {AWS_KEY}"}]}).status_code == 403


@pytest.mark.parametrize("value,mode", [("true", "block"), ("false", "off"), ("log", "log"), ("BLOCK", "block")])
def test_entropy_mode_env_parsing(value, mode):
    assert Settings.from_env({"ENTROPY_DETECTION": value}).entropy_mode == mode


def test_anthropic_adapter_injects_x_api_key_and_version(gateway, upstream):
    gw = gateway(upstream_provider="anthropic")
    assert (
        post(gw, MSG, headers={"Authorization": "Bearer client-token-not-forwarded", "anthropic-beta": "tools-2024"}).status_code
        == 200
    )
    sent = upstream.app.state.requests[-1]["headers"]
    assert sent["x-api-key"] == SERVER_KEY
    assert sent["anthropic-version"] == "2023-06-01"
    assert sent["anthropic-beta"] == "tools-2024"
    assert "authorization" not in sent
    assert "model" not in json.loads(upstream.app.state.requests[-1]["body"])  # no OpenAI default injected
