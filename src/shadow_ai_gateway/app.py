"""FastAPI application factory and request lifecycle.

Request lifecycle for proxied endpoints (each step fails closed):

1. Authenticate the workload (401).            5. Ingress DLP + injection heuristics (403).
2. Per-workload rate limit (429).              6. Model authorization (403).
3. Concurrency admission (503).                7. Forward over the SSRF-protected transport.
4. Content-Type, bounded body read, strict     8. Egress: SSE -> streaming guard; anything
   JSON parsing (415/413/408/400).                else -> bounded read + buffered DLP (403).

Whether egress is treated as a stream is decided by the *upstream response's*
Content-Type, never by the client's ``stream`` flag, so a mismatch cannot route a
response around inspection.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import anyio
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.types import Receive, Scope, Send

from . import __version__
from .audit import AuditLogger, RequestContext, configure_audit_logging
from .auth import WorkloadCredential, authenticate, extract_presented_key, model_permitted
from .config import ConfigError, Settings, settings_summary
from .detectors import Finding, scan_text_for_injection
from .inspection import (
    InspectionResult,
    PayloadError,
    describe,
    inspect_egress_body,
    inspect_json,
    iter_json_strings,
    parse_json_strict,
)
from .limits import ConcurrencyLimiter, ConcurrencySlot, RateLimiter
from .providers import (
    GATEWAY_HEADER,
    GATEWAY_HEADER_VALUE,
    apply_request_defaults,
    build_upstream_headers,
    filter_response_headers,
)
from .ssrf import async_validate_upstream_destination, create_upstream_client, validate_url_policy
from .streaming import StreamGuard, StreamViolation, guarded_sse, sse_error_event

logger = logging.getLogger("shadow_ai_gateway")

POLICY_AUTH = "SEC-GOV-LLM-AUTH-001"
POLICY_INGRESS = "SEC-GOV-LLM-001"
POLICY_EGRESS = "SEC-GOV-LLM-DLP-002"
POLICY_SSRF = "SEC-GOV-LLM-SSRF-003"
POLICY_MODEL = "SEC-GOV-LLM-AUTHZ-004"
POLICY_AVAILABILITY = "SEC-GOV-LLM-AVAIL-005"
POLICY_STREAM = "SEC-GOV-LLM-DLP-006"

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
PROXY_PATHS = ("/v1/chat/completions", "/generate", "/analyze")


class GatewayState:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client: httpx.AsyncClient | None = None
        self.limiter = ConcurrencyLimiter(settings.max_concurrent_requests)
        self.rate_limiter = RateLimiter(settings.rate_limit_per_minute)
        self.audit = AuditLogger(settings.audit_hmac_key, settings.upstream_host)
        self._validated = False

    def ensure_ready(self) -> httpx.AsyncClient:
        if not self._validated:
            self.settings.validate()
            self._validated = True
        if self.client is None:
            s = self.settings
            self.client = create_upstream_client(
                allowed_hosts=s.effective_allowed_hosts(),
                allow_local_mock=s.allow_local_mock,
                connect_timeout=s.upstream_connect_timeout_s,
                read_timeout=s.upstream_read_timeout_s,
                write_timeout=s.upstream_write_timeout_s,
                pool_timeout=s.upstream_pool_timeout_s,
                max_connections=s.upstream_max_connections,
                max_keepalive=s.upstream_max_keepalive,
                ca_bundle=s.ca_bundle,
            )
        return self.client


class _Reject(Exception):
    def __init__(self, status: int, content: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        super().__init__(status)
        self.status = status
        self.content = content
        self.headers = headers or {}


class GuardedStreamingResponse(StreamingResponse):
    """StreamingResponse that always runs ``cleanup`` (shielded from cancellation),
    even if the body iterator is never started (e.g. client gone before headers)."""

    def __init__(self, content: AsyncIterator[bytes], *, cleanup: Callable[[], Awaitable[None]], **kwargs: Any) -> None:
        super().__init__(content, **kwargs)
        self._cleanup = cleanup

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                await self._cleanup()


def _base_headers(ctx: RequestContext) -> dict[str, str]:
    return {
        GATEWAY_HEADER: GATEWAY_HEADER_VALUE,
        "X-Request-ID": ctx.request_id,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }


def _context(request: Request) -> RequestContext:
    supplied = request.headers.get("x-request-id", "")
    request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
    client_ip = request.client.host if request.client else "unknown"
    return RequestContext(request_id, client_ip, request.method, request.url.path)


async def _read_body_bounded(request: Request, settings: Settings) -> bytes:
    limit = settings.max_request_body_bytes
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise _Reject(400, {"error": "Bad Request", "reason": "Invalid Content-Length header."})
        if int(declared) > limit:
            raise _Reject(
                413,
                {"error": "Payload Too Large", "reason": f"Content-Length {declared} exceeds limit of {limit} bytes."},
            )
    chunks: list[bytes] = []
    size = 0
    try:
        with anyio.fail_after(settings.request_body_timeout_s):
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise _Reject(
                        413,
                        {"error": "Payload Too Large", "reason": f"Request body exceeds limit of {limit} bytes."},
                    )
                chunks.append(chunk)
    except TimeoutError as exc:
        raise _Reject(408, {"error": "Request Timeout", "reason": "Request body was not received in time."}) from exc
    return b"".join(chunks)


async def _read_upstream_bounded(resp: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in resp.aiter_bytes():
        size += len(chunk)
        if size > limit:
            raise _Reject(
                502, {"error": {"message": "Bad Gateway: upstream response exceeds size limit.", "type": "gateway_error"}}
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _inspect_injection(payload: Any) -> Finding | None:
    for path, value, _ in iter_json_strings(payload):
        if path.endswith("<key>"):
            continue
        found = scan_text_for_injection(value)
        if found:
            return found[0]
    return None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings.from_env()
    state = GatewayState(settings)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_audit_logging()
        state.ensure_ready()  # raises ConfigError: refuse to start with unsafe configuration
        logger.info("gateway configuration %s", json.dumps(settings_summary(settings)))
        try:
            yield
        finally:
            if state.client is not None:
                await state.client.aclose()
                state.client = None

    app = FastAPI(
        title="Shadow AI Defensive Proxy Gateway",
        description="Bi-directional inspection gateway for LLM API traffic.",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.gateway = state

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "healthy", "service": "shadow-ai-proxy-gateway", "version": __version__}

    @app.get("/ready")
    async def ready() -> Response:
        try:
            state.ensure_ready()
        except ConfigError:
            return JSONResponse({"status": "not_ready"}, status_code=503)
        return JSONResponse({"status": "ready"})

    async def authorize(request: Request, ctx: RequestContext) -> WorkloadCredential | None:
        if settings.auth_mode == "disabled":
            return None
        result = authenticate(extract_presented_key(request.headers), settings.workloads)
        if not result.ok:
            state.audit.emit(
                "AUTH_VIOLATION", decision="block", policy_id=POLICY_AUTH, ctx=ctx, reason=result.error or "Unauthorized"
            )
            raise _Reject(
                401,
                {
                    "error": "Unauthorized: Workload Gateway Authentication Required",
                    "reason": result.error,
                    "policy": POLICY_AUTH,
                },
                {"WWW-Authenticate": "Bearer"},
            )
        if result.workload is None:  # contract of authenticate(); explicit so -O cannot remove it
            raise RuntimeError("authentication succeeded without a workload")
        ctx.workload_id = result.workload.workload_id
        return result.workload

    async def proxy(request: Request) -> Response:
        ctx = _context(request)
        try:
            state.ensure_ready()
        except ConfigError as exc:
            logger.error("gateway misconfigured: %s", exc)
            return JSONResponse({"error": "Service Unavailable: gateway misconfigured"}, 503, headers=_base_headers(ctx))
        slot: ConcurrencySlot | None = None
        try:
            workload = await authorize(request, ctx)
            allowed, retry_after = state.rate_limiter.allow(ctx.workload_id or "anonymous")
            if not allowed:
                state.audit.emit("RATE_LIMITED", decision="block", policy_id=POLICY_AVAILABILITY, ctx=ctx, reason="rate limit")
                raise _Reject(
                    429,
                    {"error": "Too Many Requests", "policy": POLICY_AVAILABILITY},
                    {"Retry-After": str(max(1, math.ceil(retry_after)))},
                )
            slot = state.limiter.try_acquire()
            if slot is None:
                raise _Reject(
                    503,
                    {"error": "Service Unavailable: concurrency limit reached", "policy": POLICY_AVAILABILITY},
                    {"Retry-After": "1"},
                )
            response = await _handle_admitted(request, ctx, workload, slot)
            if isinstance(response, GuardedStreamingResponse):
                slot = None  # ownership moved to the streaming response's cleanup
            return response
        except _Reject as rej:
            return JSONResponse(rej.content, rej.status, headers={**_base_headers(ctx), **rej.headers})
        finally:
            if slot is not None:
                slot.release()

    async def _handle_admitted(
        request: Request, ctx: RequestContext, workload: WorkloadCredential | None, slot: ConcurrencySlot
    ) -> Response:
        media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if media_type != "application/json":
            raise _Reject(
                415,
                {
                    "error": "Unsupported Media Type",
                    "reason": f"Content-Type '{media_type}' is not supported. Expected 'application/json'.",
                },
            )
        body = await _read_body_bounded(request, settings)
        try:
            payload = parse_json_strict(body, settings.max_json_depth)
        except PayloadError as exc:
            raise _Reject(400, {"error": "Bad Request", "reason": str(exc)}) from exc
        if not isinstance(payload, dict):
            raise _Reject(400, {"error": "Bad Request", "reason": "Request body must be a JSON object."})

        # Ingress inspection: secrets always block; injection heuristics per policy mode.
        result = inspect_json(payload, entropy=settings.entropy_mode == "block", injection=False)
        finding = result.primary
        if finding is None and settings.entropy_mode == "log":
            _log_entropy_heuristic(inspect_json(payload, entropy=True, injection=False), ctx, "ingress")
        field_path = result.field_path
        if finding is None and settings.prompt_injection_mode != "off":
            injection = _inspect_injection(payload)
            if injection is not None:
                if settings.prompt_injection_mode == "block":
                    finding = injection
                else:
                    state.audit.emit(
                        "INGRESS_INJECTION_HEURISTIC",
                        decision="allow",
                        policy_id=POLICY_INGRESS,
                        ctx=ctx,
                        reason="prompt-injection heuristic matched (log-only mode)",
                        findings=[injection],
                    )
        if finding is not None:
            reason = f"Field '{field_path}' violation -> {describe(finding)}" if field_path else describe(finding)
            state.audit.emit(
                "INGRESS_VIOLATION",
                decision="block",
                policy_id=POLICY_INGRESS,
                ctx=ctx,
                reason=describe(finding),
                findings=[finding],
                payload=body,
                extra={"field_path": field_path},
            )
            raise _Reject(
                403,
                {
                    "error": "Forbidden: Security Violation Detected",
                    "reason": reason,
                    "policy": POLICY_INGRESS,
                    "client_ip": ctx.client_ip,
                },
            )

        # Model authorization (least privilege).
        modified = apply_request_defaults(settings.upstream_provider, payload, settings.default_model)
        model = payload.get("model")
        if model is not None and not isinstance(model, str):
            raise _Reject(400, {"error": "Bad Request", "reason": "'model' must be a string."})
        restricted = bool(settings.allowed_models) or bool(workload and workload.allowed_models)
        if restricted and (not model or not model_permitted(model, workload, settings.allowed_models)):
            state.audit.emit(
                "AUTHZ_VIOLATION",
                decision="block",
                policy_id=POLICY_MODEL,
                ctx=ctx,
                reason="model not permitted for workload",
                extra={"model": model if isinstance(model, str) and len(model) <= 128 else None},
            )
            raise _Reject(
                403,
                {
                    "error": "Forbidden: Model Not Authorized",
                    "reason": f"Model '{model}' is not permitted for this workload.",
                    "policy": POLICY_MODEL,
                },
            )

        streaming_requested = payload.get("stream") is True
        upstream_body = json.dumps(payload).encode("utf-8") if modified else body
        headers = build_upstream_headers(
            settings.upstream_provider, settings.upstream_api_key, request.headers, streaming_requested
        )
        client = state.ensure_ready()
        upstream_req = client.build_request("POST", settings.upstream_url, content=upstream_body, headers=headers)
        try:
            upstream = await client.send(upstream_req, stream=True)
        except httpx.TimeoutException as exc:
            logger.warning("upstream timeout (%s) request_id=%s", type(exc).__name__, ctx.request_id)
            raise _Reject(504, {"error": "Gateway Timeout: Upstream LLM provider did not respond within timeout."}) from exc
        except httpx.HTTPError as exc:
            if "SSRF blocked" in str(exc):
                state.audit.emit("SSRF_BLOCKED", decision="block", policy_id=POLICY_SSRF, ctx=ctx, reason=str(exc)[:300])
                raise _Reject(
                    502, {"error": "Bad Gateway: upstream destination refused by egress policy.", "policy": POLICY_SSRF}
                ) from exc
            logger.warning("upstream connection failure (%s) request_id=%s", type(exc).__name__, ctx.request_id)
            raise _Reject(502, {"error": "Bad Gateway: Connection to upstream LLM provider failed."}) from exc

        handed_off = False
        try:
            if 300 <= upstream.status_code < 400:
                await _reject_redirect(upstream, ctx)
            content_type = upstream.headers.get("content-type", "")
            if "text/event-stream" in content_type.lower() and 200 <= upstream.status_code < 300:
                handed_off = True
                return _streaming_response(upstream, ctx, slot)
            try:
                data = await _read_upstream_bounded(upstream, settings.max_response_body_bytes)
            except httpx.TimeoutException as exc:
                raise _Reject(504, {"error": "Gateway Timeout: Upstream LLM provider did not respond within timeout."}) from exc
            except httpx.HTTPError as exc:
                raise _Reject(502, {"error": "Bad Gateway: Internal upstream communication failure."}) from exc
        finally:
            if not handed_off:
                await upstream.aclose()

        return _buffered_response(upstream, data, ctx)

    def _log_entropy_heuristic(result: InspectionResult, ctx: RequestContext, direction: str) -> None:
        if result.primary is not None:
            state.audit.emit(
                "ENTROPY_HEURISTIC",
                decision="allow",
                policy_id=POLICY_INGRESS if direction == "ingress" else POLICY_EGRESS,
                ctx=ctx,
                reason=f"{direction} high-entropy token (log-only mode)",
                findings=[result.primary],
                extra={"field_path": result.field_path},
            )

    async def _reject_redirect(upstream: httpx.Response, ctx: RequestContext) -> None:
        location = upstream.headers.get("location", "")
        target = str(httpx.URL(settings.upstream_url).join(location)) if location else ""
        ok: bool = False
        reason: str | None = "missing Location"
        if target:
            ok, reason = await async_validate_upstream_destination(
                target, allow_local_mock=settings.allow_local_mock, allowed_hosts=settings.effective_allowed_hosts()
            )
        if not ok:
            state.audit.emit(
                "SSRF_REDIRECT_BLOCKED",
                decision="block",
                policy_id=POLICY_SSRF,
                ctx=ctx,
                reason=f"Prohibited upstream redirect: {reason}",
                extra={"redirect_host": httpx.URL(target).host if target else None},
            )
            raise _Reject(403, {"error": "Forbidden: SSRF Redirect Violation", "reason": reason, "policy": POLICY_SSRF})
        raise _Reject(502, {"error": "Bad Gateway: upstream redirects are not followed.", "policy": POLICY_SSRF})

    def _buffered_response(upstream: httpx.Response, data: bytes, ctx: RequestContext) -> Response:
        result = inspect_egress_body(data, entropy=settings.entropy_mode == "block")
        if not result.blocked and settings.entropy_mode == "log":
            _log_entropy_heuristic(inspect_egress_body(data, entropy=True), ctx, "egress")
        if result.blocked:
            finding = result.primary
            if finding is None:
                raise RuntimeError("blocked result without a finding")
            reason = describe(finding, egress=True)
            state.audit.emit(
                "EGRESS_DLP_LEAK",
                decision="block",
                policy_id=POLICY_EGRESS,
                ctx=ctx,
                reason=reason,
                findings=[finding],
                payload=data,
                extra={"field_path": result.field_path, "upstream_status": upstream.status_code},
            )
            return JSONResponse(
                {
                    "error": "Forbidden: Outbound Data Loss Prevention (DLP) Violation",
                    "reason": reason,
                    "policy": POLICY_EGRESS,
                    "client_ip": ctx.client_ip,
                },
                403,
                headers=_base_headers(ctx),
            )
        content_type = upstream.headers.get("content-type", "application/json")
        is_json_type = "json" in content_type.lower()
        if is_json_type or upstream.status_code >= 400:
            try:
                json.loads(data.decode("utf-8")) if data else None
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                if 200 <= upstream.status_code < 300:
                    logger.error("upstream returned malformed JSON request_id=%s", ctx.request_id)
                    return JSONResponse(
                        {"error": {"message": "Bad Gateway: Malformed non-JSON payload from upstream LLM provider."}},
                        502,
                        headers=_base_headers(ctx),
                    )
                wrapped = {"error": {"message": data.decode("utf-8", errors="replace")[:2048], "type": "upstream_error"}}
                return JSONResponse(
                    wrapped, upstream.status_code, headers={**filter_response_headers(upstream.headers), **_base_headers(ctx)}
                )
        headers = {**filter_response_headers(upstream.headers), **_base_headers(ctx)}
        headers.pop("content-type", None)
        return Response(content=data, status_code=upstream.status_code, headers=headers, media_type=content_type)

    def _streaming_response(upstream: httpx.Response, ctx: RequestContext, slot: ConcurrencySlot) -> GuardedStreamingResponse:
        async def cleanup() -> None:
            try:
                await upstream.aclose()
            finally:
                slot.release()

        headers = {**filter_response_headers(upstream.headers), **_base_headers(ctx), "X-Accel-Buffering": "no"}
        headers.pop("content-type", None)
        return GuardedStreamingResponse(
            _guarded_stream(upstream, ctx),
            cleanup=cleanup,
            status_code=upstream.status_code,
            headers=headers,
            media_type="text/event-stream",
        )

    async def _guarded_stream(upstream: httpx.Response, ctx: RequestContext) -> AsyncIterator[bytes]:
        def violation_bytes(v: StreamViolation, guard: StreamGuard) -> bytes:
            findings = [v.finding] if v.finding else []
            event_type = "EGRESS_DLP_LEAK" if v.finding else "STREAM_POLICY_VIOLATION"
            reason = describe(v.finding, egress=True) if v.finding else v.message
            state.audit.emit(
                event_type,
                decision="block",
                policy_id=POLICY_STREAM,
                ctx=ctx,
                reason=reason,
                findings=findings,
                extra={"stream_code": v.code, "events_seen": guard.events_seen, "events_released": guard.events_released},
            )
            message = f"Outbound DLP Violation: {reason} intercepted in model stream" if v.finding else v.message
            return sse_error_event(v.code, message)

        try:
            async for raw in guarded_sse(
                upstream.aiter_bytes(),
                lookback=settings.stream_lookback_chars,
                max_hold_chars=settings.stream_max_hold_chars,
                entropy=settings.entropy_mode == "block",  # log mode: not evaluated in streams
                max_event_bytes=settings.stream_max_event_bytes,
                max_total_bytes=settings.stream_max_total_bytes,
                max_duration_s=settings.stream_max_duration_s,
                on_violation=violation_bytes,
            ):
                yield raw
        except httpx.TimeoutException:
            logger.warning("upstream stream timeout request_id=%s", ctx.request_id)
            yield sse_error_event("upstream_timeout", "Upstream stream timed out; held content was discarded")
        except httpx.HTTPError as exc:
            logger.warning("upstream stream failure (%s) request_id=%s", type(exc).__name__, ctx.request_id)
            yield sse_error_event("upstream_stream_error", "Upstream stream failed; held content was discarded")

    for path in PROXY_PATHS:
        app.add_api_route(path, proxy, methods=["POST"], include_in_schema=True)

    if settings.enable_test_endpoints:

        @app.post("/test/ssrf-probe", include_in_schema=False)
        async def ssrf_probe(request: Request) -> Response:
            ctx = _context(request)
            try:
                await authorize(request, ctx)
                body = parse_json_strict(await _read_body_bounded(request, settings), settings.max_json_depth)
            except _Reject as rej:
                return JSONResponse(rej.content, rej.status, headers=rej.headers)
            except PayloadError as exc:
                return JSONResponse({"error": str(exc)}, 400)
            target = body.get("target_url", "") if isinstance(body, dict) else ""
            if not isinstance(target, str):
                return JSONResponse({"error": "target_url must be a string"}, 400)
            hosts = settings.allowed_upstream_hosts
            ok, reason = validate_url_policy(target, hosts, False)[:2]
            if ok:
                ok, reason = await async_validate_upstream_destination(target, allow_local_mock=False, allowed_hosts=hosts)
            if not ok:
                state.audit.emit("SSRF_BLOCKED", decision="block", policy_id=POLICY_SSRF, ctx=ctx, reason=reason or "blocked")
                return JSONResponse({"error": reason}, 403)
            return JSONResponse({"status": "allowed", "destination": target})

    return app


# ASGI entry point: ``uvicorn shadow_ai_gateway.app:app``. Configuration is read from
# the environment at import time and validated at startup (lifespan).
app = create_app()
