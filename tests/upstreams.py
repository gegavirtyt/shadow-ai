"""Scriptable local upstream LLM server for integration and failure-injection tests.

Tests set ``app.state.script`` before each request. Every request received is
recorded in ``app.state.requests`` (headers + body) so tests can assert exactly what
the gateway forwarded upstream.
"""

from __future__ import annotations

import asyncio
import gzip
import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse


def chat_json(content: str = "Hello from the mock upstream.", **message_extra: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content, **message_extra}, "finish_reason": "stop"}],
    }


def sse_event(obj: Any) -> bytes:
    return f"data: {json.dumps(obj)}\n\n".encode()


def content_events(pieces: list[str]) -> list[bytes]:
    return [
        sse_event({"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": p}}]})
        for p in pieces
    ]


def build_upstream() -> FastAPI:
    app = FastAPI()
    app.state.script = {"kind": "json"}
    app.state.requests = []
    app.state.stream_closed = asyncio.Event()
    app.state.stream_cancelled = False

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Response:
        body = await request.body()
        app.state.requests.append({"headers": dict(request.headers), "body": body})
        script: dict[str, Any] = app.state.script
        kind = script.get("kind", "json")
        status = script.get("status", 200)
        headers = script.get("headers", {})

        if kind == "json":
            return Response(
                json.dumps(script.get("body", chat_json())),
                status,
                headers=headers,
                media_type=script.get("content_type", "application/json"),
            )
        if kind == "raw":
            return Response(
                script["data"], status, headers=headers, media_type=script.get("content_type", "application/octet-stream")
            )
        if kind == "gzip_json":
            data = gzip.compress(json.dumps(script.get("body", chat_json())).encode())
            return Response(data, status, headers={"content-encoding": "gzip", **headers}, media_type="application/json")
        if kind == "huge":
            size = int(script["size"])

            async def huge():
                sent = 0
                while sent < size:
                    yield b"x" * 65536
                    sent += 65536

            return StreamingResponse(huge(), status, media_type="application/json")
        if kind == "sse":
            chunks: list[bytes] = script["chunks"]
            delay = float(script.get("delay", 0.0))
            hang = float(script.get("hang_after", 0.0))
            app.state.stream_closed = asyncio.Event()
            app.state.stream_cancelled = False

            async def stream():
                try:
                    for c in chunks:
                        yield c
                        if delay:
                            await asyncio.sleep(delay)
                    if hang:
                        await asyncio.sleep(hang)
                except asyncio.CancelledError:
                    app.state.stream_cancelled = True
                    raise
                finally:
                    app.state.stream_closed.set()

            return StreamingResponse(stream(), status, headers=headers, media_type="text/event-stream")
        raise AssertionError(f"unknown script kind {kind}")

    return app
