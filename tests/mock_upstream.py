"""
Deterministic Local Mock Upstream LLM Server for Testing & Verification (v2.0.0).

Simulates an upstream foundation model provider (OpenAI / Bedrock / Anthropic / vLLM):
- Standard chat completions (HTTP 200)
- HTTP Error codes (HTTP 400, 401, 403, 429 Rate Limit, 500, 503)
- Malformed upstream responses (invalid JSON, non-UTF8)
- Upstream timeouts and latency delays
- Server-Sent Events (SSE) streaming modes:
  * Normal chunked streaming with data: [DONE]
  * Empty content deltas
  * Malformed SSE syntax
  * Mid-stream errors
  * Cross-chunk credential split (e.g. 'AKIA' + 'IOSFODNN7EXAMPLE')
  * Character-by-character credential split ('A' -> 'K' -> 'I' -> 'A'...)
  * Abrupt stream disconnects
"""

import asyncio
import json
import time
from collections.abc import AsyncGenerator

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

mock_app = FastAPI(title="Mock Upstream LLM Provider", version="2.0.0")


@mock_app.get("/health")
def health():
    return {"status": "healthy", "service": "mock-upstream-llm", "version": "2.0.0"}


@mock_app.post("/v1/chat/completions")
@mock_app.post("/api/v1/generate")
async def chat_completions(request: Request):
    try:
        raw_body = await request.body()
        body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        body = {}

    auth_header = request.headers.get("authorization", "")

    # 1. Error simulation via explicit trigger fields or headers
    sim_error = body.get("simulate_error") or request.headers.get("x-simulate-error")
    if sim_error == 400 or body.get("simulate_400"):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": {"message": "Invalid model parameter or payload syntax", "type": "invalid_request_error"}},
        )
    if sim_error == 401 or body.get("simulate_401") or "invalid-api-key" in auth_header:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": {"message": "Incorrect API key provided", "type": "invalid_request_error", "code": "invalid_api_key"}},
        )
    if sim_error == 403 or body.get("simulate_403"):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": {"message": "Country, region, or organization not supported", "type": "insufficient_quota"}},
        )
    if sim_error == 429 or body.get("simulate_429"):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": {"message": "Rate limit reached for requests", "type": "requests", "code": "rate_limit_exceeded"}},
            headers={"Retry-After": "5"},
        )
    if sim_error == 500 or body.get("simulate_500"):
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": {"message": "Simulated upstream provider internal error", "type": "server_error"}},
        )
    if sim_error == 503 or body.get("simulate_503"):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": {"message": "Overloaded engine. Please retry.", "type": "server_error"}},
        )

    # 2. Malformed JSON Response Simulation
    if body.get("simulate_malformed_json") is True:
        return Response(content=b"MALFORMED_NON_JSON_RESPONSE{{{", media_type="application/json")

    # 3. Timeout / Latency Delay Simulation
    delay = body.get("simulate_delay", 0)
    if delay > 0:
        await asyncio.sleep(min(delay, 20.0))

    # 4. Prompt content inspection for leak triggers
    prompt_str = str(body.get("prompt", "") or body.get("messages", ""))
    simulate_leak = (
        body.get("simulate_leak") is True
        or "simulate_credential_leak" in prompt_str
        or "simulate_leak" in prompt_str
    )
    leak_split_mode = body.get("leak_split_mode", "")  # "chunk_boundary", "char_by_char", "mid_stream_error", "empty_chunks", "disconnect"

    # 5. Server-Sent Events (SSE) Streaming
    if body.get("stream") is True:
        async def event_generator() -> AsyncGenerator[bytes, None]:
            # Mode A: Empty Chunks
            if leak_split_mode == "empty_chunks":
                for _ in range(3):
                    chunk = {
                        "id": "chatcmpl-stream-mock",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": body.get("model", "gpt-4o-mini"),
                        "choices": [{"index": 0, "delta": {}, "finish_reason": None}],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n".encode()
                    await asyncio.sleep(0.01)
                yield b"data: [DONE]\n\n"
                return

            # Mode B: Mid-stream Error
            if leak_split_mode == "mid_stream_error":
                chunk1 = {
                    "id": "chatcmpl-stream-mock",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": body.get("model", "gpt-4o-mini"),
                    "choices": [{"index": 0, "delta": {"content": "Processing query... "}, "finish_reason": None}],
                }
                yield f"data: {json.dumps(chunk1)}\n\n".encode()
                await asyncio.sleep(0.01)
                err_chunk = {"error": {"message": "Engine crashed mid-stream", "type": "server_error"}}
                yield f"data: {json.dumps(err_chunk)}\n\n".encode()
                return

            # Mode C: Abrupt Disconnect (Socket Close)
            if leak_split_mode == "disconnect":
                chunk1 = {
                    "id": "chatcmpl-stream-mock",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": body.get("model", "gpt-4o-mini"),
                    "choices": [{"index": 0, "delta": {"content": "Starting response before drop... "}, "finish_reason": None}],
                }
                yield f"data: {json.dumps(chunk1)}\n\n".encode()
                # Immediately terminate without [DONE]
                return

            # Mode D: Malformed SSE Syntax
            if leak_split_mode == "malformed_syntax":
                yield b"data: {\"choices\": [unparseable json content\n\n"
                return

            # Mode E: Cross-Chunk Credential Split (AKIA in Chunk 1, Rest in Chunk 2)
            if leak_split_mode == "chunk_boundary" or (simulate_leak and leak_split_mode == "split_chunks"):
                chunks = [
                    "Beginning confidential exfiltration: The AWS key prefix is AKIA",
                    "IOSFODNN7EXAMPLE which grants administrative access.",
                ]
                for text_piece in chunks:
                    chunk = {
                        "id": "chatcmpl-stream-mock",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": body.get("model", "gpt-4o-mini"),
                        "choices": [{"index": 0, "delta": {"content": text_piece}, "finish_reason": None}],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n".encode()
                    await asyncio.sleep(0.02)
                yield b"data: [DONE]\n\n"
                return

            # Mode F: Character-by-Character Split ('A' -> 'K' -> 'I' -> 'A'...)
            if leak_split_mode == "char_by_char":
                secret = "AKIAIOSFODNN7EXAMPLE"
                for ch in secret:
                    chunk = {
                        "id": "chatcmpl-stream-mock",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": body.get("model", "gpt-4o-mini"),
                        "choices": [{"index": 0, "delta": {"content": ch}, "finish_reason": None}],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n".encode()
                    await asyncio.sleep(0.01)
                yield b"data: [DONE]\n\n"
                return

            # Mode G: Standard Streaming (Clean or Full-Leak string)
            base_text = (
                "Upstream model response: The credential key is AKIAIOSFODNN7EXAMPLE."
                if simulate_leak
                else "This is a verified streaming completion response from the upstream model."
            )
            words = base_text.split(" ")
            for word in words:
                chunk = {
                    "id": "chatcmpl-stream-mock",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": body.get("model", "gpt-4o-mini"),
                    "choices": [{"index": 0, "delta": {"content": word + " "}, "finish_reason": None}],
                }
                yield f"data: {json.dumps(chunk)}\n\n".encode()
                await asyncio.sleep(0.02)
            yield b"data: [DONE]\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
        )

    # 6. Standard JSON Response
    content_text = (
        "Upstream model response: Confirmed. The internal master key is AKIAIOSFODNN7EXAMPLE."
        if simulate_leak
        else "This is a verified response from the upstream LLM foundation model service."
    )

    return {
        "id": "chatcmpl-mock-success",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "gpt-4o-mini"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content_text,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 15,
            "total_tokens": 27,
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(mock_app, host="127.0.0.1", port=8090)
