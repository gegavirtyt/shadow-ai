"""Deterministic mock LLM upstream for performance measurement (no artificial delay unless requested).

Request fields (forwarded unchanged by the gateway):
* ``bench_tokens``   - number of SSE content events to stream (default 100)
* ``bench_delay_ms`` - delay between SSE events (default 0)
* ``bench_reply_bytes`` - size of the JSON completion content (default 200)
"""

from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

app = FastAPI()
WORDS = ["the", "gateway", "inspects", "every", "event", "before", "release", "and", "keeps", "latency", "low"]


@app.post("/v1/chat/completions")
async def completions(request: Request) -> Response:
    body = json.loads(await request.body())
    if body.get("stream") is True:
        n = int(body.get("bench_tokens", 100))
        delay = float(body.get("bench_delay_ms", 0)) / 1000.0

        async def gen():
            for i in range(n):
                chunk = {"id": "b", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": (" " if i else "") + WORDS[i % len(WORDS)]}}]}
                yield f"data: {json.dumps(chunk)}\n\n".encode()
                if delay:
                    await asyncio.sleep(delay)
            yield b"data: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")
    size = int(body.get("bench_reply_bytes", 200))
    content = (" ".join(WORDS) + " ") * (size // 60 + 1)
    payload = {"id": "b", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": content[:size]}}]}
    return Response(json.dumps(payload), media_type="application/json")
