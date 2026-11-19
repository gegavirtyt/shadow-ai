"""
Test Suite: Incremental SSE Parser & Streaming DLP Resilience.

Validates:
1. Single event in a single transport chunk.
2. Multiple events packed into a single transport chunk.
3. Event split across arbitrary chunk boundaries (including 1-byte chunks).
4. Multi-byte UTF-8 character split across chunk boundaries (e.g., emojis).
5. Split [DONE] stream termination markers.
6. Support for CRLF (\\r\\n\\r\\n) and LF (\\n\\n) SSE delimiters.
7. Proper handling of SSE comments (: ping).
8. Resilient handling of malformed JSON data lines (fallback scanning).
9. Fail-closed stream termination on abrupt EOF containing secrets.
"""

import json

import pytest
from src.proxy_gateway import (
    IncrementalSSEParser,
    stream_with_dlp_inspection,
)


def test_sse_parser_single_chunk_single_event():
    """Validates standard single SSE event parsing."""
    parser = IncrementalSSEParser()
    payload = json.dumps({"choices": [{"delta": {"content": "Hello, world!"}}]})
    chunk = f"data: {payload}\n\n".encode()

    events = parser.feed(chunk) + parser.finalize()
    assert len(events) == 1
    raw_event, delta = events[0]
    assert delta == "Hello, world!"
    assert "data:" in raw_event


def test_sse_parser_multiple_events_in_single_chunk():
    """Validates extraction when multiple SSE events arrive in one transport chunk."""
    parser = IncrementalSSEParser()
    p1 = json.dumps({"choices": [{"delta": {"content": "Part 1 "}}]})
    p2 = json.dumps({"choices": [{"delta": {"content": "Part 2"}}]})
    chunk = f"data: {p1}\n\ndata: {p2}\n\n".encode()

    events = parser.feed(chunk) + parser.finalize()
    assert len(events) == 2
    assert events[0][1] == "Part 1 "
    assert events[1][1] == "Part 2"


def test_sse_parser_single_byte_feeding():
    """
    Validates extreme transport fragmentation where bytes arrive one by one.
    The parser must buffer until event delimiters are reached.
    """
    parser = IncrementalSSEParser()
    payload = json.dumps({"choices": [{"delta": {"content": "Streamed token"}}]})
    data = f"data: {payload}\n\n".encode()

    collected = []
    for byte in data:
        evs = parser.feed(bytes([byte]))
        collected.extend(evs)
    collected.extend(parser.finalize())

    assert len(collected) == 1
    assert collected[0][1] == "Streamed token"


def test_sse_parser_split_multibyte_utf8():
    """
    Validates that 4-byte UTF-8 characters (e.g. key emoji 🔑) split across
    transport chunk boundaries are decoded without replacement errors.
    """
    parser = IncrementalSSEParser()
    emoji = "🔑"
    emoji_bytes = emoji.encode("utf-8")
    assert len(emoji_bytes) == 4

    p_prefix = 'data: {"choices": [{"delta": {"content": "Secret '
    p_suffix = '"}}]}\n\n'

    chunk1 = p_prefix.encode("utf-8") + emoji_bytes[:2]
    chunk2 = emoji_bytes[2:] + p_suffix.encode("utf-8")

    events1 = parser.feed(chunk1)
    assert len(events1) == 0  # No complete event yet

    events2 = parser.feed(chunk2) + parser.finalize()
    assert len(events2) == 1
    assert events2[0][1] == "Secret 🔑"


def test_sse_parser_crlf_and_lf_delimiters():
    """Validates parser tolerance for both CRLF and LF delimiters."""
    parser = IncrementalSSEParser()
    p1 = json.dumps({"choices": [{"delta": {"content": "CRLF"}}]})
    p2 = json.dumps({"choices": [{"delta": {"content": "LF"}}]})

    crlf_chunk = f"data: {p1}\r\n\r\n".encode()
    lf_chunk = f"data: {p2}\n\n".encode()

    evs1 = parser.feed(crlf_chunk)
    evs2 = parser.feed(lf_chunk)

    assert len(evs1) == 1 and evs1[0][1] == "CRLF"
    assert len(evs2) == 1 and evs2[0][1] == "LF"


def test_sse_parser_sse_comments_ignored():
    """SSE keep-alive comments (lines starting with ':') must be ignored cleanly."""
    parser = IncrementalSSEParser()
    p = json.dumps({"choices": [{"delta": {"content": "Live"}}]})
    chunk = f": keep-alive\n\ndata: {p}\n\n: ping\n\n".encode()

    events = parser.feed(chunk) + parser.finalize()
    # Filter non-empty delta events
    deltas = [d for _, d in events if d]
    assert deltas == ["Live"]


def test_sse_parser_split_done_marker():
    """Validates [DONE] marker split across transport boundaries."""
    parser = IncrementalSSEParser()
    chunk1 = b"data: [DO"
    chunk2 = b"NE]\n\n"

    evs1 = parser.feed(chunk1)
    assert len(evs1) == 0

    evs2 = parser.feed(chunk2) + parser.finalize()
    assert len(evs2) == 1
    raw_ev, delta = evs2[0]
    assert "[DONE]" in raw_ev
    assert delta is None


def test_sse_parser_malformed_json_fallback():
    """Malformed JSON in data line falls back to inspecting raw text."""
    parser = IncrementalSSEParser()
    chunk = b"data: {not valid json but has text}\n\n"

    events = parser.feed(chunk) + parser.finalize()
    assert len(events) == 1
    _, delta = events[0]
    assert "{not valid json but has text}" in delta


@pytest.mark.anyio
async def test_streaming_dlp_fail_closed_abrupt_eof():
    """
    Validates fail-closed security: if the stream ends abruptly without [DONE]
    and the remaining buffered text contains an AWS credential, the gateway
    must intercept it and yield an SSE error event instead of silently leaking it.
    """
    class MockAbruptEOFResponse:
        def __init__(self, chunks):
            self._chunks = list(chunks)
            self.status_code = 200
            self.headers = {"content-type": "text/event-stream"}

        async def aiter_bytes(self):
            for c in self._chunks:
                yield c

        async def aclose(self):
            pass

    # Send parts of an AWS credential across chunks, then abruptly terminate
    chunk1 = b'data: {"choices": [{"delta": {"content": "Your key is AKIA"}}]'
    chunk2 = b'}\n\n'
    chunk3 = b'data: {"choices": [{"delta": {"content": "IOSFODNN7EXAMPLE"}}]'
    chunk4 = b'}\n\n'

    mock_resp = MockAbruptEOFResponse([chunk1, chunk2, chunk3, chunk4])

    emitted_chunks = []
    async for output_chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        emitted_chunks.append(output_chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(emitted_chunks)
    # The secret must NOT be revealed in the clean payload
    assert "AKIAIOSFODNN7EXAMPLE" not in full_output
    # An error event must have been yielded
    assert "dlp_violation" in full_output or "credential_leak" in full_output
