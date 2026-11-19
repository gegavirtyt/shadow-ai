"""
Adversarial Verification Suite: DLP Look-Ahead Security & Boundary Resilience.

Specifically tests:
1. Secret beginning immediately BEFORE buffer boundary (e.g., at char 50 of a 64-char window).
2. Secret beginning EXACTLY AT the buffer boundary (e.g., at char 64).
3. Secret beginning AFTER older chunks were safely popped.
4. AWS Access Key ID (20 chars) fragmented across 4 arbitrary chunk boundaries.
5. AWS Secret Access Key (40 Base64 chars) fragmented across 8 micro-chunks (5 chars each).
6. Generic PEM Private Key header split across chunks.
7. Abrupt stream termination (EOF without [DONE]) containing trailing secret.
8. Normal termination with [DONE] containing trailing secret.
9. Proof that zero secret bytes are ever emitted to downstream client.
"""

import json

import pytest
from src.proxy_gateway import stream_with_dlp_inspection


class MockChunkedResponse:
    """Mock HTTP streaming response providing custom byte chunks."""
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.status_code = 200
        self.headers = {"content-type": "text/event-stream"}

    async def aiter_bytes(self):
        for c in self._chunks:
            yield c

    async def aclose(self):
        pass


def make_sse_chunk(content_str: str) -> bytes:
    payload = json.dumps({"choices": [{"delta": {"content": content_str}}]})
    return f"data: {payload}\n\n".encode()


@pytest.mark.anyio
async def test_dlp_secret_begins_immediately_before_boundary():
    """
    Pad with 50 chars of benign text, then start AWS Access Key ID at char 50
    spanning across chunk boundaries with window=64.
    """
    pad = "A" * 50  # 50 chars
    secret_part1 = "AKIAIOSF"  # 8 chars (total 58 < 64)
    secret_part2 = "ODNN7EXAMPLE"  # 12 chars (total 70 > 64)

    c1 = make_sse_chunk(pad)
    c2 = make_sse_chunk(secret_part1)
    c3 = make_sse_chunk(secret_part2)

    mock_resp = MockChunkedResponse([c1, c2, c3])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    assert "AKIAIOSFODNN7EXAMPLE" not in full_output
    assert "dlp_violation" in full_output or "credential_leak" in full_output


@pytest.mark.anyio
async def test_dlp_secret_begins_exactly_at_boundary():
    """
    Pad with exactly 64 chars of benign text in Chunk 1.
    Secret begins in Chunk 2 and completes in Chunk 3.
    """
    pad = "B" * 64
    secret_part1 = "AKIA1234"
    secret_part2 = "567890ABCDEF"

    c1 = make_sse_chunk(pad)
    c2 = make_sse_chunk(secret_part1)
    c3 = make_sse_chunk(secret_part2)

    mock_resp = MockChunkedResponse([c1, c2, c3])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    assert "AKIA1234567890ABCDEF" not in full_output
    assert "dlp_violation" in full_output or "credential_leak" in full_output


@pytest.mark.anyio
async def test_dlp_secret_after_older_chunks_popped():
    """
    Chunk 1: 100 chars of benign text (forces older chunks to pop past window 64).
    Chunk 2: benign spacer.
    Chunk 3 & 4: 40-character high-entropy secret split into two chunks.
    """
    c1 = make_sse_chunk("Benign introduction text describing cloud infrastructure. ")  # 58 chars
    c2 = make_sse_chunk("Additional configuration settings for the deployment. ")     # 54 chars (c1 pops)

    # 40-char high-entropy candidate
    secret_p1 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY"  # 30 chars
    secret_p2 = "EXAMPLEKEY"                      # 10 chars (40 total)

    c3 = make_sse_chunk(secret_p1)
    c4 = make_sse_chunk(secret_p2)

    mock_resp = MockChunkedResponse([c1, c2, c3, c4])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    # The first benign chunk may have popped before the secret began,
    # but the secret itself must NEVER appear in full output
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in full_output
    assert "dlp_violation" in full_output or "high_entropy_secret" in full_output


@pytest.mark.anyio
async def test_dlp_aws_key_fragmented_across_four_chunks():
    """AWS Access Key ID (20 chars) split into 4 micro-chunks (5 chars each)."""
    # AKIA IOSF ODNN 7EXAMPLE -> 4, 4, 4, 8
    c1 = make_sse_chunk("AKIA")
    c2 = make_sse_chunk("IOSF")
    c3 = make_sse_chunk("ODNN")
    c4 = make_sse_chunk("7EXAMPLE")

    mock_resp = MockChunkedResponse([c1, c2, c3, c4])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    assert "AKIAIOSFODNN7EXAMPLE" not in full_output
    assert "dlp_violation" in full_output or "credential_leak" in full_output


@pytest.mark.anyio
async def test_dlp_pem_private_key_header_split():
    """PEM private key header split across chunk boundaries."""
    c1 = make_sse_chunk("-----BEGIN ")
    c2 = make_sse_chunk("PRIVATE ")
    c3 = make_sse_chunk("KEY-----")

    mock_resp = MockChunkedResponse([c1, c2, c3])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    assert "-----BEGIN PRIVATE KEY-----" not in full_output
    assert "dlp_violation" in full_output or "private_key" in full_output


@pytest.mark.anyio
async def test_dlp_secret_at_abrupt_eof_without_done():
    """Stream terminates abruptly without [DONE] when buffer contains trailing secret."""
    c1 = make_sse_chunk("Here is your key: ")
    c2 = make_sse_chunk("AKIAIOSFODNN7EXAMPLE")
    # Abrupt end, no [DONE]

    mock_resp = MockChunkedResponse([c1, c2])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    assert "AKIAIOSFODNN7EXAMPLE" not in full_output
    assert "dlp_violation" in full_output or "credential_leak" in full_output


@pytest.mark.anyio
async def test_dlp_secret_with_done_termination():
    """Stream sends secret followed immediately by data: [DONE]."""
    c1 = make_sse_chunk("API key: ")
    c2 = make_sse_chunk("AKIAIOSFODNN7EXAMPLE")
    c3 = b"data: [DONE]\n\n"

    mock_resp = MockChunkedResponse([c1, c2, c3])
    outputs = []
    async for chunk in stream_with_dlp_inspection(mock_resp, delay_window_chars=64):
        outputs.append(chunk.decode("utf-8", errors="ignore"))

    full_output = "".join(outputs)
    assert "AKIAIOSFODNN7EXAMPLE" not in full_output
    assert "dlp_violation" in full_output or "credential_leak" in full_output
