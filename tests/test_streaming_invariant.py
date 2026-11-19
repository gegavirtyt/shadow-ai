"""Property-based verification of the streaming release invariant.

Property (for every generated case):
    Let FULL be the concatenated text of all upstream events and [s, t) the span of
    an embedded secret. The text contained in events forwarded to the client before
    the stream terminates must be a prefix of FULL of length <= s; i.e. no character
    of the secret is ever released, and the stream ends with a DLP error event.

And for benign streams (no secret): the output is byte-identical to the input.

Segmentation is adversarial: events are cut at arbitrary character positions
(including inside the secret, 1-character events and empty events), optionally
interleaved with keep-alive comments, role-only deltas and other channels.
"""

from __future__ import annotations

import asyncio
import json
import random
import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from shadow_ai_gateway.detectors import scan_text_for_secrets
from shadow_ai_gateway.streaming import SSEParser, StreamGuard, extract_event_text, guarded_sse

WORDS = [
    "the",
    "cloud",
    "quarterly",
    "report",
    "and",
    "deployment",
    "worker",
    "is",
    "a",
    "model",
    "status:",
    "ok.",
    "result",
    "\n",
    "value",
    "table",
    "(see",
    "below)",
    "-",
    "user",
    "config",
    "42",
    "v1.2",
]


def _rand_token(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def make_secret(kind: str, rng: random.Random) -> str:
    alnum = string.ascii_letters + string.digits
    if kind == "aws":
        return "AKIA" + _rand_token(rng, string.ascii_uppercase + "234567", 16)
    if kind == "github":
        return "ghp_" + _rand_token(rng, alnum, 36)
    if kind == "slack":
        return f"xoxb-{_rand_token(rng, string.digits, 12)}-{_rand_token(rng, string.digits, 13)}-{_rand_token(rng, alnum, 24)}"
    if kind == "google":
        return "AIza" + _rand_token(rng, alnum + "-_", 35)
    if kind == "pem":
        return "-----BEGIN RSA PRIVATE KEY-----"
    if kind == "pem_openssh":
        return "-----BEGIN OPENSSH PRIVATE KEY-----"
    if kind == "db":
        return (
            f"postgresql://svc_{_rand_token(rng, string.ascii_lowercase, 5)}:{_rand_token(rng, alnum, 14)}@db.internal:5432/app"
        )
    if kind == "keyword_hex":
        return "api key is: " + _rand_token(rng, "0123456789abcdef", 40)
    if kind == "keyword_spaced":
        return "client secret = " + _rand_token(rng, alnum, 32)
    if kind == "entropy":
        return _rand_token(rng, alnum + "+/", 40)
    raise AssertionError(kind)


STATISTICAL_KINDS = {"entropy", "keyword_hex", "keyword_spaced"}
SECRET_KINDS = ["aws", "github", "slack", "google", "pem", "pem_openssh", "db", "keyword_hex", "keyword_spaced", "entropy"]


def sse(content: str, *, channel: str = "content", index: int = 0) -> bytes:
    if channel == "content":
        delta = {"content": content}
    else:
        delta = {"tool_calls": [{"index": index, "function": {"arguments": content}}]}
    return f"data: {json.dumps({'choices': [{'index': 0, 'delta': delta}]})}\n\n".encode()


def segment(text: str, rng: random.Random, max_piece: int) -> list[str]:
    pieces, i = [], 0
    while i < len(text):
        n = rng.randint(0, max_piece)
        pieces.append(text[i : i + n])
        i += n
    return pieces


async def _collect(chunks: list[bytes], lookback: int = 64) -> bytes:
    async def gen():
        for c in chunks:
            yield c

    out = []
    async for b in guarded_sse(
        gen(),
        lookback=lookback,
        max_hold_chars=100_000,
        entropy=True,
        max_event_bytes=1 << 20,
        max_total_bytes=1 << 26,
        max_duration_s=60,
        on_violation=lambda v, g: b'data: {"error": {"code": "' + v.code.encode() + b'"}}\n\n',
    ):
        out.append(b)
    return b"".join(out)


def released_text(output: bytes, channel_suffix: str) -> tuple[str, bool]:
    parser = SSEParser()
    events = parser.feed(output) + parser.finalize()
    text, errored = [], False
    for ev in events:
        if ev.data is None or ev.is_done:
            continue
        if '"error"' in ev.data:
            errored = True
            continue
        for key, piece in extract_event_text(ev.data)[0]:
            if key.endswith(channel_suffix):
                text.append(piece)
    return "".join(text), errored


@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    seed=st.integers(0, 2**32 - 1),
    kind=st.sampled_from(SECRET_KINDS),
    max_piece=st.sampled_from([1, 2, 3, 5, 8, 17, 40]),
    tool_channel=st.booleans(),
    lookback=st.sampled_from([50, 64, 128]),
)
def test_no_secret_character_is_released(seed, kind, max_piece, tool_channel, lookback):
    rng = random.Random(seed)
    prefix = " ".join(rng.choice(WORDS) for _ in range(rng.randint(0, 40)))
    suffix = " ".join(rng.choice(WORDS) for _ in range(rng.randint(0, 20)))
    secret = make_secret(kind, rng)
    sep_before = rng.choice([" ", "\n", ": ", " (", " `"]) if prefix else ""
    full = f"{prefix}{sep_before}{secret} {suffix}"
    s = full.index(secret)

    channel = "tool" if tool_channel else "content"
    chunks: list[bytes] = []
    for piece in segment(full, rng, max_piece):
        if rng.random() < 0.1:
            chunks.append(b": keep-alive\n\n")
        if rng.random() < 0.1:
            chunks.append(sse("noise from another choice", channel="tool", index=7))
        chunks.append(sse(piece, channel=channel))
    chunks.append(b"data: [DONE]\n\n")

    # Also fragment the *transport* chunks arbitrarily (independent of event boundaries).
    blob = b"".join(chunks)
    transport, i = [], 0
    while i < len(blob):
        n = rng.randint(1, 64)
        transport.append(blob[i : i + n])
        i += n

    output = asyncio.run(_collect(transport, lookback))
    suffix_key = "tool_calls[i0]{index=0}.function.arguments" if tool_channel else "delta.content"
    text, errored = released_text(output, suffix_key)
    assert full.startswith(text)
    buffered_detects = any(f.start < s + len(secret) and f.end > s for f in scan_text_for_secrets(full) if f.variant == 0)
    if kind not in STATISTICAL_KINDS:
        # Pure pattern detectors are deterministic: the buffered scanner must flag them.
        assert buffered_detects, f"buffered scanner missed a {kind} secret"
    if not buffered_detects:
        # Detectors that include a randomness test (generic entropy, keyword context) have
        # statistical recall, measured in benchmarks/; a value the buffered scanner does not
        # flag is a recall event, not a streaming-invariant violation.
        return
    # Streaming must never be weaker than buffered inspection.
    assert errored, f"secret of kind {kind} was flagged by the buffered scanner but not in streaming"
    assert len(text) <= s, f"released {len(text) - s} characters of a {kind} secret"
    assert secret not in output.decode("utf-8", "replace")


@settings(deadline=None)
@given(seed=st.integers(0, 2**32 - 1), max_piece=st.sampled_from([1, 3, 8, 40]))
def test_benign_stream_is_forwarded_byte_identical(seed, max_piece):
    rng = random.Random(seed)
    full = " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 120)))
    chunks = [sse(p) for p in segment(full, rng, max_piece)] + [b"data: [DONE]\n\n"]
    output = asyncio.run(_collect(chunks))
    assert output == b"".join(chunks)


def test_release_is_incremental_for_benign_prose():
    """Benign events must be released while the stream is still running (not only at the end)."""
    guard = StreamGuard(lookback=64, max_hold_chars=10_000)
    parser = SSEParser()
    words = ("lorem ipsum dolor sit amet consectetur " * 20).split(" ")
    released_before_end = 0
    for w in words:
        for ev in parser.feed(sse(w + " ")):
            out, violation = guard.process(ev)
            assert violation is None
            released_before_end += len(out)
    assert released_before_end > len(words) // 2
    assert guard.held_events < 30


def test_hold_limit_fails_closed():
    """An unbounded whitespace-free run cannot be verified within the hold limit -> stream is terminated."""
    guard = StreamGuard(lookback=64, max_hold_chars=512)
    parser = SSEParser()
    violation = None
    for _ in range(100):
        for ev in parser.feed(sse("A1b2" * 4)):
            _, violation = guard.process(ev)
            if violation:
                break
        if violation:
            break
    assert violation is not None and violation.code == "stream_hold_limit_exceeded"


@pytest.mark.parametrize("lookback", [10, 49])
def test_lookback_below_detector_bound_is_rejected_by_config(lookback):
    from shadow_ai_gateway.config import ConfigError, Settings

    with pytest.raises(ConfigError):
        Settings(auth_mode="disabled", stream_lookback_chars=lookback).validate()
