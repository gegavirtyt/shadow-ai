"""Incremental SSE parsing and the streaming egress DLP engine.

Release invariant (what "no secret is forwarded before inspection" means here)
-----------------------------------------------------------------------------
Upstream events are forwarded to the client *whole and unmodified*, in order. Each
event's text contributions are appended to per-*channel* buffers (one channel per
content-bearing JSON path, e.g. ``choices[0].delta.content`` or
``choices[0].delta.tool_calls[1].function.arguments``), so interleaved choices or
tool calls cannot be used to split a secret.

For a channel with retained (unreleased) text, let ``r`` be the absolute start of
the trailing run of non-whitespace characters and ``W`` the lookback window. The
*cut* is the earliest ``s`` in ``[r - W, r)`` such that ``text[s:r]`` fullmatches
``OPEN_PREFIX_RE`` (a possible whitespace-terminated prefix of a whitespace-bearing
detector match), or ``r`` if there is none. An event may be released only if, for
every channel it contributed to, its contribution ends at or before the cut; until
the stream ends, nothing in the trailing run is ever released.

Preconditions (both verified by property tests in tests/test_components.py):
(P1) every detector match either contains no whitespace, or its whitespace lies within
a prefix of at most ``ws_prefix_bound <= W`` characters; (P2) for every such match and
every whitespace position ``w`` in it, ``OPEN_PREFIX_RE`` fullmatches ``match[: w + 1]``.

Claim: no character of a match is released before the match is complete and scanned.

Sketch: suppose part of an incomplete match ``[s, t)`` (``t`` > current length) was
released: some released contribution ended at ``e > s``, with ``e <= cut``. If the
match had no whitespace it would lie inside the trailing run (it reaches the end of
the text), so ``s >= r >= cut >= e``: contradiction. Otherwise ``s < r`` and the match
covers the whitespace at ``r - 1``; by (P1) ``s >= r - W`` and by (P2) ``text[s:r]``
fullmatches ``OPEN_PREFIX_RE``, so the cut is at most ``s``: ``e <= cut <= s``,
contradiction. Complete matches are found by the scan that runs *before* any release
decision for the event that completed them.

The generic entropy detector is evaluated on *complete* tokens only (tokens followed
by whitespace, or all tokens at end of stream), matching buffered behaviour.

Limits (all fail closed by terminating the stream with an SSE error event):
maximum incomplete-event size, maximum retained text per channel, maximum total
stream bytes and maximum stream duration.
"""

from __future__ import annotations

import collections
import json
import re
import time
from collections.abc import AsyncIterable, AsyncIterator, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .detectors import OPEN_PREFIX_RE, Finding, find_high_entropy_tokens, scan_text_for_secrets

_LINE_END_RE = re.compile(rb"\r\n|\n|\r")
DONE_MARKER = "[DONE]"

CONTENT_KEYS = frozenset(
    {
        "content",
        "text",
        "arguments",
        "refusal",
        "reasoning",
        "reasoning_content",
        "thinking",
        "partial_json",
        "delta",
        "output_text",
        "input",
    }
)
METADATA_KEYS = frozenset(
    {
        "id",
        "object",
        "model",
        "created",
        "system_fingerprint",
        "type",
        "role",
        "finish_reason",
        "index",
        "logprobs",
        "service_tier",
        "stop_reason",
        "stop_sequence",
        "item_id",
        "response_id",
        "call_id",
        "signature",
        "encrypted_content",
    }
)


class SSEProtocolError(Exception):
    """Upstream stream violated a protocol or size limit."""


@dataclass
class SSEEvent:
    raw: bytes
    data: str | None  # joined ``data:`` lines, or None if the event had no data field
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_done(self) -> bool:
        return self.data is not None and self.data.strip() == DONE_MARKER


class SSEParser:
    """Byte-level incremental SSE parser (WHATWG event-stream line rules).

    * Lines end with CRLF, LF or CR; a CR at the end of the buffer is held until the
      next byte shows whether it is part of CRLF.
    * Splitting on ASCII line terminators never cuts a multi-byte UTF-8 sequence, so
      events are decoded only once complete.
    * ``max_event_bytes`` bounds the incomplete-event buffer.
    """

    def __init__(self, max_event_bytes: int = 1_048_576) -> None:
        self._buf = bytearray()
        self._pos = 0  # where line scanning resumes
        self._lines: list[bytes] = []
        self._max = max_event_bytes
        self._first = True

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        self._buf += chunk
        events: list[SSEEvent] = []
        while True:
            m = _LINE_END_RE.search(self._buf, self._pos)
            if m is None:
                break
            if m.group(0) == b"\r" and m.end() == len(self._buf):
                break  # may be the first half of CRLF
            line = bytes(self._buf[self._pos : m.start()])
            self._pos = m.end()
            if line:
                self._lines.append(line)
                continue
            raw = bytes(self._buf[: self._pos])
            del self._buf[: self._pos]
            self._pos = 0
            events.append(self._build(raw, self._lines))
            self._lines = []
        if len(self._buf) > self._max:
            raise SSEProtocolError(f"SSE event exceeds {self._max} bytes")
        return events

    def finalize(self) -> list[SSEEvent]:
        """Flush at EOF. An unterminated trailing event is returned (it will still be inspected)."""
        if not self._buf:
            return []
        if self._pos < len(self._buf):
            tail = bytes(self._buf[self._pos :]).rstrip(b"\r\n")
            if tail:
                self._lines.append(tail)
        raw = bytes(self._buf)
        self._buf.clear()
        self._pos = 0
        lines, self._lines = self._lines, []
        if not lines and not raw.strip():
            return []
        return [self._build(raw, lines)]

    def _build(self, raw: bytes, lines: list[bytes]) -> SSEEvent:
        data_lines: list[str] = []
        fields: dict[str, str] = {}
        for line_bytes in lines:
            line = line_bytes.decode("utf-8", errors="replace")
            if self._first:
                line = line.lstrip("\ufeff")
                self._first = False
            if line.startswith(":"):
                continue
            name, sep, value = line.partition(":")
            if sep and value.startswith(" "):
                value = value[1:]
            if name == "data":
                data_lines.append(value)
            elif name in ("event", "id", "retry"):
                fields[name] = value
        return SSEEvent(raw, "\n".join(data_lines) if data_lines else None, fields)


# ---------------------------------------------------------------------------
# Content extraction
# ---------------------------------------------------------------------------
def extract_event_text(data: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Split an event payload into ``(channel, text)`` contributions and auxiliary strings.

    Channels are keyed by the JSON path with list positions replaced by the element's
    ``index`` field when present (OpenAI tool-call deltas reuse list position 0 for
    different tool calls). Integer ``*index`` fields of enclosing objects are folded
    into the key (Anthropic/Responses-API events).
    """
    try:
        payload = json.loads(data)
    except (json.JSONDecodeError, RecursionError):
        return [("raw", data)], []
    contributions: list[tuple[str, str]] = []
    aux: list[str] = []
    stack: list[tuple[Any, str]] = [(payload, "")]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            idx_parts = [f"{k}={v}" for k, v in sorted(node.items()) if k.endswith("index") and isinstance(v, int)]
            prefix = f"{path}{{{','.join(idx_parts)}}}" if idx_parts else path
            for key, value in node.items():
                child = f"{prefix}.{key}"
                if isinstance(value, str):
                    if key in CONTENT_KEYS:
                        contributions.append((child, value))
                    elif key not in METADATA_KEYS:
                        aux.append(value)
                elif isinstance(value, (dict, list)):
                    stack.append((value, child))
        elif isinstance(node, list):
            for pos, item in enumerate(node):
                if isinstance(item, dict) and isinstance(item.get("index"), int):
                    stack.append((item, f"{path}[i{item['index']}]"))
                elif isinstance(item, str):
                    contributions.append((f"{path}[{pos}]", item))
                else:
                    stack.append((item, f"{path}[{pos}]"))
    return contributions, aux


# ---------------------------------------------------------------------------
# Streaming DLP engine
# ---------------------------------------------------------------------------
class _Channel:
    __slots__ = ("base", "prev_char", "text")

    def __init__(self) -> None:
        self.text = ""
        self.base = 0  # absolute offset of text[0]
        self.prev_char = " "  # last released character ("" boundary treated as whitespace)

    @property
    def total(self) -> int:
        return self.base + len(self.text)

    def trailing_run_start(self) -> int:
        i = len(self.text)
        while i > 0 and not self.text[i - 1].isspace():
            i -= 1
        return self.base + i

    def safe_cut(self, lookback: int) -> int:
        """Absolute offset up to which text may be released.

        ``r`` = start of the trailing non-whitespace run (never released before the
        stream ends). The cut moves further left only to the earliest position ``s`` in
        ``[r - lookback, r)`` where ``text[s:r]`` could be the whitespace-terminated
        prefix of a whitespace-bearing detector match (``OPEN_PREFIX_RE``).
        """
        r = self.trailing_run_start()
        r_rel = r - self.base
        for s in range(max(0, r_rel - lookback), r_rel):
            if OPEN_PREFIX_RE.fullmatch(self.text, s, r_rel):
                return self.base + s
        return r

    def release_to(self, absolute: int) -> None:
        if absolute <= self.base:
            return
        cut = absolute - self.base
        self.prev_char = self.text[cut - 1]
        self.text = self.text[cut:]
        self.base = absolute


@dataclass
class _Pending:
    raw: bytes
    ends: dict[str, int]


@dataclass
class StreamViolation:
    code: str
    message: str
    finding: Finding | None = None


class StreamGuard:
    """Holds back SSE events until releasing them cannot expose an unscanned secret."""

    def __init__(self, *, lookback: int, max_hold_chars: int, entropy: bool = True) -> None:
        self.lookback = lookback
        self.max_hold_chars = max_hold_chars
        self.entropy = entropy
        self._channels: dict[str, _Channel] = collections.defaultdict(_Channel)
        self._pending: collections.deque[_Pending] = collections.deque()
        self.events_seen = 0
        self.events_released = 0

    # -- scanning ---------------------------------------------------------
    def _scan_channel(self, ch: _Channel, *, final: bool) -> Finding | None:
        findings = scan_text_for_secrets(ch.text, entropy=False, first_only=True)
        if findings:
            return findings[0]
        if self.entropy:
            complete = ch.text if final else ch.text[: ch.trailing_run_start() - ch.base]
            skip_fragment = not ch.prev_char.isspace()
            ent = find_high_entropy_tokens(complete, skip_leading_fragment=skip_fragment)
            if ent:
                return ent[0]
        return None

    def _violation(self, finding: Finding) -> StreamViolation:
        self._pending.clear()
        return StreamViolation(
            "high_entropy_secret" if finding.category == "high_entropy_secret" else "credential_leak",
            "Outbound DLP violation intercepted in model stream",
            finding,
        )

    # -- event processing ---------------------------------------------------
    def process(self, event: SSEEvent) -> tuple[list[bytes], StreamViolation | None]:
        self.events_seen += 1
        ends: dict[str, int] = {}
        if event.data is not None and not event.is_done:
            contributions, aux = extract_event_text(event.data)
            for text in aux:
                found = scan_text_for_secrets(text, entropy=False, first_only=True)
                if found:
                    return [], self._violation(found[0])
            touched: set[str] = set()
            for channel_key, text in contributions:
                if not text:
                    continue
                ch = self._channels[channel_key]
                ch.text += text
                ends[channel_key] = ch.total
                touched.add(channel_key)
            for key in touched:
                finding = self._scan_channel(self._channels[key], final=False)
                if finding:
                    return [], self._violation(finding)
        self._pending.append(_Pending(event.raw, ends))
        released = self._release(final=False)
        for ch in self._channels.values():
            if len(ch.text) > self.max_hold_chars:
                self._pending.clear()
                return released, StreamViolation(
                    "stream_hold_limit_exceeded",
                    f"Stream content could not be verified within the {self.max_hold_chars}-character hold limit",
                )
        return released, None

    def finish(self) -> tuple[list[bytes], StreamViolation | None]:
        """End of stream: final scan of all retained text, then release everything."""
        for ch in self._channels.values():
            finding = self._scan_channel(ch, final=True)
            if finding:
                return [], self._violation(finding)
        return self._release(final=True), None

    def _release(self, *, final: bool) -> list[bytes]:
        out: list[bytes] = []
        cuts: dict[str, int] = {}  # cut positions do not change while releasing
        while self._pending:
            head = self._pending[0]
            if not final:
                for key, end in head.ends.items():
                    if key not in cuts:
                        cuts[key] = self._channels[key].safe_cut(self.lookback)
                    if end > cuts[key]:
                        return out
            self._pending.popleft()
            for key, end in head.ends.items():
                self._channels[key].release_to(end)
            out.append(head.raw)
            self.events_released += 1
        return out

    @property
    def held_events(self) -> int:
        return len(self._pending)


async def guarded_sse(
    chunks: AsyncIterable[bytes],
    *,
    lookback: int,
    max_hold_chars: int,
    entropy: bool,
    max_event_bytes: int,
    max_total_bytes: int,
    max_duration_s: float,
    on_violation: Callable[[StreamViolation, StreamGuard], bytes],
) -> AsyncIterator[bytes]:
    """Inspect an upstream SSE byte stream and yield only bytes that are safe to forward.

    Transport exceptions from ``chunks`` propagate to the caller; held (unreleased)
    events are discarded in that case, which is the fail-closed behaviour.
    """
    parser = SSEParser(max_event_bytes)
    guard = StreamGuard(lookback=lookback, max_hold_chars=max_hold_chars, entropy=entropy)
    deadline = time.monotonic() + max_duration_s
    total = 0
    try:
        async for chunk in chunks:
            total += len(chunk)
            if total > max_total_bytes:
                yield on_violation(
                    StreamViolation("stream_size_limit_exceeded", "Upstream stream exceeded the size limit"), guard
                )
                return
            if time.monotonic() > deadline:
                yield on_violation(
                    StreamViolation("stream_duration_limit_exceeded", "Upstream stream exceeded the duration limit"), guard
                )
                return
            for event in parser.feed(chunk):
                if event.is_done:
                    released, violation = guard.finish()
                    for raw in released:
                        yield raw
                    if violation:
                        yield on_violation(violation, guard)
                    else:
                        yield event.raw
                    return
                released, violation = guard.process(event)
                for raw in released:
                    yield raw
                if violation:
                    yield on_violation(violation, guard)
                    return
        for event in parser.finalize():
            released, violation = guard.process(event)
            for raw in released:
                yield raw
            if violation:
                yield on_violation(violation, guard)
                return
        released, violation = guard.finish()
        for raw in released:
            yield raw
        if violation:
            yield on_violation(violation, guard)
    except SSEProtocolError as exc:
        yield on_violation(StreamViolation("stream_protocol_error", str(exc)), guard)


def sse_error_event(code: str, message: str) -> bytes:
    payload = {
        "error": {
            "message": f"Forbidden: {message}",
            "type": "dlp_violation" if code in ("credential_leak", "high_entropy_secret") else "gateway_stream_error",
            "code": code,
        }
    }
    return f"data: {json.dumps(payload)}\n\n".encode()


def iter_contents(events: Iterable[SSEEvent]) -> str:
    """Concatenate all channel text of ``events`` (diagnostic helper)."""
    parts: list[str] = []
    for ev in events:
        if ev.data is not None and not ev.is_done:
            parts.extend(text for _, text in extract_event_text(ev.data)[0])
    return "".join(parts)
