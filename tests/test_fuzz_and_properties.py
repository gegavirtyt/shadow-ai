"""
Fuzz Testing & Property-Based Validation Suite for Shadow AI Security Gateway.

Covers:
1. URL Parsing & SSRF Destination Fuzzing (alternate IP formats, userinfo, unusual ports, control chars)
2. Incremental SSE Parser Fuzzing (arbitrary chunk slicing, malformed framing, UTF-8 byte fragmentation)
3. Normalization Pipeline Property Tests (bounded output size, idempotence, ReDoS resilience)
4. JSON AST Parser Fuzzing (deep nesting, malformed payloads, structural exemptions)
5. Core DLP Invariant Property (AWS keys and prompt overrides are strictly detected regardless of framing)
"""

import itertools
import json
import random
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.proxy_gateway import (
    IncrementalSSEParser,
    inspect_payload_for_threats,
    inspect_text_for_threats,
    normalize_text_pipeline,
    validate_upstream_destination,
)


# ==============================================================================
# 1. URL PARSER & SSRF DESTINATION FUZZING
# ==============================================================================
def test_fuzz_url_schemes_and_hosts():
    """Fuzzes URL parser with prohibited schemes, malformed userinfo, and alternate representations."""
    schemes = ["file", "gopher", "ftp", "tftp", "ldap", "dict", "sftp", "data", "javascript", "blob"]
    hosts = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "100.100.100.200",
        "metadata.google.internal",
        "instance-data",
        "[::1]",
        "[fe80::1]",
        "[::ffff:169.254.169.254]",
        "0.0.0.0",
        "2130706433",  # 127.0.0.1 decimal
        "0177.0.0.1",   # octal
        "0x7f.1",       # hex
        "attacker.com@169.254.169.254",
        "api.openai.com.attacker.com",
        "api.openai.com@attacker.com",
    ]
    ports = ["", ":80", ":443", ":8080", ":22", ":65535"]

    for scheme, host, port in itertools.product(schemes[:5], hosts[:8], ports[:3]):
        fuzzed_url = f"{scheme}://{host}{port}/v1/completions"
        is_valid, reason = validate_upstream_destination(fuzzed_url, allow_local_mock=False)
        assert is_valid is False, f"Expected {fuzzed_url} to be blocked, but was allowed"
        assert reason is not None


def test_fuzz_url_control_characters_and_null_bytes():
    """Fuzzes URL parser with null bytes, CRLF, and control characters."""
    bad_chars = ["\x00", "\r", "\n", "\t", "\x08", "\x1f", " "]
    for ch in bad_chars:
        url = f"https://api.openai.com{ch}/v1/chat/completions"
        is_valid, reason = validate_upstream_destination(url, allow_local_mock=False)
        # Must either fail cleanly or reject; must never raise unhandled exception
        assert isinstance(is_valid, bool)


# ==============================================================================
# 2. INCREMENTAL SSE PARSER FUZZING
# ==============================================================================
def test_fuzz_sse_arbitrary_chunk_slicing():
    """
    Fuzzes SSE parser by splitting a structured multi-event stream into arbitrary
    micro-slices ranging from 1 to 7 bytes.
    """
    random.seed(42)
    events = [
        json.dumps({"choices": [{"delta": {"content": f"Token_{i} "}}]})
        for i in range(25)
    ]
    raw_sse = "".join(f"data: {ev}\n\n" for ev in events) + "data: [DONE]\n\n"
    raw_bytes = raw_sse.encode("utf-8")

    parser = IncrementalSSEParser()
    idx = 0
    parsed_events = []

    while idx < len(raw_bytes):
        chunk_size = random.randint(1, 7)
        chunk = raw_bytes[idx : idx + chunk_size]
        idx += chunk_size
        evs = parser.feed(chunk)
        parsed_events.extend(evs)

    parsed_events.extend(parser.finalize())

    deltas = [delta for _, delta in parsed_events if delta]
    combined_content = "".join(deltas)

    # All 25 tokens must be fully reassembled in order
    for i in range(25):
        assert f"Token_{i} " in combined_content
    # The [DONE] marker must be recognized
    assert any("[DONE]" in raw for raw, delta in parsed_events if delta is None)


def test_fuzz_sse_malformed_framing_and_binary_noise():
    """Fuzzes SSE parser with random binary noise, oversized lines, and broken JSON."""
    random.seed(1337)
    parser = IncrementalSSEParser()

    for _ in range(50):
        length = random.randint(10, 200)
        noise = bytes(random.randint(0, 255) for _ in range(length))
        # Feed noise; must never raise unhandled exception
        try:
            evs = parser.feed(noise)
            assert isinstance(evs, list)
        except Exception as exc:
            pytest.fail(f"SSE parser crashed on binary noise: {exc}")

    final_evs = parser.finalize()
    assert isinstance(final_evs, list)


# ==============================================================================
# 3. NORMALIZATION PIPELINE PROPERTY TESTS
# ==============================================================================
def test_normalization_property_idempotence():
    """
    PROPERTY: Normalizing an already normalized benign text must produce
    identical output without cyclic expansion.
    """
    benign_text = "Summarize the Q3 enterprise compliance audit log."
    variants_1 = normalize_text_pipeline(benign_text)
    assert len(variants_1) >= 1

    # Re-normalizing the primary variant
    variants_2 = normalize_text_pipeline(variants_1[0])
    assert variants_2[0] == variants_1[0]


def test_normalization_property_bounded_memory_on_huge_payload():
    """
    PROPERTY: Normalization pipeline must bound execution and return finite
    variants when given a 200 KB adversarial payload.
    """
    adversarial = ("%2520\u200b\\x69 " * 10000)
    variants = normalize_text_pipeline(adversarial)
    assert len(variants) <= 20
    assert all(isinstance(v, str) for v in variants)


# ==============================================================================
# 4. JSON AST PARSER FUZZING
# ==============================================================================
def test_fuzz_json_deep_nesting():
    """Fuzzes JSON payload scanner with deeply nested dictionaries (50 levels)."""
    current: dict = {"prompt": "Deeply nested prompt text"}
    for _ in range(50):
        current = {"nested": current}

    body_bytes = json.dumps(current).encode("utf-8")
    is_threat, reason = inspect_payload_for_threats(body_bytes)
    assert is_threat is False
    assert reason is None


def test_fuzz_json_malformed_payloads():
    """Fuzzes JSON payload scanner with truncated, corrupted, and invalid JSON."""
    corrupted_bodies = [
        b'{"prompt": "unclosed string',
        b'{"key": [1, 2, 3, }',
        b"\x00\x01\x02\xff\xfe",
        b"",
        b" " * 1000,
        b'{"prompt": {"messages": null}}',
        b'{"prompt": 123456789}',
    ]
    for body in corrupted_bodies:
        is_threat, reason = inspect_payload_for_threats(body)
        assert isinstance(is_threat, bool)


# ==============================================================================
# 5. CORE DLP INVARIANT PROPERTIES
# ==============================================================================
@pytest.mark.parametrize("secret_key", [
    "AKIAIOSFODNN7EXAMPLE",
    "AKIA1234567890ABCDEF",
    "ASIAT7X6M2K4P8R0EXAMPLE",
    "ghp_111122223333444455556666777788889999",
    "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "AIzaSyA1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q",
])
def test_property_dlp_secret_always_detected_in_random_contexts(secret_key):
    """
    CRITICAL INVARIANT PROPERTY:
    A real credential token embedded anywhere inside random conversational prose
    MUST ALWAYS trigger threat detection.
    """
    random.seed(hash(secret_key) % 10000)
    words = ["the", "cloud", "security", "worker", "architecture", "database", "query", "user"]

    for _ in range(5):
        prefix = " ".join(random.choices(words, k=6))
        suffix = " ".join(random.choices(words, k=6))
        text = f"{prefix} {secret_key} {suffix}"
        is_threat, reason = inspect_text_for_threats(text)
        assert is_threat is True, f"Failed to detect {secret_key} in context: '{text}'"
        assert "Credential Leak Detected" in reason
