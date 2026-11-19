"""Bounded canonicalization of text before pattern matching.

Normalization never *replaces* the original text: it produces additional
*variants* that are scanned alongside the raw input. This keeps the transformation
from changing the meaning of legitimate content (the request forwarded upstream is
always the original bytes) while letting detectors see through common encodings.

Every transformation is bounded:
* at most ``MAX_DECODE_ROUNDS`` URL-decoding rounds,
* Base64/hex decoding only of candidate tokens between 16 and 8192 characters,
  recursing at most ``MAX_NESTED_DECODE_DEPTH`` levels,
* at most ``MAX_VARIANTS`` variants and ``MAX_DECODED_TOKENS`` decoded tokens.

Expensive steps only run when their trigger characters are present, so ordinary
prose normally yields only the raw text (plus injection-specific variants).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse

MAX_INPUT_CHARS = 1_048_576
MAX_DECODE_ROUNDS = 3
MAX_VARIANTS = 16
MAX_DECODED_TOKENS = 64
MAX_NESTED_DECODE_DEPTH = 2
MIN_B64_TOKEN = 16
MAX_B64_TOKEN = 8192

# Zero-width, soft hyphen, bidi controls, word joiners, invisible operators.
INVISIBLE_CHARS_RE = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
INVISIBLE_RUN_RE = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]+")
# Unicode "tag" characters (U+E0020-U+E007E) mirror ASCII and are used for invisible prompt smuggling.
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")
HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
HEX_TOKEN_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
SPACED_LETTERS_RE = re.compile(r"(?<=\b[a-zA-Z])\s+(?=[a-zA-Z]\b)")
QUOTES_RE = re.compile(r"[\"'`]")


def _decode_hex_escape(match: re.Match[str]) -> str:
    return chr(int(match.group(1), 16))


def _decode_unicode_escape(match: re.Match[str]) -> str:
    code = int(match.group(1) or match.group(2), 16)
    if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
        return match.group(0)
    return chr(code)


def _tags_to_ascii(text: str) -> str:
    return TAG_CHARS_RE.sub(lambda m: chr(ord(m.group(0)) - 0xE0000) if 0x20 <= ord(m.group(0)) - 0xE0000 <= 0x7E else "", text)


def is_targeted_base64_candidate(token: str) -> bool:
    """Heuristic: does ``token`` look like Base64 rather than a natural-language word?"""
    n = len(token)
    if n < MIN_B64_TOKEN or n > MAX_B64_TOKEN:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", token):
        return False
    if "=" in token:
        return True
    has_digit = any(c.isdigit() for c in token)
    has_symbol = any(c in "+/-_" for c in token)
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    if (has_digit or has_symbol) and (has_upper or has_lower):
        return True
    return has_upper and has_lower and n % 4 == 0 and n <= 256


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if (c.isprintable() and c != "\ufffd") or c in "\n\r\t")
    return printable / len(text)


def _bytes_to_text(raw: bytes) -> str | None:
    """Decode bytes to text if they are (almost entirely) printable UTF-8.

    Random keys, hashes and images decode to binary noise and are rejected; encoded
    *text* (which is what an attacker smuggles) is accepted. A small amount of
    trailing garbage (e.g. from a mangled final Base64 quantum) is tolerated.
    """
    text = raw.decode("utf-8", errors="replace")
    if len(text) >= 6 and _printable_ratio(text) >= 0.9 and any(c.isalnum() for c in text):
        return text.replace("\ufffd", "")
    return None


def try_decode_base64(token: str) -> str | None:
    """Decode standard or URL-safe Base64 (with padding repair) to mostly-printable UTF-8 text."""
    core = token.rstrip("=")
    if len(core) % 4 == 1:  # impossible length for Base64; drop one trailing char
        core = core[:-1]
    padded = core + "=" * (-len(core) % 4)
    altchars: bytes | None = b"-_" if ("-" in core or "_" in core) else None
    try:
        raw = base64.b64decode(padded.encode("ascii"), altchars=altchars, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > MAX_B64_TOKEN:
        return None
    return _bytes_to_text(raw)


def try_decode_hex(token: str) -> str | None:
    """Decode a hex string to printable text (hashes decode to binary and are rejected)."""
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    return _bytes_to_text(raw)


def decode_embedded_tokens(text: str, depth: int = 0, budget: list[int] | None = None) -> list[str]:
    """Return decoded payloads of Base64/hex tokens embedded in ``text`` (bounded recursion)."""
    if budget is None:
        budget = [MAX_DECODED_TOKENS]
    decoded: list[str] = []
    if depth >= MAX_NESTED_DECODE_DEPTH:
        return decoded
    for match in B64_TOKEN_RE.finditer(text):
        if budget[0] <= 0:
            break
        token = match.group(0)
        if not is_targeted_base64_candidate(token):
            continue
        value = try_decode_base64(token)
        if value:
            budget[0] -= 1
            decoded.append(value)
            decoded.extend(decode_embedded_tokens(value, depth + 1, budget))
    for match in HEX_TOKEN_RE.finditer(text):
        if budget[0] <= 0:
            break
        value = try_decode_hex(match.group(0))
        if value:
            budget[0] -= 1
            decoded.append(value)
            decoded.extend(decode_embedded_tokens(value, depth + 1, budget))
    return decoded


def _decode_layers(text: str) -> str:
    """NFKC, HTML entities, bounded URL decoding, escape sequences and Unicode tags.

    Invisible characters are *kept* here; callers decide whether to strip them (secret
    detection) or turn them into word separators (prompt-injection matching).
    """
    current = unicodedata.normalize("NFKC", text)
    if "&" in current:
        current = html.unescape(current)
    if "%" in current:
        for _ in range(MAX_DECODE_ROUNDS):
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
    if "\\" in current:
        current = HEX_ESCAPE_RE.sub(_decode_hex_escape, current)
        current = UNICODE_ESCAPE_RE.sub(_decode_unicode_escape, current)
    if TAG_CHARS_RE.search(current):
        current = _tags_to_ascii(current)
    return current


def canonical_variants(raw_text: str) -> list[str]:
    """Variants used for *secret* detection: decodings that preserve token boundaries."""
    if not raw_text:
        return []
    text = raw_text[:MAX_INPUT_CHARS]
    stripped = INVISIBLE_CHARS_RE.sub("", _decode_layers(text))
    variants: list[str] = [text, stripped]
    variants.extend(decode_embedded_tokens(stripped))
    return _dedupe(variants)


def injection_variants(raw_text: str) -> list[str]:
    """Variants used for structural prompt-injection matching (more aggressive)."""
    if not raw_text:
        return []
    text = raw_text[:MAX_INPUT_CHARS]
    decoded = _decode_layers(text)
    stripped = INVISIBLE_CHARS_RE.sub("", decoded)  # 'i​gnore' -> 'ignore'
    variants = [text, stripped]
    if INVISIBLE_CHARS_RE.search(decoded):
        variants.append(INVISIBLE_RUN_RE.sub(" ", decoded))  # 'ignore​all' -> 'ignore all'
    despaced = SPACED_LETTERS_RE.sub("", stripped)  # 'i g n o r e' -> 'ignore'
    if despaced != stripped:
        variants.append(despaced)
    unquoted = QUOTES_RE.sub("", stripped)
    if unquoted != stripped:
        variants.append(unquoted)
    variants.extend(decode_embedded_tokens(stripped))
    return _dedupe(variants)


def _dedupe(variants: list[str]) -> list[str]:
    return list(dict.fromkeys(variants))[:MAX_VARIANTS]


def normalize_text_pipeline(raw_text: str) -> list[str]:
    """Backward-compatible API: all variants (secret + injection) for ``raw_text``."""
    return injection_variants(raw_text)
