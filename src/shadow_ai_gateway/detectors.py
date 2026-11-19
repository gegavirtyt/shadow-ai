"""Secret and structural prompt-injection detectors.

Detector contract (relied upon by the streaming engine's soundness argument, see
``streaming.py``): every regular expression that can match whitespace must bound
the length of the match *prefix that ends at its last whitespace character*. That
bound is declared as ``ws_prefix_bound`` and checked by a unit test. The streaming
hold-back window (``STREAM_DLP_WINDOW_SIZE``) must be at least the maximum bound.

All matched values are treated as sensitive: they are never logged or returned
to clients. Findings carry offsets, detector ids and categories only; the value is
kept in a non-repr field so the audit layer can compute a keyed fingerprint.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .entropy import char_class_count, is_hex, looks_random, randomness_deficit
from .normalization import canonical_variants, injection_variants, try_decode_base64

# Margins (bits/char below the expected entropy of a random string), selected on the
# calibration split only by benchmarks/calibrate_entropy.py (rule: max recall s.t. FPR <= 1%,
# ties -> smaller margins). Results: benchmarks/results/calibration.json.
GENERIC_ENTROPY_DELTA = 0.25
CONTEXT_ENTROPY_DELTA = 0.40
GENERIC_MIN_LENGTH = 20
CONTEXT_MIN_LENGTH = 16


@dataclass(frozen=True)
class Finding:
    detector: str
    category: str
    kind: str  # "secret" | "prompt_injection"
    start: int
    end: int
    variant: int = 0  # 0 = raw text, >0 = normalized variant index
    value: str = field(default="", repr=False, compare=False)

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class RegexDetector:
    id: str
    category: str
    pattern: re.Pattern[str]
    ws_prefix_bound: int = 0  # 0 = match can never contain whitespace
    group: int | str = 0
    validator: Callable[[re.Match[str]], bool] | None = None
    # Required when ws_prefix_bound > 0: a pattern that *fullmatches* every prefix of a
    # possible match that ends in a whitespace character (an over-approximation is fine).
    open_prefix: str | None = None

    def finditer(self, text: str) -> Iterable[tuple[int, int, str]]:
        for m in self.pattern.finditer(text):
            if self.validator is not None and not self.validator(m):
                continue
            yield m.start(), m.end(), m.group(self.group)


# ---------------------------------------------------------------------------
# Placeholder / example-value suppression
# ---------------------------------------------------------------------------
_PLACEHOLDER_WORDS = {
    "none",
    "null",
    "nil",
    "undefined",
    "true",
    "false",
    "empty",
    "redacted",
    "masked",
    "hidden",
    "changeme",
    "change_me",
    "change-me",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "test",
    "testing",
    "default",
    "xxxxxxxx",
    "string",
}
_PLACEHOLDER_RE = re.compile(
    r"^(?:<[^>]*>|\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|\{\{[^}]*\}\}|%\([^)]*\)s|\*+|x+|X+|\.+|_+|-+|"
    r"your[_\-]?.*|my[_\-]?(?:api[_\-]?)?(?:key|token|secret|password).*|.*[_\-]here|"
    r"(?:os\.)?(?:getenv|environ).*|process\.env.*|.*\(.*)$",
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"`").rstrip(".,;:)")
    if not v:
        return True
    if v.lower() in _PLACEHOLDER_WORDS or _PLACEHOLDER_RE.match(v):
        return True
    if len(set(v)) <= 2:
        return True
    return False


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------
def _valid_db_password(m: re.Match[str]) -> bool:
    return not is_placeholder(m.group("pw"))


_PASSWORD_KEYWORDS = re.compile(r"pass(?:word|wd|phrase)?|pwd", re.IGNORECASE)


def _valid_assignment(m: re.Match[str]) -> bool:
    value = m.group("val").rstrip(".,;:)!?")
    keyword = m.group("kw")
    if is_placeholder(value):
        return False
    if _PASSWORD_KEYWORDS.fullmatch(keyword.replace(" ", "").replace("_", "").replace("-", "")):
        # Passwords are low-entropy by nature: any concrete, non-placeholder value counts.
        return len(value) >= 8 and not value.isalpha()
    if len(value) < CONTEXT_MIN_LENGTH:
        return False
    if is_hex(value):
        return looks_random(value, CONTEXT_ENTROPY_DELTA)
    if char_class_count(value) < 2:
        return False
    return looks_random(value, CONTEXT_ENTROPY_DELTA)


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------
# Provider tokens with distinctive public prefixes are matched *without* word
# boundaries: gluing a key to adjacent text ("xxxAKIA...") must not evade detection.
# The false-positive cost is negligible (e.g. P("AKIA" + 16 x [A-Z0-9]) at a random
# base64 position is about 6e-12).
_B = ""
_E = ""

_KEYWORDS = (
    r"(?:aws[_\-]?)?secret[_\- ]?access[_\- ]?key|(?:aws[_\-]?)?session[_\- ]?token|"
    r"api[_\- ]?key|apikey|secret[_\- ]?key|client[_\- ]?secret|access[_\- ]?token|auth[_\- ]?token|"
    r"api[_\- ]?token|bearer[_\- ]?token|refresh[_\- ]?token|private[_\- ]?key|master[_\- ]?key|"
    r"pass(?:word|wd|phrase)?|pwd|secret|token"
)

SECRET_DETECTORS: tuple[RegexDetector, ...] = (
    RegexDetector(
        "aws_access_key_id",
        "aws_credential",
        # Key ids are 20 chars: 4-char prefix + 16 of [A-Z0-9] (real ids use base32 [A-Z2-7]).
        re.compile(r"(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}"),
    ),
    RegexDetector(
        "aws_session_token",
        "aws_credential",
        re.compile(r"(?<![A-Za-z0-9+/])(?:FwoGZXIvYXdz|IQoJb3JpZ2luX2Vj)[A-Za-z0-9/+=]{80,}"),
    ),
    RegexDetector("github_token", "github_token", re.compile(_B + r"gh[pousr]_[A-Za-z0-9]{36,255}" + _E)),
    RegexDetector("github_fine_grained_pat", "github_token", re.compile(_B + r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}" + _E)),
    RegexDetector("gitlab_pat", "gitlab_token", re.compile(_B + r"glpat-[A-Za-z0-9_\-]{20,64}" + _E)),
    RegexDetector("slack_token", "slack_token", re.compile(_B + r"xox[abposr]-[0-9A-Za-z\-]{10,250}" + _E)),
    RegexDetector("slack_app_token", "slack_token", re.compile(_B + r"xapp-\d-[A-Za-z0-9\-]{10,250}" + _E)),
    RegexDetector(
        "slack_webhook",
        "slack_token",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"),
    ),
    RegexDetector("google_api_key", "google_credential", re.compile(_B + r"AIza[0-9A-Za-z\-_]{35}" + _E)),
    RegexDetector("google_oauth_client_secret", "google_credential", re.compile(_B + r"GOCSPX-[A-Za-z0-9_\-]{28}" + _E)),
    RegexDetector(
        "gcp_service_account_key",
        "google_credential",
        re.compile(r"\"private_key_id\"\s{0,4}:\s{0,4}\"[0-9a-f]{40}\""),
        ws_prefix_bound=len('"private_key_id"') + 4 + 1 + 4,
        open_prefix=r'"private_key_id"\s{0,4}(?::\s{0,4})?',
    ),
    RegexDetector(
        "openai_api_key",
        "openai_api_key",
        re.compile(_B + r"sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})" + _E),
    ),
    RegexDetector(
        "anthropic_api_key", "anthropic_api_key", re.compile(_B + r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}" + _E)
    ),
    RegexDetector("stripe_live_key", "payment_credential", re.compile(_B + r"(?:sk|rk)_live_[0-9a-zA-Z]{24,99}" + _E)),
    RegexDetector(
        "pem_private_key",
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]{1,12} ){0,2}PRIVATE KEY(?: BLOCK)?-----"),
        ws_prefix_bound=11 + 2 * 13 + len("PRIVATE KEY "),
        open_prefix=r"-----BEGIN (?:[A-Z0-9]{1,12} ){0,3}",
    ),
    RegexDetector(
        "database_connection_string",
        "database_credential",
        re.compile(
            r"(?i)(?<![A-Za-z0-9+.\-])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|"
            r"oracle|cockroachdb|clickhouse)://(?P<user>[^\s:/@]{0,128}):(?P<pw>[^\s@/]{1,256})@(?P<host>[^\s/:@?#]+)"
        ),
        validator=_valid_db_password,
    ),
    RegexDetector(
        "keyword_assignment",
        "credential_assignment",
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?P<kw>" + _KEYWORDS + r")(?![A-Za-z0-9])"
            r"[\"']?[ \t]{0,4}(?:is(?![A-Za-z0-9])[ \t]{0,2}[:=]?|=>|:=|[:=])[ \t]{0,4}[\"'`]?(?P<val>[^\s\"'`<>;,]{6,512})"
        ),
        # keyword (<=21) + quote + 4 spaces + "is  :" (5) + 4 spaces + quote
        ws_prefix_bound=len("secret_access_key") + len("aws_") + 1 + 4 + 5 + 4 + 1,
        open_prefix=(
            r"(?i:(?:" + _KEYWORDS + r")[\"']?[ \t]{0,4}(?:(?:is(?![A-Za-z0-9])[ \t]{0,2}[:=]?|=>|:=|[:=])[ \t]{0,4})?)"
            r"|(?i:(?:aws[_\-]?)?(?:secret(?:[_\- ]?access)?|session|api|client|access|auth|bearer|refresh|private|master) )"
        ),
        group="val",
        validator=_valid_assignment,
    ),
    RegexDetector(
        "bearer_header",
        "credential_assignment",
        re.compile(r"(?i)(?<![A-Za-z0-9])bearer[ \t]{1,4}(?P<val>[A-Za-z0-9_\-\.=+/]{16,1024})"),
        ws_prefix_bound=len("bearer") + 4,
        open_prefix=r"(?i:bearer[ \t]{1,4})",
        group="val",
        validator=lambda m: (
            not is_placeholder(m.group("val"))
            and char_class_count(m.group("val")) >= 2
            and looks_random(m.group("val").split(".")[-1] or m.group("val"), CONTEXT_ENTROPY_DELTA)
        ),
    ),
)

# Structural prompt-injection heuristics. These match *known phrasings* only and are
# not a semantic defence (see LIMITATIONS.md). They are ingress-only.
PROMPT_OVERRIDE_REGEX = re.compile(
    r"((?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instructions|directives|rules|prompts?)|"
    r"system\s+override(?:\s+mode)?|"
    r"bypass\s+(?:all\s+)?safety\s+filters|"
    r"you\s+are\s+now\s+in\s+dan\s+mode|dan\s+mode\s+enabled|"
    r"developer\s+mode\s+(?:enabled|active|on)|"
    r"system\s+prompt\s+update|"
    r"new\s+system\s+directive)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Generic high-entropy detector
# ---------------------------------------------------------------------------
# The left boundary deliberately excludes "=": tokens directly after "KEY=" must be evaluated
# (v4.0.0 bug found on the first held-out split; see BENCHMARK_RESULTS.md).
GENERIC_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{20,}={0,2}(?![A-Za-z0-9+/_\-=])")
DATA_URI_RE = re.compile(r"data:[\w.+\-]{1,64}/[\w.+\-]{1,64}(?:;[\w\-]{1,32}=[\w\-]{1,64}){0,4};base64,[A-Za-z0-9+/=\s]*")
# Public key material is public: PEM public keys/certificates are masked from the entropy check.
PEM_PUBLIC_BLOCK_RE = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |SSH2 )?PUBLIC KEY|CERTIFICATE|CERTIFICATE REQUEST|X509 CRL)-----.{0,20000}?-----END \1-----",
    re.DOTALL,
)
URL_RE = re.compile(r"https?://[^\s\"'<>`]{1,4096}")
URL_SEGMENT_SPLIT_RE = re.compile(r"[/?&=#.:;,@%+]+")
# Labels that announce a non-secret digest/identifier/public key immediately before a token.
_DIGEST_LABEL_RE = re.compile(
    r"(?i)(?:sha-?(?:1|224|256|384|512)|md5|digest|checksum|fingerprint|commit|hash|integrity|nonce|etag|"
    r"request[_\- ]?id|trace[_\- ]?id|uuid|object[_\- ]?id|"
    r"ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d{3}|sk-ssh-ed25519@openssh\.com)[\"'\s:=()#]{0,6}(?:sha\d{0,3}[:\-])?$"
)
# Documented *public* identifiers with random-looking bodies.
PUBLIC_TOKEN_PREFIXES = ("pk_live_", "pk_test_")
# ULID (Crockford base32, 48-bit timestamp first): sortable ids, not secrets.
_INLINE_DIGEST_RE = re.compile(r"(?i)(?:sha(?:1|224|256|384|512)|md5)-")
_ULID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")


def _generic_candidate(token: str) -> bool:
    core = token.rstrip("=")
    if len(core) < GENERIC_MIN_LENGTH:
        return False
    if is_hex(core.replace("-", "")):
        # Uniform random hex is statistically indistinguishable from SHA/commit digests,
        # so hexadecimal tokens are only reported in keyword context.
        return False
    if char_class_count(core) < 2:
        return False
    if core.startswith(PUBLIC_TOKEN_PREFIXES) or _ULID_RE.fullmatch(core):
        return False
    if _INLINE_DIGEST_RE.match(core):
        return False  # SRI/npm style 'sha512-<base64>' digests (same family as integrity= labels)
    if try_decode_base64(core) is not None:
        # Base64 that decodes to printable text is encoded content, not key material;
        # the decoded text itself is scanned via the normalization variants.
        return False
    return looks_random(core, GENERIC_ENTROPY_DELTA)


def _blank(m: re.Match[str]) -> str:
    return " " * len(m.group(0))


def find_high_entropy_tokens(text: str, *, skip_leading_fragment: bool = False) -> list[Finding]:
    masked = DATA_URI_RE.sub(_blank, text) if "base64," in text else text
    if "-----BEGIN" in masked:
        masked = PEM_PUBLIC_BLOCK_RE.sub(_blank, masked)
    findings: list[Finding] = []
    if "://" in masked:
        # URLs are evaluated per segment: path words joined by '/' and '-' are not tokens,
        # but a random credential in a path or query parameter still is.
        for url in URL_RE.finditer(masked):
            for segment in URL_SEGMENT_SPLIT_RE.split(url.group(0)):
                if _generic_candidate(segment):
                    findings.append(
                        Finding("high_entropy_token", "high_entropy_secret", "secret", url.start(), url.end(), 0, segment)
                    )
                    break
        masked = URL_RE.sub(_blank, masked)
    for m in GENERIC_TOKEN_RE.finditer(masked):
        if skip_leading_fragment and m.start() == 0:
            continue
        token = m.group(0)
        if not _generic_candidate(token):
            continue
        prefix = masked[max(0, m.start() - 40) : m.start()]
        if _DIGEST_LABEL_RE.search(prefix):
            continue
        findings.append(Finding("high_entropy_token", "high_entropy_secret", "secret", m.start(), m.end(), 0, token))
    return findings


# ---------------------------------------------------------------------------
# Scanning API
# ---------------------------------------------------------------------------
def scan_text_for_secrets(
    text: str,
    *,
    entropy: bool = True,
    normalize: bool = True,
    first_only: bool = False,
) -> list[Finding]:
    """Run all secret detectors on ``text`` (and its normalized variants)."""
    if not text:
        return []
    findings: list[Finding] = []
    variants = canonical_variants(text) if normalize else [text]
    for idx, variant in enumerate(variants):
        for det in SECRET_DETECTORS:
            for start, end, value in det.finditer(variant):
                findings.append(Finding(det.id, det.category, "secret", start, end, idx, value))
                if first_only:
                    return findings
    if entropy:
        findings.extend(find_high_entropy_tokens(text))
    return findings[:1] if first_only else findings


def scan_text_for_injection(text: str) -> list[Finding]:
    if not text:
        return []
    for idx, variant in enumerate(injection_variants(text)):
        m = PROMPT_OVERRIDE_REGEX.search(variant)
        if m:
            return [Finding("prompt_override_phrase", "prompt_override", "prompt_injection", m.start(), m.end(), idx, m.group(0))]
    return []


def minimum_stream_lookback() -> int:
    """Smallest streaming hold-back window that keeps the soundness argument valid."""
    return max(det.ws_prefix_bound for det in SECRET_DETECTORS) + 1


def _combined_open_prefix() -> re.Pattern[str]:
    parts = []
    for det in SECRET_DETECTORS:
        if det.ws_prefix_bound:
            if not det.open_prefix:
                raise RuntimeError(f"detector {det.id} can match whitespace but declares no open_prefix")
            parts.append(f"(?:{det.open_prefix})")
    return re.compile("|".join(parts))


# Fullmatches every whitespace-terminated prefix of every whitespace-bearing detector match.
OPEN_PREFIX_RE = _combined_open_prefix()


__all__ = [
    "PROMPT_OVERRIDE_REGEX",
    "SECRET_DETECTORS",
    "Finding",
    "RegexDetector",
    "find_high_entropy_tokens",
    "is_placeholder",
    "minimum_stream_lookback",
    "randomness_deficit",
    "scan_text_for_injection",
    "scan_text_for_secrets",
]
