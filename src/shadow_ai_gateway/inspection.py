"""Ingress and buffered-egress inspection of JSON payloads.

Field policy
------------
* Pattern detectors (provider token formats, PEM headers, connection strings,
  keyword assignments) run on **every** string value *and every object key*.
* The generic high-entropy detector is skipped for fields that by schema carry
  opaque random identifiers or encoded media (ids, signatures, base64 images,
  encrypted reasoning content, legacy crypto fields). Skipping is by *field name*,
  which is attacker-influenceable only if the client controls the JSON schema; the
  limitation is documented in LIMITATIONS.md.
* Structural prompt-injection heuristics run on every string value (ingress only).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .detectors import Finding, scan_text_for_injection, scan_text_for_secrets

# Field names whose values are opaque by design (entropy detector skipped).
ENTROPY_EXEMPT_KEYS = frozenset(
    {
        # legacy v3 exemptions
        "jwt",
        "jwt_token",
        "access_token",
        "id_token",
        "refresh_token",
        "authorization",
        "signature",
        "sig",
        "hash",
        "sha256",
        "md5",
        "checksum",
        "nonce",
        "public_key",
        "certificate",
        "embedding",
        "embeddings",
        "vector",
        "vectors",
        "image_base64",
        "thumbnail",
        "binary_data",
        "attachment",
        # provider schemas (OpenAI / Anthropic) - identifiers and encoded media
        "id",
        "tool_call_id",
        "call_id",
        "previous_response_id",
        "response_id",
        "item_id",
        "message_id",
        "system_fingerprint",
        "encrypted_content",
        "data",
        "file_data",
        "b64_json",
        "image_url",
        "url",
        "file_id",
        "conversation_id",
        "user",
    }
)
ENTROPY_EXEMPT_SUFFIXES = ("_hash", "_sig", "_token", "_b64", "_vector", "_id")

# Display labels for detectors (bandit B105 false positives: these are not credentials).
DETECTOR_LABELS = {
    "aws_access_key_id": "AWS Access Key ID",
    "aws_session_token": "AWS session token",  # nosec B105
    "github_token": "GitHub token",  # nosec B105
    "github_fine_grained_pat": "GitHub token",
    "gitlab_pat": "GitLab token",
    "slack_token": "Slack token",  # nosec B105
    "slack_app_token": "Slack token",  # nosec B105
    "slack_webhook": "Slack webhook URL",
    "google_api_key": "Google API key",
    "google_oauth_client_secret": "Google OAuth client secret",  # nosec B105
    "gcp_service_account_key": "GCP service-account key",
    "openai_api_key": "OpenAI API key",
    "anthropic_api_key": "Anthropic API key",
    "stripe_live_key": "Stripe live key",
    "pem_private_key": "Private Key header",
    "database_connection_string": "Database credentials",
    "keyword_assignment": "API key token",
    "bearer_header": "Bearer token",
    "high_entropy_token": "High-entropy token",  # nosec B105
    "prompt_override_phrase": "System prompt override phrase",
}
# Public, non-secret format prefixes that may be echoed back to clients for triage.
PUBLIC_PREFIXES = (
    "AKIA",
    "ASIA",
    "ABIA",
    "ACCA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxo-",
    "xoxs-",
    "xoxr-",
    "xapp-",
    "AIza",
    "GOCSPX-",
    "sk-proj-",
    "sk-svcacct-",
    "sk-admin-",
    "sk-ant-",
    "sk_live_",
    "rk_live_",
)


class PayloadError(ValueError):
    """Client payload is not acceptable JSON (malformed, duplicate keys, too deep)."""


@dataclass
class InspectionResult:
    findings: list[Finding] = field(default_factory=list)
    field_path: str | None = None

    @property
    def blocked(self) -> bool:
        return bool(self.findings)

    @property
    def primary(self) -> Finding | None:
        return self.findings[0] if self.findings else None


def public_hint(finding: Finding) -> str:
    for prefix in PUBLIC_PREFIXES:
        if finding.value.startswith(prefix):
            return f" ({prefix}...)"
    return ""


def describe(finding: Finding, *, egress: bool = False) -> str:
    label = DETECTOR_LABELS.get(finding.detector, finding.detector)
    if finding.kind == "prompt_injection":
        return f"Prompt Injection Violation: System prompt override attempt detected ('{finding.value}')"
    if finding.category == "high_entropy_secret":
        prefix = "Outbound DLP High-Entropy Secret" if egress else "High Entropy Secret Detected"
        return f"{prefix}: random-looking token of length {finding.length}"
    if egress:
        return f"Outbound DLP Leak Blocked: {label} identified in model output{public_hint(finding)}"
    return f"Credential Leak Detected: {label} identified{public_hint(finding)}"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            # Different JSON parsers resolve duplicates differently (first vs last wins);
            # rejecting them prevents inspecting one value while the provider uses another.
            raise PayloadError(f"Duplicate JSON key {key!r}")
        out[key] = value
    return out


def parse_json_strict(body: bytes, max_depth: int) -> Any:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadError("Request body is not valid UTF-8") from exc
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise PayloadError("JSON nesting too deep") from exc
    except json.JSONDecodeError as exc:
        raise PayloadError(f"Malformed JSON: {exc.msg}") from exc
    _check_depth(data, max_depth)
    return data


def _check_depth(data: Any, max_depth: int) -> None:
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise PayloadError(f"JSON nesting exceeds maximum depth {max_depth}")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


def _is_entropy_exempt(key: str) -> bool:
    k = key.lower().strip()
    return k in ENTROPY_EXEMPT_KEYS or k.endswith(ENTROPY_EXEMPT_SUFFIXES)


def iter_json_strings(data: Any) -> Iterator[tuple[str, str, bool]]:
    """Yield ``(path, string, entropy_exempt)`` for every string value and object key (iterative)."""
    stack: list[tuple[Any, str, bool]] = [(data, "", False)]
    while stack:
        node, path, exempt = stack.pop()
        if isinstance(node, dict):
            items = list(node.items())
            for key, value in reversed(items):
                key_str = str(key)
                child = f"{path}.{key_str}" if path else key_str
                yield f"{child}<key>", key_str, True
                stack.append((value, child, exempt or _is_entropy_exempt(key_str)))
        elif isinstance(node, list):
            for idx in range(len(node) - 1, -1, -1):
                stack.append((node[idx], f"{path}[{idx}]", exempt))
        elif isinstance(node, str):
            yield path, node, exempt


def inspect_json(
    data: Any,
    *,
    entropy: bool = True,
    injection: bool = True,
) -> InspectionResult:
    for path, value, exempt in iter_json_strings(data):
        findings = scan_text_for_secrets(value, entropy=entropy and not exempt, first_only=True)
        if not findings and injection and not path.endswith("<key>"):
            findings = scan_text_for_injection(value)
        if findings:
            return InspectionResult(findings, path.replace("<key>", ""))
    return InspectionResult()


def inspect_text(text: str, *, entropy: bool = True, injection: bool = True) -> InspectionResult:
    findings = scan_text_for_secrets(text, entropy=entropy, first_only=True)
    if not findings and injection:
        findings = scan_text_for_injection(text)
    return InspectionResult(findings)


def inspect_egress_body(body: bytes, *, entropy: bool = True) -> InspectionResult:
    """Scan a buffered upstream response (JSON-aware, falls back to raw text)."""
    text = body.decode("utf-8", errors="replace")
    if not text.strip():
        return InspectionResult()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return inspect_text(text, entropy=entropy, injection=False)
    return inspect_json(data, entropy=entropy, injection=False)
