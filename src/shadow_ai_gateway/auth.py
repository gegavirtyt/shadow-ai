"""Workload authentication and authorization.

Design:
* Each workload has an id and one or more credentials. Only SHA-256 digests of the
  credentials are kept in memory/configuration, so a configuration leak does not
  directly disclose usable keys (keys are expected to be high-entropy random
  values, for which an unsalted fast hash is appropriate; this is NOT suitable for
  human passwords).
* Multiple digests per workload allow zero-downtime rotation (add new key, roll
  clients, remove old key).
* Verification compares the presented key's digest against *every* configured
  digest with ``hmac.compare_digest`` and does not short-circuit, so timing does not
  reveal which workload (if any) matched.
* Authorization is least-privilege: a workload may be restricted to a set of model
  patterns (``fnmatch`` syntax). An empty set means "no per-workload restriction".
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

_MIN_KEY_LENGTH = 24


class WorkloadConfigError(ValueError):
    pass


def digest_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WorkloadCredential:
    workload_id: str
    key_sha256: tuple[str, ...] = field(repr=False)
    allowed_models: frozenset[str] = frozenset()

    @classmethod
    def from_plaintext(cls, workload_id: str, key: str, allowed_models: Iterable[str] = ()) -> WorkloadCredential:
        if len(key) < _MIN_KEY_LENGTH:
            raise WorkloadConfigError(f"Credential for workload {workload_id!r} is shorter than {_MIN_KEY_LENGTH} characters")
        return cls(workload_id, (digest_key(key),), frozenset(allowed_models))

    def model_allowed(self, model: str) -> bool:
        if not self.allowed_models:
            return True
        return any(fnmatch.fnmatchcase(model, pattern) for pattern in self.allowed_models)


def parse_workloads(text: str, *, source: str) -> list[WorkloadCredential]:
    """Parse a JSON list of workloads.

    Each entry: ``{"id": "billing-bot", "key_sha256": ["<hex>", ...], "allowed_models": ["gpt-4o-mini"]}``.
    ``key_sha256`` may also be a single string. Plaintext keys are deliberately not
    accepted in this format.
    """
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WorkloadConfigError(f"{source} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, list):
        raise WorkloadConfigError(f"{source} must be a JSON list")
    workloads: list[WorkloadCredential] = []
    for idx, entry in enumerate(data):
        if not isinstance(entry, Mapping):
            raise WorkloadConfigError(f"{source}[{idx}] must be an object")
        workload_id = entry.get("id")
        if not isinstance(workload_id, str) or not workload_id.strip():
            raise WorkloadConfigError(f"{source}[{idx}].id must be a non-empty string")
        digests = entry.get("key_sha256")
        if isinstance(digests, str):
            digests = [digests]
        if not isinstance(digests, list) or not digests:
            raise WorkloadConfigError(f"{source}[{idx}].key_sha256 must be a non-empty list")
        normalized: list[str] = []
        for d in digests:
            if not isinstance(d, str) or len(d) != 64 or any(c not in "0123456789abcdef" for c in d.lower()):
                raise WorkloadConfigError(f"{source}[{idx}].key_sha256 entries must be 64-char hex SHA-256 digests")
            normalized.append(d.lower())
        models = entry.get("allowed_models", [])
        if not isinstance(models, list) or not all(isinstance(m, str) for m in models):
            raise WorkloadConfigError(f"{source}[{idx}].allowed_models must be a list of strings")
        workloads.append(WorkloadCredential(workload_id.strip(), tuple(normalized), frozenset(models)))
    return workloads


def extract_presented_key(headers: Mapping[str, str]) -> str | None:
    """Return the credential presented via ``X-Gateway-Key`` or ``Authorization: Bearer``."""
    key = headers.get("x-gateway-key")
    if key and key.strip():
        return key.strip()
    auth = headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    workload: WorkloadCredential | None = None
    error: str | None = None


def authenticate(presented: str | None, workloads: Iterable[WorkloadCredential]) -> AuthResult:
    if not presented:
        return AuthResult(
            False, error="Missing workload gateway authentication credentials (X-Gateway-Key or Authorization: Bearer)."
        )
    presented_digest = digest_key(presented).encode("ascii")
    matched: WorkloadCredential | None = None
    for workload in workloads:
        for candidate in workload.key_sha256:
            # Evaluate every candidate; never break early.
            if hmac.compare_digest(presented_digest, candidate.encode("ascii")) and matched is None:
                matched = workload
    if matched is None:
        return AuthResult(False, error="Invalid workload gateway authentication key.")
    return AuthResult(True, workload=matched)


def model_permitted(model: str, workload: WorkloadCredential | None, global_allowed: frozenset[str]) -> bool:
    if global_allowed and not any(fnmatch.fnmatchcase(model, p) for p in global_allowed):
        return False
    if workload is not None and not workload.model_allowed(model):
        return False
    return True
