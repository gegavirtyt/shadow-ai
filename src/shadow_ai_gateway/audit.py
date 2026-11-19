"""Structured security audit events.

Rules enforced here:
* Events never contain request/response content, secret values, header values or
  exception tracebacks. Detected values are represented by detector id, category,
  length and a *keyed* fingerprint (HMAC-SHA256), so repeated leaks of the same value
  can be correlated without the log becoming a secret store. With an unkeyed hash a
  short secret could be confirmed by brute force; the HMAC key prevents that.
* Without ``AUDIT_HMAC_KEY`` a random per-process key is used: fingerprints are then
  only comparable within one process (``fingerprint_scope: "process"``).
* Logging failures never break request handling (fail-safe for availability; the
  security decision itself has already been made and is enforced regardless).
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import hmac
import json
import logging
import os
import sys
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .detectors import Finding

AUDIT_LOGGER_NAME = "shadow_ai_gateway.audit"
SCHEMA_VERSION = 1

audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)


@dataclass
class RequestContext:
    request_id: str
    client_ip: str
    method: str
    path: str
    workload_id: str | None = None


class AuditLogger:
    def __init__(self, hmac_key: bytes = b"", upstream_host: str = "") -> None:
        self._key = hmac_key or os.urandom(32)
        self.fingerprint_scope = "deployment" if hmac_key else "process"
        self.upstream_host = upstream_host

    def fingerprint(self, data: bytes | str) -> str:
        raw = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else data
        return hmac.new(self._key, raw, hashlib.sha256).hexdigest()[:32]

    def emit(
        self,
        event_type: str,
        *,
        decision: str,
        policy_id: str,
        ctx: RequestContext | None,
        reason: str,
        findings: Iterable[Finding] = (),
        payload: bytes | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": event_type,
            "decision": decision,
            "policy_id": policy_id,
            "reason": reason,
            "upstream_host": self.upstream_host,
            "fingerprint_scope": self.fingerprint_scope,
        }
        if ctx is not None:
            event.update(
                request_id=ctx.request_id,
                client_ip=ctx.client_ip,
                method=ctx.method,
                path=ctx.path,
                workload_id=ctx.workload_id,
            )
        detections = [
            {
                "detector": f.detector,
                "category": f.category,
                "kind": f.kind,
                "length": f.length,
                "value_fingerprint": self.fingerprint(f.value) if f.value else None,
            }
            for f in findings
        ]
        if detections:
            event["detections"] = detections
        if payload is not None:
            event["payload_bytes"] = len(payload)
            event["payload_fingerprint"] = self.fingerprint(payload)
        if extra:
            event.update({k: v for k, v in extra.items() if k not in event})
        _write(event)
        return event


def _write(event: Mapping[str, Any]) -> None:
    try:
        audit_logger.warning(json.dumps(event, separators=(",", ":"), default=str))
    except Exception:  # noqa: BLE001 - logging must never take the gateway down (decision already enforced)
        with contextlib.suppress(Exception):
            sys.stderr.write('{"event_type":"AUDIT_LOG_FAILURE"}\n')


def configure_audit_logging() -> None:
    """Attach a JSON-lines stdout handler if the host application configured none."""
    if not audit_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False


def emit_siem_security_log(
    event_type: str,
    violation_reason: str,
    client_ip: str,
    payload_bytes: bytes,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deprecated v3 API retained for compatibility. Prefer :class:`AuditLogger`.

    Note: ``payload_sha256`` is an *unkeyed* digest, kept only because the v3 schema
    defined it; the gateway itself emits keyed fingerprints.
    """
    event: dict[str, Any] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "client_ip": client_ip or "unknown",
        "violation_reason": violation_reason,
        "payload_sha256": hashlib.sha256(payload_bytes or b"").hexdigest(),
    }
    if extra_fields:
        event.update(extra_fields)
    _write(event)
    return event
