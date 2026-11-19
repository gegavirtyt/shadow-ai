"""Immutable, validated gateway configuration.

All runtime configuration is read once (``Settings.from_env``) and passed explicitly
to the application factory. Request handlers never read ``os.environ`` directly, so
behaviour cannot drift mid-process and tests can construct isolated gateways.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .auth import WorkloadCredential, parse_workloads
from .detectors import minimum_stream_lookback

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})

DEFAULT_ALLOWED_UPSTREAM_HOSTS = frozenset({"api.openai.com", "api.anthropic.com"})
LOCAL_MOCK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SUPPORTED_PROVIDERS = frozenset({"openai", "anthropic", "generic"})
AUTH_MODES = frozenset({"required", "disabled"})
INJECTION_MODES = frozenset({"block", "log", "off"})
ENTROPY_MODES = frozenset({"block", "log", "off"})


class ConfigError(ValueError):
    """Raised when configuration is invalid. The gateway refuses to start."""


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean (true/false), got {raw!r}")


def _env_int(env: Mapping[str, str], name: str, default: int, *, minimum: int = 0, aliases: tuple[str, ...] = ()) -> int:
    raw = None
    for key in (name, *aliases):
        if env.get(key) not in (None, ""):
            raw = env[key]
            break
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_float(env: Mapping[str, str], name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_choice(env: Mapping[str, str], name: str, default: str, choices: frozenset[str]) -> str:
    value = (env.get(name) or default).strip().lower()
    if value not in choices:
        raise ConfigError(f"{name} must be one of {sorted(choices)}, got {value!r}")
    return value


def _entropy_mode(env: Mapping[str, str]) -> str:
    raw = (env.get("ENTROPY_DETECTION") or "block").strip().lower()
    legacy = {"true": "block", "1": "block", "yes": "block", "false": "off", "0": "off", "no": "off"}
    value = legacy.get(raw, raw)
    if value not in ENTROPY_MODES:
        raise ConfigError(f"ENTROPY_DETECTION must be one of {sorted(ENTROPY_MODES)}, got {raw!r}")
    return value


def _env_csv(env: Mapping[str, str], name: str) -> frozenset[str]:
    raw = env.get(name, "")
    return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    """Gateway configuration. Construct via :meth:`from_env` or directly in tests."""

    # Upstream destination (operator-controlled; never client-controlled)
    upstream_url: str = "https://api.openai.com/v1/chat/completions"
    upstream_provider: str = "openai"
    upstream_api_key: str = field(default="", repr=False)
    default_model: str = "gpt-4o-mini"
    allowed_upstream_hosts: frozenset[str] = DEFAULT_ALLOWED_UPSTREAM_HOSTS
    allow_local_mock: bool = False
    ca_bundle: str | None = None

    # Authentication / authorization
    auth_mode: str = "required"
    workloads: tuple[WorkloadCredential, ...] = field(default=(), repr=False)
    allowed_models: frozenset[str] = frozenset()  # empty = no global model restriction

    # Detection policy
    prompt_injection_mode: str = "block"
    # Generic high-entropy heuristic: block (default), log (audit only) or off. Pattern and
    # keyword detectors always block. See BENCHMARK_RESULTS.md for the measured FP cost on code.
    entropy_mode: str = "block"

    # Resource limits
    max_request_body_bytes: int = 1_048_576
    request_body_timeout_s: float = 30.0
    max_response_body_bytes: int = 8_388_608
    max_concurrent_requests: int = 64
    rate_limit_per_minute: int = 0  # per workload, per replica; 0 disables
    max_json_depth: int = 64

    # Upstream transport
    upstream_connect_timeout_s: float = 5.0
    upstream_read_timeout_s: float = 60.0
    upstream_write_timeout_s: float = 10.0
    upstream_pool_timeout_s: float = 5.0
    upstream_max_connections: int = 100
    upstream_max_keepalive: int = 20

    # Streaming DLP
    stream_lookback_chars: int = 64
    stream_max_hold_chars: int = 16_384
    stream_max_event_bytes: int = 1_048_576
    stream_max_total_bytes: int = 33_554_432
    stream_max_duration_s: float = 300.0

    # Audit
    audit_hmac_key: bytes = field(default=b"", repr=False)

    # Development affordances (must be off in production)
    enable_test_endpoints: bool = False
    enable_docs: bool = False

    @property
    def upstream_host(self) -> str:
        return (urllib.parse.urlsplit(self.upstream_url).hostname or "").lower()

    def effective_allowed_hosts(self) -> frozenset[str]:
        hosts = set(self.allowed_upstream_hosts)
        if self.allow_local_mock:
            hosts |= LOCAL_MOCK_HOSTS
        return frozenset(hosts)

    def with_overrides(self, **changes: Any) -> Settings:
        return replace(self, **changes)

    def validate(self) -> None:
        """Startup validation. Raises ConfigError on unsafe or inconsistent settings."""
        parts = urllib.parse.urlsplit(self.upstream_url)
        if parts.scheme not in ("http", "https"):
            raise ConfigError("UPSTREAM_LLM_URL must use http or https")
        if not parts.hostname:
            raise ConfigError("UPSTREAM_LLM_URL has no hostname")
        if parts.username or parts.password:
            raise ConfigError("UPSTREAM_LLM_URL must not embed credentials")
        if parts.scheme == "http" and not self.allow_local_mock:
            raise ConfigError("Plain-HTTP upstreams are only permitted with ALLOW_LOCAL_MOCK=true")
        if self.upstream_host not in self.effective_allowed_hosts():
            raise ConfigError(f"Upstream host {self.upstream_host!r} is not in ALLOWED_UPSTREAM_HOSTS")
        if self.upstream_provider not in SUPPORTED_PROVIDERS:
            raise ConfigError(f"UPSTREAM_PROVIDER must be one of {sorted(SUPPORTED_PROVIDERS)}")
        if self.auth_mode == "required" and not self.workloads:
            raise ConfigError(
                "GATEWAY_AUTH_MODE=required but no workload credentials are configured "
                "(set GATEWAY_API_KEY, GATEWAY_WORKLOADS_FILE or GATEWAY_WORKLOADS_JSON, "
                "or explicitly set GATEWAY_AUTH_MODE=disabled for local development)"
            )
        minimum = minimum_stream_lookback()
        if self.stream_lookback_chars < minimum:
            raise ConfigError(
                f"STREAM_DLP_WINDOW_SIZE={self.stream_lookback_chars} is below the minimum "
                f"{minimum} required by the configured detectors"
            )
        if self.stream_max_hold_chars < 4 * self.stream_lookback_chars:
            raise ConfigError("STREAM_MAX_HOLD_CHARS must be at least 4x STREAM_DLP_WINDOW_SIZE")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        allow_local_mock = _env_bool(env, "ALLOW_LOCAL_MOCK", False)
        provider = _env_choice(env, "UPSTREAM_PROVIDER", "openai", SUPPORTED_PROVIDERS)

        upstream_url = (env.get("UPSTREAM_LLM_URL") or env.get("UPSTREAM_TARGET_URL") or cls.upstream_url).strip()

        api_key = (env.get("UPSTREAM_API_KEY") or "").strip()
        if not api_key and provider == "openai":
            api_key = (env.get("OPENAI_API_KEY") or "").strip()
        if not api_key and provider == "anthropic":
            api_key = (env.get("ANTHROPIC_API_KEY") or "").strip()

        allowed_hosts = _env_csv(env, "ALLOWED_UPSTREAM_HOSTS") or DEFAULT_ALLOWED_UPSTREAM_HOSTS

        workloads = list(parse_workloads(env.get("GATEWAY_WORKLOADS_JSON") or "[]", source="GATEWAY_WORKLOADS_JSON"))
        workloads_file = (env.get("GATEWAY_WORKLOADS_FILE") or "").strip()
        if workloads_file:
            try:
                text = Path(workloads_file).read_text(encoding="utf-8")
            except OSError as exc:
                raise ConfigError(f"Cannot read GATEWAY_WORKLOADS_FILE: {exc.strerror}") from exc
            workloads.extend(parse_workloads(text, source="GATEWAY_WORKLOADS_FILE"))
        legacy_key = (env.get("GATEWAY_API_KEY") or "").strip()
        if legacy_key:
            workloads.append(WorkloadCredential.from_plaintext("default", legacy_key))
        ids = [w.workload_id for w in workloads]
        if len(ids) != len(set(ids)):
            raise ConfigError("Duplicate workload ids in workload configuration")

        # Fail closed: v3 treated an empty GATEWAY_API_KEY as "auth disabled"; v4 requires an
        # explicit GATEWAY_AUTH_MODE=disabled for that (see CHANGELOG / SECURITY_DESIGN.md).
        auth_mode = _env_choice(env, "GATEWAY_AUTH_MODE", "required", AUTH_MODES)

        hmac_key_raw = (env.get("AUDIT_HMAC_KEY") or "").strip()

        return cls(
            upstream_url=upstream_url,
            upstream_provider=provider,
            upstream_api_key=api_key,
            default_model=(env.get("OPENAI_MODEL") or env.get("DEFAULT_MODEL") or cls.default_model).strip(),
            allowed_upstream_hosts=allowed_hosts,
            allow_local_mock=allow_local_mock,
            ca_bundle=(env.get("UPSTREAM_CA_BUNDLE") or "").strip() or None,
            auth_mode=auth_mode,
            workloads=tuple(workloads),
            allowed_models=_env_csv(env, "ALLOWED_MODELS"),
            prompt_injection_mode=_env_choice(env, "PROMPT_INJECTION_MODE", "block", INJECTION_MODES),
            entropy_mode=_entropy_mode(env),
            max_request_body_bytes=_env_int(
                env, "MAX_REQUEST_BODY_SIZE", cls.max_request_body_bytes, minimum=1, aliases=("MAX_PAYLOAD_SIZE_BYTES",)
            ),
            request_body_timeout_s=_env_float(env, "REQUEST_BODY_TIMEOUT", cls.request_body_timeout_s, minimum=0.1),
            max_response_body_bytes=_env_int(env, "MAX_RESPONSE_BODY_SIZE", cls.max_response_body_bytes, minimum=1),
            max_concurrent_requests=_env_int(env, "MAX_CONCURRENT_REQUESTS", cls.max_concurrent_requests, minimum=1),
            rate_limit_per_minute=_env_int(env, "RATE_LIMIT_PER_MINUTE", cls.rate_limit_per_minute, minimum=0),
            max_json_depth=_env_int(env, "MAX_JSON_DEPTH", cls.max_json_depth, minimum=2),
            upstream_connect_timeout_s=_env_float(env, "UPSTREAM_CONNECT_TIMEOUT", cls.upstream_connect_timeout_s, minimum=0.1),
            upstream_read_timeout_s=_env_float(env, "UPSTREAM_READ_TIMEOUT", cls.upstream_read_timeout_s, minimum=0.1),
            upstream_write_timeout_s=_env_float(env, "UPSTREAM_WRITE_TIMEOUT", cls.upstream_write_timeout_s, minimum=0.1),
            upstream_pool_timeout_s=_env_float(env, "UPSTREAM_POOL_TIMEOUT", cls.upstream_pool_timeout_s, minimum=0.1),
            upstream_max_connections=_env_int(env, "UPSTREAM_MAX_CONNECTIONS", cls.upstream_max_connections, minimum=1),
            upstream_max_keepalive=_env_int(env, "UPSTREAM_MAX_KEEPALIVE", cls.upstream_max_keepalive, minimum=0),
            stream_lookback_chars=_env_int(
                env, "STREAM_DLP_WINDOW_SIZE", cls.stream_lookback_chars, minimum=1, aliases=("STREAMING_DELAY_WINDOW_CHARS",)
            ),
            stream_max_hold_chars=_env_int(
                env, "STREAM_MAX_HOLD_CHARS", cls.stream_max_hold_chars, minimum=1, aliases=("MAX_STREAM_BUFFER_CHARS",)
            ),
            stream_max_event_bytes=_env_int(env, "STREAM_MAX_EVENT_BYTES", cls.stream_max_event_bytes, minimum=1024),
            stream_max_total_bytes=_env_int(env, "STREAM_MAX_TOTAL_BYTES", cls.stream_max_total_bytes, minimum=1024),
            stream_max_duration_s=_env_float(env, "STREAM_MAX_DURATION", cls.stream_max_duration_s, minimum=1.0),
            audit_hmac_key=hmac_key_raw.encode("utf-8"),
            enable_test_endpoints=_env_bool(env, "ENABLE_TEST_ENDPOINTS", False),
            enable_docs=_env_bool(env, "ENABLE_API_DOCS", False),
        )


def settings_summary(settings: Settings) -> dict[str, Any]:
    """Non-secret view of the configuration for startup logging."""
    return {
        "upstream_host": settings.upstream_host,
        "upstream_provider": settings.upstream_provider,
        "upstream_credential_configured": bool(settings.upstream_api_key),
        "allow_local_mock": settings.allow_local_mock,
        "auth_mode": settings.auth_mode,
        "workload_count": len(settings.workloads),
        "prompt_injection_mode": settings.prompt_injection_mode,
        "entropy_mode": settings.entropy_mode,
        "max_concurrent_requests": settings.max_concurrent_requests,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
        "stream_lookback_chars": settings.stream_lookback_chars,
        "test_endpoints": settings.enable_test_endpoints,
    }


__all__ = ["ConfigError", "Settings", "json", "settings_summary"]
