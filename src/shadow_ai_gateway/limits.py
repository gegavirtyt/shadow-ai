"""In-process admission control: concurrency limiting and per-workload rate limiting.

Both limiters are *per replica*. With N replicas the effective cluster-wide limits
are N times the configured values; exact global limits would require shared state
(e.g. Redis), which this project deliberately does not introduce (see DEPLOYMENT.md).
All methods are called from the event loop thread without awaiting between check
and update, so no lock is required.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


class ConcurrencySlot:
    __slots__ = ("_limiter", "_released")

    def __init__(self, limiter: ConcurrencyLimiter) -> None:
        self._limiter = limiter
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._limiter.active -= 1


class ConcurrencyLimiter:
    def __init__(self, max_active: int) -> None:
        self.max_active = max_active
        self.active = 0
        self.rejected = 0

    def try_acquire(self) -> ConcurrencySlot | None:
        if self.active >= self.max_active:
            self.rejected += 1
            return None
        self.active += 1
        return ConcurrencySlot(self)


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token bucket per key: ``per_minute`` requests/minute with a burst of the same size."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.per_minute = per_minute
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    @property
    def enabled(self) -> bool:
        return self.per_minute > 0

    def allow(self, key: str) -> tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)``."""
        if not self.enabled:
            return True, 0.0
        now = self._clock()
        rate = self.per_minute / 60.0
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = _Bucket(float(self.per_minute), now)
        bucket.tokens = min(float(self.per_minute), bucket.tokens + (now - bucket.updated) * rate)
        bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True, 0.0
        return False, (1.0 - bucket.tokens) / rate
