from __future__ import annotations

import math
import threading
import time
from contextlib import contextmanager

from backend.config import settings


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_sweep: float = 0.0

    def hit(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            # Periodic sweep of stale keys to bound memory
            if now - self._last_sweep > self._window:
                self._hits = {
                    k: v for k, v in self._hits.items() if v and v[-1] > cutoff
                }
                self._last_sweep = now

            entries = self._hits.get(key)
            if entries is None:
                entries = []
                self._hits[key] = entries
            else:
                while entries and entries[0] <= cutoff:
                    entries.pop(0)

            if len(entries) >= self._limit:
                retry_after = max(1, math.ceil(entries[0] + self._window - now))
                return False, retry_after

            entries.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
            self._last_sweep = 0.0


class ConcurrencyLimiter:
    def __init__(self, max_concurrent: int) -> None:
        self._max = max_concurrent
        self._current = 0
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            if self._current >= self._max:
                return False
            self._current += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._current = max(0, self._current - 1)

    @contextmanager
    def slot(self):
        acquired = self.try_acquire()
        try:
            yield acquired
        finally:
            if acquired:
                self.release()


# ---------------------------------------------------------------------------
# Module-level singletons (created from settings at import time)
# ---------------------------------------------------------------------------

scan_ip_limiter = SlidingWindowRateLimiter(
    settings.RATE_LIMIT_SCANS_PER_MINUTE_IP, 60.0,
)
scan_session_limiter = SlidingWindowRateLimiter(
    settings.RATE_LIMIT_SCANS_PER_MINUTE_SESSION, 60.0,
)
auth_ip_limiter = SlidingWindowRateLimiter(
    settings.RATE_LIMIT_AUTH_PER_MINUTE_IP, 60.0,
)
scan_concurrency = ConcurrencyLimiter(settings.MAX_CONCURRENT_SCANS)


def client_ip(request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"
