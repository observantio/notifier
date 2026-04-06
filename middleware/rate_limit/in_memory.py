"""
In-memory rate limiter implementation for Be Notified middleware.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import threading
import time

from .models import RateLimitHitResult, RateLimitState


class InMemoryRateLimiter:
    def __init__(
        self,
        *,
        gc_every: int = 1024,
        stale_after_seconds: int = 3600,
        max_states: int = 200_000,
    ) -> None:
        self._lock = threading.Lock()
        self._states: dict[str, RateLimitState] = {}
        self._gc_every = max(100, int(gc_every))
        self._stale_after_seconds = max(60, int(stale_after_seconds))
        self._max_states = max(10_000, int(max_states))
        self._ops = 0

    def _cleanup(self, now: float, window_seconds: int) -> None:
        self._ops += 1
        if self._ops % self._gc_every != 0:
            return
        threshold = now - max(window_seconds * 2, self._stale_after_seconds)
        stale = [k for k, st in self._states.items() if st.window_start < threshold]
        for k in stale:
            self._states.pop(k, None)

    def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitHitResult:
        if limit <= 0:
            return RateLimitHitResult(True, 0, 0, "memory")

        window_seconds = int(window_seconds)
        if window_seconds <= 0:
            return RateLimitHitResult(True, 0, 0, "memory")

        now = time.time()

        with self._lock:
            self._cleanup(now, window_seconds)

            if key not in self._states and len(self._states) >= self._max_states:
                oldest = min(self._states, key=lambda k: self._states[k].window_start)
                self._states.pop(oldest, None)

            st = self._states.get(key)
            if st is None or (now - st.window_start) >= window_seconds:
                st = RateLimitState(window_start=now, count=0)
                self._states[key] = st

            st.count += 1
            allowed = st.count <= limit
            remaining = max(0, limit - st.count)
            retry_after = max(0, int(window_seconds - (now - st.window_start)))
            return RateLimitHitResult(allowed, remaining, retry_after, "memory")
