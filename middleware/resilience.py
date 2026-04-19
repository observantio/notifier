"""
Resilience decorators for service calls and rate limiting.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import ParamSpec, TypeVar

import httpx

from config import config

logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")
AsyncFunc = Callable[P, Awaitable[T]]


def with_retry(
    max_retries: int = config.max_retries, backoff: float = config.retry_backoff
) -> Callable[[AsyncFunc[P, T]], AsyncFunc[P, T]]:
    def decorator(func: AsyncFunc[P, T]) -> AsyncFunc[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            last_exception: Exception | None = None

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except httpx.HTTPStatusError as exc:
                    status_code = exc.response.status_code
                    if 400 <= status_code < 500:
                        logger.debug("%s: non-retriable HTTPStatusError %s — failing fast", func.__name__, status_code)
                        raise

                    last_exception = exc
                    if attempt < max_retries:
                        wait_time = min(config.retry_max_backoff, backoff * (2**attempt))
                        jitter = wait_time * max(0.0, config.retry_jitter)
                        wait_time = max(0.0, wait_time + random.uniform(-jitter, jitter))
                        logger.warning(
                            "Attempt %d/%d failed for %s: %s. Retrying in %ss...",
                            attempt + 1,
                            max_retries + 1,
                            func.__name__,
                            exc,
                            wait_time,
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(
                            "All %d attempts failed for %s: %s",
                            max_retries + 1,
                            func.__name__,
                            exc,
                        )
                except (TimeoutError, httpx.RequestError) as exc:
                    last_exception = exc
                    if attempt < max_retries:
                        wait_time = min(config.retry_max_backoff, backoff * (2**attempt))
                        jitter = wait_time * max(0.0, config.retry_jitter)
                        wait_time = max(0.0, wait_time + random.uniform(-jitter, jitter))
                        logger.warning(
                            "Attempt %d/%d failed for %s: %s. Retrying in %ss...",
                            attempt + 1,
                            max_retries + 1,
                            func.__name__,
                            exc,
                            wait_time,
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(
                            "All %d attempts failed for %s: %s",
                            max_retries + 1,
                            func.__name__,
                            exc,
                        )

            if last_exception is not None:
                raise last_exception
            raise RuntimeError(f"Retry wrapper exited without result or captured exception for {func.__name__}")

        return wrapper

    return decorator


def with_timeout(timeout: float = config.default_timeout) -> Callable[[AsyncFunc[P, T]], AsyncFunc[P, T]]:
    def decorator(func: AsyncFunc[P, T]) -> AsyncFunc[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
            except TimeoutError:
                logger.error("Timeout after %ss for %s", timeout, func.__name__)
                raise

        return wrapper

    return decorator
