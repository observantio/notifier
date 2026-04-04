"""
Shared router-level error handling helpers (moved from routers). Decorators for mapping expected exceptions to HTTP
status codes consistently across route handlers.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from functools import wraps
from typing import Awaitable, Callable, TypeVar
import logging

import httpx
from fastapi import HTTPException, status, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)
RouteResult = TypeVar("RouteResult")


def handle_route_errors(
    *,
    bad_request_exceptions: tuple[type[Exception], ...] = (ValueError,),
    bad_request_detail: str | None = None,
    bad_gateway_exceptions: tuple[type[Exception], ...] = (httpx.HTTPError,),
    bad_gateway_detail: str = "Upstream request failed",
    bad_gateway_status_code: int = status.HTTP_502_BAD_GATEWAY,
    internal_detail: str | None = "Internal server error",
    internal_status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
) -> Callable[[Callable[..., Awaitable[RouteResult]]], Callable[..., Awaitable[RouteResult]]]:

    def decorator(func: Callable[..., Awaitable[RouteResult]]) -> Callable[..., Awaitable[RouteResult]]:
        @wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> RouteResult:
            try:
                return await func(*args, **kwargs)
            except HTTPException:
                raise
            except bad_request_exceptions as exc:
                detail = bad_request_detail or str(exc) or "Invalid request"
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
            except bad_gateway_exceptions as exc:
                logger.warning("Upstream request failed in %s: %s", func.__name__, exc)
                raise HTTPException(status_code=bad_gateway_status_code, detail=bad_gateway_detail) from exc
            except Exception as exc:
                logger.exception("Unhandled exception in route %s: %s", func.__name__, exc)
                if internal_detail:
                    raise HTTPException(
                        status_code=internal_status_code,
                        detail=internal_detail,
                    ) from exc
                raise

        return wrapper

    return decorator


def validation_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.warning("Request validation error for %s: %s", request.url, exc)
    detail = exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": detail},
    )


def general_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.exception("Unhandled exception for %s: %s", request.url, exc)
    if isinstance(exc, (ValueError, UnicodeError, TypeError)):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Invalid request"},
        )
    if request.url.path.startswith("/internal/v1/api/alertmanager"):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Invalid request"},
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


def http_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    if isinstance(exc, (HTTPException, StarletteHTTPException)):
        status_code = int(getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR))
        detail = getattr(exc, "detail", "Request failed")
        headers = getattr(exc, "headers", None)
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        detail = "Request failed"
        headers = None

    if status_code >= 500 and request.url.path.startswith("/internal/v1/api/alertmanager"):
        status_code = status.HTTP_400_BAD_REQUEST

    content = {"detail": detail}
    if headers:
        return JSONResponse(status_code=status_code, content=content, headers=headers)
    return JSONResponse(status_code=status_code, content=content)
