"""
Shared router-level error handling helpers (moved from routers). Decorators for mapping expected exceptions to HTTP
status codes consistently across route handlers.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import wraps
from typing import TypeVar, cast

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)
RouteResult = TypeVar("RouteResult")
_MISSING = object()


@dataclass(frozen=True)
class RouteErrorResponse:
    detail: str | None
    status_code: int


def _coerce_route_error_response(
    current: RouteErrorResponse | None,
    *,
    default_detail: str | None,
    default_status_code: int,
    detail_override: object,
    status_override: object,
) -> RouteErrorResponse:
    detail = current.detail if current else default_detail
    status_code = current.status_code if current else default_status_code

    if detail_override is not _MISSING:
        detail = str(detail_override) if detail_override is not None else None
    if status_override is not _MISSING:
        try:
            status_code = int(cast(int | str | bytes | bytearray, status_override))
        except (TypeError, ValueError):
            status_code = default_status_code

    return RouteErrorResponse(detail=detail, status_code=status_code)


def handle_route_errors(
    *,
    bad_request_exceptions: tuple[type[Exception], ...] = (ValueError,),
    bad_request_detail: str | None = None,
    bad_gateway_exceptions: tuple[type[Exception], ...] = (httpx.HTTPError,),
    bad_gateway: RouteErrorResponse | None = None,
    internal: RouteErrorResponse | None = None,
    **legacy_kwargs: object,
) -> Callable[[Callable[..., Awaitable[RouteResult]]], Callable[..., Awaitable[RouteResult]]]:
    bad_gateway_response = _coerce_route_error_response(
        bad_gateway,
        default_detail="Upstream request failed",
        default_status_code=status.HTTP_502_BAD_GATEWAY,
        detail_override=legacy_kwargs.pop("bad_gateway_detail", _MISSING),
        status_override=legacy_kwargs.pop("bad_gateway_status_code", _MISSING),
    )
    internal_response = _coerce_route_error_response(
        internal,
        default_detail="Internal server error",
        default_status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail_override=legacy_kwargs.pop("internal_detail", _MISSING),
        status_override=legacy_kwargs.pop("internal_status_code", _MISSING),
    )

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
                raise HTTPException(
                    status_code=bad_gateway_response.status_code,
                    detail=bad_gateway_response.detail or "Upstream request failed",
                ) from exc
            except Exception as exc:
                logger.exception("Unhandled exception in route %s: %s", func.__name__, exc)
                if internal_response.detail:
                    raise HTTPException(
                        status_code=internal_response.status_code,
                        detail=internal_response.detail,
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
