"""
Entrypoint for the Notifier service.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Awaitable, Callable

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

import database as database_module
from config import config
from middleware.concurrency_limit import ConcurrencyLimitMiddleware
from middleware.error_handlers import general_exception_handler, http_exception_handler, validation_exception_handler
from middleware.headers import security_headers_middleware
from middleware.openapi import (
    install_custom_openapi,
    openapi_contact,
    openapi_license,
    openapi_servers,
    openapi_tags,
)
from middleware.request_size_limit import RequestSizeLimitMiddleware
from routers.observability.alerts import (
    router as alertmanager_alerts_router,
)
from routers.observability.alerts import (
    webhook_router as alertmanager_webhook_router,
)
from routers.observability.incidents import router as alertmanager_incidents_router
from routers.observability.jira import router as alertmanager_jira_router

logging.basicConfig(
    level=getattr(logging, config.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("notifier")

# Expose this name for route logic and tests that monkeypatch main.connection_test.
connection_test = database_module.connection_test

database_module.ensure_database_exists(config.notifier_database_url)
database_module.init_database(config.notifier_database_url, config.log_level == "debug")
database_module.init_db()

APP_TITLE = "Notifier"
APP_DESCRIPTION = "Internal alerting service for Watchdog"

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    servers=openapi_servers(
        host=config.host,
        port=config.port,
        tls_enabled=config.notifier_tls_enabled,
    ),
    contact=openapi_contact(service_name=APP_TITLE),
    license_info=openapi_license(),
    openapi_tags=openapi_tags(),
    generate_unique_id_function=lambda route: route.name,
    docs_url="/docs" if config.enable_api_docs else None,
    redoc_url="/redoc" if config.enable_api_docs else None,
    openapi_url="/openapi.json" if config.enable_api_docs else None,
)

app.middleware("http")(security_headers_middleware)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)

app.add_middleware(RequestSizeLimitMiddleware, max_bytes=config.max_request_bytes)
app.add_middleware(
    ConcurrencyLimitMiddleware,
    max_concurrent=config.max_concurrent_requests,
    acquire_timeout=config.concurrency_acquire_timeout,
)


@app.middleware("http")
async def require_internal_service_token(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    allowed_paths = {"/health", "/ready"}
    if config.enable_api_docs:
        allowed_paths.update({"/docs", "/redoc", "/openapi.json"})

    if request.url.path in allowed_paths:
        return await call_next(request)

    if request.url.path in {
        "/internal/v1/alertmanager/alerts/webhook",
        "/internal/v1/alertmanager/alerts/critical",
        "/internal/v1/alertmanager/alerts/warning",
    }:
        return await call_next(request)

    expected = config.get_secret("NOTIFIER_EXPECTED_SERVICE_TOKEN") or config.get_secret(
        "GATEWAY_INTERNAL_SERVICE_TOKEN"
    )
    if not expected:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Service token not configured"},
        )

    provided = request.headers.get("X-Service-Token")
    if not provided or not secrets.compare_digest(provided, expected):
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Forbidden"})

    return await call_next(request)


app.include_router(alertmanager_alerts_router, prefix="/internal/v1")
app.include_router(alertmanager_incidents_router, prefix="/internal/v1")
app.include_router(alertmanager_jira_router, prefix="/internal/v1")

app.include_router(alertmanager_webhook_router, prefix="/internal/v1/alertmanager")

install_custom_openapi(app)


@app.get(
    "/health",
    tags=["system"],
    summary="Service Health",
    description="Returns a lightweight health status for the notifier service.",
    response_description="The current health status for the notifier service.",
)
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "notifier"}


@app.get(
    "/ready",
    response_model=None,
    tags=["system"],
    summary="Service Readiness",
    description="Runs readiness checks required for notifier to serve traffic.",
    response_description="The readiness result and individual dependency checks.",
)
async def readiness() -> JSONResponse:
    checks: dict[str, bool] = {"database": connection_test()}
    ok = all(checks.values())
    payload: dict[str, bool | str | dict[str, bool]] = {"status": "ready" if ok else "not_ready", "checks": checks}
    if not ok:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)
    return JSONResponse(status_code=status.HTTP_200_OK, content=payload)


ready = readiness


if __name__ == "__main__":
    uvicorn.run(app, host=config.host, port=config.port, loop="uvloop", log_level=config.log_level)
