"""
OpenAPI customization wiring for the Notifier FastAPI app.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, TypeAlias

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
DEFAULT_TAG_GROUPS: tuple[str, ...] = (
    "alertmanager",
    "alertmanager-silences",
    "alertmanager-rules",
    "alertmanager-channels",
    "alertmanager-incidents",
    "alertmanager-jira",
    "alertmanager-webhooks",
    "system",
)

_TAG_RESOURCES: dict[str, tuple[str, ...]] = {
    "alertmanager": ("alerts", "routing status", "shared access workflows"),
    "alertmanager-silences": ("silences", "silence updates", "visibility controls"),
    "alertmanager-rules": ("alert rules", "rule imports", "metrics discovery"),
    "alertmanager-channels": ("notification channels", "channel validation", "delivery testing"),
    "alertmanager-incidents": ("incidents", "incident summaries", "incident state updates"),
    "alertmanager-jira": ("Jira config", "integration discovery", "incident linking"),
    "alertmanager-webhooks": ("inbound webhooks", "alert ingestion", "downstream notification triggers"),
    "system": ("health checks", "readiness checks", "service monitoring"),
}


ResponseSpec: TypeAlias = dict[str, Any]
ResponsesMap: TypeAlias = dict[int | str, ResponseSpec]


def status_description(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return f"HTTP {status_code}"


def error_responses(*status_codes: int) -> ResponsesMap:
    ordered_codes = tuple(dict.fromkeys(status_codes))
    return {status_code: {"description": status_description(status_code)} for status_code in ordered_codes}


COMMON_ERRORS: ResponsesMap = error_responses(401, 403, 429)
BAD_REQUEST_ERRORS: ResponsesMap = error_responses(401, 403, 429, 400)
NOT_FOUND_ERRORS: ResponsesMap = error_responses(401, 403, 429, 404)
BAD_REQUEST_NOT_FOUND_ERRORS: ResponsesMap = error_responses(401, 403, 429, 400, 404)
CONFLICT_ERRORS: ResponsesMap = error_responses(401, 403, 429, 400, 404, 409)


def tag_description(tag_name: str) -> str:
    resources = _TAG_RESOURCES.get(tag_name)
    if not resources:
        return f"Operations for {tag_name.replace('-', ' ')}."
    return f"Operations for {resources[0]}, {resources[1]}, and {resources[2]}."


def openapi_tags(tag_names: tuple[str, ...] = DEFAULT_TAG_GROUPS) -> list[dict[str, str]]:
    return [{"name": tag_name, "description": tag_description(tag_name)} for tag_name in tag_names]


def openapi_contact(
    *,
    service_name: str,
    team_name: str | None = None,
    email_prefix: str = "platform",
    email_domain: str = "internal",
) -> dict[str, str]:
    normalized = service_name.strip().lower().replace(" ", "-") or "service"
    return {
        "name": team_name or f"{service_name.strip() or 'Service'} Platform Team",
        "email": f"{email_prefix}@{normalized}.{email_domain}",
    }


def openapi_license(license_name: str = "Apache License 2.0", license_id: str = "Apache-2.0") -> dict[str, str]:
    return {"name": license_name, "identifier": license_id}


def openapi_servers(
    *,
    host: str,
    port: int,
    tls_enabled: bool = False,
    explicit_url: str | None = None,
) -> list[dict[str, str]]:
    if explicit_url:
        return [{"url": explicit_url.rstrip("/"), "description": "Configured runtime endpoint"}]

    scheme = "https" if tls_enabled else "http"
    resolved_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    label = "local runtime endpoint" if resolved_host in {"127.0.0.1", "localhost"} else "runtime endpoint"
    return [{"url": f"{scheme}://{resolved_host}:{port}", "description": label}]


def merge_responses(*groups: Mapping[int | str, ResponseSpec]) -> ResponsesMap:
    merged: ResponsesMap = {}
    for group in groups:
        merged.update(group)
    return merged


def _apply_inferred_responses(path: str, method: str, operation: dict[str, Any]) -> None:
    responses = operation.setdefault("responses", {})
    if not isinstance(responses, dict):
        return

    if path.startswith("/internal/v1"):
        # Internal API is guarded by service token + context auth layers.
        responses.setdefault("401", {"description": status_description(401)})
        responses.setdefault("403", {"description": status_description(403)})

    if "requestBody" in operation or method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        responses.setdefault("400", {"description": status_description(400)})

    if "{" in path and "}" in path:
        responses.setdefault("404", {"description": status_description(404)})

    if path.startswith("/internal/v1"):
        responses.setdefault("429", {"description": status_description(429)})


def install_custom_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )

        paths = schema.get("paths", {})
        if isinstance(paths, dict):
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    if not isinstance(operation, dict):
                        continue
                    _apply_inferred_responses(path, method, operation)

        schema["jsonSchemaDialect"] = JSON_SCHEMA_DIALECT
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
