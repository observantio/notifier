"""
OpenAPI customization wiring for the Notifier FastAPI app.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from typing import Any, Callable, cast

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


def _apply_inferred_responses(path: str, method: str, operation: dict[str, Any]) -> None:
    responses = operation.setdefault("responses", {})
    if not isinstance(responses, dict):
        return

    if path.startswith("/internal/v1"):
        # Internal API is guarded by service token + context auth layers.
        responses.setdefault("401", {"description": "Unauthorized"})
        responses.setdefault("403", {"description": "Forbidden"})

    if "requestBody" in operation or method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        responses.setdefault("400", {"description": "Bad Request"})

    if "{" in path and "}" in path:
        responses.setdefault("404", {"description": "Not Found"})

    if path.startswith("/internal/v1"):
        responses.setdefault("429", {"description": "Too Many Requests"})


def install_custom_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return cast(dict[str, Any], app.openapi_schema)

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

        app.openapi_schema = schema
        return schema

    app.openapi = cast(Callable[[], dict[str, Any]], custom_openapi)  # type: ignore[method-assign]
