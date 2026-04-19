"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from fastapi import APIRouter, Body, Depends

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS, NOT_FOUND_ERRORS, merge_responses
from models.access.auth_models import Permission, TokenData
from models.alerting.requests import JiraConfigUpdateRequest
from services.alerting.integration_security_service import (
    JiraTenantConfigUpdate,
    load_tenant_jira_config,
    save_tenant_jira_config,
)

router = APIRouter(tags=["alertmanager-jira"])


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _jira_config_payload(config_data: dict[str, object]) -> JSONDict:
    return {
        "enabled": bool(config_data.get("enabled")),
        "baseUrl": _optional_str(config_data.get("baseUrl") or config_data.get("base_url")),
        "email": _optional_str(config_data.get("email")),
        "hasApiToken": bool(config_data.get("hasApiToken") or config_data.get("api_token")),
        "hasBearerToken": bool(config_data.get("hasBearerToken") or config_data.get("bearer")),
    }


@router.get(
    "/jira/config",
    summary="Get Jira Config",
    description="Returns the tenant-level Jira configuration with secrets masked into presence flags.",
    response_description="The current tenant Jira configuration.",
    responses=NOT_FOUND_ERRORS,
)
async def get_jira_config(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.MANAGE_TENANTS, "alertmanager")),
) -> JSONDict:
    cfg = load_tenant_jira_config(current_user.tenant_id)
    return _jira_config_payload(cfg)


@router.put(
    "/jira/config",
    summary="Update Jira Config",
    description="Updates the tenant-level Jira configuration used when an explicit integration is not selected.",
    response_description="The saved tenant Jira configuration.",
    responses=merge_responses(BAD_REQUEST_ERRORS, {404: {"description": "Not Found"}}),
)
@handle_route_errors()
async def update_jira_config(
    payload: JiraConfigUpdateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.MANAGE_TENANTS, "alertmanager")),
) -> JSONDict:
    saved = save_tenant_jira_config(
        current_user.tenant_id,
        JiraTenantConfigUpdate(
            enabled=bool(payload.enabled),
            base_url=payload.baseUrl,
            email=payload.email,
            api_token=payload.apiToken,
            bearer=payload.bearerToken,
        ),
    )
    return _jira_config_payload(saved)
