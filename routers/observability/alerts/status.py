"""
Status endpoints for AlertManager integration, providing health checks and receiver information.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import cast

from fastapi import APIRouter, Depends, HTTPException

from middleware.dependencies import require_permission_with_scope
from middleware.openapi import BAD_REQUEST_ERRORS, COMMON_ERRORS
from models.access.auth_models import Permission, TokenData
from models.alerting.receivers import AlertManagerStatus

from .shared import alertmanager_service

router = APIRouter(tags=["alertmanager"])


@router.get(
    "/status",
    response_model=AlertManagerStatus,
    summary="Get Alertmanager Status",
    description="Returns alertmanager runtime status and cluster metadata.",
    response_description="The current alertmanager status payload.",
    responses=BAD_REQUEST_ERRORS,
)
async def get_alertmanager_status(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> AlertManagerStatus:
    _ = current_user
    result = await alertmanager_service.get_status()
    if not result:
        raise HTTPException(status_code=500, detail="Failed to fetch AlertManager status")
    return cast(AlertManagerStatus, result)


@router.get(
    "/receivers",
    response_model=list[str],
    summary="List Receivers",
    description="Lists alertmanager receiver names available for routing and inspection.",
    response_description="The configured alertmanager receiver names.",
    responses=COMMON_ERRORS,
)
async def list_receivers(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> list[str]:
    _ = current_user
    return cast(list[str], await alertmanager_service.get_receivers())
