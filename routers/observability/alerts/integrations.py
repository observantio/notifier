"""
Integration endpoints for AlertManager integration, providing information on allowed channel types for notifications.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from fastapi import APIRouter, Depends

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from middleware.openapi import COMMON_ERRORS
from models.access.auth_models import Permission, TokenData
from services.alerting.integration_security_service import allowed_channel_types

router = APIRouter(tags=["alertmanager"])


@router.get(
    "/integrations/channel-types",
    summary="List Allowed Channel Types",
    description="Lists notification channel types that are currently enabled for alertmanager integrations.",
    response_description="The channel types allowed by integration policy.",
    responses=COMMON_ERRORS,
)
async def list_channel_types(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
) -> JSONDict:
    _ = current_user
    return {"allowedTypes": allowed_channel_types()}
