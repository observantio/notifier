"""
Silence management endpoints for AlertManager integration, allowing users to create, update, delete, and hide silences.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from custom_types.json import JSONDict
from middleware.dependencies import require_any_permission_with_scope, require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS, BAD_REQUEST_NOT_FOUND_ERRORS
from models.access.auth_models import Permission, TokenData
from models.alerting.silences import Silence, SilenceCreateRequest

from .shared import (
    INVALID_FILTER_LABELS_JSON,
    HideTogglePayload,
    alertmanager_service,
    build_silence_payload,
    parse_show_hidden,
    reject_unknown_query_params,
    storage_service,
)

router = APIRouter(tags=["alertmanager-silences"])


class SilenceListQuery(BaseModel):
    filter_labels: str | None = Field(default=None)
    include_expired: bool = Field(default=False)
    show_hidden: str = Field(default="false", pattern="^(true|false)$")


@router.get(
    "/silences",
    response_model=list[Silence],
    summary="List Silences",
    description="Lists silences visible to the current user with optional label and expiration filtering.",
    response_description="The silences visible to the current caller.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(
    bad_request_exceptions=(ValueError, UnicodeError, TypeError),
    bad_request_detail=INVALID_FILTER_LABELS_JSON,
)
async def list_silences(
    request: Request,
    query: SilenceListQuery = Depends(),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
) -> list[Silence]:
    if request is not None:
        reject_unknown_query_params(request, {"filter_labels", "include_expired", "show_hidden"})
    silences = await alertmanager_service.get_silences(
        filter_labels=alertmanager_service.parse_filter_labels(query.filter_labels)
    )
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_silence_ids,
            current_user.tenant_id,
            current_user.user_id,
        )
    )
    result = []
    for silence in silences:
        silence = alertmanager_service.apply_silence_metadata(silence)
        if not query.include_expired:
            state = (silence.status or {}).get("state") if silence.status else None
            if state and str(state).lower() == "expired":
                continue
        if alertmanager_service.silence_accessible(silence, current_user):
            silence.is_hidden = bool(silence.id and silence.id in hidden_ids)
            if silence.is_hidden and not parse_show_hidden(query.show_hidden):
                continue
            result.append(silence)
    return result


@router.get(
    "/silences/{silence_id}",
    response_model=Silence,
    summary="Get Silence",
    description="Returns a single silence when it exists and is visible to the current user.",
    response_description="The requested silence.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(
    bad_request_exceptions=(ValueError, UnicodeError, TypeError),
    internal_detail="Invalid silence identifier",
    internal_status_code=400,
)
async def get_silence(
    silence_id: str,
    request: Request,
    show_hidden: str = Query("false", pattern="^(true|false)$"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
) -> Silence:
    if request is not None:
        reject_unknown_query_params(request, {"show_hidden"})
    silence = await alertmanager_service.get_silence(silence_id)
    if not silence:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    silence = alertmanager_service.apply_silence_metadata(silence)
    if not alertmanager_service.silence_accessible(silence, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_silence_ids,
            current_user.tenant_id,
            current_user.user_id,
        )
    )
    silence.is_hidden = bool(silence.id and silence.id in hidden_ids)
    if silence.is_hidden and not parse_show_hidden(show_hidden):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    return silence


@router.post(
    "/silences",
    response_model=dict[str, str],
    summary="Create Silence",
    description="Creates a new silence in alertmanager for the current user scope.",
    response_description="The created silence identifier and operation result.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_request_exceptions=(ValueError, UnicodeError, TypeError))
async def create_silence(
    silence: SilenceCreateRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_SILENCES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> dict[str, str]:
    silence_id = await alertmanager_service.create_silence(build_silence_payload(silence, current_user))
    if not silence_id:
        raise HTTPException(status_code=500, detail="Failed to create silence")
    return {"silenceID": silence_id, "status": "success"}


@router.put(
    "/silences/{silence_id}",
    response_model=dict[str, str],
    summary="Update Silence",
    description="Updates an existing silence when the caller owns it and still has access.",
    response_description="The updated silence identifier and operation result.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(bad_request_exceptions=(ValueError, UnicodeError, TypeError))
async def update_silence(
    silence_id: str,
    silence: SilenceCreateRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.UPDATE_SILENCES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> dict[str, str]:
    existing = await alertmanager_service.get_silence(silence_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    existing = alertmanager_service.apply_silence_metadata(existing)
    if not alertmanager_service.silence_accessible(existing, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    if not alertmanager_service.silence_owned_by(existing, current_user):
        raise HTTPException(status_code=403, detail="Only silence owner can update this silence")
    new_id = await alertmanager_service.update_silence(silence_id, build_silence_payload(silence, current_user))
    if not new_id:
        raise HTTPException(status_code=500, detail="Failed to update silence")
    return {"silenceID": new_id, "status": "success", "message": "Silence updated"}


@router.delete(
    "/silences/{silence_id}",
    summary="Delete Silence",
    description="Deletes an existing silence when the caller owns it and still has access.",
    response_description="The deletion result for the specified silence.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(
    bad_request_exceptions=(ValueError, UnicodeError, TypeError),
    internal_detail="Invalid silence identifier",
    internal_status_code=400,
)
async def delete_silence(
    silence_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_SILENCES, "alertmanager")),
) -> JSONDict:
    existing = await alertmanager_service.get_silence(silence_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    existing = alertmanager_service.apply_silence_metadata(existing)
    if not alertmanager_service.silence_accessible(existing, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    if not alertmanager_service.silence_owned_by(existing, current_user):
        raise HTTPException(status_code=403, detail="Only silence owner can delete this silence")
    if not await alertmanager_service.delete_silence(silence_id):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    return {"status": "success", "message": f"Silence {silence_id} deleted", "purged": True}


@router.post(
    "/silences/{silence_id}/hide",
    summary="Hide Silence",
    description="Toggles whether a shared silence is hidden for the current user.",
    response_description="The hide state applied to the silence.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(bad_request_exceptions=(ValueError, UnicodeError, TypeError))
async def hide_silence(
    silence_id: str,
    payload: HideTogglePayload = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
) -> JSONDict:
    silence = await alertmanager_service.get_silence(silence_id)
    if not silence:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    silence = alertmanager_service.apply_silence_metadata(silence)
    if not alertmanager_service.silence_accessible(silence, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")

    owner = str(getattr(silence, "created_by", "") or "")
    if owner and owner == str(current_user.user_id or ""):
        raise HTTPException(status_code=403, detail="You cannot hide your own silence")

    ok = await run_in_threadpool(
        storage_service.toggle_silence_hidden,
        current_user.tenant_id,
        current_user.user_id,
        silence_id,
        bool(payload.hidden),
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update silence visibility")
    return {"status": "success", "hidden": bool(payload.hidden)}
