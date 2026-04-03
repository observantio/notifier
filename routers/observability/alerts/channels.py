"""
Channel management endpoints for AlertManager integration, allowing users to create, update, delete, and test notification channels.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool

from config import config
from custom_types.json import JSONDict
from middleware.dependencies import require_any_permission_with_scope, require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS, BAD_REQUEST_NOT_FOUND_ERRORS, NOT_FOUND_ERRORS
from models.access.auth_models import Permission, TokenData
from models.alerting.alerts import Alert
from models.alerting.channels import ChannelType, NotificationChannel, NotificationChannelCreate

from .shared import (
    HideTogglePayload,
    alertmanager_service,
    notification_service,
    parse_show_hidden,
    reject_unknown_query_params,
    storage_service,
    validate_channel,
)

router = APIRouter(tags=["alertmanager-channels"])


@router.get(
    "/channels",
    response_model=List[NotificationChannel],
    summary="List Notification Channels",
    description="Lists notification channels visible to the current user.",
    response_description="The notification channels visible to the current caller.",
    responses=BAD_REQUEST_ERRORS,
)
async def list_channels(
    request: Request,
    limit: int = Query(config.DEFAULT_QUERY_LIMIT, ge=1, le=config.MAX_QUERY_LIMIT),
    offset: int = Query(0, ge=0),
    show_hidden: str = Query("false", pattern="^(true|false)$"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
) -> List[NotificationChannel]:
    if request is not None:
        reject_unknown_query_params(request, {"limit", "offset", "show_hidden"})
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    channels = await run_in_threadpool(
        storage_service.get_notification_channels,
        tenant_id,
        user_id,
        group_ids,
        limit,
        offset,
    )
    hidden_ids = set(await run_in_threadpool(storage_service.get_hidden_channel_ids, tenant_id, user_id))
    for channel in channels:
        channel.is_hidden = bool(channel.id and channel.id in hidden_ids)
    if not parse_show_hidden(show_hidden):
        channels = [channel for channel in channels if not channel.is_hidden]
    return channels


@router.get(
    "/channels/{channel_id}",
    response_model=NotificationChannel,
    summary="Get Notification Channel",
    description="Returns a single notification channel when it exists and is visible to the current user.",
    response_description="The requested notification channel.",
    responses=NOT_FOUND_ERRORS,
)
async def get_channel(
    channel_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
) -> NotificationChannel:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    channel = await run_in_threadpool(storage_service.get_notification_channel, channel_id, tenant_id, user_id, group_ids)
    if not channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found")
    hidden_ids = set(await run_in_threadpool(storage_service.get_hidden_channel_ids, tenant_id, user_id))
    channel.is_hidden = bool(channel.id and channel.id in hidden_ids)
    return channel


@router.post(
    "/channels/{channel_id}/hide",
    summary="Hide Notification Channel",
    description="Toggles whether a shared notification channel is hidden for the current user.",
    response_description="The hide state applied to the notification channel.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors()
async def hide_channel(
    channel_id: str,
    payload: HideTogglePayload = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    channel = await run_in_threadpool(storage_service.get_notification_channel, channel_id, tenant_id, user_id, group_ids)
    if not channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found")
    if str(getattr(channel, "created_by", "") or "") == user_id:
        raise HTTPException(status_code=403, detail="You cannot hide your own notification channel")
    if str(getattr(channel, "visibility", "private") or "private") == "private":
        raise HTTPException(status_code=403, detail="Only shared notification channels can be hidden")

    ok = await run_in_threadpool(storage_service.toggle_channel_hidden, tenant_id, user_id, channel_id, bool(payload.hidden))
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update channel visibility")
    return {"status": "success", "hidden": bool(payload.hidden)}


@router.post(
    "/channels",
    response_model=NotificationChannel,
    status_code=status.HTTP_201_CREATED,
    summary="Create Notification Channel",
    description="Creates a new notification channel for the current tenant scope.",
    response_description="The newly created notification channel.",
    responses=BAD_REQUEST_ERRORS,
)
async def create_channel(
    channel: NotificationChannelCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_CHANNELS, Permission.WRITE_CHANNELS], "alertmanager")
    ),
) -> NotificationChannel:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    validate_channel(channel, notification_service)
    return await run_in_threadpool(storage_service.create_notification_channel, channel, tenant_id, user_id, group_ids)


@router.put(
    "/channels/{channel_id}",
    response_model=NotificationChannel,
    summary="Update Notification Channel",
    description="Updates an existing notification channel in the current tenant scope.",
    response_description="The updated notification channel.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
async def update_channel(
    channel_id: str,
    channel: NotificationChannelCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.UPDATE_CHANNELS, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> NotificationChannel:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    validate_channel(channel, notification_service)
    updated_channel = await run_in_threadpool(storage_service.update_notification_channel, channel_id, channel, tenant_id, user_id, group_ids)
    if not updated_channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found or access denied")
    return updated_channel


@router.delete(
    "/channels/{channel_id}",
    summary="Delete Notification Channel",
    description="Deletes an existing notification channel when the caller has access.",
    response_description="The deletion result for the notification channel.",
    responses=NOT_FOUND_ERRORS,
)
@handle_route_errors()
async def delete_channel(
    channel_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_CHANNELS, "alertmanager")),
) -> JSONDict:
    tenant_id, user_id, _ = alertmanager_service.user_scope(current_user)
    if not await run_in_threadpool(storage_service.delete_notification_channel, channel_id, tenant_id, user_id):
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found or access denied")
    return {"status": "success", "message": f"Notification channel {channel_id} deleted"}


@router.post(
    "/channels/{channel_id}/test",
    summary="Test Notification Channel",
    description="Sends a test notification through the specified notification channel.",
    response_description="The test delivery result for the notification channel.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(internal_detail="Failed to send test notification")
async def test_channel(
    channel_id: str,
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.TEST_CHANNELS, Permission.WRITE_CHANNELS], "alertmanager")
    ),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    if not await run_in_threadpool(storage_service.is_notification_channel_owner, channel_id, tenant_id, user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only channel owner can test this channel")

    channel = await run_in_threadpool(storage_service.get_notification_channel, channel_id, tenant_id, user_id, group_ids)
    if not channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found")
    if not bool(getattr(channel, "enabled", False)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Channel is disabled. Enable it before sending a test notification.",
        )

    test_alert = Alert.model_validate({
        "labels": {"alertname": "InvokableTestAlert", "severity": "INFO"},
        "annotations": {
            "summary": "You have invoked a test alert",
            "description": "This is a test notification from Watchdog. Please ignore this alert if you didn't expect it.",
        },
        "startsAt": datetime.now(timezone.utc).isoformat(),
        "endsAt": None,
        "generatorURL": None,
        "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
        "fingerprint": "test",
    })

    if await notification_service.send_notification(channel, test_alert, "test"):
        return {"status": "success", "message": f"Test notification sent to {channel.name}"}
    if channel.type == ChannelType.WEBHOOK:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook test failed. Destination must accept HTTP POST and return a 2xx response.",
        )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Failed to send test notification for {channel.type} channel. Verify configuration and destination availability.",
    )
