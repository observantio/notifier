"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import cast

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from custom_types.json import JSONDict
from middleware.dependencies import require_any_permission_with_scope, require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS
from models.access.auth_models import Permission, TokenData
from models.alerting.alerts import Alert, AlertGroup
from services.alerting.alerts_ops import AlertQuery

from .shared import INVALID_FILTER_LABELS_JSON, alertmanager_service, storage_service, sync_incidents

router = APIRouter(tags=["alertmanager"])


class AlertListQuery(BaseModel):
    active: bool | None = Field(default=None)
    silenced: bool | None = Field(default=None)
    inhibited: bool | None = Field(default=None)
    filter_labels: str | None = Field(default=None)
    show_hidden: bool = Field(default=False)


def _json_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


@router.get(
    "/alerts",
    response_model=list[Alert],
    summary="List Alerts",
    description="Lists alertmanager alerts with optional state and label filtering for the current user scope.",
    response_description="The alerts visible to the current caller.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def list_alerts(
    query: AlertListQuery = Depends(),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> list[Alert]:
    labels = alertmanager_service.parse_filter_labels(query.filter_labels)
    alerts = await alertmanager_service.get_alerts(
        AlertQuery(
            filter_labels=labels or {},
            active=query.active,
            silenced=query.silenced,
            inhibited=query.inhibited,
        )
    )
    alert_dicts = [alert.model_dump(by_alias=True) for alert in alerts]
    await sync_incidents(current_user.tenant_id, alert_dicts, log_context="get_alerts")

    filtered = await run_in_threadpool(
        storage_service.filter_alerts_for_user,
        current_user.tenant_id,
        current_user.user_id,
        getattr(current_user, "group_ids", []) or [],
        alert_dicts,
    )
    if not query.show_hidden:
        hidden_rule_names = set(
            await run_in_threadpool(
                storage_service.get_hidden_rule_names,
                current_user.tenant_id,
                current_user.user_id,
            )
        )
        if hidden_rule_names:
            filtered = [
                alert
                for alert in filtered
                if str(
                    (_json_dict(alert).get("labels") and _json_dict(_json_dict(alert).get("labels")).get("alertname"))
                    or ""
                )
                not in hidden_rule_names
            ]
    return [Alert.model_validate(_json_dict(item)) for item in filtered]


@router.get(
    "/alerts/groups",
    response_model=list[AlertGroup],
    summary="List Alert Groups",
    description="Lists grouped alerts from alertmanager with optional label filtering.",
    response_description="Grouped alerts returned by alertmanager.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def list_alert_groups(
    filter_labels: str | None = Query(None),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> list[AlertGroup]:
    _ = current_user
    return cast(
        list[AlertGroup],
        await alertmanager_service.get_alert_groups(
            filter_labels=alertmanager_service.parse_filter_labels(filter_labels)
        ),
    )


@router.post(
    "/alerts",
    summary="Create Alerts",
    description="Submits one or more alerts to alertmanager for processing.",
    response_description="The submission result including the number of alerts accepted.",
    responses=BAD_REQUEST_ERRORS,
)
async def create_alerts(
    alerts: list[Alert] = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_ALERTS, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> JSONDict:
    _ = current_user
    if not await alertmanager_service.post_alerts(alerts):
        raise HTTPException(status_code=500, detail="Failed to post alerts")
    return {"status": "success", "count": len(alerts)}


@router.delete(
    "/alerts",
    summary="Delete Alerts",
    description="Deletes alerts in alertmanager that match the provided label filter set.",
    response_description="The deletion result for the matched alerts.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def delete_alerts(
    filter_labels: str = Query(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_ALERTS, "alertmanager")),
) -> JSONDict:
    _ = current_user
    labels = alertmanager_service.parse_filter_labels(filter_labels)
    if not labels:
        raise HTTPException(status_code=400, detail="filter_labels cannot be empty")
    if not await alertmanager_service.delete_alerts(filter_labels=labels):
        raise HTTPException(status_code=500, detail="Failed to delete alerts")
    return {"status": "success", "message": "Alerts silenced"}
