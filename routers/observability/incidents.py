"""
Incident management API endpoints for querying and updating alert incidents, including status updates, assignee changes,
and integration with AlertManager for active alert checks.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from dataclasses import dataclass
from email.utils import parseaddr
from typing import cast

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import SQLAlchemyError

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS, BAD_REQUEST_NOT_FOUND_ERRORS, COMMON_ERRORS
from models.access.auth_models import Permission, TokenData
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from services.alerting.alerts_ops import AlertQuery
from services.alertmanager_service import AlertManagerService
from services.incidents.helpers import (
    move_incident_ticket_to_done,
    move_incident_ticket_to_in_progress,
    move_incident_ticket_to_todo,
    sync_note_to_jira_comment,
)
from services.notification_service import IncidentAssignmentEmail, NotificationService
from services.storage.incidents import incident_key_from_labels
from services.storage.incidents import IncidentActorContext
from services.storage.incidents import IncidentAccessContext
from services.storage_db_service import DatabaseStorageService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alertmanager", tags=["alertmanager-incidents"])

alertmanager_service = AlertManagerService()
storage_service = DatabaseStorageService()
notification_service = NotificationService()


@dataclass(frozen=True)
class IncidentListQuery:
    status: str | None = Query(None)
    visibility: str | None = Query(None)
    group_id: str | None = Query(None)
    limit: int = Query(100, ge=1, le=500)
    offset: int = Query(0, ge=0)


def _recipient_email(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    parsed = parseaddr(text)[1].strip()
    return parsed if "@" in parsed else None


def _status_value(value: object) -> str:
    status_value = value.value if hasattr(value, "value") else str(value)
    return status_value.lower()


async def _send_incident_assignment_email_task(
    payload: IncidentAssignmentEmail,
) -> bool:
    return await notification_service.send_incident_assignment_email(
        payload
    )


async def _ensure_resolve_allowed(payload: AlertIncidentUpdateRequest, existing: AlertIncident) -> None:
    if payload.status is None or _status_value(payload.status) != "resolved":
        return

    existing_incident_key = incident_key_from_labels(existing.labels or {})
    try:
        if existing_incident_key:
            active_alerts = [
                alert
                for alert in (await alertmanager_service.get_alerts(AlertQuery(active=True)))
                if incident_key_from_labels(getattr(alert, "labels", {}) or {}) == existing_incident_key
            ]
        else:
            active_alerts = await alertmanager_service.get_alerts(
                AlertQuery(
                    filter_labels={"fingerprint": existing.fingerprint},
                    active=True,
                )
            )
    except httpx.HTTPError:
        active_alerts = []
    if active_alerts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot mark resolved: underlying alert is still active",
        )


async def _record_assignment_change(
    updated: AlertIncident,
    existing: AlertIncident,
    current_user: TokenData,
    background_tasks: BackgroundTasks,
) -> None:
    previous_assignee = str(getattr(existing, "assignee", "") or "").strip()
    next_assignee = str(getattr(updated, "assignee", "") or "").strip()
    if previous_assignee == next_assignee:
        return

    actor_label = current_user.username or current_user.user_id
    assignment_note = (
        f"{actor_label} assigned incident to {next_assignee}"
        if next_assignee
        else f"{actor_label} unassigned this incident"
    )
    group_ids = getattr(current_user, "group_ids", []) or []
    incident_id = str(updated.id)
    try:
        await run_in_threadpool(
            storage_service.update_incident,
            incident_id,
            current_user.tenant_id,
            AlertIncidentUpdateRequest.model_validate({"note": assignment_note}),
            actor=IncidentActorContext(
                user_id=current_user.user_id,
                group_ids=group_ids,
            ),
        )
    except SQLAlchemyError:
        logger.exception("Failed to record assignment note for incident %s", incident_id)

    await sync_note_to_jira_comment(
        updated,
        tenant_id=current_user.tenant_id,
        current_user=current_user,
        note_text=assignment_note,
    )
    if not next_assignee:
        return

    await move_incident_ticket_to_in_progress(
        updated,
        tenant_id=current_user.tenant_id,
        current_user=current_user,
    )
    recipient_email = _recipient_email(next_assignee)
    if recipient_email:
        background_tasks.add_task(
            _send_incident_assignment_email_task,
            IncidentAssignmentEmail(
                recipient_email=recipient_email,
                incident_title=updated.alert_name,
                incident_status=updated.status,
                incident_severity=updated.severity,
                actor=actor_label,
            ),
        )
        return
    logger.warning(
        "Skipping assignment email for incident=%s because assignee is not an email address: %s",
        incident_id,
        next_assignee,
    )


async def _sync_status_side_effects(
    payload: AlertIncidentUpdateRequest,
    existing: AlertIncident,
    updated: AlertIncident,
    current_user: TokenData,
) -> None:
    if payload.note:
        await sync_note_to_jira_comment(
            updated,
            tenant_id=current_user.tenant_id,
            current_user=current_user,
            note_text=payload.note,
        )

    previous_status = str(existing.status or "").lower()
    updated_status = str(updated.status or "").lower()
    actor_label = current_user.username or current_user.user_id
    if previous_status != updated_status:
        status_note = None
        if updated_status == "resolved":
            status_note = f"{actor_label} marked this incident as resolved"
        elif updated_status == "open":
            status_note = f"{actor_label} reopened this incident"
        if status_note:
            await sync_note_to_jira_comment(
                updated,
                tenant_id=current_user.tenant_id,
                current_user=current_user,
                note_text=status_note,
            )
    if updated_status == "resolved":
        await move_incident_ticket_to_done(
            updated,
            tenant_id=current_user.tenant_id,
            current_user=current_user,
        )
    if previous_status == "resolved" and updated_status == "open":
        await move_incident_ticket_to_todo(
            updated,
            tenant_id=current_user.tenant_id,
            current_user=current_user,
        )


@router.get(
    "/incidents",
    response_model=list[AlertIncident],
    summary="List Incidents",
    description=(
        "Lists alert incidents visible to the current user with optional status, visibility, and group filters."
    ),
    response_description="The incidents visible to the current caller.",
    responses=BAD_REQUEST_ERRORS,
)
async def list_incidents(
    query: IncidentListQuery = Depends(),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
) -> list[AlertIncident]:
    return await run_in_threadpool(
        storage_service.list_incidents,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        group_ids=getattr(current_user, "group_ids", []) or [],
        status=query.status,
        visibility=query.visibility,
        group_id=query.group_id,
        limit=query.limit,
        offset=query.offset,
    )


@router.get(
    "/incidents/summary",
    summary="Get Incident Summary",
    description="Returns an aggregated summary of incidents visible to the current user.",
    response_description="Aggregated incident summary counts and breakdowns.",
    responses=COMMON_ERRORS,
)
async def get_incident_summary(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
) -> JSONDict:
    return await run_in_threadpool(
        storage_service.get_incident_summary,
        current_user.tenant_id,
        current_user.user_id,
        getattr(current_user, "group_ids", []) or [],
        getattr(current_user, "email", None),
    )


@router.patch(
    "/incidents/{incident_id}",
    response_model=AlertIncident,
    summary="Update Incident",
    description="Updates an incident's status, assignment, Jira metadata, or visibility settings.",
    response_description="The updated incident.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors()
async def update_incident(
    incident_id: str,
    payload: AlertIncidentUpdateRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> AlertIncident:
    group_ids = getattr(current_user, "group_ids", []) or []
    existing = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        IncidentAccessContext(
            user_id=current_user.user_id,
            group_ids=group_ids,
            require_write=True,
        ),
    )
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    await _ensure_resolve_allowed(payload, existing)

    enriched_payload = payload.model_copy(update={"actorUsername": current_user.username or current_user.user_id})

    updated = await run_in_threadpool(
        storage_service.update_incident,
        incident_id,
        current_user.tenant_id,
        enriched_payload,
        actor=IncidentActorContext(
            user_id=current_user.user_id,
            group_ids=group_ids,
            user_email=getattr(current_user, "email", None),
        ),
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    await _record_assignment_change(updated, existing, current_user, background_tasks)
    await _sync_status_side_effects(payload, existing, updated, current_user)

    return cast(AlertIncident, updated)
