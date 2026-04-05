"""
Jira side effects for incident lifecycle (async bridge and credential resolution).

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from datetime import datetime, timezone
from typing import Optional

from custom_types.json import JSONDict
from db_models import AlertIncident as AlertIncidentDB
from services.alerting.integration_security_service import (
    get_effective_jira_credentials,
    integration_is_usable,
    jira_integration_credentials,
    load_tenant_jira_integrations,
)
from services.common.meta import parse_meta
from services.jira_service import JiraError, jira_service

logger = logging.getLogger(__name__)


def _run_async(coro: Coroutine[object, object, object]) -> None:
    try:
        asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro)
        finally:
            loop.close()


def _resolve_incident_jira_credentials(tenant_id: str, integration_id: Optional[str]) -> Optional[JSONDict]:
    integration_id = str(integration_id or "").strip()
    if integration_id:
        for item in load_tenant_jira_integrations(tenant_id):
            if str(item.get("id") or "").strip() != integration_id:
                continue
            if not integration_is_usable(item):
                return None
            return {str(key): value for key, value in jira_integration_credentials(item).items()}
    tenant_credentials = get_effective_jira_credentials(tenant_id)
    if tenant_credentials.get("base_url"):
        return {str(key): value for key, value in tenant_credentials.items()}
    return None


def _move_reopened_incident_jira_ticket_to_todo(tenant_id: str, incident: AlertIncidentDB) -> None:
    annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
    meta = parse_meta(annotations)
    issue_key = str(meta.get("jira_ticket_key") or "").strip()
    if not issue_key:
        return
    integration_id = str(meta.get("jira_integration_id") or "").strip() or None
    credentials = _resolve_incident_jira_credentials(tenant_id, integration_id)
    if not credentials:
        return
    try:
        _run_async(jira_service.transition_issue_to_todo(issue_key=issue_key, credentials=credentials))
    except JiraError as exc:
        logger.warning("Failed moving Jira issue %s to To Do for refired incident: %s", issue_key, exc)


def _sync_reopened_incident_note_to_jira(
    tenant_id: str,
    incident: AlertIncidentDB,
    *,
    note_text: str,
    created_at: datetime,
) -> None:
    annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
    meta = parse_meta(annotations)
    issue_key = str(meta.get("jira_ticket_key") or "").strip()
    if not issue_key:
        return
    integration_id = str(meta.get("jira_integration_id") or "").strip() or None
    credentials = _resolve_incident_jira_credentials(tenant_id, integration_id)
    if not credentials:
        return
    when_label = created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = f"System · {when_label}\n{note_text}"
    try:
        _run_async(jira_service.add_comment(issue_key=issue_key, text=body, credentials=credentials))
    except JiraError as exc:
        logger.warning("Failed syncing refire note to Jira issue %s: %s", issue_key, exc)
