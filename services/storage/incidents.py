"""
Incidents management service for handling alert incidents, including synchronization with incoming alerts, access
control, and integration with Jira for issue tracking.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import HTTPException, status as http_status
from sqlalchemy.orm import joinedload

from config import config as app_config
from custom_types.json import JSONDict
from database import get_db_session
from db_models import AlertIncident as AlertIncidentDB
from db_models import AlertRule as AlertRuleDB
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from services.common.access import has_access
from services.common.meta import INCIDENT_META_KEY, parse_meta, _safe_group_ids
from services.common.pagination import cap_pagination
from services.common.tenants import ensure_tenant_exists
from services.common.visibility import normalize_storage_visibility
from services.storage import incidents_core as _incidents_core
from services.storage.incidents_core import (
    _incident_access_allowed,
    _json_dict,
    _shared_group_ids,
)
from services.storage.incidents_sync import (
    _resolve_incidents_without_active_alerts,
    _sync_single_alert_into_incidents,
)
from services.storage.serializers import incident_to_pydantic

INCIDENT_META_KEY_IDENTITY = _incidents_core.INCIDENT_META_KEY_IDENTITY
METRIC_STATES_ANNOTATION_KEY = _incidents_core.METRIC_STATES_ANNOTATION_KEY
incident_activity_token_from_row = _incidents_core.incident_activity_token_from_row
incident_key_from_db_row = _incidents_core.incident_key_from_db_row
incident_key_from_labels = _incidents_core.incident_key_from_labels
incident_scope_hint_from_labels = _incidents_core.incident_scope_hint_from_labels


class IncidentStorageService:
    def unlink_jira_integration_from_incidents(
        self,
        tenant_id: str,
        integration_id: str,
    ) -> int:
        target_integration_id = str(integration_id or "").strip()
        if not target_integration_id:
            return 0

        updated_count = 0
        with get_db_session() as db:
            incidents = db.query(AlertIncidentDB).filter(AlertIncidentDB.tenant_id == tenant_id).all()
            for incident in incidents:
                annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
                meta = parse_meta(annotations)
                linked_id = str(meta.get("jira_integration_id") or "").strip()
                if linked_id != target_integration_id:
                    continue

                meta.pop("jira_integration_id", None)
                meta.pop("jira_ticket_key", None)
                meta.pop("jira_ticket_url", None)
                incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(meta)}
                updated_count += 1

            if updated_count:
                db.flush()

        return updated_count

    def get_incident_summary(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> JSONDict:
        group_ids = group_ids or []
        open_total = 0
        unassigned_open = 0
        assigned_open = 0
        assigned_to_me_open = 0
        by_visibility: dict[str, int] = {"public": 0, "private": 0, "group": 0}

        with get_db_session() as db:
            incidents = db.query(AlertIncidentDB).filter(AlertIncidentDB.tenant_id == tenant_id).all()

            for incident in incidents:
                meta = parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"

                creator_id = str(meta.get("created_by") or "") or None
                if not _incident_access_allowed(
                    visibility=inc_visibility,
                    creator_id=creator_id,
                    user_id=user_id,
                    shared_group_ids=_safe_group_ids(meta),
                    user_group_ids=group_ids,
                ):
                    continue

                if str(incident.status or "").lower() == "resolved":
                    continue

                open_total += 1
                by_visibility[inc_visibility] += 1

                assignee = str(incident.assignee or "").strip()
                if not assignee:
                    unassigned_open += 1
                else:
                    assigned_open += 1
                    if assignee == str(user_id):
                        assigned_to_me_open += 1

        return {
            "open_total": open_total,
            "unassigned_open": unassigned_open,
            "assigned_open": assigned_open,
            "assigned_to_me_open": assigned_to_me_open,
            "by_visibility": by_visibility,
        }

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: List[JSONDict], resolve_missing: bool = True) -> None:
        now = datetime.now(timezone.utc)
        active_incident_tokens: set[str] = set()

        with get_db_session() as db:
            ensure_tenant_exists(db, tenant_id)
            for alert in alerts or []:
                _sync_single_alert_into_incidents(db, tenant_id, now, alert, active_incident_tokens)
            if resolve_missing:
                _resolve_incidents_without_active_alerts(db, tenant_id, now, active_incident_tokens)

    def list_incidents(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        status: Optional[str] = None,
        visibility: Optional[str] = None,
        group_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[AlertIncident]:
        group_ids = group_ids or []
        capped_limit, capped_offset = cap_pagination(limit, offset)

        with get_db_session() as db:
            q = db.query(AlertIncidentDB).filter(AlertIncidentDB.tenant_id == tenant_id)
            if status:
                q = q.filter(AlertIncidentDB.status == status)

            incidents = q.order_by(AlertIncidentDB.updated_at.desc()).offset(capped_offset).limit(capped_limit).all()

            result: List[AlertIncident] = []
            for incident in incidents:
                meta = parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"

                if incident.status == "resolved" and meta.get("hide_when_resolved") and not status:
                    continue
                if visibility and inc_visibility != visibility:
                    continue

                creator_id = meta.get("created_by")
                shared_group_ids = _safe_group_ids(meta)

                if group_id:
                    if group_id not in group_ids or inc_visibility != "group" or group_id not in shared_group_ids:
                        continue

                if not _incident_access_allowed(
                    visibility=inc_visibility,
                    creator_id=str(creator_id or "") or None,
                    user_id=user_id,
                    shared_group_ids=shared_group_ids,
                    user_group_ids=group_ids,
                ):
                    continue

                result.append(incident_to_pydantic(incident))

            return result

    def get_incident_for_user(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: Optional[str] = None,
        group_ids: Optional[List[str]] = None,
        require_write: bool = False,
    ) -> Optional[AlertIncident]:
        group_ids = group_ids or []
        with get_db_session() as db:
            incident = (
                db.query(AlertIncidentDB)
                .filter(AlertIncidentDB.id == incident_id, AlertIncidentDB.tenant_id == tenant_id)
                .first()
            )
            if not incident:
                return None
            if user_id:
                meta = parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"
                creator_id = str(meta.get("created_by") or "") or None
                if not _incident_access_allowed(
                    visibility=inc_visibility,
                    creator_id=creator_id,
                    user_id=user_id,
                    shared_group_ids=_safe_group_ids(meta),
                    user_group_ids=group_ids,
                    require_write=require_write,
                ):
                    return None
            return incident_to_pydantic(incident)

    def update_incident(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: str,
        payload: AlertIncidentUpdateRequest,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertIncident]:
        user_group_ids = [str(g).strip() for g in (group_ids or []) if str(g).strip()]
        with get_db_session() as db:
            incident = (
                db.query(AlertIncidentDB)
                .filter(AlertIncidentDB.id == incident_id, AlertIncidentDB.tenant_id == tenant_id)
                .first()
            )
            if not incident:
                return None

            previous_status = str(incident.status or "")
            resolved_note_text: Optional[str] = None

            meta = parse_meta(incident.annotations or {})
            visibility = normalize_storage_visibility(str(meta.get("visibility") or "public"))
            creator_id = str(meta.get("created_by") or "") or None
            if not _incident_access_allowed(
                visibility=visibility,
                creator_id=creator_id,
                user_id=user_id,
                shared_group_ids=_safe_group_ids(meta),
                user_group_ids=user_group_ids,
                require_write=True,
            ):
                return None

            fields_set = set(getattr(payload, "model_fields_set", set()) or [])
            if "assignee" in fields_set:
                requested_assignee = str(payload.assignee or "").strip() or None
                if requested_assignee and visibility == "private" and requested_assignee != user_id:
                    raise HTTPException(
                        status_code=http_status.HTTP_403_FORBIDDEN,
                        detail="Private incidents can only be assigned to yourself",
                    )
                incident.assignee = requested_assignee

            manual_manage_flag: Optional[bool] = None
            if payload.status is not None:
                status_value = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
                if status_value.startswith("IncidentStatus."):
                    status_value = status_value.split(".", 1)[1].lower()
                incident.status = status_value
                if incident.status == "resolved":
                    incident.resolved_at = datetime.now(timezone.utc)
                    manual_manage_flag = False
                    if previous_status.lower() != "resolved":
                        actor_name = getattr(payload, "actor_username", None) or user_id
                        resolved_note_text = f"{actor_name} marked this incident as resolved"
                else:
                    incident.resolved_at = None
                    if incident.status == "open":
                        manual_manage_flag = True

            annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
            meta = parse_meta(annotations)
            if not meta.get("created_by"):
                meta["created_by"] = user_id

            if manual_manage_flag is True:
                meta["user_managed"] = True
            elif manual_manage_flag is False:
                meta.pop("user_managed", None)

            hide_flag = getattr(payload, "hide_when_resolved", None)
            if hide_flag is True:
                meta["hide_when_resolved"] = True
            elif hide_flag is False:
                meta.pop("hide_when_resolved", None)

            for meta_key, payload_attr in [
                ("jira_ticket_key", "jira_ticket_key"),
                ("jira_ticket_url", "jira_ticket_url"),
                ("jira_integration_id", "jira_integration_id"),
            ]:
                val = getattr(payload, payload_attr, None)
                if val is not None:
                    stripped = val.strip()
                    if stripped:
                        meta[meta_key] = stripped
                    else:
                        meta.pop(meta_key, None)

            meta["updated_by"] = user_id
            incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(meta)}

            now_iso = datetime.now(timezone.utc).isoformat()
            notes = list(incident.notes or [])
            if payload.note:
                notes.append({"author": user_id, "text": payload.note, "createdAt": now_iso})
            if resolved_note_text:
                notes.append({"author": user_id, "text": resolved_note_text, "createdAt": now_iso})
            if notes != list(incident.notes or []):
                incident.notes = notes

            db.flush()
            return incident_to_pydantic(incident)

    def filter_alerts_for_user(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]],
        alerts: List[JSONDict],
    ) -> List[JSONDict]:
        user_group_ids = [str(g) for g in (group_ids or []) if str(g).strip()]
        if not alerts:
            return []

        with get_db_session() as db:
            visible: List[JSONDict] = []
            for alert in alerts:
                labels = _json_dict(alert.get("labels"))
                alertname = str(labels.get("alertname") or "").strip()
                if not alertname:
                    continue

                org_id_hint = str(
                    labels.get("org_id") or labels.get("orgId") or labels.get("tenant") or labels.get("product") or ""
                ).strip()

                candidates = (
                    db.query(AlertRuleDB)
                    .options(joinedload(AlertRuleDB.shared_groups))
                    .filter(
                        AlertRuleDB.tenant_id == tenant_id,
                        AlertRuleDB.name == alertname,
                        AlertRuleDB.enabled.is_(True),
                    )
                    .limit(int(app_config.max_query_limit))
                    .all()
                )
                if not candidates:
                    continue

                if org_id_hint:
                    org_matched = [r for r in candidates if str(r.org_id or "") == org_id_hint]
                    candidates = org_matched or [r for r in candidates if not r.org_id] or candidates

                if any(
                    has_access(
                        normalize_storage_visibility(getattr(r, "visibility", None)),
                        getattr(r, "created_by", None),
                        user_id,
                        _shared_group_ids(r),
                        user_group_ids,
                    )
                    for r in candidates
                ):
                    visible.append(alert)

            return visible
