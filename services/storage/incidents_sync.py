"""
Alert-to-incident synchronization and deduplication.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from custom_types.json import JSONDict
from db_models import AlertIncident as AlertIncidentDB
from db_models import AlertRule as AlertRuleDB
from services.common.meta import INCIDENT_META_KEY, parse_meta
from services.storage.incidents_core import (
    INCIDENT_META_KEY_IDENTITY,
    METRIC_STATES_ANNOTATION_KEY,
    incident_activity_token_from_row,
    incident_key_from_db_row,
    incident_key_from_labels,
    _extract_metric_state,
    _is_alert_suppressed,
    _json_dict,
    _merge_metric_states,
    _resolve_rule_by_alertname,
    _shared_group_ids,
)
from services.storage.incidents_jira import (
    _move_reopened_incident_jira_ticket_to_todo,
    _sync_reopened_incident_note_to_jira,
)

logger = logging.getLogger(__name__)


def _derive_fingerprint(alert_data: JSONDict, labels: JSONDict, annotations: JSONDict) -> str:
    fp = alert_data.get("fingerprint") or labels.get("fingerprint")
    if fp:
        return str(fp)
    stable_blob = json.dumps(
        {
            "alertname": labels.get("alertname") or "",
            "severity": labels.get("severity") or "",
            "labels": labels,
            "annotations": annotations,
        },
        sort_keys=True,
        default=str,
    )
    return f"derived-{hashlib.sha256(stable_blob.encode()).hexdigest()}"


def _parse_starts_at_from_alert(alert_data: JSONDict) -> Optional[datetime]:
    starts_at_value = alert_data.get("startsAt") or alert_data.get("starts_at")
    starts_at = starts_at_value if isinstance(starts_at_value, str) else None
    if not starts_at:
        return None
    try:
        return datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
    except ValueError:
        return None


def _duplicate_state_label(labels_obj: object) -> str:
    if not isinstance(labels_obj, dict):
        return ""
    return str(
        labels_obj.get("state") or labels_obj.get("metric_state") or labels_obj.get("mem_state") or ""
    ).strip()


def _resolve_duplicate_incidents_for_key(
    *,
    tenant_id: str,
    incident_key: str,
    matching_candidates: list[AlertIncidentDB],
    now: datetime,
) -> AlertIncidentDB:
    canonical = matching_candidates[0]
    if len(matching_candidates) == 1:
        return canonical
    duplicate_ids = [str(item.id) for item in matching_candidates[1:]]
    logger.info(
        "Deduplicating incidents for key=%s tenant=%s keeping=%s duplicates=%s",
        incident_key,
        tenant_id,
        canonical.id,
        duplicate_ids,
    )
    for duplicate in matching_candidates[1:]:
        state_text = _duplicate_state_label(getattr(duplicate, "labels", None)) or "unknown"
        dedupe_note = (
            f"System deduplicated this incident into #{canonical.id} "
            f"(correlation scope: {incident_key}; metric state: {state_text})"
        )
        if str(duplicate.status or "").lower() != "resolved":
            duplicate.status = "resolved"
            duplicate.resolved_at = now
        dup_notes = list(duplicate.notes or [])
        dup_notes.append(
            {
                "author": "system",
                "text": dedupe_note,
                "createdAt": now.isoformat(),
            }
        )
        duplicate.notes = dup_notes
    merged_states = _merge_metric_states(
        canonical.annotations if isinstance(canonical.annotations, dict) else {},
        *[
            _extract_metric_state(item.labels if isinstance(item.labels, dict) else {})
            for item in matching_candidates
        ],
    )
    canonical_annotations = canonical.annotations if isinstance(canonical.annotations, dict) else {}
    canonical.annotations = {**canonical_annotations, METRIC_STATES_ANNOTATION_KEY: merged_states}
    return canonical


def _find_incident_by_key_or_fingerprint(
    db: Session,
    tenant_id: str,
    *,
    incident_key: Optional[str],
    fingerprint: str,
    labels: JSONDict,
    now: datetime,
) -> Optional[AlertIncidentDB]:
    if incident_key:
        alert_name = str(labels.get("alertname") or "").strip()
        candidates = (
            db.query(AlertIncidentDB)
            .filter(
                AlertIncidentDB.tenant_id == tenant_id,
                AlertIncidentDB.alert_name == alert_name,
            )
            .order_by(AlertIncidentDB.updated_at.desc())
            .all()
        )
        matching = [item for item in candidates if incident_key_from_db_row(item) == incident_key]
        if matching:
            return _resolve_duplicate_incidents_for_key(
                tenant_id=tenant_id,
                incident_key=incident_key,
                matching_candidates=matching,
                now=now,
            )
    return (
        db.query(AlertIncidentDB)
        .filter(AlertIncidentDB.tenant_id == tenant_id, AlertIncidentDB.fingerprint == fingerprint)
        .first()
    )


def _incident_row_for_new_alert(
    *,
    tenant_id: str,
    fingerprint: str,
    labels: JSONDict,
    annotations: JSONDict,
    metric_state: str,
    incident_key: Optional[str],
    parsed_starts: Optional[datetime],
    now: datetime,
    rule: Optional[AlertRuleDB],
) -> AlertIncidentDB:
    metadata = {
        "visibility": (rule.visibility or "public") if rule else "public",
        "shared_group_ids": _shared_group_ids(rule) if rule else [],
        "created_by": rule.created_by if rule else None,
        "correlation_id": str(getattr(rule, "group", "") or "").strip() if rule else "",
        INCIDENT_META_KEY_IDENTITY: incident_key,
    }
    merged_states = _merge_metric_states(annotations, metric_state)
    return AlertIncidentDB(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        fingerprint=fingerprint,
        alert_name=str(labels.get("alertname") or "Unnamed alert"),
        severity=str(labels.get("severity") or "warning"),
        status="open",
        labels=labels,
        starts_at=parsed_starts,
        last_seen_at=now,
        resolved_at=None,
        notes=[],
        annotations={
            **annotations,
            METRIC_STATES_ANNOTATION_KEY: merged_states,
            INCIDENT_META_KEY: json.dumps(metadata),
        },
    )


def _apply_open_incident_update_from_alert(
    *,
    tenant_id: str,
    incident: AlertIncidentDB,
    labels: JSONDict,
    annotations: JSONDict,
    metric_state: str,
    incident_key: Optional[str],
    parsed_starts: Optional[datetime],
    now: datetime,
    rule: Optional[AlertRuleDB],
) -> None:
    existing_meta = parse_meta(incident.annotations or {})
    previous_status = str(incident.status or "")

    incident.alert_name = str(labels.get("alertname") or incident.alert_name)
    incident.severity = str(labels.get("severity") or incident.severity)
    incident.labels = labels

    if previous_status == "resolved" or incident.resolved_at is not None:
        incident.assignee = None
        existing_meta.pop("user_managed", None)

    if rule:
        existing_meta["visibility"] = rule.visibility or existing_meta.get("visibility", "public")
        existing_meta["shared_group_ids"] = _shared_group_ids(rule)
        existing_meta["correlation_id"] = str(getattr(rule, "group", "") or "").strip()
        if rule.created_by:
            existing_meta["created_by"] = rule.created_by
    if incident_key:
        existing_meta[INCIDENT_META_KEY_IDENTITY] = incident_key
    if not str(existing_meta.get("correlation_id") or "").strip() and incident_key:
        existing_meta["correlation_id"] = incident_key

    merged_states = _merge_metric_states(
        incident.annotations if isinstance(incident.annotations, dict) else {},
        metric_state,
    )
    incident.annotations = {
        **annotations,
        METRIC_STATES_ANNOTATION_KEY: merged_states,
        INCIDENT_META_KEY: json.dumps(existing_meta),
    }
    if parsed_starts and not incident.starts_at:
        incident.starts_at = parsed_starts
    incident.status = "open"
    incident.last_seen_at = now
    incident.resolved_at = None

    if previous_status.lower() == "resolved":
        reopen_note = "System reopened this incident because the alert fired again"
        reopen_notes = list(incident.notes or [])
        reopen_notes.append(
            {
                "author": "system",
                "text": reopen_note,
                "createdAt": now.isoformat(),
            }
        )
        incident.notes = reopen_notes
        _move_reopened_incident_jira_ticket_to_todo(tenant_id, incident)
        _sync_reopened_incident_note_to_jira(
            tenant_id,
            incident,
            note_text=reopen_note,
            created_at=now,
        )


def _sync_single_alert_into_incidents(
    db: Session,
    tenant_id: str,
    now: datetime,
    alert: object,
    active_incident_tokens: set[str],
) -> None:
    alert_data = _json_dict(alert)
    if _is_alert_suppressed(alert_data):
        return
    labels = _json_dict(alert_data.get("labels", {}))
    annotations = _json_dict(alert_data.get("annotations", {}))
    metric_state = _extract_metric_state(labels)
    incident_key = incident_key_from_labels(labels)
    fingerprint = _derive_fingerprint(alert_data, labels, annotations)
    active_incident_tokens.add(f"k:{incident_key}" if incident_key else f"fp:{fingerprint}")
    incident = _find_incident_by_key_or_fingerprint(
        db,
        tenant_id,
        incident_key=incident_key,
        fingerprint=fingerprint,
        labels=labels,
        now=now,
    )
    parsed_starts = _parse_starts_at_from_alert(alert_data)
    rule = _resolve_rule_by_alertname(db, tenant_id, labels)
    if not incident:
        db.add(
            _incident_row_for_new_alert(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                labels=labels,
                annotations=annotations,
                metric_state=metric_state,
                incident_key=incident_key,
                parsed_starts=parsed_starts,
                now=now,
                rule=rule,
            )
        )
        return
    _apply_open_incident_update_from_alert(
        tenant_id=tenant_id,
        incident=incident,
        labels=labels,
        annotations=annotations,
        metric_state=metric_state,
        incident_key=incident_key,
        parsed_starts=parsed_starts,
        now=now,
        rule=rule,
    )


def _resolve_incidents_without_active_alerts(
    db: Session,
    tenant_id: str,
    now: datetime,
    active_incident_tokens: set[str],
) -> None:
    open_incidents = db.query(AlertIncidentDB).filter(
        AlertIncidentDB.tenant_id == tenant_id,
        AlertIncidentDB.status == "open",
    )
    for incident in open_incidents.all():
        if parse_meta(incident.annotations or {}).get("user_managed"):
            continue
        if incident_activity_token_from_row(incident) not in active_incident_tokens:
            incident.status = "resolved"
            incident.resolved_at = now
