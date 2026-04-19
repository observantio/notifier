"""
Shared incident helpers: keys, labels, access checks, and alert-name rule resolution.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from sqlalchemy.orm import Session

from custom_types.json import JSONDict
from db_models import AlertIncident as AlertIncidentDB
from db_models import AlertRule as AlertRuleDB
from services.alerting.suppression import is_suppressed_status
from services.common.access import AccessCheck, has_access
from services.common.meta import parse_meta

logger = logging.getLogger(__name__)


def _json_dict(value: object) -> JSONDict:
    return value if isinstance(value, dict) else {}


def _shared_group_ids(db_obj: object) -> list[str]:
    rule = db_obj if isinstance(db_obj, AlertRuleDB) else None
    return [g.id for g in rule.shared_groups] if rule and rule.shared_groups else []


INCIDENT_META_KEY_IDENTITY = "incident_key"
METRIC_STATES_ANNOTATION_KEY = "watchdogMetricStates"


def incident_scope_hint_from_labels(labels: Mapping[str, object]) -> str:
    for key in ("org_id", "orgId", "tenant", "product"):
        value = str((labels or {}).get(key) or "").strip()
        if value:
            return value
    return ""


def incident_key_from_labels(labels: Mapping[str, object]) -> str | None:
    alert_name = str((labels or {}).get("alertname") or "").strip()
    if not alert_name:
        return None
    scope_hint = incident_scope_hint_from_labels(labels) or "*"
    return f"rule:{alert_name}|scope:{scope_hint}"


def incident_key_from_db_row(incident: AlertIncidentDB) -> str | None:
    annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
    meta = parse_meta(annotations)
    key = str(meta.get(INCIDENT_META_KEY_IDENTITY) or "").strip()
    if key:
        return key

    labels = incident.labels if isinstance(incident.labels, dict) else {}
    fallback_key = incident_key_from_labels(labels)
    if fallback_key:
        return fallback_key

    alert_name = str(getattr(incident, "alert_name", "") or "").strip()
    if not alert_name:
        return None
    return f"rule:{alert_name}|scope:*"


def incident_activity_token_from_row(incident: AlertIncidentDB) -> str:
    key = incident_key_from_db_row(incident)
    if key:
        return f"k:{key}"
    return f"fp:{getattr(incident, 'fingerprint', '') or ''!s}"


def _extract_metric_state(labels: Mapping[str, object]) -> str:
    return str(labels.get("state") or labels.get("metric_state") or labels.get("mem_state") or "").strip()


def _parse_metric_states(value: object) -> list[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for part in raw.split(","):
        state = str(part or "").strip()
        if not state or state in seen:
            continue
        seen.add(state)
        out.append(state)
    return out


def _merge_metric_states(annotations: Mapping[str, object], *states: str) -> str:
    existing_states = _parse_metric_states(
        (annotations or {}).get(METRIC_STATES_ANNOTATION_KEY),
    )
    seen = set(existing_states)
    merged = list(existing_states)
    for state in states:
        normalized = str(state or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    return ",".join(merged)


def _is_alert_suppressed(alert: JSONDict) -> bool:
    return is_suppressed_status(alert.get("status") or {})


def _incident_access_allowed(check: AccessCheck) -> bool:
    if check.visibility == "group":
        return bool(set(check.shared_group_ids) & set(check.user_group_ids))
    return has_access(
        AccessCheck(
            visibility=check.visibility,
            created_by=check.created_by,
            user_id=check.user_id,
            shared_group_ids=check.shared_group_ids,
            user_group_ids=check.user_group_ids,
            require_write=False,
        )
    )


def _resolve_rule_by_alertname(db: Session, tenant_id: str, labels: Mapping[str, object]) -> AlertRuleDB | None:
    alertname = labels.get("alertname")
    if not alertname:
        return None

    org_id_hint = str(
        labels.get("org_id") or labels.get("orgId") or labels.get("tenant") or labels.get("product") or ""
    ).strip()

    try:
        q = db.query(AlertRuleDB).filter(AlertRuleDB.tenant_id == tenant_id, AlertRuleDB.name == alertname)
        if org_id_hint:
            return (
                q.filter((AlertRuleDB.org_id == org_id_hint) | (AlertRuleDB.org_id.is_(None)))
                .order_by(AlertRuleDB.org_id.desc())
                .first()
            )
        return q.first()
    except (TypeError, ValueError) as exc:
        logger.debug("Failed to resolve rule for alertname=%s: %s", alertname, exc)
        return None
