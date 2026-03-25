"""
Alerting-related operations for interacting with Alertmanager and Mimir, including fetching metrics, listing alerts and groups, posting new alerts, and deleting alerts via silences.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Dict, List, Optional, Any
from models.alerting.alerts import Alert, AlertGroup
from models.alerting.silences import Matcher, SilenceCreate
import httpx
from config import config

if TYPE_CHECKING:
    from services.alertmanager_service import AlertManagerService

QueryParamValue = str | int | float | bool | None
QueryParamMapping = Mapping[str, QueryParamValue | Sequence[QueryParamValue]]

async def list_metric_names(service: AlertManagerService, org_id: str) -> List[str]:
    response = await service._mimir_client.get(
        f"{config.MIMIR_URL.rstrip('/')}/prometheus/api/v1/label/__name__/values",
        headers={"X-Scope-OrgID": org_id},
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "success":
        raise httpx.HTTPStatusError(
            "Mimir returned non-success status",
            request=response.request,
            response=response,
        )
    metrics = payload.get("data") or []
    return metrics if isinstance(metrics, list) else []


async def list_label_names(service: AlertManagerService, org_id: str) -> List[str]:
    response = await service._mimir_client.get(
        f"{config.MIMIR_URL.rstrip('/')}/prometheus/api/v1/labels",
        headers={"X-Scope-OrgID": org_id},
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "success":
        raise httpx.HTTPStatusError(
            "Mimir returned non-success status",
            request=response.request,
            response=response,
        )
    labels = payload.get("data") or []
    return labels if isinstance(labels, list) else []


async def list_label_values(
    service: AlertManagerService,
    org_id: str,
    label: str,
    metric_name: Optional[str] = None,
) -> List[str]:
    params: Dict[str, str] = {}
    if metric_name:
        metric = str(metric_name).strip()
        if metric:
            params["match[]"] = metric
    response = await service._mimir_client.get(
        f"{config.MIMIR_URL.rstrip('/')}/prometheus/api/v1/label/{label}/values",
        headers={"X-Scope-OrgID": org_id},
        params=params or None,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "success":
        raise httpx.HTTPStatusError(
            "Mimir returned non-success status",
            request=response.request,
            response=response,
        )
    values = payload.get("data") or []
    return values if isinstance(values, list) else []


async def evaluate_promql(
    service: AlertManagerService,
    org_id: str,
    query: str,
    sample_limit: int = 5,
) -> Dict[str, Any]:
    response = await service._mimir_client.get(
        f"{config.MIMIR_URL.rstrip('/')}/prometheus/api/v1/query",
        headers={"X-Scope-OrgID": org_id},
        params={"query": query},
    )

    payload = response.json() if response.content else {}
    if response.status_code >= 400:
        return {
            "valid": False,
            "error": str(payload.get("error") or f"Mimir query failed with status {response.status_code}"),
            "errorType": str(payload.get("errorType") or ""),
            "resultType": None,
            "sampleCount": 0,
            "samples": [],
            "currentValue": None,
        }

    if payload.get("status") != "success":
        return {
            "valid": False,
            "error": str(payload.get("error") or "Mimir returned non-success status"),
            "errorType": str(payload.get("errorType") or ""),
            "resultType": None,
            "sampleCount": 0,
            "samples": [],
            "currentValue": None,
        }

    data = payload.get("data") or {}
    result_type = data.get("resultType")
    result = data.get("result") or []
    capped_limit = max(1, min(int(sample_limit or 5), 20))
    samples: List[Dict[str, Any]] = []
    current_value: Optional[str] = None

    if result_type == "vector" and isinstance(result, list):
        for item in result[:capped_limit]:
            metric = item.get("metric") or {}
            value = item.get("value") or []
            samples.append(
                {
                    "metric": metric if isinstance(metric, dict) else {},
                    "timestamp": value[0] if isinstance(value, list) and len(value) >= 2 else None,
                    "value": value[1] if isinstance(value, list) and len(value) >= 2 else None,
                }
            )
        if samples:
            current_value = str(samples[0].get("value", ""))
    elif result_type in {"scalar", "string"} and isinstance(result, list) and len(result) >= 2:
        current_value = str(result[1])
        samples.append({"metric": {}, "timestamp": result[0], "value": result[1]})

    return {
        "valid": True,
        "error": None,
        "errorType": None,
        "resultType": result_type,
        "sampleCount": len(result) if isinstance(result, list) else 0,
        "samples": samples,
        "currentValue": current_value,
    }


async def get_alerts(
    service: AlertManagerService,
    filter_labels: Optional[Dict[str, str]] = None,
    active: Optional[bool] = None,
    silenced: Optional[bool] = None,
    inhibited: Optional[bool] = None,
) -> List[Alert]:
    params: Dict[str, QueryParamValue | Sequence[QueryParamValue]] = {}

    if filter_labels:
        params["filter"] = [f'{k}="{v}"' for k, v in filter_labels.items()]
    if active is not None:
        params["active"] = str(active).lower()
    if silenced is not None:
        params["silenced"] = str(silenced).lower()
    if inhibited is not None:
        params["inhibited"] = str(inhibited).lower()

    try:
        response = await service._client.get(
            f"{service.alertmanager_url}/api/v2/alerts",
            params=params,
        )
        response.raise_for_status()
        return [Alert(**alert) for alert in response.json()]
    except httpx.HTTPError as exc:
        service.logger.error("Error fetching alerts: %s", exc)
        return []


async def get_alert_groups(service: AlertManagerService, filter_labels: Optional[Dict[str, str]] = None) -> List[AlertGroup]:
    params: Dict[str, QueryParamValue | Sequence[QueryParamValue]] = {}
    if filter_labels:
        params["filter"] = [f'{k}="{v}"' for k, v in filter_labels.items()]

    try:
        response = await service._client.get(
            f"{service.alertmanager_url}/api/v2/alerts/groups",
            params=params,
        )
        response.raise_for_status()
        return [AlertGroup(**group) for group in response.json()]
    except httpx.HTTPError as exc:
        service.logger.error("Error fetching alert groups: %s", exc)
        return []

async def post_alerts(service: AlertManagerService, alerts: List[Alert]) -> bool:
    try:
        response = await service._client.post(
            f"{service.alertmanager_url}/api/v2/alerts",
            json=[alert.model_dump(by_alias=True) for alert in alerts],
        )
        response.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        service.logger.error("Error posting alerts: %s", exc)
        return False


async def delete_alerts(service: AlertManagerService, filter_labels: Optional[Dict[str, str]] = None) -> bool:
    if not filter_labels:
        service.logger.warning("Cannot delete all alerts without filter")
        return False

    matchers = [
        Matcher(name=key, value=value, isRegex=False, isEqual=True)
        for key, value in filter_labels.items()
    ]

    now = datetime.now(timezone.utc)
    end = now + timedelta(seconds=60)
    silence = SilenceCreate(
        matchers=matchers,
        startsAt=now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        endsAt=end.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        createdBy="watchdog",
        comment="Alert deletion via API",
    )

    silence_id = await service.create_silence(silence)
    return silence_id is not None
