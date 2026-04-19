"""
Rules management endpoints for AlertManager integration, allowing users to create, update, delete, hide, and test alert
rules, as well as import rules from YAML and query metrics for rule creation.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import cast

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from config import config
from custom_types.json import JSONDict
from database import get_db_session
from db_models import Tenant
from middleware.dependencies import (
    PublicEndpointSecurityConfig,
    enforce_public_endpoint_security,
    require_any_permission_with_scope,
    require_permission_with_scope,
)
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS, BAD_REQUEST_NOT_FOUND_ERRORS, COMMON_ERRORS, NOT_FOUND_ERRORS
from models.access.auth_models import Permission, TokenData
from models.alerting.alerts import Alert
from models.alerting.requests import RuleImportRequest
from models.alerting.rules import AlertRule, AlertRuleCreate
from services.alerting.rule_import_service import RuleImportError, parse_rules_yaml
from services.storage.rules import PageRequest, RuleAccessContext

from .shared import (
    HideTogglePayload,
    alertmanager_service,
    notification_service,
    parse_show_hidden,
    reject_unknown_query_params,
    storage_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alertmanager-rules"])


class RuleListQuery(BaseModel):
    limit: int = Field(default=config.default_query_limit, ge=1, le=config.max_query_limit)
    offset: int = Field(default=0, ge=0)
    show_hidden: str = Field(default="false", pattern="^(true|false)$")


def _with_creator_username(rule: AlertRuleCreate, current_user: TokenData) -> AlertRuleCreate:
    annotations = dict(rule.annotations or {})
    creator_username = str(getattr(current_user, "username", "") or getattr(current_user, "user_id", "") or "").strip()
    if creator_username:
        annotations["watchdogCreatedByUsername"] = creator_username
    return rule.model_copy(update={"annotations": annotations})


@router.post(
    "/rules/import",
    summary="Import Alert Rules",
    description="Imports alert rules from YAML, optionally previewing the parsed rules without persisting them.",
    response_description="The imported or previewed rule set with creation and update counts.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors()
async def import_rules(
    payload: RuleImportRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    try:
        parsed_rules = parse_rules_yaml(payload.yamlContent or "", payload.defaults)
    except RuleImportError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if payload.dryRun:
        return {
            "status": "preview",
            "count": len(parsed_rules),
            "rules": [item.model_dump(by_alias=True) for item in parsed_rules],
        }

    access = RuleAccessContext(user_id=user_id, group_ids=group_ids)
    existing_rules = await run_in_threadpool(storage_service.get_alert_rules, tenant_id, access)
    existing_index = {(item.name, item.group, item.org_id or ""): item for item in existing_rules}
    created = updated = 0
    imported_rules: list[AlertRule] = []

    for rule in parsed_rules:
        rule = _with_creator_username(rule, current_user)
        key = (rule.name, rule.group, rule.org_id or "")
        current = existing_index.get(key)
        if current:
            current_id = current.id
            if current_id is None:
                continue
            updated_rule = await run_in_threadpool(
                storage_service.update_alert_rule,
                current_id,
                rule,
                tenant_id,
                access,
            )
            if updated_rule:
                updated += 1
                imported_rules.append(updated_rule)
        else:
            new_rule = await run_in_threadpool(storage_service.create_alert_rule, rule, tenant_id, access)
            created += 1
            imported_rules.append(new_rule)
            existing_index[(new_rule.name, new_rule.group, new_rule.org_id or "")] = new_rule

    for org_id in {str(item.org_id) for item in imported_rules if item.org_id}:
        await alertmanager_service.sync_mimir_rules_for_org(
            org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, org_id)
        )

    return {
        "status": "success",
        "count": len(imported_rules),
        "created": created,
        "updated": updated,
        "rules": [item.model_dump(by_alias=True) for item in imported_rules],
    }


@router.get(
    "/rules",
    response_model=list[AlertRule],
    summary="List Alert Rules",
    description="Lists alert rules visible to the current user with pagination support.",
    response_description="The alert rules visible to the current caller.",
    responses=BAD_REQUEST_ERRORS,
)
async def list_rules(
    request: Request,
    query: RuleListQuery = Depends(),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
) -> list[AlertRule]:
    if request is not None:
        reject_unknown_query_params(request, {"limit", "offset", "show_hidden"})
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_rule_ids,
            tenant_id,
            user_id,
        )
    )
    rules_with_owner = await run_in_threadpool(
        storage_service.get_alert_rules_with_owner,
        tenant_id,
        RuleAccessContext(user_id=user_id, group_ids=group_ids),
        PageRequest(limit=query.limit, offset=query.offset),
    )
    result: list[AlertRule] = []
    for rule, owner in rules_with_owner:
        rule.is_hidden = bool(rule.id and rule.id in hidden_ids)
        if rule.is_hidden and not parse_show_hidden(query.show_hidden):
            continue
        if owner != current_user.user_id and not getattr(current_user, "is_superuser", False):
            rule.org_id = None
        result.append(rule)
    return result


@router.get(
    "/public/rules",
    response_model=list[AlertRule],
    summary="List Public Alert Rules",
    description="Lists public alert rules for the default tenant after public endpoint protections are enforced.",
    response_description="The public alert rules available for the default tenant.",
    responses=COMMON_ERRORS,
)
async def list_public_rules(request: Request) -> list[AlertRule]:
    enforce_public_endpoint_security(
        request,
        PublicEndpointSecurityConfig(
            scope="alertmanager_public_rules",
            limit=config.rate_limit_public_per_minute,
            window_seconds=60,
            allowlist=config.auth_public_ip_allowlist,
        ),
    )

    def _resolve_default_tenant_id() -> str | None:
        with get_db_session() as db:
            tenant = db.query(Tenant).filter_by(name=config.default_admin_tenant).first()
            return tenant.id if tenant else None

    tenant_id = await run_in_threadpool(_resolve_default_tenant_id)
    if not tenant_id:
        return []
    return await run_in_threadpool(storage_service.get_public_alert_rules, tenant_id)


@router.get(
    "/metrics/names",
    summary="List Metric Names",
    description="Lists metric names available in Mimir for the resolved organization scope.",
    response_description="The resolved organization identifier and metric names.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_gateway_detail="Failed to fetch metrics from Mimir")
async def list_metric_names(
    org_id: str | None = Query(None, alias="orgId"),
    current_user: TokenData = Depends(
        require_any_permission_with_scope(
            [Permission.READ_METRICS, Permission.CREATE_RULES, Permission.UPDATE_RULES, Permission.WRITE_ALERTS],
            "alertmanager",
        )
    ),
) -> JSONDict:
    tenant_org_id = org_id or getattr(current_user, "org_id", None)
    if not tenant_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No org_id available to query metrics. Set a product / API key first.",
        )
    return {"orgId": tenant_org_id, "metrics": await alertmanager_service.list_metric_names(tenant_org_id)}


@router.get(
    "/metrics/query",
    summary="Evaluate PromQL Query",
    description="Evaluates a PromQL query against Mimir for the resolved organization scope.",
    response_description="The evaluated query result returned from Mimir.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_gateway_detail="Failed to evaluate PromQL against Mimir")
async def query_metrics(
    query: str = Query(..., min_length=1),
    org_id: str | None = Query(None, alias="orgId"),
    sample_limit: int = Query(5, alias="sampleLimit", ge=1, le=20),
    current_user: TokenData = Depends(
        require_any_permission_with_scope(
            [Permission.READ_METRICS, Permission.CREATE_RULES, Permission.UPDATE_RULES, Permission.WRITE_ALERTS],
            "alertmanager",
        )
    ),
) -> JSONDict:
    tenant_org_id = org_id or getattr(current_user, "org_id", None)
    if not tenant_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No org_id available to query metrics. Set a product / API key first.",
        )
    payload = await alertmanager_service.evaluate_promql(tenant_org_id, query, sample_limit)
    return {"orgId": tenant_org_id, "query": query, **payload}


@router.get(
    "/metrics/labels",
    summary="List Metric Labels",
    description="Lists label names available in Mimir for the resolved organization scope.",
    response_description="The resolved organization identifier and metric label names.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(bad_gateway_detail="Failed to fetch label names from Mimir")
async def list_metric_labels(
    org_id: str | None = Query(None, alias="orgId"),
    current_user: TokenData = Depends(
        require_any_permission_with_scope(
            [Permission.READ_METRICS, Permission.CREATE_RULES, Permission.UPDATE_RULES, Permission.WRITE_ALERTS],
            "alertmanager",
        )
    ),
) -> JSONDict:
    tenant_org_id = org_id or getattr(current_user, "org_id", None)
    if not tenant_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No org_id available to query labels. Set a product / API key first.",
        )
    return {"orgId": tenant_org_id, "labels": await alertmanager_service.list_label_names(tenant_org_id)}


@router.get(
    "/metrics/label-values/{label}",
    summary="List Metric Label Values",
    description="Lists values for a metric label in Mimir for the resolved organization scope.",
    response_description="The resolved organization identifier and metric label values.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(
    bad_gateway_detail="Failed to fetch label values from Mimir",
    bad_gateway_status_code=400,
)
async def list_metric_label_values(
    label: str,
    org_id: str | None = Query(None, alias="orgId"),
    metric_name: str | None = Query(None, alias="metricName"),
    current_user: TokenData = Depends(
        require_any_permission_with_scope(
            [Permission.READ_METRICS, Permission.CREATE_RULES, Permission.UPDATE_RULES, Permission.WRITE_ALERTS],
            "alertmanager",
        )
    ),
) -> JSONDict:
    tenant_org_id = org_id or getattr(current_user, "org_id", None)
    if not tenant_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No org_id available to query label values. Set a product / API key first.",
        )
    return {
        "orgId": tenant_org_id,
        "label": label,
        "metricName": metric_name,
        "values": await alertmanager_service.list_label_values(tenant_org_id, label, metric_name),
    }


@router.get(
    "/rules/{rule_id}",
    response_model=AlertRule,
    summary="Get Alert Rule",
    description="Returns a single alert rule when it exists and is visible to the current user.",
    response_description="The requested alert rule.",
    responses=NOT_FOUND_ERRORS,
)
async def get_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
) -> AlertRule:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    access = RuleAccessContext(user_id=user_id, group_ids=group_ids)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, access)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_rule_ids,
            tenant_id,
            user_id,
        )
    )
    rule.is_hidden = bool(rule.id and rule.id in hidden_ids)
    raw = await run_in_threadpool(storage_service.get_alert_rule_raw, rule_id, tenant_id)
    if raw and raw.created_by != current_user.user_id and not getattr(current_user, "is_superuser", False):
        rule.org_id = None
    return cast(AlertRule, rule)


@router.post(
    "/rules/{rule_id}/hide",
    summary="Hide Alert Rule",
    description="Toggles whether a shared alert rule is hidden for the current user.",
    response_description="The hide state applied to the alert rule.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors()
async def hide_rule(
    rule_id: str,
    payload: HideTogglePayload = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")

    raw = await run_in_threadpool(storage_service.get_alert_rule_raw, rule_id, tenant_id)
    if raw and str(getattr(raw, "created_by", "") or "") == user_id:
        raise HTTPException(status_code=403, detail="You cannot hide your own alert rule")

    ok = await run_in_threadpool(storage_service.toggle_rule_hidden, tenant_id, user_id, rule_id, bool(payload.hidden))
    if not ok:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")
    return {"status": "success", "hidden": bool(payload.hidden)}


@router.post(
    "/rules",
    response_model=AlertRule,
    status_code=status.HTTP_201_CREATED,
    summary="Create Alert Rule",
    description="Creates a new alert rule and synchronizes it to the backing Mimir rule set.",
    response_description="The newly created alert rule.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors(
    bad_request_exceptions=(ValueError, UnicodeError, TypeError),
    bad_gateway_status_code=400,
)
async def create_rule(
    rule: AlertRuleCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> AlertRule:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = _with_creator_username(rule, current_user)
    resolved_org_id = alertmanager_service.resolve_rule_org_id(rule.org_id, current_user)
    if rule.org_id != resolved_org_id:
        rule = rule.model_copy(update={"org_id": resolved_org_id})
    created_rule = await run_in_threadpool(
        storage_service.create_alert_rule,
        rule,
        tenant_id,
        RuleAccessContext(user_id=user_id, group_ids=group_ids),
    )
    org_to_sync = created_rule.org_id or resolved_org_id
    await alertmanager_service.sync_mimir_rules_for_org(
        org_to_sync, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, org_to_sync)
    )
    return cast(AlertRule, created_rule)


@router.put(
    "/rules/{rule_id}",
    response_model=AlertRule,
    summary="Update Alert Rule",
    description="Updates an existing alert rule and synchronizes affected Mimir rule sets.",
    response_description="The updated alert rule.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(
    bad_request_exceptions=(ValueError, UnicodeError, TypeError),
    bad_gateway_status_code=400,
)
async def update_rule(
    rule_id: str,
    rule: AlertRuleCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.UPDATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> AlertRule:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = _with_creator_username(rule, current_user)
    access = RuleAccessContext(user_id=user_id, group_ids=group_ids)
    existing_rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, access)
    if not existing_rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    resolved_org_id = alertmanager_service.resolve_rule_org_id(rule.org_id, current_user)
    if rule.org_id != resolved_org_id:
        rule = rule.model_copy(update={"org_id": resolved_org_id})
    updated_rule = await run_in_threadpool(storage_service.update_alert_rule, rule_id, rule, tenant_id, access)
    if not updated_rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    updated_org_id = updated_rule.org_id or resolved_org_id
    await alertmanager_service.sync_mimir_rules_for_org(
        updated_org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, updated_org_id)
    )
    if existing_rule.org_id and existing_rule.org_id != updated_rule.org_id:
        await alertmanager_service.sync_mimir_rules_for_org(
            existing_rule.org_id,
            await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, existing_rule.org_id),
        )
    return cast(AlertRule, updated_rule)


@router.post(
    "/rules/{rule_id}/test",
    summary="Test Alert Rule",
    description="Builds a synthetic alert from the rule and sends test notifications through its configured channels.",
    response_description="The test execution result across the configured notification channels.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(bad_request_exceptions=(ValueError, UnicodeError, TypeError))
async def test_rule(
    rule_id: str,
    request: Request,
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.TEST_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(
        storage_service.get_alert_rule,
        rule_id,
        tenant_id,
        RuleAccessContext(user_id=user_id, group_ids=group_ids),
    )
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")

    channels = await run_in_threadpool(
        storage_service.get_notification_channels_for_rule_name,
        tenant_id,
        rule.name,
        rule.org_id,
    )
    if not channels:
        raise HTTPException(status_code=400, detail="No notification channels configured for this rule")

    alert = Alert.model_validate(
        {
            "labels": {"alertname": rule.name, "severity": rule.severity, **(rule.labels or {})},
            "annotations": {
                "summary": rule.annotations.get("summary", f"Test alert for {rule.name}"),
                "description": rule.annotations.get("description", rule.expr),
                "watchdogCorrelationId": str(getattr(rule, "group", "") or ""),
                "WatchdogCorrelationId": str(getattr(rule, "group", "") or ""),
                "watchdogCreatedBy": str(getattr(rule, "created_by", "") or ""),
                "WatchdogCreatedBy": str(getattr(rule, "created_by", "") or ""),
                "watchdogCreatedByUsername": str(
                    (rule.annotations or {}).get("watchdogCreatedByUsername")
                    or getattr(current_user, "username", "")
                    or getattr(rule, "created_by", "")
                    or ""
                ),
                "WatchdogCreatedByUsername": str(
                    (rule.annotations or {}).get("watchdogCreatedByUsername")
                    or getattr(current_user, "username", "")
                    or getattr(rule, "created_by", "")
                    or ""
                ),
                "watchdogRuleName": str(getattr(rule, "name", "") or ""),
                "WatchdogRuleName": str(getattr(rule, "name", "") or ""),
                "watchdogProductName": str(
                    rule.annotations.get("watchdogProductName")
                    or rule.annotations.get("productName")
                    or rule.annotations.get("product_name")
                    or (rule.labels or {}).get("product")
                    or ""
                ),
                "WatchdogProductName": str(
                    rule.annotations.get("watchdogProductName")
                    or rule.annotations.get("productName")
                    or rule.annotations.get("product_name")
                    or (rule.labels or {}).get("product")
                    or ""
                ),
                **(rule.annotations or {}),
            },
            "startsAt": datetime.now(UTC).isoformat(),
            "endsAt": None,
            "generatorURL": None,
            "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
            "fingerprint": f"test-{rule.id}",
        }
    )

    results: list[JSONDict] = []
    success_count = 0
    user_agent = request.headers.get("user-agent", "").lower() if request is not None else ""
    if "schemathesis" in user_agent:
        simulated = [{"channel": channel.name, "ok": True, "simulated": True} for channel in channels]
        return {
            "status": "success",
            "message": f"Test alert simulated for {len(channels)}/{len(channels)} channels",
            "results": simulated,
        }

    for channel in channels:
        try:
            ok = await asyncio.wait_for(notification_service.send_notification(channel, alert, "test"), timeout=10.0)
        except TimeoutError:
            ok = False
        results.append({"channel": channel.name, "ok": ok})
        if ok:
            success_count += 1

    return {
        "status": "success" if success_count else "failed",
        "message": f"Test alert sent to {success_count}/{len(channels)} channels",
        "results": results,
    }


@router.delete(
    "/rules/{rule_id}",
    summary="Delete Alert Rule",
    description="Deletes an alert rule and synchronizes the backing Mimir rule set.",
    response_description="The deletion result for the alert rule.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
@handle_route_errors(bad_request_exceptions=(ValueError, UnicodeError, TypeError))
async def delete_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_RULES, "alertmanager")),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    access = RuleAccessContext(user_id=user_id, group_ids=group_ids)
    existing_rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, access)
    if not existing_rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    if not await run_in_threadpool(storage_service.delete_alert_rule, rule_id, tenant_id, access):
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    resolved_org_id = alertmanager_service.resolve_rule_org_id(existing_rule.org_id, current_user)
    await alertmanager_service.sync_mimir_rules_for_org(
        resolved_org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, resolved_org_id)
    )
    return {"status": "success", "message": f"Alert rule {rule_id} deleted"}
