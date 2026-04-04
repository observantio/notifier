"""
Webhook endpoints for receiving alerts from external systems like Alertmanager and triggering notifications/incidents in
Watchdog.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import logging

from fastapi import APIRouter, Body, Request

from config import constants
from custom_types.json import JSONDict
from middleware.error_handlers import handle_route_errors
from middleware.openapi import BAD_REQUEST_ERRORS
from models.alerting.requests import AlertWebhookRequest
from services.alerting.integration_security_service import infer_tenant_id_from_alerts

from .shared import alertmanager_service, notification_service, scope_header, storage_service, sync_incidents

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alertmanager-webhooks"])


@router.post(
    "/alerts/webhook",
    summary="Receive Alert Webhook",
    description="Receives general alert webhook payloads and dispatches notifications for the inferred tenant.",
    response_description="The webhook processing result for the submitted alerts.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors()
async def receive_alert_webhook(request: Request, payload: AlertWebhookRequest = Body(...)) -> JSONDict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_webhook")
    logger.info("Received webhook payload with %d alerts", len(payload.alerts))
    tenant_id = infer_tenant_id_from_alerts(scope_header(request), payload.alerts)
    await sync_incidents(tenant_id, payload.alerts, log_context="webhook")
    await alertmanager_service.notify_for_alerts(tenant_id, payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "count": len(payload.alerts)}


@router.post(
    "/alerts/critical",
    summary="Receive Critical Alert Webhook",
    description=(
        "Receives critical alert webhook payloads and dispatches critical notifications " "for the inferred tenant."
    ),
    response_description="The webhook processing result for the submitted critical alerts.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors()
async def receive_critical_webhook(request: Request, payload: AlertWebhookRequest = Body(...)) -> JSONDict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_critical")
    logger.warning("Received %d critical alerts", len(payload.alerts))
    tenant_id = infer_tenant_id_from_alerts(scope_header(request), payload.alerts)
    await sync_incidents(tenant_id, payload.alerts, log_context="critical webhook")
    await alertmanager_service.notify_for_alerts(tenant_id, payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "severity": "critical", "count": len(payload.alerts)}


@router.post(
    "/alerts/warning",
    summary="Receive Warning Alert Webhook",
    description="Receives warning alert webhook payloads and dispatches warning notifications for the inferred tenant.",
    response_description="The webhook processing result for the submitted warning alerts.",
    responses=BAD_REQUEST_ERRORS,
)
@handle_route_errors()
async def receive_warning_webhook(request: Request, payload: AlertWebhookRequest = Body(...)) -> JSONDict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_warning")
    logger.info("Received warning alerts payload with %d alerts", len(payload.alerts))
    tenant_id = infer_tenant_id_from_alerts(scope_header(request), payload.alerts)
    await sync_incidents(tenant_id, payload.alerts, log_context="warning webhook")
    await alertmanager_service.notify_for_alerts(tenant_id, payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "severity": "warning", "count": len(payload.alerts)}
