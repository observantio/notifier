"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from email.message import EmailMessage

import httpx
import pytest
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from middleware.error_handlers import handle_route_errors
from services import notification_service as notification_mod
from services.jira_service import JiraIssueCreateOptions, JiraIssueCreateRequest, JiraService
from services.notification import email_providers, transport
from services.notification_service import NotificationService
from services.storage import incidents as incidents_mod


@pytest.mark.asyncio
async def test_handle_route_errors_invalid_legacy_status_uses_default() -> None:
    @handle_route_errors(bad_gateway_status_code="bad-status")
    async def bad_gateway() -> str:
        raise httpx.ReadError("boom")

    with pytest.raises(HTTPException) as exc:
        await bad_gateway()
    assert exc.value.status_code == 502


@pytest.mark.asyncio
async def test_jira_create_issue_dataclass_request() -> None:
    service = JiraService(timeout=1)
    captured: dict[str, object] = {}

    async def fake_post(path, payload, credentials=None):
        captured["path"] = path
        captured["payload"] = payload
        return {"key": "OPS-42"}

    service._post = fake_post
    service._resolve_base_url = lambda credentials=None: "https://jira.example.com"

    created = await service.create_issue(
        JiraIssueCreateRequest(
            project_key="OPS",
            summary="Summary",
            options=JiraIssueCreateOptions(description="from-dataclass", issue_type="Task", priority="High"),
        )
    )

    fields = captured["payload"]["fields"]
    assert fields["description"] == "from-dataclass"
    assert fields["issuetype"]["name"] == "Task"
    assert fields["priority"]["name"] == "High"
    assert created["url"] == "https://jira.example.com/browse/OPS-42"


@pytest.mark.asyncio
async def test_email_provider_smtp_coercion_edges(monkeypatch) -> None:
    async def fake_send_smtp_with_retry(*_args, **_kwargs):
        return True

    monkeypatch.setattr(email_providers.transport, "send_smtp_with_retry", fake_send_smtp_with_retry)

    message = EmailMessage()
    smtp_cfg = transport.SmtpDeliveryConfig(hostname="smtp.example.com", port=587, start_tls=True)

    assert await email_providers.send_via_smtp(message, smtp=smtp_cfg) is True
    assert await email_providers.send_via_smtp(message, smtp="smtp.example.com", port=587) is True

    with pytest.raises(ValueError, match="SMTP hostname is required"):
        await email_providers.send_via_smtp(message, "", 587)

    with pytest.raises(ValueError, match="SMTP port must be an integer"):
        await email_providers.send_via_smtp(message, "smtp.example.com", "bad")


@pytest.mark.asyncio
async def test_transport_smtp_coercion_edges(monkeypatch) -> None:
    async def fake_aiosmtplib_send(*_args, **_kwargs):
        return {"accepted": ["ok@example.com"]}

    monkeypatch.setattr(transport.aiosmtplib, "send", fake_aiosmtplib_send)

    message = EmailMessage()
    smtp_cfg = transport.SmtpDeliveryConfig(hostname="smtp.example.com", port=587)

    result = await transport.send_smtp_with_retry(message, smtp=smtp_cfg)
    assert result["accepted"] == ["ok@example.com"]

    result_legacy = await transport.send_smtp_with_retry(message, smtp="smtp.example.com", port=587)
    assert result_legacy["accepted"] == ["ok@example.com"]

    with pytest.raises(ValueError, match="SMTP hostname is required"):
        await transport.send_smtp_with_retry(message, smtp="", port=587)

    with pytest.raises(ValueError, match="SMTP port must be an integer"):
        await transport.send_smtp_with_retry(message, smtp="smtp.example.com", port="bad")


@pytest.mark.asyncio
async def test_notification_service_smtp_helper_validation_edges(monkeypatch) -> None:
    service = NotificationService()
    captured: dict[str, object] = {}

    async def fake_send_smtp_with_retry(*_args, **kwargs):
        captured.update(kwargs)
        return True

    monkeypatch.setattr(notification_mod.notification_transport, "send_smtp_with_retry", fake_send_smtp_with_retry)

    message = EmailMessage()
    smtp_cfg = transport.SmtpDeliveryConfig(hostname="smtp.example.com", port=2525)

    assert await service._send_smtp_with_retry(message, smtp=smtp_cfg) is True
    assert captured["hostname"] == "smtp.example.com"

    with pytest.raises(ValueError, match="SMTP hostname is required"):
        await service._send_smtp_with_retry(message, hostname="")

    with pytest.raises(ValueError, match="SMTP port must be an integer"):
        await service._send_smtp_with_retry(message, "smtp.example.com", "bad")


def test_incident_filter_coercion_handles_dataclass_and_bad_numbers() -> None:
    base_filters = incidents_mod.IncidentListFilters(group_ids=["g1"], limit=10, offset=7)

    preserved = incidents_mod._coerce_incident_list_filters(base_filters, {})
    assert preserved.group_ids == ["g1"]

    coerced = incidents_mod._coerce_incident_list_filters(base_filters, {"limit": "bad", "offset": "bad"})
    assert coerced.limit == 10
    assert coerced.offset == 7
