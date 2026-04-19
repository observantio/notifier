"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from routers.observability import incidents as incidents_router
from services import alertmanager_service as alertmanager_mod
from services.jira_service import _coerce_issue_options
from services.notification import validators as notification_validators


@pytest.mark.asyncio
async def test_incident_assignment_email_task_wraps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    async def _send(payload):
        captured["payload"] = payload
        return True

    monkeypatch.setattr(incidents_router.notification_service, "send_incident_assignment_email", _send)
    result = await incidents_router._send_incident_assignment_email_task(
        recipient_email="ops@example.com",
        incident_title="CPUHigh",
        incident_status="open",
        incident_severity="critical",
        actor="alice",
    )
    assert result is True
    assert captured["payload"].recipient_email == "ops@example.com"

    direct_payload = incidents_router.IncidentAssignmentEmail(
        recipient_email="direct@example.com",
        incident_title="MemoryHigh",
        incident_status="open",
        incident_severity="warning",
        actor="bob",
    )
    result = await incidents_router._send_incident_assignment_email_task(payload=direct_payload)
    assert result is True
    assert captured["payload"].recipient_email == "direct@example.com"


@pytest.mark.asyncio
async def test_alertmanager_get_alerts_legacy_kwargs_path(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = alertmanager_mod.AlertManagerService()
    captured = {}

    async def _get_alerts_ops(_service, query):
        captured["query"] = query
        return []

    monkeypatch.setattr(alertmanager_mod, "get_alerts_ops", _get_alerts_ops)
    await svc.get_alerts(filter_labels={"alertname": "CPUHigh"}, active=True, silenced=False, inhibited=False)
    query = captured["query"]
    assert query.filter_labels == {"alertname": "CPUHigh"}
    assert query.active is True
    assert query.silenced is False
    assert query.inhibited is False


def test_jira_issue_option_coercion_default_and_legacy_overrides() -> None:
    defaults = _coerce_issue_options(None, {})
    assert defaults.description is None
    assert defaults.issue_type == "Task"
    assert defaults.priority is None

    legacy = _coerce_issue_options(
        None,
        {"description": "hello", "issue_type": "Bug", "priority": "High"},
    )
    assert legacy.description == "hello"
    assert legacy.issue_type == "Bug"
    assert legacy.priority == "High"


def test_webhook_validator_accepts_valid_url_without_errors() -> None:
    errors = notification_validators.validate_channel_config(
        "webhook",
        {"url": "https://example.com/hook"},
    )
    assert errors == []
