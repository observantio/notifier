"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from routers.observability import incidents as incidents_router
from services.alerting.alerts_ops import AlertQuery
from services import alertmanager_service as alertmanager_mod
from services.jira_service import JiraIssueCreateOptions, _coerce_issue_options
from services.notification import validators as notification_validators


@pytest.mark.asyncio
async def test_incident_assignment_email_task_wraps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    async def _send(payload):
        captured["payload"] = payload
        return True

    monkeypatch.setattr(incidents_router.notification_service, "send_incident_assignment_email", _send)
    payload = incidents_router.IncidentAssignmentEmail(
        recipient_email="ops@example.com",
        incident_title="CPUHigh",
        incident_status="open",
        incident_severity="critical",
        actor="alice",
    )
    result = await incidents_router._send_incident_assignment_email_task(
        payload,
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
async def test_alertmanager_get_alerts_query_path(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = alertmanager_mod.AlertManagerService()
    captured = {}

    async def _get_alerts_ops(_service, query):
        captured["query"] = query
        return []

    monkeypatch.setattr(alertmanager_mod, "get_alerts_ops", _get_alerts_ops)
    await svc.get_alerts(
        AlertQuery(filter_labels={"alertname": "CPUHigh"}, active=True, silenced=False, inhibited=False)
    )
    query = captured["query"]
    assert query.filter_labels == {"alertname": "CPUHigh"}
    assert query.active is True
    assert query.silenced is False
    assert query.inhibited is False


@pytest.mark.asyncio
async def test_alertmanager_get_alerts_with_none_query(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = alertmanager_mod.AlertManagerService()
    captured = {}

    async def _get_alerts_ops(_service, query):
        captured["query"] = query
        return []

    monkeypatch.setattr(alertmanager_mod, "get_alerts_ops", _get_alerts_ops)
    await svc.get_alerts()
    assert captured["query"] is None


@pytest.mark.asyncio
async def test_ensure_resolve_allowed_returns_when_not_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = incidents_router.AlertIncidentUpdateRequest(status="open")
    existing = incidents_router.AlertIncident(
        id="incident-1",
        fingerprint="fp-1",
        alertName="AlertOne",
        severity="critical",
        status="open",
        assignee=None,
        notes=[],
        labels={},
        annotations={},
        visibility="public",
        sharedGroupIds=[],
        jiraTicketKey=None,
        jiraTicketUrl=None,
        jiraIntegrationId=None,
        startsAt=datetime.now(tz=timezone.utc),
        lastSeenAt=datetime.now(tz=timezone.utc),
        resolvedAt=None,
        createdAt=datetime.now(tz=timezone.utc),
        updatedAt=datetime.now(tz=timezone.utc),
        userManaged=False,
        hideWhenResolved=False,
    )
    called = False

    async def _get_alerts(*args, **kwargs):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)
    await incidents_router._ensure_resolve_allowed(payload, existing)
    assert called is False


@pytest.mark.asyncio
async def test_ensure_resolve_allowed_raises_if_active_alert_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = incidents_router.AlertIncidentUpdateRequest(status="resolved")
    existing = incidents_router.AlertIncident(
        id="incident-2",
        fingerprint="fp-2",
        alertName="AlertTwo",
        severity="critical",
        status="open",
        assignee=None,
        notes=[],
        labels={"alertname": "AlertTwo", "tenant": "t1"},
        annotations={},
        visibility="public",
        sharedGroupIds=[],
        jiraTicketKey=None,
        jiraTicketUrl=None,
        jiraIntegrationId=None,
        startsAt=datetime.now(tz=timezone.utc),
        lastSeenAt=datetime.now(tz=timezone.utc),
        resolvedAt=None,
        createdAt=datetime.now(tz=timezone.utc),
        updatedAt=datetime.now(tz=timezone.utc),
        userManaged=False,
        hideWhenResolved=False,
    )

    async def _get_alerts(*args, **kwargs):
        return [SimpleNamespace(labels={"alertname": "AlertTwo", "tenant": "t1"})]

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)
    with pytest.raises(incidents_router.HTTPException, match="Cannot mark resolved"):
        await incidents_router._ensure_resolve_allowed(payload, existing)


def test_jira_issue_option_coercion_from_issue() -> None:
    result = _coerce_issue_options("User story")
    assert result.description == "User story"
    assert result.issue_type == "Task"
    assert result.priority is None


def test_jira_issue_option_coercion_default_and_explicit_options() -> None:
    defaults = _coerce_issue_options(None)
    assert defaults.description is None
    assert defaults.issue_type == "Task"
    assert defaults.priority is None

    explicit = _coerce_issue_options(
        JiraIssueCreateOptions(description="hello", issue_type="Bug", priority="High")
    )
    assert explicit.description == "hello"
    assert explicit.issue_type == "Bug"
    assert explicit.priority == "High"


def test_webhook_validator_accepts_valid_url_without_errors() -> None:
    errors = notification_validators.validate_channel_config(
        "webhook",
        {"url": "https://example.com/hook"},
    )
    assert errors == []
