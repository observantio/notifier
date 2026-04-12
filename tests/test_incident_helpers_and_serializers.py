"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.incidents import AlertIncident, IncidentNote, IncidentStatus
from services.incidents import helpers as helpers_mod
from services.storage import serializers as serializers_mod


def _user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant",
        "org_id": "org",
        "role": Role.ADMIN,
        "permissions": ["read:incidents"],
        "group_ids": ["g1"],
    }
    payload.update(kwargs)
    return TokenData(**cast(dict[str, Any], payload))


def _incident(**kwargs) -> AlertIncident:
    payload = {
        "id": "inc-1",
        "fingerprint": "fp-1",
        "alertName": "CPUHigh",
        "severity": "critical",
        "status": "open",
        "notes": [],
        "labels": {},
        "annotations": {},
        "lastSeenAt": datetime.now(UTC),
        "createdAt": datetime.now(UTC),
        "updatedAt": datetime.now(UTC),
    }
    payload.update(kwargs)
    return AlertIncident.model_validate(payload)


def test_incident_helper_formatting_and_author_rewrites():
    incident = _incident(
        annotations={"summary": "CPU > 90", "description": "Service degradation"},
        notes=[
            {"author": "u1", "text": "u1 acknowledged incident", "createdAt": "2024-01-01T00:00:00Z"},
            {"author": "jira:bot", "text": "ignore", "createdAt": "2024-01-01T00:00:00Z"},
            {"author": "", "text": "", "createdAt": "2024-01-01T00:00:00Z"},
        ],
    )
    current_user = _user()

    assert helpers_mod.format_incident_description(incident, "  manual text  ") == "manual text"
    assert (
        helpers_mod.format_incident_description(
            _incident(annotations={"description": "Detail", "summary": "Summary"}), None
        )
        == "Detail -> Summary"
    )
    assert helpers_mod.format_incident_description(_incident(annotations={}), None) == "CPUHigh"
    assert helpers_mod.map_severity_to_jira_priority("critical") == "High"
    assert helpers_mod.map_severity_to_jira_priority("warning") == "Medium"
    assert helpers_mod.map_severity_to_jira_priority("info") == "Low"
    assert helpers_mod.format_note_for_jira_comment(" body ", "Alice", "2024-01-01T00:00:00Z").startswith(
        "Alice · 2024-01-01 00:00:00 UTC"
    )
    assert helpers_mod.format_note_for_jira_comment("body", "Alice", "not-a-date") == "Alice · not-a-date\nbody"
    assert helpers_mod.resolve_note_author_display("", current_user) == "Unknown user"
    assert helpers_mod.resolve_note_author_display("u1", current_user) == "alice"
    assert (
        helpers_mod.resolve_note_author_display("550e8400-e29b-41d4-a716-446655440000", current_user) == "Unknown user"
    )
    assert helpers_mod.resolve_note_author_display("bob", current_user) == "bob"
    assert helpers_mod.rewrite_note_text_for_author("u1 updated status", "u1", "alice") == "alice updated status"
    assert helpers_mod.rewrite_note_text_for_author("u1 updated status", "u1", "Unknown user") == "u1 updated status"
    assert helpers_mod.rewrite_note_text_for_actor("u1 updated status", "u1", "alice") == "alice updated status"

    bodies = helpers_mod.build_formatted_incident_note_bodies(incident, current_user)
    assert len(bodies) == 1
    assert "alice acknowledged incident" in bodies[0]


def test_incident_note_serializer_handles_timezone_aware_values() -> None:
    aware = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    note = IncidentNote.model_validate({"author": "alice", "text": "investigating", "createdAt": aware})
    assert note.model_dump(by_alias=True)["createdAt"] == "2026-01-01T12:00:00Z"


def test_build_formatted_incident_note_bodies_skips_empty_formatted_body(monkeypatch):
    incident = _incident(
        notes=[
            {"author": "u1", "text": "u1 updated", "createdAt": "2024-01-01T00:00:00Z"},
        ]
    )
    monkeypatch.setattr(helpers_mod, "format_note_for_jira_comment", lambda *_args, **_kwargs: "")
    assert helpers_mod.build_formatted_incident_note_bodies(incident, _user()) == []


@pytest.mark.asyncio
async def test_incident_helper_jira_sync_paths(monkeypatch):
    current_user = _user()
    incident = _incident(id="inc-1", jiraTicketKey="ABC-1")
    calls = []

    async def fake_add_comment(issue_key, text, credentials=None):
        calls.append(("comment", issue_key, text, credentials))

    async def fake_transition_to_todo(issue_key, credentials=None):
        calls.append(("todo", issue_key, credentials))

    async def fake_transition_to_in_progress(issue_key, credentials=None):
        calls.append(("progress", issue_key, credentials))

    async def fake_transition_to_done(issue_key, credentials=None):
        calls.append(("done", issue_key, credentials))

    monkeypatch.setattr(helpers_mod, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"})
    monkeypatch.setattr(helpers_mod.jira_service, "add_comment", fake_add_comment)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_todo", fake_transition_to_todo)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_in_progress", fake_transition_to_in_progress)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_done", fake_transition_to_done)

    await helpers_mod.sync_note_to_jira_comment(
        incident, tenant_id="tenant", current_user=current_user, note_text="u1 investigating"
    )
    await helpers_mod.move_incident_ticket_to_todo(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_in_progress(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_done(incident, tenant_id="tenant", current_user=current_user)

    assert calls[0][0] == "comment"
    assert "alice" in calls[0][2]
    assert calls[1][0] == "todo"
    assert calls[2][0] == "progress"
    assert calls[3][0] == "done"

    monkeypatch.setattr(helpers_mod, "resolve_incident_jira_credentials", lambda *_args: None)
    await helpers_mod.sync_note_to_jira_comment(
        incident, tenant_id="tenant", current_user=current_user, note_text="skip"
    )

    async def raise_jira_error(*_args, **_kwargs):
        raise helpers_mod.JiraError("boom")

    monkeypatch.setattr(helpers_mod, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"})
    monkeypatch.setattr(helpers_mod.jira_service, "add_comment", raise_jira_error)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_todo", raise_jira_error)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_in_progress", raise_jira_error)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_done", raise_jira_error)
    await helpers_mod.sync_note_to_jira_comment(
        incident, tenant_id="tenant", current_user=current_user, note_text="still safe"
    )
    await helpers_mod.move_incident_ticket_to_todo(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_in_progress(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_done(incident, tenant_id="tenant", current_user=current_user)


def test_storage_serializers_cover_rule_channel_and_incident_payloads():
    now = datetime.now(UTC)
    rule = SimpleNamespace(
        id="rule-1",
        created_by="owner",
        org_id="org-1",
        name="CPUHigh",
        expr="up == 0",
        duration="5m",
        severity="critical",
        labels={"service": "api"},
        annotations={"summary": "CPU"},
        enabled=True,
        group="infra",
        notification_channels=["chan-1"],
        visibility="group",
        shared_groups=[SimpleNamespace(id="g1")],
        is_hidden=True,
    )
    channel = SimpleNamespace(
        id="chan-1",
        name="Pager",
        type="pagerduty",
        enabled=True,
        config={
            "secret": "value",
            "routing_key": "pd-key",
            "routingKey": "pd-key-3",
            "integrationKey": "pd-key-2",
            "sendgrid_api_key": "sg-secret",
            "resend_api_key": "re-secret",
            "to": "ops@example.com",
        },
        created_by="owner",
        visibility="private",
        shared_groups=[SimpleNamespace(id="g1")],
        is_hidden=False,
    )
    incident = SimpleNamespace(
        id="inc-1",
        fingerprint="fp-1",
        alert_name="CPUHigh",
        severity="critical",
        status="IncidentStatus.RESOLVED",
        assignee="u1",
        notes=[{"author": "system", "text": "closed", "createdAt": now.isoformat()}],
        labels={"service": "api"},
        annotations={
            serializers_mod.INCIDENT_META_KEY: '{"visibility":"group","shared_group_ids":["g1"],"jira_ticket_key":"ABC-1","jira_ticket_url":"https://jira/browse/ABC-1","jira_integration_id":"jira-1","correlation_id":"corr-1","user_managed":true,"hide_when_resolved":true}',
            "summary": "CPU high",
        },
        starts_at=now,
        last_seen_at=now,
        resolved_at=now,
        created_at=now,
        updated_at=now,
    )

    rule_model = serializers_mod.rule_to_pydantic(rule)
    assert rule_model.shared_group_ids == ["g1"]
    assert rule_model.is_hidden is True

    owner_view = serializers_mod.channel_to_pydantic_for_viewer(channel, viewer_user_id="owner")
    other_view = serializers_mod.channel_to_pydantic_for_viewer(channel, viewer_user_id="other")
    default_view = serializers_mod.channel_to_pydantic(channel)
    assert owner_view.config == {"to": "ops@example.com"}
    assert other_view.config == {}
    assert default_view.config == {
        "secret": "value",
        "routing_key": "pd-key",
        "routingKey": "pd-key-3",
        "integrationKey": "pd-key-2",
        "sendgrid_api_key": "sg-secret",
        "resend_api_key": "re-secret",
        "to": "ops@example.com",
    }

    incident_model = serializers_mod.incident_to_pydantic(incident)
    assert incident_model.status == "resolved"
    assert incident_model.visibility == "group"
    assert incident_model.shared_group_ids == ["g1"]
    assert incident_model.jira_ticket_key == "ABC-1"
    assert incident_model.annotations["WatchdogCorrelationId"] == "corr-1"
    assert (
        serializers_mod.incident_to_pydantic(
            SimpleNamespace(
                id="inc-2",
                fingerprint="fp-2",
                alert_name="DiskFull",
                severity="warning",
                status="open",
                assignee=None,
                notes=[],
                labels={},
                annotations={serializers_mod.INCIDENT_META_KEY: '{"visibility":"invalid"}'},
                starts_at=None,
                last_seen_at=now,
                resolved_at=None,
                created_at=now,
                updated_at=now,
            )
        ).visibility
        == "public"
    )


def test_storage_serializer_incident_status_enum_and_correlation_case_bridge():
    now = datetime.now(UTC)
    incident = SimpleNamespace(
        id="inc-3",
        fingerprint="fp-3",
        alert_name="MemoryHigh",
        severity="warning",
        status=IncidentStatus.OPEN,
        assignee=None,
        notes=[],
        labels={},
        annotations={"watchdogCorrelationId": "corr-lower"},
        starts_at=now,
        last_seen_at=now,
        resolved_at=None,
        created_at=now,
        updated_at=now,
    )

    model = serializers_mod.incident_to_pydantic(incident)
    assert model.status == "open"
    assert model.annotations["watchdogCorrelationId"] == "corr-lower"
    assert model.annotations["WatchdogCorrelationId"] == "corr-lower"


def test_storage_serializer_incident_without_correlation_leaves_keys_absent():
    now = datetime.now(UTC)
    incident = SimpleNamespace(
        id="inc-4",
        fingerprint="fp-4",
        alert_name="NetworkDown",
        severity="critical",
        status="open",
        assignee=None,
        notes=[],
        labels={},
        annotations={},
        starts_at=now,
        last_seen_at=now,
        resolved_at=None,
        created_at=now,
        updated_at=now,
    )

    model = serializers_mod.incident_to_pydantic(incident)
    assert "watchdogCorrelationId" not in model.annotations
    assert "WatchdogCorrelationId" not in model.annotations


def test_storage_serializer_preserves_existing_dual_correlation_keys():
    now = datetime.now(UTC)
    incident = SimpleNamespace(
        id="inc-5",
        fingerprint="fp-5",
        alert_name="PacketLoss",
        severity="warning",
        status="open",
        assignee=None,
        notes=[],
        labels={},
        annotations={
            "watchdogCorrelationId": "corr-a",
            "WatchdogCorrelationId": "corr-b",
        },
        starts_at=now,
        last_seen_at=now,
        resolved_at=None,
        created_at=now,
        updated_at=now,
    )

    model = serializers_mod.incident_to_pydantic(incident)
    assert model.annotations["watchdogCorrelationId"] == "corr-a"
    assert model.annotations["WatchdogCorrelationId"] == "corr-b"


def test_storage_serializer_non_dict_channel_config_returns_empty_visible_config():
    channel = SimpleNamespace(
        id="chan-2",
        name="Slack",
        type="slack",
        enabled=True,
        config=["not", "a", "dict"],
        created_by="owner",
        visibility="private",
        shared_groups=[],
        is_hidden=False,
    )

    model = serializers_mod.channel_to_pydantic_for_viewer(channel, viewer_user_id="owner", include_sensitive=False)
    assert model.config == {}


def test_incident_datetime_serializers_cover_naive_and_none_paths():
    note = IncidentNote.model_validate(
        {
            "author": "alice@example.com",
            "text": "Investigating",
            "createdAt": datetime(2026, 1, 1, 0, 0, 0),
        }
    )
    dumped_note = note.model_dump(by_alias=True)
    assert dumped_note["createdAt"].endswith("Z")

    incident = AlertIncident.model_validate(
        {
            "id": "inc-naive",
            "fingerprint": "fp-naive",
            "alertName": "CPUHigh",
            "severity": "critical",
            "status": "open",
            "assignee": None,
            "notes": [],
            "labels": {},
            "annotations": {},
            "visibility": "public",
            "sharedGroupIds": [],
            "jiraTicketKey": None,
            "jiraTicketUrl": None,
            "jiraIntegrationId": None,
            "startsAt": None,
            "lastSeenAt": datetime(2026, 1, 1, 0, 0, 0),
            "resolvedAt": None,
            "createdAt": datetime(2026, 1, 1, 0, 0, 0),
            "updatedAt": datetime(2026, 1, 1, 0, 0, 0),
            "userManaged": False,
            "hideWhenResolved": False,
        }
    )
    dumped_incident = incident.model_dump(by_alias=True)
    assert dumped_incident["lastSeenAt"].endswith("Z")
    assert dumped_incident["createdAt"].endswith("Z")
    assert dumped_incident["updatedAt"].endswith("Z")
    assert dumped_incident["startsAt"] is None
    assert dumped_incident["resolvedAt"] is None
