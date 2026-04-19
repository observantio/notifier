"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import pytest
from fastapi import BackgroundTasks

from tests._env import ensure_test_env

ensure_test_env()

import importlib.util
import sys
from pathlib import Path

from models.access.auth_models import TokenData
from models.alerting.incidents import (
    AlertIncident,
    AlertIncidentUpdateRequest,
    IncidentStatus,
)

incidents_path = Path(__file__).resolve().parents[1] / "routers" / "observability" / "incidents.py"
spec = importlib.util.spec_from_file_location("incidents_module", incidents_path)
assert spec is not None
assert spec.loader is not None
incidents_mod = importlib.util.module_from_spec(spec)
sys.modules["incidents_module"] = incidents_mod
spec.loader.exec_module(incidents_mod)

update_incident = incidents_mod.update_incident
storage_service = incidents_mod.storage_service
notification_service = incidents_mod.notification_service
recipient_email = incidents_mod._recipient_email


def test_recipient_email_parsing_and_validation() -> None:
    assert recipient_email(None) is None
    assert recipient_email("") is None
    assert recipient_email("   ") is None
    assert recipient_email("bob@example.com") == "bob@example.com"
    assert recipient_email(" Bob <bob@example.com> ") == "bob@example.com"
    assert recipient_email("not-an-email") is None
    assert recipient_email("Name <not-an-email>") is None


@pytest.mark.asyncio
async def test_patch_incident_sends_assignment_email(monkeypatch):
    # prepare fake existing and updated incidents
    existing = AlertIncident(
        id="i1",
        fingerprint="fp",
        alertName="Alert1",
        severity="critical",
        status=IncidentStatus.OPEN,
        assignee=None,
        notes=[],
        labels={},
        annotations={},
        visibility="public",
        sharedGroupIds=[],
        lastSeenAt="2023-01-01T00:00:00Z",
        createdAt="2023-01-01T00:00:00Z",
        updatedAt="2023-01-01T00:00:00Z",
        userManaged=False,
        hideWhenResolved=False,
    )
    updated = existing.model_copy(update={"assignee": "bob@example.com"})

    monkeypatch.setattr(storage_service, "get_incident_for_user", lambda *args, **kwargs: existing)
    monkeypatch.setattr(storage_service, "update_incident", lambda *args, **kwargs: updated)

    monkeypatch.setattr(notification_service, "send_incident_assignment_email", lambda **_kwargs: None)

    user = TokenData(
        user_id="u1",
        username="alice",
        tenant_id="t1",
        org_id="o1",
        role="user",
        permissions=[],
        group_ids=[],
        is_superuser=False,
    )

    payload = AlertIncidentUpdateRequest(assignee="bob@example.com")
    background_tasks = BackgroundTasks()
    result = await update_incident("i1", payload, background_tasks=background_tasks, current_user=user)

    assert result.assignee == "bob@example.com"
    assert len(background_tasks.tasks) == 1
    task = background_tasks.tasks[0]
    payload = task.args[0]
    assert payload.recipient_email == "bob@example.com"
    assert payload.incident_title == "Alert1"
    assert str(payload.incident_severity) == "critical"


@pytest.mark.asyncio
async def test_patch_incident_requests_write_access_for_existing_incident(monkeypatch):
    existing = AlertIncident(
        id="i2",
        fingerprint="fp2",
        alertName="Alert2",
        severity="warning",
        status=IncidentStatus.OPEN,
        assignee=None,
        notes=[],
        labels={},
        annotations={},
        visibility="group",
        sharedGroupIds=["g1"],
        lastSeenAt="2023-01-01T00:00:00Z",
        createdAt="2023-01-01T00:00:00Z",
        updatedAt="2023-01-01T00:00:00Z",
        userManaged=False,
        hideWhenResolved=False,
    )
    updated = existing

    captured = {}

    def fake_get_incident_for_user(*args, **kwargs):
        captured["existing_args"] = args
        captured["existing_kwargs"] = kwargs
        return existing

    def fake_update_incident(*args, **kwargs):
        captured["update_args"] = args
        captured["update_kwargs"] = kwargs
        return updated

    monkeypatch.setattr(storage_service, "get_incident_for_user", fake_get_incident_for_user)
    monkeypatch.setattr(storage_service, "update_incident", fake_update_incident)

    user = TokenData(
        user_id="u1",
        username="alice",
        tenant_id="t1",
        org_id="o1",
        role="user",
        permissions=[],
        group_ids=["g1"],
        is_superuser=False,
    )

    payload = AlertIncidentUpdateRequest()
    await update_incident("i2", payload, background_tasks=BackgroundTasks(), current_user=user)

    existing_context = captured["existing_kwargs"].get("context") or captured["existing_args"][2]
    existing_write_access = getattr(existing_context, "require_write", False)
    assert existing_write_access is True

    assert captured["update_kwargs"] == {}
    assert captured["update_args"][0] == "i2"
    assert captured["update_args"][1] == "t1"
    assert captured["update_args"][2] == "u1"
    assert captured["update_args"][4] == ["g1"]
    assert captured["update_args"][5] is None


@pytest.mark.asyncio
async def test_patch_incident_skips_assignment_email_for_non_email_assignee(monkeypatch):
    existing = AlertIncident(
        id="i3",
        fingerprint="fp3",
        alertName="Alert3",
        severity="warning",
        status=IncidentStatus.OPEN,
        assignee=None,
        notes=[],
        labels={},
        annotations={},
        visibility="public",
        sharedGroupIds=[],
        lastSeenAt="2023-01-01T00:00:00Z",
        createdAt="2023-01-01T00:00:00Z",
        updatedAt="2023-01-01T00:00:00Z",
        userManaged=False,
        hideWhenResolved=False,
    )
    updated = existing.model_copy(update={"assignee": "5f10ece5-95e9-4548-9ab0-53f9482c3473"})

    monkeypatch.setattr(storage_service, "get_incident_for_user", lambda *args, **kwargs: existing)
    monkeypatch.setattr(storage_service, "update_incident", lambda *args, **kwargs: updated)

    monkeypatch.setattr(notification_service, "send_incident_assignment_email", lambda **_kwargs: None)

    user = TokenData(
        user_id="u1",
        username="alice",
        tenant_id="t1",
        org_id="o1",
        role="user",
        permissions=[],
        group_ids=[],
        is_superuser=False,
    )

    payload = AlertIncidentUpdateRequest(assignee="5f10ece5-95e9-4548-9ab0-53f9482c3473")
    background_tasks = BackgroundTasks()
    result = await update_incident("i3", payload, background_tasks=background_tasks, current_user=user)

    assert result.assignee == "5f10ece5-95e9-4548-9ab0-53f9482c3473"
    assert len(background_tasks.tasks) == 0
