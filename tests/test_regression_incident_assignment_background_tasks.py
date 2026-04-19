"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks
from sqlalchemy.exc import SQLAlchemyError

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.incidents import AlertIncidentUpdateRequest
from routers.observability import incidents as incidents_router
from tests._regression_helpers import alert_incident, run_in_threadpool_inline, token_data


@pytest.mark.asyncio
async def test_assignment_change_schedules_email_task_for_valid_email(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-a", assignee=None)
    updated = alert_incident(incident_id="inc-a", assignee="Bob <bob@example.com>")

    sync_calls: list[str] = []
    move_calls: list[str] = []
    update_payloads: list[AlertIncidentUpdateRequest] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)

    def _update_incident(*args, **kwargs):
        payload = kwargs.get("update_data")
        if payload is None:
            for candidate in reversed(args):
                if isinstance(candidate, AlertIncidentUpdateRequest):
                    payload = candidate
                    break
        if payload is not None:
            update_payloads.append(payload)
        return updated

    monkeypatch.setattr(incidents_router.storage_service, "update_incident", _update_incident)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_calls.append(note_text)

    async def _move(_incident, **_kwargs):
        move_calls.append("in-progress")

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _move)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", lambda *_a, **_k: None)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", lambda *_a, **_k: None)

    background = BackgroundTasks()
    result = await incidents_router.update_incident(
        "inc-a",
        AlertIncidentUpdateRequest(assignee="Bob <bob@example.com>"),
        background_tasks=background,
        current_user=user,
    )

    assert result.assignee == "Bob <bob@example.com>"
    assert len(update_payloads) == 2
    assert len(sync_calls) == 1
    assert "assigned incident to Bob <bob@example.com>" in sync_calls[0]
    assert move_calls == ["in-progress"]
    assert len(background.tasks) == 1
    assert background.tasks[0].args[0].recipient_email == "bob@example.com"


@pytest.mark.asyncio
async def test_assignment_change_to_non_email_skips_assignment_email(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-b", assignee=None)
    updated = alert_incident(incident_id="inc-b", assignee="oncall-user-17")

    move_calls: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(*_args, **_kwargs):
        return None

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)

    async def _move(_incident, **_kwargs):
        move_calls.append("in-progress")

    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _move)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", lambda *_a, **_k: None)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", lambda *_a, **_k: None)

    background = BackgroundTasks()
    result = await incidents_router.update_incident(
        "inc-b",
        AlertIncidentUpdateRequest(assignee="oncall-user-17"),
        background_tasks=background,
        current_user=user,
    )

    assert result.assignee == "oncall-user-17"
    assert move_calls == ["in-progress"]
    assert background.tasks == []


@pytest.mark.asyncio
async def test_unassignment_records_note_and_skips_email(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-c", assignee="owner@example.com")
    updated = alert_incident(incident_id="inc-c", assignee="")

    sync_calls: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_calls.append(note_text)

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", lambda *_a, **_k: None)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", lambda *_a, **_k: None)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", lambda *_a, **_k: None)

    background = BackgroundTasks()
    result = await incidents_router.update_incident(
        "inc-c",
        AlertIncidentUpdateRequest(assignee=""),
        background_tasks=background,
        current_user=user,
    )

    assert result.assignee == ""
    assert background.tasks == []
    assert len(sync_calls) == 1
    assert "unassigned this incident" in sync_calls[0]


@pytest.mark.asyncio
async def test_unchanged_assignee_does_not_add_assignment_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-d", assignee="same@example.com")
    updated = alert_incident(incident_id="inc-d", assignee="same@example.com")

    update_calls: list[SimpleNamespace] = []
    sync_calls: list[str] = []
    move_calls: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)

    def _update_incident(*args, **_kwargs):
        update_calls.append(SimpleNamespace(args=args))
        return updated

    monkeypatch.setattr(incidents_router.storage_service, "update_incident", _update_incident)

    async def _sync_note(*_args, **_kwargs):
        sync_calls.append("sync")

    async def _move(*_args, **_kwargs):
        move_calls.append("move")

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _move)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _move)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _move)

    background = BackgroundTasks()
    result = await incidents_router.update_incident(
        "inc-d",
        AlertIncidentUpdateRequest(assignee="same@example.com"),
        background_tasks=background,
        current_user=user,
    )

    assert result.assignee == "same@example.com"
    assert len(update_calls) == 1
    assert sync_calls == []
    assert move_calls == []
    assert background.tasks == []


@pytest.mark.asyncio
async def test_assignment_note_write_failure_does_not_abort_assignment_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-e", assignee=None)
    updated = alert_incident(incident_id="inc-e", assignee="ops@example.com")

    call_count = {"n": 0}
    sync_calls: list[str] = []
    move_calls: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)

    def _update_incident(*_args, **_kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return updated
        raise SQLAlchemyError("failed to save assignment note")

    monkeypatch.setattr(incidents_router.storage_service, "update_incident", _update_incident)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_calls.append(note_text)

    async def _move(_incident, **_kwargs):
        move_calls.append("in-progress")

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _move)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", lambda *_a, **_k: None)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", lambda *_a, **_k: None)

    background = BackgroundTasks()
    result = await incidents_router.update_incident(
        "inc-e",
        AlertIncidentUpdateRequest(assignee="ops@example.com"),
        background_tasks=background,
        current_user=user,
    )

    assert result.assignee == "ops@example.com"
    assert call_count["n"] == 2
    assert len(sync_calls) == 1
    assert move_calls == ["in-progress"]
    assert len(background.tasks) == 1
    assert background.tasks[0].args[0].recipient_email == "ops@example.com"
