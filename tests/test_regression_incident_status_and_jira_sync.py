"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import pytest
from fastapi import BackgroundTasks

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.incidents import AlertIncidentUpdateRequest, IncidentStatus
from routers.observability import incidents as incidents_router
from tests._regression_helpers import alert_incident, run_in_threadpool_inline, token_data


@pytest.mark.asyncio
async def test_payload_note_syncs_to_jira_without_assignment_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-j1", assignee="owner@example.com", status=IncidentStatus.OPEN)
    updated = alert_incident(incident_id="inc-j1", assignee="owner@example.com", status=IncidentStatus.OPEN)

    sync_notes: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_notes.append(note_text)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _noop)

    result = await incidents_router.update_incident(
        "inc-j1",
        AlertIncidentUpdateRequest(note="Investigating this with platform team"),
        background_tasks=BackgroundTasks(),
        current_user=user,
    )

    assert result.id == "inc-j1"
    assert sync_notes == ["Investigating this with platform team"]


@pytest.mark.asyncio
async def test_resolved_transition_adds_status_note_and_moves_ticket_done(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-j2", status=IncidentStatus.OPEN)
    updated = alert_incident(incident_id="inc-j2", status=IncidentStatus.RESOLVED)

    sync_notes: list[str] = []
    moves_done: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_notes.append(note_text)

    async def _done(*_args, **_kwargs):
        moves_done.append("done")

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _done)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _noop)

    async def _get_alerts(*_args, **_kwargs):
        return []

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)

    result = await incidents_router.update_incident(
        "inc-j2",
        AlertIncidentUpdateRequest(status="resolved"),
        background_tasks=BackgroundTasks(),
        current_user=user,
    )

    assert result.status == IncidentStatus.RESOLVED
    assert any("marked this incident as resolved" in note for note in sync_notes)
    assert moves_done == ["done"]


@pytest.mark.asyncio
async def test_reopen_transition_adds_status_note_and_moves_ticket_todo(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-j3", status=IncidentStatus.RESOLVED)
    updated = alert_incident(incident_id="inc-j3", status=IncidentStatus.OPEN)

    sync_notes: list[str] = []
    moves_todo: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_notes.append(note_text)

    async def _todo(*_args, **_kwargs):
        moves_todo.append("todo")

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _todo)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _noop)

    result = await incidents_router.update_incident(
        "inc-j3",
        AlertIncidentUpdateRequest(status="open"),
        background_tasks=BackgroundTasks(),
        current_user=user,
    )

    assert result.status == IncidentStatus.OPEN
    assert any("reopened this incident" in note for note in sync_notes)
    assert moves_todo == ["todo"]


@pytest.mark.asyncio
async def test_assignment_change_and_manual_note_emit_two_jira_sync_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-j4", assignee=None, status=IncidentStatus.OPEN)
    updated = alert_incident(incident_id="inc-j4", assignee="ops@example.com", status=IncidentStatus.OPEN)

    sync_notes: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(_incident, *, note_text: str, **_kwargs):
        sync_notes.append(note_text)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _noop)

    result = await incidents_router.update_incident(
        "inc-j4",
        AlertIncidentUpdateRequest(assignee="ops@example.com", note="Will investigate in 10 minutes"),
        background_tasks=BackgroundTasks(),
        current_user=user,
    )

    assert result.assignee == "ops@example.com"
    assert len(sync_notes) == 2
    assert any("assigned incident to ops@example.com" in note for note in sync_notes)
    assert any("Will investigate in 10 minutes" in note for note in sync_notes)


@pytest.mark.asyncio
async def test_reopen_with_new_assignee_moves_todo_and_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data(username="alice")
    existing = alert_incident(incident_id="inc-j5", assignee=None, status=IncidentStatus.RESOLVED)
    updated = alert_incident(incident_id="inc-j5", assignee="ops@example.com", status=IncidentStatus.OPEN)

    moves: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)

    async def _sync_note(*_args, **_kwargs):
        return None

    async def _todo(*_args, **_kwargs):
        moves.append("todo")

    async def _in_progress(*_args, **_kwargs):
        moves.append("in-progress")

    async def _done(*_args, **_kwargs):
        moves.append("done")

    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _sync_note)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _done)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _todo)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _in_progress)

    background = BackgroundTasks()
    result = await incidents_router.update_incident(
        "inc-j5",
        AlertIncidentUpdateRequest(status="open", assignee="ops@example.com"),
        background_tasks=background,
        current_user=user,
    )

    assert result.assignee == "ops@example.com"
    assert "in-progress" in moves
    assert "todo" in moves
    assert "done" not in moves
    assert len(background.tasks) == 1
