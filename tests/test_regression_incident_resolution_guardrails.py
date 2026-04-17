"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import BackgroundTasks, HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.incidents import AlertIncidentUpdateRequest, IncidentStatus
from routers.observability import incidents as incidents_router
from tests._regression_helpers import alert_incident, run_in_threadpool_inline, token_data


async def _async_noop(*_args, **_kwargs):
    return None


@pytest.mark.asyncio
async def test_resolve_is_blocked_when_matching_active_alert_exists_by_incident_key(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    existing = alert_incident(incident_id="inc-r1", status=IncidentStatus.OPEN, labels={"alertname": "DiskFull"})

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router, "incident_key_from_labels", lambda labels: labels.get("alertname", ""))

    async def _get_alerts(**_kwargs):
        return [SimpleNamespace(labels={"alertname": "DiskFull"})]

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)

    with pytest.raises(HTTPException) as exc:
        await incidents_router.update_incident(
            "inc-r1",
            AlertIncidentUpdateRequest(status="resolved"),
            background_tasks=BackgroundTasks(),
            current_user=user,
        )

    assert exc.value.status_code == 400
    assert "underlying alert is still active" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_resolve_is_blocked_when_fingerprint_query_finds_active_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    existing = alert_incident(incident_id="inc-r2", status=IncidentStatus.OPEN, labels={}, fingerprint="fp-r2")

    get_alerts_calls: list[dict[str, object]] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router, "incident_key_from_labels", lambda _labels: None)

    async def _get_alerts(**kwargs):
        get_alerts_calls.append(kwargs)
        return [SimpleNamespace(labels={"alertname": "Anything"})]

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)

    with pytest.raises(HTTPException) as exc:
        await incidents_router.update_incident(
            "inc-r2",
            AlertIncidentUpdateRequest(status="resolved"),
            background_tasks=BackgroundTasks(),
            current_user=user,
        )

    assert exc.value.status_code == 400
    assert get_alerts_calls[0]["filter_labels"] == {"fingerprint": "fp-r2"}


@pytest.mark.asyncio
async def test_resolve_continues_when_alertmanager_lookup_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    existing = alert_incident(incident_id="inc-r3", status=IncidentStatus.OPEN, labels={"alertname": "ApiDown"})
    updated = alert_incident(incident_id="inc-r3", status=IncidentStatus.RESOLVED, labels={"alertname": "ApiDown"})

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)
    monkeypatch.setattr(incidents_router, "incident_key_from_labels", lambda labels: labels.get("alertname", ""))

    async def _get_alerts(**_kwargs):
        raise httpx.RequestError("boom", request=httpx.Request("GET", "https://alertmanager.example"))

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)
    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _async_noop)

    result = await incidents_router.update_incident(
        "inc-r3",
        AlertIncidentUpdateRequest(status="resolved"),
        background_tasks=BackgroundTasks(),
        current_user=user,
    )

    assert result.status == IncidentStatus.RESOLVED


@pytest.mark.asyncio
async def test_resolve_moves_ticket_done_when_no_active_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    existing = alert_incident(incident_id="inc-r4", status=IncidentStatus.OPEN, labels={"alertname": "ApiDown"})
    updated = alert_incident(incident_id="inc-r4", status=IncidentStatus.RESOLVED, labels={"alertname": "ApiDown"})

    moves_done: list[str] = []

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args, **_kwargs: updated)
    monkeypatch.setattr(incidents_router, "incident_key_from_labels", lambda labels: labels.get("alertname", ""))

    async def _get_alerts(**_kwargs):
        return []

    async def _done(*_args, **_kwargs):
        moves_done.append("done")

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _get_alerts)
    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _done)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _async_noop)

    result = await incidents_router.update_incident(
        "inc-r4",
        AlertIncidentUpdateRequest(status="resolved"),
        background_tasks=BackgroundTasks(),
        current_user=user,
    )

    assert result.status == IncidentStatus.RESOLVED
    assert moves_done == ["done"]


@pytest.mark.asyncio
async def test_update_returns_404_when_incident_is_not_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()

    monkeypatch.setattr(incidents_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: None)

    with pytest.raises(HTTPException) as exc:
        await incidents_router.update_incident(
            "missing",
            AlertIncidentUpdateRequest(status="resolved"),
            background_tasks=BackgroundTasks(),
            current_user=user,
        )

    assert exc.value.status_code == 404
