"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from fastapi import HTTPException

from models.alerting.incidents import AlertIncidentUpdateRequest
from services.storage import incidents as incidents_mod
from services.storage import incidents_core as incidents_core_mod
from services.storage import incidents_jira as incidents_jira_mod
from services.storage import incidents_sync as incidents_sync_mod


def _incident_row(
    incident_id: str,
    *,
    status: str = "open",
    visibility: str = "public",
    created_by: str | None = None,
    shared_group_ids: list[str] | None = None,
    hide_when_resolved: bool = False,
    assignee: str | None = None,
    alert_name: str = "CPUHigh",
    fingerprint: str = "fp-1",
    labels: dict[str, object] | None = None,
    annotations: dict[str, object] | None = None,
) -> SimpleNamespace:
    meta: dict[str, object] = {
        "visibility": visibility,
        "created_by": created_by,
        "shared_group_ids": shared_group_ids or [],
    }
    if hide_when_resolved:
        meta["hide_when_resolved"] = True
    merged_annotations = dict(annotations or {})
    merged_annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(meta)
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=incident_id,
        tenant_id="tenant-a",
        status=status,
        assignee=assignee,
        annotations=merged_annotations,
        labels=labels or {"alertname": alert_name},
        alert_name=alert_name,
        fingerprint=fingerprint,
        updated_at=now,
        last_seen_at=now,
        resolved_at=None,
        starts_at=None,
        severity="warning",
        notes=[],
    )


class _FakeQuery:
    def __init__(self, items):
        self._items = list(items)
        self._offset = 0
        self._limit: int | None = None

    def filter(self, *args, **kwargs):
        for expression in args:
            left = getattr(expression, "left", None)
            right = getattr(expression, "right", None)
            key = getattr(left, "key", None) or getattr(left, "name", None)
            value = getattr(right, "value", None)
            if key is not None and value is not None:
                self._items = [item for item in self._items if getattr(item, key, None) == value]
        return self

    def options(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, value: int):
        self._offset = value
        return self

    def limit(self, value: int):
        self._limit = value
        return self

    def all(self):
        items = self._items[self._offset :]
        if self._limit is not None:
            items = items[: self._limit]
        return list(items)

    def first(self):
        items = self.all()
        return items[0] if items else None


class _FakeDB:
    def __init__(self, incidents=None, rules=None):
        self.incidents = list(incidents or [])
        self.rules = list(rules or [])
        self.flushed = 0

    def query(self, model):
        if model is incidents_mod.AlertRuleDB:
            return _FakeQuery(self.rules)
        return _FakeQuery(self.incidents)

    def flush(self):
        self.flushed += 1


@contextmanager
def _db_session(db):
    yield db


def test_incident_storage_helper_functions(monkeypatch):
    assert incidents_mod._json_dict({"a": 1}) == {"a": 1}
    assert incidents_mod._json_dict("bad") == {}

    class FakeRule:
        def __init__(self):
            self.shared_groups = [SimpleNamespace(id="g1"), SimpleNamespace(id="g2")]

    monkeypatch.setattr("services.storage.incidents_core.AlertRuleDB", FakeRule)
    assert incidents_mod._shared_group_ids(FakeRule()) == ["g1", "g2"]
    assert incidents_mod._shared_group_ids(object()) == []

    assert incidents_mod.incident_scope_hint_from_labels({"org_id": "org-1"}) == "org-1"
    assert (
        incidents_mod.incident_key_from_labels({"alertname": "CPUHigh", "product": "api"}) == "rule:CPUHigh|scope:api"
    )
    assert incidents_mod.incident_key_from_labels({}) is None

    row = _incident_row(
        "inc-1",
        annotations={
            incidents_mod.INCIDENT_META_KEY: json.dumps(
                {incidents_mod.INCIDENT_META_KEY_IDENTITY: "rule:CPUHigh|scope:*"}
            )
        },
    )
    assert incidents_mod.incident_key_from_db_row(row) == "rule:CPUHigh|scope:*"
    assert incidents_mod.incident_activity_token_from_row(row).startswith("k:")

    row_no_key = _incident_row("inc-2", alert_name="", labels={})
    assert incidents_mod.incident_key_from_db_row(row_no_key) is None
    assert incidents_mod.incident_activity_token_from_row(row_no_key).startswith("fp:")

    row_fallback = _incident_row(
        "inc-3", annotations={incidents_mod.INCIDENT_META_KEY: "{}"}, labels={"alertname": "DiskFull"}
    )
    assert incidents_mod.incident_key_from_db_row(row_fallback) == "rule:DiskFull|scope:*"
    assert incidents_core_mod._extract_metric_state({"mem_state": "critical"}) == "critical"
    assert incidents_core_mod._parse_metric_states("high,high, low ") == ["high", "low"]
    assert (
        incidents_core_mod._merge_metric_states({incidents_mod.METRIC_STATES_ANNOTATION_KEY: "high"}, "low", "high")
        == "high,low"
    )
    assert incidents_core_mod._is_alert_suppressed({"status": {"state": "suppressed"}}) is True
    assert (
        incidents_mod._incident_access_allowed(
            incidents_mod.AccessCheck(
                visibility="group",
                created_by="owner",
                user_id="user",
                shared_group_ids=["g1"],
                user_group_ids=["g1"],
            )
        )
        is True
    )

    called = []

    async def fake_coro():
        called.append("done")

    incidents_jira_mod._run_async(fake_coro())
    assert called == ["done"]


def test_resolve_incident_jira_credentials(monkeypatch):
    monkeypatch.setattr(incidents_jira_mod, "load_tenant_jira_integrations", lambda tenant_id: [{"id": "jira-1"}])
    monkeypatch.setattr(incidents_jira_mod, "integration_is_usable", lambda item: True)
    monkeypatch.setattr(
        incidents_jira_mod,
        "jira_integration_credentials",
        lambda item: {"base_url": "https://jira.example.com", "token": "x"},
    )
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant-a", "jira-1") == {
        "base_url": "https://jira.example.com",
        "token": "x",
    }

    monkeypatch.setattr(incidents_jira_mod, "integration_is_usable", lambda item: False)
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant-a", "jira-1") is None

    monkeypatch.setattr(
        incidents_jira_mod,
        "get_effective_jira_credentials",
        lambda tenant_id: {"base_url": "https://jira.example.com", "token": "y"},
    )
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant-a", None) == {
        "base_url": "https://jira.example.com",
        "token": "y",
    }

    monkeypatch.setattr(incidents_jira_mod, "get_effective_jira_credentials", lambda tenant_id: {})
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant-a", None) is None


def test_resolve_rule_by_alertname_and_jira_side_effect_error_paths(monkeypatch):
    class _BrokenQuery:
        def filter(self, *_args, **_kwargs):
            raise ValueError("bad filter")

    class _BrokenDB:
        def query(self, *_args, **_kwargs):
            return _BrokenQuery()

    monkeypatch.setattr(
        "services.storage.incidents_core.AlertRuleDB",
        SimpleNamespace(
            tenant_id="tenant_id", name="name", org_id=SimpleNamespace(is_=lambda *_: None, desc=lambda: None)
        ),
    )
    assert incidents_core_mod._resolve_rule_by_alertname(_BrokenDB(), "tenant-a", {"alertname": "CPUHigh"}) is None
    assert incidents_core_mod._resolve_rule_by_alertname(_BrokenDB(), "tenant-a", {}) is None

    from services.jira_service import JiraError

    monkeypatch.setattr(
        incidents_jira_mod, "_resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"}
    )

    def _raise_jira(coro):
        coro.close()
        raise JiraError("boom")

    monkeypatch.setattr(incidents_jira_mod, "_run_async", _raise_jira)
    warnings = []
    monkeypatch.setattr(incidents_jira_mod.logger, "warning", lambda msg, *args: warnings.append(msg % args))
    incident = SimpleNamespace(
        annotations={
            incidents_mod.INCIDENT_META_KEY: json.dumps({"jira_ticket_key": "OPS-1", "jira_integration_id": "jira-1"})
        }
    )
    incidents_jira_mod._move_reopened_incident_jira_ticket_to_todo("tenant-a", incident)
    incidents_jira_mod._sync_reopened_incident_note_to_jira(
        "tenant-a",
        incident,
        note_text="reopened",
        created_at=datetime.now(UTC),
    )
    assert len(warnings) == 2


def test_sync_incidents_from_alerts_dedupe_reopen_and_resolve_missing(monkeypatch):
    service = incidents_mod.IncidentStorageService()
    now = datetime.now(UTC)

    class _RuleObj:
        def __init__(self):
            self.visibility = "group"
            self.created_by = "owner"
            self.group = "grp-a"
            self.shared_groups = [SimpleNamespace(id="g1")]

    canonical = _incident_row(
        "inc-canonical",
        status="resolved",
        labels={"alertname": "CPUHigh", "state": "critical"},
        annotations={},
    )
    canonical.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(
        {"incident_key": "rule:CPUHigh|scope:org-a", "jira_ticket_key": "OPS-1"}
    )
    duplicate = _incident_row(
        "inc-dup",
        status="open",
        labels={"alertname": "CPUHigh", "metric_state": "warning"},
        annotations={},
    )
    duplicate.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps({"incident_key": "rule:CPUHigh|scope:org-a"})
    stale_open = _incident_row(
        "inc-stale",
        status="open",
        labels={"alertname": "DiskFull"},
        annotations={},
    )
    stale_open.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps({"incident_key": "rule:DiskFull|scope:org-a"})

    class _SyncQuery:
        def __init__(self, db, model_name):
            self.db = db
            self.model_name = model_name

        def filter(self, *args, **kwargs):
            return self

        def order_by(self, *args, **kwargs):
            return self

        def options(self, *args, **kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        def first(self):
            if self.model_name == "rule":
                return self.db.rule
            if self.model_name == "incident":
                return None
            return None

        def all(self):
            if self.model_name == "incident":
                self.db.incident_all_calls += 1
                if self.db.incident_all_calls == 1:
                    return [canonical, duplicate]
                return [canonical, stale_open]
            return []

    class _SyncDB:
        def __init__(self):
            self.rule = _RuleObj()
            self.added = []
            self.incident_all_calls = 0

        def query(self, model):
            if model is incidents_mod.AlertRuleDB:
                return _SyncQuery(self, "rule")
            return _SyncQuery(self, "incident")

        def add(self, obj):
            self.added.append(obj)

        def flush(self):
            return None

    db = _SyncDB()
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "ensure_tenant_exists", lambda *_args: None)
    monkeypatch.setattr(incidents_sync_mod, "_is_alert_suppressed", lambda alert: False)
    monkeypatch.setattr(incidents_sync_mod, "_resolve_rule_by_alertname", lambda *_args: db.rule)
    monkeypatch.setattr(
        incidents_sync_mod, "_move_reopened_incident_jira_ticket_to_todo", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(incidents_sync_mod, "_sync_reopened_incident_note_to_jira", lambda *_args, **_kwargs: None)

    alerts = [
        {
            "labels": {"alertname": "CPUHigh", "org_id": "org-a", "severity": "critical", "state": "critical"},
            "annotations": {"summary": "cpu"},
            "startsAt": "invalid-date",
            "fingerprint": "",
        }
    ]
    service.sync_incidents_from_alerts("tenant-a", alerts, resolve_missing=True)

    assert duplicate.status == "resolved"
    assert duplicate.resolved_at is not None
    assert any("deduplicated" in note["text"] for note in duplicate.notes)
    assert canonical.status == "open"
    assert canonical.resolved_at is None
    assert any("reopened" in note["text"].lower() for note in canonical.notes)
    assert stale_open.status == "resolved"
    assert stale_open.resolved_at is not None


def test_incident_service_summary_list_get_update_and_filter(monkeypatch):
    service = incidents_mod.IncidentStorageService()
    rows = [
        _incident_row("public-open", visibility="public", created_by="owner", assignee=None),
        _incident_row("private-open", visibility="private", created_by="user-1", assignee="user-1"),
        _incident_row("group-open", visibility="group", shared_group_ids=["g1"], assignee="other"),
        _incident_row("resolved-hidden", status="resolved", hide_when_resolved=True),
    ]
    rules = [
        SimpleNamespace(
            tenant_id="tenant-a",
            name="CPUHigh",
            visibility="public",
            created_by="owner",
            shared_groups=[],
            org_id=None,
            enabled=True,
        ),
        SimpleNamespace(
            tenant_id="tenant-a",
            name="DiskFull",
            visibility="group",
            created_by="owner",
            shared_groups=[SimpleNamespace(id="g1")],
            org_id="org-1",
            enabled=True,
        ),
    ]
    db = _FakeDB(rows, rules)

    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(
            id=incident.id,
            status=incident.status,
            assignee=incident.assignee,
            annotations=incident.annotations,
            notes=incident.notes,
        ),
    )
    monkeypatch.setattr(
        incidents_mod,
        "has_access",
        lambda check: (
            check.visibility != "private" or check.created_by == check.user_id
        ),
    )

    summary = service.get_incident_summary("tenant-a", "user-1", ["g1"])
    assert summary["open_total"] == 3
    assert summary["unassigned_open"] == 1
    assert summary["assigned_to_me_open"] == 1
    assert summary["by_visibility"]["group"] == 1

    listed = service.list_incidents("tenant-a", "user-1", ["g1"])
    assert [item.id for item in listed] == ["public-open", "private-open", "group-open"]
    assert service.list_incidents("tenant-a", "user-1", ["g1"], visibility="group", group_id="g1")[0].id == "group-open"

    fetched = service.get_incident_for_user(
        "private-open",
        "tenant-a",
        incidents_mod.IncidentAccessContext(user_id="user-1", group_ids=[]),
    )
    assert fetched is not None
    assert (
        service.get_incident_for_user(
            "private-open",
            "tenant-a",
            incidents_mod.IncidentAccessContext(user_id="other", group_ids=[]),
        )
        is None
    )

    update_payload = AlertIncidentUpdateRequest(
        assignee="user-1",
        status="resolved",
        note="handled",
        actorUsername="alice",
        jiraTicketKey="ABC-1",
        jiraTicketUrl="https://jira/browse/ABC-1",
        jiraIntegrationId="jira-1",
        hideWhenResolved=True,
    )
    updated = service.update_incident("public-open", "tenant-a", "user-1", update_payload, ["g1"])
    assert updated is not None
    assert rows[0].status == "resolved"
    assert rows[0].assignee == "user-1"
    assert db.flushed == 1
    meta = incidents_mod.parse_meta(rows[0].annotations)
    assert meta["jira_ticket_key"] == "ABC-1"
    assert meta["hide_when_resolved"] is True
    assert any(note["text"] == "handled" for note in rows[0].notes)
    assert any("marked this incident as resolved" in note["text"] for note in rows[0].notes)

    private_row = rows[1]
    with pytest.raises(HTTPException) as exc:
        service.update_incident(
            "private-open",
            "tenant-a",
            "user-1",
            AlertIncidentUpdateRequest(assignee="other-user"),
            [],
        )
    assert exc.value.status_code == 403
    assert private_row.assignee == "user-1"

    visible_alerts = service.filter_alerts_for_user(
        "tenant-a",
        "user-1",
        ["g1"],
        [
            {"labels": {"alertname": "CPUHigh"}},
            {"labels": {"alertname": "DiskFull", "org_id": "org-1"}},
            {"labels": {}},
        ],
    )
    assert len(visible_alerts) == 2


def test_incident_service_unlink_and_update_edge_paths(monkeypatch):
    service = incidents_mod.IncidentStorageService()

    incident_a = _incident_row(
        "inc-a",
        annotations={},
    )
    incident_a.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(
        {
            "jira_integration_id": "jira-1",
            "jira_ticket_key": "OPS-1",
            "jira_ticket_url": "https://jira/browse/OPS-1",
        }
    )
    incident_b = _incident_row(
        "inc-b",
        annotations={},
    )
    incident_b.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps({"jira_integration_id": "jira-2"})

    class _UnlinkQuery:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return list(self.rows)

        def first(self):
            return self.rows[0] if self.rows else None

    class _UnlinkDB:
        def __init__(self, rows):
            self.rows = rows
            self.flushed = 0

        def query(self, *_args, **_kwargs):
            return _UnlinkQuery(self.rows)

        def flush(self):
            self.flushed += 1

    db = _UnlinkDB([incident_a, incident_b])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    assert service.unlink_jira_integration_from_incidents("tenant-a", "jira-1") == 1
    meta_a = incidents_mod.parse_meta(incident_a.annotations)
    assert "jira_integration_id" not in meta_a
    assert db.flushed == 1
    assert service.unlink_jira_integration_from_incidents("tenant-a", "") == 0

    row = _incident_row("inc-u", visibility="private", created_by="u1", annotations={})
    db = _FakeDB([row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "normalize_storage_visibility", lambda value: value)
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(
            id=incident.id,
            status=incident.status,
            assignee=incident.assignee,
            annotations=incident.annotations,
            notes=incident.notes,
        ),
    )

    payload = AlertIncidentUpdateRequest.model_validate(
        {
            "status": "open",
            "hideWhenResolved": False,
            "jiraTicketKey": "",
            "jiraTicketUrl": "",
            "jiraIntegrationId": "",
            "note": "note-1",
        }
    )
    updated = service.update_incident("inc-u", "tenant-a", "u1", payload, ["g1"])
    assert updated is not None
    meta = incidents_mod.parse_meta(row.annotations)
    assert meta.get("user_managed") is True
    assert "hide_when_resolved" not in meta
    assert "jira_ticket_key" not in meta
    assert any(note["text"] == "note-1" for note in row.notes)

    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: False)
    assert service.update_incident("inc-u", "tenant-a", "u1", AlertIncidentUpdateRequest(), ["g1"]) is None

    missing_db = _FakeDB([])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(missing_db))
    assert service.update_incident("missing", "tenant-a", "u1", AlertIncidentUpdateRequest(), ["g1"]) is None


def test_incident_list_and_filter_additional_edges(monkeypatch):
    service = incidents_mod.IncidentStorageService()
    rows = [
        _incident_row("resolved-hidden", status="resolved", hide_when_resolved=True),
        _incident_row("invalid-vis", visibility="unexpected", created_by="u1", shared_group_ids=[]),
        _incident_row("group-row", visibility="group", created_by="u2", shared_group_ids=["g2"]),
        _incident_row("public-row", visibility="public", created_by="u2"),
    ]
    db = _FakeDB(rows, [])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(id=incident.id),
    )

    listed = service.list_incidents("tenant-a", "u1", ["g1"], status=None, visibility=None, group_id="g1")
    assert [item.id for item in listed] == []

    listed = service.list_incidents("tenant-a", "u1", ["g2"], status="open", visibility="group", group_id="g2")
    assert any(item.id == "group-row" for item in listed)

    # get_incident_for_user not found and access denied branches
    missing_db = _FakeDB([])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(missing_db))
    assert (
        service.get_incident_for_user(
            "missing",
            "tenant-a",
            incidents_mod.IncidentAccessContext(user_id="u1", group_ids=["g1"]),
        )
        is None
    )

    denied_row = _incident_row("inc-denied", visibility="private", created_by="u2")
    denied_db = _FakeDB([denied_row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(denied_db))
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: False)
    assert (
        service.get_incident_for_user(
            "inc-denied",
            "tenant-a",
            incidents_mod.IncidentAccessContext(user_id="u1", group_ids=["g1"], require_write=True),
        )
        is None
    )

    # filter_alerts_for_user empty alerts and no candidates
    empty_db = _FakeDB([], [])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(empty_db))
    assert service.filter_alerts_for_user("tenant-a", "u1", ["g1"], []) == []
    out = service.filter_alerts_for_user("tenant-a", "u1", ["g1"], [{"labels": {"alertname": "NoRule"}}])
    assert out == []


def test_sync_incidents_from_alerts_additional_branch_edges(monkeypatch):
    service = incidents_mod.IncidentStorageService()
    now = datetime.now(UTC)

    canonical = _incident_row(
        "inc-canon",
        status="open",
        labels={"alertname": "CPUHigh", "state": "critical"},
        annotations={},
    )
    canonical.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(
        {incidents_mod.INCIDENT_META_KEY_IDENTITY: "rule:CPUHigh|scope:org-a"}
    )
    duplicate_resolved = _incident_row(
        "inc-resolved-dup",
        status="resolved",
        labels="not-a-dict",
        annotations={},
    )
    duplicate_resolved.resolved_at = now
    duplicate_resolved.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(
        {incidents_mod.INCIDENT_META_KEY_IDENTITY: "rule:CPUHigh|scope:org-a"}
    )
    existing_by_fp = _incident_row(
        "inc-by-fp",
        status="open",
        labels={"severity": "warning"},
        fingerprint="fp-no-key",
        annotations={},
    )
    existing_by_fp.resolved_at = now
    existing_by_fp.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(
        {"user_managed": True, "correlation_id": ""}
    )

    class _SyncQuery:
        def __init__(self, db):
            self._db = db

        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def options(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        def all(self):
            self._db.incident_all_calls += 1
            if self._db.incident_all_calls == 1:
                return [canonical, duplicate_resolved]
            return []

        def first(self):
            self._db.incident_first_calls += 1
            if self._db.incident_first_calls == 1:
                return existing_by_fp
            return None

    class _SyncDB:
        def __init__(self):
            self.incident_all_calls = 0
            self.incident_first_calls = 0

        def query(self, *_args, **_kwargs):
            return _SyncQuery(self)

        def add(self, *_args, **_kwargs):
            return None

    db = _SyncDB()
    rule = SimpleNamespace(visibility="group", created_by=None, group="", shared_groups=[])

    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "ensure_tenant_exists", lambda *_args: None)
    monkeypatch.setattr(incidents_sync_mod, "_is_alert_suppressed", lambda *_args: False)
    monkeypatch.setattr(incidents_sync_mod, "_resolve_rule_by_alertname", lambda *_args: rule)

    alerts = [
        {
            "labels": {"alertname": "CPUHigh", "org_id": "org-a", "severity": "critical"},
            "annotations": {"summary": "cpu"},
            "fingerprint": "fp-canon",
        },
        {
            "labels": {"severity": "warning"},
            "annotations": {"summary": "fallback"},
            "fingerprint": "fp-no-key",
        },
    ]
    service.sync_incidents_from_alerts("tenant-a", alerts, resolve_missing=False)

    assert duplicate_resolved.resolved_at == now
    assert any("metric state: unknown" in n["text"] for n in duplicate_resolved.notes)

    fallback_meta = incidents_mod.parse_meta(existing_by_fp.annotations)
    assert "user_managed" not in fallback_meta
    assert "created_by" not in fallback_meta
    assert existing_by_fp.assignee is None


def test_incident_get_update_filter_remaining_branches(monkeypatch):
    service = incidents_mod.IncidentStorageService()

    row = _incident_row("inc-1", visibility="public", created_by="u1", annotations={})
    db = _FakeDB([row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    access_called = {"value": False}

    def _access_probe(_check):
        access_called["value"] = True
        return True

    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", _access_probe)
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(id=incident.id),
    )
    assert (
        service.get_incident_for_user(
            "inc-1",
            "tenant-a",
            incidents_mod.IncidentAccessContext(user_id="", group_ids=["g1"]),
        )
        is not None
    )
    assert access_called["value"] is False


def test_update_incident_uses_explicit_actor_inputs(monkeypatch):
    service = incidents_mod.IncidentStorageService()
    row = _incident_row("inc-actor", annotations={})
    db = _FakeDB([row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "normalize_storage_visibility", lambda value: value)
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(id=incident.id),
    )

    payload = AlertIncidentUpdateRequest(status="open")
    updated = service.update_incident(
        "inc-actor",
        "tenant-a",
        "u1",
        payload,
        ["g1"],
        "u1@example.com",
    )
    assert updated is not None
    assert row.status == "open"

    resolved_row = _incident_row(
        "inc-resolved", status="resolved", visibility="public", created_by="u1", annotations={}
    )
    resolved_row.notes = [{"author": "u1", "text": "existing", "createdAt": datetime.now(UTC).isoformat()}]
    db = _FakeDB([resolved_row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "normalize_storage_visibility", lambda value: value)
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(id=incident.id, status=incident.status),
    )
    before_notes = list(resolved_row.notes)
    updated = service.update_incident(
        "inc-resolved",
        "tenant-a",
        "u1",
        AlertIncidentUpdateRequest(status="resolved"),
        ["g1"],
    )
    assert updated is not None
    assert resolved_row.notes == before_notes

    ack_row = _incident_row("inc-ack", status="open", visibility="public", created_by="u1", annotations={})
    db = _FakeDB([ack_row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    service.update_incident(
        "inc-ack",
        "tenant-a",
        "u1",
        AlertIncidentUpdateRequest(status="acknowledged"),
        ["g1"],
    )
    ack_meta = incidents_mod.parse_meta(ack_row.annotations)
    assert "user_managed" not in ack_meta
    assert ack_row.status == "acknowledged"

    no_status_row = _incident_row("inc-no-status", status="open", visibility="public", created_by="u1", annotations={})
    db = _FakeDB([no_status_row])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    service.update_incident(
        "inc-no-status",
        "tenant-a",
        "u1",
        AlertIncidentUpdateRequest(),
        ["g1"],
    )
    assert no_status_row.status == "open"

    rule = SimpleNamespace(
        tenant_id="tenant-a",
        name="CPUHigh",
        org_id=None,
        enabled=True,
        visibility="private",
        created_by="owner",
        shared_groups=[],
    )
    db = _FakeDB([], [rule])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "has_access", lambda *_args, **_kwargs: False)
    hidden = service.filter_alerts_for_user(
        "tenant-a",
        "u1",
        ["g1"],
        [{"labels": {"alertname": "CPUHigh"}}],
    )
    assert hidden == []


def test_unlink_jira_integration_no_updates_keeps_count_zero(monkeypatch):
    service = incidents_mod.IncidentStorageService()

    incident = _incident_row("inc-x", annotations={})
    incident.annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps({"jira_integration_id": "jira-other"})

    class _UnlinkQuery:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return list(self.rows)

    class _UnlinkDB:
        def __init__(self, rows):
            self.rows = rows
            self.flushed = 0

        def query(self, *_args, **_kwargs):
            return _UnlinkQuery(self.rows)

        def flush(self):
            self.flushed += 1

    db = _UnlinkDB([incident])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    assert service.unlink_jira_integration_from_incidents("tenant-a", "jira-1") == 0
    assert db.flushed == 0
