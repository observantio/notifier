"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.channels import NotificationChannelCreate
from models.alerting.incidents import AlertIncidentUpdateRequest
from models.alerting.rules import AlertRuleCreate, RuleSeverity
from services.storage import channels as channels_mod
from services.storage import incidents as incidents_mod
from services.storage import incidents_core as incidents_core_mod
from services.storage import incidents_jira as incidents_jira_mod
from services.storage import incidents_sync as incidents_sync_mod
from services.storage import rules as rules_mod


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def options(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def join(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def offset(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def all(self):
        if self.rows is None:
            return []
        if isinstance(self.rows, list):
            return self.rows
        return [self.rows]

    def first(self):
        if isinstance(self.rows, list):
            return self.rows[0] if self.rows else None
        return self.rows


class FakeDB:
    def __init__(self, *results):
        self.results = list(results)
        self.added = []
        self.deleted = []
        self.flush_count = 0

    def query(self, *_args, **_kwargs):
        rows = self.results.pop(0) if self.results else None
        return FakeQuery(rows)

    def add(self, obj):
        self.added.append(obj)

    def delete(self, obj):
        self.deleted.append(obj)

    def flush(self):
        self.flush_count += 1


class FakeCtx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, *args):
        return False


def _rule(**kwargs):
    payload = {
        "id": "rule-1",
        "tenant_id": "tenant",
        "name": "CPUHigh",
        "org_id": None,
        "created_by": "owner",
        "visibility": "private",
        "shared_groups": [],
        "enabled": True,
        "group": "compute",
        "expr": "up == 0",
        "duration": "5m",
        "severity": "warning",
        "labels": {},
        "annotations": {},
        "notification_channels": [],
    }
    payload.update(kwargs)
    return SimpleNamespace(**payload)


def _channel(**kwargs):
    payload = {
        "id": "chan-1",
        "tenant_id": "tenant",
        "created_by": "owner",
        "name": "Email",
        "type": "email",
        "config": {"token": "enc"},
        "enabled": True,
        "visibility": "private",
        "shared_groups": [],
    }
    payload.update(kwargs)
    return SimpleNamespace(**payload)


def test_rule_helpers_and_delivery_lookup(monkeypatch):
    svc = rules_mod.RuleStorageService()
    assert rules_mod.RuleStorageService._page_request(None).limit is None
    assert rules_mod.RuleStorageService._access_context("user-1", ["g1"]).group_ids == ["g1"]
    existing_access = rules_mod.RuleAccessContext(user_id="u2", group_ids=["g2"])
    assert rules_mod.RuleStorageService._access_context(existing_access) is existing_access
    shared = SimpleNamespace(id="g1")
    rule_private = _rule(shared_groups=[shared])
    assert rules_mod._shared_group_ids(rule_private) == ["g1"]
    assert rules_mod._visibility_of(rule_private) == "private"
    assert rules_mod._creator_of(rule_private) == "owner"

    monkeypatch.setattr(
        rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "org_id": getattr(obj, "org_id", None)}
    )

    db = FakeDB([])
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "") is None
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "CPUHigh") is None

    org_rule = _rule(id="rule-org", org_id="org-1")
    fallback_rule = _rule(id="rule-fallback", org_id=None)
    db = FakeDB([fallback_rule, org_rule])
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "CPUHigh") == {"id": "rule-fallback", "org_id": None}

    db = FakeDB([fallback_rule, org_rule])
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "CPUHigh", org_id="org-1") == {
        "id": "rule-org",
        "org_id": "org-1",
    }


def test_rule_storage_crud_and_visibility(monkeypatch):
    svc = rules_mod.RuleStorageService()
    rule1 = _rule(id="rule-1", visibility="public")
    rule2 = _rule(id="rule-2", visibility="group", shared_groups=[SimpleNamespace(id="g2")])
    access_calls = []

    def fake_has_access(check):
        access_calls.append(
            (
                check.visibility,
                check.created_by,
                check.user_id,
                tuple(check.shared_group_ids),
                tuple(check.user_group_ids),
                check.require_write,
            )
        )
        if check.require_write:
            return check.visibility != "group"
        return check.visibility != "group"

    monkeypatch.setattr(rules_mod, "has_access", fake_has_access)
    monkeypatch.setattr(rules_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "visibility": obj.visibility})

    db = FakeDB([("rule-1",)], [("CPUHigh",)], [rule1, rule2], [rule1, rule2], [rule1, rule2], rule1, rule2)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))

    assert svc.get_hidden_rule_ids("tenant", "user") == ["rule-1"]
    assert svc.get_hidden_rule_names("tenant", "user") == ["CPUHigh"]
    assert svc.get_public_alert_rules("tenant") == [
        {"id": "rule-1", "visibility": "public"},
        {"id": "rule-2", "visibility": "group"},
    ]
    assert svc.get_alert_rules(
        "tenant",
        rules_mod.RuleAccessContext(user_id="user", group_ids=["g1"]),
        rules_mod.PageRequest(limit=10, offset=2),
    ) == [
        {"id": "rule-1", "visibility": "public"}
    ]
    assert svc.get_alert_rules_with_owner(
        "tenant",
        rules_mod.RuleAccessContext(user_id="user", group_ids=["g1"]),
        rules_mod.PageRequest(limit=10, offset=2),
    ) == [
        ({"id": "rule-1", "visibility": "public"}, "owner")
    ]
    assert svc.get_alert_rule_raw("rule-1", "tenant") is rule1
    assert svc.get_alert_rule("rule-2", "tenant", "user", ["g1"]) is None
    assert access_calls

    missing_db = FakeDB(None, _rule(id="rule-hide"), None, _rule(id="rule-show"), SimpleNamespace(id="existing"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(missing_db))
    assert svc.toggle_rule_hidden("tenant", "user", "missing", True) is False
    assert svc.toggle_rule_hidden("tenant", "user", "rule-hide", True) is True
    assert len(missing_db.added) == 1
    assert svc.toggle_rule_hidden("tenant", "user", "rule-show", False) is True
    assert len(missing_db.deleted) == 1

    noop_db = FakeDB(
        _rule(id="rule-existing-hidden"), SimpleNamespace(id="already-hidden"), _rule(id="rule-not-hidden"), None
    )
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(noop_db))
    assert svc.toggle_rule_hidden("tenant", "user", "rule-existing-hidden", True) is True
    assert svc.toggle_rule_hidden("tenant", "user", "rule-not-hidden", False) is True
    assert noop_db.added == []
    assert noop_db.deleted == []

    assign_calls = []
    monkeypatch.setattr(rules_mod, "ensure_tenant_exists", lambda *_args: assign_calls.append("tenant"))
    monkeypatch.setattr(
        rules_mod,
        "assign_shared_groups",
        lambda obj, *_args, **kwargs: assign_calls.append((obj.visibility, tuple(kwargs.get("actor_group_ids") or []))),
    )
    monkeypatch.setattr(
        rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "name": obj.name, "visibility": obj.visibility}
    )

    create_db = FakeDB()
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(create_db))
    created = svc.create_alert_rule(
        AlertRuleCreate.model_validate(
            {
                "name": "MemHigh",
                "expression": "mem > 90",
                "severity": RuleSeverity.CRITICAL,
                "groupName": "infra",
                "notificationChannels": ["chan-1"],
                "visibility": "group",
                "sharedGroupIds": ["g1"],
            }
        ),
        "tenant",
        "owner",
        ["g1"],
    )
    assert created["visibility"] == "group"
    assert create_db.flush_count == 1

    update_target = _rule(id="rule-1", visibility="private")
    update_db = FakeDB(update_target)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(update_db))
    denied = svc.update_alert_rule(
        "rule-1",
        AlertRuleCreate.model_validate({"name": "New", "expression": "up", "severity": "warning", "groupName": "g"}),
        "tenant",
        rules_mod.RuleAccessContext(user_id="owner", group_ids=["g1"]),
    )
    assert denied["name"] == "New"

    monkeypatch.setattr(rules_mod, "has_access", lambda check: not check.require_write)
    blocked_db = FakeDB(_rule(id="rule-2", visibility="private"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(blocked_db))
    assert svc.delete_alert_rule("rule-2", "tenant", rules_mod.RuleAccessContext(user_id="owner", group_ids=["g1"])) is False

    monkeypatch.setattr(rules_mod, "has_access", lambda _check: True)
    delete_db = FakeDB(_rule(id="rule-3", visibility="private"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(delete_db))
    assert svc.delete_alert_rule("rule-3", "tenant", rules_mod.RuleAccessContext(user_id="owner", group_ids=["g1"])) is True
    assert len(delete_db.deleted) == 1


def test_channel_helpers_and_storage_branches(monkeypatch):
    svc = channels_mod.ChannelStorageService()
    assert channels_mod.ChannelStorageService._page_request(None).offset == 0
    assert channels_mod.ChannelStorageService._access_context("user-1", ["g1"]).group_ids == ["g1"]
    existing_access = channels_mod.ChannelAccessContext(user_id="u2", group_ids=["g2"])
    assert channels_mod.ChannelStorageService._access_context(existing_access) is existing_access
    private_rule = _rule(visibility="private", created_by="owner")
    private_channel = _channel(visibility="private", created_by="owner")
    other_channel = _channel(id="chan-2", visibility="private", created_by="other")
    tenant_channel = _channel(id="chan-tenant", visibility="tenant")
    group_rule = _rule(visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    group_channel = _channel(visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    other_group_channel = _channel(id="chan-4", visibility="group", shared_groups=[SimpleNamespace(id="g2")])
    public_channel = _channel(id="chan-3", visibility="public")

    assert channels_mod._shared_group_ids(group_channel) == ["g1"]
    assert channels_mod._visibility_of(private_channel) == "private"
    assert channels_mod._creator_of(private_channel) == "owner"
    assert channels_mod._config_dict(private_channel) == {"token": "enc"}
    assert svc._rule_channel_compatible(private_rule, private_channel) is True
    assert svc._rule_channel_compatible(private_rule, other_channel) is False
    assert svc._rule_channel_compatible(private_rule, tenant_channel) is False
    assert svc._rule_channel_compatible(group_rule, group_channel) is True
    assert svc._rule_channel_compatible(group_rule, other_group_channel) is False
    assert svc._rule_channel_compatible(group_rule, private_channel) is True
    assert svc._rule_channel_compatible(group_rule, public_channel) is False
    assert svc._rule_channel_compatible(_rule(visibility="public"), public_channel) is True
    assert svc._rule_channel_compatible(_rule(visibility="public"), private_channel) is True
    assert svc._rule_channel_compatible(_rule(visibility="public"), group_channel) is True

    monkeypatch.setattr(channels_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(channels_mod, "has_access", lambda check: check.visibility != "group")
    monkeypatch.setattr(channels_mod, "decrypt_config", lambda cfg: {**cfg, "decrypted": True})
    monkeypatch.setattr(channels_mod, "encrypt_config", lambda cfg: {**cfg, "encrypted": True})
    monkeypatch.setattr(channels_mod, "channel_to_pydantic", lambda obj: {"id": obj.id, "config": obj.config})
    monkeypatch.setattr(
        channels_mod,
        "channel_to_pydantic_for_viewer",
        lambda obj, user_id, include_sensitive=False: {
            "id": obj.id,
            "user": user_id,
            "config": obj.config,
            "include_sensitive": include_sensitive,
        },
    )
    monkeypatch.setattr(channels_mod, "ensure_tenant_exists", lambda *_args: None)
    monkeypatch.setattr(channels_mod, "assign_shared_groups", lambda *_args, **_kwargs: None)

    db = FakeDB([private_channel, group_channel], private_channel)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(db))
    listed = svc.get_notification_channels(
        "tenant",
        channels_mod.ChannelAccessContext(user_id="user", group_ids=["g1"]),
        channels_mod.PageRequest(limit=10, offset=1),
    )
    assert listed == [
        {
            "id": "chan-1",
            "user": "user",
            "config": {"token": "enc", "decrypted": True},
            "include_sensitive": False,
        }
    ]
    assert svc.get_notification_channel("chan-1", "tenant", "user", ["g1"])["id"] == "chan-1"

    missing_db = FakeDB(None)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(missing_db))
    assert svc.get_notification_channel("missing", "tenant", "user", ["g1"]) is None

    denied_db = FakeDB(group_channel)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(denied_db))
    assert svc.get_notification_channel("chan-2", "tenant", "user", ["g2"]) is None

    create_db = FakeDB()
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(create_db))
    created = svc.create_notification_channel(
        NotificationChannelCreate.model_validate(
            {
                "name": "Slack",
                "type": "slack",
                "config": {"webhook": "url"},
                "visibility": "group",
                "sharedGroupIds": ["g1"],
            }
        ),
        "tenant",
        "owner",
        ["g1"],
    )
    assert created["user"] == "owner"
    assert create_db.flush_count == 1

    update_target = _channel(id="chan-1", created_by="owner")
    update_db = FakeDB(update_target)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(update_db))
    updated = svc.update_notification_channel(
        "chan-1",
        NotificationChannelCreate.model_validate({"name": "Teams", "type": "teams", "config": {"hook": "1"}}),
        "tenant",
        channels_mod.ChannelAccessContext(user_id="owner", group_ids=["g1"]),
    )
    assert updated["id"] == "chan-1"

    missing_update_db = FakeDB(_channel(id="chan-2", created_by="other"))
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(missing_update_db))
    assert (
        svc.update_notification_channel(
            "chan-2",
            NotificationChannelCreate.model_validate({"name": "Nope", "type": "email", "config": {}}),
            "tenant",
            channels_mod.ChannelAccessContext(user_id="owner"),
        )
        is None
    )

    delete_db = FakeDB(
        _channel(id="chan-1", created_by="owner"),
        _channel(id="chan-3", created_by="other"),
        _channel(id="chan-4", created_by="owner"),
    )
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(delete_db))
    assert svc.delete_notification_channel("chan-1", "tenant", channels_mod.ChannelAccessContext(user_id="owner")) is True
    assert svc.delete_notification_channel("chan-3", "tenant", channels_mod.ChannelAccessContext(user_id="owner")) is False

    owner_db = FakeDB(_channel(id="chan-3", created_by="other"), _channel(id="chan-4", created_by="owner"))
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(owner_db))
    assert svc.is_notification_channel_owner("chan-3", "tenant", channels_mod.ChannelAccessContext(user_id="owner")) is False
    assert svc.is_notification_channel_owner("chan-4", "tenant", channels_mod.ChannelAccessContext(user_id="owner")) is True

    monkeypatch.setattr(
        channels_mod.ChannelStorageService,
        "get_notification_channel",
        staticmethod(lambda *_args, **_kwargs: None),
    )
    assert svc.test_notification_channel("chan-1", "tenant", channels_mod.ChannelAccessContext(user_id="owner")) == {
        "success": False,
        "error": "Channel not found",
    }
    monkeypatch.setattr(
        channels_mod.ChannelStorageService,
        "get_notification_channel",
        staticmethod(lambda *_args, **_kwargs: SimpleNamespace(name="Slack", type="slack")),
    )
    assert svc.test_notification_channel("chan-1", "tenant", channels_mod.ChannelAccessContext(user_id="owner"))[
        "success"
    ] is True

    rule_with_specific = _rule(id="rule-a", notification_channels=["chan-1", "missing", "chan-2"], visibility="private")
    rule_no_specific = _rule(
        id="rule-b", notification_channels=[], visibility="group", shared_groups=[SimpleNamespace(id="g1")]
    )
    ch1 = _channel(id="chan-1", visibility="private", created_by="owner")
    ch2 = _channel(id="chan-2", visibility="private", created_by="other", enabled=False)
    ch3 = _channel(id="chan-3", visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    ch4 = _channel(id="chan-4", visibility="public")
    delivery_db = FakeDB([rule_with_specific, rule_no_specific], [ch1, ch2, ch3, ch4])
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(delivery_db))
    delivered = svc.get_notification_channels_for_rule_name("tenant", "CPUHigh", org_id="org-x")
    assert delivered == [
        {"id": "chan-1", "config": {"token": "enc", "decrypted": True}},
        {"id": "chan-3", "config": {"token": "enc", "decrypted": True}},
    ]

    no_rules_db = FakeDB([])
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(no_rules_db))
    assert svc.get_notification_channels_for_rule_name("tenant", "MissingRule") == []

    incompatible_rule = _rule(
        id="rule-incompatible", notification_channels=["chan-x"], visibility="private", created_by="owner"
    )
    incompatible_channel = _channel(id="chan-x", visibility="private", created_by="someone-else", enabled=True)
    incompatible_db = FakeDB([incompatible_rule], [incompatible_channel])
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(incompatible_db))
    assert svc.get_notification_channels_for_rule_name("tenant", "CPUHigh") == []


def test_rule_storage_additional_edges(monkeypatch):
    svc = rules_mod.RuleStorageService()
    monkeypatch.setattr(
        rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "name": obj.name, "org": getattr(obj, "org_id", None)}
    )

    db = FakeDB([_rule(id="r-org", org_id="org-1", name="CPUHigh")])
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rules_for_org("tenant", "org-1") == [{"id": "r-org", "name": "CPUHigh", "org": "org-1"}]

    db = FakeDB(None)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule("missing", "tenant", "user", ["g1"]) is None

    monkeypatch.setattr(rules_mod, "has_access", lambda _check: True)
    db = FakeDB(_rule(id="r-visible", name="Visible"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule("r-visible", "tenant", "user", ["g1"]) == {
        "id": "r-visible",
        "name": "Visible",
        "org": None,
    }

    db = FakeDB(None)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert (
        svc.update_alert_rule(
            "missing",
            AlertRuleCreate.model_validate(
                {"name": "New", "expression": "up", "severity": "warning", "groupName": "g"}
            ),
            "tenant",
            rules_mod.RuleAccessContext(user_id="user", group_ids=["g1"]),
        )
        is None
    )

    monkeypatch.setattr(rules_mod, "has_access", lambda _check: False)
    db = FakeDB(_rule(id="r-no-read"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert (
        svc.update_alert_rule(
            "r-no-read",
            AlertRuleCreate.model_validate(
                {"name": "New", "expression": "up", "severity": "warning", "groupName": "g"}
            ),
            "tenant",
            rules_mod.RuleAccessContext(user_id="user", group_ids=["g1"]),
        )
        is None
    )

    monkeypatch.setattr(rules_mod, "has_access", lambda check: not check.require_write)
    db = FakeDB(_rule(id="r-no-write"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert (
        svc.update_alert_rule(
            "r-no-write",
            AlertRuleCreate.model_validate(
                {"name": "New", "expression": "up", "severity": "warning", "groupName": "g"}
            ),
            "tenant",
            rules_mod.RuleAccessContext(user_id="user", group_ids=["g1"]),
        )
        is None
    )

    db = FakeDB(None)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.delete_alert_rule("missing", "tenant", rules_mod.RuleAccessContext(user_id="user", group_ids=["g1"])) is False


def test_incident_run_async_falls_back_to_new_loop(monkeypatch):
    events = []

    async def noop():
        return None

    def fake_asyncio_run(_coro):
        raise RuntimeError("loop running")

    class FakeLoop:
        def run_until_complete(self, coro):
            events.append("run")
            coro.close()

        def close(self):
            events.append("close")

    monkeypatch.setattr(incidents_jira_mod.asyncio, "run", fake_asyncio_run)
    monkeypatch.setattr(incidents_jira_mod.asyncio, "new_event_loop", lambda: FakeLoop())

    incidents_jira_mod._run_async(noop())

    assert events == ["run", "close"]


@pytest.mark.asyncio
async def test_incident_helpers_and_jira_side_effects(monkeypatch):
    class FakeAlertRule:
        def __init__(self, shared_groups):
            self.shared_groups = shared_groups

    monkeypatch.setattr("services.storage.incidents_core.AlertRuleDB", FakeAlertRule)
    shared_rule = FakeAlertRule([SimpleNamespace(id="g1")])
    incident_row = SimpleNamespace(
        annotations={incidents_mod.INCIDENT_META_KEY: '{"incident_key":"rule:CPU|scope:tenant-a"}'},
        labels={"alertname": "CPU", "org_id": "tenant-a"},
        alert_name="CPU",
        fingerprint="fp-1",
    )

    assert incidents_mod._json_dict({"a": 1}) == {"a": 1}
    assert incidents_mod._json_dict("x") == {}
    assert incidents_mod._shared_group_ids(shared_rule) == ["g1"]
    assert incidents_mod.incident_scope_hint_from_labels({"org_id": "tenant-a"}) == "tenant-a"
    assert (
        incidents_mod.incident_key_from_labels({"alertname": "CPU", "org_id": "tenant-a"}) == "rule:CPU|scope:tenant-a"
    )
    assert incidents_mod.incident_key_from_labels({"severity": "warning"}) is None
    assert incidents_mod.incident_key_from_db_row(incident_row) == "rule:CPU|scope:tenant-a"
    assert incidents_mod.incident_activity_token_from_row(incident_row) == "k:rule:CPU|scope:tenant-a"
    assert incidents_core_mod._extract_metric_state({"metric_state": "critical"}) == "critical"
    assert incidents_core_mod._parse_metric_states("a, b,a,,c") == ["a", "b", "c"]
    assert (
        incidents_core_mod._merge_metric_states({incidents_mod.METRIC_STATES_ANNOTATION_KEY: "warn"}, "warn", "crit")
        == "warn,crit"
    )
    monkeypatch.setattr(
        "services.storage.incidents_core.is_suppressed_status", lambda status: status == {"state": "suppressed"}
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

    usable_integration = {"id": "jira-1", "base_url": "https://jira", "username": "u"}
    monkeypatch.setattr(incidents_jira_mod, "load_tenant_jira_integrations", lambda _tenant: [usable_integration])
    monkeypatch.setattr(incidents_jira_mod, "integration_is_usable", lambda item: bool(item.get("base_url")))
    monkeypatch.setattr(
        incidents_jira_mod,
        "jira_integration_credentials",
        lambda item: {"base_url": item["base_url"], "user": item["username"]},
    )
    monkeypatch.setattr(
        incidents_jira_mod,
        "get_effective_jira_credentials",
        lambda _tenant: {"base_url": "https://tenant-jira", "token": "x"},
    )
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant", "jira-1") == {
        "base_url": "https://jira",
        "user": "u",
    }
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant", None) == {
        "base_url": "https://tenant-jira",
        "token": "x",
    }

    notes = []

    async def fake_transition_issue_to_todo(**kwargs):
        notes.append(("todo", kwargs))

    async def fake_add_comment(**kwargs):
        notes.append(("comment", kwargs))

    monkeypatch.setattr(
        incidents_jira_mod, "_resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"}
    )

    def fake_run_async(coro):
        notes.append((coro.cr_code.co_name, None))
        coro.close()

    monkeypatch.setattr(incidents_jira_mod, "_run_async", fake_run_async)
    monkeypatch.setattr(incidents_jira_mod.jira_service, "transition_issue_to_todo", fake_transition_issue_to_todo)
    monkeypatch.setattr(incidents_jira_mod.jira_service, "add_comment", fake_add_comment)
    jira_incident = SimpleNamespace(
        annotations={incidents_mod.INCIDENT_META_KEY: '{"jira_ticket_key":"ABC-1","jira_integration_id":"jira-1"}'},
    )
    incidents_jira_mod._move_reopened_incident_jira_ticket_to_todo("tenant", jira_incident)
    incidents_jira_mod._sync_reopened_incident_note_to_jira(
        "tenant",
        jira_incident,
        note_text="Reopened",
        created_at=datetime(2024, 1, 1, tzinfo=UTC),
    )
    assert notes[0][0] == "fake_transition_issue_to_todo"
    assert notes[1][0] == "fake_add_comment"

    monkeypatch.setattr(incidents_jira_mod, "_resolve_incident_jira_credentials", lambda *_args: None)
    incidents_jira_mod._move_reopened_incident_jira_ticket_to_todo("tenant", jira_incident)
    incidents_jira_mod._sync_reopened_incident_note_to_jira(
        "tenant",
        jira_incident,
        note_text="Ignored",
        created_at=datetime.now(UTC),
    )


def test_incident_update_private_assignment_guard(monkeypatch):
    svc = incidents_mod.IncidentStorageService()
    incident = SimpleNamespace(
        id="inc-1",
        tenant_id="tenant",
        status="open",
        assignee=None,
        annotations={incidents_mod.INCIDENT_META_KEY: '{"visibility":"private","created_by":"owner"}'},
    )
    db = FakeDB(incident)
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(db))
    monkeypatch.setattr(incidents_mod, "normalize_storage_visibility", lambda value: value)
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    with pytest.raises(HTTPException) as exc:
        svc.update_incident(
            "inc-1",
            "tenant",
            "owner",
            AlertIncidentUpdateRequest(assignee="someone-else"),
            [],
        )
    assert exc.value.status_code == 403


def test_incident_storage_additional_edges(monkeypatch):
    svc = incidents_mod.IncidentStorageService()

    fallback_incident = SimpleNamespace(annotations={}, labels={}, alert_name="", fingerprint="fp-fallback")
    assert incidents_mod.incident_activity_token_from_row(fallback_incident) == "fp:fp-fallback"

    alert_name_fallback_incident = SimpleNamespace(annotations={}, labels={}, alert_name="CPUHigh")
    assert incidents_mod.incident_key_from_db_row(alert_name_fallback_incident) == "rule:CPUHigh|scope:*"

    monkeypatch.setattr(incidents_jira_mod, "load_tenant_jira_integrations", lambda _tenant: [{"id": "other"}])
    monkeypatch.setattr(incidents_jira_mod, "get_effective_jira_credentials", lambda _tenant: {})
    assert incidents_jira_mod._resolve_incident_jira_credentials("tenant", "target") is None

    no_ticket_incident = SimpleNamespace(annotations={incidents_mod.INCIDENT_META_KEY: "{}"})
    incidents_jira_mod._move_reopened_incident_jira_ticket_to_todo("tenant", no_ticket_incident)
    incidents_jira_mod._sync_reopened_incident_note_to_jira(
        "tenant",
        no_ticket_incident,
        note_text="ignored",
        created_at=datetime.now(UTC),
    )

    summary_incident = SimpleNamespace(
        annotations={incidents_mod.INCIDENT_META_KEY: '{"visibility":"weird","created_by":"owner"}'},
        status="open",
        assignee=None,
    )
    summary_db = FakeDB([summary_incident])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(summary_db))
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: False)
    summary = svc.get_incident_summary("tenant", "user", ["g1"])
    assert summary["open_total"] == 0

    existing_incident = SimpleNamespace(
        id="inc-1",
        tenant_id="tenant",
        alert_name="CPU",
        severity="warning",
        status="open",
        labels={"alertname": "CPU"},
        annotations={incidents_mod.INCIDENT_META_KEY: '{"incident_key":"rule:CPU|scope:*"}'},
        starts_at=None,
        last_seen_at=None,
        resolved_at=None,
        notes=[],
        assignee=None,
        fingerprint="fp-1",
    )
    managed_incident = SimpleNamespace(
        annotations={incidents_mod.INCIDENT_META_KEY: '{"user_managed": true}'},
        status="open",
        resolved_at=None,
        labels={},
        alert_name="",
        fingerprint="fp-managed",
    )
    sync_db = FakeDB([existing_incident], None, [managed_incident])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(sync_db))
    monkeypatch.setattr(incidents_mod, "ensure_tenant_exists", lambda *_args: None)
    monkeypatch.setattr(incidents_sync_mod, "_is_alert_suppressed", lambda _alert: False)

    svc.sync_incidents_from_alerts(
        "tenant",
        [{"labels": {"alertname": "CPU"}, "annotations": {}, "startsAt": "2026-01-01T00:00:00Z"}],
        resolve_missing=True,
    )
    assert existing_incident.starts_at is not None

    incident_private = SimpleNamespace(
        id="inc-private",
        annotations={incidents_mod.INCIDENT_META_KEY: '{"visibility":"private","created_by":"owner"}'},
        status="open",
        updated_at=datetime.now(UTC),
    )
    list_db = FakeDB([incident_private])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(list_db))
    monkeypatch.setattr(incidents_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: False)
    assert svc.list_incidents("tenant", "user", ["g1"]) == []

    incident_public = SimpleNamespace(
        id="inc-public",
        annotations={incidents_mod.INCIDENT_META_KEY: '{"visibility":"public","created_by":"owner"}'},
        status="open",
        updated_at=datetime.now(UTC),
    )
    list_db = FakeDB([incident_public])
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(list_db))
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(incidents_mod, "incident_to_pydantic", lambda incident: {"id": incident.id})
    assert svc.list_incidents("tenant", "user", ["g1"], group_id=None) == [{"id": "inc-public"}]
    assert svc.list_incidents("tenant", "user", ["g1"], group_id="g1") == []

    invalid_visibility_incident = SimpleNamespace(
        id="inc-invalid-visibility",
        annotations={incidents_mod.INCIDENT_META_KEY: '{"visibility":"invalid","created_by":"owner"}'},
    )
    get_db = FakeDB(invalid_visibility_incident)
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(get_db))
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(incidents_mod, "incident_to_pydantic", lambda incident: {"id": incident.id})
    assert svc.get_incident_for_user(
        "inc-invalid-visibility",
        "tenant",
        incidents_mod.IncidentAccessContext(user_id="user"),
    ) == {
        "id": "inc-invalid-visibility"
    }

    incident_for_update = SimpleNamespace(
        id="inc-update",
        tenant_id="tenant",
        status="open",
        assignee=None,
        annotations={},
        notes=[],
        resolved_at=None,
    )
    update_db = FakeDB(incident_for_update)
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(update_db))
    monkeypatch.setattr(incidents_mod, "normalize_storage_visibility", lambda value: value)
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda _check: True)
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: {"status": incident.status, "annotations": incident.annotations},
    )

    payload = SimpleNamespace(
        status="IncidentStatus.resolved",
        assignee=None,
        model_fields_set=set(),
        __fields_set__=set(),
        hide_when_resolved=None,
        jira_ticket_key=None,
        jira_ticket_url=None,
        jira_integration_id=None,
        note=None,
        actor_username=None,
    )
    updated = svc.update_incident("inc-update", "tenant", "owner", payload, [])
    assert updated is not None
    assert updated["status"] == "resolved"
    meta_payload = json.loads(updated["annotations"][incidents_mod.INCIDENT_META_KEY])
    assert meta_payload["created_by"] == "owner"
