"""
High-coverage router tests for observability endpoints.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import HTTPException
from starlette.requests import Request

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.alerts import Alert, AlertGroup
from models.alerting.channels import ChannelType, NotificationChannel, NotificationChannelCreate
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest, IncidentStatus
from models.alerting.requests import (
    AlertWebhookRequest,
    GroupSharePruneRequest,
    IncidentJiraCreateRequest,
    JiraConfigUpdateRequest,
    JiraIntegrationCreateRequest,
    JiraIntegrationUpdateRequest,
    RuleImportRequest,
)
from models.alerting.rules import AlertRule, AlertRuleCreate
from models.alerting.silences import Silence, SilenceCreateRequest
from routers.observability.alerts import access as access_router
from routers.observability.alerts import alerts_routes as alerts_router
from routers.observability.alerts import channels as channels_router
from routers.observability.alerts import integrations as alert_integrations_router
from routers.observability.alerts import rules as rules_router
from routers.observability.alerts import silences as silences_router
from routers.observability.alerts import status as status_router
from routers.observability.alerts import webhooks as webhooks_router
from routers.observability.alerts.shared import HideTogglePayload
from routers.observability.jira import config as jira_config_router
from routers.observability.jira import discovery as jira_discovery_router
from routers.observability.jira import incident_links as jira_links_router
from routers.observability.jira import integrations as jira_integrations_router
from services.jira_service import JiraError


def _user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.ADMIN,
        "permissions": ["read:alerts", "update:incidents", "read:channels", "read:silences", "read:rules"],
        "group_ids": ["g1"],
        "is_superuser": False,
    }
    payload.update(kwargs)
    return TokenData(**cast(dict[str, Any], payload))


def _request(headers: list[tuple[bytes, bytes]] | None = None, path: str = "/") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": path,
            "headers": headers or [],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"",
        }
    )


async def _run_in_threadpool(func, *args, **kwargs):
    return func(*args, **kwargs)


def _alert_dict(name: str) -> dict[str, object]:
    return {
        "labels": {"alertname": name, "severity": "warning"},
        "annotations": {"summary": "s"},
        "startsAt": "2026-01-01T00:00:00Z",
        "endsAt": None,
        "generatorURL": None,
        "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
        "fingerprint": f"fp-{name}",
    }


def _rule_create(name: str, org_id: str | None = None) -> AlertRuleCreate:
    return AlertRuleCreate.model_validate(
        {
            "name": name,
            "expression": "up == 0",
            "severity": "warning",
            "groupName": "default",
            "orgId": org_id,
            "annotations": {"summary": f"{name} summary"},
        }
    )


def _rule_model(rule_id: str, name: str, created_by: str = "u1", org_id: str | None = "org-a") -> AlertRule:
    return AlertRule.model_validate(
        {
            "id": rule_id,
            "name": name,
            "expression": "up == 0",
            "severity": "warning",
            "groupName": "default",
            "createdBy": created_by,
            "orgId": org_id,
            "labels": {},
            "annotations": {"summary": "sum"},
            "notificationChannels": [],
            "visibility": "private",
            "sharedGroupIds": [],
        }
    )


def _channel(
    channel_id: str,
    *,
    owner: str = "u1",
    enabled: bool = True,
    visibility: str = "private",
    channel_type: str = "slack",
) -> NotificationChannel:
    return NotificationChannel.model_validate(
        {
            "id": channel_id,
            "name": f"ch-{channel_id}",
            "type": channel_type,
            "enabled": enabled,
            "config": {"webhook_url": "https://hooks.example.test"},
            "createdBy": owner,
            "visibility": visibility,
            "sharedGroupIds": ["g1"] if visibility == "group" else [],
        }
    )


def _silence(silence_id: str, *, owner: str = "u1", state: str = "active") -> Silence:
    return Silence.model_validate(
        {
            "id": silence_id,
            "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
            "startsAt": "2026-01-01T00:00:00Z",
            "endsAt": "2026-01-01T01:00:00Z",
            "createdBy": owner,
            "comment": "c",
            "status": {"state": state},
            "visibility": "group",
            "sharedGroupIds": ["g1"],
        }
    )


def _incident(incident_id: str = "inc-1", **kwargs) -> AlertIncident:
    base: dict[str, object] = {
        "id": incident_id,
        "fingerprint": "fp-1",
        "alertName": "CPUHigh",
        "severity": "critical",
        "status": IncidentStatus.OPEN,
        "assignee": None,
        "notes": [],
        "labels": {},
        "annotations": {},
        "visibility": "public",
        "sharedGroupIds": [],
        "jiraTicketKey": None,
        "jiraTicketUrl": None,
        "jiraIntegrationId": None,
        "lastSeenAt": "2026-01-01T00:00:00Z",
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
        "userManaged": False,
        "hideWhenResolved": False,
    }
    base.update(kwargs)
    return AlertIncident.model_validate(base)


@pytest.mark.asyncio
async def test_access_webhooks_and_status_routes(monkeypatch):
    monkeypatch.setattr(access_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(
        access_router.storage_service,
        "prune_removed_member_group_shares",
        lambda *args: {"rules": 1, "channels": 0, "incidents": 0, "jira_integrations": 0},
    )

    async def _prune_silences(**_kwargs):
        return 2

    monkeypatch.setattr(access_router.alertmanager_service, "prune_removed_member_group_silences", _prune_silences)
    out = await access_router.prune_group_shares(
        GroupSharePruneRequest.model_validate(
            {
                "tenantId": "tenant-a",
                "groupId": "g1",
                "removedUserIds": ["u1"],
                "removedUsernames": ["alice"],
            }
        )
    )
    assert out["updated"]["rules"] == 1
    assert out["updated"]["silences"] == 2

    seen_scopes: list[str] = []
    synced: list[str] = []

    def _security(_request: Request, scope: str):
        seen_scopes.append(scope)

    async def _sync(tenant_id: str, _alerts, log_context: str):
        synced.append(f"{tenant_id}:{log_context}")

    async def _notify(_tenant_id, _alerts, _storage, _notification):
        return None

    monkeypatch.setattr(webhooks_router.alertmanager_service, "enforce_webhook_security", _security)
    monkeypatch.setattr(webhooks_router, "infer_tenant_id_from_alerts", lambda _scope, _alerts: "tenant-a")
    monkeypatch.setattr(webhooks_router, "sync_incidents", _sync)
    monkeypatch.setattr(webhooks_router.alertmanager_service, "notify_for_alerts", _notify)
    monkeypatch.setattr(webhooks_router, "scope_header", lambda _request: "scope-a")

    payload = AlertWebhookRequest(alerts=[_alert_dict("CPUHigh")])
    assert (await webhooks_router.receive_alert_webhook(_request(path="/alerts/webhook"), payload))[
        "status"
    ].lower() == "success"
    assert (await webhooks_router.receive_critical_webhook(_request(path="/alerts/critical"), payload))[
        "severity"
    ] == "critical"
    assert (await webhooks_router.receive_warning_webhook(_request(path="/alerts/warning"), payload))[
        "severity"
    ] == "warning"
    assert seen_scopes == ["alertmanager_webhook", "alertmanager_critical", "alertmanager_warning"]
    assert len(synced) == 3

    async def _get_status():
        return {"cluster": {}, "config": {}}

    async def _get_receivers():
        return ["default"]

    monkeypatch.setattr(status_router.alertmanager_service, "get_status", _get_status)
    monkeypatch.setattr(status_router.alertmanager_service, "get_receivers", _get_receivers)
    assert (await status_router.get_alertmanager_status(_user()))["cluster"] == {}
    assert await status_router.list_receivers(_user()) == ["default"]

    async def _get_status_none():
        return None

    monkeypatch.setattr(status_router.alertmanager_service, "get_status", _get_status_none)
    with pytest.raises(HTTPException) as exc:
        await status_router.get_alertmanager_status(_user())
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_shared_helpers_scope_sync_silence_and_channel_validation(monkeypatch):
    from routers.observability.alerts import shared as shared_router

    request = _request(headers=[(b"x-scope-orgid", b"org-a")])
    assert shared_router.scope_header(request) == "org-a"
    request = _request(headers=[])
    assert shared_router.scope_header(request) == ""
    assert shared_router.parse_show_hidden("true") is True
    assert shared_router.parse_show_hidden("false") is False

    bad_request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/x",
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"bad=1",
        }
    )
    with pytest.raises(HTTPException) as exc:
        shared_router.reject_unknown_query_params(bad_request, {"allowed"})
    assert exc.value.status_code == 400

    monkeypatch.setattr(shared_router, "run_in_threadpool", _run_in_threadpool)
    captured = {}
    monkeypatch.setattr(
        shared_router.storage_service, "sync_incidents_from_alerts", lambda *args: captured.setdefault("args", args)
    )
    await shared_router.sync_incidents("tenant-a", [{"labels": {"alertname": "A"}}], log_context="edge")
    assert captured["args"][0] == "tenant-a"

    from sqlalchemy.exc import SQLAlchemyError

    warnings: list[str] = []
    monkeypatch.setattr(
        shared_router.storage_service,
        "sync_incidents_from_alerts",
        lambda *_args: (_ for _ in ()).throw(SQLAlchemyError("db")),
    )
    monkeypatch.setattr(shared_router.logger, "warning", lambda msg, *a: warnings.append(msg % a))
    await shared_router.sync_incidents("tenant-a", [{"labels": {"alertname": "A"}}], log_context="edge")
    assert warnings and "Incident sync skipped" in warnings[0]

    monkeypatch.setattr(shared_router.alertmanager_service, "normalize_visibility", lambda _v: "group")
    monkeypatch.setattr(shared_router, "validate_shared_group_ids_for_user", lambda *_args: ["g1"])
    monkeypatch.setattr(
        shared_router.alertmanager_service, "encode_silence_comment", lambda c, v, g: f"{c}|{v}|{','.join(g)}"
    )
    payload = shared_router.build_silence_payload(
        SilenceCreateRequest.model_validate(
            {
                "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
                "startsAt": "2026-01-01T00:00:00Z",
                "endsAt": "2026-01-01T01:00:00Z",
                "comment": "hello",
                "visibility": "group",
                "sharedGroupIds": ["g1", ""],
            }
        ),
        _user(),
    )
    assert payload.created_by == "u1"
    assert payload.comment.endswith("group|g1")

    monkeypatch.setattr(shared_router, "allowed_channel_types", lambda: ["slack"])

    class FakeChannelService:
        def validate_channel_config(self, _channel_type, _config):
            return []

    good_channel = NotificationChannelCreate.model_validate(
        {
            "name": "Slack",
            "type": "slack",
            "enabled": True,
            "config": {"webhook_url": "https://hooks.example"},
        }
    )
    assert shared_router.validate_channel(good_channel, FakeChannelService()) == "slack"

    bad_type_channel = NotificationChannelCreate.model_validate(
        {
            "name": "Email",
            "type": "email",
            "enabled": True,
            "config": {"to": "ops@example.com"},
        }
    )
    with pytest.raises(HTTPException) as exc:
        shared_router.validate_channel(bad_type_channel, FakeChannelService())
    assert exc.value.status_code == 403

    class BadConfigService:
        def validate_channel_config(self, _channel_type, _config):
            return ["missing webhook_url"]

    with pytest.raises(HTTPException) as exc:
        shared_router.validate_channel(good_channel, BadConfigService())
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_alert_routes_and_channel_type_integrations(monkeypatch):
    monkeypatch.setattr(alerts_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(alerts_router.alertmanager_service, "parse_filter_labels", lambda _value: {"alertname": "A"})

    async def _get_alerts(**_kwargs):
        return [Alert.model_validate(_alert_dict("A")), Alert.model_validate(_alert_dict("HIDDEN"))]

    async def _sync(_tenant_id, _alerts, log_context: str):
        assert log_context == "get_alerts"

    monkeypatch.setattr(alerts_router.alertmanager_service, "get_alerts", _get_alerts)
    monkeypatch.setattr(alerts_router, "sync_incidents", _sync)
    monkeypatch.setattr(
        alerts_router.storage_service,
        "filter_alerts_for_user",
        lambda *_args: [_alert_dict("A"), _alert_dict("HIDDEN")],
    )
    monkeypatch.setattr(alerts_router.storage_service, "get_hidden_rule_names", lambda *_args: ["HIDDEN"])

    items = await alerts_router.list_alerts(filter_labels='{"alertname":"A"}', show_hidden=False, current_user=_user())
    assert len(items) == 1
    assert items[0].labels["alertname"] == "A"

    items = await alerts_router.list_alerts(filter_labels='{"alertname":"A"}', show_hidden=True, current_user=_user())
    assert len(items) == 2

    async def _groups(**_kwargs):
        return [
            AlertGroup.model_validate(
                {
                    "labels": {"alertname": "A"},
                    "receiver": "default",
                    "alerts": [_alert_dict("A")],
                }
            )
        ]

    monkeypatch.setattr(alerts_router.alertmanager_service, "get_alert_groups", _groups)
    groups = await alerts_router.list_alert_groups(current_user=_user())
    assert groups and groups[0].receiver == "default"

    async def _post_alerts(_alerts):
        return True

    monkeypatch.setattr(alerts_router.alertmanager_service, "post_alerts", _post_alerts)
    posted = await alerts_router.create_alerts([Alert.model_validate(_alert_dict("A"))], current_user=_user())
    assert posted["count"] == 1

    async def _delete_ok(**_kwargs):
        return True

    async def _delete_fail(**_kwargs):
        return False

    monkeypatch.setattr(alerts_router.alertmanager_service, "delete_alerts", _delete_fail)
    with pytest.raises(HTTPException) as exc:
        await alerts_router.delete_alerts(filter_labels='{"alertname":"A"}', current_user=_user())
    assert exc.value.status_code == 500

    monkeypatch.setattr(alerts_router.alertmanager_service, "parse_filter_labels", lambda _value: {})
    with pytest.raises(HTTPException) as exc:
        await alerts_router.delete_alerts(filter_labels="{}", current_user=_user())
    assert exc.value.status_code == 400

    monkeypatch.setattr(alerts_router.alertmanager_service, "parse_filter_labels", lambda _value: {"alertname": "A"})
    monkeypatch.setattr(alerts_router.alertmanager_service, "delete_alerts", _delete_ok)
    deleted = await alerts_router.delete_alerts(filter_labels='{"alertname":"A"}', current_user=_user())
    assert deleted["status"] == "success"

    monkeypatch.setattr(alert_integrations_router, "allowed_channel_types", lambda: ["slack", "email"])
    types = await alert_integrations_router.list_channel_types(_user())
    assert types["allowedTypes"] == ["slack", "email"]


@pytest.mark.asyncio
async def test_channel_routes_cover_error_and_success_paths(monkeypatch):
    monkeypatch.setattr(channels_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _u: ("tenant-a", "u1", ["g1"]))

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channels",
        lambda *_args: [_channel("c1"), _channel("c2", owner="u2", visibility="group")],
    )
    monkeypatch.setattr(channels_router.storage_service, "get_hidden_channel_ids", lambda *_args: ["c2"])
    visible = await channels_router.list_channels(request=_request(), show_hidden=False, current_user=_user())
    assert [item.id for item in visible] == ["c1"]
    all_items = await channels_router.list_channels(request=_request(), show_hidden=True, current_user=_user())
    assert len(all_items) == 2

    monkeypatch.setattr(channels_router.storage_service, "get_notification_channel", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await channels_router.get_channel("missing", _user())
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c2", owner="u2", visibility="group"),
    )
    looked_up = await channels_router.get_channel("c2", _user())
    assert looked_up.is_hidden is True

    monkeypatch.setattr(channels_router.storage_service, "toggle_channel_hidden", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await channels_router.hide_channel("c2", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 500

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c1", owner="u1", visibility="group"),
    )
    with pytest.raises(HTTPException) as exc:
        await channels_router.hide_channel("c1", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c3", owner="u2", visibility="private"),
    )
    with pytest.raises(HTTPException) as exc:
        await channels_router.hide_channel("c3", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c4", owner="u2", visibility="group"),
    )
    monkeypatch.setattr(channels_router.storage_service, "toggle_channel_hidden", lambda *_args: True)
    hidden = await channels_router.hide_channel("c4", HideTogglePayload(hidden=True), _user())
    assert hidden["hidden"] is True

    monkeypatch.setattr(channels_router, "validate_channel", lambda *_args, **_kwargs: "slack")
    monkeypatch.setattr(channels_router.storage_service, "create_notification_channel", lambda *_args: _channel("new"))
    created = await channels_router.create_channel(
        NotificationChannelCreate.model_validate(
            {
                "name": "Slack",
                "type": "slack",
                "enabled": True,
                "config": {"webhook_url": "https://hooks.example"},
            }
        ),
        current_user=_user(),
    )
    assert created.id == "new"

    monkeypatch.setattr(channels_router.storage_service, "update_notification_channel", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await channels_router.update_channel(
            "missing",
            NotificationChannelCreate.model_validate(
                {
                    "name": "Slack",
                    "type": "slack",
                    "enabled": True,
                    "config": {"webhook_url": "https://hooks.example"},
                }
            ),
            current_user=_user(),
        )
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        channels_router.storage_service, "update_notification_channel", lambda *_args: _channel("updated")
    )
    updated = await channels_router.update_channel(
        "c1",
        NotificationChannelCreate.model_validate(
            {
                "name": "Slack",
                "type": "slack",
                "enabled": True,
                "config": {"webhook_url": "https://hooks.example"},
            }
        ),
        current_user=_user(),
    )
    assert updated.id == "updated"

    monkeypatch.setattr(channels_router.storage_service, "delete_notification_channel", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await channels_router.delete_channel("c1", _user())
    assert exc.value.status_code == 404

    monkeypatch.setattr(channels_router.storage_service, "delete_notification_channel", lambda *_args: True)
    deleted = await channels_router.delete_channel("c1", _user())
    assert deleted["status"] == "success"

    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("c1", _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    monkeypatch.setattr(
        channels_router.storage_service, "get_notification_channel", lambda *_args: _channel("c1", enabled=False)
    )
    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("c1", _user())
    assert exc.value.status_code == 400

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c2", enabled=True, channel_type="slack"),
    )

    async def _send_ok(_channel_obj, _alert, _kind):
        return True

    monkeypatch.setattr(channels_router.notification_service, "send_notification", _send_ok)
    result = await channels_router.test_channel("c2", _user())
    assert result["status"] == "success"

    async def _send_fail(_channel_obj, _alert, _kind):
        return False

    monkeypatch.setattr(channels_router.notification_service, "send_notification", _send_fail)
    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c3", enabled=True, channel_type="webhook"),
    )
    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("c3", _user())
    assert exc.value.status_code == 400

    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel("c4", enabled=True, channel_type="email"),
    )
    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("c4", _user())
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_silence_routes_cover_read_write_hide(monkeypatch):
    monkeypatch.setattr(silences_router, "run_in_threadpool", _run_in_threadpool)

    async def _silences(**_kwargs):
        return [_silence("s1", owner="u2", state="active"), _silence("s2", owner="u2", state="expired")]

    monkeypatch.setattr(silences_router.alertmanager_service, "parse_filter_labels", lambda _v: {"a": "b"})
    monkeypatch.setattr(silences_router.alertmanager_service, "get_silences", _silences)
    monkeypatch.setattr(silences_router.alertmanager_service, "apply_silence_metadata", lambda s: s)
    monkeypatch.setattr(
        silences_router.alertmanager_service, "silence_accessible", lambda silence, _user: silence.id == "s1"
    )
    monkeypatch.setattr(silences_router.storage_service, "get_hidden_silence_ids", lambda *_args: ["s1"])

    visible = await silences_router.list_silences(
        request=_request(), include_expired=False, show_hidden=False, current_user=_user()
    )
    assert visible == []

    visible = await silences_router.list_silences(
        request=_request(), show_hidden=True, include_expired=True, current_user=_user()
    )
    assert [item.id for item in visible] == ["s1"]

    async def _get_single(_sid):
        return _silence("s1", owner="u2", state="active")

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _get_single)
    monkeypatch.setattr(silences_router.storage_service, "get_hidden_silence_ids", lambda *_args: ["s1"])
    with pytest.raises(HTTPException) as exc:
        await silences_router.get_silence("s1", request=_request(), show_hidden=False, current_user=_user())
    assert exc.value.status_code == 404

    shown = await silences_router.get_silence("s1", request=_request(), show_hidden=True, current_user=_user())
    assert shown.id == "s1"

    monkeypatch.setattr(silences_router, "build_silence_payload", lambda *_args: "payload")

    async def _create_ok(_payload):
        return "new-s"

    monkeypatch.setattr(silences_router.alertmanager_service, "create_silence", _create_ok)
    created = await silences_router.create_silence(
        SilenceCreateRequest.model_validate(
            {
                "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
                "startsAt": "2026-01-01T00:00:00Z",
                "endsAt": "2026-01-01T01:00:00Z",
                "comment": "x",
            }
        ),
        current_user=_user(),
    )
    assert created["silenceID"] == "new-s"

    async def _create_fail(_payload):
        return None

    monkeypatch.setattr(silences_router.alertmanager_service, "create_silence", _create_fail)
    with pytest.raises(HTTPException) as exc:
        await silences_router.create_silence(
            SilenceCreateRequest.model_validate(
                {
                    "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
                    "startsAt": "2026-01-01T00:00:00Z",
                    "endsAt": "2026-01-01T01:00:00Z",
                    "comment": "x",
                }
            ),
            current_user=_user(),
        )
    assert exc.value.status_code == 500

    async def _single(_sid):
        return _silence("s1", owner="u2")

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _single)
    monkeypatch.setattr(silences_router.alertmanager_service, "silence_accessible", lambda *_args: True)
    monkeypatch.setattr(silences_router.alertmanager_service, "silence_owned_by", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await silences_router.update_silence(
            "s1",
            SilenceCreateRequest.model_validate(
                {
                    "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
                    "startsAt": "2026-01-01T00:00:00Z",
                    "endsAt": "2026-01-01T01:00:00Z",
                    "comment": "x",
                }
            ),
            current_user=_user(),
        )
    assert exc.value.status_code == 403

    monkeypatch.setattr(silences_router.alertmanager_service, "silence_owned_by", lambda *_args: True)

    async def _update_ok(_sid, _payload):
        return "updated-s"

    monkeypatch.setattr(silences_router.alertmanager_service, "update_silence", _update_ok)
    updated = await silences_router.update_silence(
        "s1",
        SilenceCreateRequest.model_validate(
            {
                "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
                "startsAt": "2026-01-01T00:00:00Z",
                "endsAt": "2026-01-01T01:00:00Z",
                "comment": "x",
            }
        ),
        current_user=_user(),
    )
    assert updated["silenceID"] == "updated-s"

    async def _delete_ok(_sid):
        return True

    monkeypatch.setattr(silences_router.alertmanager_service, "delete_silence", _delete_ok)
    deleted = await silences_router.delete_silence("s1", _user())
    assert deleted["status"] == "success"

    monkeypatch.setattr(silences_router.alertmanager_service, "silence_owned_by", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await silences_router.delete_silence("s1", _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(silences_router.alertmanager_service, "silence_accessible", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await silences_router.hide_silence("s1", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 404

    monkeypatch.setattr(silences_router.alertmanager_service, "silence_accessible", lambda *_args: True)

    async def _owned_silence(_sid):
        return _silence("s1", owner="u1")

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _owned_silence)
    with pytest.raises(HTTPException) as exc:
        await silences_router.hide_silence("s1", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 403

    async def _shared_silence(_sid):
        return _silence("s1", owner="u2")

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _shared_silence)
    monkeypatch.setattr(silences_router.storage_service, "toggle_silence_hidden", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await silences_router.hide_silence("s1", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 500

    monkeypatch.setattr(silences_router.storage_service, "toggle_silence_hidden", lambda *_args: True)
    assert (await silences_router.hide_silence("s1", HideTogglePayload(hidden=False), _user()))["hidden"] is False


@pytest.mark.asyncio
async def test_rules_routes_cover_main_paths(monkeypatch):
    monkeypatch.setattr(rules_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(rules_router.alertmanager_service, "user_scope", lambda _u: ("tenant-a", "u1", ["g1"]))

    created_rule = _rule_model("r-new", "NewRule", org_id="org-a")
    updated_rule = _rule_model("r-1", "RuleOne", org_id="org-a")

    monkeypatch.setattr(
        rules_router,
        "parse_rules_yaml",
        lambda _yaml, _defaults: [_rule_create("RuleOne", "org-a"), _rule_create("NewRule", "org-a")],
    )
    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rules", lambda *_args: [_rule_model("r-1", "RuleOne", org_id="org-a")]
    )
    monkeypatch.setattr(rules_router.storage_service, "update_alert_rule", lambda *_args: updated_rule)
    monkeypatch.setattr(rules_router.storage_service, "create_alert_rule", lambda *_args: created_rule)
    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rules_for_org", lambda *_args: [updated_rule, created_rule]
    )

    synced_orgs: list[str] = []

    async def _sync_org(org_id, _rules):
        synced_orgs.append(org_id)

    monkeypatch.setattr(rules_router.alertmanager_service, "sync_mimir_rules_for_org", _sync_org)

    out = await rules_router.import_rules(
        RuleImportRequest.model_validate({"yamlContent": "groups: []", "dryRun": False}),
        current_user=_user(),
    )
    assert out["created"] == 1
    assert out["updated"] == 1
    assert synced_orgs == ["org-a"]

    preview = await rules_router.import_rules(
        RuleImportRequest.model_validate({"yamlContent": "x", "dryRun": True}),
        current_user=_user(),
    )
    assert preview["status"] == "preview"

    def _raise_import(_yaml, _defaults):
        raise rules_router.RuleImportError("bad")

    monkeypatch.setattr(rules_router, "parse_rules_yaml", _raise_import)
    with pytest.raises(HTTPException) as exc:
        await rules_router.import_rules(
            RuleImportRequest.model_validate({"yamlContent": "x", "dryRun": False}),
            current_user=_user(),
        )
    assert exc.value.status_code == 400

    monkeypatch.setattr(rules_router.storage_service, "get_hidden_rule_ids", lambda *_args: ["r2"])
    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rules_with_owner",
        lambda *_args: [
            (_rule_model("r1", "RuleOne", created_by="u1", org_id="org-a"), "u1"),
            (_rule_model("r2", "RuleTwo", created_by="u2", org_id="org-b"), "u2"),
        ],
    )
    listed = await rules_router.list_rules(request=_request(), show_hidden=False, current_user=_user())
    assert len(listed) == 1
    listed_all = await rules_router.list_rules(request=_request(), show_hidden=True, current_user=_user())
    assert listed_all[1].org_id is None

    async def _list_metric_names(_org):
        return ["up", "cpu_usage"]

    async def _evaluate_promql(_org, _query, _lim):
        return {"valid": True, "samples": []}

    async def _list_label_names(_org):
        return ["job", "instance"]

    async def _list_label_values(_org, _label, _metric):
        return ["api", "db"]

    monkeypatch.setattr(rules_router.alertmanager_service, "list_metric_names", _list_metric_names)
    metrics = await rules_router.list_metric_names(org_id=None, current_user=_user(org_id="org-a"))
    assert metrics["metrics"] == ["up", "cpu_usage"]

    with pytest.raises(HTTPException):
        await rules_router.list_metric_names(org_id=None, current_user=_user(org_id=""))

    monkeypatch.setattr(rules_router.alertmanager_service, "evaluate_promql", _evaluate_promql)
    eval_out = await rules_router.query_metrics(query="up", org_id=None, current_user=_user(org_id="org-a"))
    assert eval_out["valid"] is True

    monkeypatch.setattr(rules_router.alertmanager_service, "list_label_names", _list_label_names)
    labels = await rules_router.list_metric_labels(org_id=None, current_user=_user(org_id="org-a"))
    assert labels["labels"] == ["job", "instance"]

    monkeypatch.setattr(rules_router.alertmanager_service, "list_label_values", _list_label_values)
    values = await rules_router.list_metric_label_values(
        "job", org_id=None, metric_name=None, current_user=_user(org_id="org-a")
    )
    assert values["values"] == ["api", "db"]

    monkeypatch.setattr(rules_router.storage_service, "get_alert_rule", lambda *_args: None)
    with pytest.raises(HTTPException):
        await rules_router.get_rule("missing", _user())

    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rule",
        lambda *_args: _rule_model("r1", "RuleOne", created_by="u2", org_id="org-z"),
    )
    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule_raw", lambda *_args: SimpleNamespace(created_by="u2")
    )
    monkeypatch.setattr(rules_router.storage_service, "get_hidden_rule_ids", lambda *_args: ["r1"])
    one = await rules_router.get_rule("r1", _user())
    assert one.is_hidden is True
    assert one.org_id is None

    monkeypatch.setattr(rules_router.storage_service, "toggle_rule_hidden", lambda *_args: True)
    hidden = await rules_router.hide_rule("r1", HideTogglePayload(hidden=True), _user())
    assert hidden["hidden"] is True

    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule_raw", lambda *_args: SimpleNamespace(created_by="u1")
    )
    with pytest.raises(HTTPException) as exc:
        await rules_router.hide_rule("r1", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(rules_router.alertmanager_service, "resolve_rule_org_id", lambda _org, _user: "org-resolved")
    monkeypatch.setattr(
        rules_router.storage_service,
        "create_alert_rule",
        lambda *_args: _rule_model("r-created", "RuleCreated", org_id=None),
    )
    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rules_for_org",
        lambda *_args: [_rule_model("r-created", "RuleCreated", org_id="org-resolved")],
    )
    created = await rules_router.create_rule(_rule_create("RuleCreated", org_id=None), _user())
    assert created.id == "r-created"

    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule", lambda *_args: _rule_model("r1", "RuleOne", org_id="org-old")
    )
    monkeypatch.setattr(
        rules_router.storage_service, "update_alert_rule", lambda *_args: _rule_model("r1", "RuleOne", org_id="org-new")
    )
    updated = await rules_router.update_rule("r1", _rule_create("RuleOne", org_id="org-new"), _user())
    assert updated.id == "r1"

    monkeypatch.setattr(
        rules_router.storage_service, "get_notification_channels_for_rule_name", lambda *_args: [_channel("c1")]
    )

    async def _send_notification(_channel_obj, _alert, _kind):
        return True

    monkeypatch.setattr(rules_router.notification_service, "send_notification", _send_notification)
    tested = await rules_router.test_rule("r1", _request(), _user())
    assert tested["status"] == "success"

    monkeypatch.setattr(rules_router.storage_service, "get_notification_channels_for_rule_name", lambda *_args: [])
    with pytest.raises(HTTPException):
        await rules_router.test_rule("r1", _request(), _user())

    monkeypatch.setattr(rules_router.storage_service, "delete_alert_rule", lambda *_args: True)
    deleted = await rules_router.delete_rule("r1", _user())
    assert deleted["status"] == "success"

    monkeypatch.setattr(rules_router.storage_service, "delete_alert_rule", lambda *_args: False)
    with pytest.raises(HTTPException):
        await rules_router.delete_rule("r1", _user())


@pytest.mark.asyncio
async def test_jira_config_discovery_integrations_and_links(monkeypatch):
    monkeypatch.setattr(jira_integrations_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(jira_links_router, "run_in_threadpool", _run_in_threadpool)

    # config
    monkeypatch.setattr(
        jira_config_router,
        "load_tenant_jira_config",
        lambda _tenant: {
            "enabled": True,
            "base_url": "https://jira",
            "email": "a@b.c",
            "api_token": "tok",
            "bearer": None,
        },
    )
    cfg = await jira_config_router.get_jira_config(_user())
    assert cfg["hasApiToken"] is True

    monkeypatch.setattr(
        jira_config_router,
        "save_tenant_jira_config",
        lambda *_args, **_kwargs: {
            "enabled": False,
            "baseUrl": "https://jira",
            "email": "a@b.c",
            "hasApiToken": False,
            "hasBearerToken": True,
        },
    )
    saved = await jira_config_router.update_jira_config(JiraConfigUpdateRequest(enabled=False), _user())
    assert saved["hasBearerToken"] is True

    # discovery
    async def _projects(*_args, **_kwargs):
        return {"enabled": True, "projects": [{"key": "OPS"}]}

    async def _types(*_args, **_kwargs):
        return {"enabled": True, "issueTypes": ["Task"]}

    monkeypatch.setattr(jira_discovery_router, "jira_projects_via_integration", _projects)
    monkeypatch.setattr(jira_discovery_router, "jira_issue_types_via_integration", _types)
    assert (await jira_discovery_router.list_jira_projects(integration_id="i1", current_user=_user()))[
        "enabled"
    ] is True
    assert (await jira_discovery_router.list_jira_issue_types("OPS", integration_id="i1", current_user=_user()))[
        "enabled"
    ] is True
    assert (await jira_discovery_router.list_integration_projects("i1", _user()))["enabled"] is True
    assert (await jira_discovery_router.list_integration_issue_types("i1", "OPS", _user()))["enabled"] is True

    monkeypatch.setattr(jira_discovery_router, "jira_is_enabled_for_tenant", lambda _tenant: False)
    assert (await jira_discovery_router.list_jira_projects(integration_id=None, current_user=_user()))[
        "enabled"
    ] is False

    monkeypatch.setattr(jira_discovery_router, "jira_is_enabled_for_tenant", lambda _tenant: True)
    monkeypatch.setattr(
        jira_discovery_router, "get_effective_jira_credentials", lambda _tenant: {"base_url": "https://jira"}
    )

    async def _list_projects(**_kwargs):
        return [{"key": "OPS"}]

    async def _list_types(**_kwargs):
        return ["Task", "Bug"]

    monkeypatch.setattr(jira_discovery_router.jira_service, "list_projects", _list_projects)
    monkeypatch.setattr(jira_discovery_router.jira_service, "list_issue_types", _list_types)
    assert (await jira_discovery_router.list_jira_projects(integration_id=None, current_user=_user()))["projects"] == [
        {"key": "OPS"}
    ]
    assert (await jira_discovery_router.list_jira_issue_types("OPS", integration_id=None, current_user=_user()))[
        "issueTypes"
    ] == ["Task", "Bug"]

    async def _boom(**_kwargs):
        raise JiraError("bad gateway")

    monkeypatch.setattr(jira_discovery_router.jira_service, "list_projects", _boom)
    with pytest.raises(HTTPException) as exc:
        await jira_discovery_router.list_jira_projects(integration_id=None, current_user=_user())
    assert exc.value.status_code == 502

    monkeypatch.setattr(jira_discovery_router.jira_service, "list_projects", _list_projects)
    monkeypatch.setattr(jira_discovery_router.jira_service, "list_issue_types", _boom)
    with pytest.raises(HTTPException) as exc:
        await jira_discovery_router.list_jira_issue_types("OPS", integration_id=None, current_user=_user())
    assert exc.value.status_code == 502

    # integrations
    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i1", "createdBy": "u2", "visibility": "group"}],
    )
    monkeypatch.setattr(
        jira_integrations_router.storage_service, "get_hidden_jira_integration_ids", lambda *_args: ["i1"]
    )
    monkeypatch.setattr(jira_integrations_router, "jira_integration_has_access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(jira_integrations_router, "mask_jira_integration", lambda item, _user: {"id": item["id"]})
    assert (
        await jira_integrations_router.list_jira_integrations(
            request=_request(), show_hidden=False, current_user=_user()
        )
    )["items"] == []
    assert (
        len(
            (
                await jira_integrations_router.list_jira_integrations(
                    request=_request(), show_hidden=True, current_user=_user()
                )
            )["items"]
        )
        == 1
    )

    captured_integrations = []
    monkeypatch.setattr(
        jira_integrations_router, "load_tenant_jira_integrations", lambda _tenant: captured_integrations
    )
    monkeypatch.setattr(jira_integrations_router, "normalize_visibility", lambda _v, _d: "group")
    monkeypatch.setattr(jira_integrations_router, "validate_shared_group_ids_for_user", lambda *_args: ["g1"])
    monkeypatch.setattr(jira_integrations_router, "normalize_jira_auth_mode", lambda _v: "api_token")
    monkeypatch.setattr(jira_integrations_router, "validate_jira_credentials", lambda **_kwargs: None)
    monkeypatch.setattr(jira_integrations_router, "encrypt_tenant_secret", lambda v: f"enc:{v}" if v else None)
    monkeypatch.setattr(jira_integrations_router, "save_tenant_jira_integrations", lambda *_args: None)
    monkeypatch.setattr(
        jira_integrations_router, "mask_jira_integration", lambda item, _user: {"id": item["id"], "name": item["name"]}
    )

    created_integration = await jira_integrations_router.create_jira_integration(
        JiraIntegrationCreateRequest.model_validate(
            {
                "name": " Jira ",
                "enabled": True,
                "visibility": "group",
                "sharedGroupIds": ["g1"],
                "baseUrl": "https://jira",
                "email": "a@b.c",
                "apiToken": "tok",
                "authMode": "api_token",
            }
        ),
        current_user=_user(),
    )
    assert created_integration["name"] == "Jira"
    assert len(captured_integrations) == 1

    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [
            {
                "id": "i1",
                "createdBy": "u1",
                "visibility": "group",
                "sharedGroupIds": ["g1"],
                "baseUrl": "https://jira",
                "email": "a@b.c",
                "apiToken": "enc:tok",
                "bearerToken": None,
                "authMode": "api_token",
            }
        ],
    )
    monkeypatch.setattr(jira_integrations_router, "decrypt_tenant_secret", lambda value: "tok" if value else None)
    monkeypatch.setattr(jira_integrations_router, "save_tenant_jira_integrations", lambda *_args: None)
    monkeypatch.setattr(jira_integrations_router, "validate_shared_group_ids_for_user", lambda *_args: ["g1"])
    monkeypatch.setattr(
        jira_integrations_router,
        "mask_jira_integration",
        lambda item, _user: {
            "id": item["id"],
            "authMode": item["authMode"],
            "supportsSso": item.get("supportsSso", False),
        },
    )

    updated_integration = await jira_integrations_router.update_jira_integration(
        "i1",
        JiraIntegrationUpdateRequest.model_validate(
            {
                "name": "Updated",
                "enabled": True,
                "visibility": "group",
                "sharedGroupIds": ["g1"],
                "baseUrl": "https://jira",
                "email": "a@b.c",
                "apiToken": "tok2",
                "authMode": "bearer",
                "bearerToken": "bear",
            }
        ),
        current_user=_user(),
    )
    assert updated_integration["id"] == "i1"

    monkeypatch.setattr(
        jira_integrations_router, "load_tenant_jira_integrations", lambda _tenant: [{"id": "i1", "createdBy": "u2"}]
    )
    with pytest.raises(HTTPException) as exc:
        await jira_integrations_router.update_jira_integration("i1", JiraIntegrationUpdateRequest(), _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(jira_integrations_router, "load_tenant_jira_integrations", lambda _tenant: [])
    with pytest.raises(HTTPException) as exc:
        await jira_integrations_router.delete_jira_integration("missing", _user())
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        jira_integrations_router, "load_tenant_jira_integrations", lambda _tenant: [{"id": "i1", "createdBy": "u1"}]
    )
    monkeypatch.setattr(
        jira_integrations_router.storage_service, "unlink_jira_integration_from_incidents", lambda *_args: 2
    )
    monkeypatch.setattr(jira_integrations_router, "save_tenant_jira_integrations", lambda *_args: None)
    deleted = await jira_integrations_router.delete_jira_integration("i1", _user())
    assert deleted["incidentsUnlinked"] == 2

    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i2", "createdBy": "u2", "visibility": "private"}],
    )
    monkeypatch.setattr(jira_integrations_router, "jira_integration_has_access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        jira_integrations_router,
        "normalize_visibility",
        lambda value, default: str(value or default).strip().lower() or default,
    )
    with pytest.raises(HTTPException) as exc:
        await jira_integrations_router.hide_jira_integration("i2", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 403

    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i3", "createdBy": "u2", "visibility": "group"}],
    )
    monkeypatch.setattr(jira_integrations_router.storage_service, "toggle_jira_integration_hidden", lambda *_args: True)
    hidden = await jira_integrations_router.hide_jira_integration("i3", HideTogglePayload(hidden=True), _user())
    assert hidden["hidden"] is True

    # incident links
    monkeypatch.setattr(jira_links_router.storage_service, "get_incident_for_user", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.create_incident_link(
            "inc-1",
            IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS"}),
            _user(),
        )
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        jira_links_router.storage_service,
        "get_incident_for_user",
        lambda *_args: _incident("inc-1", jiraTicketKey="OPS-1"),
    )
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.create_incident_link(
            "inc-1",
            IncidentJiraCreateRequest.model_validate(
                {"integrationId": "i1", "projectKey": "OPS", "replaceExisting": False}
            ),
            _user(),
        )
    assert exc.value.status_code == 409

    monkeypatch.setattr(jira_links_router.storage_service, "get_incident_for_user", lambda *_args: _incident("inc-1"))
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.create_incident_link(
            "inc-1",
            IncidentJiraCreateRequest.model_validate({"integrationId": "", "projectKey": "OPS"}),
            _user(),
        )
    assert exc.value.status_code == 400

    monkeypatch.setattr(jira_links_router, "resolve_jira_integration", lambda *_args, **_kwargs: {"id": "i1"})
    monkeypatch.setattr(jira_links_router, "integration_is_usable", lambda _item: False)
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.create_incident_link(
            "inc-1",
            IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS"}),
            _user(),
        )
    assert exc.value.status_code == 400

    monkeypatch.setattr(jira_links_router, "integration_is_usable", lambda _item: True)
    monkeypatch.setattr(
        jira_links_router,
        "jira_integration_credentials",
        lambda _item: {"base_url": "https://jira", "auth_mode": "bearer", "bearer": "x"},
    )
    monkeypatch.setattr(jira_links_router, "format_incident_description", lambda _incident_obj, _desc: "desc")
    monkeypatch.setattr(jira_links_router, "map_severity_to_jira_priority", lambda _sev: "High")

    async def _create_issue(**_kwargs):
        return {"key": "OPS-2", "url": "https://jira/browse/OPS-2"}

    async def _transition(**_kwargs):
        return True

    async def _add_comment(*_args, **_kwargs):
        return {}

    monkeypatch.setattr(jira_links_router.jira_service, "create_issue", _create_issue)
    monkeypatch.setattr(jira_links_router.jira_service, "transition_issue_to_todo", _transition)
    monkeypatch.setattr(jira_links_router.jira_service, "add_comment", _add_comment)
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: ["note-a", "note-b"])
    monkeypatch.setattr(
        jira_links_router.storage_service,
        "update_incident",
        lambda *_args: _incident(
            "inc-1", jiraTicketKey="OPS-2", jiraTicketUrl="https://jira/browse/OPS-2", jiraIntegrationId="i1"
        ),
    )

    linked = await jira_links_router.create_incident_link(
        "inc-1",
        IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS", "issueType": "Task"}),
        _user(),
    )
    assert linked.jira_ticket_key == "OPS-2"

    monkeypatch.setattr(jira_links_router, "resolve_incident_jira_credentials", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.sync_incident_notes("inc-1", _user())
    assert exc.value.status_code == 400

    monkeypatch.setattr(
        jira_links_router.storage_service,
        "get_incident_for_user",
        lambda *_args: _incident("inc-1", jiraTicketKey="OPS-2", jiraIntegrationId="i1"),
    )
    monkeypatch.setattr(
        jira_links_router, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"}
    )
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: [])
    sync_none = await jira_links_router.sync_incident_notes("inc-1", _user())
    assert sync_none["totalNotes"] == 0

    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: ["one", "two"])

    async def _list_comments(_issue_key, credentials=None):
        return [{"body": "one"}]

    monkeypatch.setattr(jira_links_router.jira_service, "list_comments", _list_comments)
    synced = await jira_links_router.sync_incident_notes("inc-1", _user())
    assert synced["synced"] == 1
    assert synced["skipped"] == 1

    monkeypatch.setattr(
        jira_links_router.storage_service,
        "get_incident_for_user",
        lambda *_args: _incident("inc-1", jiraTicketKey=None),
    )
    assert (await jira_links_router.list_incident_comments("inc-1", _user()))["comments"] == []

    monkeypatch.setattr(
        jira_links_router.storage_service,
        "get_incident_for_user",
        lambda *_args: _incident("inc-1", jiraTicketKey="OPS-2"),
    )
    monkeypatch.setattr(
        jira_links_router, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"}
    )
    comments = await jira_links_router.list_incident_comments("inc-1", _user())
    assert isinstance(comments["comments"], list)

    async def _link_boom(**_kwargs):
        raise JiraError("create failed")

    monkeypatch.setattr(jira_links_router.storage_service, "get_incident_for_user", lambda *_args: _incident("inc-1"))
    monkeypatch.setattr(jira_links_router.jira_service, "create_issue", _link_boom)
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.create_incident_link(
            "inc-1",
            IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS", "issueType": "Task"}),
            _user(),
        )
    assert exc.value.status_code == 502


@pytest.mark.asyncio
async def test_incidents_router_listing_and_patch_paths(monkeypatch):
    from routers.observability import incidents as incidents_router

    monkeypatch.setattr(incidents_router, "run_in_threadpool", _run_in_threadpool)

    monkeypatch.setattr(
        incidents_router.storage_service,
        "list_incidents",
        lambda **_kwargs: [_incident("inc-1")],
    )
    listed = await incidents_router.list_incidents(current_user=_user())
    assert listed[0].id == "inc-1"

    monkeypatch.setattr(
        incidents_router.storage_service,
        "get_incident_summary",
        lambda *_args: {
            "open_total": 1,
            "unassigned_open": 1,
            "assigned_open": 0,
            "assigned_to_me_open": 0,
            "by_visibility": {"public": 1, "private": 0, "group": 0},
        },
    )
    summary = await incidents_router.get_incident_summary(_user())
    assert summary["open_total"] == 1

    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await incidents_router.update_incident("missing", AlertIncidentUpdateRequest(), _user())
    assert exc.value.status_code == 404

    base_incident = _incident("inc-2", labels={"alertname": "CPUHigh"}, fingerprint="fp-2")
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: base_incident)
    monkeypatch.setattr(
        incidents_router, "incident_key_from_labels", lambda labels: "rule:CPUHigh|scope:org" if labels else None
    )

    class AlertObj:
        def __init__(self, labels):
            self.labels = labels

    async def _active_alerts(**_kwargs):
        return [AlertObj({"alertname": "CPUHigh"})]

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _active_alerts)
    with pytest.raises(HTTPException) as exc:
        await incidents_router.update_incident(
            "inc-2",
            AlertIncidentUpdateRequest.model_validate({"status": "resolved"}),
            _user(),
        )
    assert exc.value.status_code == 400

    async def _boom_alerts(**_kwargs):
        import httpx

        raise httpx.RequestError("boom", request=httpx.Request("GET", "https://am"))

    async def _async_noop(*_args, **_kwargs):
        return None

    async def _async_email(**_kwargs):
        return None

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _boom_alerts)
    monkeypatch.setattr(
        incidents_router.storage_service,
        "update_incident",
        lambda *_args: _incident("inc-2", status="resolved", labels={"alertname": "CPUHigh"}),
    )
    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _async_noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _async_noop)
    monkeypatch.setattr(incidents_router.notification_service, "send_incident_assignment_email", _async_email)
    updated = await incidents_router.update_incident(
        "inc-2",
        AlertIncidentUpdateRequest.model_validate({"status": "resolved", "note": "done"}),
        _user(),
    )
    assert updated.status == IncidentStatus.RESOLVED


@pytest.mark.asyncio
async def test_rules_and_silences_additional_branch_paths(monkeypatch):
    monkeypatch.setattr(rules_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(silences_router, "run_in_threadpool", _run_in_threadpool)

    # public rules path with tenant resolution missing then present
    monkeypatch.setattr(rules_router, "enforce_public_endpoint_security", lambda *_args, **_kwargs: None)

    class _TenantQuery:
        def __init__(self, tenant):
            self.tenant = tenant

        def filter_by(self, **_kwargs):
            return self

        def first(self):
            return self.tenant

    class _TenantDB:
        def __init__(self, tenant):
            self.tenant = tenant

        def query(self, *_args, **_kwargs):
            return _TenantQuery(self.tenant)

    from contextlib import contextmanager

    @contextmanager
    def _ctx_none():
        yield _TenantDB(None)

    @contextmanager
    def _ctx_with_tenant():
        yield _TenantDB(SimpleNamespace(id="tenant-default"))

    monkeypatch.setattr(rules_router, "get_db_session", _ctx_none)
    assert await rules_router.list_public_rules(_request()) == []

    monkeypatch.setattr(rules_router, "get_db_session", _ctx_with_tenant)
    monkeypatch.setattr(
        rules_router.storage_service, "get_public_alert_rules", lambda tenant_id: [_rule_model("r1", "RuleOne")]
    )
    assert len(await rules_router.list_public_rules(_request())) == 1

    # metric endpoints missing org_id branches
    with pytest.raises(HTTPException):
        await rules_router.query_metrics(query="up", org_id=None, current_user=_user(org_id=""))
    with pytest.raises(HTTPException):
        await rules_router.list_metric_labels(org_id=None, current_user=_user(org_id=""))
    with pytest.raises(HTTPException):
        await rules_router.list_metric_label_values("job", org_id=None, metric_name=None, current_user=_user(org_id=""))

    # rules hide/toggle false
    monkeypatch.setattr(rules_router.alertmanager_service, "user_scope", lambda _u: ("tenant-a", "u1", ["g1"]))
    monkeypatch.setattr(rules_router.storage_service, "get_alert_rule", lambda *_args: _rule_model("r1", "RuleOne"))
    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule_raw", lambda *_args: SimpleNamespace(created_by="u2")
    )
    monkeypatch.setattr(rules_router.storage_service, "toggle_rule_hidden", lambda *_args: False)
    with pytest.raises(HTTPException) as exc:
        await rules_router.hide_rule("r1", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 404

    # update/delete missing branches
    monkeypatch.setattr(rules_router.storage_service, "get_alert_rule", lambda *_args: None)
    with pytest.raises(HTTPException):
        await rules_router.update_rule("missing", _rule_create("RuleX"), _user())
    with pytest.raises(HTTPException):
        await rules_router.delete_rule("missing", _user())

    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule", lambda *_args: _rule_model("r1", "RuleOne", org_id="org-a")
    )
    monkeypatch.setattr(rules_router.storage_service, "update_alert_rule", lambda *_args: None)
    monkeypatch.setattr(rules_router.alertmanager_service, "resolve_rule_org_id", lambda *_args: "org-a")
    with pytest.raises(HTTPException):
        await rules_router.update_rule("r1", _rule_create("RuleOne", org_id="org-a"), _user())

    # silences additional error paths
    async def _none_silence(_sid):
        return None

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _none_silence)
    with pytest.raises(HTTPException):
        await silences_router.get_silence("missing", request=_request(), current_user=_user())
    with pytest.raises(HTTPException):
        await silences_router.update_silence(
            "missing",
            SilenceCreateRequest.model_validate(
                {
                    "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
                    "startsAt": "2026-01-01T00:00:00Z",
                    "endsAt": "2026-01-01T01:00:00Z",
                    "comment": "x",
                }
            ),
            current_user=_user(),
        )
    with pytest.raises(HTTPException):
        await silences_router.delete_silence("missing", _user())


@pytest.mark.asyncio
async def test_incidents_jira_links_and_integrations_additional_branches(monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    from routers.observability import incidents as incidents_router

    monkeypatch.setattr(jira_integrations_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(jira_links_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(incidents_router, "run_in_threadpool", _run_in_threadpool)

    # incidents router: SQLAlchemyError while writing assignment note, reopened status note, and move-to-todo
    existing = _incident("inc-3", status=IncidentStatus.RESOLVED, assignee="bob@example.com")
    updated = _incident("inc-3", status=IncidentStatus.OPEN, assignee="")
    call_count = {"n": 0}

    def _update_incident(*_args, **_kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return updated
        raise SQLAlchemyError("note fail")

    async def _noop(*_args, **_kwargs):
        return None

    async def _email(**_kwargs):
        return None

    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: existing)
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", _update_incident)
    monkeypatch.setattr(incidents_router, "sync_note_to_jira_comment", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_done", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_todo", _noop)
    monkeypatch.setattr(incidents_router, "move_incident_ticket_to_in_progress", _noop)
    monkeypatch.setattr(incidents_router.notification_service, "send_incident_assignment_email", _email)
    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", lambda **_kwargs: [])
    out = await incidents_router.update_incident(
        "inc-3", AlertIncidentUpdateRequest.model_validate({"status": "open", "assignee": ""}), _user()
    )
    assert out.status == IncidentStatus.OPEN

    # jira integrations: no-access filter, update missing, delete non-owner, hide not-found/own/fail
    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i1", "createdBy": "u2", "visibility": "group"}],
    )
    monkeypatch.setattr(jira_integrations_router.storage_service, "get_hidden_jira_integration_ids", lambda *_args: [])
    monkeypatch.setattr(jira_integrations_router, "jira_integration_has_access", lambda *_args, **_kwargs: False)
    assert (
        await jira_integrations_router.list_jira_integrations(
            request=_request(), show_hidden=True, current_user=_user()
        )
    )["items"] == []

    monkeypatch.setattr(jira_integrations_router, "load_tenant_jira_integrations", lambda _tenant: [])
    with pytest.raises(HTTPException):
        await jira_integrations_router.update_jira_integration("missing", JiraIntegrationUpdateRequest(), _user())

    monkeypatch.setattr(
        jira_integrations_router, "load_tenant_jira_integrations", lambda _tenant: [{"id": "i1", "createdBy": "u2"}]
    )
    with pytest.raises(HTTPException):
        await jira_integrations_router.delete_jira_integration("i1", _user())

    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i1", "createdBy": "u2", "visibility": "group"}],
    )
    monkeypatch.setattr(jira_integrations_router, "jira_integration_has_access", lambda *_args, **_kwargs: False)
    with pytest.raises(HTTPException):
        await jira_integrations_router.hide_jira_integration("i1", HideTogglePayload(hidden=True), _user())

    monkeypatch.setattr(jira_integrations_router, "jira_integration_has_access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i1", "createdBy": "u1", "visibility": "group"}],
    )
    with pytest.raises(HTTPException):
        await jira_integrations_router.hide_jira_integration("i1", HideTogglePayload(hidden=True), _user())

    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "i1", "createdBy": "u2", "visibility": "group"}],
    )
    monkeypatch.setattr(
        jira_integrations_router.storage_service, "toggle_jira_integration_hidden", lambda *_args: False
    )
    with pytest.raises(HTTPException):
        await jira_integrations_router.hide_jira_integration("i1", HideTogglePayload(hidden=True), _user())

    # jira links: missing project, unsupported issue type, persist failure, sync and comments error branches
    monkeypatch.setattr(jira_links_router.storage_service, "get_incident_for_user", lambda *_args: _incident("inc-4"))
    monkeypatch.setattr(jira_links_router, "resolve_jira_integration", lambda *_args, **_kwargs: {"id": "i1"})
    monkeypatch.setattr(jira_links_router, "integration_is_usable", lambda _item: True)

    with pytest.raises(HTTPException):
        await jira_links_router.create_incident_link(
            "inc-4",
            IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": " "}),
            _user(),
        )

    with pytest.raises(HTTPException):
        await jira_links_router.create_incident_link(
            "inc-4",
            IncidentJiraCreateRequest.model_validate(
                {"integrationId": "i1", "projectKey": "OPS", "issueType": "Story"}
            ),
            _user(),
        )

    monkeypatch.setattr(jira_links_router, "jira_integration_credentials", lambda _item: {"base_url": "https://jira"})
    monkeypatch.setattr(jira_links_router, "format_incident_description", lambda *_args: "desc")
    monkeypatch.setattr(jira_links_router, "map_severity_to_jira_priority", lambda *_args: "High")

    async def _issue_no_key(**_kwargs):
        return {"key": "", "url": "https://jira/browse/none"}

    monkeypatch.setattr(jira_links_router.jira_service, "create_issue", _issue_no_key)
    monkeypatch.setattr(jira_links_router.jira_service, "transition_issue_to_todo", _noop)
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: ["n1"])
    monkeypatch.setattr(jira_links_router.storage_service, "update_incident", lambda *_args: _incident("inc-4"))
    with pytest.raises(HTTPException):
        await jira_links_router.create_incident_link(
            "inc-4",
            IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS", "issueType": "Task"}),
            _user(),
        )

    monkeypatch.setattr(jira_links_router.storage_service, "update_incident", lambda *_args: None)
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: [])
    with pytest.raises(HTTPException):
        await jira_links_router.create_incident_link(
            "inc-4",
            IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS", "issueType": "Task"}),
            _user(),
        )

    monkeypatch.setattr(jira_links_router.storage_service, "get_incident_for_user", lambda *_args: None)
    with pytest.raises(HTTPException):
        await jira_links_router.sync_incident_notes("missing", _user())
    with pytest.raises(HTTPException):
        await jira_links_router.list_incident_comments("missing", _user())

    monkeypatch.setattr(
        jira_links_router.storage_service,
        "get_incident_for_user",
        lambda *_args: _incident("inc-4", jiraTicketKey="OPS-4", jiraIntegrationId="i1"),
    )
    monkeypatch.setattr(
        jira_links_router, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"}
    )
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: ["n1"])

    async def _list_boom(*_args, **_kwargs):
        raise JiraError("comments failed")

    monkeypatch.setattr(jira_links_router.jira_service, "list_comments", _list_boom)
    with pytest.raises(HTTPException):
        await jira_links_router.sync_incident_notes("inc-4", _user())
    with pytest.raises(HTTPException):
        await jira_links_router.list_incident_comments("inc-4", _user())

    monkeypatch.setattr(jira_links_router.jira_service, "list_comments", lambda *_args, **_kwargs: [])

    async def _add_boom(*_args, **_kwargs):
        raise JiraError("add failed")

    monkeypatch.setattr(jira_links_router.jira_service, "add_comment", _add_boom)
    with pytest.raises(HTTPException):
        await jira_links_router.sync_incident_notes("inc-4", _user())


@pytest.mark.asyncio
async def test_router_remaining_line_edges(monkeypatch):
    monkeypatch.setattr(alerts_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(channels_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(rules_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(silences_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(jira_links_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(jira_integrations_router, "run_in_threadpool", _run_in_threadpool)

    # alerts route: post failure branch
    async def _post_fail(_alerts):
        return False

    monkeypatch.setattr(alerts_router.alertmanager_service, "post_alerts", _post_fail)
    with pytest.raises(HTTPException) as exc:
        await alerts_router.create_alerts([Alert.model_validate(_alert_dict("A"))], _user())
    assert exc.value.status_code == 500

    monkeypatch.setattr(alerts_router.alertmanager_service, "parse_filter_labels", lambda _value: {"alertname": "A"})

    async def _single_alerts(**_kwargs):
        return [Alert.model_validate(_alert_dict("A"))]

    monkeypatch.setattr(alerts_router.alertmanager_service, "get_alerts", _single_alerts)
    monkeypatch.setattr(alerts_router, "sync_incidents", lambda *_args, **_kwargs: _run_in_threadpool(lambda: None))
    monkeypatch.setattr(alerts_router.storage_service, "filter_alerts_for_user", lambda *_args: [_alert_dict("A")])
    monkeypatch.setattr(alerts_router.storage_service, "get_hidden_rule_names", lambda *_args: [])
    visible_alerts = await alerts_router.list_alerts(
        filter_labels='{"alertname":"A"}', show_hidden=False, current_user=_user()
    )
    assert len(visible_alerts) == 1

    # channels route: hide/test missing channel branches
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _u: ("tenant-a", "u1", ["g1"]))
    monkeypatch.setattr(channels_router.storage_service, "get_notification_channel", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await channels_router.hide_channel("missing", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 404

    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("missing", _user())
    assert exc.value.status_code == 404

    # rules route: current id none in import + hide/test not found
    monkeypatch.setattr(rules_router.alertmanager_service, "user_scope", lambda _u: ("tenant-a", "u1", ["g1"]))

    creator_field = rules_router._with_creator_username(
        _rule_create("NoCreator"), SimpleNamespace(username=None, user_id=None)
    )
    assert "watchdogCreatedByUsername" not in (creator_field.annotations or {})

    monkeypatch.setattr(rules_router, "parse_rules_yaml", lambda *_args: [_rule_create("RuleOne", "org-a")])
    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rules",
        lambda *_args: [SimpleNamespace(id=None, name="RuleOne", group="default", org_id="org-a")],
    )
    imported = await rules_router.import_rules(
        RuleImportRequest.model_validate({"yamlContent": "groups: []", "dryRun": False}),
        _user(),
    )
    assert imported["count"] == 0

    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rules",
        lambda *_args: [SimpleNamespace(id="r1", name="RuleOne", group="default", org_id="org-a")],
    )
    monkeypatch.setattr(rules_router.storage_service, "update_alert_rule", lambda *_args: None)
    imported = await rules_router.import_rules(
        RuleImportRequest.model_validate({"yamlContent": "groups: []", "dryRun": False}),
        _user(),
    )
    assert imported["updated"] == 0

    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rule",
        lambda *_args: _rule_model("r1", "RuleOne", created_by="u1", org_id="org-a"),
    )
    monkeypatch.setattr(rules_router.storage_service, "get_hidden_rule_ids", lambda *_args: [])
    monkeypatch.setattr(rules_router.storage_service, "get_alert_rule_raw", lambda *_args: None)
    looked_up = await rules_router.get_rule("r1", _user())
    assert looked_up.org_id == "org-a"

    monkeypatch.setattr(
        rules_router.alertmanager_service, "resolve_rule_org_id", lambda org_id, _user: org_id or "org-a"
    )
    monkeypatch.setattr(
        rules_router.storage_service,
        "create_alert_rule",
        lambda *_args: _rule_model("r-create", "RuleCreate", org_id="org-a"),
    )
    monkeypatch.setattr(rules_router.storage_service, "get_alert_rules_for_org", lambda *_args: [])
    monkeypatch.setattr(
        rules_router.alertmanager_service,
        "sync_mimir_rules_for_org",
        lambda *_args, **_kwargs: _run_in_threadpool(lambda: None),
    )
    created_same_org = await rules_router.create_rule(_rule_create("RuleCreate", org_id="org-a"), _user(org_id="org-a"))
    assert created_same_org.org_id == "org-a"

    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule", lambda *_args: _rule_model("r1", "RuleOne", org_id=None)
    )
    monkeypatch.setattr(
        rules_router.storage_service, "update_alert_rule", lambda *_args: _rule_model("r1", "RuleOne", org_id=None)
    )
    updated_same_org = await rules_router.update_rule("r1", _rule_create("RuleOne", org_id=None), _user(org_id="org-a"))
    assert updated_same_org.id == "r1"

    monkeypatch.setattr(
        rules_router.storage_service, "get_notification_channels_for_rule_name", lambda *_args: [_channel("c1")]
    )
    monkeypatch.setattr(
        rules_router.notification_service, "send_notification", lambda *_args: _run_in_threadpool(lambda: False)
    )
    failed_test = await rules_router.test_rule("r1", _request(), _user())
    assert failed_test["status"] == "failed"

    monkeypatch.setattr(rules_router.storage_service, "get_alert_rule", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await rules_router.hide_rule("missing", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await rules_router.test_rule("missing", _request(), _user())
    assert exc.value.status_code == 404

    # silences route: inaccessible, update failure, delete failure, and hide missing
    async def _get_silence(_sid):
        return _silence("s1", owner="u2", state="active")

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _get_silence)
    monkeypatch.setattr(silences_router.alertmanager_service, "apply_silence_metadata", lambda s: s)
    monkeypatch.setattr(silences_router.alertmanager_service, "silence_accessible", lambda *_args: False)

    with pytest.raises(HTTPException) as exc:
        await silences_router.get_silence("s1", request=_request(), current_user=_user())
    assert exc.value.status_code == 404

    payload = SilenceCreateRequest.model_validate(
        {
            "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
            "startsAt": "2026-01-01T00:00:00Z",
            "endsAt": "2026-01-01T01:00:00Z",
            "comment": "x",
        }
    )

    with pytest.raises(HTTPException) as exc:
        await silences_router.update_silence("s1", payload, _user())
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await silences_router.delete_silence("s1", _user())
    assert exc.value.status_code == 404

    monkeypatch.setattr(silences_router.alertmanager_service, "silence_accessible", lambda *_args: True)
    monkeypatch.setattr(silences_router.alertmanager_service, "silence_owned_by", lambda *_args: True)

    async def _update_none(*_args, **_kwargs):
        return None

    monkeypatch.setattr(silences_router.alertmanager_service, "update_silence", _update_none)
    with pytest.raises(HTTPException) as exc:
        await silences_router.update_silence("s1", payload, _user())
    assert exc.value.status_code == 500

    async def _delete_false(*_args, **_kwargs):
        return False

    monkeypatch.setattr(silences_router.alertmanager_service, "delete_silence", _delete_false)
    with pytest.raises(HTTPException) as exc:
        await silences_router.delete_silence("s1", _user())
    assert exc.value.status_code == 404

    async def _none_silence(_sid):
        return None

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _none_silence)
    with pytest.raises(HTTPException) as exc:
        await silences_router.hide_silence("missing", HideTogglePayload(hidden=True), _user())
    assert exc.value.status_code == 404

    # incidents route: fallback fingerprint fetch and update-missing branch
    from routers.observability import incidents as incidents_router

    monkeypatch.setattr(incidents_router, "run_in_threadpool", _run_in_threadpool)

    base_incident = _incident("inc-line", labels={}, fingerprint="fp-line", status=IncidentStatus.OPEN)
    monkeypatch.setattr(incidents_router.storage_service, "get_incident_for_user", lambda *_args: base_incident)

    seen = {}

    async def _alerts_by_fingerprint(**kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", _alerts_by_fingerprint)
    monkeypatch.setattr(
        incidents_router.storage_service,
        "update_incident",
        lambda *_args: _incident("inc-line", labels={}, status=IncidentStatus.RESOLVED),
    )
    monkeypatch.setattr(
        incidents_router, "sync_note_to_jira_comment", lambda *_args, **_kwargs: _run_in_threadpool(lambda: None)
    )
    monkeypatch.setattr(
        incidents_router, "move_incident_ticket_to_done", lambda *_args, **_kwargs: _run_in_threadpool(lambda: None)
    )
    monkeypatch.setattr(
        incidents_router, "move_incident_ticket_to_todo", lambda *_args, **_kwargs: _run_in_threadpool(lambda: None)
    )
    monkeypatch.setattr(
        incidents_router,
        "move_incident_ticket_to_in_progress",
        lambda *_args, **_kwargs: _run_in_threadpool(lambda: None),
    )
    monkeypatch.setattr(
        incidents_router.notification_service,
        "send_incident_assignment_email",
        lambda **_kwargs: _run_in_threadpool(lambda: None),
    )

    patched = await incidents_router.update_incident(
        "inc-line",
        AlertIncidentUpdateRequest.model_validate({"status": "resolved"}),
        _user(),
    )
    assert patched.status == IncidentStatus.RESOLVED
    assert seen.get("filter_labels") == {"fingerprint": "fp-line"}

    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await incidents_router.update_incident("inc-line", AlertIncidentUpdateRequest(), _user())
    assert exc.value.status_code == 404

    weird_updated = SimpleNamespace(status="investigating", assignee=None, alert_name="CPU", severity="warning")
    monkeypatch.setattr(incidents_router.storage_service, "update_incident", lambda *_args: weird_updated)
    monkeypatch.setattr(incidents_router.alertmanager_service, "get_alerts", lambda **_kwargs: [])
    patched_weird = await incidents_router.update_incident(
        "inc-line",
        AlertIncidentUpdateRequest.model_validate({"status": "investigating"}),
        _user(),
    )
    assert patched_weird.status == "investigating"

    # jira discovery: disabled issue types branch
    monkeypatch.setattr(jira_discovery_router, "jira_is_enabled_for_tenant", lambda _tenant: False)
    disabled = await jira_discovery_router.list_jira_issue_types("OPS", integration_id=None, current_user=_user())
    assert disabled == {"enabled": False, "issueTypes": []}

    # jira links: warning-only transition/backfill failures
    monkeypatch.setattr(
        jira_links_router.storage_service, "get_incident_for_user", lambda *_args: _incident("inc-warn")
    )
    monkeypatch.setattr(jira_links_router, "resolve_jira_integration", lambda *_args, **_kwargs: {"id": "i1"})
    monkeypatch.setattr(jira_links_router, "integration_is_usable", lambda _item: True)
    monkeypatch.setattr(jira_links_router, "jira_integration_credentials", lambda _item: {"base_url": "https://jira"})
    monkeypatch.setattr(jira_links_router, "format_incident_description", lambda *_args: "desc")
    monkeypatch.setattr(jira_links_router, "map_severity_to_jira_priority", lambda *_args: "High")

    async def _issue_ok(**_kwargs):
        return {"key": "OPS-99", "url": "https://jira/browse/OPS-99"}

    async def _transition_boom(**_kwargs):
        raise JiraError("no transition")

    async def _comment_boom(*_args, **_kwargs):
        raise JiraError("no comment")

    monkeypatch.setattr(jira_links_router.jira_service, "create_issue", _issue_ok)
    monkeypatch.setattr(jira_links_router.jira_service, "transition_issue_to_todo", _transition_boom)
    monkeypatch.setattr(jira_links_router.jira_service, "add_comment", _comment_boom)
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: ["note-1"])
    monkeypatch.setattr(
        jira_links_router.storage_service,
        "update_incident",
        lambda *_args: _incident(
            "inc-warn", jiraTicketKey="OPS-99", jiraTicketUrl="https://jira/browse/OPS-99", jiraIntegrationId="i1"
        ),
    )

    linked = await jira_links_router.create_incident_link(
        "inc-warn",
        IncidentJiraCreateRequest.model_validate({"integrationId": "i1", "projectKey": "OPS", "issueType": "Task"}),
        _user(),
    )
    assert linked.jira_ticket_key == "OPS-99"

    monkeypatch.setattr(
        jira_links_router.storage_service,
        "get_incident_for_user",
        lambda *_args: _incident("inc-cred", jiraTicketKey="OPS-1", jiraIntegrationId="i1"),
    )
    monkeypatch.setattr(jira_links_router, "resolve_incident_jira_credentials", lambda *_args: None)
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.sync_incident_notes("inc-cred", _user())
    assert exc.value.status_code == 400
    assert (await jira_links_router.list_incident_comments("inc-cred", _user())) == {"comments": []}

    async def _list_no_comments(*_args, **_kwargs):
        return []

    async def _add_comment_fail(*_args, **_kwargs):
        raise JiraError("sync add failed")

    monkeypatch.setattr(
        jira_links_router, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"}
    )
    monkeypatch.setattr(jira_links_router, "build_formatted_incident_note_bodies", lambda *_args: ["new-note"])
    monkeypatch.setattr(jira_links_router.jira_service, "list_comments", _list_no_comments)
    monkeypatch.setattr(jira_links_router.jira_service, "add_comment", _add_comment_fail)
    with pytest.raises(HTTPException) as exc:
        await jira_links_router.sync_incident_notes("inc-cred", _user())
    assert exc.value.status_code == 502

    # jira integrations: non-group visibility cleanup and supportsSso input field path
    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [
            {
                "id": "i-edge",
                "createdBy": "u1",
                "visibility": "group",
                "sharedGroupIds": ["g1"],
                "authMode": "api_token",
            }
        ],
    )
    monkeypatch.setattr(jira_integrations_router, "normalize_visibility", lambda value, default: str(value or default))
    monkeypatch.setattr(jira_integrations_router, "validate_shared_group_ids_for_user", lambda *_args: ["g1"])
    monkeypatch.setattr(jira_integrations_router, "normalize_jira_auth_mode", lambda _value: "api_token")
    monkeypatch.setattr(jira_integrations_router, "validate_jira_credentials", lambda **_kwargs: None)
    monkeypatch.setattr(jira_integrations_router, "decrypt_tenant_secret", lambda value: value)
    monkeypatch.setattr(jira_integrations_router, "save_tenant_jira_integrations", lambda *_args: None)
    monkeypatch.setattr(jira_integrations_router, "mask_jira_integration", lambda item, _user: item)

    updated = await jira_integrations_router.update_jira_integration(
        "i-edge",
        JiraIntegrationUpdateRequest.model_validate({"visibility": "private", "supportsSso": True}),
        _user(),
    )
    assert updated["sharedGroupIds"] == []
    assert updated["supportsSso"] is False

    updated_no_visibility = await jira_integrations_router.update_jira_integration(
        "i-edge",
        JiraIntegrationUpdateRequest.model_validate({"name": "renamed"}),
        _user(),
    )
    assert updated_no_visibility["name"] == "renamed"


@pytest.mark.asyncio
async def test_router_query_param_and_test_rule_remaining_branches(monkeypatch):
    bad_channels_request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/channels",
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"unexpected=true",
        }
    )
    with pytest.raises(HTTPException) as exc:
        await channels_router.list_channels(request=bad_channels_request, current_user=_user())
    assert exc.value.status_code == 400

    bad_silences_list_request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/silences",
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"bad=1",
        }
    )
    with pytest.raises(HTTPException) as exc:
        await silences_router.list_silences(request=bad_silences_list_request, current_user=_user())
    assert exc.value.status_code == 400

    bad_silence_get_request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/silences/s1",
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"bad=1",
        }
    )
    with pytest.raises(HTTPException) as exc:
        await silences_router.get_silence("s1", request=bad_silence_get_request, current_user=_user())
    assert exc.value.status_code == 400

    bad_jira_integrations_request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/integrations/jira",
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"bad=1",
        }
    )
    with pytest.raises(HTTPException) as exc:
        await jira_integrations_router.list_jira_integrations(
            request=bad_jira_integrations_request, current_user=_user()
        )
    assert exc.value.status_code == 400

    monkeypatch.setattr(rules_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(
        rules_router.storage_service, "get_alert_rule", lambda *_args: _rule_model("r-time", "RuleTime")
    )
    monkeypatch.setattr(
        rules_router.storage_service,
        "get_notification_channels_for_rule_name",
        lambda *_args: [_channel("c1"), _channel("c2")],
    )

    async def _ok_send(*_args, **_kwargs):
        return True

    monkeypatch.setattr(rules_router.notification_service, "send_notification", _ok_send)
    schemathesis_request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": "/rules/r-time/test",
            "headers": [(b"user-agent", b"schemathesis/4.0")],
            "client": ("203.0.113.10", 12345),
            "scheme": "http",
            "query_string": b"",
        }
    )
    simulated = await rules_router.test_rule("r-time", schemathesis_request, _user())
    assert simulated["status"] == "success"
    assert all(item["simulated"] for item in simulated["results"])

    async def _timeout_wait_for(*_args, **_kwargs):
        if _args:
            maybe_coro = _args[0]
            close = getattr(maybe_coro, "close", None)
            if callable(close):
                close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr(rules_router.asyncio, "wait_for", _timeout_wait_for)
    timed_out = await rules_router.test_rule("r-time", _request(), _user())
    assert timed_out["status"] == "failed"
    assert all(item["ok"] is False for item in timed_out["results"])


@pytest.mark.asyncio
async def test_router_list_endpoints_skip_unknown_query_rejection_when_request_none(monkeypatch):
    def _should_not_be_called(*_args, **_kwargs):
        raise AssertionError("reject_unknown_query_params should not run when request is None")

    monkeypatch.setattr(channels_router, "reject_unknown_query_params", _should_not_be_called)
    monkeypatch.setattr(channels_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(channels_router.storage_service, "get_notification_channels", lambda *_args: [_channel("c1")])
    monkeypatch.setattr(channels_router.storage_service, "get_hidden_channel_ids", lambda *_args: [])
    channels = await channels_router.list_channels(request=None, current_user=_user())
    assert len(channels) == 1

    monkeypatch.setattr(rules_router, "reject_unknown_query_params", _should_not_be_called)
    monkeypatch.setattr(rules_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(rules_router.storage_service, "get_hidden_rule_ids", lambda *_args: [])
    monkeypatch.setattr(
        rules_router.storage_service,
        "get_alert_rules_with_owner",
        lambda *_args: [(_rule_model("r1", "Rule One"), "u1")],
    )
    rules = await rules_router.list_rules(request=None, current_user=_user())
    assert len(rules) == 1

    monkeypatch.setattr(silences_router, "reject_unknown_query_params", _should_not_be_called)
    monkeypatch.setattr(silences_router, "run_in_threadpool", _run_in_threadpool)

    async def _list_silences(*_args, **_kwargs):
        return [_silence("s1")]

    async def _get_silence(*_args, **_kwargs):
        return _silence("s1")

    monkeypatch.setattr(silences_router.alertmanager_service, "get_silences", _list_silences)
    monkeypatch.setattr(silences_router.alertmanager_service, "get_silence", _get_silence)
    monkeypatch.setattr(silences_router.alertmanager_service, "parse_filter_labels", lambda _value: {})
    monkeypatch.setattr(silences_router.alertmanager_service, "apply_silence_metadata", lambda silence: silence)
    monkeypatch.setattr(silences_router.alertmanager_service, "silence_accessible", lambda *_args: True)
    monkeypatch.setattr(silences_router.storage_service, "get_hidden_silence_ids", lambda *_args: [])
    silences = await silences_router.list_silences(request=None, current_user=_user())
    assert len(silences) == 1
    silence = await silences_router.get_silence("s1", request=None, current_user=_user())
    assert silence.id == "s1"

    monkeypatch.setattr(jira_integrations_router, "reject_unknown_query_params", _should_not_be_called)
    monkeypatch.setattr(jira_integrations_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(
        jira_integrations_router,
        "load_tenant_jira_integrations",
        lambda _tenant: [{"id": "jira-1", "createdBy": "u1", "visibility": "private"}],
    )
    monkeypatch.setattr(jira_integrations_router, "jira_integration_has_access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(jira_integrations_router, "mask_jira_integration", lambda item, _user: dict(item))
    monkeypatch.setattr(jira_integrations_router.storage_service, "get_hidden_jira_integration_ids", lambda *_args: [])
    integrations = await jira_integrations_router.list_jira_integrations(request=None, current_user=_user())
    assert len(integrations["items"]) == 1
