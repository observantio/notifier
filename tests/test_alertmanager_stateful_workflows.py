"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import Request

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from models.alerting.requests import AlertWebhookRequest
from models.alerting.rules import AlertRule, AlertRuleCreate
from routers.observability.alerts import channels as channels_router
from routers.observability.alerts import router as alerts_router
from routers.observability.alerts import rules as rules_router
from routers.observability.alerts import webhook_router
from routers.observability.alerts import webhooks as webhooks_router
from routers.observability.incidents import router as incidents_router
from routers.observability.jira import router as jira_router
from services.storage.channels import ChannelStorageService


def _user(**overrides: Any) -> TokenData:
    payload = {
        "user_id": "user-1",
        "username": "alice",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.ADMIN,
        "permissions": ["write:alerts", "write:channels", "test:rules"],
        "group_ids": ["ops"],
        "is_superuser": False,
    }
    payload.update(overrides)
    return TokenData(**payload)


def _request(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": path,
            "headers": headers or [],
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "query_string": b"",
        }
    )


async def _run_in_threadpool(func, *args, **kwargs):
    return func(*args, **kwargs)


class _FakeNotificationService:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    async def send_notification(self, channel: NotificationChannel, alert, action: str = "firing") -> bool:
        _ = alert
        self.sent.append((str(channel.id or channel.name), action))
        return True


class _FakeStorage:
    def __init__(self) -> None:
        self.channels: dict[str, NotificationChannel] = {}
        self.rules: dict[str, AlertRule] = {}
        self._channel_counter = 0
        self._rule_counter = 0
        self.incident_sync_calls = 0

    @staticmethod
    def _access_parts(access: object) -> tuple[str, list[str]]:
        if hasattr(access, "user_id"):
            return str(getattr(access, "user_id", "")), list(getattr(access, "group_ids", []) or [])
        return str(access), []

    def create_notification_channel(
        self,
        channel_create: NotificationChannelCreate,
        tenant_id: str,
        access: object,
        group_ids: list[str] | None = None,
    ):
        user_id, context_groups = self._access_parts(access)
        _ = group_ids, context_groups
        self._channel_counter += 1
        channel_id = f"ch-{self._channel_counter}"
        channel = NotificationChannel.model_validate(
            {
                "id": channel_id,
                "name": channel_create.name,
                "type": channel_create.type,
                "enabled": channel_create.enabled,
                "config": dict(channel_create.config or {}),
                "createdBy": user_id,
                "visibility": channel_create.visibility,
                "sharedGroupIds": channel_create.shared_group_ids,
            }
        )
        self.channels[f"{tenant_id}:{channel_id}"] = channel
        return channel

    def create_alert_rule(
        self,
        rule_create: AlertRuleCreate,
        tenant_id: str,
        access: object,
        group_ids: list[str] | None = None,
    ):
        user_id, context_groups = self._access_parts(access)
        _ = group_ids, context_groups
        self._rule_counter += 1
        rule_id = f"rule-{self._rule_counter}"
        rule = AlertRule.model_validate(
            {
                "id": rule_id,
                "createdBy": user_id,
                "orgId": rule_create.org_id,
                "name": rule_create.name,
                "expression": rule_create.expr,
                "severity": rule_create.severity,
                "description": rule_create.description,
                "enabled": rule_create.enabled,
                "labels": dict(rule_create.labels or {}),
                "annotations": dict(rule_create.annotations or {}),
                "for": rule_create.duration,
                "groupName": rule_create.group,
                "groupInterval": rule_create.group_interval,
                "notificationChannels": list(rule_create.notification_channels or []),
                "visibility": rule_create.visibility,
                "sharedGroupIds": list(rule_create.shared_group_ids or []),
            }
        )
        self.rules[f"{tenant_id}:{rule_id}"] = rule
        return rule

    def get_alert_rule(self, rule_id: str, tenant_id: str, access: object, group_ids: list[str] | None = None):
        _ = access, group_ids
        return self.rules.get(f"{tenant_id}:{rule_id}")

    def get_alert_rules_for_org(self, tenant_id: str, org_id: str):
        return [
            r for key, r in self.rules.items() if key.startswith(f"{tenant_id}:") and str(r.org_id or "") == str(org_id)
        ]

    def get_notification_channels_for_rule_name(self, tenant_id: str, rule_name: str, org_id: str | None = None):
        matched_rules = [
            r for key, r in self.rules.items() if key.startswith(f"{tenant_id}:") and r.enabled and r.name == rule_name
        ]
        if org_id:
            matched_rules = (
                [r for r in matched_rules if str(r.org_id or "") == str(org_id)]
                or [r for r in matched_rules if not r.org_id]
                or matched_rules
            )
        if not matched_rules:
            return []

        out: list[NotificationChannel] = []
        seen: set[str] = set()
        for rule in matched_rules:
            configured = [str(cid) for cid in (rule.notification_channels or []) if str(cid).strip()]
            candidates = []
            if configured:
                for channel_id in configured:
                    ch = self.channels.get(f"{tenant_id}:{channel_id}")
                    if ch:
                        candidates.append(ch)
            else:
                candidates = [ch for key, ch in self.channels.items() if key.startswith(f"{tenant_id}:")]

            for ch in candidates:
                if str(ch.id) in seen or not bool(ch.enabled):
                    continue
                rule_db = SimpleNamespace(
                    visibility=rule.visibility,
                    created_by=rule.created_by,
                    shared_groups=[SimpleNamespace(id=g) for g in (rule.shared_group_ids or [])],
                )
                channel_db = SimpleNamespace(
                    visibility=ch.visibility,
                    created_by=ch.created_by,
                    shared_groups=[SimpleNamespace(id=g) for g in (ch.shared_group_ids or [])],
                )
                if not ChannelStorageService._rule_channel_compatible(rule_db, channel_db):
                    continue
                out.append(ch)
                seen.add(str(ch.id))
        return out

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: list[dict[str, Any]], _):
        _ = tenant_id, alerts
        self.incident_sync_calls += 1
        return {"status": "ok"}


@pytest.mark.asyncio
async def test_stateful_channel_rule_test_and_webhook_workflow(monkeypatch):
    fake_storage = _FakeStorage()
    fake_notification = _FakeNotificationService()
    current_user = _user()

    async def _notify_for_alerts(context, alerts_list: list[dict[str, Any]]):
        tenant_id = context.tenant_id
        storage = context.storage_service
        notification = context.notification_service
        for incoming in alerts_list:
            labels = incoming.get("labels") or {}
            alertname = str(labels.get("alertname") or "")
            channels = storage.get_notification_channels_for_rule_name(tenant_id, alertname, labels.get("org_id"))
            status = (incoming.get("status") or {}).get("state")
            action = "firing" if str(status or "").lower() in {"active", "firing"} else "resolved"
            for channel in channels:
                await notification.send_notification(channel, incoming, action)

    async def _sync_mimir(*_args, **_kwargs):
        return None

    async def _sync_incidents(tenant_id: str, alerts: list[dict[str, Any]], *, log_context: str):
        _ = log_context
        fake_storage.sync_incidents_from_alerts(tenant_id, alerts, False)

    monkeypatch.setattr(channels_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(rules_router, "run_in_threadpool", _run_in_threadpool)
    monkeypatch.setattr(channels_router, "validate_channel", lambda *_args, **_kwargs: "slack")

    monkeypatch.setattr(channels_router, "storage_service", fake_storage)
    monkeypatch.setattr(rules_router, "storage_service", fake_storage)
    monkeypatch.setattr(rules_router, "notification_service", fake_notification)

    monkeypatch.setattr(
        channels_router.alertmanager_service, "user_scope", lambda _u: (_u.tenant_id, _u.user_id, _u.group_ids)
    )
    monkeypatch.setattr(
        rules_router.alertmanager_service, "user_scope", lambda _u: (_u.tenant_id, _u.user_id, _u.group_ids)
    )
    monkeypatch.setattr(
        rules_router.alertmanager_service, "resolve_rule_org_id", lambda org_id, _u: org_id or _u.org_id
    )
    monkeypatch.setattr(rules_router.alertmanager_service, "sync_mimir_rules_for_org", _sync_mimir)

    monkeypatch.setattr(webhooks_router, "storage_service", fake_storage)
    monkeypatch.setattr(webhooks_router, "notification_service", fake_notification)
    monkeypatch.setattr(
        webhooks_router.alertmanager_service, "enforce_webhook_security", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(webhooks_router.alertmanager_service, "notify_for_alerts", _notify_for_alerts)
    monkeypatch.setattr(webhooks_router, "scope_header", lambda _request: "org-a")
    monkeypatch.setattr(webhooks_router, "infer_tenant_id_from_alerts", lambda _scope, _alerts: "tenant-a")
    monkeypatch.setattr(webhooks_router, "sync_incidents", _sync_incidents)

    created_channel = await channels_router.create_channel(
        NotificationChannelCreate.model_validate(
            {
                "name": "ops-slack",
                "type": "slack",
                "enabled": True,
                "config": {"webhook_url": "https://hooks.example.test"},
                "visibility": "private",
            }
        ),
        current_user,
    )

    created_rule = await rules_router.create_rule(
        AlertRuleCreate.model_validate(
            {
                "name": "CPU high",
                "expression": "up == 0",
                "severity": "critical",
                "groupName": "ops",
                "orgId": "org-a",
                "visibility": "private",
                "notificationChannels": [created_channel.id],
            }
        ),
        current_user,
    )

    tested = await rules_router.test_rule(
        str(created_rule.id),
        _request("/api/alertmanager/rules/test"),
        current_user,
    )
    assert tested["status"] == "success"
    assert "1/1" in str(tested["message"])
    assert ("ch-1", "test") in fake_notification.sent

    firing_payload = AlertWebhookRequest.model_validate(
        {
            "alerts": [
                {
                    "labels": {"alertname": "CPU high", "org_id": "org-a", "severity": "critical"},
                    "annotations": {"summary": "cpu high"},
                    "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
                }
            ]
        }
    )
    firing_result = await webhooks_router.receive_alert_webhook(_request("/alerts/webhook"), firing_payload)
    assert str(firing_result["status"]).lower() == "success"
    assert ("ch-1", "firing") in fake_notification.sent

    resolved_payload = AlertWebhookRequest.model_validate(
        {
            "alerts": [
                {
                    "labels": {"alertname": "CPU high", "org_id": "org-a"},
                    "annotations": {"summary": "resolved"},
                    "status": {"state": "resolved", "silencedBy": [], "inhibitedBy": []},
                }
            ]
        }
    )
    await webhooks_router.receive_alert_webhook(_request("/alerts/webhook"), resolved_payload)
    assert ("ch-1", "resolved") in fake_notification.sent
    assert fake_storage.incident_sync_calls >= 2


def _collect_routes(*routers) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for router in routers:
        for route in router.routes:
            methods = {m for m in getattr(route, "methods", set()) if m not in {"HEAD", "OPTIONS"}}
            for method in methods:
                out.add((method, route.path))
    return out


def test_observability_route_manifest_is_fully_registered():
    expected = {
        ("GET", "/api/alertmanager/alerts"),
        ("GET", "/api/alertmanager/alerts/groups"),
        ("POST", "/api/alertmanager/alerts"),
        ("DELETE", "/api/alertmanager/alerts"),
        ("POST", "/api/alertmanager/access/group-shares/prune"),
        ("GET", "/api/alertmanager/integrations/channel-types"),
        ("GET", "/api/alertmanager/silences"),
        ("GET", "/api/alertmanager/silences/{silence_id}"),
        ("POST", "/api/alertmanager/silences"),
        ("PUT", "/api/alertmanager/silences/{silence_id}"),
        ("DELETE", "/api/alertmanager/silences/{silence_id}"),
        ("POST", "/api/alertmanager/silences/{silence_id}/hide"),
        ("GET", "/api/alertmanager/status"),
        ("GET", "/api/alertmanager/receivers"),
        ("POST", "/api/alertmanager/rules/import"),
        ("GET", "/api/alertmanager/rules"),
        ("GET", "/api/alertmanager/public/rules"),
        ("GET", "/api/alertmanager/metrics/names"),
        ("GET", "/api/alertmanager/metrics/query"),
        ("GET", "/api/alertmanager/metrics/labels"),
        ("GET", "/api/alertmanager/metrics/label-values/{label}"),
        ("GET", "/api/alertmanager/rules/{rule_id}"),
        ("POST", "/api/alertmanager/rules/{rule_id}/hide"),
        ("POST", "/api/alertmanager/rules"),
        ("PUT", "/api/alertmanager/rules/{rule_id}"),
        ("POST", "/api/alertmanager/rules/{rule_id}/test"),
        ("DELETE", "/api/alertmanager/rules/{rule_id}"),
        ("GET", "/api/alertmanager/channels"),
        ("GET", "/api/alertmanager/channels/{channel_id}"),
        ("POST", "/api/alertmanager/channels/{channel_id}/hide"),
        ("POST", "/api/alertmanager/channels"),
        ("PUT", "/api/alertmanager/channels/{channel_id}"),
        ("DELETE", "/api/alertmanager/channels/{channel_id}"),
        ("POST", "/api/alertmanager/channels/{channel_id}/test"),
        ("POST", "/alerts/webhook"),
        ("POST", "/alerts/critical"),
        ("POST", "/alerts/warning"),
        ("GET", "/api/alertmanager/incidents"),
        ("GET", "/api/alertmanager/incidents/summary"),
        ("PATCH", "/api/alertmanager/incidents/{incident_id}"),
        ("GET", "/api/alertmanager/jira/config"),
        ("PUT", "/api/alertmanager/jira/config"),
        ("GET", "/api/alertmanager/jira/projects"),
        ("GET", "/api/alertmanager/jira/projects/{project_key}/issue-types"),
        ("GET", "/api/alertmanager/integrations/jira/{integration_id}/projects"),
        ("GET", "/api/alertmanager/integrations/jira/{integration_id}/projects/{project_key}/issue-types"),
        ("GET", "/api/alertmanager/integrations/jira"),
        ("POST", "/api/alertmanager/integrations/jira"),
        ("PUT", "/api/alertmanager/integrations/jira/{integration_id}"),
        ("DELETE", "/api/alertmanager/integrations/jira/{integration_id}"),
        ("POST", "/api/alertmanager/integrations/jira/{integration_id}/hide"),
        ("POST", "/api/alertmanager/incidents/{incident_id}/jira"),
        ("POST", "/api/alertmanager/incidents/{incident_id}/jira/sync-notes"),
        ("GET", "/api/alertmanager/incidents/{incident_id}/jira/comments"),
    }
    actual = _collect_routes(alerts_router, webhook_router, incidents_router, jira_router)
    assert actual == expected
