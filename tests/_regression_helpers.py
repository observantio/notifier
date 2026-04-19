"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.alerts import Alert
from models.alerting.channels import ChannelType, NotificationChannel
from models.alerting.incidents import AlertIncident, IncidentStatus


async def run_in_threadpool_inline(func, *args, **kwargs):
    """Execute sync/async callables inline while preserving awaitable behavior."""
    result = func(*args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


def token_data(
    *,
    user_id: str = "user-1",
    username: str = "alice",
    email: str | None = "alice@example.com",
    tenant_id: str = "tenant-1",
    org_id: str = "org-1",
    role: Role = Role.USER,
    permissions: list[str] | None = None,
    group_ids: list[str] | None = None,
) -> TokenData:
    return TokenData(
        user_id=user_id,
        username=username,
        email=email,
        tenant_id=tenant_id,
        org_id=org_id,
        role=role,
        permissions=list(permissions or []),
        group_ids=list(group_ids or []),
        is_superuser=False,
        is_mfa_setup=False,
    )


def alert_incident(
    *,
    incident_id: str = "inc-1",
    status: IncidentStatus = IncidentStatus.OPEN,
    assignee: str | None = None,
    alert_name: str = "HighCpuUsage",
    severity: str = "critical",
    labels: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
    fingerprint: str = "fp-1",
) -> AlertIncident:
    now = datetime.now(UTC)
    return AlertIncident(
        id=incident_id,
        fingerprint=fingerprint,
        alertName=alert_name,
        severity=severity,
        status=status,
        assignee=assignee,
        notes=[],
        labels=labels or {"alertname": alert_name},
        annotations=annotations or {},
        visibility="public",
        sharedGroupIds=[],
        jiraTicketKey=None,
        jiraTicketUrl=None,
        jiraIntegrationId=None,
        startsAt=now,
        lastSeenAt=now,
        resolvedAt=None,
        createdAt=now,
        updatedAt=now,
        userManaged=False,
        hideWhenResolved=False,
    )


def notification_channel(
    *,
    name: str,
    channel_type: ChannelType,
    config: dict[str, object],
    enabled: bool = True,
) -> NotificationChannel:
    return NotificationChannel(name=name, type=channel_type, config=config, enabled=enabled)


def sample_alert(
    *,
    alertname: str = "HighCpuUsage",
    severity: str = "critical",
    state: str = "active",
    fingerprint: str = "alert-fp-1",
    silenced_by: list[str] | None = None,
    inhibited_by: list[str] | None = None,
) -> Alert:
    return Alert.model_validate(
        {
            "labels": {"alertname": alertname, "severity": severity},
            "annotations": {"summary": "CPU too high", "description": "Pod CPU crossed threshold"},
            "startsAt": datetime.now(UTC).isoformat(),
            "endsAt": None,
            "generatorURL": "https://grafana.example/alert/1",
            "status": {
                "state": state,
                "silencedBy": list(silenced_by or []),
                "inhibitedBy": list(inhibited_by or []),
            },
            "fingerprint": fingerprint,
        }
    )

