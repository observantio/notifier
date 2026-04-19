"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.channels import ChannelType
from services.alerting import channels_ops
from tests._regression_helpers import notification_channel


class _StorageStub:
    def __init__(self, channels, matched_rule):
        self._channels = channels
        self._matched_rule = matched_rule
        self.channel_calls: list[tuple[str, str | None]] = []
        self.rule_calls: list[tuple[str, str | None]] = []

    def get_notification_channels_for_rule_name(self, tenant_id: str, alertname: str, org_id: str | None = None):
        self.channel_calls.append((alertname, org_id))
        return list(self._channels)

    def get_alert_rule_by_name_for_delivery(self, tenant_id: str, alertname: str, org_id: str | None = None):
        self.rule_calls.append((alertname, org_id))
        return self._matched_rule


class _NotificationStub:
    def __init__(self):
        self.calls: list[tuple[str, object, str]] = []

    async def send_notification(self, channel, alert, action: str):
        self.calls.append((channel.name, alert, action))
        return True


def _context(storage: _StorageStub, notifier: _NotificationStub) -> channels_ops.NotificationDispatchContext:
    return channels_ops.NotificationDispatchContext(
        service=object(),
        tenant_id="tenant-a",
        storage_service=storage,
        notification_service=notifier,
    )


@pytest.mark.asyncio
async def test_notify_for_alerts_skips_entries_without_alertname() -> None:
    storage = _StorageStub(
        channels=[notification_channel(name="email", channel_type=ChannelType.EMAIL, config={"to": "ops@example.com"})],
        matched_rule=None,
    )
    notifier = _NotificationStub()

    await channels_ops.notify_for_alerts(_context(storage, notifier), [{"labels": {"severity": "critical"}}])

    assert storage.channel_calls == []
    assert notifier.calls == []


@pytest.mark.asyncio
async def test_notify_for_alerts_skips_when_no_channels_are_configured() -> None:
    storage = _StorageStub(channels=[], matched_rule=None)
    notifier = _NotificationStub()

    await channels_ops.notify_for_alerts(
        _context(storage, notifier),
        [{"labels": {"alertname": "DiskFull"}, "status": {"state": "active"}}],
    )

    assert storage.channel_calls == [("DiskFull", None)]
    assert notifier.calls == []


@pytest.mark.asyncio
async def test_notify_for_alerts_skips_suppressed_status() -> None:
    storage = _StorageStub(
        channels=[notification_channel(name="slack", channel_type=ChannelType.SLACK, config={"webhook_url": "https://hooks.slack.com/services/a/b/c"})],
        matched_rule=None,
    )
    notifier = _NotificationStub()

    await channels_ops.notify_for_alerts(
        _context(storage, notifier),
        [
            {
                "labels": {"alertname": "DiskFull"},
                "status": {"state": "suppressed", "silencedBy": ["s-1"], "inhibitedBy": []},
            }
        ],
    )

    assert notifier.calls == []


@pytest.mark.asyncio
async def test_notify_for_alerts_sends_active_alert_to_all_channels() -> None:
    channels = [
        notification_channel(name="email", channel_type=ChannelType.EMAIL, config={"to": "ops@example.com"}),
        notification_channel(name="pagerduty", channel_type=ChannelType.PAGERDUTY, config={"routing_key": "rk"}),
    ]
    storage = _StorageStub(channels=channels, matched_rule=None)
    notifier = _NotificationStub()

    await channels_ops.notify_for_alerts(
        _context(storage, notifier),
        [
            {
                "labels": {"alertname": "HighCpuUsage", "severity": "critical"},
                "annotations": {"summary": "cpu"},
                "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
            }
        ],
    )

    assert len(notifier.calls) == 2
    assert all(call[2] == "firing" for call in notifier.calls)


@pytest.mark.asyncio
async def test_notify_for_alerts_enriches_rule_annotations_before_delivery() -> None:
    channels = [notification_channel(name="webhook", channel_type=ChannelType.WEBHOOK, config={"url": "https://receiver.example"})]
    matched_rule = SimpleNamespace(
        id="rule-1",
        name="LatencyHigh",
        group="corr-1",
        created_by="creator-id",
        annotations={"createdByUsername": "creator-name", "productName": "billing"},
    )
    storage = _StorageStub(channels=channels, matched_rule=matched_rule)
    notifier = _NotificationStub()

    await channels_ops.notify_for_alerts(
        _context(storage, notifier),
        [
            {
                "labels": {"alertname": "LatencyHigh", "product": "platform"},
                "annotations": {"summary": "latency too high"},
                "status": {"state": "resolved", "silencedBy": [], "inhibitedBy": []},
            }
        ],
    )

    assert len(notifier.calls) == 1
    _, delivered_alert, action = notifier.calls[0]
    assert action == "resolved"
    assert delivered_alert.annotations["watchdogCorrelationId"] == "corr-1"
    assert delivered_alert.annotations["watchdogCreatedBy"] == "creator-id"
    assert delivered_alert.annotations["watchdogCreatedByUsername"] == "creator-name"
    assert delivered_alert.annotations["watchdogProductName"] == "billing"
    assert delivered_alert.annotations["watchdogRuleName"] == "LatencyHigh"
