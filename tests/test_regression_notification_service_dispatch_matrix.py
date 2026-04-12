"""
Regression tests for notification dispatch routing across channel types.
"""

from __future__ import annotations

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.channels import ChannelType
from services.notification_service import NotificationService
from tests._regression_helpers import notification_channel, sample_alert


@pytest.mark.asyncio
async def test_send_notification_skips_disabled_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="disabled-email",
        channel_type=ChannelType.EMAIL,
        config={"to": "ops@example.com", "smtp_host": "smtp.example.com"},
        enabled=False,
    )
    called = {"email": 0}

    async def _send_email(*_args, **_kwargs):
        called["email"] += 1
        return True

    monkeypatch.setattr(svc, "_send_email", _send_email)

    result = await svc.send_notification(channel, sample_alert(), "firing")

    assert result is False
    assert called["email"] == 0


@pytest.mark.asyncio
async def test_send_notification_dispatches_slack_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="slack-main",
        channel_type=ChannelType.SLACK,
        config={"webhook_url": "https://hooks.slack.com/services/a/b/c"},
    )
    called = {"slack": 0}

    async def _send_slack(_channel, _alert, action):
        called["slack"] += 1
        return action == "firing"

    monkeypatch.setattr(svc, "_send_slack", _send_slack)

    result = await svc.send_notification(channel, sample_alert(), "firing")

    assert result is True
    assert called["slack"] == 1


@pytest.mark.asyncio
async def test_send_notification_dispatches_teams_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="teams-main",
        channel_type=ChannelType.TEAMS,
        config={"webhook_url": "https://tenant.webhook.office.com/hook"},
    )
    called = {"teams": 0}

    async def _send_teams(_channel, _alert, action):
        called["teams"] += 1
        return action == "resolved"

    monkeypatch.setattr(svc, "_send_teams", _send_teams)

    result = await svc.send_notification(channel, sample_alert(), "resolved")

    assert result is True
    assert called["teams"] == 1


@pytest.mark.asyncio
async def test_send_notification_dispatches_webhook_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="webhook-main",
        channel_type=ChannelType.WEBHOOK,
        config={"url": "https://receiver.example/path"},
    )
    called = {"webhook": 0}

    async def _send_webhook(_channel, _alert, action):
        called["webhook"] += 1
        return action == "test"

    monkeypatch.setattr(svc, "_send_webhook", _send_webhook)

    result = await svc.send_notification(channel, sample_alert(), "test")

    assert result is True
    assert called["webhook"] == 1


@pytest.mark.asyncio
async def test_send_notification_dispatches_pagerduty_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="pagerduty-main",
        channel_type=ChannelType.PAGERDUTY,
        config={"routing_key": "pd-routing-key"},
    )
    called = {"pagerduty": 0}

    async def _send_pagerduty(_channel, _alert, action):
        called["pagerduty"] += 1
        return action == "firing"

    monkeypatch.setattr(svc, "_send_pagerduty", _send_pagerduty)

    result = await svc.send_notification(channel, sample_alert(), "firing")

    assert result is True
    assert called["pagerduty"] == 1
