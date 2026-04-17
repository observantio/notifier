"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.channels import ChannelType, NotificationChannel
from routers.observability.alerts import channels as channels_router
from tests._regression_helpers import run_in_threadpool_inline, token_data


def _channel(*, channel_type: ChannelType, enabled: bool = True, config: dict[str, object] | None = None):
    return NotificationChannel(name=f"{channel_type.value}-channel", type=channel_type, enabled=enabled, config=config or {})


@pytest.mark.asyncio
async def test_test_channel_requires_owner_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    monkeypatch.setattr(channels_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _user: ("tenant", "user", []))
    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: False)

    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("channel-1", current_user=user)

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_test_channel_rejects_disabled_channels(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    monkeypatch.setattr(channels_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _user: ("tenant", "user", []))
    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel(channel_type=ChannelType.SLACK, enabled=False, config={"webhook_url": "https://hooks.slack.com/services/a/b/c"}),
    )

    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("channel-2", current_user=user)

    assert exc.value.status_code == 400
    assert "disabled" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_test_channel_surfaces_configuration_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    monkeypatch.setattr(channels_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _user: ("tenant", "user", []))
    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel(channel_type=ChannelType.EMAIL, config={"to": "ops@example.com"}),
    )
    monkeypatch.setattr(
        channels_router.notification_service,
        "validate_channel_config",
        lambda *_args: ["missing smtp_host", "missing smtp_password"],
    )

    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("channel-3", current_user=user)

    assert exc.value.status_code == 400
    assert "missing smtp_host; missing smtp_password" == exc.value.detail


@pytest.mark.asyncio
async def test_test_channel_webhook_failure_returns_specialized_error(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    monkeypatch.setattr(channels_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _user: ("tenant", "user", []))
    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel(channel_type=ChannelType.WEBHOOK, config={"url": "https://receiver.example/path"}),
    )
    monkeypatch.setattr(channels_router.notification_service, "validate_channel_config", lambda *_args: [])

    async def _send_notification(*_args, **_kwargs):
        return False

    monkeypatch.setattr(channels_router.notification_service, "send_notification", _send_notification)

    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("channel-4", current_user=user)

    assert exc.value.status_code == 400
    assert "Webhook test failed" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_test_channel_success_returns_channel_specific_message(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    monkeypatch.setattr(channels_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _user: ("tenant", "user", []))
    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel(channel_type=ChannelType.PAGERDUTY, config={"routing_key": "pd-key"}),
    )
    monkeypatch.setattr(channels_router.notification_service, "validate_channel_config", lambda *_args: [])

    async def _send_notification(*_args, **_kwargs):
        return True

    monkeypatch.setattr(channels_router.notification_service, "send_notification", _send_notification)

    result = await channels_router.test_channel("channel-5", current_user=user)

    assert result["status"] == "success"
    assert "pagerduty-channel" in result["message"]


@pytest.mark.asyncio
async def test_test_channel_non_webhook_failure_uses_generic_error(monkeypatch: pytest.MonkeyPatch) -> None:
    user = token_data()
    monkeypatch.setattr(channels_router, "run_in_threadpool", run_in_threadpool_inline)
    monkeypatch.setattr(channels_router.alertmanager_service, "user_scope", lambda _user: ("tenant", "user", []))
    monkeypatch.setattr(channels_router.storage_service, "is_notification_channel_owner", lambda *_args: True)
    monkeypatch.setattr(
        channels_router.storage_service,
        "get_notification_channel",
        lambda *_args: _channel(channel_type=ChannelType.SLACK, config={"webhook_url": "https://hooks.slack.com/services/a/b/c"}),
    )
    monkeypatch.setattr(channels_router.notification_service, "validate_channel_config", lambda *_args: [])

    async def _send_notification(*_args, **_kwargs):
        return False

    monkeypatch.setattr(channels_router.notification_service, "send_notification", _send_notification)

    with pytest.raises(HTTPException) as exc:
        await channels_router.test_channel("channel-6", current_user=user)

    assert exc.value.status_code == 400
    assert "Failed to send test notification" in str(exc.value.detail)
