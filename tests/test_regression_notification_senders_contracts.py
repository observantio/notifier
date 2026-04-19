"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from services.notification import senders
from tests._regression_helpers import sample_alert


@pytest.mark.asyncio
async def test_send_slack_rejects_non_slack_webhook_host() -> None:
    result = await senders.send_slack(
        client=None,  # type: ignore[arg-type]
        channel_config={"webhook_url": "https://example.com/not-slack"},
        alert=sample_alert(),
        action="firing",
    )

    assert result is False


@pytest.mark.asyncio
async def test_send_teams_rejects_non_teams_webhook_host() -> None:
    result = await senders.send_teams(
        client=None,  # type: ignore[arg-type]
        channel_config={"webhook_url": "https://hooks.slack.com/services/not-teams"},
        alert=sample_alert(),
        action="firing",
    )

    assert result is False


@pytest.mark.asyncio
async def test_send_webhook_forwards_only_allowed_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    async def _post_with_retry(request):
        captured["url"] = str(request.url)
        captured["json"] = request.json
        captured["headers"] = request.headers or {}
        return None

    monkeypatch.setattr(senders.transport, "post_with_retry", _post_with_retry)

    result = await senders.send_webhook(
        client=None,  # type: ignore[arg-type]
        channel_config={
            "url": "https://receiver.example/hook",
            "headers": {
                "Authorization": "Bearer token",
                "X-Custom-Header": "x-value",
                "X-Forbidden": "ignored",
            },
        },
        alert=sample_alert(),
        action="test",
    )

    assert result is True
    assert captured["url"] == "https://receiver.example/hook"
    assert captured["headers"] == {
        "Authorization": "Bearer token",
        "X-Custom-Header": "x-value",
    }
    assert captured["json"]["action"] == "test"


@pytest.mark.asyncio
async def test_send_pagerduty_requires_routing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"post": 0}

    async def _post_with_retry(*_args, **_kwargs):
        called["post"] += 1

    monkeypatch.setattr(senders.transport, "post_with_retry", _post_with_retry)

    result = await senders.send_pagerduty(
        client=None,  # type: ignore[arg-type]
        channel_config={},
        alert=sample_alert(),
        action="firing",
    )

    assert result is False
    assert called["post"] == 0


@pytest.mark.asyncio
async def test_send_pagerduty_posts_to_events_api_with_resolve_action(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    async def _post_with_retry(request):
        captured["url"] = str(request.url)
        captured["json"] = request.json
        captured["headers"] = request.headers
        return None

    monkeypatch.setattr(senders.transport, "post_with_retry", _post_with_retry)

    result = await senders.send_pagerduty(
        client=None,  # type: ignore[arg-type]
        channel_config={"routing_key": "pd-routing"},
        alert=sample_alert(severity="warning"),
        action="resolved",
    )

    assert result is True
    assert captured["url"] == senders.PAGERDUTY_EVENTS_URL
    assert captured["json"]["routing_key"] == "pd-routing"
    assert captured["json"]["event_action"] == "resolve"
