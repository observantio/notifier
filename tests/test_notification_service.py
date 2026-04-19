"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env
ensure_test_env()

import asyncio

from config import config
from models.alerting.alerts import Alert, AlertStatus
from models.alerting.channels import ChannelType, NotificationChannel
from services.notification import email_providers as notification_email
from services.notification import payloads as notification_payloads
from services.notification import senders as notification_senders
from services.notification_service import NotificationService


def _make_alert():
    return Alert(
        labels={"alertname": "A", "severity": "critical"},
        annotations={},
        startsAt="2023-01-01T00:00:00Z",
        status=AlertStatus(state="active"),
        fingerprint="fp",
    )


def test_send_slack_delegates_to_senders(monkeypatch):
    called = {}

    async def fake_send_slack(client, channel_config, alert, action):
        called["slack"] = (client, channel_config, alert, action)
        return True

    monkeypatch.setattr(notification_senders, "send_slack", fake_send_slack)

    svc = NotificationService()
    ch = NotificationChannel(name="c", type=ChannelType.SLACK, config={"webhook_url": "https://example.com/h"})
    res = asyncio.run(svc.send_notification(ch, _make_alert(), "firing"))
    assert res is True
    assert "slack" in called


def test_send_email_delegates_to_email_providers(monkeypatch):
    called = {}

    async def fake_send_via_sendgrid(*args, **kwargs):
        api_key = kwargs.get("api_key")
        recipients = kwargs.get("recipients")
        if api_key is None and len(args) > 1:
            api_key = args[1]
        if recipients is None and len(args) > 4:
            recipients = args[4]
        called["sg"] = (api_key, recipients)
        return True

    async def fake_send_via_resend(*args, **kwargs):
        api_key = kwargs.get("api_key")
        recipients = kwargs.get("recipients")
        if api_key is None and len(args) > 1:
            api_key = args[1]
        if recipients is None and len(args) > 4:
            recipients = args[4]
        called["rs"] = (api_key, recipients)
        return True

    async def fake_send_via_smtp(message, smtp=None, **_kwargs):
        called["smtp"] = (smtp.hostname, smtp.port)
        return True

    monkeypatch.setattr(notification_email, "send_via_sendgrid", fake_send_via_sendgrid)
    monkeypatch.setattr(notification_email, "send_via_resend", fake_send_via_resend)
    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_via_smtp)

    # ensure a default from address exists so service logic doesn't blow up
    config.default_admin_email = "admin@example.com"

    svc = NotificationService()
    ch1 = NotificationChannel(
        name="e1",
        type=ChannelType.EMAIL,
        config={"to": "a@b.com", "email_provider": "sendgrid", "sendgrid_api_key": "k"},
    )
    assert asyncio.run(svc.send_notification(ch1, _make_alert(), "firing")) is True
    assert called["sg"][0] == "k"

    ch2 = NotificationChannel(
        name="e2", type=ChannelType.EMAIL, config={"to": "a@b.com", "email_provider": "resend", "resend_api_key": "rk"}
    )
    assert asyncio.run(svc.send_notification(ch2, _make_alert(), "firing")) is True
    assert called["rs"][0] == "rk"

    ch3 = NotificationChannel(
        name="e3", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25}
    )
    assert asyncio.run(svc.send_notification(ch3, _make_alert(), "firing")) is True
    assert called["smtp"][0] == "h"


def test_format_helpers_delegate_to_payloads(monkeypatch):
    # ensure the formatting helper is actually invoked during notification
    called = {}

    def fake_format(alert, action):
        called["format"] = (alert, action)
        return "FORMATTED"

    monkeypatch.setattr(notification_payloads, "format_alert_body", fake_format)

    # avoid real email transport so test stays fast
    async def fake_send_smtp(message, smtp=None, **_kwargs):
        return True

    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_smtp)

    # provide a default from address for the service
    config.default_admin_email = "admin@example.com"

    svc = NotificationService()
    ch = NotificationChannel(
        name="e", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25}
    )
    asyncio.run(svc.send_notification(ch, _make_alert(), "firing"))
    assert "format" in called


def test_send_email_uses_build_smtp_message(monkeypatch):
    captured = {}

    def fake_build(payload):
        captured["built"] = (payload.subject, payload.body, payload.smtp_from, payload.recipients, payload.html_body)
        from email.message import EmailMessage

        m = EmailMessage()
        m["Subject"] = payload.subject
        return m

    async def fake_send_smtp(message, smtp=None, **_kwargs):
        captured["sent"] = (smtp.hostname, smtp.port)
        return True

    monkeypatch.setattr(notification_email, "build_smtp_message", fake_build)
    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_smtp)

    # ensure default from address available
    config.default_admin_email = "admin@example.com"

    svc = NotificationService()
    ch = NotificationChannel(
        name="e", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25}
    )
    assert asyncio.run(svc.send_notification(ch, _make_alert(), "firing")) is True
    assert captured["built"][0].startswith("[FIRING]")
    assert captured["sent"][0] == "h"
