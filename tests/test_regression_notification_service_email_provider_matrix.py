"""
Regression tests for email provider selection and SMTP auth behavior.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from services import notification_service as notification_mod
from services.notification_service import NotificationService
from tests._regression_helpers import notification_channel, sample_alert


@pytest.mark.asyncio
async def test_send_email_uses_sendgrid_with_sanitized_recipients(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="email-sendgrid",
        channel_type="email",
        config={
            "to": "ops@example.com;platform@example.com",
            "email_provider": "sendgrid",
            "sendgrid_api_key": "sg-key",
            "from": "alerts@example.com",
        },
    )
    captured = {}

    async def _send_sendgrid(_client, api_key, *delivery_args, **_kwargs):
        payload = delivery_args[0] if delivery_args else None
        recipients = getattr(payload, "recipients", None)
        from_addr = getattr(payload, "smtp_from", None)
        if recipients is None and len(delivery_args) >= 5:
            recipients = delivery_args[3]
            from_addr = delivery_args[4]
        captured["api_key"] = api_key
        captured["recipients"] = recipients
        captured["from_addr"] = from_addr
        return True

    monkeypatch.setattr(notification_mod.notification_email, "send_via_sendgrid", _send_sendgrid)

    result = await svc._send_email(channel, sample_alert(), "firing")

    assert result is True
    assert captured["api_key"] == "sg-key"
    assert captured["recipients"] == ["ops@example.com", "platform@example.com"]
    assert captured["from_addr"] == "alerts@example.com"


@pytest.mark.asyncio
async def test_send_email_sendgrid_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="email-sendgrid-missing-key",
        channel_type="email",
        config={"to": "ops@example.com", "email_provider": "sendgrid"},
    )

    called = {"sendgrid": 0}

    async def _send_sendgrid(*_args, **_kwargs):
        called["sendgrid"] += 1
        return True

    monkeypatch.setattr(notification_mod.notification_email, "send_via_sendgrid", _send_sendgrid)

    result = await svc._send_email(channel, sample_alert(), "firing")

    assert result is False
    assert called["sendgrid"] == 0


@pytest.mark.asyncio
async def test_send_email_uses_resend_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="email-resend",
        channel_type="email",
        config={
            "to": "ops@example.com",
            "email_provider": "resend",
            "resend_api_key": "re-key",
            "from": "alerts@example.com",
        },
    )
    captured = {}

    async def _send_resend(_client, api_key, *delivery_args, **_kwargs):
        payload = delivery_args[0] if delivery_args else None
        recipients = getattr(payload, "recipients", None)
        from_addr = getattr(payload, "smtp_from", None)
        if recipients is None and len(delivery_args) >= 5:
            recipients = delivery_args[3]
            from_addr = delivery_args[4]
        captured["api_key"] = api_key
        captured["recipients"] = recipients
        captured["from_addr"] = from_addr
        return True

    monkeypatch.setattr(notification_mod.notification_email, "send_via_resend", _send_resend)

    result = await svc._send_email(channel, sample_alert(), "resolved")

    assert result is True
    assert captured["api_key"] == "re-key"
    assert captured["recipients"] == ["ops@example.com"]


@pytest.mark.asyncio
async def test_send_email_smtp_api_key_mode_sets_default_username(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="email-smtp-api-key",
        channel_type="email",
        config={
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_port": 2525,
            "smtp_auth_type": "api_key",
            "smtp_api_key": "smtp-api-key",
            "from": "alerts@example.com",
        },
    )
    captured = {}

    def _build_message(_subject, _body, _from_addr, _recipients, _html_body):
        msg = EmailMessage()
        msg["Subject"] = "subject"
        return msg

    async def _send_smtp(_msg, host, port, username, password, start_tls, use_tls):
        captured["host"] = host
        captured["port"] = port
        captured["username"] = username
        captured["password"] = password
        captured["start_tls"] = start_tls
        captured["use_tls"] = use_tls
        return True

    monkeypatch.setattr(notification_mod.notification_email, "build_smtp_message", _build_message)
    monkeypatch.setattr(notification_mod.notification_email, "send_via_smtp", _send_smtp)

    result = await svc._send_email(channel, sample_alert(), "firing")

    assert result is True
    assert captured["host"] == "smtp.example.com"
    assert captured["port"] == 2525
    assert captured["username"] == "apikey"
    assert captured["password"] == "smtp-api-key"


@pytest.mark.asyncio
async def test_send_email_smtp_none_auth_clears_credentials_and_uses_default_port(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = NotificationService()
    channel = notification_channel(
        name="email-smtp-no-auth",
        channel_type="email",
        config={
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "none",
            "smtp_starttls": False,
            "smtp_use_ssl": False,
            "smtp_username": "ignored-user",
            "smtp_password": "ignored-pass",
        },
    )
    captured = {}

    def _build_message(_subject, _body, _from_addr, _recipients, _html_body):
        return EmailMessage()

    async def _send_smtp(_msg, _host, port, username, password, _start_tls, _use_tls):
        captured["port"] = port
        captured["username"] = username
        captured["password"] = password
        return True

    monkeypatch.setattr(notification_mod.notification_email, "build_smtp_message", _build_message)
    monkeypatch.setattr(notification_mod.notification_email, "send_via_smtp", _send_smtp)

    result = await svc._send_email(channel, sample_alert(), "firing")

    assert result is True
    assert captured["port"] == 25
    assert captured["username"] is None
    assert captured["password"] is None
