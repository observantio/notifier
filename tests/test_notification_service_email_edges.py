"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from config import config
from services import notification_service as notification_mod
from services.notification import transport
from services.notification_service import IncidentAssignmentEmail
from services.notification_service import NotificationService


@pytest.mark.asyncio
async def test_notification_service_support_helpers(monkeypatch):
    svc = NotificationService()
    monkeypatch.setattr(notification_mod.notification_validators, "coerce_bool", lambda value: str(value) == "ok")
    monkeypatch.setattr(notification_mod.notification_validators, "validate_channel_config", lambda *_args: ["err"])

    async def fake_send_smtp_with_retry(*args, **kwargs):
        return {"args": args, "kwargs": kwargs}

    monkeypatch.setattr(notification_mod.notification_transport, "send_smtp_with_retry", fake_send_smtp_with_retry)

    assert svc._as_bool("ok") is True
    assert svc._as_bool("other") is False
    assert svc.validate_channel_config("email", {}) == ["err"]

    msg = EmailMessage()
    smtp = transport.SmtpDeliveryConfig(
        hostname="smtp.example.com",
        port=25,
        username="user",
        password="pw",
        start_tls=True,
    )
    result = await svc._send_smtp_with_retry(msg, smtp=smtp)
    assert result["kwargs"]["smtp"].hostname == "smtp.example.com"


@pytest.mark.asyncio
async def test_incident_assignment_email_paths(monkeypatch):
    svc = NotificationService()
    monkeypatch.setattr(config, "default_admin_email", "admin@example.com")

    monkeypatch.setattr(notification_mod.config, "get_secret", lambda key: None)
    assert (
        await svc.send_incident_assignment_email(
            IncidentAssignmentEmail("u@example.com", "CPU", "open", "critical", "admin")
        )
        is False
    )

    monkeypatch.setattr(
        notification_mod.config,
        "get_secret",
        lambda key: {
            "INCIDENT_ASSIGNMENT_EMAIL_ENABLED": "true",
            "INCIDENT_ASSIGNMENT_SMTP_PORT": "bad-port",
        }.get(key),
    )
    assert (
        await svc.send_incident_assignment_email(
            IncidentAssignmentEmail("u@example.com", "CPU", "open", "critical", "admin")
        )
        is False
    )

    async def fake_send(*, message, smtp, **_kwargs):
        assert smtp.hostname == "smtp.example.com"
        assert smtp.port == 587
        assert message["To"] == "u@example.com"

    monkeypatch.setattr(
        notification_mod.config,
        "get_secret",
        lambda key: {
            "INCIDENT_ASSIGNMENT_EMAIL_ENABLED": "true",
            "INCIDENT_ASSIGNMENT_SMTP_HOST": "smtp.example.com",
            "INCIDENT_ASSIGNMENT_SMTP_PORT": "bad-port",
            "INCIDENT_ASSIGNMENT_FROM": "alerts@example.com",
        }.get(key),
    )
    monkeypatch.setattr(svc, "_send_smtp_with_retry", fake_send)
    assert (
        await svc.send_incident_assignment_email(
            IncidentAssignmentEmail("u@example.com", "CPU", "open", "critical", "admin")
        )
        is True
    )

    async def fail_send(**_kwargs):
        raise OSError("smtp down")

    monkeypatch.setattr(svc, "_send_smtp_with_retry", fail_send)
    assert (
        await svc.send_incident_assignment_email(
            IncidentAssignmentEmail("u@example.com", "CPU", "open", "critical", "admin")
        )
        is False
    )


def test_notification_service_html_template_and_theme_paths(monkeypatch):
    monkeypatch.setattr(
        notification_mod.Path,
        "read_text",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("missing")),
    )
    assert notification_mod._render_html_template("missing.html", {"x": "y"}) is None

    warning_theme = notification_mod._incident_severity_theme("warning")
    info_theme = notification_mod._incident_severity_theme("info")
    assert warning_theme["header_bg"] == "#f59e0b"
    assert info_theme["header_bg"] == "#2563eb"


@pytest.mark.asyncio
async def test_incident_assignment_email_skips_html_alternative_when_template_missing(monkeypatch):
    svc = NotificationService()
    monkeypatch.setattr(config, "default_admin_email", "admin@example.com")
    monkeypatch.setattr(
        notification_mod.config,
        "get_secret",
        lambda key: {
            "INCIDENT_ASSIGNMENT_EMAIL_ENABLED": "true",
            "INCIDENT_ASSIGNMENT_SMTP_HOST": "smtp.example.com",
            "INCIDENT_ASSIGNMENT_SMTP_PORT": "587",
            "INCIDENT_ASSIGNMENT_FROM": "alerts@example.com",
        }.get(key),
    )
    monkeypatch.setattr(notification_mod, "_render_html_template", lambda *_args, **_kwargs: None)

    captured = {}

    async def fake_send(*, message, smtp, **_kwargs):
        captured["hostname"] = smtp.hostname
        captured["port"] = smtp.port
        captured["is_multipart"] = message.is_multipart()

    monkeypatch.setattr(svc, "_send_smtp_with_retry", fake_send)

    result = await svc.send_incident_assignment_email(
        IncidentAssignmentEmail(
            "u@example.com",
            "CPU",
            "open",
            "warning",
            "admin",
        )
    )

    assert result is True
    assert captured["hostname"] == "smtp.example.com"
    assert captured["port"] == 587
    assert captured["is_multipart"] is False
