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
from email.message import EmailMessage

import httpx
import pytest

from services.notification import email_providers, transport


def test_build_smtp_message():
    msg = email_providers.build_smtp_message(
        email_providers.EmailDeliveryPayload("subj", "body", ["a@b.com", "c@d.com"], "from@example.com", "<b>body</b>")
    )
    assert isinstance(msg, EmailMessage)
    assert msg["Subject"] == "subj"
    assert "a@b.com" in msg["To"]
    assert msg.is_multipart()


def test_send_via_sendgrid_and_resend_success_and_failure(monkeypatch):
    async def ok_post(_request):
        return httpx.Response(202)

    async def fail_post(_request):
        raise Exception("boom")

    monkeypatch.setattr(transport, "post_with_retry", ok_post)
    client = httpx.AsyncClient()
    assert asyncio.run(email_providers.send_via_sendgrid(client, "key", "s", "b", ["x@x"], "from@f")) is True
    assert asyncio.run(email_providers.send_via_resend(client, "key", "s", "b", ["x@x"], "from@f")) is True

    monkeypatch.setattr(transport, "post_with_retry", fail_post)
    assert asyncio.run(email_providers.send_via_sendgrid(client, "key", "s", "b", ["x@x"], "from@f")) is False
    assert asyncio.run(email_providers.send_via_resend(client, "key", "s", "b", ["x@x"], "from@f")) is False


def test_send_via_smtp_calls_transport(monkeypatch):
    async def fake_send(message, hostname, port, username=None, password=None, start_tls=False, use_tls=False):
        return True

    monkeypatch.setattr(transport, "send_smtp_with_retry", fake_send)
    # updated helper no longer accepts a timeout parameter
    assert asyncio.run(email_providers.send_via_smtp("m", "h", 25, None, None, False, False)) is True

    async def fake_send_err(*args, **kwargs):
        raise Exception("fail")

    monkeypatch.setattr(transport, "send_smtp_with_retry", fake_send_err)
    assert asyncio.run(email_providers.send_via_smtp("m", "h", 25, None, None, False, False)) is False


def test_sendgrid_and_resend_include_html_payload_when_provided(monkeypatch):
    captured = {}

    async def capture_post(request):
        captured[str(request.url)] = request.json
        return httpx.Response(202)

    monkeypatch.setattr(transport, "post_with_retry", capture_post)
    client = httpx.AsyncClient()

    assert (
        asyncio.run(
            email_providers.send_via_sendgrid(
                client,
                "key",
                "subject",
                "body",
                ["x@x.com"],
                "from@example.com",
                "<b>html</b>",
            )
        )
        is True
    )
    assert captured["https://api.sendgrid.com/v3/mail/send"]["content"][1]["type"] == "text/html"

    assert (
        asyncio.run(
            email_providers.send_via_resend(
                client,
                "key",
                "subject",
                "body",
                ["x@x.com"],
                "from@example.com",
                "<b>html</b>",
            )
        )
        is True
    )
    assert captured["https://api.resend.com/emails"]["html"] == "<b>html</b>"


def test_coerce_email_delivery_payload_accepts_payload_object():
    payload = email_providers.EmailDeliveryPayload(
        subject="subj",
        body="body",
        recipients=["a@example.com"],
        smtp_from="from@example.com",
        html_body="<p>hello</p>",
    )
    result = email_providers._coerce_email_delivery_payload(payload, ())
    assert result is payload


def test_coerce_email_delivery_payload_requires_legacy_arguments():
    with pytest.raises(ValueError, match="subject, body, recipients, and smtp_from are required"):
        email_providers._coerce_email_delivery_payload(None, ("subj", "body", ["a@example.com"]))
