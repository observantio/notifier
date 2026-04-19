"""
Email provider utilities for sending notifications via different email services, including SendGrid, Resend, and SMTP.
This module provides functions to build email messages, validate recipient email addresses, and send emails using the
respective APIs or protocols while handling errors and implementing retry logic for transient failures. The utilities
ensure that email sending operations are performed securely and efficiently, with proper logging and error handling to
facilitate troubleshooting and monitoring of email delivery performance.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import parseaddr
from typing import cast

import aiosmtplib
import httpx

from custom_types.json import JSONDict

from . import transport

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailDeliveryPayload:
    subject: str
    body: str
    recipients: list[str]
    smtp_from: str
    html_body: str | None = None


def _coerce_email_delivery_payload(
    payload: EmailDeliveryPayload | None,
    legacy_args: tuple[object, ...],
) -> EmailDeliveryPayload:
    if payload is not None:
        return payload
    if len(legacy_args) < 4:
        raise ValueError("subject, body, recipients, and smtp_from are required")
    subject = str(legacy_args[0])
    body = str(legacy_args[1])
    recipients = cast(list[str], legacy_args[2])
    smtp_from = str(legacy_args[3])
    html_body = str(legacy_args[4]) if len(legacy_args) > 4 and legacy_args[4] is not None else None
    return EmailDeliveryPayload(
        subject=subject,
        body=body,
        recipients=recipients,
        smtp_from=smtp_from,
        html_body=html_body,
    )


def _coerce_smtp_delivery_config(
    smtp: transport.SmtpDeliveryConfig | object | None,
    legacy_args: tuple[object, ...],
    legacy_kwargs: dict[str, object],
) -> transport.SmtpDeliveryConfig:
    if isinstance(smtp, transport.SmtpDeliveryConfig):
        return smtp

    values: list[object] = []
    if smtp is not None:
        values.append(smtp)
    values.extend(legacy_args)

    hostname_value = values[0] if values else legacy_kwargs.pop("hostname", "")
    port_value = values[1] if len(values) > 1 else legacy_kwargs.pop("port", 0)
    username_value = values[2] if len(values) > 2 else legacy_kwargs.pop("username", None)
    password_value = values[3] if len(values) > 3 else legacy_kwargs.pop("password", None)
    start_tls_value = values[4] if len(values) > 4 else legacy_kwargs.pop("start_tls", False)
    use_tls_value = values[5] if len(values) > 5 else legacy_kwargs.pop("use_tls", False)

    hostname = str(hostname_value or "").strip()
    if not hostname:
        raise ValueError("SMTP hostname is required")
    try:
        port = int(cast(int | str | bytes | bytearray, port_value))
    except (TypeError, ValueError) as exc:
        raise ValueError("SMTP port must be an integer") from exc

    username = str(username_value).strip() if username_value is not None else ""

    return transport.SmtpDeliveryConfig(
        hostname=hostname,
        port=port,
        username=username or None,
        password=str(password_value) if password_value is not None else None,
        start_tls=bool(start_tls_value),
        use_tls=bool(use_tls_value),
    )


def _is_valid_email(addr: str) -> bool:
    return "@" in parseaddr(addr)[1]


def _sanitize_recipients(recipients: list[str]) -> list[str]:
    valid = [r.strip() for r in recipients if _is_valid_email(r)]
    if not valid:
        raise ValueError("No valid recipient email addresses provided")
    return valid


def build_smtp_message(payload: EmailDeliveryPayload) -> EmailMessage:
    recipients = _sanitize_recipients(payload.recipients)
    msg = EmailMessage()
    msg["Subject"] = payload.subject
    msg["From"] = payload.smtp_from
    msg["To"] = ", ".join(recipients)
    msg.set_content(payload.body)
    if payload.html_body:
        msg.add_alternative(payload.html_body, subtype="html")
    return msg


async def send_via_sendgrid(
    client: httpx.AsyncClient,
    api_key: str,
    *delivery_args: object,
) -> bool:
    payload = delivery_args[0] if delivery_args else None
    legacy_args = delivery_args[1:] if isinstance(payload, EmailDeliveryPayload) else delivery_args
    email = _coerce_email_delivery_payload(payload if isinstance(payload, EmailDeliveryPayload) else None, legacy_args)
    recipients = _sanitize_recipients(email.recipients)

    content_items: list[JSONDict] = [{"type": "text/plain", "value": email.body}]
    if email.html_body:
        content_items.append({"type": "text/html", "value": email.html_body})

    request_payload: JSONDict = {
        "personalizations": [{"to": [{"email": r} for r in recipients]}],
        "from": {"email": email.smtp_from},
        "subject": email.subject,
        "content": content_items,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        await transport.post_with_retry(
            transport.HttpPostRequest(
                client=client,
                url="https://api.sendgrid.com/v3/mail/send",
                json=request_payload,
                headers=headers,
                retry_on_status={429, 500, 502, 503, 504},
            )
        )
        return True
    except httpx.HTTPStatusError as e:
        logger.error("SendGrid rejected request", extra={"status": e.response.status_code})
    except httpx.HTTPError as exc:
        logger.error("SendGrid transport failure: %s", exc)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("SendGrid unexpected failure: %s", exc)

    return False


async def send_via_resend(
    client: httpx.AsyncClient,
    api_key: str,
    *delivery_args: object,
) -> bool:
    payload = delivery_args[0] if delivery_args else None
    legacy_args = delivery_args[1:] if isinstance(payload, EmailDeliveryPayload) else delivery_args
    email = _coerce_email_delivery_payload(payload if isinstance(payload, EmailDeliveryPayload) else None, legacy_args)
    recipients = _sanitize_recipients(email.recipients)

    request_payload: JSONDict = {
        "from": email.smtp_from,
        "to": recipients,
        "subject": email.subject,
        "text": email.body,
    }
    if email.html_body:
        request_payload["html"] = email.html_body

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        await transport.post_with_retry(
            transport.HttpPostRequest(
                client=client,
                url="https://api.resend.com/emails",
                json=request_payload,
                headers=headers,
                retry_on_status={429, 500, 502, 503, 504},
            )
        )
        return True
    except httpx.HTTPStatusError as e:
        logger.error("Resend rejected request", extra={"status": e.response.status_code})
    except httpx.HTTPError as exc:
        logger.error("Resend transport failure: %s", exc)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Resend unexpected failure: %s", exc)

    return False


async def send_via_smtp(
    message: EmailMessage,
    *legacy_args: object,
    smtp: transport.SmtpDeliveryConfig | object | None = None,
    **legacy_kwargs: object,
) -> bool:
    smtp_config = _coerce_smtp_delivery_config(smtp, legacy_args, dict(legacy_kwargs))

    if (smtp_config.username or smtp_config.password) and not (smtp_config.start_tls or smtp_config.use_tls):
        raise ValueError("SMTP authentication without TLS is insecure")

    try:
        await transport.send_smtp_with_retry(
            message,
            smtp_config.hostname,
            smtp_config.port,
            smtp_config.username,
            smtp_config.password,
            smtp_config.start_tls,
            smtp_config.use_tls,
        )
        return True
    except (aiosmtplib.errors.SMTPException, OSError, TimeoutError, ValueError) as exc:
        logger.error("SMTP delivery failed: %s", exc)
        return False
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("SMTP unexpected failure: %s", exc)
        return False
