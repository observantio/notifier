"""
Email provider utilities for sending notifications via different email services, including SendGrid, Resend, and SMTP.
This module provides functions to build email messages, validate recipient email addresses, and send emails using the
respective APIs or protocols while handling errors and implementing retry logic for transient failures. The utilities
ensure that email sending operations are performed securely and efficiently, with proper logging and error handling to
facilitate troubleshooting and monitoring of email delivery performance.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import parseaddr

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
    payload: EmailDeliveryPayload,
) -> EmailDeliveryPayload:
    return payload


def _coerce_smtp_delivery_config(
    smtp: transport.SmtpDeliveryConfig,
) -> transport.SmtpDeliveryConfig:
    return smtp


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
    payload: EmailDeliveryPayload,
) -> bool:
    email = _coerce_email_delivery_payload(payload)
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
    payload: EmailDeliveryPayload,
) -> bool:
    email = _coerce_email_delivery_payload(payload)
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
    smtp: transport.SmtpDeliveryConfig,
) -> bool:
    smtp_config = _coerce_smtp_delivery_config(smtp)

    if (smtp_config.username or smtp_config.password) and not (smtp_config.start_tls or smtp_config.use_tls):
        raise ValueError("SMTP authentication without TLS is insecure")

    try:
        await transport.send_smtp_with_retry(
            message=message,
            smtp=smtp_config,
        )
        return True
    except (aiosmtplib.errors.SMTPException, OSError, TimeoutError, ValueError) as exc:
        logger.error("SMTP delivery failed: %s", exc)
        return False
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("SMTP unexpected failure: %s", exc)
        return False
