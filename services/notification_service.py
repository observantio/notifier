"""
Service for managing notifications, providing functions to send notifications through various channels such as email,
Slack, and Microsoft Teams.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import re
from datetime import UTC, datetime
from email.message import EmailMessage
from html import escape as html_escape
from pathlib import Path
from string import Template
from typing import cast

import aiosmtplib

from config import config
from custom_types.json import JSONDict
from models.alerting.alerts import Alert
from models.alerting.channels import ChannelType, NotificationChannel
from services.common.http_client import create_async_client
from services.notification import email_providers as notification_email
from services.notification import payloads as notification_payloads
from services.notification import senders as notification_senders
from services.notification import transport as notification_transport
from services.notification import validators as notification_validators

logger = logging.getLogger(__name__)
_EMAIL_TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "templates" / "emails"


def _render_html_template(template_name: str, values: dict[str, str]) -> str | None:
    path = _EMAIL_TEMPLATE_ROOT / template_name
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Email template %s could not be loaded: %s", path, exc)
        return None
    safe_values = {
        key: (str(value or "") if key.endswith("_html") else html_escape(str(value or "")))
        for key, value in values.items()
    }
    return Template(raw).safe_substitute(safe_values)


def _incident_severity_theme(severity: str) -> dict[str, str]:
    normalized = str(severity or "").strip().lower()
    if normalized in {"critical", "high", "error"}:
        return {
            "header_bg": "#dc2626",
            "header_fg": "#fef2f2",
            "severity_bg": "#fee2e2",
            "severity_fg": "#991b1b",
        }
    if normalized == "warning":
        return {
            "header_bg": "#f59e0b",
            "header_fg": "#1f2937",
            "severity_bg": "#fef3c7",
            "severity_fg": "#92400e",
        }
    return {
        "header_bg": "#2563eb",
        "header_fg": "#eff6ff",
        "severity_bg": "#dbeafe",
        "severity_fg": "#1e40af",
    }


class NotificationService:
    def __init__(self) -> None:
        self.timeout = config.default_timeout
        self._client = create_async_client(self.timeout)

    @staticmethod
    def _as_bool(value: object) -> bool:
        try:
            return notification_validators.coerce_bool(value)
        except AttributeError:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value != 0
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return False

    def validate_channel_config(self, channel_type: str, channel_config: JSONDict | None) -> list[str]:
        return notification_validators.validate_channel_config(channel_type, channel_config)

    async def _send_smtp_with_retry(
        self,
        message: EmailMessage,
        *legacy_args: object,
        smtp: notification_transport.SmtpDeliveryConfig | None = None,
        **legacy_kwargs: object,
    ) -> object:
        smtp_config = smtp
        if smtp_config is None:
            values = list(legacy_args)
            hostname = str(values[0] if values else legacy_kwargs.get("hostname") or "").strip()
            if not hostname:
                raise ValueError("SMTP hostname is required")
            try:
                port_value = values[1] if len(values) > 1 else legacy_kwargs.get("port") or 0
                port = int(cast(int | str | bytes | bytearray, port_value))
            except (TypeError, ValueError) as exc:
                raise ValueError("SMTP port must be an integer") from exc
            smtp_config = notification_transport.SmtpDeliveryConfig(
                hostname=hostname,
                port=port,
                username=(str(values[2] if len(values) > 2 else legacy_kwargs.get("username") or "").strip() or None),
                password=(
                    str(values[3])
                    if len(values) > 3 and values[3] is not None
                    else str(legacy_kwargs.get("password"))
                    if legacy_kwargs.get("password") is not None
                    else None
                ),
                start_tls=bool(values[4] if len(values) > 4 else legacy_kwargs.get("start_tls", False)),
                use_tls=bool(values[5] if len(values) > 5 else legacy_kwargs.get("use_tls", False)),
            )
        return await notification_transport.send_smtp_with_retry(
            message,
            hostname=smtp_config.hostname,
            port=smtp_config.port,
            username=smtp_config.username,
            password=smtp_config.password,
            start_tls=smtp_config.start_tls,
            use_tls=smtp_config.use_tls,
        )

    async def send_notification(self, channel: NotificationChannel, alert: Alert, action: str = "firing") -> bool:
        if not channel.enabled:
            logger.info("Channel %s is disabled, skipping notification", channel.name)
            return False
        if channel.type == ChannelType.EMAIL:
            return await self._send_email(channel, alert, action)
        senders = {
            ChannelType.SLACK: self._send_slack,
            ChannelType.TEAMS: self._send_teams,
            ChannelType.WEBHOOK: self._send_webhook,
            ChannelType.PAGERDUTY: self._send_pagerduty,
        }
        sender = senders.get(channel.type)
        if not sender:
            logger.error("Unknown channel type: %s", channel.type)
            return False
        return await sender(channel, alert, action)

    async def send_incident_assignment_email(
        self,
        recipient_email: str,
        incident_title: str,
        incident_status: str,
        incident_severity: str,
        actor: str,
    ) -> bool:
        enabled = str(config.get_secret("INCIDENT_ASSIGNMENT_EMAIL_ENABLED") or "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if not enabled:
            return False
        smtp_host = (config.get_secret("INCIDENT_ASSIGNMENT_SMTP_HOST") or "").strip()
        if not smtp_host:
            logger.info("Incident assignment email skipped: INCIDENT_ASSIGNMENT_SMTP_HOST not set")
            return False
        try:
            smtp_port = int(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_PORT") or "587")
        except ValueError:
            smtp_port = 587
        smtp_user = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_USERNAME")
        smtp_pass = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_PASSWORD")
        smtp_from = config.get_secret("INCIDENT_ASSIGNMENT_FROM") or config.default_admin_email
        use_starttls = self._as_bool(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_STARTTLS") or "true")
        use_ssl = self._as_bool(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_USE_SSL") or "false")
        msg = EmailMessage()
        msg["Subject"] = f"[Incident Assigned] {incident_title}"
        msg["From"] = smtp_from
        msg["To"] = recipient_email
        timestamp = datetime.now(UTC).isoformat()
        msg.set_content(
            f"You have been assigned an incident in Watchdog.\n\n"
            f"Title: {incident_title}\n"
            f"Status: {incident_status}\n"
            f"Severity: {incident_severity}\n"
            f"Updated by: {actor}\n"
            f"Timestamp: {timestamp}\n"
        )
        theme = _incident_severity_theme(incident_severity)
        html_body = _render_html_template(
            "incident_assignment.html",
            {
                "incident_title": incident_title,
                "incident_status": incident_status,
                "incident_severity": incident_severity,
                "incident_severity_upper": str(incident_severity or "info").upper(),
                "actor": actor,
                "timestamp": timestamp,
                "header_bg": theme["header_bg"],
                "header_fg": theme["header_fg"],
                "severity_bg": theme["severity_bg"],
                "severity_fg": theme["severity_fg"],
            },
        )
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        try:
            await self._send_smtp_with_retry(
                message=msg,
                hostname=smtp_host,
                port=smtp_port,
                username=smtp_user,
                password=smtp_pass,
                start_tls=use_starttls,
                use_tls=use_ssl,
            )
            logger.info("Incident assignment email sent to %s", recipient_email)
            return True
        except (ValueError, TimeoutError, OSError, aiosmtplib.errors.SMTPException) as exc:
            logger.warning("Failed to send incident assignment email to %s: %s", recipient_email, exc)
            return False

    async def _send_email(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        cfg = channel.config or {}
        to_field = cfg.get("to") or cfg.get("recipient")
        if not to_field:
            logger.error("Email channel '%s' has no 'to' address configured", channel.name)
            return False
        recipients = [r.strip() for r in re.split(r"[,;\s]+", str(to_field)) if r.strip()]
        if not recipients:
            logger.error("No valid recipient addresses for channel %s", channel.name)
            return False
        subject = f"[{action.upper()}] {alert.labels.get('alertname', 'Alert')}"
        body = notification_payloads.format_alert_body(alert, action)
        html_body = notification_payloads.format_alert_html(alert, action)
        provider_value = cfg.get("email_provider") or cfg.get("emailProvider") or "smtp"
        provider = str(provider_value).strip().lower()
        smtp_from = str(cfg.get("smtp_from") or cfg.get("smtpFrom") or cfg.get("from") or config.default_admin_email)

        if provider == "sendgrid":
            api_key = str(
                cfg.get("sendgrid_api_key")
                or cfg.get("sendgridApiKey")
                or cfg.get("api_key")
                or cfg.get("apiKey")
                or ""
            )
            if not api_key:
                logger.error("SendGrid API key not configured for email channel %s", channel.name)
                return False
            sent = await notification_email.send_via_sendgrid(
                self._client,
                api_key,
                notification_email.EmailDeliveryPayload(
                    subject=subject,
                    body=body,
                    recipients=recipients,
                    smtp_from=smtp_from,
                    html_body=html_body,
                ),
            )
            if sent:
                logger.info("Email notification sent via SendGrid (channel=%s)", channel.name)
            else:
                logger.error("Failed SendGrid email for channel %s", channel.name)
            return sent

        if provider == "resend":
            api_key = str(
                cfg.get("resend_api_key") or cfg.get("resendApiKey") or cfg.get("api_key") or cfg.get("apiKey") or ""
            )
            if not api_key:
                logger.error("Resend API key not configured for email channel %s", channel.name)
                return False
            sent = await notification_email.send_via_resend(
                self._client,
                api_key,
                notification_email.EmailDeliveryPayload(
                    subject=subject,
                    body=body,
                    recipients=recipients,
                    smtp_from=smtp_from,
                    html_body=html_body,
                ),
            )
            if sent:
                logger.info("Email notification sent via Resend (channel=%s)", channel.name)
            else:
                logger.error("Failed Resend email for channel %s", channel.name)
            return sent

        if provider != "smtp":
            logger.error("Unsupported email provider '%s' for channel %s", provider, channel.name)
            return False

        smtp_host = str(cfg.get("smtp_host") or cfg.get("smtpHost") or "")
        smtp_port = int(str(cfg.get("smtp_port") or cfg.get("smtpPort") or 0))
        smtp_user = str(cfg.get("smtp_username") or cfg.get("smtpUsername") or cfg.get("username") or "") or None
        smtp_pass = str(cfg.get("smtp_password") or cfg.get("smtpPassword") or cfg.get("password") or "") or None
        smtp_api_key = (
            str(cfg.get("smtp_api_key") or cfg.get("smtpApiKey") or cfg.get("api_key") or cfg.get("apiKey") or "")
            or None
        )
        smtp_auth_type = str(cfg.get("smtp_auth_type") or cfg.get("smtpAuthType") or "password").strip().lower()
        use_starttls = self._as_bool(
            cfg.get("smtp_starttls") or cfg.get("smtpStartTLS") or cfg.get("starttls") or False
        )
        use_ssl = self._as_bool(cfg.get("smtp_use_ssl") or cfg.get("smtpUseSSL") or False)

        if not smtp_host:
            logger.error("SMTP host not configured for email channel %s", channel.name)
            return False
        if smtp_port == 0:
            smtp_port = 465 if use_ssl else 587 if use_starttls else 25

        if smtp_auth_type == "none":
            smtp_user = None
            smtp_pass = None
        elif smtp_auth_type == "api_key":
            smtp_user = smtp_user or "apikey"
            smtp_pass = smtp_api_key
            if not smtp_pass:
                logger.error("SMTP API key not configured for email channel %s", channel.name)
                return False
        elif smtp_user and not smtp_pass and smtp_api_key:
            smtp_pass = smtp_api_key

        msg = notification_email.build_smtp_message(subject, body, smtp_from, recipients, html_body)
        logger.info("Sending email to %s via %s:%s (channel=%s)", recipients, smtp_host, smtp_port, channel.name)
        sent = await notification_email.send_via_smtp(
            msg,
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_pass,
            use_starttls,
            use_ssl,
        )
        if sent:
            logger.info("Email notification sent (channel=%s)", channel.name)
        else:
            logger.error("Failed to send email for channel %s after retries", channel.name)
        return sent

    async def _send_slack(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_slack(self._client, channel.config or {}, alert, action)

    async def _send_teams(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_teams(self._client, channel.config or {}, alert, action)

    async def _send_webhook(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_webhook(self._client, channel.config or {}, alert, action)

    async def _send_pagerduty(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_pagerduty(self._client, channel.config or {}, alert, action)
