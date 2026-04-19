"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env
ensure_test_env()


from services.notification import validators as notification_validators


def test_validate_channel_config_email_checks():
    errs = notification_validators.validate_channel_config("email", {})
    assert any("recipient" in e.lower() or "to'" in e for e in errs)

    errs = notification_validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "smtp"})
    assert any("smtp_host" in e or "smtp host" in e.replace(" ", "_") for e in errs)

    errs = notification_validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "sendgrid"})
    assert any("sendgrid" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "resend"})
    assert any("resend" in e.lower() for e in errs)


def test_validate_channel_config_slack_and_webhook_and_pagerduty():
    errs = notification_validators.validate_channel_config("slack", {"webhook_url": "ftp://example.com"})
    assert any("webhook" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("teams", {"webhookUrl": ""})
    assert any("webhook" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("webhook", {"url": None})
    assert any("webhook" in e.lower() or "url" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("pagerduty", {})
    assert any("routing_key" in e or "integrationkey" in e.lower() for e in errs)


def test_validate_channel_config_smtp_auth_branch_matrix():
    password_ok_errors = notification_validators.validate_channel_config(
        "email",
        {
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "password",
            "smtp_username": "user",
            "smtp_password": "pass",
        },
    )
    assert password_ok_errors == []

    api_key_ok_errors = notification_validators.validate_channel_config(
        "email",
        {
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "api_key",
            "smtp_api_key": "key",
        },
    )
    assert api_key_ok_errors == []

    invalid_auth_errors = notification_validators.validate_channel_config(
        "email",
        {
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "token",
        },
    )
    assert any("smtp_auth_type" in error for error in invalid_auth_errors)
