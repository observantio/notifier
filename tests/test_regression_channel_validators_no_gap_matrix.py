"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from services.notification import validators


def test_validate_email_smtp_password_auth_requires_username_and_password() -> None:
    errors = validators.validate_channel_config(
        "email",
        {
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "password",
        },
    )

    assert "SMTP email channel auth_type=password requires 'smtp_username'" in errors
    assert "SMTP email channel auth_type=password requires 'smtp_password'" in errors


def test_validate_email_smtp_api_key_auth_requires_api_key_and_port_bounds() -> None:
    errors = validators.validate_channel_config(
        "email",
        {
            "to": "ops@example.com",
            "email_provider": "smtp",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "api_key",
            "smtp_port": 70000,
        },
    )

    assert "SMTP email channel auth_type=api_key requires 'smtp_api_key'" in errors
    assert "SMTP email channel 'smtp_port' must be between 1 and 65535" in errors


def test_validate_slack_requires_safe_webhook_url() -> None:
    bad_errors = validators.validate_channel_config("slack", {"webhook_url": "ftp://hooks.slack.com/services/a/b/c"})
    good_errors = validators.validate_channel_config(
        "slack", {"webhook_url": "https://hooks.slack.com/services/a/b/c"}
    )

    assert bad_errors == ["Slack channel requires a valid 'webhook_url'"]
    assert good_errors == []


def test_validate_teams_and_webhook_require_safe_urls() -> None:
    teams_errors = validators.validate_channel_config("teams", {"webhook_url": "not-a-url"})
    webhook_errors = validators.validate_channel_config("webhook", {"url": "javascript:alert(1)"})

    assert teams_errors == ["Teams channel requires a valid 'webhook_url'"]
    assert webhook_errors == ["Webhook channel requires a valid URL"]


def test_validate_pagerduty_requires_routing_key_or_integration_key() -> None:
    missing_errors = validators.validate_channel_config("pagerduty", {})
    present_errors = validators.validate_channel_config("pagerduty", {"integrationKey": "pd-routing-key"})

    assert missing_errors == ["PagerDuty channel requires 'routing_key'"]
    assert present_errors == []
