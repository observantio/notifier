"""
Regression tests for recipient extraction in incident assignment workflow.
"""

from __future__ import annotations

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from routers.observability import incidents as incidents_router


def test_recipient_email_accepts_plain_email() -> None:
    assert incidents_router._recipient_email("ops@example.com") == "ops@example.com"


def test_recipient_email_extracts_email_from_display_name() -> None:
    assert incidents_router._recipient_email("Ops Team <ops@example.com>") == "ops@example.com"


def test_recipient_email_returns_none_for_blank_value() -> None:
    assert incidents_router._recipient_email("   ") is None


def test_recipient_email_returns_none_for_non_email_identifier() -> None:
    assert incidents_router._recipient_email("oncall-user-17") is None


def test_recipient_email_returns_none_for_display_name_without_address() -> None:
    assert incidents_router._recipient_email("Ops Team") is None
