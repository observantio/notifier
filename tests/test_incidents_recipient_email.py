"""
Focused tests for incident assignee email normalization helper.
"""

from __future__ import annotations

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from routers.observability import incidents as incidents_router


def test_recipient_email_parsing_and_validation_surface() -> None:
    parse = incidents_router._recipient_email

    assert parse(None) is None
    assert parse("") is None
    assert parse("   ") is None
    assert parse("bob@example.com") == "bob@example.com"
    assert parse(" Bob <bob@example.com> ") == "bob@example.com"
    assert parse("not-an-email") is None
    assert parse("Name <not-an-email>") is None
