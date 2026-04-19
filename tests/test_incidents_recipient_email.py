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
