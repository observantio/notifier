"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import jwt
import pytest
from fastapi import HTTPException
from starlette.requests import Request

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from config import config
from middleware import dependencies
from middleware.rate_limit import ip as ip_mod
from middleware.rate_limit import hybrid as hybrid_mod
from middleware.rate_limit import redis_fixed_window as redis_mod
import middleware.rate_limit as rate_limit_mod
import database as db_mod
from models.access.auth_models import Role, TokenData


def _request(ip: str = "203.0.113.10", headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/",
            "headers": headers or [],
            "client": (ip, 12345),
            "scheme": "http",
            "query_string": b"",
        }
    )


def _claims(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.USER,
        "is_superuser": False,
        "permissions": ["read:alerts"],
        "group_ids": ["g1"],
    }
    payload.update(kwargs)
    return TokenData(**cast(dict[str, Any], payload))


def test_dependencies_token_and_permission_edges(monkeypatch):
    assert dependencies._extract_bearer_token(_request(headers=[(b"authorization", b"Bearer tkn")]), None) == "tkn"
    creds = SimpleNamespace(credentials="abc")
    assert dependencies._extract_bearer_token(_request(), creds) == "abc"

    monkeypatch.setattr(config, "get_secret", lambda *_args, **_kwargs: None)
    with pytest.raises(HTTPException) as exc:
        dependencies._compare_service_token(_request())
    assert exc.value.status_code == 500

    monkeypatch.setattr(config, "get_secret", lambda *_args, **_kwargs: "expected")
    with pytest.raises(HTTPException) as exc:
        dependencies._compare_service_token(_request(headers=[(b"x-service-token", b"wrong")]))
    assert exc.value.status_code == 403

    req = _request(headers=[(b"x-service-token", b"expected")])
    dependencies._compare_service_token(req)

    monkeypatch.setattr(config, "get_secret", lambda key: None if "VERIFY" in key or "SIGNING" in key else "x")
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token("t")
    assert exc.value.status_code == 500

    monkeypatch.setattr(config, "get_secret", lambda _key: "secret")
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_ALGORITHM", "HS256")
    monkeypatch.setattr(
        jwt, "decode", lambda *_args, **_kwargs: {"iat": "x", "exp": "y", "jti": "j", "user_id": "u", "tenant_id": "t"}
    )
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token("t")
    assert exc.value.status_code == 401

    monkeypatch.setattr(
        jwt, "decode", lambda *_args, **_kwargs: {"iat": 20, "exp": 10, "jti": "j", "user_id": "u", "tenant_id": "t"}
    )
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token("t")
    assert exc.value.status_code == 401

    monkeypatch.setattr(
        jwt, "decode", lambda *_args, **_kwargs: {"iat": 10, "exp": 20, "jti": "", "user_id": "u", "tenant_id": "t"}
    )
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token("t")
    assert exc.value.status_code == 401

    monkeypatch.setattr(
        jwt, "decode", lambda *_args, **_kwargs: {"iat": 10, "exp": 20, "jti": "j", "user_id": "", "tenant_id": ""}
    )
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token("t")
    assert exc.value.status_code == 401

    monkeypatch.setattr(dependencies, "_compare_service_token", lambda _request: None)
    monkeypatch.setattr(dependencies, "_verify_context_token", lambda _token: _claims(group_ids=["g1", "", "g1"]))
    user = dependencies.get_current_user(_request(headers=[(b"authorization", b"Bearer x")]), None)
    assert user.group_ids == ["g1"]

    with pytest.raises(HTTPException) as exc:
        dependencies.get_current_user(_request(headers=[(b"x-service-token", b"expected")]), None)
    assert exc.value.status_code == 401

    checker = dependencies.require_permission("read:alerts")
    assert checker(_claims())
    with pytest.raises(HTTPException):
        checker(_claims(permissions=[]))

    any_checker = dependencies.require_any_permission(["read:alerts", "read:rules"])
    assert any_checker(_claims(permissions=["read:rules"]))
    with pytest.raises(HTTPException):
        any_checker(_claims(permissions=[]))
    assert any_checker(_claims(is_superuser=True, permissions=[]))

    observed = []
    monkeypatch.setattr(
        dependencies, "apply_scoped_rate_limit", lambda user, scope: observed.append((user.user_id, scope))
    )
    scoped = dependencies.require_permission_with_scope("read:alerts", "scope-a")
    assert scoped(_claims()).user_id == "u1"
    any_scoped = dependencies.require_any_permission_with_scope(["read:alerts"], "scope-b")
    assert any_scoped(_claims()).user_id == "u1"
    assert observed == [("u1", "scope-a"), ("u1", "scope-b")]


def test_dependencies_public_allowlist_edges(monkeypatch):
    monkeypatch.setattr(dependencies, "enforce_ip_rate_limit", lambda *args, **kwargs: None)
    monkeypatch.setattr(config, "REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS", True)
    monkeypatch.setattr(dependencies, "client_ip", lambda _req: "unknown")
    with pytest.raises(HTTPException) as exc:
        dependencies.enforce_public_endpoint_security(_request(), scope="public", limit=1, window_seconds=60)
    assert exc.value.status_code == 403

    monkeypatch.setattr(config, "REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS", False)
    monkeypatch.setattr(config, "ALLOWLIST_FAIL_OPEN", False)
    with pytest.raises(HTTPException) as exc:
        dependencies._enforce_ip_allowlist(_request(), "", scope="public")
    assert exc.value.status_code == 403

    with pytest.raises(HTTPException) as exc:
        dependencies._enforce_ip_allowlist(_request(), "bad-cidr/xx", scope="public")
    assert exc.value.status_code == 403

    monkeypatch.setattr(dependencies, "client_ip", lambda _req: "not-an-ip")
    with pytest.raises(HTTPException) as exc:
        dependencies._enforce_ip_allowlist(_request(), "203.0.113.0/24", scope="public")
    assert exc.value.status_code == 403

    monkeypatch.setattr(dependencies, "client_ip", lambda _req: "203.0.113.10")
    dependencies._enforce_ip_allowlist(_request(), "203.0.113.0/24", scope="public")

    networks = dependencies._parse_allowlist_networks("203.0.113.10,2001:db8::1")
    assert len(networks) == 2


def test_rate_limit_builder_and_enforcement_edges(monkeypatch):
    monkeypatch.setattr(rate_limit_mod.config, "RATE_LIMIT_GC_EVERY", 100)
    monkeypatch.setattr(rate_limit_mod.config, "RATE_LIMIT_STALE_AFTER_SECONDS", 60)
    monkeypatch.setattr(rate_limit_mod.config, "RATE_LIMIT_MAX_STATES", 10000)

    monkeypatch.setattr(
        rate_limit_mod.os,
        "getenv",
        lambda key, default=None: {"RATE_LIMIT_BACKEND": "memory", "RATE_LIMIT_REDIS_URL": ""}.get(key, default),
    )
    limiter = rate_limit_mod._build_rate_limiter()
    assert limiter is not None

    monkeypatch.setattr(rate_limit_mod.config, "IS_PRODUCTION", True)
    monkeypatch.setattr(
        rate_limit_mod.os,
        "getenv",
        lambda key, default=None: {"RATE_LIMIT_BACKEND": "redis", "RATE_LIMIT_REDIS_URL": ""}.get(key, default),
    )
    limiter = rate_limit_mod._build_rate_limiter()
    assert limiter is not None

    monkeypatch.setattr(
        rate_limit_mod.os,
        "getenv",
        lambda key, default=None: {"RATE_LIMIT_BACKEND": "auto", "RATE_LIMIT_REDIS_URL": "redis://x"}.get(key, default),
    )
    monkeypatch.setattr(
        rate_limit_mod,
        "RedisFixedWindowRateLimiter",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("redis down")),
    )
    limiter = rate_limit_mod._build_rate_limiter()
    assert limiter is not None

    class _Limiter:
        def hit(self, *_args, **_kwargs):
            return SimpleNamespace(allowed=False, retry_after_seconds=7)

    monkeypatch.setattr(rate_limit_mod, "rate_limiter", _Limiter())
    with pytest.raises(HTTPException) as exc:
        rate_limit_mod.enforce_rate_limit(key="k", limit=1, window_seconds=60)
    assert exc.value.status_code == 429

    captured = {}

    def _enforce_rate_limit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(rate_limit_mod, "enforce_rate_limit", _enforce_rate_limit)
    monkeypatch.setattr(rate_limit_mod, "client_ip", lambda _req: "unknown")
    rate_limit_mod.enforce_ip_rate_limit(
        _request(headers=[(b"user-agent", b"ua")]), scope="api", limit=1, window_seconds=60
    )
    assert captured["key"].startswith("ip:unknown-")


def test_rate_limit_ip_and_redis_edges(monkeypatch):
    assert ip_mod._valid_ip("") is None
    assert ip_mod._valid_ip("203.0.113.10") == "203.0.113.10"

    monkeypatch.setattr(ip_mod.config, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(ip_mod.config, "TRUSTED_PROXY_CIDRS", [])
    req = _request(headers=[(b"x-forwarded-for", b"198.51.100.5, 10.0.0.1")])
    assert ip_mod.client_ip(req) == "198.51.100.5"

    monkeypatch.setattr(ip_mod.config, "TRUSTED_PROXY_CIDRS", ["203.0.113.0/24", "bad-cidr"])
    req = _request(ip="invalid-ip", headers=[(b"x-real-ip", b"198.51.100.9")])
    assert ip_mod.client_ip(req) == "unknown"

    req = _request(ip="203.0.113.10", headers=[(b"x-real-ip", b"198.51.100.9")])
    assert ip_mod.client_ip(req) == "198.51.100.9"

    monkeypatch.setattr(ip_mod.config, "TRUST_PROXY_HEADERS", False)
    assert ip_mod.client_ip(_request(ip="bad-ip")) == "unknown"

    assert redis_mod._sanitize_redis_url(object()) == "<redis-url>"

    limiter = redis_mod.RedisFixedWindowRateLimiter.__new__(redis_mod.RedisFixedWindowRateLimiter)
    limiter._key_prefix = "prefix"

    class _Pipe:
        def incr(self, _k):
            return self

        def expire(self, _k, _ttl):
            return self

        def execute(self):
            return [2, True]

    limiter._client = SimpleNamespace(pipeline=lambda transaction=False: _Pipe())
    assert limiter.hit("k", limit=0, window_seconds=60).allowed is True
    assert limiter.hit("k", limit=1, window_seconds=0).allowed is True
    out = limiter.hit("k", limit=1, window_seconds=60)
    assert out.allowed is False


def test_hybrid_and_database_edges(monkeypatch):
    fallback = hybrid_mod.InMemoryRateLimiter()

    class _Redis:
        def hit(self, *_args, **_kwargs):
            raise HTTPException(status_code=429, detail="too many")

    limiter = hybrid_mod.HybridRateLimiter(_Redis(), fallback)
    with pytest.raises(HTTPException):
        limiter.hit("k", limit=1, window_seconds=60)

    class _RedisFail:
        def hit(self, *_args, **_kwargs):
            raise RuntimeError("down")

    events = []
    monkeypatch.setattr(hybrid_mod, "record_fallback_event", lambda mode, reason: events.append((mode, reason)))
    limiter = hybrid_mod.HybridRateLimiter(_RedisFail(), fallback)
    deny = limiter.hit("k", limit=1, window_seconds=60, fallback_mode="deny")
    allow = limiter.hit("k", limit=1, window_seconds=60, fallback_mode="allow")
    assert deny.allowed is False and allow.allowed is True
    assert events

    assert db_mod.connection_test() is False

    with pytest.raises(RuntimeError):
        db_mod.ensure_database_exists("postgresql://user:pass@host")

    class _Conn:
        def execution_options(self, **_kwargs):
            return self

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, *_args, **_kwargs):
            return SimpleNamespace(scalar=lambda: True)

    class _Engine:
        def connect(self):
            return _Conn()

        def dispose(self):
            return None

    monkeypatch.setattr(db_mod, "create_engine", lambda *_args, **_kwargs: _Engine())
    db_mod.ensure_database_exists("postgresql://user:pass@host:5432/dbname")

    old = db_mod._SESSION_LOCAL
    db_mod._SESSION_LOCAL = None
    try:
        with pytest.raises(RuntimeError):
            db_mod._require_session_factory()
    finally:
        db_mod._SESSION_LOCAL = old
