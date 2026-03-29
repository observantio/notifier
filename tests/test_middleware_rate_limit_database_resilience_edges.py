"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import httpx
import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from config import config
import database as db_mod
from middleware import dependencies
import middleware.rate_limit as rate_mod
from middleware.rate_limit.hybrid import HybridRateLimiter
from middleware.rate_limit.in_memory import InMemoryRateLimiter
from middleware.rate_limit.ip import _valid_ip, client_ip
from middleware.rate_limit.models import RateLimitHitResult, RateLimitState
from middleware.rate_limit.redis_fixed_window import RedisFixedWindowRateLimiter, _sanitize_redis_url
from middleware import resilience
from models.access.auth_models import Permission, Role, TokenData


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


def _user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.USER,
        "permissions": [Permission.READ_ALERTS.value],
        "group_ids": ["g1"],
        "is_superuser": False,
    }
    payload.update(kwargs)
    return TokenData(**cast(dict[str, Any], payload))


class _FakeSession:
    def __init__(self):
        self.committed = 0
        self.rolled_back = 0
        self.closed = 0

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


class _FakeConn:
    def __init__(self, *, exists=True, execute_error: Exception | None = None):
        self.exists = exists
        self.execute_error = execute_error
        self.executed: list[object] = []

    def execution_options(self, **_kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, stmt, params=None):
        self.executed.append((stmt, params))
        if self.execute_error:
            raise self.execute_error
        if params and "name" in params:
            return SimpleNamespace(scalar=lambda: self.exists)
        return SimpleNamespace(scalar=lambda: None)


class _FakeEngine:
    def __init__(self, conn: _FakeConn | None = None):
        self.conn = conn or _FakeConn()
        self.disposed = 0

    def connect(self):
        return self.conn

    def dispose(self):
        self.disposed += 1


def test_database_module_paths(monkeypatch):
    with pytest.raises(RuntimeError):
        db_mod.ensure_database_exists("sqlite://")

    class _Url:
        database = "appdb"

        def set(self, **_kwargs):
            return "postgres-admin"

    fake_admin_conn = _FakeConn(exists=False)
    fake_admin_engine = _FakeEngine(fake_admin_conn)
    monkeypatch.setattr(db_mod, "make_url", lambda _u: _Url())
    monkeypatch.setattr(db_mod, "create_engine", lambda *_args, **_kwargs: fake_admin_engine)
    db_mod.ensure_database_exists("postgresql://user:pass@localhost:5432/appdb")
    assert fake_admin_engine.disposed == 1
    assert any("CREATE DATABASE" in str(stmt) for stmt, _ in fake_admin_conn.executed)

    db_mod.dispose_database()
    engine = _FakeEngine(_FakeConn())
    monkeypatch.setattr(db_mod, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(db_mod, "sessionmaker", lambda **_kwargs: (lambda: _FakeSession()))
    db_mod.init_database("postgresql://user:pass@localhost:5432/appdb")
    db_mod.init_database("postgresql://user:pass@localhost:5432/appdb")

    with db_mod.get_db_session() as session:
        assert isinstance(session, _FakeSession)

    with pytest.raises(RuntimeError):
        with db_mod.get_db_session() as _session:
            raise RuntimeError("boom")

    gen = db_mod.get_db()
    session = next(gen)
    assert isinstance(session, _FakeSession)
    with pytest.raises(StopIteration):
        next(gen)

    gen = db_mod.get_db()
    _ = next(gen)
    with pytest.raises(RuntimeError):
        gen.throw(RuntimeError("fail"))

    assert db_mod.connection_test() is True
    db_mod._engine = _FakeEngine(_FakeConn(execute_error=SQLAlchemyError("db")))
    assert db_mod.connection_test() is False

    db_mod.dispose_database()
    assert db_mod._engine is None

    # Cover guard paths where one side of initialization is missing.
    db_mod._engine = object()
    db_mod._session_local = None
    with pytest.raises(RuntimeError):
        with db_mod.get_db_session():
            pass

    db_mod._engine = object()
    db_mod._session_local = None
    with pytest.raises(RuntimeError):
        next(db_mod.get_db())

    with pytest.raises(RuntimeError):
        db_mod.init_db()

    class _Meta:
        def __init__(self):
            self.called = 0

        def create_all(self, bind=None):
            self.called += 1
            assert bind is engine

    meta = _Meta()
    monkeypatch.setattr(db_mod.Base, "metadata", meta)
    db_mod._engine = engine
    db_mod.init_db()
    assert meta.called == 1


def test_in_memory_and_hybrid_rate_limiters(monkeypatch):
    limiter = InMemoryRateLimiter(gc_every=100, stale_after_seconds=60, max_states=10000)
    assert limiter.hit("k", limit=0, window_seconds=10).allowed is True
    assert limiter.hit("k", limit=1, window_seconds=0).allowed is True

    first = limiter.hit("k", limit=1, window_seconds=60)
    second = limiter.hit("k", limit=1, window_seconds=60)
    assert first.allowed is True
    assert second.allowed is False

    limiter._gc_every = 1
    now = 1_000.0
    monkeypatch.setattr("middleware.rate_limit.in_memory.time.time", lambda: now)
    limiter._states = {
        "old": RateLimitState(window_start=0, count=1),
        "new": RateLimitState(window_start=999, count=1),
    }
    limiter.hit("current", limit=5, window_seconds=10)
    assert "old" not in limiter._states

    limiter._max_states = 2
    limiter._gc_every = 10_000
    monkeypatch.setattr("middleware.rate_limit.in_memory.time.time", lambda: 3.0)
    limiter._states = {
        "a": RateLimitState(window_start=1, count=1),
        "b": RateLimitState(window_start=2, count=1),
    }
    limiter.hit("c", limit=5, window_seconds=10)
    assert len(limiter._states) == 2

    class _Redis:
        def hit(self, *_args, **_kwargs):
            return RateLimitHitResult(True, 1, 0, "redis")

    class _Fallback:
        def hit(self, *_args, **_kwargs):
            return RateLimitHitResult(True, 2, 0, "memory")

    hybrid = HybridRateLimiter(_Redis(), _Fallback())
    assert hybrid.hit("k", limit=1, window_seconds=10).backend == "redis"

    events = []
    monkeypatch.setattr("middleware.rate_limit.hybrid.record_fallback_event", lambda mode, reason: events.append((mode, reason)))

    class _BrokenRedis:
        def hit(self, *_args, **_kwargs):
            raise ConnectionError("down")

    hybrid = HybridRateLimiter(_BrokenRedis(), _Fallback())
    deny = hybrid.hit("k", limit=1, window_seconds=7, fallback_mode="deny")
    allow = hybrid.hit("k", limit=3, window_seconds=7, fallback_mode="allow")
    memory = hybrid.hit("k", limit=3, window_seconds=7, fallback_mode="memory")
    assert deny.allowed is False and deny.fallback_used is True
    assert allow.allowed is True and allow.backend == "redis-fallback-allow"
    assert memory.backend == "memory"
    assert events and events[0][0] in {"deny", "allow", "memory"}


def test_rate_limit_ip_and_enforcement(monkeypatch):
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", False)
    assert _valid_ip("203.0.113.10") == "203.0.113.10"
    assert _valid_ip("not-an-ip") is None
    assert client_ip(_request("198.51.100.1")) == "198.51.100.1"

    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(config, "TRUSTED_PROXY_CIDRS", ["198.51.100.0/24"])
    req = _request(
        "198.51.100.10",
        headers=[
            (b"x-forwarded-for", b"203.0.113.1, 198.51.100.10"),
            (b"x-real-ip", b"203.0.113.2"),
        ],
    )
    assert client_ip(req) == "203.0.113.1"

    req = _request("198.51.100.10", headers=[(b"x-forwarded-for", b"bad"), (b"x-real-ip", b"203.0.113.2")])
    assert client_ip(req) == "203.0.113.2"

    req = _request("192.0.2.10", headers=[(b"x-forwarded-for", b"203.0.113.3")])
    assert client_ip(req) == "192.0.2.10"

    allowed = RateLimitHitResult(True, 1, 0, "memory")
    denied = RateLimitHitResult(False, 0, 12, "memory")
    monkeypatch.setattr(rate_mod, "rate_limiter", SimpleNamespace(hit=lambda *_args, **_kwargs: allowed))
    rate_mod.enforce_rate_limit(key="k", limit=1, window_seconds=30)

    monkeypatch.setattr(rate_mod, "rate_limiter", SimpleNamespace(hit=lambda *_args, **_kwargs: denied))
    with pytest.raises(HTTPException) as exc:
        rate_mod.enforce_rate_limit(key="k", limit=1, window_seconds=30)
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "12"

    keys = []

    def _capture_enforce(**kwargs):
        keys.append(kwargs["key"])

    monkeypatch.setattr(rate_mod, "enforce_rate_limit", _capture_enforce)
    monkeypatch.setattr(rate_mod, "client_ip", lambda _request: "unknown")
    rate_mod.enforce_ip_rate_limit(_request(), scope="public", limit=10, window_seconds=60)
    assert keys[-1].startswith("ip:unknown-")

    monkeypatch.setattr(rate_mod, "client_ip", lambda _request: "203.0.113.7")
    rate_mod.enforce_ip_rate_limit(_request(), scope="public", limit=10, window_seconds=60)
    assert keys[-1] == "ip:203.0.113.7:public"


def test_redis_fixed_window_and_sanitize(monkeypatch):
    assert _sanitize_redis_url("redis://user:pass@localhost:6379/0") == "redis://localhost:6379/0"
    assert _sanitize_redis_url("bad://") == "bad:"

    monkeypatch.setattr("middleware.rate_limit.redis_fixed_window.import_module", lambda _name: (_ for _ in ()).throw(ImportError("no redis")))
    with pytest.raises(RuntimeError):
        RedisFixedWindowRateLimiter("redis://localhost:6379/0")

    class _Pipe:
        def __init__(self):
            self.calls = []

        def incr(self, key):
            self.calls.append(("incr", key))

        def expire(self, key, ttl):
            self.calls.append(("expire", key, ttl))

        def execute(self):
            return [2, True]

    class _Client:
        def __init__(self, ping_value=True, ping_error: Exception | None = None):
            self.ping_value = ping_value
            self.ping_error = ping_error

        def ping(self):
            if self.ping_error:
                raise self.ping_error
            return self.ping_value

        def pipeline(self, transaction=False):
            assert transaction is False
            return _Pipe()

    class _RedisModule:
        def __init__(self, client):
            self._client = client

        def from_url(self, *_args, **_kwargs):
            return self._client

    monkeypatch.setattr("middleware.rate_limit.redis_fixed_window.import_module", lambda _name: _RedisModule(_Client()))
    limiter = RedisFixedWindowRateLimiter("redis://localhost:6379/0")
    hit = limiter.hit("k", limit=2, window_seconds=30)
    assert hit.allowed is True and hit.remaining == 0

    monkeypatch.setattr("middleware.rate_limit.redis_fixed_window.import_module", lambda _name: _RedisModule(_Client(ping_value=False)))
    with pytest.raises(RuntimeError):
        RedisFixedWindowRateLimiter("redis://localhost:6379/0")


def test_dependencies_helpers_and_allowlist_paths(monkeypatch):
    creds = SimpleNamespace(credentials="tok")
    req = _request(headers=[(b"authorization", b"Bearer hdr-token")])
    assert dependencies._extract_bearer_token(req, creds) == "tok"
    assert dependencies._extract_bearer_token(req, None) == "hdr-token"
    assert dependencies._extract_bearer_token(_request(), None) is None

    monkeypatch.setattr(config, "get_secret", lambda *_args, **_kwargs: None)
    with pytest.raises(HTTPException):
        dependencies._compare_service_token(_request())

    monkeypatch.setattr(config, "get_secret", lambda key: "expected" if key in {"NOTIFIER_EXPECTED_SERVICE_TOKEN", "GATEWAY_INTERNAL_SERVICE_TOKEN"} else None)
    with pytest.raises(HTTPException):
        dependencies._compare_service_token(_request())

    ok_req = _request(headers=[(b"x-service-token", b"expected")])
    dependencies._compare_service_token(ok_req)

    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS", 1)
    with dependencies._jti_lock:
        dependencies._jti_cache.clear()
    dependencies._assert_jti_not_replayed("j1")
    with pytest.raises(HTTPException):
        dependencies._assert_jti_not_replayed("j1")

    with dependencies._jti_lock:
        dependencies._jti_cache["old"] = 0
    monkeypatch.setattr("middleware.dependencies.time.monotonic", lambda: 10_000)
    dependencies._assert_jti_not_replayed("j2")

    assert dependencies._normalize_group_ids(["g1", "g1", "", "g2"]) == ["g1", "g2"]

    checker = dependencies.require_permission(Permission.READ_ALERTS)
    assert checker(_user()) == _user()
    with pytest.raises(HTTPException):
        checker(_user(permissions=[]))

    any_checker = dependencies.require_any_permission([Permission.READ_ALERTS, Permission.UPDATE_ALERTS])
    assert any_checker(_user()) == _user()
    with pytest.raises(HTTPException):
        any_checker(_user(permissions=[]))

    captured_scopes = []
    monkeypatch.setattr(dependencies, "apply_scoped_rate_limit", lambda _user, scope: captured_scopes.append(scope))
    scoped = dependencies.require_permission_with_scope(Permission.READ_ALERTS, "alert-scope")
    assert scoped(_user()).user_id == "u1"
    any_scoped = dependencies.require_any_permission_with_scope([Permission.READ_ALERTS], "any-scope")
    assert any_scoped(_user()).user_id == "u1"
    assert captured_scopes == ["alert-scope", "any-scope"]

    monkeypatch.setattr(config, "REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS", True)
    monkeypatch.setattr(dependencies, "client_ip", lambda _request: "unknown")
    with pytest.raises(HTTPException):
        dependencies.enforce_public_endpoint_security(_request(), scope="public", limit=10, window_seconds=60)

    monkeypatch.setattr(config, "REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS", False)
    monkeypatch.setattr(dependencies, "enforce_ip_rate_limit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(config, "ALLOWLIST_FAIL_OPEN", False)
    monkeypatch.setattr(dependencies, "client_ip", lambda request: request.client.host if request.client else "unknown")

    with pytest.raises(HTTPException):
        dependencies.enforce_public_endpoint_security(_request(), scope="public", limit=10, window_seconds=60, allowlist="203.0.113.0/24,bad-cidr/")

    with pytest.raises(HTTPException):
        dependencies.enforce_public_endpoint_security(_request("198.51.100.1"), scope="public", limit=10, window_seconds=60, allowlist="203.0.113.0/24")

    dependencies.enforce_public_endpoint_security(_request("203.0.113.10"), scope="public", limit=10, window_seconds=60, allowlist="203.0.113.0/24")

    monkeypatch.setattr(config, "ALLOWLIST_FAIL_OPEN", True)
    dependencies._enforce_ip_allowlist(_request(), "", scope="public")

    parsed = dependencies._parse_allowlist_networks("203.0.113.10,2001:db8::1")
    assert len(parsed) == 2


def test_dependencies_rate_limit_and_allowlist_remaining_edges(monkeypatch):
    monkeypatch.setattr(config, "get_secret", lambda _key: "secret")
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_ALGORITHM", "HS256")
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda *_args, **_kwargs: {
            "iat": int((datetime.now(timezone.utc) - timedelta(seconds=10)).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(seconds=60)).timestamp()),
            "jti": "edge-jti",
            "user_id": "u1",
            "tenant_id": "t1",
            "org_id": "o1",
            "role": "user",
            "permissions": [],
            "group_ids": [],
        },
    )
    monkeypatch.setattr(dependencies, "TokenData", lambda **_kwargs: (_ for _ in ()).throw(ValueError("bad claims")))
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token("token")
    assert exc.value.status_code == 401

    assert dependencies.apply_scoped_rate_limit(_user(), "scope") is None
    assert dependencies.require_permission(Permission.READ_ALERTS)(_user(is_superuser=True, permissions=[])).is_superuser is True
    assert dependencies._enforce_ip_allowlist(_request(), None, scope="public") is None


def test_rate_limit_build_and_helper_remaining_edges(monkeypatch):
    monkeypatch.setattr(rate_mod.os, "getenv", lambda key, default=None: {"RATE_LIMIT_BACKEND": "auto", "RATE_LIMIT_REDIS_URL": "redis://localhost:6379/0"}.get(key, default))
    monkeypatch.setattr(rate_mod, "RedisFixedWindowRateLimiter", lambda *_args, **_kwargs: SimpleNamespace())
    limiter = rate_mod._build_rate_limiter()
    assert getattr(limiter, "_redis_limiter", None) is not None

    hybrid = HybridRateLimiter(None, InMemoryRateLimiter())
    result = hybrid.hit("k-edge", limit=5, window_seconds=60, fallback_mode="invalid-mode")
    assert result.allowed is True

    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(config, "TRUSTED_PROXY_CIDRS", ["bad-cidr"])
    assert client_ip(_request(ip="203.0.113.10")) == "203.0.113.10"

    monkeypatch.setattr(config, "TRUSTED_PROXY_CIDRS", ["203.0.113.0/24"])
    monkeypatch.setattr("middleware.rate_limit.ip._valid_ip", lambda _value: "not-an-ip")
    assert client_ip(_request(ip="203.0.113.10")) == "not-an-ip"

    monkeypatch.setattr(rate_mod.config, "IS_PRODUCTION", True)
    monkeypatch.setattr(rate_mod, "RedisFixedWindowRateLimiter", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("redis down")))
    limiter = rate_mod._build_rate_limiter()
    assert getattr(limiter, "_redis_limiter", None) is None

    monkeypatch.setattr(rate_mod.config, "IS_PRODUCTION", False)
    limiter = rate_mod._build_rate_limiter()
    assert getattr(limiter, "_redis_limiter", None) is None

    monkeypatch.setattr("middleware.rate_limit.ip._valid_ip", lambda value: None if value in {"bad", "also-bad"} else value)
    req = _request(
        ip="203.0.113.10",
        headers=[(b"x-forwarded-for", b"bad"), (b"x-real-ip", b"also-bad")],
    )
    assert client_ip(req) == "203.0.113.10"


@pytest.mark.asyncio
async def test_request_size_limit_non_http_and_retry_httpstatus_exhaustion(monkeypatch):
    calls: list[str] = []

    async def app(scope, receive, send):
        calls.append(scope.get("type", ""))

    middleware = __import__("middleware.request_size_limit", fromlist=["RequestSizeLimitMiddleware"]).RequestSizeLimitMiddleware(app, max_bytes=5)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    await middleware({"type": "websocket", "headers": []}, receive, send)
    assert calls == ["websocket"]

    request = httpx.Request("GET", "https://example.com")
    response = httpx.Response(503, request=request)

    @resilience.with_retry(max_retries=0, backoff=0.0)
    async def always_fail_http_status() -> None:
        raise httpx.HTTPStatusError("fail", request=request, response=response)

    with pytest.raises(httpx.HTTPStatusError):
        await always_fail_http_status()


def test_verify_context_token_and_get_current_user(monkeypatch):
    key = "x" * 32
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_VERIFY_KEY", key)
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_SIGNING_KEY", key)
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_ALGORITHM", "HS256")
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_AUDIENCE", "notifier")
    monkeypatch.setattr(config, "NOTIFIER_CONTEXT_ISSUER", "watchdog-main")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "watchdog-main",
            "aud": "notifier",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=60)).timestamp()),
            "jti": "jti-1",
            "user_id": "u1",
            "username": "alice",
            "tenant_id": "tenant-a",
            "role": "not-a-real-role",
            "permissions": ["read:alerts"],
            "group_ids": ["g1", "g1"],
        },
        key,
        algorithm="HS256",
    )
    claims = dependencies._verify_context_token(token)
    assert claims.role == Role.USER

    with pytest.raises(HTTPException):
        dependencies._verify_context_token("bad-token")

    monkeypatch.setattr(config, "get_secret", lambda key: "expected" if key in {"NOTIFIER_EXPECTED_SERVICE_TOKEN", "GATEWAY_INTERNAL_SERVICE_TOKEN"} else None)
    monkeypatch.setattr(dependencies, "_verify_context_token", lambda _token: _user(group_ids=["g1", "g1", "", "g2"]))
    request = _request(headers=[(b"x-service-token", b"expected"), (b"authorization", b"Bearer ctx")])
    user = dependencies.get_current_user(request, None)
    assert user.group_ids == ["g1", "g2"]


def test_resilience_retry_and_timeout(monkeypatch):
    real_sleep = asyncio.sleep
    monkeypatch.setattr(resilience.random, "uniform", lambda _a, _b: 0.0)

    sleeps = []

    async def _sleep(duration):
        sleeps.append(duration)

    monkeypatch.setattr(resilience.asyncio, "sleep", _sleep)

    calls = {"n": 0}

    @resilience.with_retry(max_retries=2, backoff=0.01)
    async def flaky_http_500():
        calls["n"] += 1
        if calls["n"] < 2:
            req = httpx.Request("GET", "https://example.test")
            res = httpx.Response(500, request=req)
            raise httpx.HTTPStatusError("boom", request=req, response=res)
        return "ok"

    assert asyncio.run(flaky_http_500()) == "ok"
    assert sleeps

    @resilience.with_retry(max_retries=1, backoff=0.01)
    async def bad_request_fast_fail():
        req = httpx.Request("GET", "https://example.test")
        res = httpx.Response(400, request=req)
        raise httpx.HTTPStatusError("bad", request=req, response=res)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(bad_request_fast_fail())

    @resilience.with_retry(max_retries=1, backoff=0.01)
    async def request_error_then_fail():
        raise httpx.RequestError("down", request=httpx.Request("GET", "https://example.test"))

    with pytest.raises(httpx.RequestError):
        asyncio.run(request_error_then_fail())

    @resilience.with_retry(max_retries=-1, backoff=0.01)
    async def no_attempts():
        return "never"

    with pytest.raises(RuntimeError):
        asyncio.run(no_attempts())

    monkeypatch.setattr(resilience.asyncio, "sleep", real_sleep)

    @resilience.with_timeout(timeout=0.001)
    async def slow():
        await asyncio.sleep(0.01)
        return "slow"

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(slow())

    @resilience.with_timeout(timeout=0.1)
    async def fast():
        return "fast"

    assert asyncio.run(fast()) == "fast"
