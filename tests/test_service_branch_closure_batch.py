"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.alerts import Alert, AlertState, AlertStatus
from models.alerting.channels import ChannelType, NotificationChannel
from models.alerting.silences import Matcher, Silence, SilenceCreate
from services import notification_service as notif_mod
from services.alerting import integration_security_service as sec_mod
from services.alerting import silences_ops as sil_mod
from services.jira_service import JiraError, JiraService
from services.notification_service import NotificationService
from services.storage import revocation as rev_mod


def _user(**overrides) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.USER,
        "permissions": ["read:alerts"],
        "group_ids": ["g1"],
        "is_superuser": False,
    }
    payload.update(overrides)
    return TokenData(**cast(dict[str, Any], payload))


def _alert() -> Alert:
    return Alert(
        labels={"alertname": "CPUHigh", "severity": "critical"},
        annotations={"summary": "CPU high"},
        startsAt="2026-01-01T00:00:00Z",
        endsAt=None,
        generatorURL=None,
        status=AlertStatus(state=AlertState.ACTIVE),
        fingerprint="fp-1",
    )


class _DBQuery:
    def __init__(self, rows):
        self._rows = rows

    def options(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def filter_by(self, **_kwargs):
        return self

    def all(self):
        if self._rows is None:
            return []
        if isinstance(self._rows, list):
            return self._rows
        return [self._rows]

    def first(self):
        if isinstance(self._rows, list):
            return self._rows[0] if self._rows else None
        return self._rows


class _DBCtx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


class _SeqDB:
    def __init__(self, *rows):
        self._rows = list(rows)
        self.flushed = 0

    def query(self, *_args, **_kwargs):
        rows = self._rows.pop(0) if self._rows else None
        return _DBQuery(rows)

    def execute(self, *_args, **_kwargs):
        return None

    def flush(self):
        self.flushed += 1


class _AMResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://am.local")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("bad", request=request, response=response)


class _AMClient:
    def __init__(self, *, get_payload=None, post_payload=None, delete_code=200):
        self.get_payload = get_payload
        self.post_payload = post_payload
        self.delete_code = delete_code

    async def get(self, _url, params=None):
        return _AMResponse(self.get_payload)

    async def post(self, _url, json=None):
        return _AMResponse(self.post_payload)

    async def delete(self, _url):
        return _AMResponse({}, status_code=self.delete_code)


class _JiraResponse:
    def __init__(self, *, status_code=200, payload=None, text="", content=b"{}"):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.content = content

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            req = httpx.Request("GET", "https://jira.example.com")
            res = httpx.Response(self.status_code, request=req, text=self.text)
            raise httpx.HTTPStatusError("bad", request=req, response=res)


@pytest.mark.asyncio
async def test_jira_service_uncovered_paths(monkeypatch):
    monkeypatch.setattr("services.jira_service.is_safe_http_url", lambda url: bool(url and url.startswith("https://")))

    svc = JiraService(timeout=1)
    svc.base_url = "https://jira.example.com"
    svc.email = "user@example.com"
    svc.api_token = "api-token"
    svc.bearer = "bear"

    svc.bearer = None
    with pytest.raises(JiraError):
        svc._auth_headers({"authMode": "bearer"})

    svc.bearer = "bear"
    assert svc._auth_headers({})["Authorization"].startswith("Bearer ")
    svc.bearer = None
    assert svc._auth_headers({})["Authorization"].startswith("Basic ")
    svc.email = None
    svc.api_token = None
    with pytest.raises(JiraError, match="No Jira credentials configured"):
        svc._auth_headers({})

    monkeypatch.setattr("services.jira_service.is_safe_http_url", lambda _url: False)
    with pytest.raises(JiraError, match="invalid"):
        svc._build_url("/rest/api/2/project")

    monkeypatch.setattr("services.jira_service.is_safe_http_url", lambda _url: True)
    creds = {"base_url": "https://jira.example.com", "authMode": "bearer", "bearer": "tok"}

    class _StatusClient:
        async def get(self, _url, headers=None, params=None):
            return _JiraResponse(status_code=503, text="")

        async def post(self, _url, json=None, headers=None):
            return _JiraResponse(status_code=400, text="bad payload")

    class _RequestErrorClient:
        async def get(self, url, headers=None, params=None):
            raise httpx.RequestError("boom", request=httpx.Request("GET", url))

        async def post(self, url, json=None, headers=None):
            raise httpx.RequestError("boom", request=httpx.Request("POST", url))

    class _JiraErrorClient:
        async def get(self, _url, headers=None, params=None):
            raise JiraError("already wrapped")

        async def post(self, _url, json=None, headers=None):
            raise JiraError("already wrapped")

    class _UnexpectedClient:
        async def get(self, _url, headers=None, params=None):
            raise ValueError("unexpected")

        async def post(self, _url, json=None, headers=None):
            raise ValueError("unexpected")

    svc._client = _StatusClient()
    with pytest.raises(JiraError, match="503"):
        await svc._request("GET", "/rest/api/2/project", creds)

    class _StatusClientWithDetail:
        async def get(self, _url, headers=None, params=None):
            return _JiraResponse(status_code=400, text="jira says no")

        async def post(self, _url, json=None, headers=None):
            return _JiraResponse(status_code=400, text="jira says no")

    svc._client = _StatusClientWithDetail()
    with pytest.raises(JiraError, match="jira says no"):
        await svc._request("GET", "/rest/api/2/project", creds)

    svc._client = _RequestErrorClient()
    with pytest.raises(JiraError, match="Unable to connect"):
        await svc._request("GET", "/rest/api/2/project", creds)

    svc._client = _JiraErrorClient()
    with pytest.raises(JiraError, match="already wrapped"):
        await svc._request("GET", "/rest/api/2/project", creds)

    svc._client = _UnexpectedClient()
    with pytest.raises(JiraError, match="Failed to contact Jira API"):
        await svc._request("GET", "/rest/api/2/project", creds)

    captured: dict[str, object] = {}

    async def fake_post(path, payload, credentials=None):
        captured["payload"] = payload
        return {"key": "OPS-1"}

    svc._post = fake_post
    svc._resolve_base_url = lambda credentials=None: "https://jira.example.com"
    created = await svc.create_issue("OPS", "Summary", priority="High", credentials=creds)
    assert created["key"] == "OPS-1"
    assert captured["payload"]["fields"]["priority"]["name"] == "High"

    async def no_transitions(issue_key, credentials=None):
        return []

    svc.list_transitions = no_transitions
    assert (
        await svc._transition_issue_by_target(
            "OPS-1",
            credentials=creds,
            target_names={"done"},
            transition_names={"done"},
            status_category_key="done",
        )
        is False
    )

    async def no_id_transition(issue_key, credentials=None):
        return [{"name": "Done", "to": {"name": "Done"}}]

    svc.list_transitions = no_id_transition
    assert (
        await svc._transition_issue_by_target(
            "OPS-1",
            credentials=creds,
            target_names={"done"},
            transition_names={"done"},
            status_category_key="done",
        )
        is False
    )


def test_integration_security_uncovered_paths(monkeypatch):
    monkeypatch.setattr(sec_mod, "tenant_id_from_scope_header", lambda _scope: "base")
    assert sec_mod.infer_tenant_id_from_alerts(None, None) == "base"

    db = _SeqDB([("tenant-a",), ("tenant-b",)])
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: _DBCtx(db))
    assert sec_mod.infer_tenant_id_from_alerts(None, [{"labels": "bad"}, {"labels": {"alertname": "CPU"}}]) == "base"

    monkeypatch.setattr(sec_mod.config, "data_encryption_key", "x")

    class _BadFernet:
        def __init__(self, _key):
            raise TypeError("bad key")

    monkeypatch.setattr(sec_mod, "Fernet", _BadFernet)
    with pytest.raises(HTTPException, match="Failed to encrypt Jira secret"):
        sec_mod.encrypt_tenant_secret("secret")

    class _DecryptFailFernet:
        def __init__(self, _key):
            return None

        def decrypt(self, _payload):
            raise TypeError("bad payload")

    monkeypatch.setattr(sec_mod, "Fernet", _DecryptFailFernet)
    assert sec_mod.decrypt_tenant_secret("enc:abc") is None

    tenant = SimpleNamespace(settings={"jira": "legacy"})
    db = _SeqDB(tenant)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: _DBCtx(db))
    loaded = sec_mod.load_tenant_jira_config("tenant-a")
    assert loaded["base_url"] is None

    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: False)
    with pytest.raises(HTTPException, match="missing or invalid"):
        sec_mod.save_tenant_jira_config(
            "tenant-a",
            enabled=True,
            base_url="http://bad",
            email="user@example.com",
            api_token="token",
            bearer=None,
        )

    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: True)
    with pytest.raises(HTTPException, match="credentials are incomplete"):
        sec_mod.save_tenant_jira_config(
            "tenant-a",
            enabled=True,
            base_url="https://jira.example.com",
            email="user@example.com",
            api_token=None,
            bearer=None,
        )

    monkeypatch.setattr(
        sec_mod,
        "load_tenant_jira_config",
        lambda _tenant_id: {
            "enabled": True,
            "base_url": "https://jira.example.com",
            "email": "user@example.com",
            "api_token": None,
            "bearer": None,
        },
    )
    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: True)
    assert sec_mod.get_effective_jira_credentials("tenant-a") == {}

    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: False)
    with pytest.raises(HTTPException):
        sec_mod.validate_jira_credentials(
            base_url="https://jira.example.com",
            auth_mode="api_token",
            email="user@example.com",
            api_token="token",
            bearer_token=None,
        )

    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: True)
    with pytest.raises(HTTPException, match="apiToken is required"):
        sec_mod.validate_jira_credentials(
            base_url="https://jira.example.com",
            auth_mode="api_token",
            email="user@example.com",
            api_token="",
            bearer_token=None,
        )

    sec_mod.validate_jira_credentials(
        base_url="https://jira.example.com",
        auth_mode="bearer",
        email=None,
        api_token=None,
        bearer_token="token",
    )

    with pytest.raises(HTTPException, match="requires a bearerToken"):
        sec_mod.validate_jira_credentials(
            base_url="https://jira.example.com",
            auth_mode="sso",
            email=None,
            api_token=None,
            bearer_token=None,
        )

    db = _SeqDB(SimpleNamespace(settings={"jira_integrations": "bad"}))
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: _DBCtx(db))
    assert sec_mod.load_tenant_jira_integrations("tenant-a") == []

    db = _SeqDB(None)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: _DBCtx(db))
    with pytest.raises(HTTPException, match="Tenant not found"):
        sec_mod.save_tenant_jira_integrations("tenant-a", [{"id": "x"}])

    assert sec_mod.validate_shared_group_ids_for_user("tenant-a", ["", "   "], _user()) == []
    assert sec_mod.jira_integration_has_access({"createdBy": "other", "visibility": "private"}, _user()) is False

    def _raise_http_exception(_item):
        raise HTTPException(status_code=400, detail="bad")

    monkeypatch.setattr(sec_mod, "jira_integration_credentials", _raise_http_exception)
    assert sec_mod.integration_is_usable({"enabled": True}) is False

    monkeypatch.setattr(
        sec_mod,
        "jira_integration_credentials",
        lambda _item: {
            "auth_mode": "api_token",
            "base_url": "https://jira",
            "email": "user",
            "api_token": "tok",
            "bearer": None,
        },
    )
    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: False)
    assert sec_mod.integration_is_usable({"enabled": True}) is False

    monkeypatch.setattr(
        sec_mod,
        "jira_integration_credentials",
        lambda _item: {
            "auth_mode": "bearer",
            "base_url": "https://jira",
            "email": None,
            "api_token": None,
            "bearer": "tok",
        },
    )
    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda _url: True)
    assert sec_mod.integration_is_usable({"enabled": True}) is True


def _silence(**overrides) -> Silence:
    payload = {
        "id": "s1",
        "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
        "startsAt": "2026-01-01T00:00:00Z",
        "endsAt": "2026-01-01T01:00:00Z",
        "createdBy": "u1",
        "comment": "group",
        "status": {"state": "active"},
    }
    payload.update(overrides)
    return Silence.model_validate(payload)


@pytest.mark.asyncio
async def test_silences_ops_uncovered_paths(monkeypatch):
    assert sil_mod.silence_owned_by(_silence(createdBy=""), _user()) is False

    def decode_comment(comment: str):
        if comment == "private":
            return {"comment": "private", "visibility": "private", "shared_group_ids": ["g1"]}
        if comment == "owner-missing":
            return {"comment": "owner-missing", "visibility": "group", "shared_group_ids": ["g1"]}
        return {"comment": comment, "visibility": "group", "shared_group_ids": ["g2"]}

    service = SimpleNamespace(
        alertmanager_http_client=_AMClient(
            get_payload=[_silence(id="s-get").model_dump(by_alias=True)],
            post_payload={"silenceID": "x"},
            delete_code=200,
        ),
        alertmanager_url="https://am.local",
        decode_silence_comment=decode_comment,
        encode_silence_comment=lambda comment, visibility, shared_group_ids: (
            f"{comment}|{visibility}|{','.join(shared_group_ids)}"
        ),
    )

    original_get_silences = sil_mod.get_silences

    async def fake_get_silences(_service, filter_labels=None):
        return [
            _silence(id="s-private", comment="private", createdBy="u1"),
            _silence(id="s-no-owner", comment="owner-missing", createdBy=""),
            _silence(id="s-no-group", comment="group", createdBy="u1"),
        ]

    async def fake_update(_service, silence_id, payload):
        return "new-id"

    monkeypatch.setattr(sil_mod, "get_silences", fake_get_silences)
    monkeypatch.setattr(sil_mod, "update_silence", fake_update)
    assert await sil_mod.prune_removed_member_group_silences(service, group_id="g1", removed_user_ids=["u1"]) == 0
    monkeypatch.setattr(sil_mod, "get_silences", original_get_silences)

    class _PurgedDB:
        def __init__(self, rows):
            self.rows = rows

        def query(self, *_args, **_kwargs):
            return _DBQuery(self.rows)

    monkeypatch.setattr(sil_mod, "get_db_session", lambda: _DBCtx(_PurgedDB([])))
    raw = await sil_mod.get_silences(service)
    assert len(raw) == 1

    monkeypatch.setattr(sil_mod, "get_db_session", lambda: _DBCtx(_PurgedDB([SimpleNamespace(id="not-present")])))
    raw = await sil_mod.get_silences(service)
    assert len(raw) == 1

    service_err = SimpleNamespace(
        alertmanager_http_client=_AMClient(
            get_payload=[],
            post_payload={},
            delete_code=200,
        ),
        alertmanager_url="https://am.local",
    )

    async def failing_post(_url, json=None):
        return _AMResponse({}, status_code=500)

    service_err.alertmanager_http_client.post = failing_post
    created = await sil_mod.create_silence(
        service_err,
        SilenceCreate(
            matchers=[Matcher(name="severity", value="critical")],
            startsAt="2026-01-01T00:00:00Z",
            endsAt="2026-01-01T01:00:00Z",
            createdBy="u1",
            comment="x",
        ),
    )
    assert created is None

    async def fast_sleep(_seconds):
        return None

    monkeypatch.setattr(sil_mod.asyncio, "sleep", fast_sleep)
    monkeypatch.setattr(sil_mod, "get_silence", lambda _service, _silence_id: _async_value(None))
    assert await sil_mod.delete_silence(service, "s1") is True

    failing_delete_service = SimpleNamespace(
        alertmanager_http_client=_AMClient(get_payload=[], post_payload={}, delete_code=500),
        alertmanager_url="https://am.local",
    )
    assert await sil_mod.delete_silence(failing_delete_service, "s1") is False


def test_notification_service_uncovered_paths(monkeypatch):
    svc = NotificationService()

    def raise_attr_error(_value):
        raise AttributeError("missing")

    monkeypatch.setattr(notif_mod.notification_validators, "coerce_bool", raise_attr_error)
    assert svc._as_bool(True) is True
    assert svc._as_bool(1) is True
    assert svc._as_bool(object()) is False

    alert = _alert()

    channel = NotificationChannel(
        name="edge-recipient",
        type=ChannelType.EMAIL,
        enabled=True,
        config={"to": " , ;   ", "smtp_host": "smtp.example.com"},
    )
    assert asyncio.run(svc.send_notification(channel, alert, "firing")) is False

    async def sendgrid_false(*_args, **_kwargs):
        return False

    channel = NotificationChannel(
        name="sendgrid-false",
        type=ChannelType.EMAIL,
        enabled=True,
        config={"to": "ops@example.com", "email_provider": "sendgrid", "sendgrid_api_key": "sg-key"},
    )
    monkeypatch.setattr(notif_mod.notification_email, "send_via_sendgrid", sendgrid_false)
    assert asyncio.run(svc.send_notification(channel, alert, "firing")) is False

    channel = NotificationChannel(
        name="resend-missing",
        type=ChannelType.EMAIL,
        enabled=True,
        config={"to": "ops@example.com", "email_provider": "resend"},
    )
    assert asyncio.run(svc.send_notification(channel, alert, "firing")) is False

    channel = NotificationChannel(
        name="smtp-api-key-missing",
        type=ChannelType.EMAIL,
        enabled=True,
        config={
            "to": "ops@example.com",
            "smtp_host": "smtp.example.com",
            "smtp_auth_type": "api_key",
        },
    )
    assert asyncio.run(svc.send_notification(channel, alert, "firing")) is False

    captured = {}

    def build_message(subject, body, smtp_from, recipients):
        return SimpleNamespace(subject=subject, body=body, smtp_from=smtp_from, recipients=recipients)

    async def smtp_capture(message, hostname, port, username, password, start_tls, use_tls):
        captured["username"] = username
        captured["password"] = password
        return False

    channel = NotificationChannel(
        name="smtp-api-key-fallback",
        type=ChannelType.EMAIL,
        enabled=True,
        config={
            "to": "ops@example.com",
            "smtp_host": "smtp.example.com",
            "smtp_username": "mailer",
            "smtp_auth_type": "password",
            "smtp_api_key": "fallback-token",
        },
    )

    monkeypatch.setattr(notif_mod.notification_email, "build_smtp_message", build_message)
    monkeypatch.setattr(notif_mod.notification_email, "send_via_smtp", smtp_capture)
    assert asyncio.run(svc.send_notification(channel, alert, "firing")) is False
    assert captured["username"] == "mailer"
    assert captured["password"] == "fallback-token"

    async def fake_teams(client, cfg, alert_obj, action):
        return True

    async def fake_webhook(client, cfg, alert_obj, action):
        return True

    async def fake_pagerduty(client, cfg, alert_obj, action):
        return True

    monkeypatch.setattr(notif_mod.notification_senders, "send_teams", fake_teams)
    monkeypatch.setattr(notif_mod.notification_senders, "send_webhook", fake_webhook)
    monkeypatch.setattr(notif_mod.notification_senders, "send_pagerduty", fake_pagerduty)

    noop_channel = NotificationChannel(name="teams", type=ChannelType.TEAMS, enabled=True, config={})
    assert asyncio.run(svc._send_teams(noop_channel, alert, "firing")) is True
    noop_channel = NotificationChannel(name="webhook", type=ChannelType.WEBHOOK, enabled=True, config={})
    assert asyncio.run(svc._send_webhook(noop_channel, alert, "firing")) is True
    noop_channel = NotificationChannel(name="pagerduty", type=ChannelType.PAGERDUTY, enabled=True, config={})
    assert asyncio.run(svc._send_pagerduty(noop_channel, alert, "firing")) is True


def test_revocation_uncovered_paths_with_fake_db():
    assert rev_mod._normalize_ids(["", " a ", "a", "b"]) == ["a", "b"]

    empty_counts = rev_mod.prune_removed_member_group_shares(
        object(),
        tenant_id="tenant-a",
        group_id="",
        removed_user_ids=["u1"],
        removed_usernames=None,
    )
    assert empty_counts == {"rules": 0, "channels": 0, "incidents": 0, "jira_integrations": 0}

    class _FakeQuery:
        def __init__(self, rows):
            self.rows = rows

        def options(self, *_args, **_kwargs):
            return self

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return self.rows

        def first(self):
            return self.rows

    class _FakeDB:
        def __init__(self):
            self.rule_rows = [
                SimpleNamespace(created_by="other", shared_groups=[SimpleNamespace(id="g1")], visibility="group"),
                SimpleNamespace(created_by="", shared_groups=[SimpleNamespace(id="g1")], visibility="group"),
                SimpleNamespace(created_by="u1", shared_groups=[SimpleNamespace(id="g2")], visibility="group"),
            ]
            self.channel_rows = [
                SimpleNamespace(created_by="other", shared_groups=[SimpleNamespace(id="g1")], visibility="group"),
                SimpleNamespace(created_by="u1", shared_groups=[SimpleNamespace(id="g2")], visibility="group"),
            ]
            self.incident_rows = [
                SimpleNamespace(
                    annotations={
                        rev_mod.INCIDENT_META_KEY: json.dumps(
                            {"created_by": "other", "visibility": "group", "shared_group_ids": ["g1"]}
                        )
                    }
                ),
                SimpleNamespace(
                    annotations={
                        rev_mod.INCIDENT_META_KEY: json.dumps(
                            {"created_by": "u1", "visibility": "private", "shared_group_ids": ["g1"]}
                        )
                    }
                ),
                SimpleNamespace(
                    annotations={
                        rev_mod.INCIDENT_META_KEY: json.dumps(
                            {"created_by": "u1", "visibility": "group", "shared_group_ids": ["g2"]}
                        )
                    }
                ),
            ]
            self.tenant = SimpleNamespace(
                settings={
                    "jira_integrations": [
                        "bad-item",
                        {"createdBy": "other", "visibility": "group", "sharedGroupIds": ["g1"]},
                        {"createdBy": "u1", "visibility": "group", "sharedGroupIds": ["g2"]},
                    ]
                }
            )

        def query(self, model):
            if model is rev_mod.AlertRule:
                return _FakeQuery(self.rule_rows)
            if model is rev_mod.NotificationChannel:
                return _FakeQuery(self.channel_rows)
            if model is rev_mod.AlertIncident:
                return _FakeQuery(self.incident_rows)
            if model is rev_mod.Tenant:
                return _FakeQuery(self.tenant)
            raise AssertionError(f"Unexpected model: {model}")

    counts = rev_mod.prune_removed_member_group_shares(
        _FakeDB(),
        tenant_id="tenant-a",
        group_id="g1",
        removed_user_ids=["u1"],
        removed_usernames=[],
    )
    assert counts == {"rules": 0, "channels": 0, "incidents": 0, "jira_integrations": 0}


def _async_value(value):
    async def _inner():
        return value

    return _inner()


def test_notification_senders_unexpected_http_error_branch(monkeypatch):
    senders = notif_mod.notification_senders

    monkeypatch.setattr(senders, "is_safe_http_url", lambda _url: True)

    async def raise_generic_http_error(*_args, **_kwargs):
        raise httpx.HTTPError("unexpected")

    monkeypatch.setattr(senders.transport, "post_with_retry", raise_generic_http_error)

    result = asyncio.run(
        senders._send_json(
            client=object(),
            url="https://hooks.example.test/notify",
            payload={"ok": True},
        )
    )
    assert result is False
