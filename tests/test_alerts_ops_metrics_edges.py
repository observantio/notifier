"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.alerts import Alert
from services.alerting import alerts_ops


class _Response:
    def __init__(self, payload, *, status_code=200, content=b"{}"):
        self._payload = payload
        self.status_code = status_code
        self.content = content
        self.request = httpx.Request("GET", "https://mimir")

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=self.request, response=httpx.Response(self.status_code, request=self.request))

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_metric_name_label_and_label_values_paths():
    class _MimirClient:
        def __init__(self):
            self.last_params = None

        async def get(self, _url, headers=None, params=None):
            self.last_params = params
            if "/label/__name__/values" in _url:
                return _Response({"status": "success", "data": ["up", "cpu_usage"]})
            if _url.endswith("/labels"):
                return _Response({"status": "success", "data": ["job", "instance"]})
            return _Response({"status": "success", "data": ["api", "db"]})

    client = _MimirClient()
    service = SimpleNamespace(_mimir_client=client)

    names = await alerts_ops.list_metric_names(service, "org-a")
    labels = await alerts_ops.list_label_names(service, "org-a")
    values = await alerts_ops.list_label_values(service, "org-a", "job", metric_name="up")

    assert names == ["up", "cpu_usage"]
    assert labels == ["job", "instance"]
    assert values == ["api", "db"]

    values = await alerts_ops.list_label_values(service, "org-a", "job", metric_name="   ")
    assert values == ["api", "db"]
    assert client.last_params is None


@pytest.mark.asyncio
async def test_metric_queries_and_http_status_handling():
    class _MimirClient:
        def __init__(self):
            self.mode = "ok"

        async def get(self, _url, headers=None, params=None):
            if self.mode == "bad-status":
                return _Response({"status": "error", "error": "boom", "errorType": "parse"})
            if self.mode == "http-500":
                return _Response({"error": "backend down", "errorType": "backend"}, status_code=500)
            if self.mode == "vector-empty":
                return _Response({"status": "success", "data": {"resultType": "vector", "result": []}}, content=b"x")
            if self.mode == "scalar-short":
                return _Response({"status": "success", "data": {"resultType": "scalar", "result": [123]}}, content=b"x")
            if self.mode == "scalar":
                return _Response({"status": "success", "data": {"resultType": "scalar", "result": [123, "7"]}}, content=b"x")
            if self.mode == "string":
                return _Response({"status": "success", "data": {"resultType": "string", "result": [124, "ok"]}}, content=b"x")
            return _Response(
                {
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {"metric": {"job": "api"}, "value": [123, "1"]},
                            {"metric": {"job": "db"}, "value": [124, "2"]},
                        ],
                    },
                },
                content=b"x",
            )

    client = _MimirClient()
    service = SimpleNamespace(_mimir_client=client)

    ok = await alerts_ops.evaluate_promql(service, "org-a", "up", sample_limit=1)
    assert ok["valid"] is True
    assert ok["sampleCount"] == 2
    assert len(ok["samples"]) == 1

    client.mode = "scalar"
    scalar = await alerts_ops.evaluate_promql(service, "org-a", "scalar", sample_limit=5)
    assert scalar["currentValue"] == "7"

    client.mode = "string"
    string_val = await alerts_ops.evaluate_promql(service, "org-a", "str", sample_limit=5)
    assert string_val["currentValue"] == "ok"

    client.mode = "bad-status"
    bad_status = await alerts_ops.evaluate_promql(service, "org-a", "bad", sample_limit=5)
    assert bad_status["valid"] is False
    assert bad_status["errorType"] == "parse"

    client.mode = "vector-empty"
    vector_empty = await alerts_ops.evaluate_promql(service, "org-a", "empty", sample_limit=5)
    assert vector_empty["samples"] == []
    assert vector_empty["currentValue"] is None

    client.mode = "scalar-short"
    scalar_short = await alerts_ops.evaluate_promql(service, "org-a", "short", sample_limit=5)
    assert scalar_short["samples"] == []
    assert scalar_short["currentValue"] is None

    client.mode = "http-500"
    bad_http = await alerts_ops.evaluate_promql(service, "org-a", "bad", sample_limit=5)
    assert bad_http["valid"] is False
    assert bad_http["errorType"] == "backend"


@pytest.mark.asyncio
async def test_metrics_non_success_raise_http_status_error():
    class _MimirClient:
        async def get(self, _url, headers=None, params=None):
            return _Response({"status": "error"})

    service = SimpleNamespace(_mimir_client=_MimirClient())

    with pytest.raises(httpx.HTTPStatusError):
        await alerts_ops.list_metric_names(service, "org-a")
    with pytest.raises(httpx.HTTPStatusError):
        await alerts_ops.list_label_names(service, "org-a")
    with pytest.raises(httpx.HTTPStatusError):
        await alerts_ops.list_label_values(service, "org-a", "job")


@pytest.mark.asyncio
async def test_alert_and_group_get_post_delete_paths():
    class _Client:
        def __init__(self):
            self.mode = "ok"

        async def get(self, url, params=None):
            if self.mode == "error":
                raise httpx.RequestError("down", request=httpx.Request("GET", url))
            if "/alerts/groups" in url:
                return _Response(
                    [
                        {
                            "labels": {"alertname": "CPUHigh"},
                            "receiver": "default",
                            "alerts": [
                                {
                                    "labels": {"alertname": "CPUHigh", "severity": "critical"},
                                    "annotations": {},
                                    "startsAt": "2026-01-01T00:00:00Z",
                                    "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
                                }
                            ],
                        }
                    ]
                )
            return _Response(
                [
                    {
                        "labels": {"alertname": "CPUHigh", "severity": "critical"},
                        "annotations": {},
                        "startsAt": "2026-01-01T00:00:00Z",
                        "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
                    }
                ]
            )

        async def post(self, url, json=None):
            if self.mode == "error":
                raise httpx.RequestError("down", request=httpx.Request("POST", url))
            return _Response({"ok": True})

    client = _Client()
    logs = []
    service = SimpleNamespace(_client=client, alertmanager_url="https://alertmanager", logger=SimpleNamespace(error=lambda *_args: logs.append("error"), warning=lambda *_args: logs.append("warning")))

    alerts = await alerts_ops.get_alerts(service, filter_labels={"alertname": "CPUHigh"}, active=True, silenced=False, inhibited=False)
    assert alerts and alerts[0].labels["alertname"] == "CPUHigh"

    groups = await alerts_ops.get_alert_groups(service, filter_labels={"alertname": "CPUHigh"})
    assert groups and groups[0].receiver == "default"

    ok_post = await alerts_ops.post_alerts(service, [Alert.model_validate({"labels": {"alertname": "CPUHigh", "severity": "critical"}, "annotations": {}, "startsAt": "2026-01-01T00:00:00Z", "status": {"state": "active", "silencedBy": [], "inhibitedBy": []}})])
    assert ok_post is True

    async def _create_silence(_silence):
        return "s1"

    service.create_silence = _create_silence
    assert await alerts_ops.delete_alerts(service, {"alertname": "CPUHigh"}) is True

    client.mode = "error"
    assert await alerts_ops.get_alerts(service, {"a": "b"}) == []
    assert await alerts_ops.get_alert_groups(service, {"a": "b"}) == []
    assert await alerts_ops.post_alerts(service, []) is False

    assert await alerts_ops.delete_alerts(service, None) is False

    async def _no_silence(_silence):
        return None

    service.create_silence = _no_silence
    assert await alerts_ops.delete_alerts(service, {"alertname": "CPUHigh"}) is False
