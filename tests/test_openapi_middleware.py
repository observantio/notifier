from __future__ import annotations

from fastapi import FastAPI

from tests._env import ensure_test_env

ensure_test_env()

from middleware import openapi as openapi_middleware


def test_apply_inferred_responses_handles_non_dict_responses() -> None:
    operation: dict[str, object] = {"responses": []}
    openapi_middleware._apply_inferred_responses("/internal/v1/x/{id}", "POST", operation)  # type: ignore[arg-type]
    assert operation["responses"] == []


def test_apply_inferred_responses_internal_rules() -> None:
    operation: dict[str, object] = {"requestBody": {"content": {}}}
    openapi_middleware._apply_inferred_responses("/internal/v1/api/alertmanager/rules/{rule_id}", "POST", operation)  # type: ignore[arg-type]
    responses = operation["responses"]
    assert isinstance(responses, dict)
    assert responses["401"]["description"] == "Unauthorized"
    assert responses["403"]["description"] == "Forbidden"
    assert responses["400"]["description"] == "Bad Request"
    assert responses["404"]["description"] == "Not Found"
    assert responses["429"]["description"] == "Too Many Requests"


def test_apply_inferred_responses_non_internal_get_keeps_empty_responses() -> None:
    operation: dict[str, object] = {}
    openapi_middleware._apply_inferred_responses("/public/health", "GET", operation)  # type: ignore[arg-type]
    responses = operation["responses"]
    assert isinstance(responses, dict)
    assert responses == {}


def test_install_custom_openapi_uses_cache_and_normalizes_paths(monkeypatch) -> None:
    app = FastAPI()
    app.openapi_schema = {"cached": True}
    openapi_middleware.install_custom_openapi(app)
    assert app.openapi() == {"cached": True}

    app2 = FastAPI()
    openapi_middleware.install_custom_openapi(app2)
    fake_schema = {
        "paths": {
            "/internal/v1/api/alertmanager/rules/{rule_id}": {
                "post": {"requestBody": {"content": {}}},
                "trace": "skip",
            },
            "/internal/v1/health": "skip",
        }
    }
    monkeypatch.setattr(openapi_middleware, "get_openapi", lambda **kwargs: fake_schema)
    generated = app2.openapi()
    responses = generated["paths"]["/internal/v1/api/alertmanager/rules/{rule_id}"]["post"]["responses"]
    assert responses["401"]["description"] == "Unauthorized"
    assert responses["403"]["description"] == "Forbidden"
    assert responses["400"]["description"] == "Bad Request"
    assert responses["404"]["description"] == "Not Found"
    assert responses["429"]["description"] == "Too Many Requests"

    app3 = FastAPI()
    openapi_middleware.install_custom_openapi(app3)
    monkeypatch.setattr(openapi_middleware, "get_openapi", lambda **kwargs: {"paths": []})
    assert app3.openapi()["paths"] == []
