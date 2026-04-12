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


def test_helper_functions_cover_fallback_and_explicit_server_paths() -> None:
    assert openapi_middleware.status_description(999) == "HTTP 999"
    assert openapi_middleware.tag_description("custom-tag") == "Operations for custom tag."

    servers = openapi_middleware.openapi_servers(host="0.0.0.0", port=4323, tls_enabled=False)
    assert servers[0]["url"] == "http://127.0.0.1:4323"

    explicit_servers = openapi_middleware.openapi_servers(
        host="localhost",
        port=4323,
        explicit_url="https://example.internal/notifier/",
    )
    assert explicit_servers == [
        {"url": "https://example.internal/notifier", "description": "Configured runtime endpoint"}
    ]

    merged = openapi_middleware.merge_responses(
        {401: {"description": "Unauthorized"}},
        {"404": {"description": "Not Found"}},
    )
    assert merged[401]["description"] == "Unauthorized"
    assert merged["404"]["description"] == "Not Found"


def test_project_version_uses_pyproject_and_fallbacks(monkeypatch) -> None:
    monkeypatch.setattr(
        openapi_middleware.Path,
        "read_text",
        lambda self, encoding="utf-8": "[project]\nversion = '1.2.3'\n",
    )
    assert openapi_middleware._project_version() == "1.2.3"

    monkeypatch.setattr(
        openapi_middleware.Path,
        "read_text",
        lambda self, encoding="utf-8": "[project]\nversion = ''\n",
    )
    assert openapi_middleware._project_version() == openapi_middleware.DEFAULT_APP_VERSION

    def _raise_oserror(self, encoding="utf-8"):
        raise OSError("missing")

    monkeypatch.setattr(openapi_middleware.Path, "read_text", _raise_oserror)
    assert openapi_middleware._project_version() == openapi_middleware.DEFAULT_APP_VERSION


def test_install_custom_openapi_sets_info_version(monkeypatch) -> None:
    app = FastAPI()
    openapi_middleware.install_custom_openapi(app)

    monkeypatch.setattr(
        openapi_middleware,
        "get_openapi",
        lambda **kwargs: {"info": {}, "paths": {}},
    )
    monkeypatch.setattr(openapi_middleware, "_project_version", lambda: "9.9.9")

    generated = app.openapi()
    assert generated["info"]["version"] == "9.9.9"
