"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import importlib
import sys
import time
import types

import pytest

from tests._env import ensure_test_env

ensure_test_env()


def _import_vault_module_with_fake_hvac(
    monkeypatch: pytest.MonkeyPatch,
    *,
    non_exception_bindings: bool = False,
):
    original_import_module = importlib.import_module
    created_clients: list[object] = []

    class FakeForbidden(Exception):
        pass

    class FakeInvalidPath(Exception):
        pass

    class FakeVaultError(Exception):
        pass

    class FakeKV:
        def __init__(self, client):
            self._client = client
            self.v2 = types.SimpleNamespace(read_secret_version=self.read_secret_version)

        def read_secret_version(self, path, mount_point, raise_on_deleted_version=False):
            self._client.last_v2_call = {
                "path": path,
                "mount_point": mount_point,
                "raise_on_deleted_version": raise_on_deleted_version,
            }
            if self._client.raise_v2 is not None:
                raise self._client.raise_v2
            return self._client.v2_response

        def read_secret(self, path):
            self._client.last_v1_path = path
            if self._client.raise_v1 is not None:
                raise self._client.raise_v1
            return self._client.v1_response

    class FakeClient:
        auth_checks_default: list[bool] = [True]

        def __init__(self, url, timeout, verify):
            self.url = url
            self.timeout = timeout
            self.verify = verify
            self.token = None
            self.auth_checks = list(type(self).auth_checks_default)
            self.auth = types.SimpleNamespace(approle=types.SimpleNamespace(login=self._login))
            self.secrets = types.SimpleNamespace(kv=FakeKV(self))
            self.raise_v2 = None
            self.raise_v1 = None
            self.v2_response = {"data": {"data": {"value": "ok"}}}
            self.v1_response = {"data": {"value": "ok"}}
            self.last_login = None
            self.last_v2_call = None
            self.last_v1_path = None
            created_clients.append(self)

        def _login(self, role_id, secret_id):
            self.last_login = {"role_id": role_id, "secret_id": secret_id}
            self.token = "approle-token"
            return {"auth": {"client_token": "approle-token"}}

        def is_authenticated(self):
            if self.auth_checks:
                return self.auth_checks.pop(0)
            return True

    fake_hvac = types.SimpleNamespace(Client=FakeClient)
    if non_exception_bindings:
        fake_hvac_exceptions = types.SimpleNamespace(Forbidden="nope", InvalidPath=123, VaultError=None)
    else:
        fake_hvac_exceptions = types.SimpleNamespace(
            Forbidden=FakeForbidden,
            InvalidPath=FakeInvalidPath,
            VaultError=FakeVaultError,
        )

    def fake_import_module(name, package=None):
        if name == "hvac":
            return fake_hvac
        if name == "hvac.exceptions":
            return fake_hvac_exceptions
        return original_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    sys.modules.pop("services.secrets.vault_client", None)
    module = importlib.import_module("services.secrets.vault_client")
    return module, FakeClient, created_clients


def test_vault_module_imports_hvac_exceptions_and_fallback_types(monkeypatch):
    module, _, _ = _import_vault_module_with_fake_hvac(monkeypatch)
    assert module.hvac is not None
    assert issubclass(module.Forbidden, Exception)
    assert issubclass(module.InvalidPath, Exception)
    assert issubclass(module.VaultError, Exception)

    module, _, _ = _import_vault_module_with_fake_hvac(monkeypatch, non_exception_bindings=True)
    assert module.Forbidden is module._VaultForbiddenFallback
    assert module.InvalidPath is module._VaultInvalidPathFallback
    assert module.VaultError is module._VaultErrorFallback


def test_vault_module_importerror_path_sets_fallbacks(monkeypatch):
    original_import_module = importlib.import_module

    def fake_import_module(name, package=None):
        if name in {"hvac", "hvac.exceptions"}:
            raise ImportError("missing")
        return original_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    sys.modules.pop("services.secrets.vault_client", None)
    module = importlib.import_module("services.secrets.vault_client")
    assert module.hvac is None
    assert module.Forbidden is module._VaultForbiddenFallback
    assert module.InvalidPath is module._VaultInvalidPathFallback
    assert module.VaultError is module._VaultErrorFallback


def test_vault_provider_init_validation_and_auth_modes(monkeypatch):
    module, FakeClient, _ = _import_vault_module_with_fake_hvac(monkeypatch)

    module.hvac = None
    with pytest.raises(module.VaultClientError, match="hvac library is required"):
        module.VaultSecretProvider(address="http://vault:8200", token="tok")

    module, FakeClient, clients = _import_vault_module_with_fake_hvac(monkeypatch)
    with pytest.raises(module.VaultClientError, match="VAULT_ADDR is required"):
        module.VaultSecretProvider(address="", token="tok")

    with pytest.raises(module.VaultClientError, match="Unsupported kv_version"):
        module.VaultSecretProvider(address="http://vault:8200", token="tok", kv_version=3)

    with pytest.raises(module.VaultClientError, match="Vault auth not configured"):
        module.VaultSecretProvider(address="http://vault:8200")

    provider = module.VaultSecretProvider(address="http://vault:8200", token="token-1", cacert="/tmp/ca.pem")
    assert provider._client.token == "token-1"
    assert provider._client.verify == "/tmp/ca.pem"

    approle_provider = module.VaultSecretProvider(
        address="http://vault:8200",
        role_id="role-1",
        secret_id_fn=lambda: "secret-1",
    )
    assert approle_provider._client.last_login == {"role_id": "role-1", "secret_id": "secret-1"}
    assert approle_provider._client.token == "approle-token"

    FakeClient.auth_checks_default = [False]
    with pytest.raises(module.VaultClientError, match="Vault authentication failed"):
        module.VaultSecretProvider(address="http://vault:8200", token="tok")

    assert clients


def test_vault_provider_auth_refresh_and_cache_edge_paths(monkeypatch):
    module, _, _ = _import_vault_module_with_fake_hvac(monkeypatch)
    provider = module.VaultSecretProvider(address="http://vault:8200", token="token-1", cache_ttl=0.01)

    provider._cache["bad"] = "broken-entry"
    assert provider._from_cache("bad") is module.SENTINEL
    assert "bad" not in provider._cache

    provider._cache["exp"] = (time.monotonic() - 1, "old")
    assert provider._from_cache("exp") is module.SENTINEL
    assert "exp" not in provider._cache

    provider._to_cache("obj", object())
    assert provider.get("obj") is None

    provider._role_id = None
    provider._secret_id_fn = None
    provider._client.auth_checks = [False]
    with pytest.raises(module.VaultClientError, match="token expired"):
        provider._ensure_authenticated()

    provider._secret_id_fn = lambda: "new-secret"
    provider._role_id = "role-a"
    provider._client.auth_checks = [False]
    provider._ensure_authenticated()
    assert provider._client.last_login == {"role_id": "role-a", "secret_id": "new-secret"}


def test_vault_provider_get_kv2_paths_and_errors(monkeypatch):
    module, _, _ = _import_vault_module_with_fake_hvac(monkeypatch)
    provider = module.VaultSecretProvider(address="http://vault:8200", token="token-1")

    provider._client.v2_response = {"data": {"data": {"value": 42}}}
    assert provider.get("db_password") == "42"
    assert provider._client.last_v2_call["mount_point"] == "secret"

    provider._client.v2_response = {"data": {"data": {"db_password": 7}}}
    assert provider.get("db_password") == "42"
    provider._cache.pop("db_password", None)
    assert provider.get("db_password") == "7"

    provider._cache.pop("db_password", None)
    provider._client.v2_response = {"data": {"data": {"only": "value"}}}
    assert provider.get("db_password") == "value"

    provider._cache.pop("db_password", None)
    provider._client.v2_response = {"data": {"data": {"a": {}, "b": []}}}
    assert provider.get("db_password") is None

    provider._cache.pop("db_password", None)
    provider._client.v2_response = {"data": {"data": {}}}
    assert provider.get("db_password") is None

    provider._cache.pop("missing", None)
    provider._client.raise_v2 = module.InvalidPath("missing")
    assert provider.get("missing") is None

    provider._cache.pop("missing", None)
    provider._client.raise_v2 = module.Forbidden("forbidden")
    with pytest.raises(module.VaultClientError, match="Vault error fetching 'missing'"):
        provider.get("missing")

    provider._client.raise_v2 = module.VaultError("boom")
    with pytest.raises(module.VaultClientError, match="Vault error fetching 'missing'"):
        provider.get("missing")


def test_vault_provider_get_kv1_and_get_many(monkeypatch):
    module, _, _ = _import_vault_module_with_fake_hvac(monkeypatch)
    provider = module.VaultSecretProvider(
        address="http://vault:8200",
        token="token-1",
        prefix="kv",
        kv_version=1,
    )

    provider._client.v1_response = {"data": {"value": "v1-secret"}}
    assert provider.get("alpha") == "v1-secret"
    assert provider._client.last_v1_path == "kv/alpha"

    provider._client.v1_response = {"data": {"alpha": "v2"}}
    provider._cache.pop("alpha", None)
    assert provider.get("alpha") == "v2"

    provider._cache.pop("alpha", None)
    provider._client.v1_response = {"data": {"only": 11}}
    assert provider.get("alpha") == "11"

    provider._cache.pop("alpha", None)
    provider._client.raise_v1 = module.InvalidPath("nope")
    assert provider.get("alpha") is None

    provider._client.raise_v1 = None
    provider._client.v1_response = {"data": {"value": "one"}}
    provider._cache.pop("alpha", None)
    provider._cache.pop("beta", None)
    result = provider.get_many(["alpha", "beta"])
    assert result["alpha"] == "one"
    assert result["beta"] == "one"


def test_vault_provider_approle_login_requires_secret_callback(monkeypatch):
    module, _, _ = _import_vault_module_with_fake_hvac(monkeypatch)
    provider = module.VaultSecretProvider(address="http://vault:8200", token="token-1")
    provider._secret_id_fn = None
    provider._role_id = "role-1"
    with pytest.raises(module.VaultClientError, match="secret id callback"):
        provider._approle_login()
