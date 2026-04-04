"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import types

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from tests._env import ensure_test_env

ensure_test_env()


CONFIG_MODULE = "config"


def _reload_config_module():
    if CONFIG_MODULE in sys.modules:
        del sys.modules[CONFIG_MODULE]
    return importlib.import_module(CONFIG_MODULE)


def _rsa_keypair_pem() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _ec_keypair_pem() -> tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _valid_dev_env() -> dict[str, str]:
    return {
        "APP_ENV": "development",
        "DATABASE_URL": "postgresql://safeuser:safePass_123@db:5432/notifier",
        "NOTIFIER_DATABASE_URL": "postgresql://safeuser:safePass_123@db:5432/notifier",
        "CORS_ORIGINS": "http://localhost:5173",
        "CORS_ALLOW_CREDENTIALS": "true",
        "JWT_ALGORITHM": "RS256",
        "JWT_PRIVATE_KEY": "",
        "JWT_PUBLIC_KEY": "",
        "JWT_AUTO_GENERATE_KEYS": "true",
        "VAULT_ENABLED": "false",
        "NOTIFIER_CONTEXT_ALGORITHM": "HS256",
        "NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS": "180",
        "MAX_QUERY_LIMIT": "1000",
        "DEFAULT_QUERY_LIMIT": "20",
    }


def _valid_prod_env() -> dict[str, str]:
    private_key, public_key = _rsa_keypair_pem()
    return {
        "APP_ENV": "production",
        "DATABASE_URL": "postgresql://safeuser:safePass_123@db:5432/notifier",
        "NOTIFIER_DATABASE_URL": "postgresql://safeuser:safePass_123@db:5432/notifier",
        "CORS_ORIGINS": "https://app.example.com",
        "CORS_ALLOW_CREDENTIALS": "true",
        "JWT_ALGORITHM": "RS256",
        "JWT_PRIVATE_KEY": private_key,
        "JWT_PUBLIC_KEY": public_key,
        "JWT_AUTO_GENERATE_KEYS": "false",
        "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode("utf-8"),
        "INBOUND_WEBHOOK_TOKEN": "strong_webhook_token_123",
        "GATEWAY_INTERNAL_SERVICE_TOKEN": "strong_gateway_token_123",
        "NOTIFIER_EXPECTED_SERVICE_TOKEN": "strong_expected_token_123",
        "NOTIFIER_CONTEXT_VERIFY_KEY": "strong_verify_key_123",
        "NOTIFIER_CONTEXT_SIGNING_KEY": "strong_signing_key_123",
        "NOTIFIER_CONTEXT_ALGORITHM": "HS256",
        "NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS": "180",
        "ALLOWLIST_FAIL_OPEN": "false",
        "MAX_QUERY_LIMIT": "1000",
        "DEFAULT_QUERY_LIMIT": "20",
        "VAULT_ENABLED": "false",
    }


def test_config_helper_functions_and_secret_callbacks():
    module = _reload_config_module()

    assert module._to_bool(None, default=True) is True
    assert module._to_bool(" yes ") is True
    assert module._to_bool("0") is False
    assert module._to_list(None, default=["x"]) == ["x"]
    assert module._to_list(" a, ,b ") == ["a", "b"]
    assert module._normalized_secret("  Secret ") == "secret"
    assert module._is_weak_secret(None) is True
    assert module._is_weak_secret("replace_with_real_secret") is True
    assert module._is_weak_secret("Truly-Strong-Token-123") is False

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write("file-secret\n")
        temp_name = handle.name
    try:
        assert module._file_secret_callback(temp_name)() == "file-secret"
    finally:
        os.unlink(temp_name)

    assert module._literal_secret_callback("literal")() == "literal"


def test_build_secret_provider_prefers_env_and_supports_role_secret_sources(monkeypatch):
    module = _reload_config_module()

    with monkeypatch.context() as ctx:
        ctx.delenv("VAULT_ADDR", raising=False)
        provider = module.build_secret_provider()
        assert isinstance(provider, module.EnvSecretProvider)

    fake_calls: dict[str, object] = {}

    class FakeVaultSecretProvider:
        def __init__(self, **kwargs):
            fake_calls.update(kwargs)

        def get(self, key: str) -> str | None:
            return None

    fake_module = types.SimpleNamespace(
        VaultClientError=RuntimeError,
        VaultSecretProvider=FakeVaultSecretProvider,
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write("secret-from-file\n")
        temp_name = handle.name
    try:
        with monkeypatch.context() as ctx:
            ctx.setenv("VAULT_ADDR", "http://vault:8200")
            ctx.delenv("VAULT_ROLE_ID", raising=False)
            ctx.delenv("VAULT_SECRET_ID_FILE", raising=False)
            ctx.delenv("VAULT_SECRET_ID", raising=False)
            ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
            provider = module.build_secret_provider()
            assert isinstance(provider, FakeVaultSecretProvider)
            assert fake_calls["secret_id_fn"] is None

        with monkeypatch.context() as ctx:
            ctx.setenv("VAULT_ADDR", "http://vault:8200")
            ctx.setenv("VAULT_ROLE_ID", "role-id")
            ctx.setenv("VAULT_SECRET_ID_FILE", temp_name)
            ctx.setenv("VAULT_PREFIX", "kv")
            ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
            provider = module.build_secret_provider()
            assert isinstance(provider, FakeVaultSecretProvider)
            assert fake_calls["address"] == "http://vault:8200"
            assert fake_calls["prefix"] == "kv"
            assert callable(fake_calls["secret_id_fn"])
            assert fake_calls["secret_id_fn"]() == "secret-from-file"

        with monkeypatch.context() as ctx:
            ctx.setenv("VAULT_ADDR", "http://vault:8200")
            ctx.setenv("VAULT_ROLE_ID", "role-id")
            ctx.delenv("VAULT_SECRET_ID_FILE", raising=False)
            ctx.setenv("VAULT_SECRET_ID", "inline-secret")
            ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
            provider = module.build_secret_provider()
            assert isinstance(provider, FakeVaultSecretProvider)
            assert fake_calls["secret_id_fn"]() == "inline-secret"

        with monkeypatch.context() as ctx:
            ctx.setenv("VAULT_ADDR", "http://vault:8200")
            ctx.setenv("VAULT_ROLE_ID", "role-id")
            ctx.delenv("VAULT_SECRET_ID_FILE", raising=False)
            ctx.delenv("VAULT_SECRET_ID", raising=False)
            ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
            with pytest.raises(RuntimeError, match="neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE"):
                module.build_secret_provider()
    finally:
        os.unlink(temp_name)
        sys.modules.pop("services.secrets.vault_client", None)


def test_config_loads_vault_values_and_get_secret_falls_back(monkeypatch):
    class FakeVaultSecretProvider:
        def __init__(self, **kwargs):
            self.values = {
                "DATABASE_URL": "postgresql://vaultuser:vaultpass@db:5432/notifier",
                "NOTIFIER_CONTEXT_VERIFY_KEY": "vault-verify",
            }

        def get(self, key: str) -> str | None:
            if key == "JWT_PRIVATE_KEY":
                raise RuntimeError("broken")
            return self.values.get(key)

    fake_module = types.SimpleNamespace(
        VaultClientError=RuntimeError,
        VaultSecretProvider=FakeVaultSecretProvider,
    )

    with monkeypatch.context() as ctx:
        for key, value in _valid_dev_env().items():
            ctx.setenv(key, value)
        ctx.setenv("VAULT_ENABLED", "true")
        ctx.setenv("VAULT_ADDR", "http://vault:8200")
        ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
        module = _reload_config_module()
        assert module.config.database_url == "postgresql://vaultuser:vaultpass@db:5432/notifier"
        assert module.config.notifier_context_verify_key == "vault-verify"
        assert module.config.get_secret("NOTIFIER_CONTEXT_VERIFY_KEY") == "vault-verify"

        module.config.MISSING_VALUE = None
        module.config._secret_provider = types.SimpleNamespace(
            get=lambda key: "fallback-secret" if key == "MISSING_VALUE" else None
        )
        assert module.config.get_secret("MISSING_VALUE") == "fallback-secret"

        module.config._secret_provider = types.SimpleNamespace(
            get=lambda key: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        assert module.config.get_secret("MISSING_VALUE") is None

    sys.modules.pop("services.secrets.vault_client", None)


def test_config_auto_generates_rsa_and_ec_keys(monkeypatch):
    with monkeypatch.context() as ctx:
        for key, value in _valid_dev_env().items():
            ctx.setenv(key, value)
        module = _reload_config_module()
        assert "BEGIN PRIVATE KEY" in module.config.jwt_private_key
        assert "BEGIN PUBLIC KEY" in module.config.jwt_public_key

    with monkeypatch.context() as ctx:
        for key, value in _valid_dev_env().items():
            ctx.setenv(key, value)
        ctx.setenv("JWT_ALGORITHM", "ES256")
        module = _reload_config_module()
        assert "BEGIN PRIVATE KEY" in module.config.jwt_private_key
        assert "BEGIN PUBLIC KEY" in module.config.jwt_public_key


def test_apply_security_defaults_rejects_unknown_auto_key_algorithm():
    module = _reload_config_module()
    cfg = module.Config.__new__(module.Config)
    cfg.jwt_algorithm = "HS512"
    cfg.allowed_jwt_algorithms = {"HS512"}
    cfg.jwt_private_key = ""
    cfg.jwt_public_key = ""
    cfg.jwt_auto_generate_keys = True
    cfg.is_production = False
    with pytest.raises(ValueError, match="Unsupported JWT_ALGORITHM"):
        module.Config._apply_security_defaults(cfg)


@pytest.mark.parametrize(
    ("env_updates", "expected_message"),
    [
        ({"DATABASE_URL": "postgresql://user:changeme123@localhost:5432/appdb"}, "Unsafe DATABASE_URL detected"),
        ({"JWT_ALGORITHM": "HS256"}, "Unsupported JWT_ALGORITHM"),
        (
            {"JWT_PRIVATE_KEY": "", "JWT_PUBLIC_KEY": "", "JWT_AUTO_GENERATE_KEYS": "false"},
            "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured",
        ),
        (
            {"APP_ENV": "production", "JWT_AUTO_GENERATE_KEYS": "true"},
            "JWT_AUTO_GENERATE_KEYS must be disabled in production",
        ),
        ({"APP_ENV": "production", "DATA_ENCRYPTION_KEY": ""}, "DATA_ENCRYPTION_KEY must be configured in production"),
        ({"DATA_ENCRYPTION_KEY": "not-a-fernet-key"}, "DATA_ENCRYPTION_KEY must be a valid Fernet key"),
        ({"CORS_ORIGINS": "*", "CORS_ALLOW_CREDENTIALS": "true"}, "CORS_ORIGINS cannot contain '*'"),
        ({"NOTIFIER_CONTEXT_ALGORITHM": "HS384"}, "Unsupported NOTIFIER_CONTEXT_ALGORITHM"),
        ({"NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS": "0"}, "NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS must be greater than 0"),
        (
            {"APP_ENV": "production", "INBOUND_WEBHOOK_TOKEN": "changeme"},
            "INBOUND_WEBHOOK_TOKEN must be set to a strong non-placeholder secret in production",
        ),
        ({"APP_ENV": "production", "ALLOWLIST_FAIL_OPEN": "true"}, "ALLOWLIST_FAIL_OPEN must be false in production"),
        ({"MAX_QUERY_LIMIT": "0"}, "MAX_QUERY_LIMIT must be greater than 0"),
        ({"DEFAULT_QUERY_LIMIT": "0"}, "DEFAULT_QUERY_LIMIT must be greater than 0"),
        ({"MAX_QUERY_LIMIT": "20", "DEFAULT_QUERY_LIMIT": "30"}, "DEFAULT_QUERY_LIMIT cannot exceed MAX_QUERY_LIMIT"),
    ],
)
def test_config_validation_edges(monkeypatch, env_updates, expected_message):
    env = _valid_prod_env() if env_updates.get("APP_ENV") == "production" else _valid_dev_env()
    env.update(env_updates)
    with monkeypatch.context() as ctx:
        for key, value in env.items():
            ctx.setenv(key, value)
        with pytest.raises(ValueError, match=expected_message):
            _reload_config_module()


def test_config_accepts_valid_production_environment(monkeypatch):
    with monkeypatch.context() as ctx:
        for key, value in _valid_prod_env().items():
            ctx.setenv(key, value)
        module = _reload_config_module()
        assert module.config.is_production is True
        assert module.config.get_secret("NOTIFIER_EXPECTED_SERVICE_TOKEN") == "strong_expected_token_123"


def test_config_init_handles_nonfatal_vault_load_failure(monkeypatch):
    module = _reload_config_module()
    original_loader = module.Config._load_vault_secrets
    try:
        with monkeypatch.context() as ctx:
            for key, value in _valid_dev_env().items():
                ctx.setenv(key, value)
            ctx.setenv("VAULT_ENABLED", "true")

            def failing_loader(self):
                raise ValueError("vault unavailable")

            module.Config._load_vault_secrets = failing_loader
            cfg = module.Config()
            assert cfg.vault_enabled is True
            assert cfg._secret_provider is not None
    finally:
        module.Config._load_vault_secrets = original_loader


def test_load_vault_secrets_requires_addr_and_secret_source(monkeypatch):
    module = _reload_config_module()

    cfg = module.Config.__new__(module.Config)
    cfg.vault_enabled = True
    cfg.vault_addr = None
    with pytest.raises(ValueError, match="VAULT_ADDR must be set"):
        module.Config._load_vault_secrets(cfg)

    fake_module = types.SimpleNamespace(
        VaultClientError=RuntimeError,
        VaultSecretProvider=lambda **_kwargs: types.SimpleNamespace(get=lambda _key: None),
    )

    cfg = module.Config.__new__(module.Config)
    cfg.vault_enabled = True
    cfg.vault_addr = "http://vault:8200"
    cfg.vault_token = None
    cfg.vault_role_id = "role-id"
    cfg.vault_secret_id = None
    cfg.vault_secret_id_file = None
    cfg.vault_secrets_prefix = "secret"
    cfg.vault_kv_version = 2
    cfg.vault_timeout = 2.0
    cfg.vault_cacert = None
    cfg.vault_cache_ttl = 30.0
    cfg.vault_secret_keys = ()
    with monkeypatch.context() as ctx:
        ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
        with pytest.raises(RuntimeError, match="neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE"):
            module.Config._load_vault_secrets(cfg)


def test_config_validate_warns_when_jwt_secret_key_set(monkeypatch):
    with monkeypatch.context() as ctx:
        for key, value in _valid_dev_env().items():
            ctx.setenv(key, value)
        ctx.setenv("JWT_SECRET_KEY", "legacy-secret")
        module = _reload_config_module()
        assert module.config.jwt_secret_key == "legacy-secret"


def test_config_init_raises_when_vault_required_and_load_fails(monkeypatch):
    module = _reload_config_module()

    with monkeypatch.context() as ctx:
        for key, value in _valid_dev_env().items():
            ctx.setenv(key, value)
        ctx.setenv("VAULT_ENABLED", "true")
        ctx.setenv("VAULT_FAIL_ON_MISSING", "true")

        def failing_loader(self):
            raise ValueError("vault load failed")

        ctx.setattr(module.Config, "_load_vault_secrets", failing_loader)
        with pytest.raises(ValueError, match="vault load failed"):
            module.Config()


def test_load_vault_secrets_selects_file_and_literal_secret_callbacks(monkeypatch):
    module = _reload_config_module()
    captured: list[dict[str, object]] = []

    class FakeVaultSecretProvider:
        def __init__(self, **kwargs):
            captured.append(kwargs)

        def get(self, _key: str):
            return None

    fake_module = types.SimpleNamespace(
        VaultClientError=RuntimeError,
        VaultSecretProvider=FakeVaultSecretProvider,
    )

    cfg = module.Config.__new__(module.Config)
    cfg.vault_enabled = True
    cfg.vault_addr = "http://vault:8200"
    cfg.vault_token = None
    cfg.vault_role_id = "role-1"
    cfg.vault_cacert = None
    cfg.vault_secrets_prefix = "secret"
    cfg.vault_kv_version = 2
    cfg.vault_timeout = 2.0
    cfg.vault_cache_ttl = 30.0
    cfg.vault_secret_keys = ()

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write("file-secret\n")
        secret_file = handle.name

    try:
        with monkeypatch.context() as ctx:
            ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
            cfg.vault_secret_id_file = secret_file
            cfg.vault_secret_id = None
            module.Config._load_vault_secrets(cfg)
            assert callable(captured[-1]["secret_id_fn"])
            assert captured[-1]["secret_id_fn"]() == "file-secret"

        with monkeypatch.context() as ctx:
            ctx.setitem(sys.modules, "services.secrets.vault_client", fake_module)
            cfg.vault_secret_id_file = None
            cfg.vault_secret_id = "inline-secret"
            module.Config._load_vault_secrets(cfg)
            assert callable(captured[-1]["secret_id_fn"])
            assert captured[-1]["secret_id_fn"]() == "inline-secret"
    finally:
        os.unlink(secret_file)
        sys.modules.pop("services.secrets.vault_client", None)
