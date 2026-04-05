"""
Configuration management for the application, loading settings from environment variables with support for defaults,
type conversion, and validation. This module defines a `Config` class that encapsulates all configuration options for
the application, including server settings, service URLs, authentication parameters, rate limiting controls, and
security hardening features. The configuration is designed to be flexible and secure by default, with special
considerations for production environments. It also includes integration with Vault for secret management when enabled.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import importlib
import logging
import os
from typing import Any, Callable, List, Optional, cast

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from services.secrets.provider import EnvSecretProvider, SecretProvider

logger = logging.getLogger(__name__)


def _to_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _to_list(value: Optional[str], default: Optional[List[str]] = None) -> List[str]:
    if value is None:
        return default or []
    parsed = [item.strip() for item in value.split(",") if item.strip()]
    return parsed if parsed else (default or [])


def _normalized_secret(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def _is_weak_secret(value: Optional[str]) -> bool:
    normalized = _normalized_secret(value)
    if not normalized:
        return True
    weak_markers = ("changeme", "replace_with", "example", "default", "secret", "password")
    return any(marker in normalized for marker in weak_markers)


def _generate_rsa_keypair() -> tuple[str, str]:
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


def _generate_ec_keypair() -> tuple[str, str]:
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


def _env_name() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "development").strip().lower()


def _is_production_env() -> bool:
    return _env_name() in {"prod", "production"}


def _file_secret_callback(secret_path: str) -> Callable[[], str]:
    def load_secret_id() -> str:
        with open(secret_path, encoding="utf-8") as handle:
            return handle.read().strip()

    return load_secret_id


def _literal_secret_callback(secret_value: str) -> Callable[[], str]:
    def load_secret_id() -> str:
        return secret_value

    return load_secret_id


def build_secret_provider() -> SecretProvider:
    vault_addr = os.getenv("VAULT_ADDR", "").strip()
    if not vault_addr:
        return EnvSecretProvider()

    vault_mod = importlib.import_module("services.secrets.vault_client")

    token = os.getenv("VAULT_TOKEN", "").strip() or None
    role_id = os.getenv("VAULT_ROLE_ID", "").strip() or None
    secret_id_file = os.getenv("VAULT_SECRET_ID_FILE", "").strip() or None
    secret_id = os.getenv("VAULT_SECRET_ID", "").strip() or None

    secret_id_fn = None
    if role_id:
        if secret_id_file:
            secret_id_fn = _file_secret_callback(secret_id_file)
        elif secret_id:
            secret_id_fn = _literal_secret_callback(secret_id)
        else:
            raise vault_mod.VaultClientError(
                "VAULT_ROLE_ID set but neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE provided"
            )

    return cast(
        SecretProvider,
        vault_mod.VaultSecretProvider(
            address=vault_addr,
            token=token,
            role_id=role_id,
            secret_id_fn=secret_id_fn,
            prefix=os.getenv("VAULT_PREFIX", "secret").strip(),
            kv_version=int(os.getenv("VAULT_KV_VERSION", "2")),
            timeout=float(os.getenv("VAULT_TIMEOUT", "2.0")),
            cacert=os.getenv("VAULT_CACERT", "").strip() or None,
            cache_ttl=float(os.getenv("VAULT_CACHE_TTL", "30.0")),
        ),
    )


_CONFIG_EXAMPLE_DATABASE_URL = "postgresql://user:changeme123@localhost:5432/appdb"


def _config_identity_block(app_env: str, is_production: bool) -> dict[str, Any]:
    return {
        "app_env": app_env,
        "is_production": is_production,
        "default_admin_email": os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com"),
        "default_admin_tenant": os.getenv("DEFAULT_ADMIN_TENANT", "default"),
    }


def _config_listen_block(is_production: bool) -> dict[str, Any]:
    return {
        "host": os.getenv("HOST", "127.0.0.1"),
        "port": int(os.getenv("PORT", "4319")),
        "log_level": os.getenv("LOG_LEVEL", "info"),
        "enable_api_docs": _to_bool(os.getenv("ENABLE_API_DOCS"), default=not is_production),
    }


def _config_metrics_urls() -> dict[str, Any]:
    return {
        "alertmanager_url": os.getenv("ALERTMANAGER_URL", "http://alertmanager:9093"),
        "mimir_url": os.getenv("MIMIR_URL", "http://mimir:9009"),
    }


def _config_resilience_block() -> dict[str, Any]:
    return {
        "default_timeout": float(os.getenv("DEFAULT_TIMEOUT", "30.0")),
        "max_retries": int(os.getenv("MAX_RETRIES", "3")),
        "retry_backoff": float(os.getenv("RETRY_BACKOFF", "1.0")),
        "retry_max_backoff": float(os.getenv("RETRY_MAX_BACKOFF", "8.0")),
        "retry_jitter": float(os.getenv("RETRY_JITTER", "0.1")),
    }


def _config_rate_limit_block() -> dict[str, Any]:
    return {
        "rate_limit_gc_every": int(os.getenv("RATE_LIMIT_GC_EVERY", "1000")),
        "rate_limit_stale_after_seconds": int(os.getenv("RATE_LIMIT_STALE_AFTER_SECONDS", "300")),
        "rate_limit_max_states": int(os.getenv("RATE_LIMIT_MAX_STATES", "10000")),
        "rate_limit_fallback_mode": os.getenv("RATE_LIMIT_FALLBACK_MODE", "memory").strip().lower(),
    }


def _config_http_client_block() -> dict[str, Any]:
    return {
        "http_client_max_connections": int(os.getenv("HTTP_CLIENT_MAX_CONNECTIONS", "100")),
        "http_client_max_keepalive_connections": int(os.getenv("HTTP_CLIENT_MAX_KEEPALIVE_CONNECTIONS", "40")),
        "http_client_keepalive_expiry": float(os.getenv("HTTP_CLIENT_KEEPALIVE_EXPIRY", "30")),
        "service_cache_ttl_seconds": int(os.getenv("SERVICE_CACHE_TTL_SECONDS", "60")),
    }


def _config_query_limits_block() -> dict[str, Any]:
    return {
        "max_query_limit": int(os.getenv("MAX_QUERY_LIMIT", "1000")),
        "default_query_limit": int(os.getenv("DEFAULT_QUERY_LIMIT", "20")),
    }


def _config_request_limits_block() -> dict[str, Any]:
    return {
        "max_request_bytes": int(os.getenv("MAX_REQUEST_BYTES", "1048576")),
        "max_concurrent_requests": int(os.getenv("MAX_CONCURRENT_REQUESTS", "200")),
        "concurrency_acquire_timeout": float(os.getenv("CONCURRENCY_ACQUIRE_TIMEOUT", "1.0")),
        "rate_limit_public_per_minute": int(os.getenv("RATE_LIMIT_PUBLIC_PER_MINUTE", "120")),
    }


def _config_proxy_and_allowlists(is_production: bool) -> dict[str, Any]:
    return {
        "trust_proxy_headers": _to_bool(os.getenv("TRUST_PROXY_HEADERS"), default=False),
        "trusted_proxy_cidrs": _to_list(os.getenv("TRUSTED_PROXY_CIDRS"), default=[]),
        "require_client_ip_for_public_endpoints": _to_bool(
            os.getenv("REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS"), default=is_production
        ),
        "allowlist_fail_open": _to_bool(os.getenv("ALLOWLIST_FAIL_OPEN"), default=False),
        "auth_public_ip_allowlist": os.getenv("AUTH_PUBLIC_IP_ALLOWLIST"),
        "webhook_ip_allowlist": os.getenv("WEBHOOK_IP_ALLOWLIST"),
        "grafana_proxy_ip_allowlist": os.getenv("GRAFANA_PROXY_IP_ALLOWLIST"),
    }


def _config_tokens_block() -> dict[str, Any]:
    return {
        "inbound_webhook_token": os.getenv("INBOUND_WEBHOOK_TOKEN"),
        "gateway_internal_service_token": os.getenv("GATEWAY_INTERNAL_SERVICE_TOKEN"),
        "notifier_expected_service_token": os.getenv("NOTIFIER_EXPECTED_SERVICE_TOKEN"),
        "notifier_context_verify_key": os.getenv("NOTIFIER_CONTEXT_VERIFY_KEY"),
        "notifier_context_signing_key": os.getenv("NOTIFIER_CONTEXT_SIGNING_KEY"),
    }


def _config_notifier_context_block() -> dict[str, Any]:
    ctx_algo = (
        (os.getenv("NOTIFIER_CONTEXT_ALGORITHM") or os.getenv("NOTIFIER_CONTEXT_ALGORITHMS") or "HS256")
        .strip()
        .upper()
    )
    return {
        "notifier_context_issuer": os.getenv("NOTIFIER_CONTEXT_ISSUER", "watchdog-main"),
        "notifier_context_audience": os.getenv("NOTIFIER_CONTEXT_AUDIENCE", "notifier"),
        "notifier_context_algorithm": ctx_algo,
        "notifier_context_algorithms": ctx_algo,
        "notifier_context_replay_ttl_seconds": int(os.getenv("NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS", "180")),
        "notifier_tls_enabled": _to_bool(os.getenv("NOTIFIER_TLS_ENABLED"), default=False),
    }


def _config_org_and_jwt_block(is_production: bool) -> dict[str, Any]:
    return {
        "default_org_id": os.getenv("DEFAULT_ORG_ID", "default"),
        "jwt_algorithm": os.getenv("JWT_ALGORITHM", "RS256").strip().upper(),
        "jwt_secret_key": os.getenv("JWT_SECRET_KEY"),
        "jwt_private_key": os.getenv("JWT_PRIVATE_KEY"),
        "jwt_public_key": os.getenv("JWT_PUBLIC_KEY"),
        "jwt_auto_generate_keys": _to_bool(os.getenv("JWT_AUTO_GENERATE_KEYS"), default=not is_production),
    }


def _config_cors_block() -> dict[str, Any]:
    return {
        "cors_origins": _to_list(os.getenv("CORS_ORIGINS"), default=["http://localhost:3000"]),
        "cors_allow_credentials": _to_bool(os.getenv("CORS_ALLOW_CREDENTIALS"), default=True),
    }


def _config_vault_env_block(is_production: bool) -> dict[str, Any]:
    return {
        "vault_enabled": _to_bool(os.getenv("VAULT_ENABLED"), default=False),
        "vault_addr": os.getenv("VAULT_ADDR"),
        "vault_token": os.getenv("VAULT_TOKEN"),
        "vault_role_id": os.getenv("VAULT_ROLE_ID"),
        "vault_secret_id": os.getenv("VAULT_SECRET_ID"),
        "vault_secret_id_file": os.getenv("VAULT_SECRET_ID_FILE"),
        "vault_cacert": os.getenv("VAULT_CACERT"),
        "vault_secrets_prefix": os.getenv("VAULT_SECRETS_PREFIX", "secret"),
        "vault_kv_version": int(os.getenv("VAULT_KV_VERSION", "2")),
        "vault_timeout": float(os.getenv("VAULT_TIMEOUT", "2.0")),
        "vault_cache_ttl": float(os.getenv("VAULT_CACHE_TTL", "30.0")),
        "vault_fail_on_missing": _to_bool(os.getenv("VAULT_FAIL_ON_MISSING"), default=is_production),
    }


def _config_notification_channels_block() -> dict[str, Any]:
    raw_types = os.getenv("ENABLED_NOTIFICATION_CHANNEL_TYPES", "email,slack,teams,webhook,pagerduty")
    return {
        "default_rule_group": os.getenv("DEFAULT_RULE_GROUP", "BENOTFIED"),
        "enabled_notification_channel_types": [t.strip().lower() for t in raw_types.split(",") if t.strip()],
    }


def _build_config_values() -> dict[str, Any]:
    app_env = _env_name()
    is_production = _is_production_env()
    database_url = os.getenv("DATABASE_URL", _CONFIG_EXAMPLE_DATABASE_URL)
    values: dict[str, Any] = {}
    values.update(_config_identity_block(app_env, is_production))
    values.update(_config_listen_block(is_production))
    values.update(_config_metrics_urls())
    values["database_url"] = database_url
    values["notifier_database_url"] = os.getenv("NOTIFIER_DATABASE_URL", database_url)
    values["data_encryption_key"] = os.getenv("DATA_ENCRYPTION_KEY")
    values.update(_config_resilience_block())
    values.update(_config_rate_limit_block())
    values.update(_config_http_client_block())
    values.update(_config_query_limits_block())
    values.update(_config_request_limits_block())
    values.update(_config_proxy_and_allowlists(is_production))
    values.update(_config_tokens_block())
    values.update(_config_notifier_context_block())
    values.update(_config_org_and_jwt_block(is_production))
    values.update(_config_cors_block())
    values.update(_config_vault_env_block(is_production))
    values.update(_config_notification_channels_block())
    return values


class Config:
    EXAMPLE_DATABASE_URL: str = _CONFIG_EXAMPLE_DATABASE_URL
    ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"RS256", "ES256"})
    ALLOWED_CONTEXT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS512", "RS256", "ES256"})
    example_database_url: str = EXAMPLE_DATABASE_URL
    allowed_jwt_algorithms: frozenset[str] = ALLOWED_JWT_ALGORITHMS
    allowed_context_algorithms: frozenset[str] = ALLOWED_CONTEXT_ALGORITHMS

    VAULT_SECRET_KEYS: tuple[str, ...] = (
        "DATABASE_URL",
        "NOTIFIER_DATABASE_URL",
        "DATA_ENCRYPTION_KEY",
        "JWT_SECRET_KEY",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "INBOUND_WEBHOOK_TOKEN",
        "GATEWAY_INTERNAL_SERVICE_TOKEN",
        "NOTIFIER_EXPECTED_SERVICE_TOKEN",
        "NOTIFIER_CONTEXT_VERIFY_KEY",
        "NOTIFIER_CONTEXT_SIGNING_KEY",
    )
    vault_secret_keys: tuple[str, ...] = VAULT_SECRET_KEYS

    def __init__(self) -> None:
        object.__setattr__(self, "_secret_provider", None)
        object.__setattr__(self, "_values", _build_config_values())
        try:
            self._load_vault_secrets()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            if self.vault_enabled and (self.is_production or self.vault_fail_on_missing):
                raise
            logger.warning("Vault not available or misconfigured; continuing with environment variables: %s", exc)

        if object.__getattribute__(self, "_secret_provider") is None:
            object.__setattr__(self, "_secret_provider", EnvSecretProvider())

        self._apply_security_defaults()
        self.validate()

    def __getattr__(self, name: str) -> Any:
        vals = object.__getattribute__(self, "_values")
        try:
            return vals[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name: str, value: object) -> None:
        if name in ("_secret_provider", "_values"):
            object.__setattr__(self, name, value)
            return
        try:
            vals = object.__getattribute__(self, "_values")
        except AttributeError:
            object.__setattr__(self, name, value)
            return
        if name in vals:
            vals[name] = value
            return
        object.__setattr__(self, name, value)

    def _load_vault_secrets(self) -> None:
        if not self.vault_enabled:
            return

        vault_mod = importlib.import_module("services.secrets.vault_client")

        if not self.vault_addr:
            raise ValueError("VAULT_ADDR must be set when VAULT_ENABLED=true")

        secret_id_fn = None
        if self.vault_role_id:
            if self.vault_secret_id_file:
                secret_id_fn = _file_secret_callback(self.vault_secret_id_file)
            elif self.vault_secret_id:
                secret_id_fn = _literal_secret_callback(self.vault_secret_id)
            else:
                raise vault_mod.VaultClientError(
                    "VAULT_ROLE_ID set but neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE provided"
                )

        object.__setattr__(
            self,
            "_secret_provider",
            cast(
                SecretProvider,
                vault_mod.VaultSecretProvider(
                    address=self.vault_addr,
                    token=self.vault_token,
                    role_id=self.vault_role_id,
                    secret_id_fn=secret_id_fn,
                    prefix=self.vault_secrets_prefix,
                    kv_version=self.vault_kv_version,
                    timeout=self.vault_timeout,
                    cacert=self.vault_cacert,
                    cache_ttl=self.vault_cache_ttl,
                ),
            ),
        )

        vals = object.__getattribute__(self, "_values")
        provider = object.__getattribute__(self, "_secret_provider")
        for key in self.vault_secret_keys:
            try:
                val = provider.get(key)
            except (OSError, RuntimeError, TypeError, ValueError):
                val = None
            if val:
                vals[key.lower()] = val
                logger.info("Loaded secret %s from Vault", key)

    def get_secret(self, key: str) -> Optional[str]:
        val = getattr(self, key.lower(), None)
        if isinstance(val, str) and val:
            return val
        try:
            return cast(Optional[str], object.__getattribute__(self, "_secret_provider").get(key))
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

    def _apply_security_defaults(self) -> None:
        vals = object.__getattribute__(self, "_values")
        if self.jwt_algorithm in self.allowed_jwt_algorithms and (
            not vals.get("jwt_private_key") or not vals.get("jwt_public_key")
        ):
            if self.jwt_auto_generate_keys and not self.is_production:
                if self.jwt_algorithm == "RS256":
                    private_key, public_key = _generate_rsa_keypair()
                elif self.jwt_algorithm == "ES256":
                    private_key, public_key = _generate_ec_keypair()
                else:
                    raise ValueError("Unsupported JWT_ALGORITHM for auto key generation")
                vals["jwt_private_key"] = private_key
                vals["jwt_public_key"] = public_key
                logger.warning(
                    "Generated ephemeral JWT keypair for %s. Persist JWT_PRIVATE_KEY and JWT_PUBLIC_KEY "
                    "in a secret manager to avoid token invalidation on restart.",
                    self.jwt_algorithm,
                )

    def validate(self) -> None:
        if self.database_url == self.example_database_url or "changeme123" in self.database_url:
            raise ValueError(
                "Unsafe DATABASE_URL detected. Set DATABASE_URL to a non-example credentialed connection string."
            )

        if self.jwt_algorithm not in self.allowed_jwt_algorithms:
            raise ValueError(
                f"Unsupported JWT_ALGORITHM '{self.jwt_algorithm}'. "
                f"Allowed values: {sorted(self.allowed_jwt_algorithms)}"
            )

        if self.jwt_secret_key:
            logger.warning(
                "JWT_SECRET_KEY is currently unused for JWT_ALGORITHM=%s. "
                "Configure JWT_PRIVATE_KEY/JWT_PUBLIC_KEY instead.",
                self.jwt_algorithm,
            )

        if self.jwt_algorithm in self.allowed_jwt_algorithms and (not self.jwt_private_key or not self.jwt_public_key):
            raise ValueError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured for RS256/ES256 tokens")

        if self.is_production and self.jwt_auto_generate_keys:
            raise ValueError("JWT_AUTO_GENERATE_KEYS must be disabled in production")

        if self.is_production and not self.data_encryption_key:
            raise ValueError("DATA_ENCRYPTION_KEY must be configured in production")

        if self.data_encryption_key:
            try:
                Fernet(self.data_encryption_key)
            except (TypeError, ValueError) as exc:
                raise ValueError("DATA_ENCRYPTION_KEY must be a valid Fernet key") from exc

        if any(origin.strip() == "*" for origin in self.cors_origins) and self.cors_allow_credentials:
            raise ValueError("CORS_ORIGINS cannot contain '*' when CORS_ALLOW_CREDENTIALS is enabled.")

        if self.notifier_context_algorithm not in self.allowed_context_algorithms:
            raise ValueError(
                f"Unsupported NOTIFIER_CONTEXT_ALGORITHM '{self.notifier_context_algorithm}'. "
                f"Allowed values: {sorted(self.allowed_context_algorithms)}"
            )
        if self.notifier_context_replay_ttl_seconds <= 0:
            raise ValueError("NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS must be greater than 0")

        if self.is_production:
            required_production_secrets = {
                "INBOUND_WEBHOOK_TOKEN": self.inbound_webhook_token,
                "NOTIFIER_EXPECTED_SERVICE_TOKEN": (
                    self.notifier_expected_service_token or self.gateway_internal_service_token
                ),
                "NOTIFIER_CONTEXT_VERIFY_KEY": (self.notifier_context_verify_key or self.notifier_context_signing_key),
                "GATEWAY_INTERNAL_SERVICE_TOKEN": self.gateway_internal_service_token,
            }
            for key, value in required_production_secrets.items():
                if _is_weak_secret(value):
                    raise ValueError(f"{key} must be set to a strong non-placeholder secret in production")
            if self.allowlist_fail_open:
                raise ValueError("ALLOWLIST_FAIL_OPEN must be false in production")

        if self.max_query_limit <= 0:
            raise ValueError("MAX_QUERY_LIMIT must be greater than 0")
        if self.default_query_limit <= 0:
            raise ValueError("DEFAULT_QUERY_LIMIT must be greater than 0")
        if self.default_query_limit > self.max_query_limit:
            raise ValueError("DEFAULT_QUERY_LIMIT cannot exceed MAX_QUERY_LIMIT")


class Constants:
    STATUS_SUCCESS: str = "Success"


config = Config()
constants = Constants()
