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
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.exc import SQLAlchemyError

SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

os.environ["DATABASE_URL"] = "postgresql://safeuser:safePass_123@db:5432/notifier"
os.environ["NOTIFIER_DATABASE_URL"] = "postgresql://safeuser:safePass_123@db:5432/notifier"
os.environ["HOST"] = "127.0.0.1"
os.environ["PORT"] = "4319"
os.environ["LOG_LEVEL"] = "info"
os.environ["ENABLE_API_DOCS"] = "true"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["CORS_ALLOW_CREDENTIALS"] = "true"
os.environ["JWT_ALGORITHM"] = "RS256"
os.environ["JWT_AUTO_GENERATE_KEYS"] = "true"
os.environ["DATA_ENCRYPTION_KEY"] = Fernet.generate_key().decode("utf-8")


def _load_main() -> object:
    if "main" in sys.modules:
        del sys.modules["main"]
    return importlib.import_module("main")


@pytest.mark.asyncio
async def test_startup_database_wraps_bootstrap_in_to_thread(monkeypatch):
    main_module = _load_main()
    calls: list[str] = []

    async def fake_to_thread(func):
        calls.append("to_thread")
        return func()

    monkeypatch.setattr(main_module.asyncio, "to_thread", fake_to_thread)
    monkeypatch.setattr(main_module, "_bootstrap_database", lambda: calls.append("bootstrap"))

    await main_module._startup_database()

    assert calls == ["to_thread", "bootstrap"]


def test_bootstrap_database_retries_then_succeeds(monkeypatch):
    main_module = _load_main()
    warnings: list[tuple[str, tuple[object, ...]]] = []
    calls: list[object] = []
    attempts = iter([0.0, 0.1])
    failure = SQLAlchemyError("database unavailable")

    monkeypatch.setenv("DATABASE_STARTUP_TIMEOUT", "30")
    monkeypatch.setenv("DATABASE_STARTUP_RETRY_DELAY", "0")
    monkeypatch.setattr(main_module.time, "monotonic", lambda: next(attempts))
    monkeypatch.setattr(main_module.time, "sleep", lambda seconds: calls.append(("sleep", seconds)))
    monkeypatch.setattr(
        main_module.logger,
        "warning",
        lambda message, *args: warnings.append((message, args)),
    )

    state = {"attempt": 0}

    def ensure_database_exists(database_url):
        calls.append(("ensure", database_url))
        state["attempt"] += 1
        if state["attempt"] == 1:
            raise failure

    def init_database(database_url, echo):
        calls.append(("init", database_url, echo))

    def init_db():
        calls.append("init_db")

    monkeypatch.setattr(main_module.database_module, "ensure_database_exists", ensure_database_exists)
    monkeypatch.setattr(main_module.database_module, "init_database", init_database)
    monkeypatch.setattr(main_module.database_module, "init_db", init_db)

    main_module._bootstrap_database()

    assert calls == [
        ("ensure", main_module.config.notifier_database_url),
        ("sleep", 0.0),
        ("ensure", main_module.config.notifier_database_url),
        ("init", main_module.config.notifier_database_url, main_module.config.log_level == "debug"),
        "init_db",
    ]
    assert warnings and warnings[0][0] == "Notifier database not ready (attempt %d, retrying in %.1fs): %s"
    assert isinstance(warnings[0][1][2], SQLAlchemyError)


def test_bootstrap_database_times_out_on_sqlalchemy_error(monkeypatch):
    main_module = _load_main()
    attempts = iter([0.0, 1.0])

    monkeypatch.setenv("DATABASE_STARTUP_TIMEOUT", "0")
    monkeypatch.setenv("DATABASE_STARTUP_RETRY_DELAY", "0")
    monkeypatch.setattr(main_module.time, "monotonic", lambda: next(attempts))
    monkeypatch.setattr(main_module.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        main_module.database_module,
        "ensure_database_exists",
        lambda database_url: (_ for _ in ()).throw(SQLAlchemyError("still down")),
    )
    monkeypatch.setattr(main_module.database_module, "init_database", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module.database_module, "init_db", lambda: None)

    with pytest.raises(RuntimeError, match="Notifier database did not become ready before startup timeout") as exc_info:
        main_module._bootstrap_database()

    assert isinstance(exc_info.value.__cause__, SQLAlchemyError)


@pytest.mark.parametrize("env_name", ["DATABASE_STARTUP_TIMEOUT", "DATABASE_STARTUP_RETRY_DELAY"])
def test_bootstrap_database_rejects_invalid_float_env(monkeypatch, env_name):
    main_module = _load_main()
    monkeypatch.setenv("DATABASE_STARTUP_TIMEOUT", "30")
    monkeypatch.setenv("DATABASE_STARTUP_RETRY_DELAY", "2")
    monkeypatch.setenv(env_name, "not-a-number")

    with pytest.raises(RuntimeError, match=rf"Invalid value for {env_name}: 'not-a-number'"):
        main_module._bootstrap_database()