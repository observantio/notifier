"""
Runtime SSL helpers for the Notifier service.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any


@dataclass(frozen=True)
class RuntimeSSLOptions:
    ssl_certfile: str
    ssl_keyfile: str

    @classmethod
    def from_config(cls, config: object) -> RuntimeSSLOptions | None:
        if not getattr(config, "notifier_ssl_enabled"):
            return None

        return cls(
            ssl_certfile=str(getattr(config, "notifier_ssl_certfile", "")).strip(),
            ssl_keyfile=str(getattr(config, "notifier_ssl_keyfile", "")).strip(),
        )

    def to_uvicorn_kwargs(self) -> dict[str, str]:
        return {
            "ssl_certfile": self.ssl_certfile,
            "ssl_keyfile": self.ssl_keyfile,
        }


def run_uvicorn(app: Any, *, ssl_options: RuntimeSSLOptions | None = None, **kwargs: Any) -> None:
    if ssl_options is not None:
        kwargs.update(ssl_options.to_uvicorn_kwargs())

    uvicorn = import_module("uvicorn")
    uvicorn.run(app=app, **kwargs)
