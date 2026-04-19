"""
Storage service for managing alert incidents, rules, and notification channels, providing a unified interface for
database operations and ensuring proper access control and data handling based on user permissions.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from typing import Any

from services.storage.channels import ChannelStorageService
from services.storage.hidden_entity_storage import HiddenEntityStorageService
from services.storage.incidents import IncidentStorageService
from services.storage.rules import RuleStorageService


class DatabaseStorageService:
    """Unified DB facade; methods resolve to ``channels``, ``incidents``, ``rules``, or ``hidden`` sub-services."""

    channels: ChannelStorageService
    incidents: IncidentStorageService
    rules: RuleStorageService
    hidden: HiddenEntityStorageService

    def __init__(self) -> None:
        self.channels = ChannelStorageService()
        self.incidents = IncidentStorageService()
        self.rules = RuleStorageService()
        self.hidden = HiddenEntityStorageService()

    def __getattr__(self, name: str) -> Any:
        for svc in (self.incidents, self.rules, self.channels, self.hidden):
            if hasattr(svc, name):
                return getattr(svc, name)
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")
