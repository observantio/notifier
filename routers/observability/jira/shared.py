"""
Shared models and utilities for Jira integration in the observability notifier router. This includes common data models, 
constants, and helper functions that are used across multiple Jira-related endpoints, such as those for incident link 
discovery and integration management. By centralizing these shared components, we can ensure consistency and reduce code 
duplication across the Jira integration features in the notifier router.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from pydantic import BaseModel

from services.storage_db_service import DatabaseStorageService

storage_service = DatabaseStorageService()
SUPPORTED_INCIDENT_JIRA_ISSUE_TYPES = {"task", "bug"}


class HideTogglePayload(BaseModel):
    hidden: bool = True
