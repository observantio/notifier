"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from pydantic import BaseModel

from services.storage_db_service import DatabaseStorageService

storage_service = DatabaseStorageService()
SUPPORTED_INCIDENT_JIRA_ISSUE_TYPES = {"task", "bug"}


class HideTogglePayload(BaseModel):
    hidden: bool = True
