"""
Shared Jira router state and helpers.
"""

from pydantic import BaseModel

from services.storage_db_service import DatabaseStorageService

storage_service = DatabaseStorageService()
SUPPORTED_INCIDENT_JIRA_ISSUE_TYPES = {"task", "bug"}


class HideTogglePayload(BaseModel):
    hidden: bool = True
