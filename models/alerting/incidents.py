"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer


def _to_rfc3339(value: datetime) -> str:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")

class IncidentStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"


class IncidentVisibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    GROUP = "group"


class IncidentNote(BaseModel):
    author: str = Field(..., examples=["alice@example.com"])
    text: str = Field(..., examples=["Investigating elevated CPU on api-01"])
    created_at: datetime = Field(..., alias="createdAt", examples=["2026-04-03T12:00:00Z"])

    model_config = ConfigDict(populate_by_name=True)

    @field_serializer("created_at")
    def serialize_created_at(self, value: datetime) -> str:
        return _to_rfc3339(value)


class AlertIncident(BaseModel):
    id: str = Field(..., examples=["incident-123"])
    fingerprint: str = Field(..., examples=["01ARZ3NDEKTSV4RRFFQ69G5FAV"])
    alert_name: str = Field(..., alias="alertName", examples=["HighCpuUsage"])
    severity: str = Field(..., examples=["critical"])
    status: IncidentStatus = Field(..., examples=["open"])
    assignee: Optional[str] = Field(None, examples=["alice@example.com"])
    notes: List[IncidentNote] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict, examples=[{"service": "api", "severity": "critical"}])
    annotations: Dict[str, str] = Field(default_factory=dict, examples=[{"summary": "CPU above 95%"}])
    visibility: IncidentVisibility = Field(IncidentVisibility.PUBLIC, examples=["public"])
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", examples=[["group-ops"]])
    jira_ticket_key: Optional[str] = Field(None, alias="jiraTicketKey", examples=["OPS-321"])
    jira_ticket_url: Optional[str] = Field(None, alias="jiraTicketUrl", examples=["https://jira.example.internal/browse/OPS-321"])
    jira_integration_id: Optional[str] = Field(None, alias="jiraIntegrationId", examples=["jira-int-01"])
    starts_at: Optional[datetime] = Field(None, alias="startsAt", examples=["2026-04-03T11:55:00Z"])
    last_seen_at: datetime = Field(..., alias="lastSeenAt", examples=["2026-04-03T12:05:00Z"])
    resolved_at: Optional[datetime] = Field(None, alias="resolvedAt", examples=["2026-04-03T12:20:00Z"])
    created_at: datetime = Field(..., alias="createdAt", examples=["2026-04-03T12:00:00Z"])
    updated_at: datetime = Field(..., alias="updatedAt", examples=["2026-04-03T12:10:00Z"])
    user_managed: bool = Field(False, alias="userManaged", examples=[False])
    hide_when_resolved: bool = Field(False, alias="hideWhenResolved", examples=[False])

    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)

    @field_serializer("starts_at", "last_seen_at", "resolved_at", "created_at", "updated_at")
    def serialize_datetime_fields(self, value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None
        return _to_rfc3339(value)


class AlertIncidentUpdateRequest(BaseModel):
    status: Optional[str] = Field(None, examples=["resolved"])
    assignee: Optional[str] = Field(None, examples=["alice@example.com"])
    note: Optional[str] = Field(None, examples=["Resolved after scaling the deployment"])
    actor_username: Optional[str] = Field(None, alias="actorUsername", examples=["alice"])
    visibility: Optional[IncidentVisibility] = Field(None, examples=["group"])
    shared_group_ids: Optional[List[str]] = Field(default=None, alias="sharedGroupIds", examples=[["group-ops"]])
    jira_ticket_key: Optional[str] = Field(None, alias="jiraTicketKey", examples=["OPS-321"])
    jira_ticket_url: Optional[str] = Field(None, alias="jiraTicketUrl", examples=["https://jira.example.internal/browse/OPS-321"])
    jira_integration_id: Optional[str] = Field(None, alias="jiraIntegrationId", examples=["jira-int-01"])
    hide_when_resolved: Optional[bool] = Field(None, alias="hideWhenResolved", examples=[True])

    model_config = ConfigDict(populate_by_name=True)
