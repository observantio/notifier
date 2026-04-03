"""
Request models for alerting-related API endpoints.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations
from typing import Annotated, List, Optional
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from custom_types.json import JSONDict


class AlertWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    alerts: List[JSONDict] = Field(default_factory=list, examples=[[{"labels": {"alertname": "HighCpuUsage", "severity": "critical"}}]])


class RuleImportRequest(BaseModel):
    yamlContent: Optional[str] = Field(None, examples=['groups:\n  - name: watchdog-default\n    rules:\n      - alert: HighCpuUsage'])
    defaults: JSONDict = Field(default_factory=dict, examples=[{"labels": {"team": "platform"}}])
    dryRun: bool = Field(False, examples=[True])


class JiraConfigUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: Optional[StrictBool] = Field(None, examples=[True])
    baseUrl: Optional[str] = Field(None, examples=["https://jira.example.internal"])
    email: Optional[str] = Field(None, examples=["jira-bot@example.com"])
    apiToken: Optional[str] = Field(None, examples=["jira-api-token"])
    bearerToken: Optional[str] = Field(None, examples=["jira-bearer-token"])


class JiraIntegrationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(None, examples=["Primary Jira"])
    enabled: StrictBool = Field(True, examples=[True])
    visibility: str = Field("private", examples=["group"])
    sharedGroupIds: List[str] = Field(default_factory=list, examples=[["group-ops"]])
    baseUrl: Optional[str] = Field(None, examples=["https://jira.example.internal"])
    email: Optional[str] = Field(None, examples=["jira-bot@example.com"])
    apiToken: Optional[str] = Field(None, examples=["jira-api-token"])
    bearerToken: Optional[str] = Field(None, examples=["jira-bearer-token"])
    authMode: Optional[str] = Field(None, examples=["api_token"])
    supportsSso: Optional[StrictBool] = Field(None, examples=[False])


class JiraIntegrationUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(None, examples=["Primary Jira"])
    enabled: Optional[bool] = Field(None, examples=[True])
    visibility: Optional[str] = Field(None, examples=["group"])
    sharedGroupIds: Optional[List[str]] = Field(None, examples=[["group-ops"]])
    baseUrl: Optional[str] = Field(None, examples=["https://jira.example.internal"])
    email: Optional[str] = Field(None, examples=["jira-bot@example.com"])
    apiToken: Optional[str] = Field(None, examples=["jira-api-token"])
    bearerToken: Optional[str] = Field(None, examples=["jira-bearer-token"])
    authMode: Optional[str] = Field(None, examples=["api_token"])
    supportsSso: Optional[bool] = Field(None, examples=[False])


class IncidentJiraCreateRequest(BaseModel):
    integrationId: str = Field(..., examples=["jira-int-01"])
    projectKey: str = Field(..., examples=["OPS"])
    summary: Optional[str] = Field(None, examples=["Investigate HighCpuUsage incident"])
    description: Optional[str] = Field(None, examples=["CPU usage has remained above 95% for five minutes."])
    issueType: Optional[str] = Field(None, examples=["Task"])
    replaceExisting: bool = Field(False, examples=[False])


class GroupSharePruneRequest(BaseModel):
    tenant_id: Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$", alias="tenantId", examples=["tenant-01"])]
    group_id: Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$", alias="groupId", examples=["group-ops"])]
    removed_user_ids: List[Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$")]] = Field(
        default_factory=list,
        alias="removedUserIds",
        examples=[["user-42"]],
    )
    removed_usernames: List[Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$")]] = Field(
        default_factory=list,
        alias="removedUsernames",
        examples=[["alice"]],
    )
