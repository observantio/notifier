"""
Request models for alerting-related API endpoints.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from custom_types.json import JSONDict


class AlertWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    alerts: list[JSONDict] = Field(
        default_factory=list, examples=[[{"labels": {"alertname": "HighCpuUsage", "severity": "critical"}}]]
    )


class RuleImportRequest(BaseModel):
    yamlContent: str | None = Field(
        None, examples=["groups:\n  - name: watchdog-default\n    rules:\n      - alert: HighCpuUsage"]
    )
    defaults: JSONDict = Field(default_factory=dict, examples=[{"labels": {"team": "platform"}}])
    dryRun: bool = Field(False, examples=[True])


class JiraConfigUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool | None = Field(None, examples=[True])
    baseUrl: str | None = Field(None, examples=["https://jira.example.internal"])
    email: str | None = Field(None, examples=["jira-bot@example.com"])
    apiToken: str | None = Field(None, examples=["jira-api-token"])
    bearerToken: str | None = Field(None, examples=["jira-bearer-token"])


class JiraIntegrationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, examples=["Primary Jira"])
    enabled: StrictBool = Field(True, examples=[True])
    visibility: str = Field("private", examples=["group"])
    sharedGroupIds: list[str] = Field(default_factory=list, examples=[["group-ops"]])
    baseUrl: str | None = Field(None, examples=["https://jira.example.internal"])
    email: str | None = Field(None, examples=["jira-bot@example.com"])
    apiToken: str | None = Field(None, examples=["jira-api-token"])
    bearerToken: str | None = Field(None, examples=["jira-bearer-token"])
    authMode: str | None = Field(None, examples=["api_token"])
    supportsSso: StrictBool | None = Field(None, examples=[False])


class JiraIntegrationUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, examples=["Primary Jira"])
    enabled: bool | None = Field(None, examples=[True])
    visibility: str | None = Field(None, examples=["group"])
    sharedGroupIds: list[str] | None = Field(None, examples=[["group-ops"]])
    baseUrl: str | None = Field(None, examples=["https://jira.example.internal"])
    email: str | None = Field(None, examples=["jira-bot@example.com"])
    apiToken: str | None = Field(None, examples=["jira-api-token"])
    bearerToken: str | None = Field(None, examples=["jira-bearer-token"])
    authMode: str | None = Field(None, examples=["api_token"])
    supportsSso: bool | None = Field(None, examples=[False])


class IncidentJiraCreateRequest(BaseModel):
    integrationId: str = Field(..., examples=["jira-int-01"])
    projectKey: str = Field(..., examples=["OPS"])
    summary: str | None = Field(None, examples=["Investigate HighCpuUsage incident"])
    description: str | None = Field(None, examples=["CPU usage has remained above 95% for five minutes."])
    issueType: str | None = Field(None, examples=["Task"])
    replaceExisting: bool = Field(False, examples=[False])


class GroupSharePruneRequest(BaseModel):
    tenant_id: Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$", alias="tenantId", examples=["tenant-01"])]
    group_id: Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$", alias="groupId", examples=["group-ops"])]
    removed_user_ids: list[Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$")]] = Field(
        default_factory=list,
        alias="removedUserIds",
        examples=[["user-42"]],
    )
    removed_usernames: list[Annotated[str, Field(min_length=1, pattern=r"^[^\x00]+$")]] = Field(
        default_factory=list,
        alias="removedUsernames",
        examples=[["alice"]],
    )
