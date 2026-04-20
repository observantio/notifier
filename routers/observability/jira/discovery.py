"""
Discovery endpoints for Jira integration in the observability notifier router.
These endpoints allow clients to list available Jira projects and issue types
based on either tenant-level Jira configuration or specific Jira integrations.
The endpoints handle authentication and permissions, and they return structured
responses that indicate whether Jira is enabled for the tenant and what projects
and issue types are available. This functionality is essential for users to
configure their Jira integrations effectively when setting up incident management
workflows in the observability platform.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from middleware.openapi import BAD_REQUEST_NOT_FOUND_ERRORS
from models.access.auth_models import Permission, TokenData
from services.alerting.integration_security_service import (
    get_effective_jira_credentials,
    jira_is_enabled_for_tenant,
)
from services.jira.helpers import jira_issue_types_via_integration, jira_projects_via_integration
from services.jira_service import JiraError, jira_service

router = APIRouter(tags=["alertmanager-jira"])


@router.get(
    "/jira/projects",
    summary="List Jira Projects",
    description="Lists Jira projects using either the tenant Jira config or a selected integration.",
    response_description="The available Jira projects for the resolved credentials.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
async def list_jira_projects(
    integration_id: str | None = Query(None, alias="integrationId"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    if integration_id:
        return await jira_projects_via_integration(current_user.tenant_id, integration_id, current_user)
    if not jira_is_enabled_for_tenant(current_user.tenant_id):
        return {"enabled": False, "projects": []}
    try:
        projects = await jira_service.list_projects(credentials=get_effective_jira_credentials(current_user.tenant_id))
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return {"enabled": True, "projects": projects}


@router.get(
    "/jira/projects/{project_key}/issue-types",
    summary="List Jira Issue Types",
    description="Lists Jira issue types for a project using either the tenant Jira config or a selected integration.",
    response_description="The available Jira issue types for the requested project.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
async def list_jira_issue_types(
    project_key: str,
    integration_id: str | None = Query(None, alias="integrationId"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    if integration_id:
        return await jira_issue_types_via_integration(current_user.tenant_id, integration_id, project_key, current_user)
    if not jira_is_enabled_for_tenant(current_user.tenant_id):
        return {"enabled": False, "issueTypes": []}
    try:
        issue_types = await jira_service.list_issue_types(
            project_key=project_key,
            credentials=get_effective_jira_credentials(current_user.tenant_id),
        )
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return {"enabled": True, "issueTypes": issue_types}


@router.get(
    "/integrations/jira/{integration_id}/projects",
    summary="List Jira Projects By Integration",
    description="Lists Jira projects using a specific Jira integration.",
    response_description="The Jira projects available through the selected integration.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
async def list_integration_projects(
    integration_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    return await jira_projects_via_integration(current_user.tenant_id, integration_id, current_user)


@router.get(
    "/integrations/jira/{integration_id}/projects/{project_key}/issue-types",
    summary="List Jira Issue Types By Integration",
    description="Lists Jira issue types for a project using a specific Jira integration.",
    response_description="The Jira issue types available through the selected integration.",
    responses=BAD_REQUEST_NOT_FOUND_ERRORS,
)
async def list_integration_issue_types(
    integration_id: str,
    project_key: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    return await jira_issue_types_via_integration(current_user.tenant_id, integration_id, project_key, current_user)
