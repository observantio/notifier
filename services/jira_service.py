"""
Service for managing interactions with Jira, providing functions to create issues, list projects and issue types, and
manage comments on issues. This module includes logic to handle authentication with Jira using either API tokens or
bearer tokens, to construct appropriate API requests to the Jira REST API, and to process the responses received from
Jira. The service ensures that the base URL for Jira is properly configured and validated, and it provides error
handling for various scenarios that may arise when interacting with the Jira API.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import base64
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Optional
from urllib.parse import urlparse

import httpx

from config import config
from custom_types.json import JSONDict, JSONValue
from services.common.http_client import create_async_client
from services.common.url_utils import is_safe_http_url

logger = logging.getLogger(__name__)

Credentials = Optional[Mapping[str, object]]
QueryParams = Mapping[str, str | int | float | bool | None]


@dataclass(frozen=True)
class JiraIssueCreateOptions:
    description: str | None = None
    issue_type: str = "Task"
    priority: str | None = None


@dataclass(frozen=True)
class JiraRequest:
    method: Literal["GET", "POST"]
    path: str
    credentials: Credentials = None
    params: QueryParams | None = None
    payload: JSONDict | None = None


@dataclass(frozen=True)
class JiraTransitionTarget:
    target_names: set[str]
    transition_names: set[str]
    status_category_key: str


@dataclass(frozen=True)
class JiraIssueCreateRequest:
    project_key: str
    summary: str
    options: JiraIssueCreateOptions = JiraIssueCreateOptions()
    credentials: Credentials = None


def _string_value(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _json_dict(value: object) -> JSONDict:
    return value if isinstance(value, dict) else {}


def _json_dict_list(value: object) -> list[JSONDict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _coerce_issue_options(
    issue: JiraIssueCreateOptions | object | None,
) -> JiraIssueCreateOptions:
    if isinstance(issue, JiraIssueCreateOptions):
        return issue
    if issue is not None:
        return JiraIssueCreateOptions(description=str(issue))
    return JiraIssueCreateOptions()


class JiraError(Exception):
    pass


class JiraService:
    def __init__(self, timeout: float | None = None) -> None:
        self.base_url = (os.getenv("JIRA_BASE_URL") or "").strip().rstrip("/")
        self.email = (os.getenv("JIRA_EMAIL") or "").strip() or None
        self.api_token = (os.getenv("JIRA_API_TOKEN") or "").strip() or None
        self.bearer = (os.getenv("JIRA_BEARER_TOKEN") or "").strip() or None
        self.timeout = float(timeout or config.default_timeout)
        self._client = create_async_client(self.timeout)

    def _resolve_base_url(self, credentials: Credentials = None) -> str:
        scoped = credentials or {}
        url = scoped.get("base_url") or scoped.get("baseUrl") or self.base_url or ""
        return str(url).strip().rstrip("/")

    def _auth_headers(self, credentials: Credentials = None) -> dict[str, str]:
        scoped = credentials or {}
        auth_mode = str(scoped.get("auth_mode") or scoped.get("authMode") or "").strip().lower()
        bearer_value = (
            scoped.get("bearer") or scoped.get("bearer_token") or scoped.get("bearerToken") or self.bearer or ""
        )
        bearer = _string_value(bearer_value)
        email = _string_value(scoped.get("email") or self.email or "")
        api_token = _string_value(scoped.get("api_token") or scoped.get("apiToken") or self.api_token or "")

        if auth_mode in {"bearer", "sso"}:
            if not bearer:
                raise JiraError(f"Jira {auth_mode} auth requires bearer token")
            return {"Authorization": f"Bearer {bearer}"}
        if auth_mode == "api_token":
            if not (email and api_token):
                raise JiraError("Jira api_token auth requires email and api_token")
            token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
            return {"Authorization": f"Basic {token}"}

        if bearer:
            return {"Authorization": f"Bearer {bearer}"}
        if email and api_token:
            token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
            return {"Authorization": f"Basic {token}"}

        raise JiraError("No Jira credentials configured")

    def _headers(self, credentials: Credentials = None) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            **self._auth_headers(credentials),
        }

    def _build_url(self, path: str, credentials: Credentials = None) -> str:
        base_url = self._resolve_base_url(credentials)
        if not is_safe_http_url(base_url):
            raise JiraError("JIRA_BASE_URL not configured or invalid")
        return f"{base_url}{path}"

    async def _request(self, request: JiraRequest) -> JSONValue:
        url = self._build_url(request.path, request.credentials)
        headers = self._headers(request.credentials)
        try:
            if request.method == "GET":
                response = await self._client.get(url, headers=headers, params=request.params)
            else:
                response = await self._client.post(url, json=request.payload, headers=headers)
            response.raise_for_status()
            result = response.json() if response.content else {}
            return result
        except httpx.HTTPStatusError as exc:
            logger.warning("Jira %s failed: %s %s", request.method, exc.response.status_code, exc.response.text[:240])
            detail = (exc.response.text or "").strip()
            if detail:
                raise JiraError(f"Jira API error: {exc.response.status_code} - {detail[:240]}") from exc
            raise JiraError(f"Jira API error: {exc.response.status_code}") from exc
        except httpx.TimeoutException as exc:
            host = urlparse(url).netloc or "jira"
            logger.warning("Jira %s timeout contacting %s", request.method, host)
            raise JiraError(f"Jira request timed out while contacting {host}") from exc
        except httpx.RequestError as exc:
            host = urlparse(url).netloc or "jira"
            logger.warning("Jira %s connection failure contacting %s: %s", request.method, host, exc)
            raise JiraError(f"Unable to connect to Jira host {host}") from exc
        except RuntimeError as exc:
            host = urlparse(url).netloc or "jira"
            logger.warning("Jira %s runtime transport failure contacting %s: %s", request.method, host, exc)
            raise JiraError(f"Unable to connect to Jira host {host}") from exc
        except JiraError:
            raise
        except Exception as exc:
            logger.exception("Unexpected Jira %s error", request.method)
            raise JiraError("Failed to contact Jira API") from exc

    async def _get(self, path: str, credentials: Credentials = None, params: QueryParams | None = None) -> JSONValue:
        return await self._request(JiraRequest(method="GET", path=path, credentials=credentials, params=params))

    async def _post(self, path: str, payload: JSONDict, credentials: Credentials = None) -> JSONValue:
        return await self._request(JiraRequest(method="POST", path=path, credentials=credentials, payload=payload))

    async def create_issue(self, request: JiraIssueCreateRequest) -> JSONDict:
        issue_options = _coerce_issue_options(request.options)
        fields: JSONDict = {
            "project": {"key": request.project_key},
            "summary": request.summary,
            "description": issue_options.description or "",
            "issuetype": {"name": issue_options.issue_type},
        }
        if issue_options.priority:
            fields["priority"] = {"name": str(issue_options.priority).strip()}
        payload: JSONDict = {"fields": fields}
        data = await self._post("/rest/api/2/issue", payload, request.credentials)
        data_dict = _json_dict(data)
        key = data_dict.get("key")
        base_url = self._resolve_base_url(request.credentials)
        return {
            "key": key,
            "url": f"{base_url}/browse/{key}" if key else None,
            "raw": data_dict,
        }

    async def list_projects(self, credentials: Credentials = None) -> list[dict[str, str]]:
        data = await self._get("/rest/api/2/project", credentials)
        return [
            {"key": key, "name": str(p.get("name") or key).strip()}
            for p in _json_dict_list(data)
            if (key := str(p.get("key") or "").strip())
        ]

    async def list_issue_types(self, project_key: str, credentials: Credentials = None) -> list[str]:
        project = await self._get(f"/rest/api/2/project/{project_key}", credentials)
        issue_types = _json_dict(project).get("issueTypes")
        return [name for it in _json_dict_list(issue_types) if (name := str(it.get("name") or "").strip())]

    async def list_transitions(self, issue_key: str, credentials: Credentials = None) -> list[JSONDict]:
        data = await self._get(f"/rest/api/2/issue/{issue_key}/transitions", credentials)
        transitions = data.get("transitions") if isinstance(data, dict) else []
        return [item for item in (transitions or []) if isinstance(item, dict)]

    async def transition_issue(
        self,
        issue_key: str,
        transition_id: str,
        credentials: Credentials = None,
    ) -> JSONDict:
        return _json_dict(
            await self._post(
                f"/rest/api/2/issue/{issue_key}/transitions",
                {"transition": {"id": str(transition_id)}},
                credentials,
            )
        )

    async def transition_issue_to_todo(self, issue_key: str, credentials: Credentials = None) -> bool:
        return await self._transition_issue_by_target(
            issue_key,
            JiraTransitionTarget(
                target_names={"to do", "todo"},
                transition_names={"to do", "todo"},
                status_category_key="new",
            ),
            credentials,
        )

    async def transition_issue_to_in_progress(self, issue_key: str, credentials: Credentials = None) -> bool:
        return await self._transition_issue_by_target(
            issue_key,
            JiraTransitionTarget(
                target_names={"in progress", "in-progress", "doing"},
                transition_names={"start progress", "in progress", "start"},
                status_category_key="indeterminate",
            ),
            credentials,
        )

    async def transition_issue_to_done(self, issue_key: str, credentials: Credentials = None) -> bool:
        return await self._transition_issue_by_target(
            issue_key,
            JiraTransitionTarget(
                target_names={"done", "closed", "resolved"},
                transition_names={"done", "close issue", "resolve issue", "resolve"},
                status_category_key="done",
            ),
            credentials,
        )

    async def _transition_issue_by_target(
        self,
        issue_key: str,
        target: JiraTransitionTarget,
        credentials: Credentials = None,
    ) -> bool:
        transitions = await self.list_transitions(issue_key, credentials)
        if not transitions:
            return False

        def _name(item: JSONDict) -> str:
            return str(item.get("name") or "").strip().lower()

        def _target_name(item: JSONDict) -> str:
            raw_to = item.get("to")
            to_obj: JSONDict = raw_to if isinstance(raw_to, dict) else {}
            return str(to_obj.get("name") or "").strip().lower()

        def _status_category(item: JSONDict) -> str:
            raw_to = item.get("to")
            to_obj: JSONDict = raw_to if isinstance(raw_to, dict) else {}
            raw_category = to_obj.get("statusCategory")
            category: JSONDict = raw_category if isinstance(raw_category, dict) else {}
            return str(category.get("key") or "").strip().lower()

        preferred: JSONDict | None = next(
            (item for item in transitions if _target_name(item) in target.target_names),
            None,
        )
        if not preferred:
            preferred = next(
                (item for item in transitions if _name(item) in target.transition_names),
                None,
            )
        if not preferred:
            preferred = next(
                (item for item in transitions if _status_category(item) == target.status_category_key),
                None,
            )
        if not preferred:
            return False

        transition_id = str(preferred.get("id") or "").strip()
        if not transition_id:
            return False
        await self.transition_issue(issue_key, transition_id, credentials)
        return True

    async def add_comment(self, issue_key: str, text: str, credentials: Credentials = None) -> JSONDict:
        return _json_dict(await self._post(f"/rest/api/2/issue/{issue_key}/comment", {"body": text}, credentials))

    async def list_comments(self, issue_key: str, credentials: Credentials = None) -> list[JSONDict]:
        data = await self._get(f"/rest/api/2/issue/{issue_key}/comment", credentials)
        comments = _json_dict(data).get("comments")
        return [
            {
                "id": str(item.get("id") or ""),
                "author": _extract_display_name(item.get("author")),
                "body": str(item.get("body") or ""),
                "created": item.get("created"),
            }
            for item in _json_dict_list(comments)
        ]


def _extract_display_name(author: object) -> str:
    if not isinstance(author, dict):
        return "jira"
    return str(author.get("displayName") or author.get("name") or "jira")


jira_service = JiraService()
