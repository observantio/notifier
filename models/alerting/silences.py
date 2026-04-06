"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, StrictBool

DESC_LABEL_NAME_MATCH = "Label name to match"
DESC_VALUE_MATCH_AGAINST = "Value to match against"
DESC_VALUE_IS_REGEX = "Whether the value is a regular expression"
DESC_MATCH_EQUAL_VALUES = "Whether to match equal values"
DESC_UNIQUE_IDENTIFIER_SILENCE = "Unique identifier for the silence"
DESC_MATCHERS_DEFINE_SILENCE = "Matchers that define which alerts to silence"
DESC_TIME_SILENCE_STARTS = "Time when the silence starts"
DESC_TIME_SILENCE_ENDS = "Time when the silence ends"
DESC_USER_CREATED_SILENCE = "User who created the silence"
DESC_COMMENT_EXPLAINING_SILENCE = "Comment explaining the silence"
DESC_CURRENT_STATUS_SILENCE = "Current status of the silence"
DESC_VISIBILITY_SCOPE = "Visibility scope"
DESC_GROUP_IDS_SILENCE_SHARED_WITH = "Group IDs this silence is shared with"
DESC_GROUP_IDS_SHARE_WITH = "Group IDs to share with"


class Visibility(str, Enum):
    PRIVATE = "private"
    GROUP = "group"
    TENANT = "tenant"
    PUBLIC = "public"


class Matcher(BaseModel):
    name: str = Field(..., description=DESC_LABEL_NAME_MATCH, examples=["alertname"])
    value: str = Field(..., description=DESC_VALUE_MATCH_AGAINST, examples=["HighCpuUsage"])
    is_regex: StrictBool = Field(False, alias="isRegex", description=DESC_VALUE_IS_REGEX, examples=[False])
    is_equal: StrictBool = Field(True, alias="isEqual", description=DESC_MATCH_EQUAL_VALUES, examples=[True])
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class Silence(BaseModel):
    id: str | None = Field(None, description=DESC_UNIQUE_IDENTIFIER_SILENCE, examples=["silence-123"])
    matchers: list[Matcher] = Field(
        ...,
        description=DESC_MATCHERS_DEFINE_SILENCE,
        examples=[[{"name": "alertname", "value": "HighCpuUsage", "isRegex": False, "isEqual": True}]],
    )
    starts_at: str = Field(
        ..., alias="startsAt", description=DESC_TIME_SILENCE_STARTS, examples=["2026-04-03T12:00:00Z"]
    )
    ends_at: str = Field(..., alias="endsAt", description=DESC_TIME_SILENCE_ENDS, examples=["2026-04-03T13:00:00Z"])
    created_by: str = Field(..., alias="createdBy", description=DESC_USER_CREATED_SILENCE, examples=["user-42"])
    comment: str = Field(
        ...,
        description=DESC_COMMENT_EXPLAINING_SILENCE,
        examples=["Suppress noisy deploy alert while maintenance is in progress"],
    )
    status: dict[str, str] | None = Field(None, description=DESC_CURRENT_STATUS_SILENCE, examples=[{"state": "active"}])
    visibility: Visibility | None = Field(None, description=DESC_VISIBILITY_SCOPE, examples=["private"])
    shared_group_ids: list[str] = Field(
        default_factory=list,
        alias="sharedGroupIds",
        description=DESC_GROUP_IDS_SILENCE_SHARED_WITH,
        examples=[["group-ops"]],
    )
    is_hidden: bool = Field(
        False, alias="isHidden", description="Whether this silence is hidden for the current user", examples=[False]
    )
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)


class SilenceCreate(BaseModel):
    matchers: list[Matcher] = Field(
        ...,
        description=DESC_MATCHERS_DEFINE_SILENCE,
        examples=[[{"name": "alertname", "value": "HighCpuUsage", "isRegex": False, "isEqual": True}]],
    )
    starts_at: str = Field(
        ..., alias="startsAt", description=DESC_TIME_SILENCE_STARTS, examples=["2026-04-03T12:00:00Z"]
    )
    ends_at: str = Field(..., alias="endsAt", description=DESC_TIME_SILENCE_ENDS, examples=["2026-04-03T13:00:00Z"])
    created_by: str = Field(..., alias="createdBy", description=DESC_USER_CREATED_SILENCE, examples=["user-42"])
    comment: str = Field(
        ...,
        description=DESC_COMMENT_EXPLAINING_SILENCE,
        examples=["Suppress noisy deploy alert while maintenance is in progress"],
    )
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class SilenceCreateRequest(BaseModel):
    matchers: list[Matcher] = Field(
        ...,
        min_length=1,
        description=DESC_MATCHERS_DEFINE_SILENCE,
        examples=[[{"name": "alertname", "value": "HighCpuUsage", "isRegex": False, "isEqual": True}]],
    )
    starts_at: str = Field(
        ..., alias="startsAt", description=DESC_TIME_SILENCE_STARTS, examples=["2026-04-03T12:00:00Z"]
    )
    ends_at: str = Field(..., alias="endsAt", description=DESC_TIME_SILENCE_ENDS, examples=["2026-04-03T13:00:00Z"])
    comment: str = Field(
        ...,
        description=DESC_COMMENT_EXPLAINING_SILENCE,
        examples=["Suppress noisy deploy alert while maintenance is in progress"],
    )
    visibility: Visibility = Field(Visibility.PRIVATE, description=DESC_VISIBILITY_SCOPE, examples=["private"])
    shared_group_ids: list[str] = Field(
        default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_SHARE_WITH, examples=[["group-ops"]]
    )
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True, extra="forbid")
