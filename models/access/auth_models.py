"""
This module defines Pydantic models for authentication and authorization data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from enum import Enum

from pydantic import BaseModel, Field


class Role(str, Enum):
    PROVISIONING = "provisioning"
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class Permission(str, Enum):
    READ_ALERTS = "read:alerts"
    CREATE_ALERTS = "create:alerts"
    UPDATE_ALERTS = "update:alerts"
    WRITE_ALERTS = "write:alerts"
    DELETE_ALERTS = "delete:alerts"
    READ_RULES = "read:rules"
    CREATE_RULES = "create:rules"
    UPDATE_RULES = "update:rules"
    DELETE_RULES = "delete:rules"
    TEST_RULES = "test:rules"
    READ_METRICS = "read:metrics"
    READ_CHANNELS = "read:channels"
    CREATE_CHANNELS = "create:channels"
    UPDATE_CHANNELS = "update:channels"
    WRITE_CHANNELS = "write:channels"
    DELETE_CHANNELS = "delete:channels"
    TEST_CHANNELS = "test:channels"
    READ_SILENCES = "read:silences"
    CREATE_SILENCES = "create:silences"
    UPDATE_SILENCES = "update:silences"
    DELETE_SILENCES = "delete:silences"
    READ_INCIDENTS = "read:incidents"
    UPDATE_INCIDENTS = "update:incidents"
    MANAGE_TENANTS = "manage:tenants"


class TokenData(BaseModel):
    user_id: str
    username: str
    email: str | None = None
    tenant_id: str
    org_id: str
    role: Role
    is_superuser: bool = False
    permissions: list[str]
    group_ids: list[str] = Field(default_factory=list)
    is_mfa_setup: bool = False
