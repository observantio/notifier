"""
Access control utilities for checking user permissions and resolving group memberships for tenant-based resources.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db_models import AlertRule, Group, NotificationChannel

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GroupResolveRequest:
    tenant_id: str
    group_ids: list[str]
    actor_group_ids: list[str] | None = None
    enforce_membership: bool = True


@dataclass(frozen=True)
class SharedGroupAssignment:
    tenant_id: str
    visibility: str
    group_ids: list[str] | None
    actor_group_ids: list[str] | None


@dataclass(frozen=True)
class AccessCheck:
    visibility: str
    created_by: str | None
    user_id: str
    shared_group_ids: list[str]
    user_group_ids: list[str]
    require_write: bool = False


def _resolve_groups(db: Session, request: GroupResolveRequest) -> list[Group]:
    tenant_id = request.tenant_id
    group_ids = request.group_ids
    normalized = [s for gid in (group_ids or []) if gid is not None and (s := str(gid).strip())]
    if not normalized:
        return []

    groups = db.query(Group).filter(Group.tenant_id == tenant_id, Group.id.in_(normalized)).all()
    present_ids = {g.id for g in groups}
    missing = [gid for gid in normalized if gid not in present_ids]
    if missing:
        logger.warning("Auto-creating missing group IDs for tenant %s: %s", tenant_id, missing)
        for gid in missing:
            db.add(
                Group(
                    id=gid,
                    tenant_id=tenant_id,
                    name=gid,
                    description="Auto-created placeholder group",
                    is_active=True,
                )
            )
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
        groups = db.query(Group).filter(Group.tenant_id == tenant_id, Group.id.in_(normalized)).all()
        present_ids = {g.id for g in groups}

    if request.enforce_membership:
        actor_groups = set(request.actor_group_ids or [])
        unauthorized = [gid for gid in normalized if gid in present_ids and gid not in actor_groups]
        if unauthorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not a member of one or more specified groups",
            )

    return groups


def assign_shared_groups(
    db_obj: AlertRule | NotificationChannel,
    db: Session,
    assignment: SharedGroupAssignment,
) -> None:
    if assignment.visibility != "group":
        db_obj.shared_groups = []
        return
    if assignment.group_ids is None:
        raise ValueError("group_ids is required when visibility is 'group'")
    db_obj.shared_groups = _resolve_groups(
        db,
        GroupResolveRequest(
            tenant_id=assignment.tenant_id,
            group_ids=assignment.group_ids,
            actor_group_ids=assignment.actor_group_ids,
        ),
    )


def has_access(check: AccessCheck) -> bool:
    if check.created_by == check.user_id:
        return True

    if check.require_write:
        return False

    if check.visibility in ("public", "tenant"):
        return True

    if check.visibility == "group":
        return bool(set(check.shared_group_ids) & set(check.user_group_ids))

    if check.visibility != "private":
        logger.warning("Unknown visibility value %r encountered in access check", check.visibility)
    return False
