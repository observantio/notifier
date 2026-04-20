"""
Rules management service for handling alert rules, including CRUD operations, access control, and visibility management.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import joinedload

from database import get_db_session
from db_models import AlertRule as AlertRuleDB
from db_models import HiddenAlertRule
from models.alerting.rules import AlertRule, AlertRuleCreate
from services.common.access import AccessCheck, SharedGroupAssignment, assign_shared_groups, has_access
from services.common.pagination import cap_pagination
from services.common.tenants import ensure_tenant_exists
from services.storage.serializers import rule_to_pydantic

logger = logging.getLogger(__name__)


def _shared_group_ids(db_obj: AlertRuleDB) -> list[str]:
    return [g.id for g in db_obj.shared_groups] if db_obj.shared_groups else []


def _visibility_of(rule: AlertRuleDB) -> str:
    return str(rule.visibility or "private")


def _creator_of(rule: AlertRuleDB) -> str:
    return str(rule.created_by or "")


@dataclass(frozen=True)
class RuleAccessContext:
    user_id: str
    group_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PageRequest:
    limit: int | None = None
    offset: int = 0


class RuleStorageService:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        return

    @staticmethod
    def _access_context(
        access: RuleAccessContext | str,
        group_ids: list[str] | None = None,
    ) -> RuleAccessContext:
        if isinstance(access, RuleAccessContext):
            return access
        return RuleAccessContext(user_id=str(access), group_ids=list(group_ids or []))

    @staticmethod
    def _page_request(value: PageRequest | list[str] | None) -> PageRequest:
        if isinstance(value, PageRequest):
            return value
        return PageRequest()

    @staticmethod
    def get_alert_rule_by_name_for_delivery(
        tenant_id: str,
        rule_name: str,
        org_id: str | None = None,
    ) -> AlertRule | None:
        target_name = str(rule_name or "").strip()
        if not target_name:
            return None
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id, AlertRuleDB.name == target_name)
                .all()
            )
            if not rules:
                return None
            if org_id:
                org_matched = [r for r in rules if str(getattr(r, "org_id", "") or "") == str(org_id)]
                rules = org_matched or [r for r in rules if not getattr(r, "org_id", None)] or rules
            return rule_to_pydantic(rules[0])

    @staticmethod
    def get_hidden_rule_ids(tenant_id: str, user_id: str) -> list[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenAlertRule.rule_id)
                .filter(
                    HiddenAlertRule.tenant_id == tenant_id,
                    HiddenAlertRule.user_id == user_id,
                )
                .all()
            )
            return [str(rule_id) for (rule_id,) in rows]

    @staticmethod
    def get_hidden_rule_names(tenant_id: str, user_id: str) -> list[str]:
        with get_db_session() as db:
            rows = (
                db.query(AlertRuleDB.name)
                .join(HiddenAlertRule, HiddenAlertRule.rule_id == AlertRuleDB.id)
                .filter(
                    HiddenAlertRule.tenant_id == tenant_id,
                    HiddenAlertRule.user_id == user_id,
                    AlertRuleDB.tenant_id == tenant_id,
                )
                .all()
            )
            return [str(name) for (name,) in rows if str(name or "").strip()]

    @staticmethod
    def toggle_rule_hidden(tenant_id: str, user_id: str, rule_id: str, hidden: bool) -> bool:
        with get_db_session() as db:
            rule = (
                db.query(AlertRuleDB)
                .filter(
                    AlertRuleDB.id == rule_id,
                    AlertRuleDB.tenant_id == tenant_id,
                )
                .first()
            )
            if not rule:
                return False

            existing = (
                db.query(HiddenAlertRule)
                .filter(
                    HiddenAlertRule.tenant_id == tenant_id,
                    HiddenAlertRule.user_id == user_id,
                    HiddenAlertRule.rule_id == rule_id,
                )
                .first()
            )

            if hidden:
                if not existing:
                    db.add(
                        HiddenAlertRule(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            rule_id=rule_id,
                        )
                    )
            else:
                if existing:
                    db.delete(existing)
            return True

    @staticmethod
    def get_public_alert_rules(tenant_id: str) -> list[AlertRule]:
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(
                    AlertRuleDB.tenant_id == tenant_id,
                    AlertRuleDB.visibility == "public",
                    AlertRuleDB.enabled.is_(True),
                )
                .all()
            )
            return [rule_to_pydantic(r) for r in rules]

    @staticmethod
    def get_alert_rules(
        tenant_id: str,
        access: RuleAccessContext | str,
        page_or_group_ids: PageRequest | list[str] | None = None,
    ) -> list[AlertRule]:
        context = RuleStorageService._access_context(
            access,
            group_ids=page_or_group_ids if isinstance(page_or_group_ids, list) else None,
        )
        group_ids = list(context.group_ids or [])
        paging = RuleStorageService._page_request(page_or_group_ids)
        capped_limit, capped_offset = cap_pagination(paging.limit, paging.offset)

        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .offset(capped_offset)
                .limit(capped_limit)
                .all()
            )
            out: list[AlertRule] = []
            for r in rules:
                if has_access(
                    AccessCheck(
                        visibility=_visibility_of(r),
                        created_by=_creator_of(r),
                        user_id=context.user_id,
                        shared_group_ids=_shared_group_ids(r),
                        user_group_ids=group_ids,
                    )
                ):
                    out.append(rule_to_pydantic(r))
            return out

    @staticmethod
    def get_alert_rules_for_org(tenant_id: str, org_id: str) -> list[AlertRule]:
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id, AlertRuleDB.org_id == org_id)
                .all()
            )
            return [rule_to_pydantic(r) for r in rules]

    @staticmethod
    def get_alert_rules_with_owner(
        tenant_id: str,
        access: RuleAccessContext | str,
        page_or_group_ids: PageRequest | list[str] | None = None,
    ) -> list[tuple[AlertRule, str]]:
        context = RuleStorageService._access_context(
            access,
            group_ids=page_or_group_ids if isinstance(page_or_group_ids, list) else None,
        )
        group_ids = list(context.group_ids or [])
        paging = RuleStorageService._page_request(page_or_group_ids)
        capped_limit, capped_offset = cap_pagination(paging.limit, paging.offset)

        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .offset(capped_offset)
                .limit(capped_limit)
                .all()
            )

            out: list[tuple[AlertRule, str]] = []
            for r in rules:
                if has_access(
                    AccessCheck(
                        visibility=_visibility_of(r),
                        created_by=_creator_of(r),
                        user_id=context.user_id,
                        shared_group_ids=_shared_group_ids(r),
                        user_group_ids=group_ids,
                    )
                ):
                    out.append((rule_to_pydantic(r), _creator_of(r)))
            return out

    @staticmethod
    def get_alert_rule_raw(rule_id: str, tenant_id: str) -> AlertRuleDB | None:
        with get_db_session() as db:
            return (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )

    @staticmethod
    def get_alert_rule(
        rule_id: str,
        tenant_id: str,
        access: RuleAccessContext | str,
        group_ids: list[str] | None = None,
    ) -> AlertRule | None:
        context = RuleStorageService._access_context(access, group_ids=group_ids)
        group_ids = list(context.group_ids or [])
        with get_db_session() as db:
            r = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )
            if not r:
                return None
            if not has_access(
                    AccessCheck(
                        visibility=_visibility_of(r),
                        created_by=_creator_of(r),
                        user_id=context.user_id,
                        shared_group_ids=_shared_group_ids(r),
                        user_group_ids=group_ids,
                )
            ):
                return None
            return rule_to_pydantic(r)

    @staticmethod
    def create_alert_rule(
        rule_create: AlertRuleCreate,
        tenant_id: str,
        access: RuleAccessContext | str,
        group_ids: list[str] | None = None,
    ) -> AlertRule:
        context = RuleStorageService._access_context(access, group_ids=group_ids)
        with get_db_session() as db:
            ensure_tenant_exists(db, tenant_id)
            rule = AlertRuleDB(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                created_by=context.user_id,
                org_id=rule_create.org_id or None,
                name=rule_create.name,
                group=rule_create.group,
                expr=rule_create.expr,
                duration=rule_create.duration,
                severity=rule_create.severity,
                labels=rule_create.labels or {},
                annotations=rule_create.annotations or {},
                enabled=rule_create.enabled,
                notification_channels=rule_create.notification_channels or [],
                visibility=rule_create.visibility or "private",
            )
            assign_shared_groups(
                rule,
                db,
                SharedGroupAssignment(
                    tenant_id=tenant_id,
                    visibility=_visibility_of(rule),
                    group_ids=rule_create.shared_group_ids,
                    actor_group_ids=context.group_ids,
                ),
            )
            db.add(rule)
            db.flush()
            logger.info(
                "Created alert rule %s (%s) org_id=%s visibility=%s", rule.name, rule.id, rule.org_id, rule.visibility
            )
            return rule_to_pydantic(rule)

    @staticmethod
    def update_alert_rule(
        rule_id: str,
        rule_update: AlertRuleCreate,
        tenant_id: str,
        access: RuleAccessContext | str,
        group_ids: list[str] | None = None,
    ) -> AlertRule | None:
        context = RuleStorageService._access_context(access, group_ids=group_ids)
        group_ids = list(context.group_ids or [])
        with get_db_session() as db:
            r = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )
            if not r:
                return None
            if not has_access(
                    AccessCheck(
                        visibility=_visibility_of(r),
                        created_by=_creator_of(r),
                        user_id=context.user_id,
                        shared_group_ids=_shared_group_ids(r),
                        user_group_ids=group_ids,
                )
            ):
                return None
            if not has_access(
                    AccessCheck(
                        visibility=_visibility_of(r),
                        created_by=_creator_of(r),
                        user_id=context.user_id,
                        shared_group_ids=_shared_group_ids(r),
                        user_group_ids=group_ids,
                    require_write=True,
                )
            ):
                return None

            r.org_id = rule_update.org_id or None
            r.name = rule_update.name
            r.group = rule_update.group
            r.expr = rule_update.expr
            r.duration = rule_update.duration or "5m"
            r.severity = rule_update.severity
            r.labels = {str(key): value for key, value in (rule_update.labels or {}).items()}
            r.annotations = {str(key): value for key, value in (rule_update.annotations or {}).items()}
            r.enabled = rule_update.enabled
            r.notification_channels = [str(channel) for channel in (rule_update.notification_channels or [])]
            r.visibility = rule_update.visibility or "private"

            assign_shared_groups(
                r,
                db,
                SharedGroupAssignment(
                    tenant_id=tenant_id,
                    visibility=_visibility_of(r),
                    group_ids=rule_update.shared_group_ids,
                    actor_group_ids=group_ids,
                ),
            )
            db.flush()
            logger.info("Updated alert rule %s (%s) org_id=%s", r.name, rule_id, r.org_id)
            return rule_to_pydantic(r)

    @staticmethod
    def delete_alert_rule(
        rule_id: str,
        tenant_id: str,
        access: RuleAccessContext | str,
        group_ids: list[str] | None = None,
    ) -> bool:
        context = RuleStorageService._access_context(access, group_ids=group_ids)
        group_ids = list(context.group_ids or [])
        with get_db_session() as db:
            r = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )
            if not r:
                return False
            if not has_access(
                    AccessCheck(
                        visibility=_visibility_of(r),
                        created_by=_creator_of(r),
                        user_id=context.user_id,
                        shared_group_ids=_shared_group_ids(r),
                        user_group_ids=group_ids,
                    require_write=True,
                )
            ):
                return False
            db.delete(r)
            logger.info("Deleted alert rule %s", rule_id)
            return True
