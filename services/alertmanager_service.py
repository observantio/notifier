"""
Service for managing interactions with AlertManager, providing functions to retrieve and manage alerts, silences, and
notification channels.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import json
import logging
from collections.abc import Awaitable, Callable
from hmac import compare_digest
from typing import Any, Dict, List, Optional

import httpx

from fastapi import HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError

from config import config
from database import get_db_session
from db_models import PurgedSilence
from middleware.dependencies import enforce_public_endpoint_security
from middleware.resilience import with_retry, with_timeout
from models.access.auth_models import TokenData
from models.alerting.alerts import Alert
from models.alerting.rules import AlertRule
from models.alerting.silences import Silence
from services.alerting.alerts_ops import (
    delete_alerts as delete_alerts_ops,
    evaluate_promql as evaluate_promql_ops,
    get_alert_groups as get_alert_groups_ops,
    get_alerts as get_alerts_ops,
    list_label_names as list_label_names_ops,
    list_label_values as list_label_values_ops,
    list_metric_names as list_metric_names_ops,
    post_alerts as post_alerts_ops,
)
from services.alerting.channels_ops import (
    get_receivers as get_receivers_ops,
    get_status as get_status_ops,
    notify_for_alerts as notify_for_alerts_ops,
)
from services.alerting.ruler_yaml import (
    build_ruler_group_yaml,
    extract_mimir_group_names,
    group_enabled_rules,
    yaml_quote,
)
from services.alerting.rules_ops import (
    resolve_rule_org_id as resolve_rule_org_id_ops,
    sync_mimir_rules_for_org as sync_mimir_rules_for_org_ops,
)
from services.alerting.silence_metadata import (
    decode_silence_comment as decode_silence_comment_ops,
    encode_silence_comment as encode_silence_comment_ops,
    normalize_visibility as normalize_visibility_ops,
)
from services.alerting.silences_ops import (
    apply_silence_metadata as apply_silence_metadata_ops,
    create_silence as create_silence_ops,
    delete_silence as delete_silence_ops,
    get_silence as get_silence_ops,
    get_silences as get_silences_ops,
    prune_removed_member_group_silences as prune_removed_member_group_silences_ops,
    silence_accessible as silence_accessible_ops,
    silence_owned_by as silence_owned_by_ops,
    update_silence as update_silence_ops,
)
from services.common.http_client import create_async_client

logger = logging.getLogger(__name__)

_AsyncOp = Callable[..., Awaitable[Any]]

_ALERTMANAGER_ASYNC_OPS: dict[str, _AsyncOp] = {
    "notify_for_alerts": notify_for_alerts_ops,
    "list_metric_names": list_metric_names_ops,
    "list_label_names": list_label_names_ops,
    "list_label_values": list_label_values_ops,
    "evaluate_promql": evaluate_promql_ops,
    "sync_mimir_rules_for_org": sync_mimir_rules_for_org_ops,
    "get_alert_groups": get_alert_groups_ops,
    "post_alerts": post_alerts_ops,
    "delete_alerts": delete_alerts_ops,
    "get_silences": get_silences_ops,
    "get_silence": get_silence_ops,
    "create_silence": create_silence_ops,
    "update_silence": update_silence_ops,
    "prune_removed_member_group_silences": prune_removed_member_group_silences_ops,
    "get_status": get_status_ops,
    "get_receivers": get_receivers_ops,
}

LABELS_JSON_ERROR = "Invalid filter_labels JSON"
MIMIR_RULES_NAMESPACE = "watchdog"
MIMIR_RULER_CONFIG_BASEPATH = "/prometheus/config/v1/rules"


class AlertManagerService:
    def __init__(self, alertmanager_url: str = config.alertmanager_url) -> None:
        self.mimir_rules_namespace = MIMIR_RULES_NAMESPACE
        self.mimir_ruler_config_basepath = MIMIR_RULER_CONFIG_BASEPATH
        self.alertmanager_url = alertmanager_url.rstrip("/")
        self.timeout = config.default_timeout
        self.logger = logger
        self._client = create_async_client(self.timeout)
        self._mimir_client = create_async_client(self.timeout)

    @property
    def alertmanager_http_client(self) -> httpx.AsyncClient:
        return self._client

    @property
    def mimir_http_client(self) -> httpx.AsyncClient:
        return self._mimir_client

    def parse_filter_labels(self, filter_labels: Optional[str]) -> Optional[Dict[str, str]]:
        if not filter_labels:
            return None
        try:
            parsed = json.loads(filter_labels)
        except json.JSONDecodeError as exc:
            raise ValueError(LABELS_JSON_ERROR) from exc
        if not isinstance(parsed, dict):
            raise ValueError(LABELS_JSON_ERROR)
        return {str(k): str(v) for k, v in parsed.items()}

    def user_scope(self, current_user: TokenData) -> tuple[str, str, List[str]]:
        return (
            current_user.tenant_id,
            current_user.user_id,
            getattr(current_user, "group_ids", []) or [],
        )

    def enforce_webhook_security(self, request: Request, *, scope: str) -> None:
        enforce_public_endpoint_security(
            request,
            scope=scope,
            limit=config.rate_limit_public_per_minute,
            window_seconds=60,
            allowlist=config.webhook_ip_allowlist,
        )
        expected = config.inbound_webhook_token
        if not expected:
            if config.is_production:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="INBOUND_WEBHOOK_TOKEN is required in production",
                )
            return
        provided_header = request.headers.get("x-watchdog-webhook-token")
        if provided_header and compare_digest(provided_header, expected):
            return
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer = auth_header.split(" ", 1)[1].strip()
            if bearer and compare_digest(bearer, expected):
                return
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token")

    def normalize_visibility(self, value: Optional[str]) -> str:
        return normalize_visibility_ops(value)

    def encode_silence_comment(self, comment: str, visibility: str, shared_group_ids: List[str]) -> str:
        return encode_silence_comment_ops(comment, visibility, shared_group_ids)

    def decode_silence_comment(self, comment: Optional[str]) -> Dict[str, object]:
        return decode_silence_comment_ops(comment)

    def apply_silence_metadata(self, silence: Silence) -> Silence:
        return apply_silence_metadata_ops(self, silence)

    def silence_accessible(self, silence: Silence, current_user: TokenData) -> bool:
        return silence_accessible_ops(silence, current_user)

    def silence_owned_by(self, silence: Silence, current_user: TokenData) -> bool:
        return silence_owned_by_ops(silence, current_user)

    def resolve_rule_org_id(self, rule_org_id: Optional[str], current_user: TokenData) -> str:
        return resolve_rule_org_id_ops(rule_org_id, current_user)

    def _yaml_quote(self, value: object) -> str:
        return yaml_quote(value)

    def _group_enabled_rules(self, rules: List[AlertRule]) -> Dict[str, List[AlertRule]]:
        return group_enabled_rules(rules)

    def _build_ruler_group_yaml(self, group_name: str, rules: List[AlertRule]) -> str:
        return build_ruler_group_yaml(group_name, rules)

    def _extract_mimir_group_names(self, namespace_yaml: str) -> List[str]:
        return extract_mimir_group_names(namespace_yaml)

    def __getattr__(self, name: str) -> Any:
        op = _ALERTMANAGER_ASYNC_OPS.get(name)
        if op is None:
            raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

        async def _async_bound(*args: object, **kwargs: object) -> Any:
            return await op(self, *args, **kwargs)

        return _async_bound

    @with_retry()
    @with_timeout()
    async def get_alerts(
        self,
        filter_labels: Optional[Dict[str, str]] = None,
        active: Optional[bool] = None,
        silenced: Optional[bool] = None,
        inhibited: Optional[bool] = None,
    ) -> List[Alert]:
        return await get_alerts_ops(self, filter_labels, active, silenced, inhibited)

    async def delete_silence(self, silence_id: str) -> bool:
        if not await delete_silence_ops(self, silence_id):
            return False
        try:
            with get_db_session() as db:
                if not db.query(PurgedSilence).filter_by(id=silence_id).first():
                    db.add(PurgedSilence(id=silence_id, tenant_id=None))
                    db.commit()
                    logger.info("Purged silence %s persisted to DB", silence_id)
        except SQLAlchemyError as exc:
            logger.warning("Failed to persist purged silence %s: %s", silence_id, exc)
        return True
