"""
Persistence for per-user hidden silences, channels, and Jira integration preferences.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from sqlalchemy.dialects.postgresql import insert as pg_insert

from database import get_db_session
from db_models import HiddenJiraIntegration, HiddenNotificationChannel, HiddenSilence
from services.storage.revocation import prune_removed_member_group_shares


class HiddenEntityStorageService:
    @staticmethod
    def get_hidden_silence_ids(tenant_id: str, user_id: str) -> list[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenSilence.silence_id)
                .filter(
                    HiddenSilence.tenant_id == tenant_id,
                    HiddenSilence.user_id == user_id,
                )
                .all()
            )
            return [str(silence_id) for (silence_id,) in rows]

    @staticmethod
    def toggle_silence_hidden(tenant_id: str, user_id: str, silence_id: str, hidden: bool) -> bool:
        with get_db_session() as db:
            existing = (
                db.query(HiddenSilence)
                .filter(
                    HiddenSilence.tenant_id == tenant_id,
                    HiddenSilence.user_id == user_id,
                    HiddenSilence.silence_id == silence_id,
                )
                .first()
            )

            if hidden:
                if not existing:
                    db.add(
                        HiddenSilence(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            silence_id=silence_id,
                        )
                    )
            else:
                if existing:
                    db.delete(existing)
            return True

    @staticmethod
    def get_hidden_channel_ids(tenant_id: str, user_id: str) -> list[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenNotificationChannel.channel_id)
                .filter(
                    HiddenNotificationChannel.tenant_id == tenant_id,
                    HiddenNotificationChannel.user_id == user_id,
                )
                .all()
            )
            return [str(channel_id) for (channel_id,) in rows]

    @staticmethod
    def toggle_channel_hidden(tenant_id: str, user_id: str, channel_id: str, hidden: bool) -> bool:
        with get_db_session() as db:
            existing = (
                db.query(HiddenNotificationChannel)
                .filter(
                    HiddenNotificationChannel.tenant_id == tenant_id,
                    HiddenNotificationChannel.user_id == user_id,
                    HiddenNotificationChannel.channel_id == channel_id,
                )
                .first()
            )
            if hidden:
                if not existing:
                    db.add(
                        HiddenNotificationChannel(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            channel_id=channel_id,
                        )
                    )
            else:
                if existing:
                    db.delete(existing)
            return True

    @staticmethod
    def prune_removed_member_group_shares(
        tenant_id: str,
        group_id: str,
        removed_user_ids: list[str] | None = None,
        removed_usernames: list[str] | None = None,
    ) -> dict[str, int]:
        with get_db_session() as db:
            return prune_removed_member_group_shares(
                db,
                tenant_id=tenant_id,
                group_id=group_id,
                removed_user_ids=removed_user_ids or [],
                removed_usernames=removed_usernames or [],
            )

    @staticmethod
    def get_hidden_jira_integration_ids(tenant_id: str, user_id: str) -> list[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenJiraIntegration.integration_id)
                .filter(
                    HiddenJiraIntegration.tenant_id == tenant_id,
                    HiddenJiraIntegration.user_id == user_id,
                )
                .all()
            )
            return [str(integration_id) for (integration_id,) in rows]

    @staticmethod
    def toggle_jira_integration_hidden(
        tenant_id: str,
        user_id: str,
        integration_id: str,
        hidden: bool,
    ) -> bool:
        with get_db_session() as db:
            if hidden:
                db.execute(
                    pg_insert(HiddenJiraIntegration)
                    .values(
                        tenant_id=tenant_id,
                        user_id=user_id,
                        integration_id=integration_id,
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            HiddenJiraIntegration.tenant_id,
                            HiddenJiraIntegration.user_id,
                            HiddenJiraIntegration.integration_id,
                        ]
                    )
                )
            else:
                existing = (
                    db.query(HiddenJiraIntegration)
                    .filter(
                        HiddenJiraIntegration.tenant_id == tenant_id,
                        HiddenJiraIntegration.user_id == user_id,
                        HiddenJiraIntegration.integration_id == integration_id,
                    )
                    .first()
                )
                if existing:
                    db.delete(existing)
            return True
