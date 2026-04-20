"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env
ensure_test_env()

import os

from cryptography.fernet import Fernet
import pytest

from config import config
from database import get_db_session
from db_models import NotificationChannel as NotificationChannelDB
from models.alerting.channels import ChannelType, NotificationChannelCreate
from services.common import encryption as encryption_module
from services.storage.channels import ChannelStorageService


@pytest.mark.skipif(
    os.getenv("MUTANT_UNDER_TEST") is not None,
    reason="Skip under mutmut due unstable crypto backend behavior in mutant execution environment.",
)
def test_encrypt_decrypt_config_roundtrip(monkeypatch):
    key = Fernet.generate_key().decode()
    prev = config.data_encryption_key
    try:
        config.data_encryption_key = key
        cfg = {"a": 1, "b": "s"}
        enc = encryption_module.encrypt_config(cfg)
        assert isinstance(enc, dict) and "__encrypted__" in enc
        dec = encryption_module.decrypt_config(enc)
        assert dec == cfg
    finally:
        config.data_encryption_key = prev

@pytest.mark.skipif(not __import__("database", fromlist=[""]).connection_test(), reason="DB not available")
def test_create_channel_stores_encrypted_and_owner_sees_config(monkeypatch):
    svc = ChannelStorageService()
    prev = config.data_encryption_key
    try:
        config.data_encryption_key = Fernet.generate_key().decode()
        ch_in = NotificationChannelCreate(
            name="c1", type=ChannelType.SLACK, config={"webhook_url": "https://x"}, enabled=True, visibility="private"
        )
        created = svc.create_notification_channel(ch_in, tenant_id="t-1", access="owner", group_ids=None)
        assert created.config == {"webhook_url": "https://x"}

        with get_db_session() as db:
            db_ch = db.query(NotificationChannelDB).filter(NotificationChannelDB.id == created.id).first()
            assert db_ch is not None
            assert isinstance(db_ch.config, dict)
            assert "__encrypted__" in db_ch.config
    finally:
        config.data_encryption_key = prev


import pytest


@pytest.mark.skipif(not __import__("database", fromlist=[""]).connection_test(), reason="DB not available")
def test_get_notification_channel_access_control():
    svc = ChannelStorageService()
    ch_in = NotificationChannelCreate(
        name="c2", type=ChannelType.SLACK, config={"webhook_url": "https://x"}, enabled=True, visibility="private"
    )
    created = svc.create_notification_channel(ch_in, tenant_id="t-2", access="owner2", group_ids=None)
    fetched = svc.get_notification_channel(created.id, tenant_id="t-2", access="someone_else", group_ids=None)
    assert fetched is None
    fetched_owner = svc.get_notification_channel(created.id, tenant_id="t-2", access="owner2", group_ids=None)
    assert fetched_owner is not None
    assert fetched_owner.config == {"webhook_url": "https://x"}


@pytest.mark.skipif(not __import__("database", fromlist=[""]).connection_test(), reason="DB not available")
def test_channel_update_delete_require_owner():
    svc = ChannelStorageService()
    ch_in = NotificationChannelCreate(
        name="shared-ch",
        type=ChannelType.SLACK,
        config={"webhook_url": "https://x"},
        enabled=True,
        visibility="tenant",
    )
    created = svc.create_notification_channel(ch_in, tenant_id="t-3", access="owner3", group_ids=None)
    updated = svc.update_notification_channel(
        created.id,
        NotificationChannelCreate(
            name="mutated",
            type=ChannelType.SLACK,
            config={"webhook_url": "https://mutated"},
            enabled=True,
            visibility="tenant",
        ),
        tenant_id="t-3",
        access="viewer3",
        group_ids=None,
    )
    assert updated is None
    assert svc.delete_notification_channel(created.id, tenant_id="t-3", access="viewer3") is False
