"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0 for details.
"""

from types import SimpleNamespace

from services.storage.channels import ChannelStorageService


def _group(group_id: str):
    return SimpleNamespace(id=group_id)


def test_group_rule_can_dispatch_private_channel():
    rule = SimpleNamespace(
        visibility="group",
        created_by="u1",
        shared_groups=[_group("g1")],
    )
    channel = SimpleNamespace(
        visibility="private",
        created_by="u1",
        shared_groups=[],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, channel) is True


def test_group_rule_dispatches_group_channel_with_overlap():
    rule = SimpleNamespace(
        visibility="group",
        created_by="u1",
        shared_groups=[_group("g1")],
    )
    channel = SimpleNamespace(
        visibility="group",
        created_by="u2",
        shared_groups=[_group("g1")],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, channel) is True


def test_group_rule_cannot_dispatch_group_channel_without_overlap():
    rule = SimpleNamespace(
        visibility="group",
        created_by="u1",
        shared_groups=[_group("g1")],
    )
    channel = SimpleNamespace(
        visibility="group",
        created_by="u2",
        shared_groups=[_group("g2")],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, channel) is False


def test_private_rule_cannot_dispatch_tenant_channel():
    rule = SimpleNamespace(
        visibility="private",
        created_by="u1",
        shared_groups=[],
    )
    channel = SimpleNamespace(
        visibility="tenant",
        created_by="u2",
        shared_groups=[],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, channel) is False


def test_public_rule_dispatches_private_group_and_public_channels():
    rule = SimpleNamespace(
        visibility="public",
        created_by="u1",
        shared_groups=[],
    )
    private_channel = SimpleNamespace(
        visibility="private",
        created_by="u2",
        shared_groups=[],
    )
    group_channel = SimpleNamespace(
        visibility="group",
        created_by="u2",
        shared_groups=[_group("g1")],
    )
    public_channel = SimpleNamespace(
        visibility="public",
        created_by="u2",
        shared_groups=[],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, private_channel) is True
    assert ChannelStorageService._rule_channel_compatible(rule, group_channel) is True
    assert ChannelStorageService._rule_channel_compatible(rule, public_channel) is True
