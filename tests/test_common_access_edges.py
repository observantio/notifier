"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from services.common import access


class FakeQuery:
    def __init__(self, groups):
        self.groups = groups

    def filter(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self.groups)


class FakeDB:
    def __init__(self, groups=None, flush_error: Exception | None = None):
        self.groups = list(groups or [])
        self.flush_error = flush_error
        self.added: list[object] = []
        self.rolled_back = False
        self.query_calls = 0

    def query(self, *_args, **_kwargs):
        self.query_calls += 1
        if self.query_calls == 1:
            return FakeQuery(self.groups)
        full_groups = self.groups + [
            SimpleNamespace(id=item.id, tenant_id=item.tenant_id, name=item.name) for item in self.added
        ]
        return FakeQuery(full_groups)

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        if self.flush_error is not None:
            raise self.flush_error

    def rollback(self):
        self.rolled_back = True


def test_resolve_groups_handles_empty_missing_and_membership_paths():
    db = FakeDB(groups=[])
    assert access._resolve_groups(db, access.GroupResolveRequest(tenant_id="tenant", group_ids=[])) == []

    existing = [SimpleNamespace(id="g1", tenant_id="tenant")]
    db = FakeDB(groups=existing)
    groups = access._resolve_groups(
        db,
        access.GroupResolveRequest(tenant_id="tenant", group_ids=[" g1 ", None, ""], actor_group_ids=["g1"]),
    )
    assert [group.id for group in groups] == ["g1"]

    db = FakeDB(groups=[])
    groups = access._resolve_groups(
        db,
        access.GroupResolveRequest(tenant_id="tenant", group_ids=["g2"], actor_group_ids=["g2"]),
    )
    assert [group.id for group in groups] == ["g2"]
    assert len(db.added) == 1

    db = FakeDB(groups=[], flush_error=IntegrityError("stmt", {}, Exception("boom")))
    groups = access._resolve_groups(
        db,
        access.GroupResolveRequest(tenant_id="tenant", group_ids=["g3"], actor_group_ids=["g3"]),
    )
    assert [group.id for group in groups] == ["g3"]
    assert db.rolled_back is True

    db = FakeDB(groups=[SimpleNamespace(id="g4", tenant_id="tenant")])
    with pytest.raises(HTTPException) as exc:
        access._resolve_groups(
            db,
            access.GroupResolveRequest(tenant_id="tenant", group_ids=["g4"], actor_group_ids=["other"]),
        )
    assert exc.value.status_code == 403

    db = FakeDB(groups=[SimpleNamespace(id="g5", tenant_id="tenant")])
    groups = access._resolve_groups(
        db,
        access.GroupResolveRequest(
            tenant_id="tenant",
            group_ids=["g5"],
            actor_group_ids=[],
            enforce_membership=False,
        ),
    )
    assert [group.id for group in groups] == ["g5"]


def test_assign_shared_groups_and_access_matrix(monkeypatch):
    resolved = [SimpleNamespace(id="g1")]
    monkeypatch.setattr(access, "_resolve_groups", lambda *_args, **_kwargs: resolved)
    obj = SimpleNamespace(shared_groups=["old"])

    access.assign_shared_groups(
        obj,
        "db",
        access.SharedGroupAssignment(
            tenant_id="tenant",
            visibility="private",
            group_ids=["g1"],
            actor_group_ids=["g1"],
        ),
    )
    assert obj.shared_groups == []

    with pytest.raises(ValueError):
        access.assign_shared_groups(
            obj,
            "db",
            access.SharedGroupAssignment(
                tenant_id="tenant",
                visibility="group",
                group_ids=None,
                actor_group_ids=["g1"],
            ),
        )

    access.assign_shared_groups(
        obj,
        "db",
        access.SharedGroupAssignment(
            tenant_id="tenant",
            visibility="group",
            group_ids=["g1"],
            actor_group_ids=["g1"],
        ),
    )
    assert obj.shared_groups == resolved

    assert access.has_access(access.AccessCheck("private", "u1", "u1", [], [])) is True
    assert access.has_access(access.AccessCheck("tenant", "owner", "u2", [], [], require_write=False)) is True
    assert access.has_access(access.AccessCheck("tenant", "owner", "u2", [], [], require_write=True)) is False
    assert access.has_access(access.AccessCheck("group", "owner", "u2", ["g1"], ["g1"])) is True
    assert access.has_access(access.AccessCheck("group", "owner", "u2", ["g1"], ["g2"])) is False
    assert access.has_access(access.AccessCheck("private", "owner", "u2", [], [])) is False
    assert access.has_access(access.AccessCheck("mystery", "owner", "u2", [], [])) is False
