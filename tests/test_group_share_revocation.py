"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import json
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/observantio_test")

from db_models import AlertIncident, AlertRule, Base, Group, NotificationChannel, Tenant
from services.common.meta import INCIDENT_META_KEY, parse_meta
from services.storage.revocation import prune_removed_member_group_shares


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def test_prune_removed_member_group_shares_revokes_visibility_across_resources(db_session):
    db = db_session
    db.add_all(
        [
            Tenant(
                id="t1",
                name="tenant-1",
                display_name="Tenant 1",
                settings={
                    "jira_integrations": [
                        {
                            "id": "jira-1",
                            "name": "Jira",
                            "createdBy": "u1",
                            "visibility": "group",
                            "sharedGroupIds": ["g1"],
                        }
                    ]
                },
            ),
            Group(id="g1", tenant_id="t1", name="Team A"),
            Group(id="g2", tenant_id="t1", name="Team B"),
        ]
    )
    db.commit()

    g1 = db.query(Group).filter_by(id="g1", tenant_id="t1").first()
    assert g1 is not None

    rule = AlertRule(
        id="r1",
        tenant_id="t1",
        created_by="u1",
        name="Rule",
        group="default",
        expr="up == 0",
        visibility="group",
    )
    rule.shared_groups.append(g1)

    channel = NotificationChannel(
        id="c1",
        tenant_id="t1",
        created_by="u1",
        name="Channel",
        type="slack",
        config={"webhook_url": "https://hooks.slack.test/abc"},
        enabled=True,
        visibility="group",
    )
    channel.shared_groups.append(g1)

    incident = AlertIncident(
        id="i1",
        tenant_id="t1",
        fingerprint="fp-1",
        alert_name="HighErrorRate",
        severity="critical",
        status="open",
        labels={},
        annotations={
            INCIDENT_META_KEY: json.dumps(
                {
                    "visibility": "group",
                    "shared_group_ids": ["g1"],
                    "created_by": "u1",
                }
            )
        },
    )

    db.add_all([rule, channel, incident])
    db.commit()

    counts = prune_removed_member_group_shares(
        db,
        tenant_id="t1",
        group_id="g1",
        removed_user_ids=["u1"],
    )
    db.commit()

    db_rule = db.query(AlertRule).filter_by(id="r1", tenant_id="t1").first()
    db_channel = db.query(NotificationChannel).filter_by(id="c1", tenant_id="t1").first()
    db_incident = db.query(AlertIncident).filter_by(id="i1", tenant_id="t1").first()
    db_tenant = db.query(Tenant).filter_by(id="t1").first()

    assert db_rule is not None and db_rule.visibility == "private" and len(db_rule.shared_groups or []) == 0
    assert db_channel is not None and db_channel.visibility == "private" and len(db_channel.shared_groups or []) == 0
    assert db_incident is not None
    inc_meta = parse_meta(db_incident.annotations or {})
    assert inc_meta.get("visibility") == "private"
    assert inc_meta.get("shared_group_ids") == []
    assert db_tenant is not None
    jira_items = (db_tenant.settings or {}).get("jira_integrations") or []
    assert isinstance(jira_items, list) and jira_items
    assert jira_items[0].get("visibility") == "private"
    assert jira_items[0].get("sharedGroupIds") == []

    assert counts["rules"] == 1
    assert counts["channels"] == 1
    assert counts["incidents"] == 1
    assert counts["jira_integrations"] == 1


def test_prune_removed_member_group_shares_matches_username_creators(db_session):
    db = db_session
    db.add_all(
        [
            Tenant(
                id="t1",
                name="tenant-1",
                display_name="Tenant 1",
                settings={
                    "jira_integrations": [
                        {
                            "id": "jira-1",
                            "name": "Jira",
                            "createdBy": "alice",
                            "visibility": "group",
                            "sharedGroupIds": ["g1"],
                        }
                    ]
                },
            ),
            Group(id="g1", tenant_id="t1", name="Team A"),
        ]
    )
    db.commit()

    g1 = db.query(Group).filter_by(id="g1", tenant_id="t1").first()
    assert g1 is not None

    rule = AlertRule(
        id="r1",
        tenant_id="t1",
        created_by="alice",
        name="Rule",
        group="default",
        expr="up == 0",
        visibility="group",
    )
    rule.shared_groups.append(g1)

    channel = NotificationChannel(
        id="c1",
        tenant_id="t1",
        created_by="alice",
        name="Channel",
        type="slack",
        config={"webhook_url": "https://hooks.slack.test/abc"},
        enabled=True,
        visibility="group",
    )
    channel.shared_groups.append(g1)

    incident = AlertIncident(
        id="i1",
        tenant_id="t1",
        fingerprint="fp-1",
        alert_name="HighErrorRate",
        severity="critical",
        status="open",
        labels={},
        annotations={
            INCIDENT_META_KEY: json.dumps(
                {
                    "visibility": "group",
                    "shared_group_ids": ["g1"],
                    "created_by": "alice",
                }
            )
        },
    )

    db.add_all([rule, channel, incident])
    db.commit()

    counts = prune_removed_member_group_shares(
        db,
        tenant_id="t1",
        group_id="g1",
        removed_user_ids=["u1"],
        removed_usernames=["ALICE"],
    )
    db.commit()

    db_rule = db.query(AlertRule).filter_by(id="r1", tenant_id="t1").first()
    db_channel = db.query(NotificationChannel).filter_by(id="c1", tenant_id="t1").first()
    db_incident = db.query(AlertIncident).filter_by(id="i1", tenant_id="t1").first()
    db_tenant = db.query(Tenant).filter_by(id="t1").first()

    assert db_rule is not None and db_rule.visibility == "private" and len(db_rule.shared_groups or []) == 0
    assert db_channel is not None and db_channel.visibility == "private" and len(db_channel.shared_groups or []) == 0
    assert db_incident is not None
    inc_meta = parse_meta(db_incident.annotations or {})
    assert inc_meta.get("visibility") == "private"
    assert inc_meta.get("shared_group_ids") == []
    assert db_tenant is not None
    jira_items = (db_tenant.settings or {}).get("jira_integrations") or []
    assert isinstance(jira_items, list) and jira_items
    assert jira_items[0].get("visibility") == "private"
    assert jira_items[0].get("sharedGroupIds") == []

    assert counts["rules"] == 1
    assert counts["channels"] == 1
    assert counts["incidents"] == 1
    assert counts["jira_integrations"] == 1


def test_prune_removed_member_group_shares_keeps_group_visibility_when_groups_remain(db_session):
    db = db_session
    db.add_all(
        [
            Tenant(
                id="t2",
                name="tenant-2",
                display_name="Tenant 2",
                settings={
                    "jira_integrations": [
                        {
                            "id": "jira-2",
                            "name": "Jira",
                            "createdBy": "u2",
                            "visibility": "group",
                            "sharedGroupIds": ["g1", "g2"],
                        }
                    ]
                },
            ),
            Group(id="g1", tenant_id="t2", name="Team A"),
            Group(id="g2", tenant_id="t2", name="Team B"),
        ]
    )
    db.commit()

    g1 = db.query(Group).filter_by(id="g1", tenant_id="t2").first()
    g2 = db.query(Group).filter_by(id="g2", tenant_id="t2").first()
    assert g1 is not None and g2 is not None

    rule = AlertRule(
        id="r2",
        tenant_id="t2",
        created_by="u2",
        name="Rule",
        group="default",
        expr="up == 0",
        visibility="group",
    )
    rule.shared_groups.extend([g1, g2])

    channel = NotificationChannel(
        id="c2",
        tenant_id="t2",
        created_by="u2",
        name="Channel",
        type="slack",
        config={"webhook_url": "https://hooks.slack.test/abc"},
        enabled=True,
        visibility="group",
    )
    channel.shared_groups.extend([g1, g2])

    incident = AlertIncident(
        id="i2",
        tenant_id="t2",
        fingerprint="fp-2",
        alert_name="HighErrorRate",
        severity="critical",
        status="open",
        labels={},
        annotations={
            INCIDENT_META_KEY: json.dumps(
                {
                    "visibility": "group",
                    "shared_group_ids": ["g1", "g2"],
                    "created_by": "u2",
                }
            )
        },
    )

    db.add_all([rule, channel, incident])
    db.commit()

    counts = prune_removed_member_group_shares(
        db,
        tenant_id="t2",
        group_id="g1",
        removed_user_ids=["u2"],
    )
    db.commit()

    db_rule = db.query(AlertRule).filter_by(id="r2", tenant_id="t2").first()
    db_channel = db.query(NotificationChannel).filter_by(id="c2", tenant_id="t2").first()
    db_incident = db.query(AlertIncident).filter_by(id="i2", tenant_id="t2").first()
    db_tenant = db.query(Tenant).filter_by(id="t2").first()

    assert (
        db_rule is not None
        and db_rule.visibility == "group"
        and [g.id for g in (db_rule.shared_groups or [])] == ["g2"]
    )
    assert (
        db_channel is not None
        and db_channel.visibility == "group"
        and [g.id for g in (db_channel.shared_groups or [])] == ["g2"]
    )
    assert db_incident is not None
    inc_meta = parse_meta(db_incident.annotations or {})
    assert inc_meta.get("visibility") == "group"
    assert inc_meta.get("shared_group_ids") == ["g2"]
    assert db_tenant is not None
    jira_items = (db_tenant.settings or {}).get("jira_integrations") or []
    assert jira_items[0].get("visibility") == "group"
    assert jira_items[0].get("sharedGroupIds") == ["g2"]

    assert counts["rules"] == 1
    assert counts["channels"] == 1
    assert counts["incidents"] == 1
    assert counts["jira_integrations"] == 1


def test_prune_removed_member_group_shares_ignores_non_list_jira_integrations(db_session):
    db = db_session
    db.add(
        Tenant(
            id="t3",
            name="tenant-3",
            display_name="Tenant 3",
            settings={"jira_integrations": {"id": "jira-3"}},
        )
    )
    db.commit()

    counts = prune_removed_member_group_shares(
        db,
        tenant_id="t3",
        group_id="g1",
        removed_user_ids=["u3"],
    )
    assert counts == {"rules": 0, "channels": 0, "incidents": 0, "jira_integrations": 0}
