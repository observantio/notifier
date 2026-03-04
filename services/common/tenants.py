"""
Tenant helpers for BeNotified storage operations.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db_models import Tenant


def ensure_tenant_exists(db: Session, tenant_id: Optional[str]) -> str:
    normalized = str(tenant_id or "").strip()
    if not normalized:
        raise ValueError("tenant_id is required")

    existing = db.query(Tenant).filter(Tenant.id == normalized).first()
    if existing:
        return existing.id

    db.add(
        Tenant(
            id=normalized,
            name=normalized,
            display_name=normalized,
            is_active=True,
            settings={},
        )
    )
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.query(Tenant).filter(Tenant.id == normalized).first()
        if existing:
            return existing.id
        raise
    return normalized

