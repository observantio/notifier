"""
Tenants management utilities for ensuring tenant existence and handling tenant-related operations in a multi-tenant application context.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
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

