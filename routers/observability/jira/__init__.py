"""
Jira integration routers split by resource domain.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from fastapi import APIRouter

from .config import router as config_router
from .discovery import router as discovery_router
from .incident_links import router as incident_links_router
from .integrations import router as integrations_router

router = APIRouter(prefix="/api/alertmanager")
router.include_router(config_router)
router.include_router(discovery_router)
router.include_router(integrations_router)
router.include_router(incident_links_router)

__all__ = ["router"]
