from fastapi import APIRouter, Body, Depends

from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.requests import JiraConfigUpdateRequest
from services.alerting.integration_security_service import load_tenant_jira_config, save_tenant_jira_config

router = APIRouter()


@router.get("/jira/config")
async def get_jira_config(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.MANAGE_TENANTS, "alertmanager")),
):
    cfg = load_tenant_jira_config(current_user.tenant_id)
    return {
        "enabled": bool(cfg.get("enabled")),
        "baseUrl": cfg.get("base_url"),
        "email": cfg.get("email"),
        "hasApiToken": bool(cfg.get("api_token")),
        "hasBearerToken": bool(cfg.get("bearer")),
    }


@router.put("/jira/config")
@handle_route_errors()
async def put_jira_config(
    payload: JiraConfigUpdateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.MANAGE_TENANTS, "alertmanager")),
):
    return save_tenant_jira_config(
        current_user.tenant_id,
        enabled=payload.enabled,
        base_url=payload.baseUrl,
        email=payload.email,
        api_token=payload.apiToken,
        bearer=payload.bearerToken,
    )
