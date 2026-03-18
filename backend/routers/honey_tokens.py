"""
Honey Tokens Router - Deception Technology API
===============================================
Integrated with Seraph Deception Engine for campaign tracking.
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Optional, Dict, List
from pydantic import BaseModel
import asyncio

from .dependencies import get_current_user, check_permission, logger
from honey_tokens import honey_token_manager

router = APIRouter(prefix="/honey-tokens", tags=["Honey Tokens"])

# Deception engine integration (lazy import to avoid circular deps)
_deception_engine = None

def get_deception_engine():
    """Lazy load deception engine to avoid circular imports"""
    global _deception_engine
    if _deception_engine is None:
        try:
            from deception_engine import deception_engine
            _deception_engine = deception_engine
        except ImportError:
            pass
    return _deception_engine

class CreateTokenRequest(BaseModel):
    name: str
    token_type: str
    description: str = ""
    location: str = ""
    custom_value: Optional[str] = None

class CheckTokenRequest(BaseModel):
    value: str

@router.get("/stats")
async def get_honey_token_stats(current_user: dict = Depends(get_current_user)):
    """Get honey token statistics"""
    return honey_token_manager.get_stats()

@router.get("")
async def list_honey_tokens(
    include_values: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """List all honey tokens"""
    tokens = honey_token_manager.get_tokens(include_values=include_values)
    return {"tokens": tokens, "count": len(tokens)}

@router.get("/{token_id}")
async def get_honey_token(
    token_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific honey token"""
    token = honey_token_manager.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token

@router.post("")
async def create_honey_token(
    request: CreateTokenRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new honey token"""
    try:
        token = honey_token_manager.create_token(
            name=request.name,
            token_type=request.token_type,
            description=request.description,
            location=request.location,
            created_by=current_user["id"],
            custom_value=request.custom_value
        )
        logger.info(f"Created honey token {token['id']} by user {current_user['id']}")
        return token
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{token_id}")
async def delete_honey_token(
    token_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Delete a honey token"""
    if not honey_token_manager.delete_token(token_id):
        raise HTTPException(status_code=404, detail="Token not found")
    logger.info(f"Deleted honey token {token_id} by user {current_user['id']}")
    return {"success": True, "message": "Token deleted"}

@router.post("/{token_id}/toggle")
async def toggle_honey_token(
    token_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Toggle honey token active status"""
    token = honey_token_manager.toggle_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return {"success": True, "is_active": token["is_active"]}

@router.post("/check")
async def check_honey_token(
    request: CheckTokenRequest,
    req: Request,
    current_user: dict = Depends(get_current_user)
):
    """Check if a value matches any honey token (for testing/validation)"""
    token = honey_token_manager.check_token(request.value)
    if token:
        source_ip = req.client.host if req.client else "unknown"
        headers = dict(req.headers)
        
        # This is a match - record the access
        access = honey_token_manager.record_access(
            token_id=token.id,
            source_ip=source_ip,
            user_agent=req.headers.get("user-agent"),
            request_path="/api/honey-tokens/check",
            request_method="POST",
            headers=headers
        )
        
        # Notify deception engine for campaign tracking
        deception = get_deception_engine()
        campaign_info = None
        if deception:
            try:
                assessment = await deception.record_decoy_interaction(
                    ip=source_ip,
                    decoy_type="honey_token",
                    decoy_id=token.id,
                    headers=headers
                )
                campaign_info = {
                    "campaign_id": assessment.campaign_id,
                    "escalation_level": assessment.escalation_level.value,
                    "risk_score": assessment.score
                }
            except Exception as e:
                logger.warning(f"Deception engine notification failed: {e}")
        
        return {
            "matched": True,
            "token_name": token.name,
            "token_type": token.token_type.value,
            "alert": "CRITICAL: Honey token accessed!",
            "access_id": access.id,
            "campaign_tracking": campaign_info
        }
    return {"matched": False}

@router.get("/accesses/list")
async def list_honey_token_accesses(
    limit: int = 50,
    token_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get honey token access history"""
    accesses = honey_token_manager.get_accesses(limit=limit, token_id=token_id)
    return {"accesses": accesses, "count": len(accesses)}

@router.get("/types/list")
async def list_token_types(current_user: dict = Depends(get_current_user)):
    """Get available honey token types"""
    from honey_tokens import HoneyTokenType
    types = [
        {
            "value": t.value,
            "name": t.value.replace("_", " ").title(),
            "description": _get_type_description(t.value)
        }
        for t in HoneyTokenType
    ]
    return {"types": types}

def _get_type_description(token_type: str) -> str:
    descriptions = {
        "api_key": "Fake API key (e.g., sk-xxx format)",
        "password": "Fake password for config files",
        "aws_key": "Fake AWS access key (AKIA format)",
        "database_cred": "Fake database connection string",
        "ssh_key": "Fake SSH public key",
        "jwt_token": "Fake JWT bearer token",
        "oauth_token": "Fake OAuth access token",
        "webhook_url": "Fake webhook URL endpoint"
    }
    return descriptions.get(token_type, "Custom credential type")
