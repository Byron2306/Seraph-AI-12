"""
Threat Intelligence Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission

# Import threat intel service
from threat_intel import threat_intel, ThreatIntelManager

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

class IOCCheckRequest(BaseModel):
    value: str
    ioc_type: Optional[str] = None

class BulkIOCCheckRequest(BaseModel):
    values: List[str]
    ioc_type: Optional[str] = None

@router.get("/stats")
async def get_threat_intel_stats(current_user: dict = Depends(get_current_user)):
    """Get threat intelligence statistics"""
    return threat_intel.get_stats()

@router.post("/check")
async def check_indicator(request: IOCCheckRequest, current_user: dict = Depends(get_current_user)):
    """Check a single indicator against threat feeds"""
    match = await threat_intel.check_and_log(
        request.value, 
        request.ioc_type,
        {"checked_by": current_user.get("email")}
    )
    
    result = {
        "matched": match.matched,
        "query_value": match.query_value,
        "query_type": match.query_type,
        "matched_at": match.matched_at
    }
    
    if match.indicator:
        from dataclasses import asdict
        result["indicator"] = asdict(match.indicator)
    
    return result

@router.post("/check-bulk")
async def check_indicators_bulk(request: BulkIOCCheckRequest, current_user: dict = Depends(get_current_user)):
    """Check multiple indicators against threat feeds"""
    matches = threat_intel.check_bulk(request.values, request.ioc_type)
    
    results = []
    for match in matches:
        result = {
            "matched": match.matched,
            "query_value": match.query_value,
            "query_type": match.query_type
        }
        if match.indicator:
            from dataclasses import asdict
            result["indicator"] = asdict(match.indicator)
        results.append(result)
    
    return {
        "total_checked": len(request.values),
        "matches_found": len([r for r in results if r["matched"]]),
        "results": results
    }

@router.post("/update")
async def update_feeds(current_user: dict = Depends(check_permission("write"))):
    """Manually trigger threat feed update"""
    await threat_intel.update_all_feeds()
    return {"message": "Feeds updated", "stats": threat_intel.get_stats()}

@router.get("/matches/recent")
async def get_recent_matches(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get recent threat matches"""
    return threat_intel.get_recent_matches(limit)

@router.get("/feeds")
async def get_feeds_status(current_user: dict = Depends(get_current_user)):
    """Get status of all threat intelligence feeds"""
    stats = threat_intel.get_stats()
    return {
        "enabled_feeds": stats["enabled_feeds"],
        "by_feed": stats["by_feed"],
        "total_indicators": stats["total_indicators"]
    }
