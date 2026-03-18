"""
Container Security Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, get_db

# Import container security service
from container_security import container_security, ContainerSecurityManager

router = APIRouter(prefix="/containers", tags=["Container Security"])

class ScanImageRequest(BaseModel):
    image_name: str
    force: bool = False

@router.get("/stats")
async def get_container_stats(current_user: dict = Depends(get_current_user)):
    """Get container security statistics"""
    db = get_db()
    
    # Get stats from service
    service_stats = container_security.get_stats()
    
    # Also get from database
    total_scans = await db.container_scans.count_documents({})
    total_containers = await db.containers.count_documents({})
    total_events = await db.container_runtime_events.count_documents({})
    
    # Count vulnerabilities from scans
    scans = await db.container_scans.find({}, {"_id": 0}).to_list(100)
    critical_vulns = sum(s.get("critical_count", 0) for s in scans)
    high_vulns = sum(s.get("high_count", 0) for s in scans)
    
    return {
        **service_stats,
        "total_scans": total_scans,
        "total_containers": total_containers,
        "runtime_events": total_events,
        "critical_vulnerabilities": critical_vulns,
        "high_vulnerabilities": high_vulns
    }

@router.get("")
async def get_containers(current_user: dict = Depends(get_current_user)):
    """Get running containers with security info"""
    db = get_db()
    
    # Try to get from Docker first
    containers = await container_security.get_containers()
    
    # If empty, get from database (sample data)
    if not containers:
        containers = await db.containers.find({}, {"_id": 0}).to_list(100)
    
    return {"containers": containers, "count": len(containers)}

@router.get("/{container_id}/security")
async def check_container_security(container_id: str, current_user: dict = Depends(get_current_user)):
    """Run security check on a specific container"""
    result = await container_security.check_container(container_id)
    return result

@router.post("/scan")
async def scan_container_image(request: ScanImageRequest, current_user: dict = Depends(get_current_user)):
    """Scan a container image for vulnerabilities"""
    db = get_db()
    result = await container_security.scan_image(request.image_name, request.force)
    
    # Store in database
    await db.container_scans.update_one(
        {"image_name": request.image_name},
        {"$set": result},
        upsert=True
    )
    
    return result

@router.post("/scan-all")
async def scan_all_images(current_user: dict = Depends(check_permission("write"))):
    """Scan all local container images"""
    results = await container_security.scan_all_images()
    
    # Summary
    total_vulns = sum(r.get("total_vulnerabilities", 0) for r in results)
    critical = sum(r.get("critical_count", 0) for r in results)
    
    return {
        "images_scanned": len(results),
        "total_vulnerabilities": total_vulns,
        "critical_count": critical,
        "results": results
    }

@router.get("/scans/history")
async def get_scan_history(limit: int = 20, current_user: dict = Depends(get_current_user)):
    """Get container scan history"""
    db = get_db()
    
    # Get from database
    scans = await db.container_scans.find({}, {"_id": 0}).sort("scanned_at", -1).to_list(limit)
    
    return {
        "scans": scans,
        "total": len(scans)
    }

@router.get("/runtime-events")
async def get_runtime_events(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get container runtime security events"""
    db = get_db()
    
    events = await db.container_runtime_events.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    
    return {"events": events, "count": len(events)}
