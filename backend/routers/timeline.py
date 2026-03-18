"""
Threat Timeline Router
"""
from dataclasses import asdict
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Optional

from .dependencies import get_current_user, get_db, check_permission

# Import timeline services
from threat_timeline import timeline_builder, ReportType

router = APIRouter(prefix="/timeline", tags=["Timeline"])


class ArtifactRegisterRequest(BaseModel):
    artifact_type: str
    name: str
    description: str
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None


class ArtifactCustodyUpdateRequest(BaseModel):
    action: str
    notes: Optional[str] = ""


@router.get("/correlate/all")
async def correlate_all_timelines(
    preload_limit: int = Query(25, ge=2, le=200),
    current_user: dict = Depends(check_permission("read")),
):
    """Correlate incidents across recent timelines."""
    _ = current_user
    db = get_db()

    # Prime correlator with recent incidents so correlation works after restart.
    recent = await db.threats.find({}, {"_id": 0, "id": 1}).sort("created_at", -1).limit(preload_limit).to_list(preload_limit)
    for item in recent:
        tid = item.get("id")
        if tid:
            await timeline_builder.build_timeline(tid, full_analysis=True)

    result = timeline_builder.correlate_all_incidents()
    result["preloaded_timelines"] = len(recent)
    return result


@router.get("/{threat_id}/related-incidents")
async def get_related_incidents(
    threat_id: str,
    current_user: dict = Depends(check_permission("read")),
):
    """Get incidents correlated to the provided threat timeline."""
    _ = current_user
    db = get_db()
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0, "id": 1})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    await timeline_builder.build_timeline(threat_id, full_analysis=True)
    related = timeline_builder.find_related_incidents(threat_id)
    return {
        "threat_id": threat_id,
        "related_incidents": related,
        "count": len(related),
    }


@router.get("/{threat_id}/report")
async def get_timeline_report(
    threat_id: str,
    type: str = Query("technical"),
    current_user: dict = Depends(check_permission("read")),
):
    """Generate enterprise incident report for a threat timeline."""
    _ = current_user
    db = get_db()
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0, "id": 1})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    try:
        report_type = ReportType(type.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Unsupported report type: {type}",
                "supported": [rt.value for rt in ReportType],
            },
        )

    timeline = await timeline_builder.build_timeline(threat_id, full_analysis=True)
    if not timeline:
        raise HTTPException(status_code=404, detail="Could not build timeline")

    report = timeline_builder.generate_report(timeline, report_type=report_type)
    return {
        "threat_id": threat_id,
        "report_type": report_type.value,
        "report": report,
    }


@router.post("/artifacts/register")
async def register_timeline_artifact(
    request: ArtifactRegisterRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """Register a forensic artifact for timeline evidence workflows."""
    actor = current_user.get("email") or current_user.get("name") or "unknown"
    artifact = timeline_builder.register_artifact(
        artifact_type=request.artifact_type,
        name=request.name,
        description=request.description,
        collected_by=actor,
        hash_md5=request.hash_md5,
        hash_sha256=request.hash_sha256,
    )
    return {
        "status": "registered",
        "artifact": asdict(artifact),
    }


@router.post("/artifacts/{artifact_id}/custody")
async def update_artifact_custody(
    artifact_id: str,
    request: ArtifactCustodyUpdateRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """Append chain-of-custody entry for an artifact."""
    actor = current_user.get("email") or current_user.get("name") or "unknown"
    ok = timeline_builder.update_artifact_custody(
        artifact_id=artifact_id,
        action=request.action,
        actor=actor,
        notes=request.notes or "",
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Artifact not found")

    artifact = timeline_builder.get_artifact(artifact_id)
    return {
        "status": "updated",
        "artifact_id": artifact_id,
        "artifact": artifact,
    }


@router.get("/artifacts/{artifact_id}/custody-report")
async def get_artifact_custody_report(
    artifact_id: str,
    current_user: dict = Depends(check_permission("read")),
):
    """Export chain-of-custody report for a forensic artifact."""
    _ = current_user
    report = timeline_builder.export_custody_report(artifact_id)
    if not report:
        raise HTTPException(status_code=404, detail="Artifact not found")

    return {
        "artifact_id": artifact_id,
        "report_markdown": report,
    }

@router.get("/{threat_id}")
async def get_threat_timeline(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Get complete timeline for a threat"""
    db = get_db()
    
    # Check if threat exists
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Build timeline (only takes threat_id)
    timeline = await timeline_builder.build_timeline(threat_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Could not build timeline")
    
    return asdict(timeline)

@router.get("/{threat_id}/export")
async def export_threat_timeline(threat_id: str, format: str = "json", current_user: dict = Depends(get_current_user)):
    """Export timeline in specified format"""
    db = get_db()
    
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    timeline = await timeline_builder.build_timeline(threat_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Could not build timeline")
    
    from dataclasses import asdict
    if format == "json":
        return asdict(timeline)
    elif format == "markdown":
        return {"markdown": timeline_builder._to_markdown(timeline)}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

# Alternative route for listing recent timelines
timelines_router = APIRouter(prefix="/timelines", tags=["Timeline"])

@timelines_router.get("/recent")
async def get_recent_timelines(limit: int = 10, current_user: dict = Depends(get_current_user)):
    """Get recent threat timelines"""
    # Use the class method that handles this properly
    timelines = await timeline_builder.get_recent_timelines(limit)
    return {"timelines": timelines, "count": len(timelines)}
