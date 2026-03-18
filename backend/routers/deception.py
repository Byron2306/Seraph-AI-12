"""
Deception Engine API Router
============================
Endpoints for Seraph's advanced deception system featuring:
- Pebbles (Campaign Tracking)
- Mystique (Adaptive Deception)
- Stonewall (Progressive Escalation)
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from enum import Enum
import logging

from deception_engine import deception_engine, RouteDecision, EscalationLevel
from .dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/deception", tags=["Deception Engine"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class RouteDecisionEnum(str, Enum):
    PASS_THROUGH = "pass_through"
    FRICTION = "friction"
    TRAP_SINK = "trap_sink"
    HONEYPOT = "honeypot"
    DISINFORMATION = "disinformation"


class RiskAssessmentRequest(BaseModel):
    ip: str
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    session_id: Optional[str] = None
    timing_data: Optional[Dict[str, Any]] = None
    behavior_flags: Optional[Dict[str, bool]] = None


class RiskAssessmentResponse(BaseModel):
    score: int
    reasons: List[str]
    route: str
    delay_ms: int
    campaign_id: Optional[str]
    fingerprint_id: Optional[str]
    escalation_level: str


class DecoyInteractionRequest(BaseModel):
    ip: str
    decoy_type: str
    decoy_id: str
    session_id: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class DeployDecoyRequest(BaseModel):
    host_id: str = Field(default="deception-engine")
    decoy_type: str = Field(default="credentials")
    decoys: List[str] = Field(default_factory=lambda: ["svc_backup:Winter2026!", "api_key_trap_01"])
    placement: str = Field(default="standard")


class IPRequest(BaseModel):
    ip: str


class CampaignQueryParams(BaseModel):
    min_events: int = Field(default=5, ge=1, le=1000)
    limit: int = Field(default=50, ge=1, le=500)


class EventQueryParams(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)
    route_filter: Optional[str] = None
    campaign_id: Optional[str] = None


# =============================================================================
# STATUS & CONFIG
# =============================================================================

@router.get("/status")
async def get_deception_status():
    """Get deception engine status and configuration"""
    status = deception_engine.get_status()

    # Frontend compatibility: DeceptionPage expects top-level engine/status booleans.
    config = status.get("config", {}) if isinstance(status, dict) else {}
    return {
        **status,
        "engine": "Seraph Deception Engine",
        "status": "active",
        "uptime": status.get("uptime", "n/a") if isinstance(status, dict) else "n/a",
        "pebbles_enabled": True,
        "mystique_enabled": bool(config.get("mystique_enabled", True)),
        "stonewall_enabled": bool(config.get("stonewall_enabled", True)),
    }


@router.get("/capabilities")
async def get_capabilities():
    """Get list of deception capabilities"""
    return {
        "engine": "Seraph Deception Engine",
        "capabilities": [
            {
                "name": "Pebbles",
                "description": "Campaign-based attack correlation via behavioral fingerprints",
                "features": ["fingerprint_tracking", "campaign_correlation", "cross_session_linking"]
            },
            {
                "name": "Mystique",
                "description": "Self-adapting deception parameters based on attacker behavior",
                "features": ["adaptive_friction", "adaptive_tarpit", "dynamic_thresholds"]
            },
            {
                "name": "Stonewall",
                "description": "Progressive escalation for persistent attackers",
                "features": ["soft_ban", "hard_ban", "automatic_blocklisting"]
            },
            {
                "name": "Risk Scoring",
                "description": "Weighted behavioral risk assessment",
                "features": ["multi_signal", "weighted_scoring", "categorical_reasons"]
            },
            {
                "name": "Friction",
                "description": "Graduated response delays based on risk",
                "features": ["adaptive_delays", "challenge_mode", "rate_limiting"]
            },
            {
                "name": "Trap Sink",
                "description": "Tarpit + containment for high-risk traffic",
                "features": ["tarpit_delay", "deny_access", "campaign_tracking"]
            }
        ],
        "decisions": [d.value for d in RouteDecision],
        "escalation_levels": [e.value for e in EscalationLevel]
    }


# =============================================================================
# RISK ASSESSMENT
# =============================================================================

@router.post("/assess", response_model=RiskAssessmentResponse)
async def assess_risk(request: RiskAssessmentRequest):
    """
    Perform risk assessment on an incoming request.
    Returns routing decision with delay if applicable.
    """
    assessment = await deception_engine.process_request(
        ip=request.ip,
        path=request.path,
        headers=request.headers,
        session_id=request.session_id,
        timing_data=request.timing_data,
        behavior_flags=request.behavior_flags
    )
    
    return RiskAssessmentResponse(
        score=assessment.score,
        reasons=assessment.reasons,
        route=assessment.route.value,
        delay_ms=assessment.delay_ms,
        campaign_id=assessment.campaign_id,
        fingerprint_id=assessment.fingerprint_id,
        escalation_level=assessment.escalation_level.value
    )


@router.post("/assess/batch")
async def assess_risk_batch(requests: List[RiskAssessmentRequest]):
    """Batch risk assessment for multiple requests"""
    results = []
    for req in requests[:100]:  # Limit to 100
        assessment = await deception_engine.process_request(
            ip=req.ip,
            path=req.path,
            headers=req.headers,
            session_id=req.session_id,
            timing_data=req.timing_data,
            behavior_flags=req.behavior_flags
        )
        results.append({
            "ip": req.ip,
            "score": assessment.score,
            "route": assessment.route.value,
            "campaign_id": assessment.campaign_id
        })
    
    return {"assessments": results, "count": len(results)}


# =============================================================================
# DECOY INTERACTIONS
# =============================================================================

@router.post("/decoy/interaction")
async def record_decoy_interaction(request: DecoyInteractionRequest):
    """
    Record interaction with a decoy/honey token.
    Triggers immediate escalation.
    """
    assessment = await deception_engine.record_decoy_interaction(
        ip=request.ip,
        decoy_type=request.decoy_type,
        decoy_id=request.decoy_id,
        session_id=request.session_id,
        headers=request.headers
    )
    
    return {
        "recorded": True,
        "score": assessment.score,
        "route": assessment.route.value,
        "campaign_id": assessment.campaign_id,
        "escalation_level": assessment.escalation_level.value
    }


@router.post("/decoy/deploy")
async def deploy_decoy(request: DeployDecoyRequest, current_user: dict = Depends(get_current_user)):
    """Deploy decoys using the AI defense engine for Deception page quick actions."""
    from threat_response import AIDefenseEngine
    from dataclasses import asdict

    result = await AIDefenseEngine.deploy_decoy(
        host_id=request.host_id,
        decoy_type=request.decoy_type,
        decoys=request.decoys,
        placement=request.placement,
    )

    payload = asdict(result)
    payload["requested_by"] = current_user.get("email", "unknown")
    return payload


# =============================================================================
# CAMPAIGNS
# =============================================================================

@router.get("/campaigns")
async def get_campaigns(min_events: int = 5, limit: int = 50):
    """Get active attack campaigns"""
    campaigns = deception_engine.get_campaigns(min_events=min_events, limit=limit)
    return {
        "campaigns": campaigns,
        "count": len(campaigns)
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get specific campaign details"""
    campaign = deception_engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("/campaigns/{campaign_id}/events")
async def get_campaign_events(campaign_id: str, limit: int = 100):
    """Get events for a specific campaign"""
    events = deception_engine.get_events(limit=limit, campaign_id=campaign_id)
    return {"events": events, "count": len(events)}


# =============================================================================
# EVENTS
# =============================================================================

@router.get("/events")
async def get_events(
    limit: int = 100,
    route_filter: Optional[str] = None,
    campaign_id: Optional[str] = None
):
    """Get recent deception events with optional filtering"""
    events = deception_engine.get_events(
        limit=min(limit, 1000),
        route_filter=route_filter,
        campaign_id=campaign_id
    )
    return {"events": events, "count": len(events)}


@router.get("/events/summary")
async def get_events_summary():
    """Get summary of recent events by type"""
    events = deception_engine.get_events(limit=1000)
    
    summary = {
        "total": len(events),
        "by_route": {},
        "by_escalation": {},
        "unique_ips": set(),
        "unique_campaigns": set()
    }
    
    for event in events:
        route = event.get("route_decision", "unknown")
        summary["by_route"][route] = summary["by_route"].get(route, 0) + 1
        
        escalation = event.get("details", {}).get("escalation", "none")
        summary["by_escalation"][escalation] = summary["by_escalation"].get(escalation, 0) + 1
        
        summary["unique_ips"].add(event.get("source_ip"))
        if event.get("campaign_id"):
            summary["unique_campaigns"].add(event["campaign_id"])
    
    summary["unique_ips"] = len(summary["unique_ips"])
    summary["unique_campaigns"] = len(summary["unique_campaigns"])
    
    return summary


# =============================================================================
# BLOCKLIST/ALLOWLIST
# =============================================================================

@router.post("/allowlist/add")
async def add_to_allowlist(request: IPRequest):
    """Add IP to allowlist"""
    success = deception_engine.add_to_allowlist(request.ip)
    return {"success": success, "ip": request.ip, "action": "allowlisted"}


@router.post("/blocklist/add")
async def add_to_blocklist(request: IPRequest):
    """Add IP to blocklist"""
    success = deception_engine.add_to_blocklist(request.ip)
    return {"success": success, "ip": request.ip, "action": "blocklisted"}


@router.post("/blocklist/remove")
async def remove_from_blocklist(request: IPRequest):
    """Remove IP from blocklist"""
    success = deception_engine.remove_from_blocklist(request.ip)
    return {"success": success, "ip": request.ip, "action": "unblocked"}


@router.get("/blocklist")
async def get_blocklist():
    """Get current blocklist"""
    return {
        "blocklist": list(deception_engine.blocklist),
        "allowlist": list(deception_engine.allowlist),
        "soft_bans": len(deception_engine.soft_bans)
    }


# =============================================================================
# FINGERPRINTS
# =============================================================================

@router.get("/fingerprints")
async def get_fingerprints(min_events: int = 3, limit: int = 100):
    """Get behavioral fingerprints"""
    fingerprints = [
        fp.to_dict() for fp in deception_engine.fingerprints.values()
        if fp.total_events >= min_events
    ]
    fingerprints.sort(key=lambda x: x["total_events"], reverse=True)
    
    return {
        "fingerprints": fingerprints[:limit],
        "total": len(fingerprints)
    }


@router.get("/fingerprints/{fingerprint_id}")
async def get_fingerprint(fingerprint_id: str):
    """Get specific fingerprint details"""
    if fingerprint_id not in deception_engine.fingerprints:
        raise HTTPException(status_code=404, detail="Fingerprint not found")
    
    fp = deception_engine.fingerprints[fingerprint_id]
    
    # Find campaigns for this fingerprint
    campaigns = [
        c.to_dict() for c in deception_engine.campaigns.values()
        if fingerprint_id in c.fingerprint_ids
    ]
    
    return {
        "fingerprint": fp.to_dict(),
        "campaigns": campaigns
    }


# =============================================================================
# MYSTIQUE TUNING
# =============================================================================

@router.post("/mystique/force-adapt/{campaign_id}")
async def force_mystique_adapt(campaign_id: str):
    """Force Mystique adaptation for a campaign"""
    if campaign_id not in deception_engine.campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Temporarily increase events to trigger adaptation
    campaign = deception_engine.campaigns[campaign_id]
    original_events = campaign.total_events
    
    # Force adaptation
    campaign.total_events = max(campaign.total_events, 
                                deception_engine.config.campaign_promote_threshold + 1)
    campaign.total_events = (
        (campaign.total_events // deception_engine.config.adapt_every_n_events + 1) 
        * deception_engine.config.adapt_every_n_events
    )
    
    adapted = deception_engine.mystique_adapt(campaign_id)
    
    return {
        "adapted": adapted,
        "campaign_id": campaign_id,
        "friction_multiplier": campaign.friction_multiplier,
        "tarpit_multiplier": campaign.tarpit_multiplier,
        "sink_score_override": campaign.sink_score_override
    }


@router.get("/mystique/config")
async def get_mystique_config():
    """Get Mystique configuration"""
    cfg = deception_engine.config
    return {
        "enabled": cfg.mystique_enabled,
        "adapt_every_n_events": cfg.adapt_every_n_events,
        "campaign_promote_threshold": cfg.campaign_promote_threshold,
        "max_friction_multiplier": cfg.max_friction_multiplier,
        "max_tarpit_multiplier": cfg.max_tarpit_multiplier,
        "min_sink_score_floor": cfg.min_sink_score_floor
    }


# =============================================================================
# STONEWALL CONFIG
# =============================================================================

@router.get("/stonewall/config")
async def get_stonewall_config():
    """Get Stonewall configuration"""
    cfg = deception_engine.config
    return {
        "enabled": cfg.stonewall_enabled,
        "repeat_threshold": cfg.repeat_threshold,
        "ban_seconds_first": cfg.ban_seconds_first,
        "ban_seconds_repeat": cfg.ban_seconds_repeat,
        "trap_hits_to_blocklist": cfg.trap_hits_to_blocklist
    }


# =============================================================================
# ANALYTICS
# =============================================================================

@router.get("/analytics/threat-heatmap")
async def get_threat_heatmap():
    """Get threat data for heatmap visualization"""
    campaigns = deception_engine.get_campaigns(min_events=1, limit=500)
    
    heatmap = []
    for campaign in campaigns:
        for ip in campaign.get("source_ips", []):
            heatmap.append({
                "ip": ip,
                "campaign_id": campaign["campaign_id"],
                "total_events": campaign["total_events"],
                "trap_events": campaign["trap_events"],
                "escalation_level": campaign.get("escalation_level", "none"),
                "risk_indicator": campaign.get("friction_multiplier", 1.0)
            })
    
    return {"data": heatmap, "count": len(heatmap)}


@router.get("/analytics/campaigns-timeline")
async def get_campaigns_timeline(hours: int = 24):
    """Get campaign activity timeline"""
    events = deception_engine.get_events(limit=5000)
    
    # Group by hour
    timeline = {}
    for event in events:
        ts = event.get("timestamp", "")[:13]  # YYYY-MM-DDTHH
        if ts not in timeline:
            timeline[ts] = {"trap_sink": 0, "friction": 0, "pass": 0}
        
        route = event.get("route_decision", "pass_through")
        if route == "trap_sink":
            timeline[ts]["trap_sink"] += 1
        elif route == "friction":
            timeline[ts]["friction"] += 1
        else:
            timeline[ts]["pass"] += 1
    
    # Convert to sorted list
    sorted_timeline = [
        {"hour": k, **v} for k, v in sorted(timeline.items())
    ]
    
    return {"timeline": sorted_timeline[-hours:], "hours": hours}
