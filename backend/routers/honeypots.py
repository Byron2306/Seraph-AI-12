"""
Honeypots Router
================
Integrated with Seraph Deception Engine for campaign tracking.
"""
from fastapi import APIRouter, HTTPException, Depends, WebSocket
from datetime import datetime, timezone
from typing import List, Dict, Any
import uuid

from .dependencies import (
    HoneypotCreate, HoneypotResponse, HoneypotInteraction,
    get_current_user, get_db, check_permission
)

router = APIRouter(prefix="/honeypots", tags=["Honeypots"])

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

# WebSocket manager for real-time updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

ws_manager = ConnectionManager()

@router.post("", response_model=HoneypotResponse)
async def create_honeypot(honeypot_data: HoneypotCreate, current_user: dict = Depends(check_permission("write"))):
    """Create a new honeypot"""
    db = get_db()
    honeypot_id = str(uuid.uuid4())
    honeypot_doc = {
        "id": honeypot_id,
        "name": honeypot_data.name,
        "type": honeypot_data.type,
        "ip": honeypot_data.ip,
        "port": honeypot_data.port,
        "description": honeypot_data.description,
        "status": "active",
        "interactions": 0,
        "last_interaction": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": current_user["id"]
    }
    await db.honeypots.insert_one(honeypot_doc)
    return HoneypotResponse(**honeypot_doc)

@router.get("", response_model=List[HoneypotResponse])
async def get_honeypots(current_user: dict = Depends(get_current_user)):
    """Get all honeypots"""
    db = get_db()
    honeypots = await db.honeypots.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return [HoneypotResponse(**h) for h in honeypots]

@router.post("/{honeypot_id}/interaction")
async def record_honeypot_interaction(honeypot_id: str, source_ip: str, action: str, data: dict = {}):
    """Record an interaction with a honeypot (called by honeypot sensors)"""
    db = get_db()
    
    # Find honeypot
    honeypot = await db.honeypots.find_one({"id": honeypot_id}, {"_id": 0})
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    
    # Determine threat level based on action
    threat_levels = {
        "connection": "low",
        "login_attempt": "medium",
        "command": "high",
        "file_access": "high"
    }
    
    interaction_id = str(uuid.uuid4())
    interaction_doc = {
        "id": interaction_id,
        "honeypot_id": honeypot_id,
        "source_ip": source_ip,
        "source_port": data.get("source_port", 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "data": data,
        "threat_level": threat_levels.get(action, "medium")
    }
    
    await db.honeypot_interactions.insert_one(interaction_doc)
    
    # Update honeypot stats
    await db.honeypots.update_one(
        {"id": honeypot_id},
        {
            "$inc": {"interactions": 1},
            "$set": {
                "last_interaction": datetime.now(timezone.utc).isoformat(),
                "status": "triggered"
            }
        }
    )
    
    # Notify deception engine for campaign tracking
    deception = get_deception_engine()
    campaign_info = None
    if deception:
        try:
            headers = data.get("headers", {})
            assessment = await deception.record_decoy_interaction(
                ip=source_ip,
                decoy_type="honeypot",
                decoy_id=honeypot_id,
                headers=headers
            )
            campaign_info = {
                "campaign_id": assessment.campaign_id,
                "escalation_level": assessment.escalation_level.value,
                "risk_score": assessment.score
            }
            interaction_doc["campaign_id"] = assessment.campaign_id
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Deception engine notification failed: {e}")
    
    # Auto-create threat if high severity
    if threat_levels.get(action) == "high":
        threat_doc = {
            "id": str(uuid.uuid4()),
            "name": f"Honeypot Triggered: {honeypot['name']}",
            "type": "honeypot",
            "severity": "high",
            "status": "active",
            "source_ip": source_ip,
            "target_system": f"Honeypot {honeypot['name']}",
            "description": f"High-threat interaction detected on honeypot. Action: {action}",
            "indicators": [f"Honeypot IP: {honeypot['ip']}", f"Action: {action}", f"Source: {source_ip}"],
            "ai_analysis": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        await db.threats.insert_one(threat_doc)
        
        # Broadcast via WebSocket
        await ws_manager.broadcast({
            "type": "honeypot_alert",
            "honeypot": honeypot["name"],
            "source_ip": source_ip,
            "action": action,
            "threat_level": "high"
        })
    
    response = {"message": "Interaction recorded", "id": interaction_id, "threat_level": threat_levels.get(action)}
    if campaign_info:
        response["campaign_tracking"] = campaign_info
    return response

@router.get("/{honeypot_id}/interactions", response_model=List[HoneypotInteraction])
async def get_honeypot_interactions(honeypot_id: str, current_user: dict = Depends(get_current_user)):
    """Get interactions for a specific honeypot"""
    db = get_db()
    interactions = await db.honeypot_interactions.find(
        {"honeypot_id": honeypot_id}, {"_id": 0}
    ).sort("timestamp", -1).to_list(100)
    return [HoneypotInteraction(**i) for i in interactions]

@router.patch("/{honeypot_id}/status")
async def update_honeypot_status(honeypot_id: str, status: str, current_user: dict = Depends(check_permission("write"))):
    """Update honeypot status"""
    db = get_db()
    if status not in ["active", "inactive", "triggered"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.honeypots.update_one({"id": honeypot_id}, {"$set": {"status": status}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    return {"message": "Status updated", "status": status}

# Export ws_manager for use in other modules
__all__ = ['router', 'ws_manager']
