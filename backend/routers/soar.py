"""
SOAR (Security Orchestration, Automation and Response) Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, Dict, List
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, logger
from soar_engine import soar_engine, PlaybookStatus

router = APIRouter(prefix="/soar", tags=["SOAR"])

class CreatePlaybookRequest(BaseModel):
    name: str
    description: str = ""
    trigger: str
    trigger_conditions: Dict = {}
    steps: List[Dict]
    status: str = "active"

class UpdatePlaybookRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    trigger_conditions: Optional[Dict] = None
    steps: Optional[List[Dict]] = None

class TriggerEventRequest(BaseModel):
    trigger_type: str
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    file_path: Optional[str] = None
    pid: Optional[int] = None
    agent_id: Optional[str] = None
    confidence: Optional[str] = None
    ioc_type: Optional[str] = None
    extra: Dict = {}

class CreateTemplateRequest(BaseModel):
    name: str
    description: str = ""
    category: str = "custom"
    trigger: str
    trigger_conditions: Dict = {}
    steps: List[Dict]
    tags: List[str] = []

class CloneTemplateRequest(BaseModel):
    name: str

@router.get("/stats")
async def get_soar_stats(current_user: dict = Depends(get_current_user)):
    """Get SOAR engine statistics"""
    return soar_engine.get_stats()

@router.get("/playbooks")
async def list_playbooks(current_user: dict = Depends(get_current_user)):
    """Get all playbooks"""
    playbooks = soar_engine.get_playbooks()
    return {"playbooks": playbooks, "count": len(playbooks)}

@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific playbook"""
    playbook = soar_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook

@router.post("/playbooks")
async def create_playbook(
    request: CreatePlaybookRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new playbook"""
    try:
        playbook = soar_engine.create_playbook({
            **request.model_dump(),
            "created_by": current_user["id"]
        })
        logger.info(f"Created playbook {playbook['id']} by user {current_user['id']}")
        return playbook
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: str,
    request: UpdatePlaybookRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Update a playbook"""
    update_data = {k: v for k, v in request.model_dump().items() if v is not None}
    playbook = soar_engine.update_playbook(playbook_id, update_data)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    logger.info(f"Updated playbook {playbook_id} by user {current_user['id']}")
    return playbook

@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(
    playbook_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Delete a playbook"""
    if not soar_engine.delete_playbook(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    logger.info(f"Deleted playbook {playbook_id} by user {current_user['id']}")
    return {"success": True, "message": "Playbook deleted"}

@router.post("/playbooks/{playbook_id}/toggle")
async def toggle_playbook(
    playbook_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Toggle playbook active/disabled status"""
    playbook = soar_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    new_status = "disabled" if playbook["status"] == "active" else "active"
    updated = soar_engine.update_playbook(playbook_id, {"status": new_status})
    return {"success": True, "new_status": new_status}

@router.post("/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    event: TriggerEventRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Manually execute a playbook"""
    try:
        event_dict = event.model_dump()
        event_dict.update(event_dict.pop("extra", {}))
        
        execution = await soar_engine.execute_playbook(playbook_id, event_dict)
        logger.info(f"Executed playbook {playbook_id} by user {current_user['id']}")
        
        from dataclasses import asdict
        return asdict(execution)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/trigger")
async def trigger_playbooks(
    event: TriggerEventRequest,
    current_user: dict = Depends(get_current_user)
):
    """Trigger all matching playbooks for an event"""
    event_dict = event.model_dump()
    event_dict.update(event_dict.pop("extra", {}))
    
    executions = await soar_engine.trigger_playbooks(event_dict)
    
    from dataclasses import asdict
    return {
        "triggered_playbooks": len(executions),
        "executions": [asdict(e) for e in executions]
    }

@router.get("/executions")
async def list_executions(
    limit: int = 50,
    playbook_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get playbook execution history"""
    executions = soar_engine.get_executions(limit=limit, playbook_id=playbook_id)
    return {"executions": executions, "count": len(executions)}

@router.get("/actions")
async def list_available_actions(current_user: dict = Depends(get_current_user)):
    """Get list of available playbook actions"""
    from soar_engine import PlaybookAction
    actions = [
        {
            "value": a.value,
            "name": a.value.replace("_", " ").title(),
            "description": _get_action_description(a.value)
        }
        for a in PlaybookAction
    ]
    return {"actions": actions}

@router.get("/triggers")
async def list_available_triggers(current_user: dict = Depends(get_current_user)):
    """Get list of available playbook triggers"""
    from soar_engine import PlaybookTrigger
    triggers = [
        {
            "value": t.value,
            "name": t.value.replace("_", " ").title(),
            "description": _get_trigger_description(t.value)
        }
        for t in PlaybookTrigger
    ]
    return {"triggers": triggers}

def _get_action_description(action: str) -> str:
    descriptions = {
        "block_ip": "Block an IP address in the firewall",
        "kill_process": "Terminate a running process",
        "quarantine_file": "Move a file to quarantine",
        "send_alert": "Send notification to configured channels",
        "isolate_endpoint": "Disconnect endpoint from network",
        "collect_forensics": "Gather forensic evidence",
        "disable_user": "Disable a user account",
        "scan_endpoint": "Run antimalware scan on endpoint",
        "update_firewall": "Add or modify firewall rules",
        "create_ticket": "Create a support/incident ticket",
        # AI Defense Actions
        "throttle_cli": "Rate-limit AI agent CLI commands",
        "inject_latency": "Inject response delays to slow AI attackers",
        "deploy_decoy": "Deploy honey tokens/decoys for AI deception",
        "engage_tarpit": "Engage adaptive tarpit to trap AI threats",
        "capture_triage_bundle": "Capture full triage bundle for AI session",
        "capture_memory_snapshot": "Capture memory snapshot for forensics",
        "kill_process_tree": "Kill entire process tree (parent + children)",
        "tag_session": "Apply threat tags to session for tracking",
        "rotate_credentials": "Rotate compromised credentials",
        "notify": "Send notification to security team",
        "feed_disinformation": "Feed false data to mislead AI attackers"
    }
    return descriptions.get(action, "No description available")

def _get_trigger_description(trigger: str) -> str:
    descriptions = {
        "threat_detected": "Generic threat detection event",
        "malware_found": "Malware detected by scanner",
        "ransomware_detected": "Ransomware behavior detected",
        "suspicious_process": "Suspicious process identified",
        "ioc_match": "Indicator of compromise matched",
        "honeypot_triggered": "Honeypot accessed by attacker",
        "anomaly_detected": "Behavioral anomaly detected",
        "manual": "Manual playbook execution",
        # AI Agent Threat Triggers
        "ai_agent_detected": "Autonomous AI agent detected on session",
        "rapid_tool_switching": "Fast tool/command switching (AI pattern)",
        "decoy_touched": "Deployed decoy accessed by potential AI",
        "credential_spray_burst": "Burst credential spraying detected",
        "systematic_enumeration": "Systematic recon enumeration pattern",
        "ml_pattern_match": "Machine learning detected AI behavior",
        "goal_persistence_high": "High goal persistence typical of AI agents",
        "timing_anomaly": "Timing patterns indicate automation",
        "api_abuse_burst": "Burst API requests typical of AI",
        "lateral_automation": "Automated lateral movement detected"
    }
    return descriptions.get(trigger, "No description available")

# =============================================================================
# PLAYBOOK TEMPLATES
# =============================================================================

@router.get("/templates")
async def list_templates(
    category: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all playbook templates"""
    templates = soar_engine.get_templates(category=category)
    return {"templates": templates, "count": len(templates)}

@router.get("/templates/categories")
async def get_template_categories(current_user: dict = Depends(get_current_user)):
    """Get all template categories"""
    categories = soar_engine.get_template_categories()
    return {"categories": categories}

@router.get("/templates/{template_id}")
async def get_template(
    template_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific template"""
    template = soar_engine.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template

@router.post("/templates")
async def create_template(
    request: CreateTemplateRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a custom playbook template"""
    try:
        template = soar_engine.create_template(
            request.model_dump(),
            created_by=current_user["id"]
        )
        logger.info(f"Created template {template['id']} by user {current_user['id']}")
        return template
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/templates/{template_id}/clone")
async def clone_template(
    template_id: str,
    request: CloneTemplateRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new playbook from a template"""
    try:
        playbook = soar_engine.clone_from_template(
            template_id=template_id,
            name=request.name,
            created_by=current_user["id"]
        )
        logger.info(f"Cloned template {template_id} to playbook {playbook['id']} by user {current_user['id']}")
        return playbook
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

