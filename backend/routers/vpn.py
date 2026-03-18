"""
VPN Integration Router
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission

# Import VPN service
from vpn_integration import vpn_manager, VPNManager

router = APIRouter(prefix="/vpn", tags=["VPN"])

class AddPeerRequest(BaseModel):
    name: str

@router.get("/status")
async def get_vpn_status(current_user: dict = Depends(get_current_user)):
    """Get VPN server status"""
    status = await vpn_manager.get_status()
    
    # Add server public key for display
    if vpn_manager.server.server_config:
        status["server"]["public_key"] = vpn_manager.server.server_config.public_key
    
    return status

@router.post("/initialize")
async def initialize_vpn(current_user: dict = Depends(check_permission("write"))):
    """Initialize VPN server (generates keys and config)"""
    result = await vpn_manager.initialize()
    return result

@router.post("/start")
async def start_vpn(current_user: dict = Depends(check_permission("write"))):
    """Start VPN server"""
    result = await vpn_manager.start()
    return result

@router.post("/stop")
async def stop_vpn(current_user: dict = Depends(check_permission("write"))):
    """Stop VPN server"""
    result = await vpn_manager.stop()
    return result

@router.get("/peers")
async def get_peers(current_user: dict = Depends(get_current_user)):
    """Get all VPN peers"""
    peers = vpn_manager.get_peers()
    return {"peers": peers, "count": len(peers)}

@router.post("/peers")
async def add_peer(request: AddPeerRequest, current_user: dict = Depends(check_permission("write"))):
    """Add a new VPN peer/client"""
    peer = await vpn_manager.add_peer(request.name)
    return {"message": "Peer added", "peer": peer}

@router.get("/peers/{peer_id}/config")
async def get_peer_config(peer_id: str, current_user: dict = Depends(get_current_user)):
    """Get WireGuard configuration file for a peer"""
    config = vpn_manager.get_peer_config(peer_id)
    if not config:
        raise HTTPException(status_code=404, detail="Peer not found")
    return PlainTextResponse(content=config, media_type="text/plain")

@router.delete("/peers/{peer_id}")
async def remove_peer(peer_id: str, current_user: dict = Depends(check_permission("write"))):
    """Remove a VPN peer"""
    success = await vpn_manager.remove_peer(peer_id)
    if not success:
        raise HTTPException(status_code=404, detail="Peer not found")
    return {"message": "Peer removed"}

@router.get("/kill-switch")
async def get_kill_switch_status(current_user: dict = Depends(get_current_user)):
    """Get kill switch status"""
    return vpn_manager.kill_switch.get_status()

@router.post("/kill-switch/enable")
async def enable_kill_switch(current_user: dict = Depends(check_permission("manage_users"))):
    """Enable VPN kill switch"""
    result = await vpn_manager.kill_switch.enable()
    return result

@router.post("/kill-switch/disable")
async def disable_kill_switch(current_user: dict = Depends(check_permission("manage_users"))):
    """Disable VPN kill switch"""
    result = await vpn_manager.kill_switch.disable()
    return result
