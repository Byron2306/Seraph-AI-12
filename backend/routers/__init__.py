# Anti-AI Defense System - API Routers
# Modular router architecture for better maintainability

from .auth import router as auth_router
from .threats import router as threats_router
from .alerts import router as alerts_router
from .ai_analysis import router as ai_router
from .dashboard import router as dashboard_router
from .network import router as network_router
from .hunting import router as hunting_router
from .honeypots import router as honeypots_router
from .reports import router as reports_router
from .agents import router as agents_router
from .quarantine import router as quarantine_router
from .settings import router as settings_router
from .response import router as response_router
from .audit import router as audit_router
from .timeline import router as timeline_router
from .websocket import router as websocket_router
from .openclaw import router as openclaw_router
from .threat_intel import router as threat_intel_router
from .ransomware import router as ransomware_router
from .containers import router as containers_router
from .vpn import router as vpn_router

__all__ = [
    'auth_router',
    'threats_router', 
    'alerts_router',
    'ai_router',
    'dashboard_router',
    'network_router',
    'hunting_router',
    'honeypots_router',
    'reports_router',
    'agents_router',
    'quarantine_router',
    'settings_router',
    'response_router',
    'audit_router',
    'timeline_router',
    'websocket_router',
    'openclaw_router',
    'threat_intel_router',
    'ransomware_router',
    'containers_router',
    'vpn_router'
]
