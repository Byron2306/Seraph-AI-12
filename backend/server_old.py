from fastapi import FastAPI, APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import asyncio
import json
import random
import io
from openai import AsyncOpenAI
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from emergentintegrations.llm.chat import LlmChat, UserMessage

# Import notification and quarantine services
from notifications import (
    dispatcher, config as notification_config,
    notify_critical_threat, notify_malware_detected, 
    notify_quarantine_action, notify_intrusion_attempt,
    notify_new_host_discovered, send_slack_notification, 
    send_email_notification, log_to_elasticsearch
)
from quarantine import (
    quarantine_file, restore_file, delete_quarantined,
    list_quarantined, get_quarantine_entry, get_quarantine_summary,
    handle_malware_detection, QuarantineEntry
)
from threat_response import (
    response_engine, firewall, sms_service, openclaw, forensics,
    ThreatContext, ResponseAction, ResponseStatus,
    respond_to_intrusion, respond_to_malware, respond_to_port_scan,
    manual_block_ip, manual_unblock_ip, config as response_config
)
from audit_logging import (
    audit, AuditCategory, AuditSeverity,
    log_auth_event, log_user_action, log_threat_response,
    log_security_event, log_config_change, log_agent_event
)
from threat_timeline import timeline_builder, ThreatTimeline
from websocket_service import realtime_ws, WSMessageType, WSMessage
from runtime_paths import ensure_data_dir

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Set database for services
audit.set_database(db)
timeline_builder.set_database(db)

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'anti-ai-defense-secret')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# API Keys
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', '')

# Try OpenAI first, fallback to Emergent
openai_client = None
if OPENAI_API_KEY:
    openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

app = FastAPI(title="Anti-AI Defense System API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# WebSocket connection manager
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

# ============ MODELS ============

class UserCreate(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    name: str
    role: str = "analyst"
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ThreatCreate(BaseModel):
    name: str
    type: str  # ai_agent, malware, botnet, phishing, ransomware
    severity: str  # critical, high, medium, low
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    description: Optional[str] = None
    indicators: Optional[List[str]] = []

class ThreatResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    type: str
    severity: str
    status: str  # active, contained, resolved
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    description: Optional[str] = None
    indicators: List[str] = []
    ai_analysis: Optional[str] = None
    created_at: str
    updated_at: str

class AlertCreate(BaseModel):
    title: str
    type: str  # behavioral, signature, anomaly, ai_detected
    severity: str
    threat_id: Optional[str] = None
    message: str

class AlertResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    title: str
    type: str
    severity: str
    threat_id: Optional[str] = None
    message: str
    status: str  # new, acknowledged, resolved
    created_at: str

class AIAnalysisRequest(BaseModel):
    content: str
    analysis_type: str  # threat_detection, behavior_analysis, malware_scan, pattern_recognition

class AIAnalysisResponse(BaseModel):
    analysis_id: str
    analysis_type: str
    result: str
    threat_indicators: List[str]
    risk_score: float
    recommendations: List[str]
    timestamp: str

class DashboardStats(BaseModel):
    total_threats: int
    active_threats: int
    contained_threats: int
    resolved_threats: int
    critical_alerts: int
    threats_by_type: dict
    threats_by_severity: dict
    recent_threats: List[ThreatResponse]
    recent_alerts: List[AlertResponse]
    ai_scans_today: int
    system_health: float

# ============ AUTH HELPERS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============ AUTH ENDPOINTS ============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "role": "analyst",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id, user_data.email)
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            name=user_data.name,
            role="analyst",
            created_at=user_doc["created_at"]
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["email"])
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            name=user["name"],
            role=user.get("role", "analyst"),
            created_at=user["created_at"]
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# ============ THREAT ENDPOINTS ============

@api_router.post("/threats", response_model=ThreatResponse)
async def create_threat(threat_data: ThreatCreate, current_user: dict = Depends(get_current_user)):
    threat_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    threat_doc = {
        "id": threat_id,
        "name": threat_data.name,
        "type": threat_data.type,
        "severity": threat_data.severity,
        "status": "active",
        "source_ip": threat_data.source_ip,
        "target_system": threat_data.target_system,
        "description": threat_data.description,
        "indicators": threat_data.indicators or [],
        "ai_analysis": None,
        "created_at": now,
        "updated_at": now,
        "created_by": current_user["id"]
    }
    await db.threats.insert_one(threat_doc)
    return ThreatResponse(**threat_doc)

@api_router.get("/threats", response_model=List[ThreatResponse])
async def get_threats(status: Optional[str] = None, severity: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    
    threats = await db.threats.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [ThreatResponse(**t) for t in threats]

@api_router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: str, current_user: dict = Depends(get_current_user)):
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return ThreatResponse(**threat)

@api_router.patch("/threats/{threat_id}/status")
async def update_threat_status(threat_id: str, status: str, current_user: dict = Depends(get_current_user)):
    if status not in ["active", "contained", "resolved"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.threats.update_one(
        {"id": threat_id},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"message": "Status updated", "status": status}

# ============ ALERT ENDPOINTS ============

@api_router.post("/alerts", response_model=AlertResponse)
async def create_alert(alert_data: AlertCreate, current_user: dict = Depends(get_current_user)):
    alert_id = str(uuid.uuid4())
    alert_doc = {
        "id": alert_id,
        "title": alert_data.title,
        "type": alert_data.type,
        "severity": alert_data.severity,
        "threat_id": alert_data.threat_id,
        "message": alert_data.message,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.alerts.insert_one(alert_doc)
    return AlertResponse(**alert_doc)

@api_router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {}
    if status:
        query["status"] = status
    alerts = await db.alerts.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [AlertResponse(**a) for a in alerts]

@api_router.patch("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, status: str, current_user: dict = Depends(get_current_user)):
    if status not in ["new", "acknowledged", "resolved"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.alerts.update_one({"id": alert_id}, {"$set": {"status": status}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Alert status updated", "status": status}

# ============ AI ANALYSIS ENDPOINTS ============

async def call_openai(system_message: str, user_message: str) -> str:
    """Helper function to call AI API - tries OpenAI first, falls back to Emergent"""
    # Try OpenAI first if available
    if openai_client and OPENAI_API_KEY:
        try:
            response = await openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"OpenAI call failed, falling back to Emergent: {str(e)}")
    
    # Fallback to Emergent LLM
    if EMERGENT_LLM_KEY:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"analysis-{str(uuid.uuid4())[:8]}",
            system_message=system_message
        ).with_model("openai", "gpt-4o")
        
        msg = UserMessage(text=user_message)
        response = await chat.send_message(msg)
        return response
    
    raise Exception("No AI API available")

@api_router.post("/ai/analyze", response_model=AIAnalysisResponse)
async def ai_analyze(request: AIAnalysisRequest, current_user: dict = Depends(get_current_user)):
    analysis_id = str(uuid.uuid4())
    
    system_prompts = {
        "threat_detection": """You are an elite cybersecurity AI threat detection system. Analyze the provided content for potential threats including:
- Malicious code patterns
- AI-generated attack signatures
- Behavioral anomalies
- Known attack vectors
Provide a detailed threat assessment with specific indicators, risk score (0-100), and actionable recommendations.

Format your response with clear sections:
RISK SCORE: [0-100]
THREAT INDICATORS:
- [indicator 1]
- [indicator 2]
ANALYSIS:
[detailed analysis]
RECOMMENDATIONS:
- [recommendation 1]
- [recommendation 2]""",
        
        "behavior_analysis": """You are an advanced behavioral analysis AI. Examine the provided data for:
- Non-human interaction patterns (Turing test inversion)
- Algorithmic decision-making signatures
- Superhuman speed or consistency indicators
- Automated bot behaviors
Provide behavioral assessment with confidence scores and detection methods.

Format your response with:
RISK SCORE: [0-100]
BEHAVIOR TYPE: [human/bot/ai_agent/unknown]
CONFIDENCE: [percentage]
INDICATORS:
- [indicator]
ANALYSIS:
[detailed analysis]""",
        
        "malware_scan": """You are a polymorphic malware detection AI. Analyze for:
- Obfuscated code patterns
- Self-modifying code signatures
- Zero-day exploit indicators
- AI-generated malicious code
Provide malware classification, family identification if possible, and containment recommendations.

Format your response with:
RISK SCORE: [0-100]
MALWARE FAMILY: [family name or Unknown]
CLASSIFICATION: [trojan/ransomware/worm/etc]
INDICATORS:
- [indicator]
CONTAINMENT:
- [action]""",
        
        "pattern_recognition": """You are a pattern recognition AI for cyber threat intelligence. Identify:
- Attack campaign patterns
- Threat actor signatures
- Temporal patterns in attack data
- Correlations with known threat groups
Provide pattern analysis with attribution confidence and predicted next moves.

Format your response with:
RISK SCORE: [0-100]
THREAT ACTOR: [name or Unknown]
CAMPAIGN: [campaign name or Unknown]
PATTERNS:
- [pattern]
PREDICTED ACTIONS:
- [action]"""
    }
    
    system_message = system_prompts.get(request.analysis_type, system_prompts["threat_detection"])
    
    try:
        user_prompt = f"Analyze the following content:\n\n{request.content}\n\nProvide a structured analysis."
        response = await call_openai(system_message, user_prompt)
        
        # Parse response for structured data
        risk_score = 65.0  # Default moderate risk
        response_lower = response.lower()
        
        # Extract risk score from response
        if "risk score:" in response_lower:
            try:
                score_part = response_lower.split("risk score:")[1].split("\n")[0]
                score_num = ''.join(filter(str.isdigit, score_part[:10]))
                if score_num:
                    risk_score = min(100, max(0, float(score_num)))
            except:
                pass
        elif "critical" in response_lower or "high risk" in response_lower or "malicious" in response_lower:
            risk_score = 85.0
        elif "low risk" in response_lower or "benign" in response_lower or "safe" in response_lower:
            risk_score = 25.0
        
        # Extract indicators from response
        indicators = []
        if "indicators:" in response_lower or "indicator" in response_lower:
            lines = response.split("\n")
            for line in lines:
                if line.strip().startswith("-") and len(line.strip()) > 5:
                    indicator = line.strip()[1:].strip()
                    if len(indicator) > 3 and len(indicator) < 100:
                        indicators.append(indicator)
            indicators = indicators[:5]  # Limit to 5
        
        if not indicators:
            indicators = ["Pattern analysis completed", "Behavioral signature extracted"]
        
        # Extract recommendations
        recommendations = []
        if "recommend" in response_lower:
            in_recommendations = False
            for line in response.split("\n"):
                if "recommend" in line.lower():
                    in_recommendations = True
                if in_recommendations and line.strip().startswith("-"):
                    rec = line.strip()[1:].strip()
                    if len(rec) > 3:
                        recommendations.append(rec)
        
        if not recommendations:
            recommendations = ["Continue monitoring", "Update threat signatures", "Review access logs"]
        
        # Store analysis
        analysis_doc = {
            "id": analysis_id,
            "type": request.analysis_type,
            "content": request.content[:500],
            "result": response,
            "risk_score": risk_score,
            "indicators": indicators,
            "recommendations": recommendations[:5],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": current_user["id"]
        }
        await db.ai_analyses.insert_one(analysis_doc)
        
        # Increment scan counter
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        await db.scan_stats.update_one(
            {"date": today},
            {"$inc": {"count": 1}},
            upsert=True
        )
        
        return AIAnalysisResponse(
            analysis_id=analysis_id,
            analysis_type=request.analysis_type,
            result=response,
            threat_indicators=indicators,
            risk_score=risk_score,
            recommendations=recommendations,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"AI Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@api_router.get("/ai/analyses", response_model=List[dict])
async def get_ai_analyses(current_user: dict = Depends(get_current_user)):
    analyses = await db.ai_analyses.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return analyses

# ============ DASHBOARD ENDPOINTS ============

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    # Get threat counts
    total_threats = await db.threats.count_documents({})
    active_threats = await db.threats.count_documents({"status": "active"})
    contained_threats = await db.threats.count_documents({"status": "contained"})
    resolved_threats = await db.threats.count_documents({"status": "resolved"})
    
    # Get critical alerts
    critical_alerts = await db.alerts.count_documents({"severity": "critical", "status": {"$ne": "resolved"}})
    
    # Threats by type aggregation
    type_pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
    type_results = await db.threats.aggregate(type_pipeline).to_list(20)
    threats_by_type = {r["_id"]: r["count"] for r in type_results if r["_id"]}
    
    # Threats by severity
    severity_pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    severity_results = await db.threats.aggregate(severity_pipeline).to_list(10)
    threats_by_severity = {r["_id"]: r["count"] for r in severity_results if r["_id"]}
    
    # Recent threats
    recent_threats_data = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)
    recent_threats = [ThreatResponse(**t) for t in recent_threats_data]
    
    # Recent alerts
    recent_alerts_data = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)
    recent_alerts = [AlertResponse(**a) for a in recent_alerts_data]
    
    # AI scans today
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    scan_stat = await db.scan_stats.find_one({"date": today}, {"_id": 0})
    ai_scans_today = scan_stat["count"] if scan_stat else 0
    
    # System health (based on contained/resolved ratio)
    system_health = 100.0
    if total_threats > 0:
        system_health = ((contained_threats + resolved_threats) / total_threats) * 100
        system_health = min(100, max(0, system_health))
    
    return DashboardStats(
        total_threats=total_threats,
        active_threats=active_threats,
        contained_threats=contained_threats,
        resolved_threats=resolved_threats,
        critical_alerts=critical_alerts,
        threats_by_type=threats_by_type,
        threats_by_severity=threats_by_severity,
        recent_threats=recent_threats,
        recent_alerts=recent_alerts,
        ai_scans_today=ai_scans_today,
        system_health=system_health
    )

# ============ SEED DATA ============

@api_router.post("/seed")
async def seed_data():
    """Seed initial demo data"""
    # Check if data already exists
    existing = await db.threats.count_documents({})
    if existing > 0:
        return {"message": "Data already seeded"}
    
    # Sample threats
    sample_threats = [
        {
            "id": str(uuid.uuid4()),
            "name": "GPT-4 Autonomous Agent Attack",
            "type": "ai_agent",
            "severity": "critical",
            "status": "active",
            "source_ip": "192.168.1.105",
            "target_system": "Production API Server",
            "description": "Detected autonomous AI agent attempting to exploit API endpoints with adaptive attack patterns",
            "indicators": ["Superhuman request rate", "Adaptive payload modification", "Non-human timing patterns"],
            "ai_analysis": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Polymorphic Ransomware Variant",
            "type": "malware",
            "severity": "critical",
            "status": "contained",
            "source_ip": "10.0.0.45",
            "target_system": "File Server FS-01",
            "description": "AI-generated polymorphic ransomware detected, code mutations every 30 seconds",
            "indicators": ["Self-modifying bytecode", "Encrypted C2 communication", "Anti-sandbox techniques"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Adversarial ML Attack",
            "type": "ai_agent",
            "severity": "high",
            "status": "active",
            "source_ip": "172.16.0.88",
            "target_system": "ML Pipeline",
            "description": "Adversarial inputs detected attempting to poison training data in ML pipeline",
            "indicators": ["Gradient-based perturbations", "Training data injection", "Model inversion attempts"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Botnet Command Server",
            "type": "botnet",
            "severity": "high",
            "status": "active",
            "source_ip": "45.33.32.156",
            "target_system": "Network Edge",
            "description": "AI-coordinated botnet C2 server discovered communicating with internal hosts",
            "indicators": ["Encrypted beacon traffic", "Domain generation algorithm", "P2P mesh topology"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Deepfake Phishing Campaign",
            "type": "phishing",
            "severity": "medium",
            "status": "resolved",
            "source_ip": "unknown",
            "target_system": "Email Gateway",
            "description": "AI-generated deepfake video phishing attempt targeting executives",
            "indicators": ["Synthetic voice patterns", "Facial manipulation artifacts", "Social engineering vectors"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Sample alerts
    sample_alerts = [
        {
            "id": str(uuid.uuid4()),
            "title": "Critical: AI Agent Behavior Detected",
            "type": "ai_detected",
            "severity": "critical",
            "message": "Behavioral analysis flagged non-human interaction patterns on API endpoint /api/data",
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Anomaly: Unusual Traffic Spike",
            "type": "anomaly",
            "severity": "high",
            "message": "300% increase in API calls from single source with perfect timing distribution",
            "status": "acknowledged",
            "created_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Signature Match: Known Malware Family",
            "type": "signature",
            "severity": "high",
            "message": "File hash matches AI-generated malware variant LockAI.B",
            "status": "new",
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Behavioral: Model Probing Detected",
            "type": "behavioral",
            "severity": "medium",
            "message": "Sequential queries suggest systematic probing of ML model decision boundaries",
            "status": "acknowledged",
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        }
    ]
    
    await db.threats.insert_many(sample_threats)
    await db.alerts.insert_many(sample_alerts)
    
    return {"message": "Demo data seeded successfully", "threats": len(sample_threats), "alerts": len(sample_alerts)}

# ============ WEBSOCKET ENDPOINT ============

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for messages
            data = await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({"type": "ack", "message": "received"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Helper to broadcast threat updates
async def broadcast_threat_update(threat_data: dict, action: str):
    await ws_manager.broadcast({
        "type": "threat_update",
        "action": action,
        "data": threat_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# ============ NETWORK TOPOLOGY ENDPOINTS ============

class NetworkNode(BaseModel):
    id: str
    label: str
    type: str  # server, workstation, router, firewall, cloud, attacker
    ip: Optional[str] = None
    status: str = "normal"  # normal, compromised, suspicious, protected
    threat_count: int = 0

class NetworkLink(BaseModel):
    source: str
    target: str
    type: str = "connection"  # connection, attack, data_flow
    strength: float = 1.0

class NetworkTopology(BaseModel):
    nodes: List[NetworkNode]
    links: List[NetworkLink]

@api_router.get("/network/topology", response_model=NetworkTopology)
async def get_network_topology(current_user: dict = Depends(get_current_user)):
    """Generate network topology based on threats and system data"""
    
    # Get all threats with IPs
    threats = await db.threats.find({"status": {"$ne": "resolved"}}, {"_id": 0}).to_list(100)
    
    # Build nodes - core infrastructure
    nodes = [
        NetworkNode(id="firewall-1", label="Edge Firewall", type="firewall", ip="10.0.0.1", status="protected"),
        NetworkNode(id="router-1", label="Core Router", type="router", ip="10.0.0.2", status="normal"),
        NetworkNode(id="server-web", label="Web Server", type="server", ip="10.0.1.10", status="normal"),
        NetworkNode(id="server-api", label="API Server", type="server", ip="10.0.1.11", status="normal"),
        NetworkNode(id="server-db", label="Database", type="server", ip="10.0.1.20", status="protected"),
        NetworkNode(id="server-ml", label="ML Pipeline", type="server", ip="10.0.1.30", status="normal"),
        NetworkNode(id="server-file", label="File Server", type="server", ip="10.0.1.40", status="normal"),
        NetworkNode(id="cloud-1", label="Cloud Services", type="cloud", ip="cloud.defense.io", status="normal"),
        NetworkNode(id="ws-1", label="Analyst WS-01", type="workstation", ip="10.0.2.10", status="normal"),
        NetworkNode(id="ws-2", label="Analyst WS-02", type="workstation", ip="10.0.2.11", status="normal"),
    ]
    
    # Add attacker nodes based on threats
    attacker_ips = set()
    for threat in threats:
        if threat.get("source_ip") and threat["source_ip"] not in attacker_ips:
            attacker_ips.add(threat["source_ip"])
            severity = threat.get("severity", "medium")
            nodes.append(NetworkNode(
                id=f"attacker-{threat['source_ip'].replace('.', '-')}",
                label=f"Threat: {threat['name'][:20]}",
                type="attacker",
                ip=threat["source_ip"],
                status="compromised" if severity in ["critical", "high"] else "suspicious",
                threat_count=1
            ))
    
    # Update node statuses based on threats targeting them
    target_threats = {}
    for threat in threats:
        target = threat.get("target_system", "")
        if target:
            target_lower = target.lower()
            if "api" in target_lower:
                target_threats["server-api"] = target_threats.get("server-api", 0) + 1
            elif "web" in target_lower:
                target_threats["server-web"] = target_threats.get("server-web", 0) + 1
            elif "ml" in target_lower or "pipeline" in target_lower:
                target_threats["server-ml"] = target_threats.get("server-ml", 0) + 1
            elif "file" in target_lower:
                target_threats["server-file"] = target_threats.get("server-file", 0) + 1
            elif "database" in target_lower or "db" in target_lower:
                target_threats["server-db"] = target_threats.get("server-db", 0) + 1
    
    for node in nodes:
        if node.id in target_threats:
            node.threat_count = target_threats[node.id]
            node.status = "suspicious" if target_threats[node.id] >= 1 else node.status
            if target_threats[node.id] >= 2:
                node.status = "compromised"
    
    # Build links - infrastructure connections
    links = [
        NetworkLink(source="firewall-1", target="router-1", type="connection"),
        NetworkLink(source="router-1", target="server-web", type="connection"),
        NetworkLink(source="router-1", target="server-api", type="connection"),
        NetworkLink(source="router-1", target="server-db", type="connection"),
        NetworkLink(source="router-1", target="server-ml", type="connection"),
        NetworkLink(source="router-1", target="server-file", type="connection"),
        NetworkLink(source="server-api", target="server-db", type="data_flow"),
        NetworkLink(source="server-api", target="server-ml", type="data_flow"),
        NetworkLink(source="server-web", target="server-api", type="data_flow"),
        NetworkLink(source="cloud-1", target="firewall-1", type="connection"),
        NetworkLink(source="router-1", target="ws-1", type="connection"),
        NetworkLink(source="router-1", target="ws-2", type="connection"),
    ]
    
    # Add attack links from threats
    for threat in threats:
        if threat.get("source_ip"):
            attacker_id = f"attacker-{threat['source_ip'].replace('.', '-')}"
            target = threat.get("target_system", "").lower()
            target_id = "server-api"  # default
            if "web" in target:
                target_id = "server-web"
            elif "ml" in target or "pipeline" in target:
                target_id = "server-ml"
            elif "file" in target:
                target_id = "server-file"
            elif "database" in target or "db" in target:
                target_id = "server-db"
            
            links.append(NetworkLink(
                source=attacker_id,
                target="firewall-1",
                type="attack",
                strength=2.0 if threat.get("severity") == "critical" else 1.5
            ))
    
    return NetworkTopology(nodes=nodes, links=links)

# ============ THREAT HUNTING ENDPOINTS ============

class HuntingHypothesis(BaseModel):
    id: str
    title: str
    description: str
    category: str  # ai_behavior, malware, lateral_movement, data_exfil, persistence
    confidence: float
    indicators: List[str]
    recommended_actions: List[str]
    related_threats: List[str]
    status: str = "pending"  # pending, investigating, confirmed, dismissed
    created_at: str

class HuntingRequest(BaseModel):
    focus_area: Optional[str] = None  # ai_agents, malware, network, all
    time_range_hours: int = 24

@api_router.post("/hunting/generate", response_model=List[HuntingHypothesis])
async def generate_hunting_hypotheses(request: HuntingRequest, current_user: dict = Depends(get_current_user)):
    """AI-powered threat hunting hypothesis generation"""
    
    # Get recent threats and alerts for context
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    
    # Build context for AI
    context = f"""Recent Threats: {len(threats)} detected
Threat Types: {', '.join(set(t.get('type', 'unknown') for t in threats))}
Active Threats: {len([t for t in threats if t.get('status') == 'active'])}
Recent Alerts: {len(alerts)}
Focus Area: {request.focus_area or 'all'}
Time Range: Last {request.time_range_hours} hours"""

    try:
        system_message = """You are an elite threat hunting AI. Generate threat hunting hypotheses based on the security context provided.
For each hypothesis, provide:
1. A clear title
2. Detailed description of what to look for
3. Category (ai_behavior, malware, lateral_movement, data_exfil, persistence)
4. Confidence score (0-100)
5. Specific indicators to search for
6. Recommended investigation actions

Return exactly 3-5 hypotheses in a structured format. Be specific and actionable."""

        user_prompt = f"""Based on this security context, generate threat hunting hypotheses:

{context}

Threat Details:
{json.dumps([{'name': t.get('name'), 'type': t.get('type'), 'severity': t.get('severity'), 'indicators': t.get('indicators', [])} for t in threats[:5]], indent=2)}

Generate hunting hypotheses that would help discover hidden threats or validate existing detections."""
        
        ai_response = await call_openai(system_message, user_prompt)
        logger.info(f"AI generated hunting response: {ai_response[:200]}...")
        
        # Generate structured hypotheses based on context and AI response
        hypotheses = []
        
        # AI Agent Detection Hypothesis
        if not request.focus_area or request.focus_area in ["ai_agents", "all"]:
            ai_threats = [t for t in threats if t.get("type") == "ai_agent"]
            hypotheses.append(HuntingHypothesis(
                id=str(uuid.uuid4()),
                title="Undetected AI Agent Activity",
                description="Hunt for AI agents that may be evading current detection by analyzing API request patterns, timing distributions, and behavioral signatures that indicate non-human operators.",
                category="ai_behavior",
                confidence=75.0 if ai_threats else 50.0,
                indicators=[
                    "Requests with sub-millisecond timing precision",
                    "Perfect distribution of request intervals",
                    "Adaptive payload modifications",
                    "Sequential endpoint enumeration patterns"
                ],
                recommended_actions=[
                    "Analyze API logs for timing anomalies",
                    "Review authentication patterns for automated behavior",
                    "Check for systematic data access patterns",
                    "Monitor for adversarial ML inputs"
                ],
                related_threats=[t.get("id", "") for t in ai_threats[:3]],
                status="pending",
                created_at=datetime.now(timezone.utc).isoformat()
            ))
        
        # Lateral Movement Hypothesis
        if not request.focus_area or request.focus_area in ["network", "all"]:
            hypotheses.append(HuntingHypothesis(
                id=str(uuid.uuid4()),
                title="Internal Lateral Movement Detection",
                description="Hunt for signs of lateral movement within the network by analyzing internal traffic patterns, unusual authentication sequences, and cross-system access that deviates from baseline behavior.",
                category="lateral_movement",
                confidence=60.0,
                indicators=[
                    "Unusual internal SSH/RDP connections",
                    "Service account usage anomalies",
                    "Sequential system access patterns",
                    "Off-hours administrative actions"
                ],
                recommended_actions=[
                    "Review internal firewall logs",
                    "Analyze authentication logs for pass-the-hash indicators",
                    "Check for unusual service account activity",
                    "Map internal connection patterns"
                ],
                related_threats=[],
                status="pending",
                created_at=datetime.now(timezone.utc).isoformat()
            ))
        
        # Malware Persistence Hypothesis  
        if not request.focus_area or request.focus_area in ["malware", "all"]:
            malware_threats = [t for t in threats if t.get("type") in ["malware", "ransomware"]]
            hypotheses.append(HuntingHypothesis(
                id=str(uuid.uuid4()),
                title="Hidden Persistence Mechanisms",
                description="Hunt for malware persistence mechanisms that may have been established during previous compromises, including registry modifications, scheduled tasks, and startup entries.",
                category="persistence",
                confidence=70.0 if malware_threats else 45.0,
                indicators=[
                    "Modified startup registry keys",
                    "Unusual scheduled tasks",
                    "Hidden services or drivers",
                    "Modified system binaries"
                ],
                recommended_actions=[
                    "Run autoruns analysis on critical systems",
                    "Compare current state to known-good baselines",
                    "Check for unsigned drivers or services",
                    "Review scheduled task creation logs"
                ],
                related_threats=[t.get("id", "") for t in malware_threats[:3]],
                status="pending",
                created_at=datetime.now(timezone.utc).isoformat()
            ))
        
        # Data Exfiltration Hypothesis
        hypotheses.append(HuntingHypothesis(
            id=str(uuid.uuid4()),
            title="Covert Data Exfiltration Channels",
            description="Hunt for potential data exfiltration activities including DNS tunneling, encrypted channels to unknown destinations, and unusual outbound data volumes.",
            category="data_exfil",
            confidence=55.0,
            indicators=[
                "High-entropy DNS queries",
                "Large outbound data to new destinations",
                "Connections to known bad IPs/domains",
                "Unusual protocol usage on standard ports"
            ],
            recommended_actions=[
                "Analyze DNS query logs for tunneling patterns",
                "Review NetFlow data for volume anomalies",
                "Check TLS certificate validity for outbound connections",
                "Monitor cloud storage API access patterns"
            ],
            related_threats=[],
            status="pending",
            created_at=datetime.now(timezone.utc).isoformat()
        ))
        
        # Store hypotheses
        for h in hypotheses:
            await db.hunting_hypotheses.insert_one(h.model_dump())
        
        return hypotheses
        
    except Exception as e:
        logger.error(f"Hunting hypothesis generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate hypotheses: {str(e)}")

@api_router.get("/hunting/hypotheses", response_model=List[HuntingHypothesis])
async def get_hunting_hypotheses(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Get all hunting hypotheses"""
    query = {}
    if status:
        query["status"] = status
    hypotheses = await db.hunting_hypotheses.find(query, {"_id": 0}).sort("created_at", -1).to_list(50)
    return [HuntingHypothesis(**h) for h in hypotheses]

@api_router.patch("/hunting/hypotheses/{hypothesis_id}/status")
async def update_hypothesis_status(hypothesis_id: str, status: str, current_user: dict = Depends(get_current_user)):
    """Update hunting hypothesis status"""
    if status not in ["pending", "investigating", "confirmed", "dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.hunting_hypotheses.update_one(
        {"id": hypothesis_id},
        {"$set": {"status": status}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"message": "Status updated", "status": status}

# ============ ROLE-BASED ACCESS CONTROL ============

ROLES = {
    "admin": ["read", "write", "delete", "manage_users", "manage_honeypots", "export_reports"],
    "analyst": ["read", "write", "export_reports"],
    "viewer": ["read"]
}

class RoleUpdate(BaseModel):
    role: str

def check_permission(required_permission: str):
    async def permission_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role", "viewer")
        permissions = ROLES.get(user_role, [])
        if required_permission not in permissions:
            raise HTTPException(status_code=403, detail=f"Permission denied. Required: {required_permission}")
        return current_user
    return permission_checker

@api_router.patch("/users/{user_id}/role")
async def update_user_role(user_id: str, role_update: RoleUpdate, current_user: dict = Depends(check_permission("manage_users"))):
    """Update user role (admin only)"""
    if role_update.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Valid roles: {list(ROLES.keys())}")
    
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"role": role_update.role}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Role updated", "role": role_update.role}

@api_router.get("/users")
async def list_users(current_user: dict = Depends(check_permission("manage_users"))):
    """List all users (admin only)"""
    users = await db.users.find({}, {"_id": 0, "password": 0}).to_list(100)
    return users

# ============ HONEYPOT SYSTEM ============

class HoneypotCreate(BaseModel):
    name: str
    type: str  # ssh, http, ftp, smb, database
    ip: str
    port: int
    description: Optional[str] = None

class HoneypotResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    type: str
    ip: str
    port: int
    description: Optional[str] = None
    status: str  # active, inactive, triggered
    interactions: int
    last_interaction: Optional[str] = None
    created_at: str

class HoneypotInteraction(BaseModel):
    id: str
    honeypot_id: str
    source_ip: str
    source_port: int
    timestamp: str
    action: str  # connection, login_attempt, command, file_access
    data: Dict[str, Any]
    threat_level: str  # low, medium, high

@api_router.post("/honeypots", response_model=HoneypotResponse)
async def create_honeypot(honeypot_data: HoneypotCreate, current_user: dict = Depends(check_permission("manage_honeypots"))):
    """Create a new honeypot"""
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

@api_router.get("/honeypots", response_model=List[HoneypotResponse])
async def get_honeypots(current_user: dict = Depends(get_current_user)):
    """Get all honeypots"""
    honeypots = await db.honeypots.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return [HoneypotResponse(**h) for h in honeypots]

@api_router.post("/honeypots/{honeypot_id}/interaction")
async def record_honeypot_interaction(honeypot_id: str, source_ip: str, action: str, data: dict = {}):
    """Record an interaction with a honeypot (called by honeypot sensors)"""
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
    
    return {"message": "Interaction recorded", "id": interaction_id, "threat_level": threat_levels.get(action)}

@api_router.get("/honeypots/{honeypot_id}/interactions", response_model=List[HoneypotInteraction])
async def get_honeypot_interactions(honeypot_id: str, current_user: dict = Depends(get_current_user)):
    """Get interactions for a specific honeypot"""
    interactions = await db.honeypot_interactions.find(
        {"honeypot_id": honeypot_id}, {"_id": 0}
    ).sort("timestamp", -1).to_list(100)
    return [HoneypotInteraction(**i) for i in interactions]

@api_router.patch("/honeypots/{honeypot_id}/status")
async def update_honeypot_status(honeypot_id: str, status: str, current_user: dict = Depends(check_permission("manage_honeypots"))):
    """Update honeypot status"""
    if status not in ["active", "inactive", "triggered"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.honeypots.update_one({"id": honeypot_id}, {"$set": {"status": status}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    return {"message": "Status updated", "status": status}

# ============ PDF REPORT GENERATION ============

def generate_threat_report_pdf(threats: List[dict], alerts: List[dict], stats: dict) -> io.BytesIO:
    """Generate PDF threat intelligence report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#3B82F6')
    ))
    styles.add(ParagraphStyle(
        name='SectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.HexColor('#1E293B')
    ))
    styles.add(ParagraphStyle(
        name='CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=8
    ))
    
    elements = []
    
    # Title
    elements.append(Paragraph("THREAT INTELLIGENCE REPORT", styles['TitleStyle']))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles['CustomBody']))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", styles['SectionTitle']))
    summary_data = [
        ['Metric', 'Value'],
        ['Total Threats', str(stats.get('total_threats', 0))],
        ['Active Threats', str(stats.get('active_threats', 0))],
        ['Contained Threats', str(stats.get('contained_threats', 0))],
        ['Resolved Threats', str(stats.get('resolved_threats', 0))],
        ['Critical Alerts', str(stats.get('critical_alerts', 0))],
        ['System Health', f"{stats.get('system_health', 100):.1f}%"]
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3B82F6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1E293B')),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('ROWHEIGHT', (0, 0), (-1, -1), 25)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Active Threats Section
    elements.append(Paragraph("ACTIVE THREATS", styles['SectionTitle']))
    active_threats = [t for t in threats if t.get('status') == 'active']
    
    if active_threats:
        threat_data = [['Name', 'Type', 'Severity', 'Source IP']]
        for threat in active_threats[:10]:
            threat_data.append([
                threat.get('name', 'Unknown')[:30],
                threat.get('type', 'Unknown'),
                threat.get('severity', 'Unknown').upper(),
                threat.get('source_ip', 'N/A')
            ])
        
        threat_table = Table(threat_data, colWidths=[150, 80, 80, 100])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EF4444')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWHEIGHT', (0, 0), (-1, -1), 22)
        ]))
        elements.append(threat_table)
    else:
        elements.append(Paragraph("No active threats at this time.", styles['CustomBody']))
    
    elements.append(Spacer(1, 20))
    
    # Recent Alerts Section
    elements.append(Paragraph("RECENT ALERTS", styles['SectionTitle']))
    if alerts:
        alert_data = [['Title', 'Type', 'Severity', 'Status']]
        for alert in alerts[:10]:
            alert_data.append([
                alert.get('title', 'Unknown')[:35],
                alert.get('type', 'Unknown'),
                alert.get('severity', 'Unknown').upper(),
                alert.get('status', 'Unknown')
            ])
        
        alert_table = Table(alert_data, colWidths=[170, 80, 80, 80])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F59E0B')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWHEIGHT', (0, 0), (-1, -1), 22)
        ]))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No recent alerts.", styles['CustomBody']))
    
    elements.append(Spacer(1, 30))
    
    # Footer
    elements.append(Paragraph("--- End of Report ---", styles['CustomBody']))
    elements.append(Paragraph("Generated by Anti-AI Defense System", styles['CustomBody']))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

@api_router.get("/reports/threat-intelligence")
async def generate_threat_report(current_user: dict = Depends(check_permission("export_reports"))):
    """Generate PDF threat intelligence report"""
    # Gather data
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    
    # Calculate stats
    total_threats = len(threats)
    active_threats = len([t for t in threats if t.get('status') == 'active'])
    contained_threats = len([t for t in threats if t.get('status') == 'contained'])
    resolved_threats = len([t for t in threats if t.get('status') == 'resolved'])
    critical_alerts = len([a for a in alerts if a.get('severity') == 'critical' and a.get('status') != 'resolved'])
    
    system_health = 100.0
    if total_threats > 0:
        system_health = ((contained_threats + resolved_threats) / total_threats) * 100
    
    stats = {
        'total_threats': total_threats,
        'active_threats': active_threats,
        'contained_threats': contained_threats,
        'resolved_threats': resolved_threats,
        'critical_alerts': critical_alerts,
        'system_health': system_health
    }
    
    # Generate PDF
    pdf_buffer = generate_threat_report_pdf(threats, alerts, stats)
    
    filename = f"threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@api_router.post("/reports/ai-summary")
async def generate_ai_summary_report(current_user: dict = Depends(check_permission("export_reports"))):
    """Generate AI-powered threat summary"""
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    
    context = f"""
Threats Summary:
- Total: {len(threats)}
- Active: {len([t for t in threats if t.get('status') == 'active'])}
- Types: {', '.join(set(t.get('type', 'unknown') for t in threats))}

Alerts Summary:
- Total: {len(alerts)}
- Critical: {len([a for a in alerts if a.get('severity') == 'critical'])}

Recent Threat Names:
{chr(10).join(['- ' + t.get('name', 'Unknown') for t in threats[:5]])}
"""
    
    system_message = """You are a cybersecurity analyst. Provide a concise executive summary of the current threat landscape based on the data provided. Include:
1. Overall risk assessment (Critical/High/Medium/Low)
2. Key findings (3-5 bullet points)
3. Recommended immediate actions (2-3 points)
4. Trend analysis

Keep the summary professional and actionable."""

    try:
        summary = await call_openai(system_message, f"Analyze this security data and provide an executive summary:\n{context}")
        return {
            "summary": summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_points": {
                "threats_analyzed": len(threats),
                "alerts_analyzed": len(alerts)
            }
        }
    except Exception as e:
        logger.error(f"AI summary generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate summary: {str(e)}")

# ============ LOCAL AGENT ENDPOINTS ============

class AgentEvent(BaseModel):
    agent_id: str
    agent_name: str
    event_type: str
    timestamp: str
    data: Dict[str, Any]

class AgentInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    ip: Optional[str] = None
    os: Optional[str] = None
    status: str = "online"
    last_heartbeat: str
    system_info: Dict[str, Any] = {}
    created_at: str

@api_router.post("/agent/event")
async def receive_agent_event(event: AgentEvent):
    """Receive events from local security agents (no auth required for agents)"""
    logger.info(f"Agent event from {event.agent_name}: {event.event_type}")
    
    # Update or create agent record
    agent_doc = {
        "id": event.agent_id,
        "name": event.agent_name,
        "status": "online",
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
    }
    
    if event.event_type == "heartbeat":
        # Update agent system info
        agent_doc["system_info"] = event.data
        agent_doc["ip"] = event.data.get("network_interfaces", [{}])[0].get("ip") if event.data.get("network_interfaces") else None
        agent_doc["os"] = event.data.get("os")
        
        await db.agents.update_one(
            {"id": event.agent_id},
            {"$set": agent_doc, "$setOnInsert": {"created_at": datetime.now(timezone.utc).isoformat()}},
            upsert=True
        )
        
        # Broadcast to WebSocket
        await ws_manager.broadcast({
            "type": "agent_heartbeat",
            "agent_id": event.agent_id,
            "agent_name": event.agent_name,
            "timestamp": event.timestamp
        })
        
        return {"status": "ok", "message": "Heartbeat received"}
    
    elif event.event_type == "alert":
        # Create alert from agent
        alert_data = event.data
        alert_doc = {
            "id": str(uuid.uuid4()),
            "title": alert_data.get("title", "Agent Alert"),
            "type": alert_data.get("alert_type", "agent"),
            "severity": alert_data.get("severity", "medium"),
            "message": json.dumps(alert_data.get("details", {}))[:500],
            "status": "new",
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.alerts.insert_one(alert_doc)
        
        # Broadcast to WebSocket
        await ws_manager.broadcast({
            "type": "new_alert",
            "alert": alert_doc,
            "from_agent": event.agent_name
        })
        
        return {"status": "ok", "alert_id": alert_doc["id"]}
    
    elif event.event_type == "suricata_alert":
        # Create threat from Suricata IDS alert
        suricata_data = event.data
        severity = "critical" if suricata_data.get("severity", 3) == 1 else "high" if suricata_data.get("severity", 3) == 2 else "medium"
        
        threat_doc = {
            "id": str(uuid.uuid4()),
            "name": f"IDS Alert: {suricata_data.get('signature', 'Unknown')}",
            "type": "ids_alert",
            "severity": severity,
            "status": "active",
            "source_ip": suricata_data.get("src_ip"),
            "target_system": suricata_data.get("dest_ip"),
            "description": f"Suricata IDS detected: {suricata_data.get('signature')}. Category: {suricata_data.get('category')}",
            "indicators": [
                f"Signature ID: {suricata_data.get('signature_id')}",
                f"Protocol: {suricata_data.get('protocol')}",
                f"Source Port: {suricata_data.get('src_port')}",
                f"Dest Port: {suricata_data.get('dest_port')}"
            ],
            "ai_analysis": None,
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        await db.threats.insert_one(threat_doc)
        
        # AUTOMATED THREAT RESPONSE - Process intrusion with agentic response
        response_results = []
        try:
            response_results = await respond_to_intrusion(
                source_ip=suricata_data.get('src_ip'),
                signature=suricata_data.get('signature', 'Unknown'),
                severity=severity,
                agent_name=event.agent_name
            )
            
            # Update threat with response actions
            actions_taken = [r.action.value for r in response_results if r.status.value == "success"]
            if actions_taken:
                await db.threats.update_one(
                    {"id": threat_doc["id"]},
                    {"$set": {"automated_response": actions_taken, "response_timestamp": datetime.now(timezone.utc).isoformat()}}
                )
        except Exception as e:
            logger.error(f"Automated response failed: {e}")
        
        # Send intrusion notification
        try:
            await notify_intrusion_attempt(
                signature=suricata_data.get('signature', 'Unknown'),
                source_ip=suricata_data.get('src_ip', 'Unknown'),
                dest_ip=suricata_data.get('dest_ip', 'Unknown'),
                category=suricata_data.get('category'),
                agent_name=event.agent_name
            )
        except Exception as e:
            logger.error(f"Failed to send intrusion notification: {e}")
        
        # Broadcast to WebSocket
        ip_blocked = any(r.action.value == "block_ip" and r.status.value == "success" for r in response_results)
        await ws_manager.broadcast({
            "type": "new_threat",
            "threat": {"id": threat_doc["id"], "name": threat_doc["name"], "severity": threat_doc["severity"]},
            "source": "suricata",
            "auto_blocked": ip_blocked
        })
        
        return {"status": "ok", "threat_id": threat_doc["id"], "ip_blocked": ip_blocked}
    
    elif event.event_type == "yara_match":
        # Create threat from YARA malware detection
        yara_data = event.data
        matches = yara_data.get("matches", [])
        match_names = [m.get("rule", "Unknown") for m in matches]
        filepath = yara_data.get("filepath", "Unknown")
        
        # Determine severity based on rule metadata
        severity = "high"
        threat_type = "malware"
        for match in matches:
            meta = match.get("meta", {})
            if meta.get("severity") == "critical":
                severity = "critical"
            if meta.get("category"):
                threat_type = meta.get("category")
        
        threat_doc = {
            "id": str(uuid.uuid4()),
            "name": f"Malware Detected: {', '.join(match_names[:3])}",
            "type": threat_type,
            "severity": severity,
            "status": "active",
            "source_ip": None,
            "target_system": filepath,
            "description": f"YARA rules matched on file: {filepath}",
            "indicators": [
                f"File: {filepath}",
                f"Rules matched: {', '.join(match_names)}",
                f"File size: {yara_data.get('file_size', 'Unknown')} bytes"
            ],
            "ai_analysis": None,
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        await db.threats.insert_one(threat_doc)
        
        # Create critical alert
        alert_doc = {
            "id": str(uuid.uuid4()),
            "title": f"Malware Detected: {match_names[0] if match_names else 'Unknown'}",
            "type": "malware",
            "severity": severity,
            "message": f"File: {filepath}. Matched rules: {', '.join(match_names)}",
            "status": "new",
            "threat_id": threat_doc["id"],
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.alerts.insert_one(alert_doc)
        
        # AUTO-QUARANTINE: Handle malware detection with auto-quarantine
        quarantine_result = None
        try:
            quarantine_result = await handle_malware_detection(
                filepath=filepath,
                threat_name=match_names[0] if match_names else "Unknown",
                threat_type=threat_type,
                detection_source="yara",
                agent_id=event.agent_id,
                agent_name=event.agent_name,
                auto_quarantine=True,
                notify=True
            )
            
            # Store quarantine info in threat document
            if quarantine_result.get("quarantined"):
                await db.threats.update_one(
                    {"id": threat_doc["id"]},
                    {"$set": {
                        "quarantine_info": quarantine_result.get("quarantine_entry"),
                        "status": "quarantined"
                    }}
                )
        except Exception as e:
            logger.error(f"Auto-quarantine failed: {e}")
        
        # Broadcast
        await ws_manager.broadcast({
            "type": "malware_detected",
            "threat_id": threat_doc["id"],
            "file": filepath,
            "rules": match_names,
            "quarantined": quarantine_result.get("quarantined", False) if quarantine_result else False
        })
        
        return {
            "status": "ok", 
            "threat_id": threat_doc["id"], 
            "alert_id": alert_doc["id"],
            "quarantined": quarantine_result.get("quarantined", False) if quarantine_result else False
        }
    
    elif event.event_type == "network_scan":
        # Store network scan results
        scan_doc = {
            "id": str(uuid.uuid4()),
            "agent_id": event.agent_id,
            "agent_name": event.agent_name,
            "hosts": event.data.get("hosts", []),
            "host_count": len(event.data.get("hosts", [])),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await db.network_scans.insert_one(scan_doc)
        
        # Update network topology with discovered hosts
        for host in event.data.get("hosts", []):
            await db.discovered_hosts.update_one(
                {"ip": host.get("ip")},
                {"$set": {
                    "ip": host.get("ip"),
                    "hostname": host.get("hostname"),
                    "mac": host.get("mac"),
                    "vendor": host.get("vendor"),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "discovered_by": event.agent_name
                }},
                upsert=True
            )
        
        return {"status": "ok", "hosts_recorded": len(event.data.get("hosts", []))}
    
    elif event.event_type == "suspicious_packet":
        # Log suspicious network traffic
        packet_data = event.data
        
        # Create alert for suspicious traffic
        alert_doc = {
            "id": str(uuid.uuid4()),
            "title": f"Suspicious Traffic: {packet_data.get('reason', 'Unknown')}",
            "type": "network",
            "severity": "high",
            "message": f"From {packet_data.get('src_ip')}:{packet_data.get('src_port')} to {packet_data.get('dst_ip')}:{packet_data.get('dst_port')}",
            "status": "new",
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.alerts.insert_one(alert_doc)
        
        # Store packet info
        await db.suspicious_packets.insert_one({
            **packet_data,
            "agent_id": event.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return {"status": "ok", "alert_id": alert_doc["id"]}
    
    else:
        # Store generic event
        await db.agent_events.insert_one({
            "agent_id": event.agent_id,
            "agent_name": event.agent_name,
            "event_type": event.event_type,
            "data": event.data,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        return {"status": "ok", "message": "Event recorded"}

@api_router.get("/agents", response_model=List[AgentInfo])
async def get_agents(current_user: dict = Depends(get_current_user)):
    """Get all registered security agents"""
    agents = await db.agents.find({}, {"_id": 0}).sort("last_heartbeat", -1).to_list(50)
    
    # Mark agents as offline if no heartbeat in 2 minutes
    now = datetime.now(timezone.utc)
    for agent in agents:
        try:
            last_hb = datetime.fromisoformat(agent.get("last_heartbeat", "").replace("Z", "+00:00"))
            if (now - last_hb).total_seconds() > 120:
                agent["status"] = "offline"
        except:
            agent["status"] = "unknown"
    
    return [AgentInfo(**a) for a in agents]

@api_router.get("/network/discovered-hosts")
async def get_discovered_hosts(current_user: dict = Depends(get_current_user)):
    """Get all hosts discovered by agents"""
    hosts = await db.discovered_hosts.find({}, {"_id": 0}).sort("last_seen", -1).to_list(200)
    return hosts

@api_router.get("/network/scans")
async def get_network_scans(limit: int = 10, current_user: dict = Depends(get_current_user)):
    """Get recent network scan results"""
    scans = await db.network_scans.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return scans

@api_router.get("/agent/download")
async def download_agent_script():
    """Download the comprehensive security suite installer"""
    # Use the new comprehensive installer
    installer_path = ROOT_DIR.parent / "scripts" / "defender_installer.py"
    
    if not installer_path.exists():
        # Fallback to old script
        installer_path = ROOT_DIR.parent / "scripts" / "local_agent.py"
    
    if not installer_path.exists():
        raise HTTPException(status_code=404, detail="Agent installer not found")
    
    with open(installer_path, 'r') as f:
        content = f.read()
    
    # Update the API URL dynamically
    backend_url = os.environ.get("REACT_APP_BACKEND_URL", "https://seraph-security.preview.emergentagent.com")
    content = content.replace(
        'CLOUD_API_URL = "https://seraph-security.preview.emergentagent.com/api"',
        f'CLOUD_API_URL = "{backend_url}/api"'
    )
    # Also update for legacy format
    content = content.replace(
        '"API_URL": "https://seraph-security.preview.emergentagent.com/api"',
        f'"API_URL": "{backend_url}/api"'
    )
    content = content.replace(
        '"api_url": "https://seraph-security.preview.emergentagent.com/api"',
        f'"api_url": "{backend_url}/api"'
    )
    
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/x-python",
        headers={"Content-Disposition": "attachment; filename=defender_installer.py"}
    )

@api_router.get("/agent/download/legacy")
async def download_legacy_agent():
    """Download the legacy simple agent script"""
    agent_script_path = ROOT_DIR.parent / "scripts" / "local_agent.py"
    
    if not agent_script_path.exists():
        raise HTTPException(status_code=404, detail="Agent script not found")
    
    with open(agent_script_path, 'r') as f:
        content = f.read()
    
    backend_url = os.environ.get("REACT_APP_BACKEND_URL", "https://seraph-security.preview.emergentagent.com")
    content = content.replace(
        '"API_URL": "https://seraph-security.preview.emergentagent.com/api"',
        f'"API_URL": "{backend_url}/api"'
    )
    
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/x-python",
        headers={"Content-Disposition": "attachment; filename=local_agent.py"}
    )

# ============ QUARANTINE MANAGEMENT ENDPOINTS ============

class QuarantineActionRequest(BaseModel):
    entry_id: str

@api_router.get("/quarantine")
async def get_quarantine_list(
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get list of quarantined files"""
    entries = list_quarantined(status=status, threat_type=threat_type, limit=limit)
    return {"entries": [vars(e) if hasattr(e, '__dict__') else e.__dict__ for e in entries]}

@api_router.get("/quarantine/summary")
async def get_quarantine_stats(current_user: dict = Depends(get_current_user)):
    """Get quarantine system summary statistics"""
    return get_quarantine_summary()

@api_router.get("/quarantine/{entry_id}")
async def get_quarantine_details(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Get details of a specific quarantine entry"""
    entry = get_quarantine_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")
    return vars(entry) if hasattr(entry, '__dict__') else entry.__dict__

@api_router.post("/quarantine/{entry_id}/restore")
async def restore_quarantined_file(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Restore a quarantined file to its original location"""
    # Only admins can restore files
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Only administrators can restore quarantined files")
    
    success = restore_file(entry_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to restore file")
    
    return {"status": "ok", "message": "File restored successfully"}

@api_router.delete("/quarantine/{entry_id}")
async def delete_quarantine_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Permanently delete a quarantined file"""
    # Only admins can delete
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Only administrators can delete quarantined files")
    
    success = delete_quarantined(entry_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete file")
    
    return {"status": "ok", "message": "File permanently deleted"}

# ============ NOTIFICATION SETTINGS ENDPOINTS ============

class NotificationSettingsUpdate(BaseModel):
    slack_webhook_url: Optional[str] = None
    sendgrid_api_key: Optional[str] = None
    sender_email: Optional[str] = None
    alert_recipients: Optional[List[str]] = None
    elasticsearch_url: Optional[str] = None
    elasticsearch_api_key: Optional[str] = None

class TestNotificationRequest(BaseModel):
    channel: str  # slack, email, or all
    message: Optional[str] = "This is a test notification from Anti-AI Defense System"

@api_router.get("/settings/notifications")
async def get_notification_settings(current_user: dict = Depends(get_current_user)):
    """Get current notification settings (masked for security)"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "slack": {
            "enabled": notification_config.slack_enabled,
            "webhook_configured": bool(notification_config.slack_webhook_url)
        },
        "email": {
            "enabled": notification_config.email_enabled,
            "sendgrid_configured": bool(notification_config.sendgrid_api_key),
            "sender_email": notification_config.sender_email,
            "recipients_count": len([r for r in notification_config.alert_recipients if r])
        },
        "elasticsearch": {
            "enabled": notification_config.elasticsearch_enabled,
            "url_configured": bool(notification_config.elasticsearch_url)
        }
    }

@api_router.post("/settings/notifications")
async def update_notification_settings(
    settings: NotificationSettingsUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update notification settings"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Store settings in database for persistence
    settings_doc = {
        "type": "notification_settings",
        "updated_by": current_user.get("email"),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    if settings.slack_webhook_url is not None:
        settings_doc["slack_webhook_url"] = settings.slack_webhook_url
        notification_config.slack_webhook_url = settings.slack_webhook_url
    
    if settings.sendgrid_api_key is not None:
        settings_doc["sendgrid_api_key"] = settings.sendgrid_api_key
        notification_config.sendgrid_api_key = settings.sendgrid_api_key
    
    if settings.sender_email is not None:
        settings_doc["sender_email"] = settings.sender_email
        notification_config.sender_email = settings.sender_email
    
    if settings.alert_recipients is not None:
        settings_doc["alert_recipients"] = settings.alert_recipients
        notification_config.alert_recipients = settings.alert_recipients
    
    if settings.elasticsearch_url is not None:
        settings_doc["elasticsearch_url"] = settings.elasticsearch_url
        notification_config.elasticsearch_url = settings.elasticsearch_url
    
    if settings.elasticsearch_api_key is not None:
        settings_doc["elasticsearch_api_key"] = settings.elasticsearch_api_key
        notification_config.elasticsearch_api_key = settings.elasticsearch_api_key
    
    await db.settings.update_one(
        {"type": "notification_settings"},
        {"$set": settings_doc},
        upsert=True
    )
    
    return {"status": "ok", "message": "Notification settings updated"}

@api_router.post("/settings/notifications/test")
async def test_notification(
    request: TestNotificationRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Send a test notification"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    results = {}
    
    if request.channel in ["slack", "all"]:
        if notification_config.slack_enabled:
            success = await send_slack_notification(
                title="Test Notification",
                message=request.message,
                severity="low",
                fields={"Sent By": current_user.get("email", "Unknown")}
            )
            results["slack"] = success
        else:
            results["slack"] = "Not configured"
    
    if request.channel in ["email", "all"]:
        if notification_config.email_enabled:
            success = await send_email_notification(
                subject="Test Notification",
                body=request.message,
                severity="low"
            )
            results["email"] = success
        else:
            results["email"] = "Not configured"
    
    return {"status": "ok", "results": results}

# ============ ELASTICSEARCH/KIBANA INTEGRATION ============

@api_router.get("/elasticsearch/status")
async def get_elasticsearch_status(current_user: dict = Depends(get_current_user)):
    """Check Elasticsearch connection status"""
    if not notification_config.elasticsearch_enabled:
        return {"status": "not_configured", "message": "Elasticsearch URL not set"}
    
    try:
        import httpx
        headers = {"Content-Type": "application/json"}
        if notification_config.elasticsearch_api_key:
            headers["Authorization"] = f"ApiKey {notification_config.elasticsearch_api_key}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(notification_config.elasticsearch_url, headers=headers, timeout=5)
            if response.status_code == 200:
                return {"status": "connected", "info": response.json()}
            else:
                return {"status": "error", "code": response.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@api_router.get("/elasticsearch/indices")
async def get_elasticsearch_indices(current_user: dict = Depends(get_current_user)):
    """Get list of security-related Elasticsearch indices"""
    if not notification_config.elasticsearch_enabled:
        raise HTTPException(status_code=400, detail="Elasticsearch not configured")
    
    try:
        import httpx
        headers = {"Content-Type": "application/json"}
        if notification_config.elasticsearch_api_key:
            headers["Authorization"] = f"ApiKey {notification_config.elasticsearch_api_key}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{notification_config.elasticsearch_url}/_cat/indices/security-*?format=json",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return {"indices": response.json()}
            else:
                raise HTTPException(status_code=response.status_code, detail="Failed to get indices")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/elasticsearch/search")
async def search_elasticsearch(
    index: str = "security-events-*",
    query: Optional[Dict[str, Any]] = None,
    size: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Search Elasticsearch for security events"""
    if not notification_config.elasticsearch_enabled:
        raise HTTPException(status_code=400, detail="Elasticsearch not configured")
    
    search_body = {
        "query": query or {"match_all": {}},
        "size": min(size, 1000),
        "sort": [{"@timestamp": "desc"}]
    }
    
    try:
        import httpx
        headers = {"Content-Type": "application/json"}
        if notification_config.elasticsearch_api_key:
            headers["Authorization"] = f"ApiKey {notification_config.elasticsearch_api_key}"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{notification_config.elasticsearch_url}/{index}/_search",
                json=search_body,
                headers=headers,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(status_code=response.status_code, detail="Search failed")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============ AUTOMATED THREAT RESPONSE ENDPOINTS ============

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"
    duration_hours: int = 24

class ThreatResponseSettingsUpdate(BaseModel):
    auto_block_enabled: Optional[bool] = None
    auto_isolate_enabled: Optional[bool] = None
    block_duration_hours: Optional[int] = None
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_phone_number: Optional[str] = None
    emergency_contacts: Optional[List[str]] = None
    openclaw_enabled: Optional[bool] = None
    openclaw_gateway_url: Optional[str] = None
    openclaw_api_key: Optional[str] = None

@api_router.get("/threat-response/stats")
async def get_threat_response_stats(current_user: dict = Depends(get_current_user)):
    """Get statistics about automated threat responses"""
    stats = await response_engine.get_response_stats()
    return stats

@api_router.get("/threat-response/blocked-ips")
async def get_blocked_ips_list(current_user: dict = Depends(get_current_user)):
    """Get list of currently blocked IPs"""
    blocked = response_engine.get_blocked_ips()
    return {"blocked_ips": blocked, "count": len(blocked)}

@api_router.post("/threat-response/block-ip")
async def block_ip_endpoint(
    request: BlockIPRequest,
    current_user: dict = Depends(get_current_user)
):
    """Manually block an IP address"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await manual_block_ip(request.ip, request.reason, request.duration_hours)
    
    # Log the action
    await db.response_actions.insert_one({
        "action": "block_ip",
        "ip": request.ip,
        "reason": request.reason,
        "duration_hours": request.duration_hours,
        "performed_by": current_user.get("email"),
        "result": result.status.value,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    if result.status.value == "success":
        return {"status": "ok", "message": f"IP {request.ip} blocked successfully"}
    else:
        raise HTTPException(status_code=400, detail=result.message)

@api_router.post("/threat-response/unblock-ip/{ip}")
async def unblock_ip_endpoint(ip: str, current_user: dict = Depends(get_current_user)):
    """Manually unblock an IP address"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await manual_unblock_ip(ip)
    
    # Log the action
    await db.response_actions.insert_one({
        "action": "unblock_ip",
        "ip": ip,
        "performed_by": current_user.get("email"),
        "result": result.status.value,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    if result.status.value == "success":
        return {"status": "ok", "message": f"IP {ip} unblocked successfully"}
    else:
        raise HTTPException(status_code=400, detail=result.message)

@api_router.get("/threat-response/history")
async def get_response_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get history of automated threat responses"""
    history = response_engine.response_history[-limit:]
    return {"history": list(reversed(history)), "total": len(response_engine.response_history)}

@api_router.get("/threat-response/settings")
async def get_threat_response_settings(current_user: dict = Depends(get_current_user)):
    """Get current threat response settings"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "auto_response": {
            "auto_block_enabled": response_config.auto_block_enabled,
            "auto_isolate_enabled": response_config.auto_isolate_enabled,
            "block_duration_hours": response_config.block_duration_hours,
            "critical_threat_threshold": response_config.critical_threat_threshold
        },
        "sms_alerts": {
            "enabled": response_config.twilio_enabled,
            "phone_configured": bool(response_config.twilio_phone_number),
            "contacts_count": len([c for c in response_config.emergency_contacts if c])
        },
        "openclaw": {
            "enabled": response_config.openclaw_enabled,
            "gateway_url": response_config.openclaw_gateway_url if response_config.openclaw_enabled else None
        }
    }

@api_router.post("/threat-response/settings")
async def update_threat_response_settings(
    settings: ThreatResponseSettingsUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update threat response settings"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    settings_doc = {
        "type": "threat_response_settings",
        "updated_by": current_user.get("email"),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    if settings.auto_block_enabled is not None:
        response_config.auto_block_enabled = settings.auto_block_enabled
        settings_doc["auto_block_enabled"] = settings.auto_block_enabled
    
    if settings.block_duration_hours is not None:
        response_config.block_duration_hours = settings.block_duration_hours
        settings_doc["block_duration_hours"] = settings.block_duration_hours
    
    if settings.twilio_account_sid is not None:
        response_config.twilio_account_sid = settings.twilio_account_sid
        settings_doc["twilio_configured"] = True
    
    if settings.twilio_auth_token is not None:
        response_config.twilio_auth_token = settings.twilio_auth_token
    
    if settings.twilio_phone_number is not None:
        response_config.twilio_phone_number = settings.twilio_phone_number
        settings_doc["twilio_phone_number"] = settings.twilio_phone_number
    
    if settings.emergency_contacts is not None:
        response_config.emergency_contacts = settings.emergency_contacts
        settings_doc["emergency_contacts_count"] = len(settings.emergency_contacts)
    
    if settings.openclaw_enabled is not None:
        response_config.openclaw_enabled = settings.openclaw_enabled
        settings_doc["openclaw_enabled"] = settings.openclaw_enabled
    
    if settings.openclaw_gateway_url is not None:
        response_config.openclaw_gateway_url = settings.openclaw_gateway_url
        settings_doc["openclaw_gateway_url"] = settings.openclaw_gateway_url
    
    await db.settings.update_one(
        {"type": "threat_response_settings"},
        {"$set": settings_doc},
        upsert=True
    )
    
    return {"status": "ok", "message": "Threat response settings updated"}

@api_router.post("/threat-response/test-sms")
async def test_sms_alert(current_user: dict = Depends(get_current_user)):
    """Send a test SMS alert"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if not response_config.twilio_enabled:
        raise HTTPException(status_code=400, detail="Twilio SMS not configured")
    
    result = await sms_service.send_emergency_sms(
        message=f"Test alert from Anti-AI Defense System. Triggered by {current_user.get('email')}"
    )
    
    if result.status.value == "success":
        return {"status": "ok", "message": result.message, "details": result.details}
    else:
        raise HTTPException(status_code=400, detail=result.message)

@api_router.get("/threat-response/openclaw/status")
async def get_openclaw_status(current_user: dict = Depends(get_current_user)):
    """Check OpenClaw gateway status"""
    available = await openclaw.is_available()
    return {
        "enabled": response_config.openclaw_enabled,
        "available": available,
        "gateway_url": response_config.openclaw_gateway_url if response_config.openclaw_enabled else None
    }

@api_router.post("/threat-response/openclaw/analyze")
async def openclaw_analyze_threat(
    threat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Use OpenClaw AI to analyze a specific threat"""
    if not response_config.openclaw_enabled:
        raise HTTPException(status_code=400, detail="OpenClaw not enabled")
    
    # Get threat from database
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    context = ThreatContext(
        threat_id=threat_id,
        threat_type=threat.get("type", "unknown"),
        severity=threat.get("severity", "medium"),
        source_ip=threat.get("source_ip"),
        target_path=threat.get("target_system"),
        indicators=threat.get("indicators", [])
    )
    
    analysis = await openclaw.analyze_threat(context)
    
    # Store analysis in threat document
    await db.threats.update_one(
        {"id": threat_id},
        {"$set": {"ai_analysis": analysis.get("analysis"), "analyzed_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"analysis": analysis}

@api_router.get("/threat-response/forensics/{incident_id}")
async def get_forensics_data(
    incident_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get forensic data for an incident"""
    forensics_path = ensure_data_dir("forensics") / incident_id
    
    if not forensics_path.exists():
        raise HTTPException(status_code=404, detail="Forensics data not found")
    
    artifacts = []
    for f in forensics_path.iterdir():
        artifacts.append({
            "name": f.name,
            "size": f.stat().st_size,
            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
        })
    
    # Read threat context if available
    context_file = forensics_path / "threat_context.json"
    context = None
    if context_file.exists():
        with open(context_file) as f:
            context = json.load(f)
    
    return {
        "incident_id": incident_id,
        "path": str(forensics_path),
        "artifacts": artifacts,
        "threat_context": context
    }

# ============ AUDIT LOG ENDPOINTS ============

@api_router.get("/audit/logs")
async def get_audit_logs(
    category: Optional[str] = None,
    actor: Optional[str] = None,
    target_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get audit log entries with optional filtering"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = await audit.search(
        category=category,
        actor=actor,
        target_type=target_type,
        severity=severity,
        limit=min(limit, 500)
    )
    return {"logs": logs, "count": len(logs)}

@api_router.get("/audit/stats")
async def get_audit_stats(current_user: dict = Depends(get_current_user)):
    """Get audit log statistics"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    stats = await audit.get_stats()
    return stats

@api_router.get("/audit/recent")
async def get_recent_audit(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get recent audit entries from memory buffer"""
    entries = await audit.get_recent(limit=min(limit, 200))
    return {"entries": [vars(e) if hasattr(e, '__dict__') else e.__dict__ for e in entries]}

@api_router.post("/audit/cleanup")
async def cleanup_audit_logs(
    days: int = 90,
    current_user: dict = Depends(get_current_user)
):
    """Clean up old audit logs"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    deleted = await audit.cleanup_old_entries(days)
    return {"status": "ok", "deleted_count": deleted}

# ============ THREAT TIMELINE ENDPOINTS ============

@api_router.get("/timeline/{threat_id}")
async def get_threat_timeline(
    threat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get complete timeline for a threat incident"""
    timeline = await timeline_builder.build_timeline(threat_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Log the access
    await log_user_action(
        action="view_timeline",
        actor=current_user.get("email"),
        target_type="threat",
        target_id=threat_id,
        description=f"Viewed timeline for threat {threat_id}"
    )
    
    return {
        "threat_id": timeline.threat_id,
        "threat_name": timeline.threat_name,
        "threat_type": timeline.threat_type,
        "severity": timeline.severity,
        "status": timeline.status,
        "first_seen": timeline.first_seen,
        "last_updated": timeline.last_updated,
        "events": [vars(e) if hasattr(e, '__dict__') else e.__dict__ for e in timeline.events],
        "summary": timeline.summary,
        "impact_assessment": timeline.impact_assessment,
        "recommendations": timeline.recommendations
    }

@api_router.get("/timeline/{threat_id}/export")
async def export_threat_timeline(
    threat_id: str,
    format: str = "json",
    current_user: dict = Depends(get_current_user)
):
    """Export timeline in specified format"""
    if format not in ["json", "markdown"]:
        raise HTTPException(status_code=400, detail="Format must be 'json' or 'markdown'")
    
    content = await timeline_builder.export_timeline(threat_id, format)
    if not content:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    if format == "json":
        return json.loads(content)
    else:
        return {"markdown": content}

@api_router.get("/timelines/recent")
async def get_recent_timelines(
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """Get summaries of recent threat timelines"""
    summaries = await timeline_builder.get_recent_timelines(limit=min(limit, 50))
    return {"timelines": summaries}

# ============ ENHANCED WEBSOCKET ENDPOINTS ============

@api_router.get("/websocket/stats")
async def get_websocket_stats(current_user: dict = Depends(get_current_user)):
    """Get WebSocket connection statistics"""
    return realtime_ws.get_stats()

@api_router.get("/websocket/agents")
async def get_connected_agents_ws(current_user: dict = Depends(get_current_user)):
    """Get list of WebSocket-connected agents"""
    return {"agents": realtime_ws.get_connected_agents()}

@api_router.post("/websocket/command/{agent_id}")
async def send_command_to_agent(
    agent_id: str,
    command: str,
    parameters: Optional[Dict[str, Any]] = None,
    current_user: dict = Depends(get_current_user)
):
    """Send a command to a specific agent via WebSocket"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    success = await realtime_ws.send_command(agent_id, command, parameters)
    
    # Log the command
    await log_user_action(
        action="send_command",
        actor=current_user.get("email"),
        target_type="agent",
        target_id=agent_id,
        description=f"Sent command '{command}' to agent {agent_id}",
        details={"command": command, "parameters": parameters}
    )
    
    if success:
        return {"status": "ok", "message": f"Command sent to agent {agent_id}"}
    else:
        return {"status": "queued", "message": f"Agent {agent_id} offline. Command queued."}

@api_router.post("/websocket/scan/{agent_id}")
async def request_agent_scan(
    agent_id: str,
    scan_type: str,
    target: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Request a scan from a specific agent"""
    if scan_type not in ["network", "yara", "clamav", "process"]:
        raise HTTPException(status_code=400, detail="Invalid scan type")
    
    success = await realtime_ws.request_scan(agent_id, scan_type, target)
    
    return {
        "status": "ok" if success else "queued",
        "message": f"Scan request {'sent' if success else 'queued'} for agent {agent_id}"
    }

# ============ OPENCLAW GATEWAY CONFIGURATION ============

class OpenClawConfig(BaseModel):
    enabled: bool
    gateway_url: str
    api_key: Optional[str] = None

@api_router.get("/openclaw/config")
async def get_openclaw_config(current_user: dict = Depends(get_current_user)):
    """Get OpenClaw gateway configuration"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "enabled": response_config.openclaw_enabled,
        "gateway_url": response_config.openclaw_gateway_url,
        "api_key_configured": bool(response_config.openclaw_api_key)
    }

@api_router.post("/openclaw/config")
async def update_openclaw_config(
    config_update: OpenClawConfig,
    current_user: dict = Depends(get_current_user)
):
    """Update OpenClaw gateway configuration"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    old_enabled = response_config.openclaw_enabled
    old_url = response_config.openclaw_gateway_url
    
    response_config.openclaw_enabled = config_update.enabled
    response_config.openclaw_gateway_url = config_update.gateway_url
    if config_update.api_key:
        response_config.openclaw_api_key = config_update.api_key
    
    # Log configuration change
    await log_config_change(
        setting="openclaw",
        actor=current_user.get("email"),
        old_value={"enabled": old_enabled, "url": old_url},
        new_value={"enabled": config_update.enabled, "url": config_update.gateway_url}
    )
    
    # Save to database
    await db.settings.update_one(
        {"type": "openclaw_settings"},
        {"$set": {
            "enabled": config_update.enabled,
            "gateway_url": config_update.gateway_url,
            "api_key_configured": bool(config_update.api_key),
            "updated_by": current_user.get("email"),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }},
        upsert=True
    )
    
    return {"status": "ok", "message": "OpenClaw configuration updated"}

@api_router.post("/openclaw/test")
async def test_openclaw_connection(current_user: dict = Depends(get_current_user)):
    """Test OpenClaw gateway connection"""
    if current_user.get("role") not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if not response_config.openclaw_enabled:
        raise HTTPException(status_code=400, detail="OpenClaw not enabled")
    
    available = await openclaw.is_available()
    
    if available:
        # Try a simple task
        result = await openclaw.execute_security_task(
            task="Test connection - respond with 'OK' if you receive this message.",
            tools=[]
        )
        return {
            "status": "connected",
            "gateway_url": response_config.openclaw_gateway_url,
            "test_response": result.details.get("ai_response", "No response") if result.status.value == "success" else "Failed"
        }
    else:
        return {
            "status": "offline",
            "gateway_url": response_config.openclaw_gateway_url,
            "message": "Gateway not reachable"
        }

# ============ ROOT ENDPOINT ============

@api_router.get("/")
async def root():
    return {"message": "Anti-AI Defense System API", "version": "1.0.0", "status": "operational"}

# Include router and middleware
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
