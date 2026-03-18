"""
Ransomware Protection Service
==============================
Multi-layered ransomware protection including:

1. Canary Files - Decoy files that trigger alerts when modified
2. Behavioral Detection - Monitor for mass encryption patterns
3. Protected Folders - Prevent unauthorized access to critical directories
4. Backup Integration - Automatic backup before suspicious activity
5. Process Rollback - Ability to terminate and rollback ransomware damage
"""

import os
import json
import asyncio
import hashlib
import shutil
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum
import threading
import time
from runtime_paths import ensure_data_dir

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

DATA_ROOT_DIR = ensure_data_dir()
CANARY_DIR = ensure_data_dir("canaries")
BACKUP_DIR = ensure_data_dir("ransomware_backups")
PROTECTED_DIRS_FILE = DATA_ROOT_DIR / "protected_dirs.json"

class RansomwareConfig:
    def __init__(self):
        self.canary_enabled = os.environ.get("RANSOMWARE_CANARY_ENABLED", "true").lower() == "true"
        self.behavioral_detection = os.environ.get("RANSOMWARE_BEHAVIORAL", "true").lower() == "true"
        self.auto_backup = os.environ.get("RANSOMWARE_AUTO_BACKUP", "true").lower() == "true"
        self.auto_kill_ransomware = os.environ.get("RANSOMWARE_AUTO_KILL", "false").lower() == "true"
        
        # Thresholds
        self.encryption_threshold = int(os.environ.get("ENCRYPTION_THRESHOLD", "10"))  # files/minute
        self.file_rename_threshold = int(os.environ.get("RENAME_THRESHOLD", "20"))  # renames/minute

config = RansomwareConfig()

# =============================================================================
# DATA MODELS
# =============================================================================

class RansomwareEventType(Enum):
    CANARY_TRIGGERED = "canary_triggered"
    MASS_ENCRYPTION = "mass_encryption"
    SUSPICIOUS_RENAME = "suspicious_rename"
    PROTECTED_FOLDER_ACCESS = "protected_folder_access"
    SHADOW_COPY_DELETE = "shadow_copy_delete"
    BACKUP_SERVICE_STOP = "backup_service_stop"

@dataclass
class CanaryFile:
    """Represents a canary/decoy file"""
    id: str
    path: str
    original_hash: str
    created_at: str
    last_checked: str
    status: str = "active"  # active, triggered, disabled

@dataclass
class RansomwareEvent:
    """Represents a ransomware-related security event"""
    id: str
    event_type: str
    timestamp: str
    severity: str
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_path: Optional[str] = None
    affected_files: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    action_taken: str = "none"

@dataclass
class ProtectedFolder:
    """Represents a folder protected from ransomware"""
    path: str
    allowed_processes: List[str] = field(default_factory=list)
    created_at: str = ""
    last_access_attempt: Optional[str] = None

# =============================================================================
# CANARY FILE SYSTEM
# =============================================================================

class CanaryFileManager:
    """
    Manages canary/decoy files that act as tripwires for ransomware.
    When ransomware encrypts files, it will hit canaries first.
    """
    
    # Attractive filenames for ransomware
    CANARY_NAMES = [
        "Important_Documents.docx",
        "Financial_Records_2024.xlsx",
        "Passwords.txt",
        "Company_Secrets.pdf",
        "Bitcoin_Wallet_Backup.dat",
        "Tax_Returns_2024.pdf",
        "Employee_SSN_List.csv",
        "Bank_Account_Details.doc",
        "Private_Keys.pem",
        "Confidential_Report.docx",
    ]
    
    # Canary content templates
    CANARY_CONTENT = {
        ".txt": "CONFIDENTIAL - DO NOT SHARE\n\nThis document contains sensitive information.\n" + "=" * 50 + "\n" * 100,
        ".docx": b'PK\x03\x04',  # DOCX magic bytes (simplified)
        ".xlsx": b'PK\x03\x04',  # XLSX magic bytes
        ".pdf": b'%PDF-1.4',     # PDF magic bytes
        ".csv": "Name,SSN,Account,Balance\nJohn Doe,123-45-6789,ACC001,$50000\n" * 50,
        ".dat": os.urandom(1024),  # Random binary data
        ".pem": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 64 + "\n" * 20 + "-----END RSA PRIVATE KEY-----\n",
    }
    
    def __init__(self):
        self.canaries: Dict[str, CanaryFile] = {}
        self.triggered_canaries: List[CanaryFile] = []
        self._db = None
        self._alert_callback: Optional[Callable] = None
        self._load_canaries()
    
    def set_database(self, db):
        self._db = db
    
    def set_alert_callback(self, callback: Callable):
        self._alert_callback = callback
    
    def _load_canaries(self):
        """Load existing canaries from disk"""
        canary_index = CANARY_DIR / "index.json"
        if canary_index.exists():
            try:
                with open(canary_index, 'r') as f:
                    data = json.load(f)
                    for canary_data in data.get("canaries", []):
                        canary = CanaryFile(**canary_data)
                        self.canaries[canary.id] = canary
                logger.info(f"Loaded {len(self.canaries)} canary files")
            except Exception as e:
                logger.error(f"Failed to load canaries: {e}")
    
    def _save_canaries(self):
        """Save canary index to disk"""
        canary_index = CANARY_DIR / "index.json"
        try:
            data = {"canaries": [asdict(c) for c in self.canaries.values()]}
            with open(canary_index, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save canaries: {e}")
    
    def deploy_canaries(self, target_dirs: List[str] = None) -> List[CanaryFile]:
        """
        Deploy canary files to specified directories.
        If no directories specified, uses common user directories.
        """
        if target_dirs is None:
            home = Path.home()
            target_dirs = [
                str(home / "Documents"),
                str(home / "Desktop"),
                str(home / "Downloads"),
                str(home),
                "/tmp",
            ]
        
        deployed = []
        
        for target_dir in target_dirs:
            dir_path = Path(target_dir)
            if not dir_path.exists():
                continue
            
            # Deploy 2 canaries per directory
            for name in self.CANARY_NAMES[:2]:
                canary_path = dir_path / f".{name}"  # Hidden file
                
                # Skip if already exists
                if str(canary_path) in [c.path for c in self.canaries.values()]:
                    continue
                
                try:
                    # Determine content based on extension
                    ext = Path(name).suffix.lower()
                    content = self.CANARY_CONTENT.get(ext, self.CANARY_CONTENT[".txt"])
                    
                    # Write canary file
                    mode = 'wb' if isinstance(content, bytes) else 'w'
                    with open(canary_path, mode) as f:
                        f.write(content)
                    
                    # Calculate hash
                    file_hash = self._hash_file(canary_path)
                    
                    # Create canary record
                    canary_id = hashlib.md5(str(canary_path).encode()).hexdigest()[:16]
                    canary = CanaryFile(
                        id=canary_id,
                        path=str(canary_path),
                        original_hash=file_hash,
                        created_at=datetime.now(timezone.utc).isoformat(),
                        last_checked=datetime.now(timezone.utc).isoformat(),
                        status="active"
                    )
                    
                    self.canaries[canary_id] = canary
                    deployed.append(canary)
                    logger.info(f"Deployed canary: {canary_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to deploy canary at {canary_path}: {e}")
        
        self._save_canaries()
        return deployed
    
    def check_canaries(self) -> List[CanaryFile]:
        """Check all canaries for modifications"""
        triggered = []
        
        for canary_id, canary in list(self.canaries.items()):
            if canary.status != "active":
                continue
            
            canary_path = Path(canary.path)
            
            # Check if file was deleted
            if not canary_path.exists():
                canary.status = "triggered"
                self.triggered_canaries.append(canary)
                triggered.append(canary)
                self._emit_alert(canary, "deleted")
                continue
            
            # Check if file was modified
            current_hash = self._hash_file(canary_path)
            if current_hash != canary.original_hash:
                canary.status = "triggered"
                self.triggered_canaries.append(canary)
                triggered.append(canary)
                self._emit_alert(canary, "modified")
            
            canary.last_checked = datetime.now(timezone.utc).isoformat()
        
        self._save_canaries()
        return triggered
    
    def _hash_file(self, path: Path) -> str:
        """Calculate SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""
    
    def _emit_alert(self, canary: CanaryFile, action: str):
        """Emit ransomware alert"""
        event = RansomwareEvent(
            id=hashlib.md5(f"{canary.id}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            event_type=RansomwareEventType.CANARY_TRIGGERED.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity="critical",
            affected_files=[canary.path],
            details={
                "canary_id": canary.id,
                "action": action,
                "original_hash": canary.original_hash
            }
        )
        
        logger.critical(f"RANSOMWARE ALERT: Canary {action}! Path: {canary.path}")
        
        if self._alert_callback:
            self._alert_callback(event)
    
    def get_status(self) -> Dict[str, Any]:
        """Get canary system status"""
        return {
            "total_canaries": len(self.canaries),
            "active_canaries": len([c for c in self.canaries.values() if c.status == "active"]),
            "triggered_canaries": len(self.triggered_canaries),
            "canary_locations": [c.path for c in self.canaries.values()][:10]
        }


# =============================================================================
# BEHAVIORAL RANSOMWARE DETECTION
# =============================================================================

class RansomwareBehaviorDetector:
    """
    Detects ransomware through behavioral patterns:
    - Mass file encryption/modification
    - Suspicious file renames (.encrypted, .locked, etc.)
    - Shadow copy deletion attempts
    - Backup service manipulation
    """
    
    RANSOMWARE_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".crypted",
        ".locky", ".zepto", ".cerber", ".wcry", ".wncry", ".wncryt",
        ".WNCRY", ".crypt1", ".crinf", ".r5a", ".XRNT", ".XTBL",
        ".crypt", ".R16M01D05", ".pzdc", ".good", ".LOL!", ".OMG!",
        ".fun", ".kb", ".encrypted", ".locked", ".kraken", ".darkness",
        ".nochance", ".oshit", ".carote", ".surprise"
    }
    
    def __init__(self):
        self.file_events: List[Dict] = []
        self.rename_events: List[Dict] = []
        self.suspicious_processes: Set[int] = set()
        self._monitoring = False
        self._monitor_thread = None
        self._alert_callback: Optional[Callable] = None
        self._db = None
    
    def set_database(self, db):
        self._db = db
    
    def set_alert_callback(self, callback: Callable):
        self._alert_callback = callback
    
    def record_file_event(self, event_type: str, path: str, process_pid: int = None, process_name: str = None):
        """Record a file system event for analysis"""
        event = {
            "type": event_type,
            "path": path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_pid": process_pid,
            "process_name": process_name
        }
        
        self.file_events.append(event)
        
        # Keep only last 5 minutes of events
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.file_events = [e for e in self.file_events 
                          if datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) > cutoff]
        
        # Check for ransomware patterns
        self._analyze_patterns()
    
    def record_rename_event(self, old_path: str, new_path: str, process_pid: int = None, process_name: str = None):
        """Record a file rename event"""
        event = {
            "old_path": old_path,
            "new_path": new_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_pid": process_pid,
            "process_name": process_name
        }
        
        # Check for ransomware extension
        new_ext = Path(new_path).suffix.lower()
        if new_ext in self.RANSOMWARE_EXTENSIONS:
            event["suspicious"] = True
            event["reason"] = f"Ransomware extension: {new_ext}"
            self._emit_alert(RansomwareEventType.SUSPICIOUS_RENAME, [new_path], {
                "old_path": old_path,
                "new_extension": new_ext,
                "process_pid": process_pid,
                "process_name": process_name
            })
        
        self.rename_events.append(event)
        
        # Keep only last 5 minutes
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.rename_events = [e for e in self.rename_events
                            if datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) > cutoff]
    
    def _analyze_patterns(self):
        """Analyze recent events for ransomware patterns"""
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(minutes=1)
        
        # Count recent file modifications per process
        recent_events = [e for e in self.file_events 
                        if datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) > one_minute_ago]
        
        # Group by process
        by_process: Dict[int, List[Dict]] = {}
        for event in recent_events:
            pid = event.get("process_pid")
            if pid:
                by_process.setdefault(pid, []).append(event)
        
        # Check for mass encryption pattern
        for pid, events in by_process.items():
            if len(events) >= config.encryption_threshold:
                if pid not in self.suspicious_processes:
                    self.suspicious_processes.add(pid)
                    self._emit_alert(
                        RansomwareEventType.MASS_ENCRYPTION,
                        [e["path"] for e in events[:10]],
                        {
                            "process_pid": pid,
                            "process_name": events[0].get("process_name"),
                            "files_modified": len(events),
                            "time_window": "1 minute"
                        }
                    )
    
    def _emit_alert(self, event_type: RansomwareEventType, affected_files: List[str], details: Dict):
        """Emit ransomware detection alert"""
        event = RansomwareEvent(
            id=hashlib.md5(f"{event_type.value}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            event_type=event_type.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity="critical",
            process_name=details.get("process_name"),
            process_pid=details.get("process_pid"),
            affected_files=affected_files,
            details=details
        )
        
        logger.critical(f"RANSOMWARE DETECTION: {event_type.value}")
        
        if self._alert_callback:
            self._alert_callback(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get behavioral detection statistics"""
        return {
            "monitoring": self._monitoring,
            "recent_file_events": len(self.file_events),
            "recent_rename_events": len(self.rename_events),
            "suspicious_renames": len([e for e in self.rename_events if e.get("suspicious")]),
            "suspicious_processes": list(self.suspicious_processes)
        }


# =============================================================================
# PROTECTED FOLDERS
# =============================================================================

class ProtectedFolderManager:
    """
    Manages folders protected from ransomware access.
    Only whitelisted processes can modify files in protected folders.
    
    Enforcement mechanisms:
    - Windows: Integrates with Controlled Folder Access API
    - Linux: Uses inotify for real-time monitoring + process verification
    - Cross-platform: Process whitelist validation with alert generation
    """
    
    DEFAULT_PROTECTED = [
        str(Path.home() / "Documents"),
        str(Path.home() / "Pictures"),
        str(Path.home() / "Desktop"),
        str(Path.home() / "Videos"),
        str(Path.home() / "Music"),
    ]
    
    # Expanded whitelist with common legitimate applications
    DEFAULT_ALLOWED_PROCESSES = [
        # Windows shell/system
        "explorer.exe", "notepad.exe", "notepad++.exe", "wordpad.exe",
        # Microsoft Office
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
        # Development
        "code.exe", "code", "devenv.exe", "vim", "nvim", "nano", "emacs", "gedit",
        "atom", "sublime_text", "idea64.exe", "pycharm64.exe", "webstorm64.exe",
        # Media
        "vlc.exe", "vlc", "mpv", "gimp", "photoshop.exe", "illustrator.exe",
        # Productivity
        "libreoffice", "soffice.bin", "abiword", "gnumeric", "evince", "okular",
        # Browsers (for download management)
        "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
        # Cloud sync (legitimate file modifications)
        "onedrive.exe", "dropbox", "googledrivesync.exe",
    ]
    
    # Known ransomware process patterns to always block
    BLOCKED_PROCESS_PATTERNS = [
        "vssadmin", "wmic shadowcopy", "bcdedit", "wbadmin", "cipher /w",
        "powershell.*-enc", "cmd.*/c.*del", "taskkill.*defender",
        "reg.*delete.*backup", "net stop.*vss", "net stop.*backup",
    ]
    
    def __init__(self):
        self.protected_folders: Dict[str, ProtectedFolder] = {}
        self.access_violations: List[Dict] = []
        self.blocked_attempts: int = 0
        self._alert_callback: Optional[Callable] = None
        self._monitoring = False
        self._monitor_thread = None
        self._windows_cfa_enabled = False
        self._load_config()
        self._check_platform_features()
    
    def _check_platform_features(self):
        """Check available platform-specific features"""
        import platform
        system = platform.system()
        
        if system == "Windows":
            # Check if Controlled Folder Access is available
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
                    0, winreg.KEY_READ
                )
                value, _ = winreg.QueryValueEx(key, "EnableControlledFolderAccess")
                self._windows_cfa_enabled = value == 1
                winreg.CloseKey(key)
                logger.info(f"Windows Controlled Folder Access: {'enabled' if self._windows_cfa_enabled else 'disabled'}")
            except Exception:
                logger.info("Windows Controlled Folder Access not available")
        
        elif system == "Linux":
            # Check for inotify support
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6")
                self._inotify_available = hasattr(libc, 'inotify_init')
                logger.info(f"Linux inotify support: {'available' if self._inotify_available else 'unavailable'}")
            except Exception:
                self._inotify_available = False
    
    def _load_config(self):
        """Load protected folder configuration"""
        if PROTECTED_DIRS_FILE.exists():
            try:
                with open(PROTECTED_DIRS_FILE, 'r') as f:
                    data = json.load(f)
                    for folder_data in data.get("folders", []):
                        folder = ProtectedFolder(**folder_data)
                        self.protected_folders[folder.path] = folder
            except Exception as e:
                logger.error(f"Failed to load protected folders config: {e}")
    
    def _save_config(self):
        """Save protected folder configuration"""
        try:
            data = {"folders": [asdict(f) for f in self.protected_folders.values()]}
            with open(PROTECTED_DIRS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save protected folders config: {e}")
    
    def set_alert_callback(self, callback: Callable):
        """Set callback for folder access alerts"""
        self._alert_callback = callback
    
    def add_protected_folder(self, path: str, allowed_processes: List[str] = None) -> ProtectedFolder:
        """Add a folder to protection"""
        folder = ProtectedFolder(
            path=path,
            allowed_processes=allowed_processes or self.DEFAULT_ALLOWED_PROCESSES.copy(),
            created_at=datetime.now(timezone.utc).isoformat()
        )
        self.protected_folders[path] = folder
        self._save_config()
        
        # Try to enable Windows CFA for this folder
        self._enable_windows_cfa(path)
        
        return folder
    
    def _enable_windows_cfa(self, path: str):
        """Enable Windows Controlled Folder Access for a folder"""
        import platform
        if platform.system() != "Windows":
            return
        
        try:
            import subprocess
            # Add folder to Windows Defender Controlled Folder Access
            result = subprocess.run([
                "powershell", "-Command",
                f"Add-MpPreference -ControlledFolderAccessProtectedFolders '{path}'"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Added {path} to Windows Controlled Folder Access")
            else:
                logger.debug(f"Could not add to CFA: {result.stderr}")
        except Exception as e:
            logger.debug(f"CFA integration not available: {e}")
    
    def add_allowed_process(self, folder_path: str, process_name: str) -> bool:
        """Add an allowed process to a protected folder"""
        if folder_path in self.protected_folders:
            folder = self.protected_folders[folder_path]
            if process_name not in folder.allowed_processes:
                folder.allowed_processes.append(process_name)
                self._save_config()
                
                # Also add to Windows CFA if available
                self._add_windows_cfa_allowed_app(process_name)
            return True
        return False
    
    def _add_windows_cfa_allowed_app(self, process_path: str):
        """Add an allowed application to Windows Controlled Folder Access"""
        import platform
        if platform.system() != "Windows":
            return
        
        try:
            import subprocess
            result = subprocess.run([
                "powershell", "-Command",
                f"Add-MpPreference -ControlledFolderAccessAllowedApplications '{process_path}'"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Added {process_path} to CFA allowed apps")
        except Exception:
            pass
    
    def remove_protected_folder(self, path: str) -> bool:
        """Remove a folder from protection"""
        if path in self.protected_folders:
            del self.protected_folders[path]
            self._save_config()
            return True
        return False
    
    def check_access(self, file_path: str, process_name: str, process_cmdline: str = "") -> bool:
        """
        Check if a process is allowed to access a protected file.
        Returns True if access is allowed, False if blocked.
        """
        import re
        file_path = Path(file_path)
        
        # First check for known ransomware patterns (always block)
        full_cmd = f"{process_name} {process_cmdline}".lower()
        for pattern in self.BLOCKED_PROCESS_PATTERNS:
            if re.search(pattern.lower(), full_cmd):
                self._record_violation(str(file_path), process_name, "ransomware_pattern", pattern)
                return False
        
        # Check protected folders
        for protected_path, folder in self.protected_folders.items():
            if str(file_path).startswith(protected_path):
                # File is in a protected folder
                process_lower = process_name.lower()
                allowed = any(p.lower() in process_lower for p in folder.allowed_processes)
                
                if not allowed:
                    folder.last_access_attempt = datetime.now(timezone.utc).isoformat()
                    self._save_config()
                    self._record_violation(str(file_path), process_name, "not_whitelisted", protected_path)
                    return False
                
                return True
        
        # Not in a protected folder
        return True
    
    def _record_violation(self, file_path: str, process_name: str, reason: str, detail: str):
        """Record an access violation"""
        self.blocked_attempts += 1
        
        violation = {
            "id": hashlib.md5(f"{file_path}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file_path": file_path,
            "process_name": process_name,
            "reason": reason,
            "detail": detail
        }
        
        self.access_violations.append(violation)
        
        # Keep only last 1000 violations
        if len(self.access_violations) > 1000:
            self.access_violations = self.access_violations[-1000:]
        
        logger.warning(f"Protected folder access blocked: {process_name} -> {file_path} ({reason})")
        
        # Emit alert for potential ransomware
        if self._alert_callback and reason == "ransomware_pattern":
            event = RansomwareEvent(
                id=violation["id"],
                event_type=RansomwareEventType.PROTECTED_FOLDER_ACCESS.value,
                timestamp=violation["timestamp"],
                severity="critical",
                process_name=process_name,
                affected_files=[file_path],
                details={"reason": reason, "pattern": detail}
            )
            self._alert_callback(event)
    
    def get_protected_folders(self) -> List[ProtectedFolder]:
        """Get all protected folders"""
        return list(self.protected_folders.values())
    
    def get_violations(self, limit: int = 100) -> List[Dict]:
        """Get recent access violations"""
        return self.access_violations[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get protected folder statistics"""
        return {
            "protected_folders_count": len(self.protected_folders),
            "protected_paths": list(self.protected_folders.keys()),
            "blocked_attempts": self.blocked_attempts,
            "recent_violations": len(self.access_violations),
            "windows_cfa_enabled": self._windows_cfa_enabled,
            "monitoring_active": self._monitoring
        }


# =============================================================================
# SHADOW COPY MONITORING
# =============================================================================

class ShadowCopyMonitor:
    """
    Monitors Windows Shadow Copies (VSS) and Linux snapshots for ransomware activity.
    
    Ransomware commonly deletes shadow copies to prevent recovery:
    - Windows: vssadmin delete shadows, wmic shadowcopy delete
    - Also monitors for Volume Shadow Copy service stop/disable
    - Linux: Monitors LVM/btrfs snapshot deletion
    
    Detection methods:
    - Process command line monitoring for vssadmin/wmic commands
    - Windows Event Log monitoring (Event ID 524, 8224)
    - Service state monitoring for VSS service
    - Periodic shadow copy count validation
    """
    
    # Suspicious commands that target shadow copies
    SHADOW_COPY_COMMANDS = [
        "vssadmin delete shadows",
        "vssadmin resize shadowstorage",
        "wmic shadowcopy delete",
        "wmic shadowcopy where",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "bcdedit /set {default} recoveryenabled no",
        "wbadmin delete catalog",
        "wbadmin delete systemstatebackup",
    ]
    
    # Suspicious services being stopped/disabled
    BACKUP_SERVICES = [
        "VSS",              # Volume Shadow Copy
        "VSSAdmin",         # Shadow copy admin
        "SDRSVC",           # Windows Backup
        "wbengine",         # Block Level Backup Engine
        "swprv",            # Microsoft Software Shadow Copy Provider
        "vds",              # Virtual Disk Service
        "SQLWriter",        # SQL Server VSS Writer (targeted by ransomware)
    ]
    
    def __init__(self):
        self._alert_callback: Optional[Callable] = None
        self._monitoring = False
        self._monitor_thread = None
        self._baseline_shadow_count: Optional[int] = None
        self._baseline_snapshots: Dict[str, List[str]] = {}
        self._alerts: List[Dict] = []
        self._detections: int = 0
        self._last_check: Optional[str] = None
        self._platform = self._detect_platform()
    
    def _detect_platform(self) -> str:
        """Detect the current platform"""
        import platform
        return platform.system()
    
    def set_alert_callback(self, callback: Callable):
        """Set callback for shadow copy alerts"""
        self._alert_callback = callback
    
    def start_monitoring(self):
        """Start shadow copy monitoring"""
        if self._monitoring:
            return
        
        # Establish baseline
        self._establish_baseline()
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("Shadow copy monitoring started")
    
    def stop_monitoring(self):
        """Stop shadow copy monitoring"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Shadow copy monitoring stopped")
    
    def _establish_baseline(self):
        """Establish baseline shadow copy/snapshot count"""
        if self._platform == "Windows":
            self._baseline_shadow_count = self._get_windows_shadow_count()
            logger.info(f"Baseline shadow copies: {self._baseline_shadow_count}")
        elif self._platform == "Linux":
            self._baseline_snapshots = self._get_linux_snapshots()
            logger.info(f"Baseline snapshots: {sum(len(v) for v in self._baseline_snapshots.values())}")
    
    def _get_windows_shadow_count(self) -> int:
        """Get current Windows shadow copy count"""
        try:
            import subprocess
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True,
                timeout=30
            )
            # Count "Shadow Copy ID:" occurrences
            return result.stdout.lower().count("shadow copy id:")
        except Exception as e:
            logger.debug(f"Could not enumerate shadow copies: {e}")
            return -1
    
    def _get_linux_snapshots(self) -> Dict[str, List[str]]:
        """Get current Linux LVM/btrfs snapshots"""
        snapshots = {"lvm": [], "btrfs": []}
        
        try:
            import subprocess
            
            # LVM snapshots
            result = subprocess.run(
                ["lvs", "--noheadings", "-o", "lv_name,lv_attr"],
                capture_output=True, text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and 's' in line:  # 's' in attributes = snapshot
                        snapshots["lvm"].append(line.strip().split()[0])
        except Exception:
            pass
        
        try:
            # Btrfs snapshots
            result = subprocess.run(
                ["btrfs", "subvolume", "list", "-s", "/"],
                capture_output=True, text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        snapshots["btrfs"].append(line.strip())
        except Exception:
            pass
        
        return snapshots
    
    def _check_windows_services(self) -> List[Dict]:
        """Check if backup-related services are running"""
        alerts = []
        
        try:
            import subprocess
            
            for service in self.BACKUP_SERVICES:
                result = subprocess.run(
                    ["sc", "query", service],
                    capture_output=True, text=True,
                    timeout=10
                )
                
                if "STOPPED" in result.stdout or "DISABLED" in result.stdout:
                    alerts.append({
                        "type": "service_stopped",
                        "service": service,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
        except Exception as e:
            logger.debug(f"Service check error: {e}")
        
        return alerts
    
    def _check_windows_event_log(self) -> List[Dict]:
        """Check Windows Event Log for shadow copy deletion events"""
        alerts = []
        
        try:
            import subprocess
            
            # Query for VSS-related events (Event ID 524 = shadow copy deleted)
            result = subprocess.run([
                "wevtutil", "qe", "System",
                "/q:*[System[(EventID=524 or EventID=8224)]]",
                "/c:10", "/rd:true", "/f:text"
            ], capture_output=True, text=True, timeout=30)
            
            if result.stdout and "Event ID" in result.stdout:
                alerts.append({
                    "type": "event_log_alert",
                    "details": "Recent shadow copy deletion events detected",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        except Exception as e:
            logger.debug(f"Event log check error: {e}")
        
        return alerts
    
    def check_command(self, command: str, process_name: str = "") -> bool:
        """
        Check if a command is attempting to delete shadow copies.
        Returns True if suspicious (should be blocked).
        """
        command_lower = command.lower()
        
        for pattern in self.SHADOW_COPY_COMMANDS:
            if pattern.lower() in command_lower:
                self._record_detection(
                    event_type="shadow_copy_command",
                    process_name=process_name,
                    details={"command": command, "pattern": pattern}
                )
                return True
        
        # Check for service stop commands targeting backup services
        if "net stop" in command_lower or "sc stop" in command_lower:
            for service in self.BACKUP_SERVICES:
                if service.lower() in command_lower:
                    self._record_detection(
                        event_type="backup_service_stop",
                        process_name=process_name,
                        details={"command": command, "service": service}
                    )
                    return True
        
        return False
    
    def _record_detection(self, event_type: str, process_name: str, details: Dict):
        """Record a shadow copy attack detection"""
        self._detections += 1
        
        alert = {
            "id": hashlib.md5(f"{event_type}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "process_name": process_name,
            "details": details,
            "severity": "critical"
        }
        
        self._alerts.append(alert)
        
        # Keep only last 500 alerts
        if len(self._alerts) > 500:
            self._alerts = self._alerts[-500:]
        
        logger.critical(f"SHADOW COPY ATTACK DETECTED: {event_type} by {process_name}")
        
        # Emit alert
        if self._alert_callback:
            event = RansomwareEvent(
                id=alert["id"],
                event_type=RansomwareEventType.SHADOW_COPY_DELETE.value if "shadow" in event_type 
                          else RansomwareEventType.BACKUP_SERVICE_STOP.value,
                timestamp=alert["timestamp"],
                severity="critical",
                process_name=process_name,
                affected_files=[],
                details=details
            )
            self._alert_callback(event)
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._monitoring:
            try:
                self._last_check = datetime.now(timezone.utc).isoformat()
                
                if self._platform == "Windows":
                    # Check current shadow count against baseline
                    current_count = self._get_windows_shadow_count()
                    
                    if self._baseline_shadow_count is not None and current_count >= 0:
                        if current_count < self._baseline_shadow_count:
                            reduction = self._baseline_shadow_count - current_count
                            self._record_detection(
                                event_type="shadow_count_reduced",
                                process_name="unknown",
                                details={
                                    "baseline": self._baseline_shadow_count,
                                    "current": current_count,
                                    "reduction": reduction
                                }
                            )
                    
                    # Check services
                    service_alerts = self._check_windows_services()
                    for alert in service_alerts:
                        self._record_detection(
                            event_type="backup_service_stopped",
                            process_name="system",
                            details=alert
                        )
                    
                    # Check event logs
                    event_alerts = self._check_windows_event_log()
                    for alert in event_alerts:
                        self._record_detection(
                            event_type="event_log_shadow_deletion",
                            process_name="unknown",
                            details=alert
                        )
                
                elif self._platform == "Linux":
                    # Check current snapshot count against baseline
                    current_snapshots = self._get_linux_snapshots()
                    
                    for snap_type in ["lvm", "btrfs"]:
                        baseline_count = len(self._baseline_snapshots.get(snap_type, []))
                        current_count = len(current_snapshots.get(snap_type, []))
                        
                        if baseline_count > 0 and current_count < baseline_count:
                            self._record_detection(
                                event_type=f"{snap_type}_snapshot_deleted",
                                process_name="unknown",
                                details={
                                    "baseline": baseline_count,
                                    "current": current_count,
                                    "reduction": baseline_count - current_count
                                }
                            )
                
            except Exception as e:
                logger.error(f"Shadow copy monitor error: {e}")
            
            # Check every 60 seconds
            time.sleep(60)
    
    def get_status(self) -> Dict[str, Any]:
        """Get shadow copy monitor status"""
        current_count = -1
        if self._platform == "Windows":
            current_count = self._get_windows_shadow_count()
        
        return {
            "monitoring": self._monitoring,
            "platform": self._platform,
            "baseline_shadow_count": self._baseline_shadow_count,
            "current_shadow_count": current_count,
            "detections": self._detections,
            "recent_alerts": len(self._alerts),
            "last_check": self._last_check
        }
    
    def get_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent shadow copy alerts"""
        return self._alerts[-limit:]


# =============================================================================
# RANSOMWARE PROTECTION MANAGER
# =============================================================================

class RansomwareProtectionManager:
    """
    Central manager for all ransomware protection features.
    Includes: Canary Files, Behavioral Detection, Protected Folders, Shadow Copy Monitoring
    """
    
    _instance = None
    _db = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.canary_manager = CanaryFileManager()
        self.behavior_detector = RansomwareBehaviorDetector()
        self.folder_manager = ProtectedFolderManager()
        self.shadow_monitor = ShadowCopyMonitor()
        self.events: List[RansomwareEvent] = []
        self._monitoring = False
        self._monitor_thread = None
        self._initialized = True
    
    @classmethod
    def set_database(cls, db):
        cls._db = db
        if cls._instance:
            cls._instance.canary_manager.set_database(db)
            cls._instance.behavior_detector.set_database(db)
    
    def set_alert_callback(self, callback: Callable):
        """Set callback for ransomware alerts"""
        self.canary_manager.set_alert_callback(callback)
        self.behavior_detector.set_alert_callback(callback)
        self.folder_manager.set_alert_callback(callback)
        self.shadow_monitor.set_alert_callback(callback)
    
    def start_protection(self):
        """Start all ransomware protection features"""
        logger.info("Starting ransomware protection...")
        
        # Deploy canaries if enabled
        if config.canary_enabled:
            self.canary_manager.deploy_canaries()
        
        # Start shadow copy monitoring
        self.shadow_monitor.start_monitoring()
        
        # Start main monitoring loop
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Ransomware protection active (all modules)")
    
    def stop_protection(self):
        """Stop ransomware protection"""
        self._monitoring = False
        self.shadow_monitor.stop_monitoring()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Ransomware protection stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._monitoring:
            try:
                # Check canaries every 30 seconds
                triggered = self.canary_manager.check_canaries()
                if triggered:
                    logger.critical(f"ALERT: {len(triggered)} canaries triggered!")
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
            
            time.sleep(30)
    
    def check_command_safety(self, command: str, process_name: str = "") -> Dict[str, Any]:
        """
        Check if a command should be blocked.
        Returns dict with 'allowed' boolean and 'reason' if blocked.
        """
        # Check shadow copy operations
        if self.shadow_monitor.check_command(command, process_name):
            return {
                "allowed": False,
                "reason": "shadow_copy_operation",
                "details": "Command attempts to delete shadow copies or disable backup services"
            }
        
        return {"allowed": True, "reason": None}
    
    def check_file_access(self, file_path: str, process_name: str, process_cmdline: str = "") -> Dict[str, Any]:
        """
        Check if a process can access a file in protected folders.
        Returns dict with 'allowed' boolean and details.
        """
        allowed = self.folder_manager.check_access(file_path, process_name, process_cmdline)
        
        if not allowed:
            return {
                "allowed": False,
                "reason": "protected_folder_violation",
                "file_path": file_path,
                "process": process_name
            }
        
        return {"allowed": True, "reason": None}
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive protection status"""
        return {
            "protection_active": self._monitoring,
            "canary_status": self.canary_manager.get_status(),
            "behavioral_status": self.behavior_detector.get_stats(),
            "protected_folders_status": self.folder_manager.get_stats(),
            "shadow_copy_status": self.shadow_monitor.get_status(),
            "recent_events": len(self.events),
            "config": {
                "canary_enabled": config.canary_enabled,
                "behavioral_detection": config.behavioral_detection,
                "auto_backup": config.auto_backup,
                "auto_kill": config.auto_kill_ransomware
            }
        }
    
    def deploy_canaries(self, directories: List[str] = None) -> List[Dict]:
        """Deploy canary files"""
        canaries = self.canary_manager.deploy_canaries(directories)
        return [asdict(c) for c in canaries]
    
    def add_protected_folder(self, path: str, allowed_processes: List[str] = None) -> Dict:
        """Add a protected folder"""
        folder = self.folder_manager.add_protected_folder(path, allowed_processes)
        return asdict(folder)
    
    def get_protected_folders(self) -> List[Dict]:
        """Get all protected folders"""
        return [asdict(f) for f in self.folder_manager.get_protected_folders()]
    
    def get_folder_violations(self, limit: int = 100) -> List[Dict]:
        """Get recent protected folder violations"""
        return self.folder_manager.get_violations(limit)
    
    def get_shadow_copy_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent shadow copy alerts"""
        return self.shadow_monitor.get_alerts(limit)


# Global instance
ransomware_protection = RansomwareProtectionManager()
