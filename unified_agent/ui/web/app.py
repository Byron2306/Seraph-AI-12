#!/usr/bin/env python3
"""
Seraph AI – Web Dashboard
=========================
Flask-based local web UI that mirrors every feature of the Tkinter desktop UI
while using the visual style from the original Defender installer web dashboard.

Runs on http://localhost:5000 by default.
"""

import os
import sys
import json
import time
import socket
import platform
import threading
import subprocess
import tempfile
import logging
from pathlib import Path
from datetime import datetime, timezone
from collections import deque
from typing import Dict, Any, List, Optional

from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Resolve import of UnifiedAgentCore from the desktop package
# ---------------------------------------------------------------------------
_this_dir = Path(__file__).resolve().parent          # …/ui/web
_desktop_dir = _this_dir.parent / "desktop"           # …/ui/desktop
_agent_root = _this_dir.parent.parent                 # …/unified_agent

# Add desktop dir so we can import main
if str(_desktop_dir) not in sys.path:
    sys.path.insert(0, str(_desktop_dir))
if str(_agent_root) not in sys.path:
    sys.path.insert(0, str(_agent_root))

# Avoid Tkinter import since we're headless – patch before import
import importlib
_tk_spec = importlib.util.find_spec("tkinter")
# We'll guard against Tkinter failing by pre-setting a minimal shim
_original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

# We need to import UnifiedAgentCore and related constants without pulling in tkinter.
# Strategy: import the module source and exec the non-GUI classes.
import types as _types
import re as _re

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests as _requests
except ImportError:
    _requests = None

logger = logging.getLogger("SeraphWebUI")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _load_agent_core():
    """Import UnifiedAgentCore, AgentConfig, and constants from main.py
    without triggering Tkinter imports."""
    main_py = _desktop_dir / "main.py"
    if not main_py.exists():
        raise FileNotFoundError(f"Cannot find {main_py}")

    source = main_py.read_text(encoding="utf-8")

    # ---- Build a minimal tkinter stub so the import doesn't crash ----
    tk_stub = _types.ModuleType("tkinter")
    tk_stub.Tk = type("Tk", (), {"__init__": lambda *a, **kw: None})
    tk_stub.Frame = type("Frame", (), {})
    tk_stub.Label = type("Label", (), {})
    tk_stub.Button = type("Button", (), {})
    tk_stub.Toplevel = type("Toplevel", (), {})
    tk_stub.BOTH = "both"; tk_stub.X = "x"; tk_stub.Y = "y"
    tk_stub.LEFT = "left"; tk_stub.RIGHT = "right"; tk_stub.END = "end"
    tk_stub.W = "w"; tk_stub.DISABLED = "disabled"; tk_stub.NORMAL = "normal"
    tk_stub.BooleanVar = type("BooleanVar", (), {"__init__": lambda s, **kw: setattr(s, '_v', kw.get('value', False)),
                                                   "get": lambda s: s._v, "set": lambda s, v: setattr(s, '_v', v)})
    tk_stub.StringVar = type("StringVar", (), {"__init__": lambda s, **kw: setattr(s, '_v', kw.get('value', '')),
                                                 "get": lambda s: s._v, "set": lambda s, v: setattr(s, '_v', v),
                                                 "trace_add": lambda s, *a: None})
    tk_stub.IntVar = type("IntVar", (), {"__init__": lambda s, **kw: setattr(s, '_v', kw.get('value', 0)),
                                           "get": lambda s: s._v, "set": lambda s, v: setattr(s, '_v', v)})

    ttk_stub = _types.ModuleType("tkinter.ttk")
    ttk_stub.Style = type("Style", (), {"__init__": lambda *a, **kw: None,
                                          "configure": lambda *a, **kw: None,
                                          "map": lambda *a, **kw: None})
    ttk_stub.Frame = tk_stub.Frame
    ttk_stub.Label = tk_stub.Label
    ttk_stub.Button = tk_stub.Button
    ttk_stub.Notebook = type("Notebook", (), {})
    ttk_stub.Treeview = type("Treeview", (), {})
    ttk_stub.Scrollbar = type("Scrollbar", (), {})
    ttk_stub.Progressbar = type("Progressbar", (), {})
    ttk_stub.LabelFrame = type("LabelFrame", (), {})
    ttk_stub.Spinbox = type("Spinbox", (), {})
    ttk_stub.Entry = type("Entry", (), {})
    ttk_stub.Checkbutton = type("Checkbutton", (), {})

    messagebox_stub = _types.ModuleType("tkinter.messagebox")
    messagebox_stub.showinfo = lambda *a, **kw: None
    messagebox_stub.showerror = lambda *a, **kw: None
    messagebox_stub.showwarning = lambda *a, **kw: None
    messagebox_stub.askyesno = lambda *a, **kw: True

    scrolledtext_stub = _types.ModuleType("tkinter.scrolledtext")
    scrolledtext_stub.ScrolledText = type("ScrolledText", (), {})

    # Inject stubs
    sys.modules["tkinter"] = tk_stub
    sys.modules["tkinter.ttk"] = ttk_stub
    sys.modules["tkinter.messagebox"] = messagebox_stub
    sys.modules["tkinter.scrolledtext"] = scrolledtext_stub

    # Force-reload the module if it was already imported
    mod_name = "main"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    spec = importlib.util.spec_from_file_location(mod_name, main_py)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)

    return module


_main_module = _load_agent_core()
UnifiedAgentCore = _main_module.UnifiedAgentCore
AgentConfig = _main_module.AgentConfig
SUSPICIOUS_PORTS = _main_module.SUSPICIOUS_PORTS
SUSPICIOUS_PROCESS_NAMES = _main_module.SUSPICIOUS_PROCESS_NAMES

# ============================================================================
# Web-specific wrapper around the agent core
# ============================================================================

class WebAgentBridge:
    """Wraps UnifiedAgentCore and adds state tracking for the web UI."""

    def __init__(self):
        self.agent = UnifiedAgentCore()
        self.monitoring_active = False
        self.events: deque = deque(maxlen=500)
        self.logs: deque = deque(maxlen=1000)
        self.auto_reduce_log: deque = deque(maxlen=200)
        self.auto_execute_commands = False
        self.pending_commands: List[Dict] = []
        self.command_history: deque = deque(maxlen=200)
        self.quarantine_items: List[Dict] = []
        # Auto-reduce settings
        self.ar_enabled = True
        self.ar_cpu_thresh = 80
        self.ar_mem_thresh = 85
        self.ar_disk_thresh = 90
        self._ar_aggressive = True  # escalate from throttle → suspend → kill
        self._ar_max_rounds = 10    # max passes per cycle before giving up
        # Resource history
        self._cpu_history: deque = deque(maxlen=20)
        self._mem_history: deque = deque(maxlen=20)
        self._disk_history: deque = deque(maxlen=20)
        self._last_auto_reduce_time = 0
        # Lock for thread safety
        self._lock = threading.Lock()
        # CPU monitor — psutil.cpu_percent(interval=0) returns 0 without priming
        self._cpu_value = 0.0
        self._cpu_thread = threading.Thread(target=self._cpu_monitor_loop, daemon=True)
        self._cpu_thread.start()
        # Background auto-reduce loop (runs every 10s)
        self._ar_monitor_thread = threading.Thread(target=self._auto_reduce_monitor_loop, daemon=True)
        self._ar_monitor_thread.start()

        # Patch agent _log to capture to our log buffer
        original_log = self.agent._log.__func__ if hasattr(self.agent._log, '__func__') else None
        bridge = self

        def _patched_log(self_agent, message, level="INFO"):
            ts = datetime.now().strftime("%H:%M:%S")
            bridge.logs.appendleft({"time": ts, "level": level, "message": message})
        self.agent._log = lambda msg, lvl="INFO": _patched_log(self.agent, msg, lvl)

        # Set up web UI adapter so agent's command poll routes commands here
        self._setup_command_bridge()

    def _cpu_monitor_loop(self):
        """Background thread: continuously measure CPU so values stay fresh."""
        if not psutil:
            return
        psutil.cpu_percent(interval=1)  # prime
        while True:
            try:
                self._cpu_value = psutil.cpu_percent(interval=1)
            except Exception:
                pass

    def _setup_command_bridge(self):
        """Install a web-compatible adapter as the agent's ui_ref so the
        command poll loop routes commands to our pending_commands list
        instead of auto-executing."""
        bridge = self

        class _ThresholdVar:
            """Mimics tk.IntVar/BooleanVar: exposes .get() for agent core."""
            def __init__(self, getter):
                self._getter = getter
            def get(self):
                return self._getter()

        class _WebUIAdapter:
            auto_execute_commands = False

            def __init__(self):
                self.root = self  # fake root for root.after()
                self.ar_cpu_thresh = _ThresholdVar(lambda: bridge.ar_cpu_thresh)
                self.ar_mem_thresh = _ThresholdVar(lambda: bridge.ar_mem_thresh)
                self.ar_disk_thresh = _ThresholdVar(lambda: bridge.ar_disk_thresh)
                self.auto_reduce_var = _ThresholdVar(lambda: bridge.ar_enabled)

            def after(self, _delay, callback):
                """Execute callback immediately (no Tk mainloop)."""
                try:
                    callback()
                except Exception:
                    pass

            def _queue_command(self, cmd):
                bridge.queue_command(cmd)

            def _add_history(self, cmd_id, cmd_type, status, result_text):
                bridge.command_history.appendleft({
                    "id": cmd_id, "type": cmd_type,
                    "status": status,
                    "result": str(result_text)[:200],
                    "time": datetime.now().strftime("%H:%M:%S")
                })

            def _log_auto_reduce(self, resource, action, detail):
                bridge.log_auto_reduce(resource, action, detail)

            def add_event(self, level, message):
                bridge.add_event(level, message)

        self.agent.ui_ref = _WebUIAdapter()

    def log(self, message: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.appendleft({"time": ts, "level": level, "message": message})

    def add_event(self, level: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.events.appendleft({"time": ts, "level": level, "message": message})

    def log_auto_reduce(self, resource: str, action: str, detail: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.auto_reduce_log.appendleft({
            "time": ts, "resource": resource, "action": action, "detail": detail
        })

    # --- Agent lifecycle ---
    def start_monitoring(self):
        if self.monitoring_active:
            return {"status": "already_running"}
        self.log("Starting agent (connecting to servers)...")

        def _bg():
            try:
                self.agent.start()
            except Exception as e:
                logger.warning(f"Agent start error: {e}")
            self.monitoring_active = True
            if self.agent.registered:
                self.log("Monitoring started - Connected to server")
            else:
                self.log("Monitoring started - Server offline (local mode)", "WARN")
        threading.Thread(target=_bg, daemon=True).start()
        return {"status": "starting"}

    def stop_monitoring(self):
        if not self.monitoring_active:
            return {"status": "not_running"}
        try:
            self.agent.stop()
            self.monitoring_active = False
            self.log("Monitoring stopped")
            return {"status": "stopped"}
        except Exception as e:
            self.log(f"Failed to stop monitoring: {e}", "ERROR")
            return {"status": "error", "message": str(e)}

    def restart(self):
        if self.monitoring_active:
            self.stop_monitoring()
            time.sleep(1)
        self.start_monitoring()
        self.log("Agent restarted")
        return {"status": "restarting"}

    # --- System info ---
    def get_system_status(self) -> dict:
        cpu = mem_pct = disk_pct = 0.0
        mem_used = mem_total = disk_used = disk_total = 0
        if psutil:
            try:
                cpu = self._cpu_value  # from background thread
                mem = psutil.virtual_memory()
                mem_pct = mem.percent
                mem_used = mem.used
                mem_total = mem.total
                disk = psutil.disk_usage("/")
                disk_pct = disk.percent
                disk_used = disk.used
                disk_total = disk.total
                # Track history
                self._cpu_history.append(cpu)
                self._mem_history.append(mem_pct)
                self._disk_history.append(disk_pct)
            except Exception:
                pass

        return {
            "monitoring_active": self.monitoring_active,
            "registered": self.agent.registered,
            "agent_id": self.agent.config.agent_id,
            "agent_name": self.agent.config.agent_name,
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "cpu_percent": round(cpu, 1),
            "memory_percent": round(mem_pct, 1),
            "memory_used_gb": round(mem_used / (1024**3), 1),
            "memory_total_gb": round(mem_total / (1024**3), 1),
            "disk_percent": round(disk_pct, 1),
            "disk_used_gb": round(disk_used / (1024**3), 1),
            "disk_total_gb": round(disk_total / (1024**3), 1),
            "cpu_trend": list(self._cpu_history)[-10:],
            "mem_trend": list(self._mem_history)[-10:],
            "ar_enabled": self.ar_enabled,
            "auto_execute_commands": self.auto_execute_commands,
            "pending_commands_count": len(self.pending_commands),
            "network_scanning": self.agent.config.network_scanning,
            "process_monitoring": self.agent.config.process_monitoring,
            "file_scanning": self.agent.config.file_scanning,
            "wireless_scanning": self.agent.config.wireless_scanning,
            "bluetooth_scanning": self.agent.config.bluetooth_scanning,
        }

    # --- Process management ---
    def get_processes(self, filter_text: str = "", sort_col: str = "cpu",
                      sort_reverse: bool = True) -> list:
        if not psutil:
            return []
        rows = []
        filt = filter_text.lower()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    info = proc.info
                    name = info.get('name', '') or ''
                    if filt and filt not in name.lower():
                        continue
                    rows.append({
                        "pid": info.get('pid', 0),
                        "name": name,
                        "cpu": round(info.get('cpu_percent', 0) or 0, 1),
                        "memory": round(info.get('memory_percent', 0) or 0, 1),
                        "status": info.get('status', 'unknown')
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        # Sort
        key_map = {"pid": "pid", "name": "name", "cpu": "cpu", "memory": "memory", "status": "status"}
        sort_key = key_map.get(sort_col, "cpu")
        try:
            if sort_key in ("pid", "cpu", "memory"):
                rows.sort(key=lambda r: r[sort_key], reverse=sort_reverse)
            else:
                rows.sort(key=lambda r: str(r[sort_key]).lower(), reverse=sort_reverse)
        except Exception:
            pass
        return rows

    def kill_process(self, pid: int) -> dict:
        if not psutil:
            return {"success": False, "error": "psutil not available"}
        try:
            p = psutil.Process(pid)
            name = p.name()
            p.terminate()
            self.add_event("INFO", f"Terminated {name} (PID {pid})")
            self.log(f"Killed process {name} PID={pid}")
            return {"success": True, "message": f"Terminated {name} (PID {pid})"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def lower_process_priority(self, pid: int) -> dict:
        if not psutil:
            return {"success": False, "error": "psutil not available"}
        try:
            p = psutil.Process(pid)
            name = p.name()
            if platform.system() == "Windows":
                p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            else:
                current = p.nice()
                p.nice(min(current + 5, 19))
            self.add_event("INFO", f"Lowered priority: {name} (PID {pid})")
            return {"success": True, "message": f"Lowered priority of {name} (PID {pid})"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- Service management ---
    def get_services(self, filter_text: str = "") -> list:
        rows = []
        if platform.system() != "Windows":
            return [{"name": "N/A", "display": "Services only on Windows", "status": "", "start_type": ""}]
        filt = filter_text.lower()
        try:
            if psutil:
                for svc in psutil.win_service_iter():
                    try:
                        info = svc.as_dict()
                        svc_name = info.get("name", "")
                        display = info.get("display_name", "")
                        status = info.get("status", "unknown")
                        start_type = info.get("start_type", "unknown")
                        if filt and filt not in svc_name.lower() and filt not in display.lower():
                            continue
                        rows.append({"name": svc_name, "display": display,
                                     "status": status, "start_type": start_type})
                    except Exception:
                        continue
        except Exception:
            # Fallback to sc query
            try:
                result = subprocess.run(
                    ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                    capture_output=True, text=True, timeout=15)
                lines = result.stdout.split('\n')
                svc_name = ''
                svc_state = ''
                for line in lines:
                    line_s = line.strip()
                    if line_s.startswith("SERVICE_NAME:"):
                        svc_name = line_s.split(":", 1)[1].strip()
                    elif 'STATE' in line_s and ':' in line_s:
                        svc_state = line_s.split(':', 1)[1].strip().split()[0]
                    elif line_s == '' and svc_name:
                        if not filt or filt in svc_name.lower():
                            rows.append({"name": svc_name, "display": svc_name,
                                         "status": svc_state, "start_type": ""})
                        svc_name = ''
                        svc_state = ''
            except Exception:
                pass
        rows.sort(key=lambda r: r["name"].lower())
        return rows

    def service_action(self, svc_name: str, action: str) -> dict:
        try:
            result = subprocess.run(['sc', action, svc_name],
                                    capture_output=True, text=True, timeout=15)
            self.add_event("INFO", f"Service {action}: {svc_name}")
            return {"success": True, "message": f"{action} {svc_name}: {result.stdout.strip()[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- Connection management ---
    def get_connections(self, filter_text: str = "", show_listen: bool = False) -> list:
        if not psutil:
            return []
        rows = []
        filt = filter_text.lower()
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                try:
                    status = c.status or ''
                    if not show_listen and status == 'LISTEN':
                        continue
                    if status == 'NONE':
                        continue
                    local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ''
                    remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ''
                    proc_name = ''
                    try:
                        if c.pid:
                            proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = f'PID {c.pid}'
                    family = 'TCP' if c.type == socket.SOCK_STREAM else 'UDP'
                    if filt and filt not in proc_name.lower() and filt not in remote.lower() and filt not in local.lower():
                        continue
                    rows.append({
                        "pid": c.pid or 0, "process": proc_name,
                        "local": local, "remote": remote,
                        "status": status, "family": family
                    })
                except Exception:
                    continue
        except (psutil.AccessDenied, OSError):
            pass
        rows.sort(key=lambda r: (0 if r["status"] == "ESTABLISHED" else 1, r["remote"]))
        return rows

    def kill_connection(self, pid: int) -> dict:
        return self.kill_process(pid)

    def block_ip(self, remote_ip: str) -> dict:
        if remote_ip in ('127.0.0.1', '0.0.0.0', '::1', ''):
            return {"success": False, "error": "Cannot block localhost"}
        try:
            rule_name = f"SeraphAI-Block-{remote_ip}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}', 'dir=out', 'action=block',
                f'remoteip={remote_ip}', 'protocol=any'
            ], capture_output=True, text=True, timeout=10)
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}-In', 'dir=in', 'action=block',
                f'remoteip={remote_ip}', 'protocol=any'
            ], capture_output=True, text=True, timeout=10)
            self.add_event("CRITICAL", f"Blocked IP: {remote_ip} via firewall")
            self.log(f"Blocked IP {remote_ip}")
            return {"success": True, "message": f"Blocked {remote_ip}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- Port management ---
    def get_ports(self) -> list:
        if not psutil:
            return []
        rows = []
        try:
            conns = psutil.net_connections(kind='inet')
            seen = set()
            for c in conns:
                if c.status != 'LISTEN':
                    continue
                if not c.laddr:
                    continue
                port = c.laddr.port
                addr = c.laddr.ip
                key = f"{addr}:{port}"
                if key in seen:
                    continue
                seen.add(key)
                proc_name = ''
                try:
                    if c.pid:
                        proc_name = psutil.Process(c.pid).name()
                except Exception:
                    proc_name = f'PID {c.pid}'
                proto = 'TCP' if c.type == socket.SOCK_STREAM else 'UDP'
                flag = SUSPICIOUS_PORTS.get(port, '')
                rows.append({
                    "port": port, "protocol": proto, "pid": c.pid or 0,
                    "process": proc_name, "address": addr, "suspicious": flag
                })
        except (psutil.AccessDenied, OSError):
            pass
        rows.sort(key=lambda r: r["port"])
        return rows

    def kill_listener(self, pid: int) -> dict:
        return self.kill_process(pid)

    # --- Network scanning ---
    def scan_network(self) -> dict:
        self.log("Starting network scan...")
        # Go straight to ARP fallback — scapy requires Npcap driver
        # which may not be installed and causes multi-minute hangs
        return self._scan_network_arp_fallback()

    def _scan_network_arp_fallback(self) -> dict:
        """Fallback network discovery using 'arp -a' command."""
        start = time.time()
        devices = []
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=15)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    dtype = parts[2] if len(parts) > 2 else ''
                    if _re.match(r'\d+\.\d+\.\d+\.\d+', ip) and ('-' in mac or ':' in mac):
                        # Skip broadcast/multicast MACs
                        if mac in ('ff-ff-ff-ff-ff-ff', 'FF-FF-FF-FF-FF-FF'):
                            continue
                        if mac.startswith('01-00-5e') or mac.startswith('01:00:5e'):
                            continue
                        hostname = ip  # Use IP as default — DNS lookups too slow
                        devices.append({
                            "ip": ip,
                            "mac": mac.replace('-', ':'),
                            "hostname": hostname,
                            "type": dtype
                        })
        except Exception as e:
            self.log(f"ARP scan error: {e}", "ERROR")
        elapsed = round(time.time() - start, 2)
        self.add_event("INFO", f"Network scan (ARP): {len(devices)} devices found in {elapsed}s")
        return {"success": True, "devices": devices, "scan_time": elapsed}

    def scan_wireless(self) -> dict:
        self.log("Starting wireless scan...")
        start = time.time()
        try:
            results = self.agent.scan_wireless()
            elapsed = round(time.time() - start, 2)
            if isinstance(results, list):
                self.add_event("INFO", f"Wireless scan: {len(results)} networks found in {elapsed}s")
                return {"success": True, "networks": results, "scan_time": elapsed}
            return {"success": True, "networks": [], "message": str(results), "scan_time": elapsed}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def scan_bluetooth(self) -> dict:
        self.log("Starting Bluetooth scan...")
        start = time.time()
        try:
            results = self.agent.scan_bluetooth()
            elapsed = round(time.time() - start, 2)
            if isinstance(results, list):
                self.add_event("INFO", f"Bluetooth scan: {len(results)} devices found in {elapsed}s")
                return {"success": True, "devices": results, "scan_time": elapsed}
            return {"success": True, "devices": [], "message": str(results), "scan_time": elapsed}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- Hidden file scan ---
    def scan_hidden_files(self) -> dict:
        self.add_event("INFO", "Starting hidden file scan...")
        results = []
        if platform.system().lower() != "windows":
            return {"success": True, "findings": [], "message": "Hidden file scan only supported on Windows"}

        suspicious_locations = [
            os.path.expandvars(r'%TEMP%'), os.path.expandvars(r'%APPDATA%'),
            os.path.expandvars(r'%LOCALAPPDATA%'), os.path.expandvars(r'%PROGRAMDATA%'),
            os.path.join(os.path.expanduser('~'), 'Downloads'),
            os.path.join(os.path.expanduser('~'), 'Desktop'),
        ]
        dangerous_exts = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.scr', '.com',
                          '.cmd', '.hta', '.msi', '.pif', '.wsf', '.wsh'}

        for loc in suspicious_locations:
            if not os.path.isdir(loc):
                continue
            try:
                dirs_to_scan = [(loc, 0)]
                count = 0
                while dirs_to_scan and count < 500:
                    current, depth = dirs_to_scan.pop(0)
                    try:
                        for entry in os.scandir(current):
                            count += 1
                            if count > 500:
                                break
                            try:
                                if entry.is_dir() and depth < 2:
                                    dirs_to_scan.append((entry.path, depth + 1))
                                if not entry.is_file():
                                    continue
                                import ctypes
                                attrs = ctypes.windll.kernel32.GetFileAttributesW(entry.path)
                                if attrs == -1:
                                    continue
                                is_hidden = bool(attrs & 0x2)
                                is_system = bool(attrs & 0x4)
                                if is_hidden and not is_system:
                                    ext = os.path.splitext(entry.name)[1].lower()
                                    severity = 'critical' if ext in dangerous_exts else 'medium'
                                    results.append({
                                        "path": entry.path, "type": "Hidden File",
                                        "severity": severity,
                                        "detail": f"Ext: {ext}, Size: {entry.stat().st_size} bytes"
                                    })
                            except (PermissionError, OSError):
                                continue
                    except (PermissionError, OSError):
                        continue
            except Exception:
                continue

        # Check ADS
        try:
            user_dir = os.path.expanduser('~')
            for subdir in ['Desktop', 'Downloads', 'Documents']:
                target = os.path.join(user_dir, subdir)
                if not os.path.isdir(target):
                    continue
                result = subprocess.run(
                    ['cmd', '/c', f'dir /r /s "{target}"'],
                    capture_output=True, text=True, timeout=30)
                for line in result.stdout.splitlines():
                    if ':$DATA' in line and line.count(':') >= 3:
                        cleaned = line.strip()[:200]
                        results.append({"path": cleaned, "type": "ADS Stream",
                                        "severity": "high", "detail": "Alternate Data Stream detected"})
        except Exception:
            pass

        # Recent temp executables
        try:
            temp_dir = tempfile.gettempdir()
            for entry in os.scandir(temp_dir):
                try:
                    if entry.is_file():
                        ext = os.path.splitext(entry.name)[1].lower()
                        if ext in dangerous_exts:
                            age_hours = (time.time() - entry.stat().st_mtime) / 3600
                            if age_hours < 24:
                                results.append({
                                    "path": entry.path, "type": "Recent Temp Exe",
                                    "severity": "high",
                                    "detail": f"{ext} file, created {age_hours:.1f}h ago"
                                })
                except (PermissionError, OSError):
                    continue
        except Exception:
            pass

        self.add_event("INFO", f"Hidden scan done: {len(results)} findings")
        return {"success": True, "findings": results}

    # --- Privilege scan ---
    def scan_privileges(self) -> dict:
        self.add_event("INFO", "Starting admin privilege scan...")
        results = []
        is_admin = False
        user_info = ""

        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass

        try:
            result = subprocess.run(['whoami'], capture_output=True, text=True, timeout=5)
            user_info = result.stdout.strip()
        except Exception:
            user_info = "unknown"

        results.append({
            "type": "Admin Status", "name": "Current User",
            "severity": "high" if is_admin else "info",
            "detail": f"{'Running as admin' if is_admin else 'Standard user'} | {user_info}"
        })

        if platform.system().lower() == "windows":
            # Check privileges
            try:
                result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=10)
                dangerous_privs = [
                    'SeDebugPrivilege', 'SeTcbPrivilege', 'SeAssignPrimaryTokenPrivilege',
                    'SeLoadDriverPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege',
                    'SeImpersonatePrivilege', 'SeCreateTokenPrivilege',
                    'SeBackupPrivilege', 'SeSecurityPrivilege',
                ]
                for priv in dangerous_privs:
                    if priv in result.stdout:
                        line_part = result.stdout.split(priv)[1].split('\n')[0]
                        enabled = 'Enabled' in line_part
                        results.append({
                            "type": "Privilege", "name": priv,
                            "severity": "critical" if enabled else "medium",
                            "detail": "ENABLED" if enabled else "Disabled"
                        })
            except Exception:
                pass

            # Check scheduled tasks running as SYSTEM
            try:
                result = subprocess.run(['schtasks', '/query', '/fo', 'CSV', '/v'],
                                        capture_output=True, text=True, timeout=30)
                lines = result.stdout.splitlines()
                for line in lines[1:]:
                    parts = line.strip('"').split('","')
                    if len(parts) > 7:
                        task_name = parts[0]
                        run_as = parts[7] if len(parts) > 7 else ''
                        status = parts[3] if len(parts) > 3 else ''
                        if 'SYSTEM' in run_as.upper() and '\\Microsoft\\' not in task_name:
                            if 'Ready' in status or 'Running' in status:
                                results.append({
                                    "type": "SYSTEM Task", "name": task_name,
                                    "severity": "high",
                                    "detail": f"Runs as {run_as}, Status: {status}"
                                })
            except Exception:
                pass

            # Check suspicious SYSTEM processes
            if psutil:
                suspicious_as_system = ['cmd.exe', 'powershell.exe', 'pwsh.exe',
                                        'python.exe', 'python3.exe', 'node.exe',
                                        'wscript.exe', 'cscript.exe', 'mshta.exe']
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        info = proc.info
                        username = (info.get('username') or '').upper()
                        pname = (info.get('name') or '').lower()
                        if 'SYSTEM' in username and pname in suspicious_as_system:
                            results.append({
                                "type": "SYSTEM Process", "name": f"{pname} (PID {info['pid']})",
                                "severity": "critical",
                                "detail": f"Running as {username}"
                            })
                        base_name = pname.replace('.exe', '')
                        if base_name in SUSPICIOUS_PROCESS_NAMES:
                            results.append({
                                "type": "Offensive Tool", "name": f"{pname} (PID {info['pid']})",
                                "severity": "critical",
                                "detail": f"Known offensive tool running as {info.get('username', '?')}"
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            # UAC settings
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                enable_lua, _ = winreg.QueryValueEx(key, 'EnableLUA')
                consent_prompt, _ = winreg.QueryValueEx(key, 'ConsentPromptBehaviorAdmin')
                winreg.CloseKey(key)
                if enable_lua == 0:
                    results.append({"type": "UAC", "name": "EnableLUA",
                                    "severity": "critical", "detail": "UAC is DISABLED"})
                else:
                    results.append({"type": "UAC", "name": "EnableLUA",
                                    "severity": "info", "detail": "UAC is enabled"})
                if consent_prompt == 0:
                    results.append({"type": "UAC", "name": "ConsentPrompt",
                                    "severity": "high", "detail": "Admin auto-approve without prompt"})
            except Exception:
                pass

            # Admin group members
            try:
                result = subprocess.run(['net', 'localgroup', 'Administrators'],
                                        capture_output=True, text=True, timeout=10)
                in_members = False
                for line in result.stdout.splitlines():
                    if '---' in line:
                        in_members = True
                        continue
                    if in_members and line.strip() and 'command completed' not in line.lower():
                        results.append({"type": "Admin Group", "name": line.strip(),
                                        "severity": "medium", "detail": "Member of local Administrators group"})
            except Exception:
                pass

            # Firewall state
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                                        capture_output=True, text=True, timeout=10)
                for line in result.stdout.splitlines():
                    if 'State' in line and 'OFF' in line.upper():
                        results.append({"type": "Firewall", "name": "Profile",
                                        "severity": "critical", "detail": f"Firewall DISABLED: {line.strip()}"})
            except Exception:
                pass

            # Defender status
            try:
                result = subprocess.run(
                    ['powershell', '-Command',
                     'Get-MpPreference | Select-Object DisableRealtimeMonitoring | Format-List'],
                    capture_output=True, text=True, timeout=15)
                if 'True' in result.stdout:
                    results.append({"type": "Defender", "name": "RealTime",
                                    "severity": "critical", "detail": "Real-time protection DISABLED"})
                else:
                    results.append({"type": "Defender", "name": "RealTime",
                                    "severity": "info", "detail": "Real-time protection enabled"})
            except Exception:
                pass

        self.add_event("INFO", f"Admin scan done: {len(results)} findings")
        return {"success": True, "findings": results, "is_admin": is_admin, "user": user_info}

    # --- Quarantine ---
    def quarantine_file(self, file_path: str) -> dict:
        try:
            new_path = self.agent.quarantine_file(file_path)
            self.quarantine_items.append({"path": new_path, "original": file_path, "status": "quarantined"})
            self.add_event("INFO", f"Quarantined {file_path}")
            return {"success": True, "quarantined_path": new_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def restore_quarantine_item(self, path: str) -> dict:
        try:
            self.agent.restore_quarantine(path)
            self.quarantine_items = [q for q in self.quarantine_items if q["path"] != path]
            self.add_event("INFO", f"Restored {path}")
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def remove_quarantine_item(self, path: str) -> dict:
        try:
            self.agent.remove_quarantine(path)
            self.quarantine_items = [q for q in self.quarantine_items if q["path"] != path]
            self.add_event("INFO", f"Removed {path} from quarantine")
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- Command management ---
    def get_pending_commands(self) -> list:
        return self.pending_commands

    def get_command_history(self) -> list:
        return list(self.command_history)

    def approve_command(self, command_id: str) -> dict:
        cmd = None
        for c in self.pending_commands:
            if c.get("command_id") == command_id:
                cmd = c
                break
        if not cmd:
            return {"success": False, "error": "Command not found"}

        cmd_type = cmd.get("type", "unknown")
        cmd_params = cmd.get("params", {})
        self.log(f"Approved command {command_id}: {cmd_type}")

        def _run():
            try:
                result_data = self.agent._execute_command(cmd_type, cmd_params)
                self.agent._ack_command(command_id, result_data)
                ok = result_data.get("success", False)
                out = result_data.get("output", str(result_data))
                self.command_history.appendleft({
                    "id": command_id, "type": cmd_type,
                    "status": "OK" if ok else "FAIL",
                    "result": out[:200], "time": datetime.now().strftime("%H:%M:%S")
                })
                self.log(f"Command {cmd_type} {'succeeded' if ok else 'FAILED'}: {out[:100]}")
            except Exception as e:
                self.agent._ack_command(command_id, {"success": False, "error": str(e)})
                self.command_history.appendleft({
                    "id": command_id, "type": cmd_type,
                    "status": "ERROR", "result": str(e)[:200],
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                self.log(f"Command {cmd_type} error: {e}", "ERROR")

        threading.Thread(target=_run, daemon=True).start()
        self.pending_commands = [c for c in self.pending_commands if c.get("command_id") != command_id]
        return {"success": True, "message": f"Executing {cmd_type}"}

    def approve_all_commands(self) -> dict:
        ids = [c.get("command_id") for c in self.pending_commands]
        for cid in ids:
            self.approve_command(cid)
        return {"success": True, "approved": len(ids)}

    def reject_command(self, command_id: str) -> dict:
        cmd = None
        for c in self.pending_commands:
            if c.get("command_id") == command_id:
                cmd = c
                break
        if not cmd:
            return {"success": False, "error": "Command not found"}
        cmd_type = cmd.get("type", "unknown")
        self.agent._ack_command(command_id, {
            "success": False, "output": "Rejected by operator", "rejected": True
        })
        self.command_history.appendleft({
            "id": command_id, "type": cmd_type, "status": "REJECTED",
            "result": "Rejected by operator", "time": datetime.now().strftime("%H:%M:%S")
        })
        self.log(f"Rejected command {command_id}: {cmd_type}")
        self.pending_commands = [c for c in self.pending_commands if c.get("command_id") != command_id]
        return {"success": True}

    def queue_command(self, cmd: dict):
        """Called when the agent polls a new command from the server."""
        self.pending_commands.append(cmd)
        self.add_event("INFO", f"New command: {cmd.get('type', '?')}")

    # =================================================================
    # AUTO-REDUCE: forceful resource reduction to target percentiles
    # =================================================================
    _PROTECTED = frozenset({
        'system', 'idle', 'csrss', 'wininit', 'winlogon', 'services',
        'lsass', 'smss', 'svchost', 'explorer', 'dwm', 'registry',
        'memory compression', 'secure system',
        'python', 'pythonw', 'python3', 'cmd', 'powershell', 'pwsh',
        'conhost', 'fontdrvhost', 'sihost', 'taskhostw', 'runtimebroker',
        'searchhost', 'startmenuexperiencehost', 'textinputhost',
        'shellexperiencehost', 'securityhealthservice', 'msmpeng',
        'antimalwareserviceexecutable', 'wudfhost', 'dllhost',
        'spoolsv', 'audiodg', 'ctfmon', 'flask',
    })

    def _auto_reduce_monitor_loop(self):
        """Background loop: check resources every 10s and force-reduce
        when above thresholds. Replaces the manual-only approach."""
        if not psutil:
            return
        time.sleep(15)  # let system settle after startup
        while True:
            try:
                if self.ar_enabled:
                    cpu = self._cpu_value
                    mem = psutil.virtual_memory().percent
                    try:
                        disk = psutil.disk_usage('/').percent
                    except Exception:
                        disk = psutil.disk_usage('C:\\').percent

                    now = time.time()
                    if now - self._last_auto_reduce_time < 15:
                        time.sleep(10)
                        continue

                    triggered = False
                    if cpu > self.ar_cpu_thresh:
                        threading.Thread(target=self._force_reduce_cpu, daemon=True).start()
                        triggered = True
                    if mem > self.ar_mem_thresh:
                        threading.Thread(target=self._force_reduce_memory, daemon=True).start()
                        triggered = True
                    if disk > self.ar_disk_thresh:
                        threading.Thread(target=self._force_reduce_disk, daemon=True).start()
                        triggered = True
                    if triggered:
                        self._last_auto_reduce_time = now
            except Exception as e:
                logger.warning(f"Auto-reduce monitor error: {e}")
            time.sleep(10)

    def toggle_auto_reduce(self, enabled: bool) -> dict:
        self.ar_enabled = enabled
        self.add_event("INFO", f"Auto-Reduce toggled {'ON' if enabled else 'OFF'}")
        return {"success": True, "enabled": enabled}

    def update_auto_reduce_thresholds(self, cpu: int = None, mem: int = None, disk: int = None) -> dict:
        if cpu is not None:
            self.ar_cpu_thresh = max(10, min(cpu, 99))
        if mem is not None:
            self.ar_mem_thresh = max(10, min(mem, 99))
        if disk is not None:
            self.ar_disk_thresh = max(10, min(disk, 99))
        return {"success": True, "cpu": self.ar_cpu_thresh,
                "mem": self.ar_mem_thresh, "disk": self.ar_disk_thresh}

    def manual_auto_reduce(self) -> dict:
        """Trigger a forceful auto-reduce cycle immediately."""
        cpu = mem_pct = disk_pct = 0
        if psutil:
            try:
                cpu = self._cpu_value
                mem_pct = psutil.virtual_memory().percent
                disk_pct = psutil.disk_usage('/').percent
            except Exception:
                try:
                    disk_pct = psutil.disk_usage('C:\\').percent
                except Exception:
                    pass
        self.add_event("INFO", f"Manual auto-reduce triggered "
                       f"(CPU={cpu:.0f}%>{self.ar_cpu_thresh}% "
                       f"Mem={mem_pct:.0f}%>{self.ar_mem_thresh}% "
                       f"Disk={disk_pct:.0f}%>{self.ar_disk_thresh}%)")

        actions = []
        if cpu > self.ar_cpu_thresh:
            actions.append(f"CPU force-reduce ({cpu:.0f}% -> {self.ar_cpu_thresh}%)")
            threading.Thread(target=self._force_reduce_cpu, daemon=True).start()
        if mem_pct > self.ar_mem_thresh:
            actions.append(f"Memory force-reduce ({mem_pct:.0f}% -> {self.ar_mem_thresh}%)")
            threading.Thread(target=self._force_reduce_memory, daemon=True).start()
        if disk_pct > self.ar_disk_thresh:
            actions.append(f"Disk cleanup ({disk_pct:.0f}% -> {self.ar_disk_thresh}%)")
            threading.Thread(target=self._force_reduce_disk, daemon=True).start()

        if not actions:
            self.log_auto_reduce("ALL", "Within thresholds",
                                 f"CPU={cpu:.0f}% Mem={mem_pct:.0f}% Disk={disk_pct:.0f}%")
            return {"success": True, "message": "All resources within thresholds", "actions": []}
        return {"success": True, "actions": actions,
                "before": {"cpu": round(cpu, 1), "mem": round(mem_pct, 1), "disk": round(disk_pct, 1)}}

    # ---------- FORCE REDUCE CPU ----------
    def _force_reduce_cpu(self):
        """Multi-pass CPU reduction: throttle → affinitize → suspend → terminate.
        Keeps going until CPU% drops below threshold or max rounds exhausted."""
        if not psutil:
            return
        target = self.ar_cpu_thresh
        protected = self._PROTECTED
        my_pid = os.getpid()
        rounds_done = 0
        total_acted = 0

        try:
            for round_num in range(self._ar_max_rounds):
                # Re-measure CPU
                time.sleep(1.5)
                cpu_now = psutil.cpu_percent(interval=1)
                if cpu_now <= target:
                    self.log_auto_reduce('CPU', 'Target reached',
                                         f'CPU at {cpu_now:.1f}% (target {target}%) after {round_num} rounds')
                    break
                rounds_done = round_num + 1

                # Gather CPU hogs fresh each round
                for p in psutil.process_iter(['cpu_percent']):
                    pass
                time.sleep(1)

                hogs = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        info = proc.info
                        c = info.get('cpu_percent', 0) or 0
                        pname = (info.get('name', '') or '').lower().replace('.exe', '')
                        pid = info.get('pid', 0)
                        if c > 3 and pname not in protected and pid != my_pid:
                            hogs.append((pid, info.get('name', ''), c, proc))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                hogs.sort(key=lambda x: x[2], reverse=True)
                if not hogs:
                    self.log_auto_reduce('CPU', 'No targets',
                                         f'CPU {cpu_now:.1f}% but no non-system hogs found')
                    break

                # Escalation ladder per round
                for pid, name, c, proc in hogs[:8]:
                    try:
                        # Round 0-2: Lower priority
                        if round_num < 3:
                            if platform.system() == 'Windows':
                                cur = proc.nice()
                                if c > 50 and cur != psutil.IDLE_PRIORITY_CLASS:
                                    proc.nice(psutil.IDLE_PRIORITY_CLASS)
                                    action = 'IDLE priority'
                                elif cur not in (psutil.BELOW_NORMAL_PRIORITY_CLASS,
                                                 psutil.IDLE_PRIORITY_CLASS):
                                    proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                                    action = 'BELOW_NORMAL priority'
                                else:
                                    continue
                            else:
                                cur = proc.nice()
                                new_n = min(cur + 5, 19)
                                if new_n == cur:
                                    continue
                                proc.nice(new_n)
                                action = f'nice {new_n}'

                        # Round 3-4: Limit CPU affinity (halve available cores)
                        elif round_num < 5:
                            try:
                                cur_aff = proc.cpu_affinity()
                                n_cores = len(cur_aff)
                                if n_cores > 1:
                                    new_aff = cur_aff[:max(1, n_cores // 2)]
                                    proc.cpu_affinity(new_aff)
                                    action = f'affinity {n_cores}->{len(new_aff)} cores'
                                else:
                                    continue
                            except (AttributeError, OSError):
                                continue

                        # Round 5-6: Suspend high-CPU processes temporarily
                        elif round_num < 7:
                            if self._ar_aggressive:
                                proc.suspend()
                                # Schedule resume after 10 seconds
                                threading.Timer(10.0, self._safe_resume, args=[pid]).start()
                                action = 'SUSPENDED (10s)'
                            else:
                                continue

                        # Round 7+: Terminate worst offenders
                        else:
                            if self._ar_aggressive and c > 30:
                                proc.terminate()
                                action = 'TERMINATED'
                            else:
                                continue

                        self.agent._throttled_pids.add(pid)
                        total_acted += 1
                        msg = f'{name} PID={pid} CPU={c:.1f}% -> {action}'
                        self.log_auto_reduce('CPU', action, msg)
                        self.add_event('INFO', f'Auto-reduce CPU: {msg}')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        logger.debug(f'CPU reduce pid {pid}: {e}')
                        continue

            # Final measurement
            time.sleep(1)
            final_cpu = psutil.cpu_percent(interval=1)
            self.log_auto_reduce('CPU', 'Cycle complete',
                f'Acted on {total_acted} processes in {rounds_done} rounds. '
                f'CPU: {final_cpu:.1f}% (target {target}%)')
        except Exception as e:
            logger.warning(f'Force-reduce CPU error: {e}')

    def _safe_resume(self, pid: int):
        """Resume a suspended process; ignore if it no longer exists."""
        try:
            p = psutil.Process(pid)
            if p.status() == psutil.STATUS_STOPPED:
                p.resume()
                self.log_auto_reduce('CPU', 'Resumed', f'PID={pid} resumed after suspend')
        except Exception:
            pass

    # ---------- FORCE REDUCE MEMORY ----------
    def _force_reduce_memory(self):
        """Multi-pass memory reduction: trim working sets → terminate hogs.
        Keeps going until memory% drops below threshold."""
        if not psutil:
            return
        target = self.ar_mem_thresh
        protected = self._PROTECTED
        my_pid = os.getpid()
        total_freed_mb = 0
        total_acted = 0

        try:
            for round_num in range(self._ar_max_rounds):
                mem_now = psutil.virtual_memory().percent
                if mem_now <= target:
                    self.log_auto_reduce('Memory', 'Target reached',
                                         f'Memory at {mem_now:.1f}% (target {target}%) after {round_num} rounds')
                    break

                # Gather memory hogs
                hogs = []
                for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'memory_info']):
                    try:
                        info = proc.info
                        mem = info.get('memory_percent', 0) or 0
                        pname = (info.get('name', '') or '').lower().replace('.exe', '')
                        pid = info.get('pid', 0)
                        rss = 0
                        if info.get('memory_info'):
                            rss = info['memory_info'].rss
                        if mem > 1.0 and pname not in protected and pid != my_pid:
                            hogs.append((pid, info.get('name', ''), mem, rss, proc))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                hogs.sort(key=lambda x: x[2], reverse=True)

                if not hogs:
                    self.log_auto_reduce('Memory', 'No targets',
                                         f'Memory {mem_now:.1f}% but no non-system hogs found')
                    break

                # Round 0-3: Trim working sets (Windows) or just log (Linux)
                if round_num < 4:
                    for pid, name, mem, rss, proc in hogs[:10]:
                        try:
                            if platform.system() == 'Windows':
                                import ctypes
                                PROCESS_SET_QUOTA = 0x0100
                                PROCESS_QUERY_INFO = 0x0400
                                handle = ctypes.windll.kernel32.OpenProcess(
                                    PROCESS_SET_QUOTA | PROCESS_QUERY_INFO, False, pid)
                                if handle:
                                    ctypes.windll.psapi.EmptyWorkingSet(handle)
                                    ctypes.windll.kernel32.CloseHandle(handle)
                                    freed = rss / (1024 * 1024)
                                    total_freed_mb += freed
                                    total_acted += 1
                                    msg = f'{name} PID={pid} Mem={mem:.1f}% RSS={freed:.0f}MB -> trimmed'
                                    self.log_auto_reduce('Memory', 'Trimmed', msg)
                            else:
                                msg = f'{name} PID={pid} Mem={mem:.1f}%'
                                self.log_auto_reduce('Memory', 'High mem', msg)
                        except Exception:
                            continue
                # Round 4+: Terminate worst memory hogs if aggressive
                else:
                    if self._ar_aggressive:
                        for pid, name, mem, rss, proc in hogs[:3]:
                            if mem > 5:  # only kill if using >5% of memory
                                try:
                                    freed = rss / (1024 * 1024)
                                    proc.terminate()
                                    total_acted += 1
                                    total_freed_mb += freed
                                    msg = f'{name} PID={pid} Mem={mem:.1f}% ({freed:.0f}MB) -> TERMINATED'
                                    self.log_auto_reduce('Memory', 'TERMINATED', msg)
                                    self.add_event('WARNING', f'Auto-reduce killed {name} ({freed:.0f}MB)')
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue

                time.sleep(2)

            # Final
            final_mem = psutil.virtual_memory().percent
            self.log_auto_reduce('Memory', 'Cycle complete',
                f'Acted on {total_acted} procs, ~{total_freed_mb:.0f}MB freed. '
                f'Memory: {final_mem:.1f}% (target {target}%)')
        except Exception as e:
            logger.warning(f'Force-reduce memory error: {e}')

    # ---------- FORCE REDUCE DISK ----------
    def _force_reduce_disk(self):
        """Multi-pass disk cleanup: temp → caches → logs → Windows Update."""
        if not psutil:
            return
        target = self.ar_disk_thresh
        total_cleaned_mb = 0
        total_files = 0

        try:
            # Phase 1: Temp directories (files > 1 day old)
            temp_dirs = [tempfile.gettempdir()]
            if platform.system() == 'Windows':
                for env_var in ['TEMP', 'TMP']:
                    d = os.environ.get(env_var, '')
                    if d and os.path.isdir(d) and d not in temp_dirs:
                        temp_dirs.append(d)
                local_temp = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp')
                if os.path.isdir(local_temp) and local_temp not in temp_dirs:
                    temp_dirs.append(local_temp)

            for td in temp_dirs:
                cmb, cf = self._clean_dir(td, min_age_days=1, recurse=True)
                total_cleaned_mb += cmb
                total_files += cf

            self.log_auto_reduce('Disk', 'Phase 1: Temp',
                                 f'{total_files} files, {total_cleaned_mb:.1f}MB')

            # Check if still above threshold
            try:
                disk_now = psutil.disk_usage('/').percent
            except Exception:
                disk_now = psutil.disk_usage('C:\\').percent
            if disk_now <= target:
                self.log_auto_reduce('Disk', 'Target reached', f'Disk at {disk_now:.1f}%')
                self._finish_disk_report(total_cleaned_mb, total_files)
                return

            # Phase 2: Browser caches (Chrome, Edge, Firefox)
            if platform.system() == 'Windows':
                local = os.environ.get('LOCALAPPDATA', '')
                browser_caches = [
                    os.path.join(local, 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
                    os.path.join(local, 'Google', 'Chrome', 'User Data', 'Default', 'Code Cache'),
                    os.path.join(local, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
                    os.path.join(local, 'Microsoft', 'Edge', 'User Data', 'Default', 'Code Cache'),
                ]
                for cache_dir in browser_caches:
                    if os.path.isdir(cache_dir):
                        cmb, cf = self._clean_dir(cache_dir, min_age_days=0, recurse=True)
                        total_cleaned_mb += cmb
                        total_files += cf

                self.log_auto_reduce('Disk', 'Phase 2: Browser caches',
                                     f'{total_files} total files, {total_cleaned_mb:.1f}MB')

            # Check again
            try:
                disk_now = psutil.disk_usage('/').percent
            except Exception:
                disk_now = psutil.disk_usage('C:\\').percent
            if disk_now <= target:
                self.log_auto_reduce('Disk', 'Target reached', f'Disk at {disk_now:.1f}%')
                self._finish_disk_report(total_cleaned_mb, total_files)
                return

            # Phase 3: Python __pycache__ dirs
            home = os.path.expanduser('~')
            for root_dir, dirs, files in os.walk(home):
                if '__pycache__' in root_dir:
                    cmb, cf = self._clean_dir(root_dir, min_age_days=0, recurse=False)
                    total_cleaned_mb += cmb
                    total_files += cf
                # Don't recurse too deep
                depth = root_dir.replace(home, '').count(os.sep)
                if depth > 4:
                    dirs.clear()

            # Phase 4 (Windows): Run disk cleanup utility
            if platform.system() == 'Windows':
                try:
                    subprocess.run(['cleanmgr', '/d', 'C', '/sagerun:1'],
                                   capture_output=True, timeout=120)
                    self.log_auto_reduce('Disk', 'Phase 4: cleanmgr', 'Windows Disk Cleanup triggered')
                except Exception:
                    pass

            self._finish_disk_report(total_cleaned_mb, total_files)
        except Exception as e:
            logger.warning(f'Force-reduce disk error: {e}')

    def _clean_dir(self, path: str, min_age_days: float = 1, recurse: bool = False) -> tuple:
        """Delete files in a directory. Returns (cleaned_mb, cleaned_count)."""
        cleaned_mb = 0
        cleaned_count = 0
        try:
            if recurse:
                for root, dirs, files in os.walk(path, topdown=False):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            st = os.stat(fpath)
                            age = (time.time() - st.st_mtime) / 86400
                            if age >= min_age_days:
                                size = st.st_size
                                os.unlink(fpath)
                                cleaned_mb += size / (1024 * 1024)
                                cleaned_count += 1
                        except (PermissionError, OSError):
                            continue
                    # Try removing empty dirs
                    for d in dirs:
                        try:
                            os.rmdir(os.path.join(root, d))
                        except OSError:
                            pass
            else:
                for entry in os.scandir(path):
                    try:
                        if entry.is_file():
                            st = entry.stat()
                            age = (time.time() - st.st_mtime) / 86400
                            if age >= min_age_days:
                                cleaned_mb += st.st_size / (1024 * 1024)
                                os.unlink(entry.path)
                                cleaned_count += 1
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            pass
        return cleaned_mb, cleaned_count

    def _finish_disk_report(self, total_mb: float, total_files: int):
        try:
            disk_now = psutil.disk_usage('/').percent
        except Exception:
            try:
                disk_now = psutil.disk_usage('C:\\').percent
            except Exception:
                disk_now = 0
        msg = f'Cleaned {total_files} files ({total_mb:.1f}MB). Disk now {disk_now:.1f}%'
        self.log_auto_reduce('Disk', 'Cycle complete', msg)
        self.add_event('INFO', f'Auto-reduce Disk: {msg}')

    # --- Settings ---
    def get_settings(self) -> dict:
        cfg = self.agent.config
        return {
            "server_url": cfg.server_url,
            "agent_name": cfg.agent_name,
            "update_interval": cfg.update_interval,
            "heartbeat_interval": cfg.heartbeat_interval,
            "network_scanning": cfg.network_scanning,
            "process_monitoring": cfg.process_monitoring,
            "file_scanning": cfg.file_scanning,
            "wireless_scanning": cfg.wireless_scanning,
            "bluetooth_scanning": cfg.bluetooth_scanning,
        }

    def save_settings(self, settings: dict) -> dict:
        cfg = self.agent.config
        if "server_url" in settings:
            cfg.server_url = settings["server_url"]
        if "agent_name" in settings:
            cfg.agent_name = settings["agent_name"]
        if "update_interval" in settings:
            cfg.update_interval = int(settings["update_interval"])
        if "heartbeat_interval" in settings:
            cfg.heartbeat_interval = int(settings["heartbeat_interval"])
        if "network_scanning" in settings:
            cfg.network_scanning = bool(settings["network_scanning"])
        if "process_monitoring" in settings:
            cfg.process_monitoring = bool(settings["process_monitoring"])
        if "file_scanning" in settings:
            cfg.file_scanning = bool(settings["file_scanning"])
        if "wireless_scanning" in settings:
            cfg.wireless_scanning = bool(settings["wireless_scanning"])
        if "bluetooth_scanning" in settings:
            cfg.bluetooth_scanning = bool(settings["bluetooth_scanning"])
        try:
            self.agent.save_config()
            self.log("Settings saved")
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- Logs ---
    def get_logs(self, limit: int = 200) -> list:
        return list(self.logs)[:limit]

    def clear_logs(self) -> dict:
        self.logs.clear()
        return {"success": True}

    def export_logs(self) -> str:
        lines = []
        for entry in reversed(list(self.logs)):
            lines.append(f"[{entry['time']}] [{entry['level']}] {entry['message']}")
        return "\n".join(lines)

    def get_events(self, limit: int = 100) -> list:
        return list(self.events)[:limit]

    def get_auto_reduce_log(self, limit: int = 100) -> list:
        return list(self.auto_reduce_log)[:limit]

    # --- Malware / Virus scanning ---
    def scan_malware(self, custom_paths: list = None) -> dict:
        """Run the agent's heuristic malware scanner."""
        self.add_event("INFO", "Starting virus/malware heuristic scan...")
        self.log("Virus/malware scan started")
        start = time.time()
        try:
            results = self.agent.scan_files_for_malware(path_list=custom_paths)
            elapsed = round(time.time() - start, 2)
            if isinstance(results, list):
                self.add_event(
                    "WARN" if results else "INFO",
                    f"Malware scan done: {len(results)} suspicious file(s) in {elapsed}s"
                )
                return {"success": True, "findings": results, "scan_time": elapsed}
            return {"success": False, "error": str(results), "scan_time": elapsed}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- VPN control (proxies to unified server & local WireGuard) ---
    def get_vpn_status(self) -> dict:
        """Get VPN / WireGuard status."""
        status = {"running": False, "interface": "wg0", "config": {}, "error": None}
        # Check local WireGuard
        try:
            result = subprocess.run(['wg', 'show'], capture_output=True, text=True, timeout=5)
            status["running"] = result.returncode == 0
            if result.returncode == 0:
                status["wg_output"] = result.stdout[:500]
        except FileNotFoundError:
            status["error"] = "WireGuard not installed"
        except Exception as e:
            status["error"] = str(e)
        # Try getting config from unified server
        try:
            server_url = self.agent.config.server_url
            if _requests and server_url:
                resp = _requests.get(f"{server_url}/api/vpn/status", timeout=5)
                if resp.status_code == 200:
                    server_status = resp.json()
                    status["config"] = server_status.get("config", {})
                    status["clients_connected"] = server_status.get("clients_connected", 0)
                    status["server_address"] = server_status.get("server_address", "")
                    status["port"] = server_status.get("port", 51820)
        except Exception:
            pass
        return status

    def get_vpn_clients(self) -> list:
        """Get VPN client list from unified server."""
        try:
            server_url = self.agent.config.server_url
            if _requests and server_url:
                resp = _requests.get(f"{server_url}/api/vpn/clients", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("clients", [])
        except Exception:
            pass
        return []

    def vpn_start(self) -> dict:
        """Start WireGuard VPN tunnel."""
        try:
            if platform.system() == "Windows":
                # Try Windows WireGuard service
                result = subprocess.run(
                    ['sc', 'start', 'WireGuardTunnel$wg0'],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode != 0:
                    # Try wireguard.exe /installtunnelservice
                    wg_exe = r"C:\Program Files\WireGuard\wireguard.exe"
                    conf_candidates = [
                        r"C:\Program Files\WireGuard\Data\Configurations\wg0.conf",
                        os.path.expanduser(r"~\wg0.conf"),
                    ]
                    for conf in conf_candidates:
                        if os.path.exists(conf):
                            result = subprocess.run(
                                [wg_exe, '/installtunnelservice', conf],
                                capture_output=True, text=True, timeout=15
                            )
                            break
                    else:
                        return {"success": False, "error": "No WireGuard config found. Place wg0.conf in WireGuard Data folder."}
            else:
                result = subprocess.run(
                    ['wg-quick', 'up', 'wg0'],
                    capture_output=True, text=True, timeout=15
                )
            msg = (result.stdout + result.stderr).strip()[:200]
            if result.returncode == 0 or 'already exists' in msg.lower():
                self.add_event("INFO", "VPN tunnel started")
                self.log("VPN started")
                return {"success": True, "message": "VPN started"}
            return {"success": False, "error": msg or "Start failed"}
        except FileNotFoundError:
            return {"success": False, "error": "WireGuard not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def vpn_stop(self) -> dict:
        """Stop WireGuard VPN tunnel."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ['sc', 'stop', 'WireGuardTunnel$wg0'],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode != 0:
                    wg_exe = r"C:\Program Files\WireGuard\wireguard.exe"
                    result = subprocess.run(
                        [wg_exe, '/uninstalltunnelservice', 'wg0'],
                        capture_output=True, text=True, timeout=15
                    )
            else:
                result = subprocess.run(
                    ['wg-quick', 'down', 'wg0'],
                    capture_output=True, text=True, timeout=15
                )
            msg = (result.stdout + result.stderr).strip()[:200]
            if result.returncode == 0 or 'not found' in msg.lower():
                self.add_event("INFO", "VPN tunnel stopped")
                self.log("VPN stopped")
                return {"success": True, "message": "VPN stopped"}
            return {"success": False, "error": msg or "Stop failed"}
        except FileNotFoundError:
            return {"success": False, "error": "WireGuard not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def vpn_generate_keys(self) -> dict:
        """Generate WireGuard key pair."""
        try:
            priv = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True, timeout=5)
            private_key = priv.stdout.strip()
            pub = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True, check=True, timeout=5)
            public_key = pub.stdout.strip()
            return {"success": True, "private_key": private_key, "public_key": public_key}
        except FileNotFoundError:
            return {"success": False, "error": "WireGuard tools not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def vpn_update_config(self, config: dict) -> dict:
        """Update VPN config on the unified server."""
        try:
            server_url = self.agent.config.server_url
            if _requests and server_url:
                resp = _requests.put(f"{server_url}/api/vpn/config", json=config, timeout=10)
                return resp.json()
            return {"success": False, "error": "Server not reachable"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def vpn_kill_switch(self, enabled: bool) -> dict:
        """Toggle kill switch — block all non-VPN traffic via firewall."""
        try:
            if enabled:
                # Add firewall rules to block non-WireGuard traffic
                cmds = [
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     'name=SeraphAI-KillSwitch-Block', 'dir=out', 'action=block',
                     'protocol=any', 'enable=yes'],
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     'name=SeraphAI-KillSwitch-AllowWG', 'dir=out', 'action=allow',
                     'protocol=udp', 'remoteport=51820', 'enable=yes'],
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     'name=SeraphAI-KillSwitch-AllowLocal', 'dir=out', 'action=allow',
                     'remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8',
                     'enable=yes'],
                ]
                for cmd in cmds:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                self.add_event("INFO", "VPN Kill Switch ENABLED")
            else:
                # Remove kill switch rules
                for name in ['SeraphAI-KillSwitch-Block', 'SeraphAI-KillSwitch-AllowWG', 'SeraphAI-KillSwitch-AllowLocal']:
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}'],
                        capture_output=True, text=True, timeout=10
                    )
                self.add_event("INFO", "VPN Kill Switch DISABLED")
            return {"success": True, "enabled": enabled}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # =========================================================================
    # MONITOR STATS - Expose all 17 MonitorModule stats locally
    # =========================================================================

    def get_all_monitor_stats(self) -> dict:
        """Get aggregated stats from all monitors."""
        stats = {
            "monitors": {},
            "summary": {
                "total_monitors": len(self.agent.monitors),
                "active_monitors": sum(1 for m in self.agent.monitors.values() if m.enabled),
                "total_threats": len(self.agent.threat_history),
                "total_events": len(self.agent.event_log),
            }
        }
        for name, monitor in self.agent.monitors.items():
            stats["monitors"][name] = {
                "enabled": monitor.enabled,
                "stats": getattr(monitor, 'stats', {}),
                "last_scan": getattr(monitor, 'last_scan', None),
            }
        return stats

    def get_monitor_stats(self, monitor_name: str) -> dict:
        """Get stats for a specific monitor."""
        if monitor_name not in self.agent.monitors:
            return {"error": f"Monitor '{monitor_name}' not found", "available": list(self.agent.monitors.keys())}
        monitor = self.agent.monitors[monitor_name]
        return {
            "name": monitor_name,
            "enabled": monitor.enabled,
            "stats": getattr(monitor, 'stats', {}),
            "last_scan": getattr(monitor, 'last_scan', None),
            "alerts": getattr(monitor, 'alerts', [])[-50:] if hasattr(monitor, 'alerts') else [],
        }

    def get_ransomware_stats(self) -> dict:
        """Get ransomware protection monitor stats."""
        if 'ransomware' not in self.agent.monitors:
            return {"enabled": False, "error": "Ransomware monitor not initialized"}
        mon = self.agent.monitors['ransomware']
        return {
            "enabled": mon.enabled,
            "canary_files": getattr(mon, 'canary_files', []),
            "canary_alerts": getattr(mon, 'canary_alerts', 0),
            "protected_folders": getattr(mon, 'protected_folders', []),
            "protected_extensions": getattr(mon, 'protected_extensions', []),
            "shadow_copy_protected": getattr(mon, 'shadow_copies_protected', False),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_rootkit_stats(self) -> dict:
        """Get rootkit detector stats."""
        if 'rootkit' not in self.agent.monitors:
            return {"enabled": False, "error": "Rootkit detector not initialized"}
        mon = self.agent.monitors['rootkit']
        return {
            "enabled": mon.enabled,
            "hidden_processes": getattr(mon, 'hidden_processes', []),
            "suspicious_modules": getattr(mon, 'suspicious_modules', []),
            "ld_preload_hooks": getattr(mon, 'ld_preload_hooks', []),
            "dkom_indicators": getattr(mon, 'dkom_indicators', []),
            "integrity_violations": getattr(mon, 'integrity_violations', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_kernel_stats(self) -> dict:
        """Get kernel security monitor stats."""
        if 'kernel_security' not in self.agent.monitors:
            return {"enabled": False, "error": "Kernel security monitor not initialized"}
        mon = self.agent.monitors['kernel_security']
        return {
            "enabled": mon.enabled,
            "syscall_anomalies": getattr(mon, 'syscall_anomalies', []),
            "audit_alerts": getattr(mon, 'audit_alerts', []),
            "ptrace_detections": getattr(mon, 'ptrace_detections', []),
            "privilege_escalations": getattr(mon, 'privilege_escalations', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_self_protection_stats(self) -> dict:
        """Get agent self-protection stats."""
        if 'self_protection' not in self.agent.monitors:
            return {"enabled": False, "error": "Self-protection monitor not initialized"}
        mon = self.agent.monitors['self_protection']
        return {
            "enabled": mon.enabled,
            "anti_debug_active": getattr(mon, 'anti_debug_active', False),
            "watchdog_running": getattr(mon, 'watchdog_running', False),
            "debugger_detections": getattr(mon, 'debugger_detections', []),
            "injection_attempts": getattr(mon, 'injection_attempts', []),
            "integrity_status": getattr(mon, 'integrity_status', 'unknown'),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_identity_stats(self) -> dict:
        """Get identity protection stats."""
        if 'identity' not in self.agent.monitors:
            return {"enabled": False, "error": "Identity protection monitor not initialized"}
        mon = self.agent.monitors['identity']
        return {
            "enabled": mon.enabled,
            "credential_tools_detected": getattr(mon, 'credential_tools_detected', []),
            "lsass_access_alerts": getattr(mon, 'lsass_access_alerts', []),
            "browser_credential_alerts": getattr(mon, 'browser_credential_alerts', []),
            "pth_indicators": getattr(mon, 'pth_indicators', []),
            "kerberos_anomalies": getattr(mon, 'kerberos_anomalies', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_process_tree_stats(self) -> dict:
        """Get process tree monitor stats."""
        if 'process_tree' not in self.agent.monitors:
            return {"enabled": False, "error": "Process tree monitor not initialized"}
        mon = self.agent.monitors['process_tree']
        return {
            "enabled": mon.enabled,
            "suspicious_chains": getattr(mon, 'suspicious_chains', []),
            "injection_detections": getattr(mon, 'injection_detections', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_lolbin_stats(self) -> dict:
        """Get LOLBin monitor stats."""
        if 'lolbin' not in self.agent.monitors:
            return {"enabled": False, "error": "LOLBin monitor not initialized"}
        mon = self.agent.monitors['lolbin']
        return {
            "enabled": mon.enabled,
            "lolbin_executions": getattr(mon, 'lolbin_executions', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_dns_stats(self) -> dict:
        """Get DNS monitor stats."""
        if 'dns' not in self.agent.monitors:
            return {"enabled": False, "error": "DNS monitor not initialized"}
        mon = self.agent.monitors['dns']
        return {
            "enabled": mon.enabled,
            "dns_anomalies": getattr(mon, 'dns_anomalies', []),
            "dga_detections": getattr(mon, 'dga_detections', []),
            "dns_tunneling_alerts": getattr(mon, 'dns_tunneling_alerts', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_memory_stats(self) -> dict:
        """Get memory scanner stats."""
        if 'memory' not in self.agent.monitors:
            return {"enabled": False, "error": "Memory scanner not initialized"}
        mon = self.agent.monitors['memory']
        return {
            "enabled": mon.enabled,
            "injections_detected": getattr(mon, 'injections_detected', []),
            "reflective_loads": getattr(mon, 'reflective_loads', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_dlp_stats(self) -> dict:
        """Get DLP monitor stats."""
        if 'dlp' not in self.agent.monitors:
            return {"enabled": False, "error": "DLP monitor not initialized"}
        mon = self.agent.monitors['dlp']
        return {
            "enabled": mon.enabled,
            "sensitive_data_alerts": getattr(mon, 'sensitive_data_alerts', []),
            "exfiltration_attempts": getattr(mon, 'exfiltration_attempts', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_vulnerability_stats(self) -> dict:
        """Get vulnerability scanner stats."""
        if 'vulnerability' not in self.agent.monitors:
            return {"enabled": False, "error": "Vulnerability scanner not initialized"}
        mon = self.agent.monitors['vulnerability']
        return {
            "enabled": mon.enabled,
            "vulnerabilities": getattr(mon, 'vulnerabilities', []),
            "cve_matches": getattr(mon, 'cve_matches', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_whitelist_stats(self) -> dict:
        """Get application whitelist stats."""
        if 'whitelist' not in self.agent.monitors:
            return {"enabled": False, "error": "Whitelist monitor not initialized"}
        mon = self.agent.monitors['whitelist']
        return {
            "enabled": mon.enabled,
            "blocked_applications": getattr(mon, 'blocked_applications', []),
            "allowed_list": getattr(mon, 'allowed_list', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_code_signing_stats(self) -> dict:
        """Get code signing monitor stats."""
        if 'code_signing' not in self.agent.monitors:
            return {"enabled": False, "error": "Code signing monitor not initialized"}
        mon = self.agent.monitors['code_signing']
        return {
            "enabled": mon.enabled,
            "unsigned_executions": getattr(mon, 'unsigned_executions', []),
            "invalid_signatures": getattr(mon, 'invalid_signatures', []),
            "stats": getattr(mon, 'stats', {}),
        }

    def get_email_protection_stats(self) -> dict:
        """Get email protection monitor stats."""
        if 'email_protection' not in self.agent.monitors:
            return {"enabled": False, "error": "Email protection monitor not initialized"}
        mon = self.agent.monitors['email_protection']
        return mon.get_status() if hasattr(mon, 'get_status') else {
            "enabled": mon.enabled,
            "emails_scanned": getattr(mon, 'emails_scanned', 0),
            "phishing_detected": getattr(mon, 'phishing_detected', 0),
            "malicious_attachments": getattr(mon, 'malicious_attachments', 0),
            "suspicious_urls": getattr(mon, 'suspicious_urls', 0),
            "stats": getattr(mon, 'stats', {}),
        }

    def analyze_url(self, url: str) -> dict:
        """Analyze a URL for phishing indicators."""
        if 'email_protection' not in self.agent.monitors:
            return {"error": "Email protection monitor not available"}
        mon = self.agent.monitors['email_protection']
        if hasattr(mon, 'analyze_url'):
            return mon.analyze_url(url)
        return {"error": "URL analysis not available"}

    def analyze_email_content(self, content: str) -> dict:
        """Analyze email content for phishing indicators."""
        if 'email_protection' not in self.agent.monitors:
            return {"error": "Email protection monitor not available"}
        mon = self.agent.monitors['email_protection']
        if hasattr(mon, 'analyze_content'):
            return mon.analyze_content(content)
        return {"error": "Content analysis not available"}

    def get_mobile_security_stats(self) -> dict:
        """Get mobile security monitor stats."""
        if 'mobile_security' not in self.agent.monitors:
            return {"enabled": False, "error": "Mobile security monitor not initialized"}
        mon = self.agent.monitors['mobile_security']
        return mon.get_status() if hasattr(mon, 'get_status') else {
            "enabled": mon.enabled,
            "device_info": getattr(mon, 'device_info', {}),
            "threats_detected": getattr(mon, 'threats_detected', 0),
            "compliance_score": getattr(mon, 'compliance_score', 100.0),
            "compliance_checks": getattr(mon, 'compliance_checks', {}),
        }

    def analyze_app(self, app_name: str, package_name: str = '', permissions: list = None) -> dict:
        """Analyze an app for security issues."""
        if 'mobile_security' not in self.agent.monitors:
            return {"error": "Mobile security monitor not available"}
        mon = self.agent.monitors['mobile_security']
        if hasattr(mon, 'analyze_app'):
            return mon.analyze_app(app_name, package_name, permissions or [])
        return {"error": "App analysis not available"}

    def toggle_monitor(self, monitor_name: str, enabled: bool) -> dict:
        """Enable or disable a specific monitor."""
        if monitor_name not in self.agent.monitors:
            return {"success": False, "error": f"Monitor '{monitor_name}' not found"}
        self.agent.monitors[monitor_name].enabled = enabled
        self.log(f"Monitor '{monitor_name}' {'enabled' if enabled else 'disabled'}")
        return {"success": True, "monitor": monitor_name, "enabled": enabled}


# ============================================================================
# Flask Application
# ============================================================================

def create_app() -> Flask:
    """Create and configure the Flask app."""
    template_dir = Path(__file__).resolve().parent / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    CORS(app)

    # Single global agent bridge
    bridge = WebAgentBridge()

    # ------------------------------------------------------------------
    # Page routes
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("dashboard.html")

    # ------------------------------------------------------------------
    # System / Status
    # ------------------------------------------------------------------
    @app.route("/api/status")
    def api_status():
        return jsonify(bridge.get_system_status())

    @app.route("/api/events")
    def api_events():
        limit = request.args.get("limit", 100, type=int)
        return jsonify(bridge.get_events(limit))

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------
    @app.route("/api/agent/start", methods=["POST"])
    def api_start():
        return jsonify(bridge.start_monitoring())

    @app.route("/api/agent/stop", methods=["POST"])
    def api_stop():
        return jsonify(bridge.stop_monitoring())

    @app.route("/api/agent/restart", methods=["POST"])
    def api_restart():
        return jsonify(bridge.restart())

    # ------------------------------------------------------------------
    # Processes
    # ------------------------------------------------------------------
    @app.route("/api/processes")
    def api_processes():
        filt = request.args.get("filter", "")
        sort_col = request.args.get("sort", "cpu")
        sort_rev = request.args.get("reverse", "true").lower() == "true"
        return jsonify(bridge.get_processes(filt, sort_col, sort_rev))

    @app.route("/api/processes/<int:pid>/kill", methods=["POST"])
    def api_kill_process(pid):
        return jsonify(bridge.kill_process(pid))

    @app.route("/api/processes/<int:pid>/lower-priority", methods=["POST"])
    def api_lower_priority(pid):
        return jsonify(bridge.lower_process_priority(pid))

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------
    @app.route("/api/services")
    def api_services():
        filt = request.args.get("filter", "")
        return jsonify(bridge.get_services(filt))

    @app.route("/api/services/<name>/<action>", methods=["POST"])
    def api_service_action(name, action):
        if action not in ("start", "stop"):
            return jsonify({"success": False, "error": "Invalid action"}), 400
        return jsonify(bridge.service_action(name, action))

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------
    @app.route("/api/connections")
    def api_connections():
        filt = request.args.get("filter", "")
        show_listen = request.args.get("show_listen", "false").lower() == "true"
        return jsonify(bridge.get_connections(filt, show_listen))

    @app.route("/api/connections/<int:pid>/kill", methods=["POST"])
    def api_kill_connection(pid):
        return jsonify(bridge.kill_connection(pid))

    @app.route("/api/block-ip", methods=["POST"])
    def api_block_ip():
        data = request.get_json(force=True)
        ip = data.get("ip", "")
        return jsonify(bridge.block_ip(ip))

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------
    @app.route("/api/ports")
    def api_ports():
        return jsonify(bridge.get_ports())

    @app.route("/api/ports/<int:pid>/kill", methods=["POST"])
    def api_kill_listener(pid):
        return jsonify(bridge.kill_listener(pid))

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    @app.route("/api/scan/network", methods=["POST"])
    def api_scan_network():
        return jsonify(bridge.scan_network())

    @app.route("/api/scan/wireless", methods=["POST"])
    def api_scan_wireless():
        return jsonify(bridge.scan_wireless())

    @app.route("/api/scan/bluetooth", methods=["POST"])
    def api_scan_bluetooth():
        return jsonify(bridge.scan_bluetooth())

    @app.route("/api/scan/hidden", methods=["POST"])
    def api_scan_hidden():
        return jsonify(bridge.scan_hidden_files())

    @app.route("/api/scan/privileges", methods=["POST"])
    def api_scan_privileges():
        return jsonify(bridge.scan_privileges())

    @app.route("/api/scan/malware", methods=["POST"])
    def api_scan_malware():
        data = request.get_json(silent=True) or {}
        paths = data.get("paths")
        return jsonify(bridge.scan_malware(paths))

    # ------------------------------------------------------------------
    # VPN
    # ------------------------------------------------------------------
    @app.route("/api/vpn/status")
    def api_vpn_status():
        return jsonify(bridge.get_vpn_status())

    @app.route("/api/vpn/clients")
    def api_vpn_clients():
        return jsonify(bridge.get_vpn_clients())

    @app.route("/api/vpn/start", methods=["POST"])
    def api_vpn_start():
        return jsonify(bridge.vpn_start())

    @app.route("/api/vpn/stop", methods=["POST"])
    def api_vpn_stop():
        return jsonify(bridge.vpn_stop())

    @app.route("/api/vpn/config", methods=["PUT"])
    def api_vpn_config():
        data = request.get_json(force=True)
        return jsonify(bridge.vpn_update_config(data))

    @app.route("/api/vpn/generate-keys", methods=["POST"])
    def api_vpn_gen_keys():
        return jsonify(bridge.vpn_generate_keys())

    @app.route("/api/vpn/kill-switch", methods=["POST"])
    def api_vpn_kill_switch():
        data = request.get_json(force=True)
        return jsonify(bridge.vpn_kill_switch(bool(data.get("enabled", False))))

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------
    @app.route("/api/quarantine")
    def api_quarantine_list():
        return jsonify(bridge.quarantine_items)

    @app.route("/api/quarantine/add", methods=["POST"])
    def api_quarantine_add():
        data = request.get_json(force=True)
        path = data.get("path", "")
        return jsonify(bridge.quarantine_file(path))

    @app.route("/api/quarantine/restore", methods=["POST"])
    def api_quarantine_restore():
        data = request.get_json(force=True)
        path = data.get("path", "")
        return jsonify(bridge.restore_quarantine_item(path))

    @app.route("/api/quarantine/remove", methods=["POST"])
    def api_quarantine_remove():
        data = request.get_json(force=True)
        path = data.get("path", "")
        return jsonify(bridge.remove_quarantine_item(path))

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    @app.route("/api/commands")
    def api_commands():
        return jsonify({
            "pending": bridge.get_pending_commands(),
            "history": bridge.get_command_history(),
            "auto_execute": bridge.auto_execute_commands,
        })

    @app.route("/api/commands/<command_id>/approve", methods=["POST"])
    def api_approve_command(command_id):
        return jsonify(bridge.approve_command(command_id))

    @app.route("/api/commands/<command_id>/reject", methods=["POST"])
    def api_reject_command(command_id):
        return jsonify(bridge.reject_command(command_id))

    @app.route("/api/commands/approve-all", methods=["POST"])
    def api_approve_all():
        return jsonify(bridge.approve_all_commands())

    @app.route("/api/commands/auto-execute", methods=["POST"])
    def api_toggle_auto_execute():
        data = request.get_json(force=True)
        bridge.auto_execute_commands = bool(data.get("enabled", False))
        bridge.log(f"Auto-execute commands: {'ON' if bridge.auto_execute_commands else 'OFF'}")
        return jsonify({"success": True, "enabled": bridge.auto_execute_commands})

    # ------------------------------------------------------------------
    # Auto-Reduce
    # ------------------------------------------------------------------
    @app.route("/api/auto-reduce")
    def api_auto_reduce():
        # Include live resource usage for context
        cpu = bridge._cpu_value
        mem = psutil.virtual_memory().percent if psutil else 0
        try:
            disk = psutil.disk_usage('/').percent if psutil else 0
        except Exception:
            try:
                disk = psutil.disk_usage('C:\\').percent if psutil else 0
            except Exception:
                disk = 0
        return jsonify({
            "enabled": bridge.ar_enabled,
            "aggressive": bridge._ar_aggressive,
            "cpu_threshold": bridge.ar_cpu_thresh,
            "mem_threshold": bridge.ar_mem_thresh,
            "disk_threshold": bridge.ar_disk_thresh,
            "current": {"cpu": round(cpu, 1), "mem": round(mem, 1), "disk": round(disk, 1)},
            "log": bridge.get_auto_reduce_log(),
        })

    @app.route("/api/auto-reduce/toggle", methods=["POST"])
    def api_ar_toggle():
        data = request.get_json(force=True)
        return jsonify(bridge.toggle_auto_reduce(bool(data.get("enabled", True))))

    @app.route("/api/auto-reduce/thresholds", methods=["POST"])
    def api_ar_thresholds():
        data = request.get_json(force=True)
        return jsonify(bridge.update_auto_reduce_thresholds(
            cpu=data.get("cpu"), mem=data.get("mem"), disk=data.get("disk")
        ))

    @app.route("/api/auto-reduce/trigger", methods=["POST"])
    def api_ar_trigger():
        return jsonify(bridge.manual_auto_reduce())

    @app.route("/api/auto-reduce/aggressive", methods=["POST"])
    def api_ar_aggressive():
        data = request.get_json(force=True)
        bridge._ar_aggressive = bool(data.get("enabled", True))
        bridge.add_event("INFO", f"Aggressive auto-reduce {'ON' if bridge._ar_aggressive else 'OFF'}")
        return jsonify({"success": True, "aggressive": bridge._ar_aggressive})

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    @app.route("/api/settings", methods=["GET"])
    def api_get_settings():
        return jsonify(bridge.get_settings())

    @app.route("/api/settings", methods=["POST"])
    def api_save_settings():
        data = request.get_json(force=True)
        return jsonify(bridge.save_settings(data))

    # ------------------------------------------------------------------
    # Monitor Stats - All 17 monitors exposed locally
    # ------------------------------------------------------------------
    @app.route("/api/monitors")
    def api_all_monitors():
        return jsonify(bridge.get_all_monitor_stats())

    @app.route("/api/monitors/<monitor_name>")
    def api_monitor_stats(monitor_name):
        return jsonify(bridge.get_monitor_stats(monitor_name))

    @app.route("/api/monitors/<monitor_name>/toggle", methods=["POST"])
    def api_toggle_monitor(monitor_name):
        data = request.get_json(force=True)
        return jsonify(bridge.toggle_monitor(monitor_name, bool(data.get("enabled", True))))

    @app.route("/api/monitors/ransomware")
    def api_ransomware_stats():
        return jsonify(bridge.get_ransomware_stats())

    @app.route("/api/monitors/rootkit")
    def api_rootkit_stats():
        return jsonify(bridge.get_rootkit_stats())

    @app.route("/api/monitors/kernel")
    def api_kernel_stats():
        return jsonify(bridge.get_kernel_stats())

    @app.route("/api/monitors/self-protection")
    def api_self_protection_stats():
        return jsonify(bridge.get_self_protection_stats())

    @app.route("/api/monitors/identity")
    def api_identity_stats():
        return jsonify(bridge.get_identity_stats())

    @app.route("/api/monitors/process-tree")
    def api_process_tree_stats():
        return jsonify(bridge.get_process_tree_stats())

    @app.route("/api/monitors/lolbin")
    def api_lolbin_stats():
        return jsonify(bridge.get_lolbin_stats())

    @app.route("/api/monitors/dns")
    def api_dns_stats():
        return jsonify(bridge.get_dns_stats())

    @app.route("/api/monitors/memory")
    def api_memory_stats():
        return jsonify(bridge.get_memory_stats())

    @app.route("/api/monitors/dlp")
    def api_dlp_stats():
        return jsonify(bridge.get_dlp_stats())

    @app.route("/api/monitors/vulnerability")
    def api_vulnerability_stats():
        return jsonify(bridge.get_vulnerability_stats())

    @app.route("/api/monitors/whitelist")
    def api_whitelist_stats():
        return jsonify(bridge.get_whitelist_stats())

    @app.route("/api/monitors/code-signing")
    def api_code_signing_stats():
        return jsonify(bridge.get_code_signing_stats())

    # ------------------------------------------------------------------
    # Email Protection
    # ------------------------------------------------------------------
    @app.route("/api/email-protection/stats")
    def api_email_protection_stats():
        return jsonify(bridge.get_email_protection_stats())

    @app.route("/api/email-protection/analyze-url", methods=["POST"])
    def api_analyze_url():
        data = request.get_json(force=True)
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        return jsonify(bridge.analyze_url(url))

    @app.route("/api/email-protection/analyze-content", methods=["POST"])
    def api_analyze_content():
        data = request.get_json(force=True)
        content = data.get("content", "")
        if not content:
            return jsonify({"error": "Content required"}), 400
        return jsonify(bridge.analyze_email_content(content))

    # ------------------------------------------------------------------
    # Mobile Security
    # ------------------------------------------------------------------
    @app.route("/api/mobile-security/stats")
    def api_mobile_security_stats():
        return jsonify(bridge.get_mobile_security_stats())

    @app.route("/api/mobile-security/analyze-app", methods=["POST"])
    def api_analyze_app():
        data = request.get_json(force=True)
        app_name = data.get("app_name", "")
        package_name = data.get("package_name", "")
        permissions = data.get("permissions", [])
        if not app_name:
            return jsonify({"error": "App name required"}), 400
        return jsonify(bridge.analyze_app(app_name, package_name, permissions))

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------
    @app.route("/api/logs")
    def api_logs():
        limit = request.args.get("limit", 200, type=int)
        return jsonify(bridge.get_logs(limit))

    @app.route("/api/logs/clear", methods=["POST"])
    def api_clear_logs():
        return jsonify(bridge.clear_logs())

    @app.route("/api/logs/export")
    def api_export_logs():
        content = bridge.export_logs()
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment; filename=seraph_agent_logs.txt"}
        )

    return app


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Seraph AI - Web Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Port to run dashboard on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  SERAPH AI - WEB DASHBOARD")
    print("=" * 60)
    print(f"  Dashboard: http://localhost:{args.port}")
    print("=" * 60)
    print()

    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
