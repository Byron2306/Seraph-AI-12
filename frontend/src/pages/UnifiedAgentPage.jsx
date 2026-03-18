import { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { Input } from "../components/ui/input";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Cpu,
  Shield,
  Activity,
  Wifi,
  Bluetooth,
  Network,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Download,
  Terminal,
  Database,
  Server,
  Radio,
  Eye,
  Zap,
  Lock,
  Globe,
  Search,
  Monitor,
  Laptop,
  Smartphone,
  HardDrive,
  Copy,
  Bug,
  Fingerprint,
  ShieldOff,
  Scan,
  Key,
  Flame,
  AppWindow,
  FileText,
  EyeOff,
  UserX,
  ShieldCheck,
  // New icons for Unified Agent v2.0 monitors
  Sparkles,
  ShieldAlert,
  Award,
  Settings,
  Calendar,
  Cog,
  Code2,
  Usb,
  Power
} from "lucide-react";

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API_URL = rawBackendUrl || "";
const API_ROOT = API_URL ? `${API_URL}/api` : '/api';

/**
 * Unified Agent Dashboard - THE SINGLE SOURCE FOR ALL AGENT MANAGEMENT
 * 
 * This page consolidates:
 * - Agent management (previously AgentsPage, AgentCommandsPage)
 * - Network scanning & device discovery (previously SwarmDashboard)
 * - Auto-deployment of unified agents
 * - VPN status and configuration
 * - Bulk commands and individual agent control
 */
export default function UnifiedAgentPage() {
  const { token } = useAuth();
  
  // Agent state
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState(null);
  
  // Network/Device state
  const [devices, setDevices] = useState([]);
  const [deviceStats, setDeviceStats] = useState(null);
  const [deploymentStatus, setDeploymentStatus] = useState(null);
  
  // Monitor stats state
  const [monitorStats, setMonitorStats] = useState(null);
  const [monitorAlerts, setMonitorAlerts] = useState([]);
  
  // UI state
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [activeTab, setActiveTab] = useState("agents");

  const headers = { Authorization: `Bearer ${token}` };

  // Fetch all data
  const fetchData = useCallback(async () => {
    try {
      const [agentsRes, statsRes, devicesRes, deployStatusRes, monitorStatsRes, monitorAlertsRes] = await Promise.all([
        fetch(`${API_ROOT}/unified/agents`, { headers }),
        fetch(`${API_ROOT}/unified/stats`, { headers }),
        fetch(`${API_ROOT}/swarm/devices`, { headers }),
        fetch(`${API_ROOT}/swarm/unified/deployment-status`, { headers }),
        fetch(`${API_ROOT}/unified/stats/monitors`, { headers }),
        fetch(`${API_ROOT}/unified/monitors/alerts?limit=20`, { headers })
      ]);
      
      if (agentsRes.ok) {
        const agentsData = await agentsRes.json();
        setAgents(agentsData.agents || []);
      }
      
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
      
      if (devicesRes.ok) {
        const devicesData = await devicesRes.json();
        setDevices(devicesData.devices || []);
        setDeviceStats(devicesData.stats || null);
      }
      
      if (deployStatusRes.ok) {
        const deployData = await deployStatusRes.json();
        setDeploymentStatus(deployData);
      }
      
      if (monitorStatsRes.ok) {
        const monitorData = await monitorStatsRes.json();
        setMonitorStats(monitorData);
      }
      
      if (monitorAlertsRes.ok) {
        const alertsData = await monitorAlertsRes.json();
        setMonitorAlerts(alertsData.alerts || []);
      }
    } catch (error) {
      console.error("Failed to fetch data:", error);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Send command to agent
  const sendCommand = async (agentId, command, params = {}) => {
    try {
      const response = await fetch(`${API_ROOT}/unified/agents/${agentId}/command`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          command_type: command,
          parameters: params,
          priority: "normal"
        })
      });
      
      if (response.ok) {
        toast.success(`Command "${command}" sent to agent`);
      } else {
        toast.error("Failed to send command");
      }
    } catch (error) {
      toast.error("Error sending command");
    }
  };

  // Bulk command to all online agents
  const runBulkCommand = async (command, params = {}, successLabel = 'Command') => {
    const onlineAgents = agents.filter((agent) => (agent.status || '').toLowerCase() === 'online');
    if (onlineAgents.length === 0) {
      toast.warning('No online agents available');
      return;
    }

    const results = await Promise.allSettled(
      onlineAgents.map((agent) => sendCommand(agent.agent_id, command, params))
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    toast.success(`${successLabel} sent to ${succeeded}/${onlineAgents.length} agents`);
    fetchData();
  };

  // Network scan and auto-deploy
  const triggerScanAndDeploy = async () => {
    setScanning(true);
    try {
      // Trigger direct discovery scan and unified auto-deploy queue in parallel.
      const [scanRes, deployRes] = await Promise.all([
        fetch(`${API_ROOT}/swarm/scan`, {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({})
        }),
        fetch(`${API_ROOT}/swarm/unified/scan-and-deploy`, {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({})
        })
      ]);

      if (scanRes.ok && deployRes.ok) {
        const data = await deployRes.json();
        toast.success(`Network scan started. ${data.devices_queued} devices queued for deployment`);

        // Discovery can take longer than a single refresh; poll for up to 60s.
        for (let i = 0; i < 6; i++) {
          setTimeout(fetchData, 10000 * (i + 1));
        }
      } else {
        const scanTxt = scanRes.ok ? '' : await scanRes.text();
        const deployTxt = deployRes.ok ? '' : await deployRes.text();
        toast.error(`Failed to start scan${scanTxt || deployTxt ? `: ${scanTxt || deployTxt}` : ''}`);
      }
    } catch (error) {
      toast.error("Network scan error");
    } finally {
      setScanning(false);
    }
  };

  // Deploy to specific device
  const deployToDevice = async (deviceIp) => {
    try {
      const response = await fetch(`${API_ROOT}/swarm/unified/deploy-to-device?device_ip=${deviceIp}`, {
        method: "POST",
        headers
      });
      
      if (response.ok) {
        toast.success(`Deployment queued for ${deviceIp}`);
        fetchData();
      } else {
        toast.error("Failed to queue deployment");
      }
    } catch (error) {
      toast.error("Deployment error");
    }
  };

  // Deploy to all discovered devices
  const deployAll = async () => {
    setDeploying(true);
    try {
      const response = await fetch(`${API_ROOT}/swarm/deploy/batch`, {
        method: "POST",
        headers
      });
      
      if (response.ok) {
        const data = await response.json();
        toast.success(`Batch deployment initiated for ${data.devices?.length || 0} devices`);
        fetchData();
      } else {
        toast.error("Batch deployment failed");
      }
    } catch (error) {
      toast.error("Deployment error");
    } finally {
      setDeploying(false);
    }
  };

  // Helper functions
  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case "online": case "deployed": return "text-green-400 bg-green-500/20 border-green-500/30";
      case "offline": case "failed": return "text-red-400 bg-red-500/20 border-red-500/30";
      case "warning": case "deploying": case "queued": return "text-yellow-400 bg-yellow-500/20 border-yellow-500/30";
      default: return "text-slate-400 bg-slate-500/20 border-slate-500/30";
    }
  };

  const getPlatformIcon = (platform) => {
    switch (platform?.toLowerCase()) {
      case "windows": return "🪟";
      case "linux": return "🐧";
      case "darwin": case "macos": return "🍎";
      case "android": return "🤖";
      case "ios": return "📱";
      default: return "💻";
    }
  };

  const getDeviceIcon = (type) => {
    switch (type?.toLowerCase()) {
      case "workstation": return <Laptop className="w-5 h-5 text-blue-400" />;
      case "server": return <Server className="w-5 h-5 text-purple-400" />;
      case "mobile": return <Smartphone className="w-5 h-5 text-green-400" />;
      default: return <Monitor className="w-5 h-5 text-slate-400" />;
    }
  };

  // Filter devices by search
  const filteredDevices = devices.filter(d => 
    !searchQuery || 
    (d.ip_address || d.ip || '')?.includes(searchQuery) || 
    d.hostname?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Unified Agent Dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cpu className="w-6 h-6 text-cyan-500" />
            Unified Agent Dashboard
          </h1>
          <p className="text-slate-400">Network discovery, agent deployment, and endpoint security - all in one place</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchData} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button 
            className="bg-cyan-600 hover:bg-cyan-700"
            onClick={triggerScanAndDeploy}
            disabled={scanning}
          >
            {scanning ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Search className="w-4 h-4 mr-2" />}
            Scan & Deploy
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Total Agents</p>
                <p className="text-xl font-bold text-white">{stats?.total_agents || agents.length}</p>
              </div>
              <Cpu className="w-6 h-6 text-cyan-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Online</p>
                <p className="text-xl font-bold text-green-400">{stats?.online_agents || agents.filter(a => a.status === 'online').length}</p>
              </div>
              <CheckCircle className="w-6 h-6 text-green-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Discovered</p>
                <p className="text-xl font-bold text-blue-400">{deviceStats?.total || devices.length}</p>
              </div>
              <Globe className="w-6 h-6 text-blue-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Unmanaged</p>
                <p className="text-xl font-bold text-orange-400">{deviceStats?.unmanaged || 0}</p>
              </div>
              <AlertTriangle className="w-6 h-6 text-orange-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Threats</p>
                <p className="text-xl font-bold text-red-400">{stats?.total_threats || 0}</p>
              </div>
              <Shield className="w-6 h-6 text-red-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Auto-Kills</p>
                <p className="text-xl font-bold text-purple-400">{stats?.auto_kills || 0}</p>
              </div>
              <Zap className="w-6 h-6 text-purple-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Features Banner - All 29 Enterprise Monitors */}
      <Card className="bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border-cyan-500/30">
        <CardContent className="p-4">
          <div className="grid grid-cols-6 md:grid-cols-10 lg:grid-cols-15 xl:grid-cols-29 gap-2 text-center">
            {[
              { icon: Activity, label: "Process", color: "text-green-400" },
              { icon: Network, label: "Network", color: "text-blue-400" },
              { icon: Database, label: "Registry", color: "text-yellow-400" },
              { icon: Server, label: "Process Tree", color: "text-cyan-400" },
              { icon: Terminal, label: "LOLBin", color: "text-orange-400" },
              { icon: Lock, label: "Code Sign", color: "text-pink-400" },
              { icon: Globe, label: "DNS", color: "text-purple-400" },
              { icon: Cpu, label: "Memory", color: "text-red-400" },
              { icon: Shield, label: "Whitelist", color: "text-emerald-400" },
              { icon: Eye, label: "DLP", color: "text-amber-400" },
              { icon: AlertTriangle, label: "Vuln Scan", color: "text-rose-400" },
              { icon: Zap, label: "AMSI", color: "text-indigo-400" },
              { icon: HardDrive, label: "Ransomware", color: "text-red-500" },
              { icon: Bug, label: "Rootkit", color: "text-violet-400" },
              { icon: Scan, label: "Kernel", color: "text-lime-400" },
              { icon: ShieldOff, label: "Anti-Tamper", color: "text-teal-400" },
              { icon: Fingerprint, label: "Identity", color: "text-fuchsia-400" },
              { icon: Cpu, label: "Throttle", color: "text-sky-400" },
              { icon: Flame, label: "Firewall", color: "text-orange-500" },
              { icon: AppWindow, label: "WebView2", color: "text-blue-500" },
              { icon: FileText, label: "CLI Tel.", color: "text-cyan-500" },
              { icon: EyeOff, label: "Hidden", color: "text-slate-400" },
              { icon: UserX, label: "Alias", color: "text-amber-500" },
              { icon: ShieldCheck, label: "Priv Esc", color: "text-red-600" },
              // NEW Unified Agent v2.0 Monitors
              { icon: Sparkles, label: "Trusted AI", color: "text-violet-500" },
              { icon: ShieldAlert, label: "Bootkit", color: "text-rose-600" },
              { icon: Award, label: "CA Cert", color: "text-emerald-500" },
              { icon: Settings, label: "BIOS/UEFI", color: "text-gray-400" },
              { icon: Calendar, label: "Sched Task", color: "text-blue-300" },
              { icon: Cog, label: "Service", color: "text-indigo-400" },
              { icon: Code2, label: "WMI", color: "text-purple-300" },
              { icon: Usb, label: "USB", color: "text-pink-400" },
              { icon: Power, label: "Power", color: "text-yellow-300" }
            ].map(({ icon: Icon, label, color }) => (
              <div key={label} className="flex flex-col items-center">
                <Icon className={`w-4 h-4 ${color}`} />
                <span className="text-[10px] text-slate-400 mt-1">{label}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="agents" className="data-[state=active]:bg-cyan-500/20">
            <Shield className="w-4 h-4 mr-2" /> Active Agents
          </TabsTrigger>
          <TabsTrigger value="devices" className="data-[state=active]:bg-blue-500/20">
            <Globe className="w-4 h-4 mr-2" /> Discovered Devices
          </TabsTrigger>
          <TabsTrigger value="commands" className="data-[state=active]:bg-purple-500/20">
            <Terminal className="w-4 h-4 mr-2" /> Bulk Commands
          </TabsTrigger>
          <TabsTrigger value="install" className="data-[state=active]:bg-green-500/20">
            <Download className="w-4 h-4 mr-2" /> Installation
          </TabsTrigger>
          <TabsTrigger value="monitors" className="data-[state=active]:bg-orange-500/20">
            <Activity className="w-4 h-4 mr-2" /> Monitors
          </TabsTrigger>
        </TabsList>

        {/* Active Agents Tab */}
        <TabsContent value="agents">
          <div className="space-y-4">
            {agents.length === 0 ? (
              <Card className="bg-slate-900/50 border-slate-800">
                <CardContent className="py-12 text-center">
                  <Cpu className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-white font-medium mb-2">No Agents Registered</h3>
                  <p className="text-slate-400 text-sm mb-4">
                    Scan your network and deploy agents, or install manually
                  </p>
                  <div className="flex gap-2 justify-center">
                    <Button className="bg-cyan-600" onClick={triggerScanAndDeploy}>
                      <Search className="w-4 h-4 mr-2" /> Scan Network
                    </Button>
                    <Button variant="outline" onClick={() => setActiveTab("install")}>
                      <Download className="w-4 h-4 mr-2" /> Manual Install
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <div className="grid grid-cols-1 gap-4">
                {agents.map((agent) => (
                  <Card key={agent.agent_id} className="bg-slate-900/50 border-slate-800 hover:border-cyan-500/30 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-4">
                          <div className="w-12 h-12 rounded-lg bg-slate-800 flex items-center justify-center text-2xl">
                            {getPlatformIcon(agent.platform)}
                          </div>
                          <div>
                            <h3 className="text-white font-medium flex items-center gap-2">
                              {agent.hostname || agent.agent_id}
                              <Badge className={getStatusColor(agent.status)}>
                                {agent.status || "unknown"}
                              </Badge>
                              {agent.vpn?.connected && (
                                <Badge className="text-pink-400 bg-pink-500/20 border-pink-500/30">
                                  <Lock className="w-3 h-3 mr-1" /> VPN
                                </Badge>
                              )}
                            </h3>
                            <p className="text-slate-400 text-sm">{agent.ip_address}</p>
                            <p className="text-slate-500 text-xs mt-1">v{agent.version || "2.0.0"} | {agent.platform}</p>
                          </div>
                        </div>
                        <div className="text-right text-sm">
                          <div className="grid grid-cols-4 gap-4 text-center">
                            <div><p className="text-slate-500 text-xs">CPU</p><p className="text-white font-mono">{agent.cpu_usage?.toFixed(0) || 0}%</p></div>
                            <div><p className="text-slate-500 text-xs">MEM</p><p className="text-white font-mono">{agent.memory_usage?.toFixed(0) || 0}%</p></div>
                            <div><p className="text-slate-500 text-xs">Threats</p><p className="text-red-400 font-mono">{agent.threat_count || 0}</p></div>
                            <div><p className="text-slate-500 text-xs">Conn</p><p className="text-cyan-400 font-mono">{agent.network_connections || 0}</p></div>
                          </div>
                        </div>
                      </div>
                      <div className="mt-4 flex gap-2 flex-wrap">
                        <Button size="sm" variant="outline" onClick={() => sendCommand(agent.agent_id, "scan")} className="text-cyan-400 border-cyan-500/30">
                          <Activity className="w-4 h-4 mr-1" /> Full Scan
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => sendCommand(agent.agent_id, "network_scan")} className="text-blue-400 border-blue-500/30">
                          <Network className="w-4 h-4 mr-1" /> Network Scan
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => sendCommand(agent.agent_id, "update_config")} className="text-green-400 border-green-500/30">
                          <RefreshCw className="w-4 h-4 mr-1" /> Update
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setSelectedAgent(agent)} className="text-purple-400 border-purple-500/30">
                          <Eye className="w-4 h-4 mr-1" /> Details
                        </Button>
                        {agent.local_ui_url && /^https?:\/\//.test(agent.local_ui_url) && (
                          <a href={agent.local_ui_url} target="_blank" rel="noopener noreferrer">
                            <Button size="sm" variant="outline" className="text-amber-400 border-amber-500/30">
                              <Monitor className="w-4 h-4 mr-1" /> Local Dashboard
                            </Button>
                          </a>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </TabsContent>

        {/* Discovered Devices Tab */}
        <TabsContent value="devices">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <Input
                  placeholder="Search by IP or hostname..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-64 bg-slate-900/50 border-slate-700"
                />
                <span className="text-slate-400 text-sm">{filteredDevices.length} devices</span>
              </div>
              <div className="flex gap-2">
                <Button onClick={triggerScanAndDeploy} disabled={scanning} className="bg-cyan-600">
                  {scanning ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Search className="w-4 h-4 mr-2" />}
                  Scan Network
                </Button>
                <Button onClick={deployAll} disabled={deploying} className="bg-purple-600">
                  {deploying ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Download className="w-4 h-4 mr-2" />}
                  Deploy All
                </Button>
              </div>
            </div>

            {filteredDevices.length === 0 ? (
              <Card className="bg-slate-900/50 border-slate-800">
                <CardContent className="py-12 text-center">
                  <Globe className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-white font-medium mb-2">No Devices Discovered</h3>
                  <p className="text-slate-400 text-sm mb-4">
                    Run a network scan to discover devices on your network
                  </p>
                  <Button className="bg-cyan-600" onClick={triggerScanAndDeploy}>
                    <Search className="w-4 h-4 mr-2" /> Start Network Scan
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredDevices.map((device) => (
                  <Card key={device.ip_address || device.ip || device.hostname} className="bg-slate-900/50 border-slate-800 hover:border-blue-500/30 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center">
                            {getDeviceIcon(device.device_type)}
                          </div>
                          <div>
                            <h3 className="text-white font-medium flex items-center gap-2">
                              {device.hostname || device.ip_address || device.ip}
                              <Badge className={getStatusColor(device.deployment_status)}>
                                {device.deployment_status || "discovered"}
                              </Badge>
                            </h3>
                            <p className="text-slate-400 text-sm">{device.ip_address || device.ip}</p>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-xs text-slate-500">{device.os_type || "Unknown"}</span>
                              {device.mac_address && <span className="text-xs text-slate-600">{device.mac_address}</span>}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          {device.deployable && device.deployment_status !== 'deployed' && (
                            <Button size="sm" onClick={() => deployToDevice(device.ip_address || device.ip)} className="bg-green-600 hover:bg-green-500">
                              <Download className="w-4 h-4 mr-1" /> Deploy
                            </Button>
                          )}
                          {device.deployment_status === 'deployed' && (
                            <Badge className="text-green-400 bg-green-500/20">
                              <CheckCircle className="w-3 h-3 mr-1" /> Managed
                            </Badge>
                          )}
                        </div>
                      </div>
                      {device.open_ports && device.open_ports.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1">
                          {device.open_ports.slice(0, 6).map((p) => (
                            <Badge key={p.port} variant="outline" className="text-xs text-slate-400 border-slate-700">
                              {p.port}/{p.service}
                            </Badge>
                          ))}
                          {device.open_ports.length > 6 && (
                            <Badge variant="outline" className="text-xs text-slate-500">+{device.open_ports.length - 6}</Badge>
                          )}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="commands">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Bulk Commands</CardTitle>
              <CardDescription>Send commands to all connected agents simultaneously</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Button
                  className="h-24 flex-col bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30"
                  onClick={() => runBulkCommand('scan', {}, 'Full scan')}
                >
                  <Activity className="w-6 h-6 mb-2 text-cyan-400" />
                  <span className="text-cyan-400">Full Scan All</span>
                </Button>
                <Button
                  className="h-24 flex-col bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30"
                  onClick={() => runBulkCommand('network_scan', {}, 'Network scan')}
                >
                  <Network className="w-6 h-6 mb-2 text-blue-400" />
                  <span className="text-blue-400">Network Scan All</span>
                </Button>
                <Button
                  className="h-24 flex-col bg-green-500/10 hover:bg-green-500/20 border border-green-500/30"
                  onClick={() => runBulkCommand('update_config', {}, 'Config update')}
                >
                  <RefreshCw className="w-6 h-6 mb-2 text-green-400" />
                  <span className="text-green-400">Update All</span>
                </Button>
                <Button
                  className="h-24 flex-col bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30"
                  onClick={() => runBulkCommand('update_config', { auto_kill: true }, 'Auto-kill enable')}
                >
                  <Zap className="w-6 h-6 mb-2 text-orange-400" />
                  <span className="text-orange-400">Enable Auto-Kill</span>
                </Button>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Button
                  className="h-20 flex-col bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30"
                  onClick={() => runBulkCommand('wifi_scan', {}, 'WiFi scan')}
                >
                  <Wifi className="w-5 h-5 mb-2 text-purple-400" />
                  <span className="text-purple-400 text-sm">WiFi Scan</span>
                </Button>
                <Button
                  className="h-20 flex-col bg-pink-500/10 hover:bg-pink-500/20 border border-pink-500/30"
                  onClick={() => runBulkCommand('bluetooth_scan', {}, 'Bluetooth scan')}
                >
                  <Bluetooth className="w-5 h-5 mb-2 text-pink-400" />
                  <span className="text-pink-400 text-sm">Bluetooth Scan</span>
                </Button>
                <Button
                  className="h-20 flex-col bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/30"
                  onClick={() => runBulkCommand('collect_forensics', {}, 'Forensics')}
                >
                  <HardDrive className="w-5 h-5 mb-2 text-yellow-400" />
                  <span className="text-yellow-400 text-sm">Collect Forensics</span>
                </Button>
                <Button
                  className="h-20 flex-col bg-red-500/10 hover:bg-red-500/20 border border-red-500/30"
                  onClick={() => runBulkCommand('threat_hunt', {}, 'Threat hunt')}
                >
                  <Eye className="w-5 h-5 mb-2 text-red-400" />
                  <span className="text-red-400 text-sm">Threat Hunt</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="install">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">Quick Install by Platform</CardTitle>
                <CardDescription>Click to download or copy install command</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {[
                  { 
                    name: "Linux", 
                    icon: "🐧", 
                    command: `curl -sSL ${API_ROOT}/unified/agent/install-script | sudo bash`,
                    endpoint: `${API_ROOT}/unified/agent/install-script`,
                    color: "border-green-500 hover:bg-green-500/10"
                  },
                  { 
                    name: "Windows", 
                    icon: "🪟", 
                    command: `powershell -Command "irm ${API_ROOT}/unified/agent/install-windows | iex"`,
                    endpoint: `${API_ROOT}/unified/agent/install-windows`,
                    color: "border-blue-500 hover:bg-blue-500/10"
                  },
                  { 
                    name: "macOS", 
                    icon: "🍎", 
                    command: `curl -sSL ${API_ROOT}/unified/agent/install-macos | bash`,
                    endpoint: `${API_ROOT}/unified/agent/install-macos`,
                    color: "border-purple-500 hover:bg-purple-500/10"
                  },
                  { 
                    name: "Android", 
                    icon: "🤖", 
                    command: `curl -sSL ${API_ROOT}/unified/agent/install-android | bash`,
                    endpoint: `${API_ROOT}/unified/agent/install-android`,
                    color: "border-cyan-500 hover:bg-cyan-500/10",
                    note: "Run in Termux"
                  },
                  { 
                    name: "iOS", 
                    icon: "📱", 
                    endpoint: `${API_ROOT}/unified/agent/install-ios`,
                    color: "border-pink-500 hover:bg-pink-500/10",
                    note: "Pythonista 3 or Native App"
                  }
                ].map((platform) => (
                  <div 
                    key={platform.name} 
                    className={`p-4 bg-slate-800/50 rounded-lg border ${platform.color} cursor-pointer transition-all`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <span className="text-3xl">{platform.icon}</span>
                        <div>
                          <p className="text-white font-medium">{platform.name}</p>
                          {platform.note && <p className="text-slate-500 text-xs">{platform.note}</p>}
                        </div>
                      </div>
                      <div className="flex gap-2">
                        {platform.command && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => {
                              navigator.clipboard.writeText(platform.command);
                              toast({ title: "Copied!", description: `${platform.name} install command copied` });
                            }}
                          >
                            <Copy className="w-3 h-3 mr-1" /> Copy
                          </Button>
                        )}
                        <Button 
                          size="sm"
                          onClick={() => window.open(platform.endpoint, '_blank')}
                        >
                          <Download className="w-3 h-3 mr-1" /> Get
                        </Button>
                      </div>
                    </div>
                    {platform.command && (
                      <pre className="bg-slate-950/50 p-2 rounded text-xs text-slate-400 font-mono overflow-x-auto">
                        {platform.command}
                      </pre>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">What's Included</CardTitle>
                <CardDescription>Unified agent works across all platforms with full features</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
                    <h4 className="text-cyan-400 font-medium mb-2 flex items-center gap-2">
                      <CheckCircle className="w-4 h-4" /> Core Features
                    </h4>
                    <ul className="text-sm text-slate-300 space-y-1">
                      <li>• Network scanner (auto-discovers devices)</li>
                      <li>• WireGuard VPN (auto-configured on install)</li>
                      <li>• Process monitoring with auto-kill</li>
                      <li>• WiFi & Bluetooth scanning</li>
                      <li>• SIEM integration ready</li>
                      <li>• AI threat analysis</li>
                    </ul>
                  </div>

                  <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                    <h4 className="text-green-400 font-medium mb-2 flex items-center gap-2">
                      <Shield className="w-4 h-4" /> MCP Command Execution
                    </h4>
                    <ul className="text-sm text-slate-300 space-y-1">
                      <li>• Remote command polling from dashboard</li>
                      <li>• Threat hunting on-demand</li>
                      <li>• Forensics collection</li>
                      <li>• Remote quarantine & block</li>
                      <li>• VPN connect/disconnect</li>
                    </ul>
                  </div>

                  <div className="p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                    <h4 className="text-purple-400 font-medium mb-2">Manual Download</h4>
                    <pre className="bg-slate-950/50 p-2 rounded text-xs text-slate-400 font-mono overflow-x-auto">
{`# Download agent package
curl -sSL ${API_ROOT}/unified/agent/download -o agent.tar.gz
tar -xzf agent.tar.gz && cd unified_agent
pip install -r requirements.txt
python core/agent.py --server ${API_URL || window.location.origin}`}
                    </pre>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Monitors Tab - Enterprise Security Monitors */}
        <TabsContent value="monitors">
          <div className="space-y-4">
            {/* Monitor Stats Summary */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card className="bg-slate-900/50 border-red-500/30">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400">Threat Detections</p>
                      <p className="text-2xl font-bold text-red-400">
                        {monitorStats?.threat_summary ? 
                          Object.values(monitorStats.threat_summary).reduce((a, b) => a + b, 0) : 0}
                      </p>
                    </div>
                    <AlertTriangle className="w-8 h-8 text-red-500/50" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-slate-900/50 border-yellow-500/30">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400">Compliance Issues</p>
                      <p className="text-2xl font-bold text-yellow-400">
                        {monitorStats?.compliance_summary ?
                          Object.values(monitorStats.compliance_summary).reduce((a, b) => a + b, 0) : 0}
                      </p>
                    </div>
                    <Shield className="w-8 h-8 text-yellow-500/50" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-slate-900/50 border-cyan-500/30">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400">Agents with Monitors</p>
                      <p className="text-2xl font-bold text-cyan-400">
                        {monitorStats?.total_agents_with_monitors || 0}
                      </p>
                    </div>
                    <Cpu className="w-8 h-8 text-cyan-500/50" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-slate-900/50 border-green-500/30">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400">Active Alerts</p>
                      <p className="text-2xl font-bold text-green-400">
                        {monitorAlerts.length}
                      </p>
                    </div>
                    <Activity className="w-8 h-8 text-green-500/50" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Monitor Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {/* Registry Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-yellow-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-yellow-400 flex items-center gap-2">
                    <Database className="w-4 h-4" /> Registry Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Persistence Locations</span>
                      <span className="text-white">{monitorStats?.threat_summary?.registry_persistence || 0}</span>
                    </div>
                    <p className="text-slate-500">Monitors registry run keys, services, scheduled tasks</p>
                  </div>
                </CardContent>
              </Card>

              {/* Process Tree Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-cyan-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-cyan-400 flex items-center gap-2">
                    <Server className="w-4 h-4" /> Process Tree Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Anomalies Detected</span>
                      <span className="text-white">{monitorStats?.threat_summary?.process_anomalies || 0}</span>
                    </div>
                    <p className="text-slate-500">Parent-child process relationship analysis</p>
                  </div>
                </CardContent>
              </Card>

              {/* LOLBin Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-orange-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-orange-400 flex items-center gap-2">
                    <Terminal className="w-4 h-4" /> LOLBin Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">LOLBin Abuse Detected</span>
                      <span className="text-white">{monitorStats?.threat_summary?.lolbin_abuse || 0}</span>
                    </div>
                    <p className="text-slate-500">Living-off-the-land binary detection</p>
                  </div>
                </CardContent>
              </Card>

              {/* Code Signing Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-pink-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-pink-400 flex items-center gap-2">
                    <Lock className="w-4 h-4" /> Code Signing Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Unsigned Binaries</span>
                      <span className="text-white">{monitorStats?.compliance_summary?.unsigned_binaries || 0}</span>
                    </div>
                    <p className="text-slate-500">Authenticode signature verification</p>
                  </div>
                </CardContent>
              </Card>

              {/* DNS Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-purple-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-purple-400 flex items-center gap-2">
                    <Globe className="w-4 h-4" /> DNS Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">DGA Domains</span>
                      <span className="text-white">{monitorStats?.threat_summary?.dga_domains || 0}</span>
                    </div>
                    <p className="text-slate-500">DGA detection, DNS tunneling analysis</p>
                  </div>
                </CardContent>
              </Card>

              {/* Memory Scanner */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-red-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-red-400 flex items-center gap-2">
                    <Cpu className="w-4 h-4" /> Memory Scanner
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Memory Injections</span>
                      <span className="text-white">{monitorStats?.threat_summary?.memory_injections || 0}</span>
                    </div>
                    <p className="text-slate-500">RWX regions, shellcode, process injection</p>
                  </div>
                </CardContent>
              </Card>

              {/* Application Whitelist */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-emerald-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-emerald-400 flex items-center gap-2">
                    <Shield className="w-4 h-4" /> App Whitelist
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Violations</span>
                      <span className="text-white">{monitorStats?.compliance_summary?.whitelist_violations || 0}</span>
                    </div>
                    <p className="text-slate-500">Approved application enforcement</p>
                  </div>
                </CardContent>
              </Card>

              {/* DLP Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-amber-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-amber-400 flex items-center gap-2">
                    <Eye className="w-4 h-4" /> DLP Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">DLP Alerts</span>
                      <span className="text-white">{monitorStats?.compliance_summary?.dlp_alerts || 0}</span>
                    </div>
                    <p className="text-slate-500">Data exfiltration detection</p>
                  </div>
                </CardContent>
              </Card>

              {/* Vulnerability Scanner */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-rose-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-rose-400 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> Vulnerability Scanner
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Critical CVEs</span>
                      <span className="text-white">{monitorStats?.compliance_summary?.critical_vulnerabilities || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">High CVEs</span>
                      <span className="text-white">{monitorStats?.compliance_summary?.high_vulnerabilities || 0}</span>
                    </div>
                    <p className="text-slate-500">CVE checking for installed software</p>
                  </div>
                </CardContent>
              </Card>

              {/* AMSI Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-indigo-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-indigo-400 flex items-center gap-2">
                    <Zap className="w-4 h-4" /> AMSI Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Script Threats</span>
                      <span className="text-white">{monitorStats?.threat_summary?.amsi_threats || 0}</span>
                    </div>
                    <p className="text-slate-500">Windows script scanning (PowerShell, VBScript)</p>
                  </div>
                </CardContent>
              </Card>

              {/* Ransomware Protection */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-red-600/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-red-500 flex items-center gap-2">
                    <HardDrive className="w-4 h-4" /> Ransomware Shield
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Canary Alerts</span>
                      <span className="text-white">{monitorStats?.threat_summary?.canary_alerts || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Shadow Copy Threats</span>
                      <span className="text-white">{monitorStats?.threat_summary?.shadow_copy_attempts || 0}</span>
                    </div>
                    <p className="text-slate-500">Canary traps, shadow copy protection, entropy analysis</p>
                  </div>
                </CardContent>
              </Card>

              {/* Rootkit Detector */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-violet-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-violet-400 flex items-center gap-2">
                    <Bug className="w-4 h-4" /> Rootkit Detector
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Hidden Processes</span>
                      <span className="text-white">{monitorStats?.threat_summary?.hidden_processes || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Kernel Module Threats</span>
                      <span className="text-white">{monitorStats?.threat_summary?.kernel_module_threats || 0}</span>
                    </div>
                    <p className="text-slate-500">DKOM detection, LD_PRELOAD hijacking, hidden file scans</p>
                  </div>
                </CardContent>
              </Card>

              {/* Kernel Security Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-lime-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-lime-400 flex items-center gap-2">
                    <Scan className="w-4 h-4" /> Kernel Security
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Syscall Anomalies</span>
                      <span className="text-white">{monitorStats?.threat_summary?.syscall_anomalies || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Ptrace Detections</span>
                      <span className="text-white">{monitorStats?.threat_summary?.ptrace_detections || 0}</span>
                    </div>
                    <p className="text-slate-500">eBPF-style syscall monitoring, audit log analysis</p>
                  </div>
                </CardContent>
              </Card>

              {/* Agent Self-Protection */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-teal-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-teal-400 flex items-center gap-2">
                    <ShieldOff className="w-4 h-4" /> Anti-Tamper
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Tamper Events</span>
                      <span className="text-white">{monitorStats?.threat_summary?.tamper_events || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Debug Attempts</span>
                      <span className="text-white">{monitorStats?.threat_summary?.debug_attempts || 0}</span>
                    </div>
                    <p className="text-slate-500">Anti-debug, file integrity watchdog, injection detection</p>
                  </div>
                </CardContent>
              </Card>

              {/* Identity Protection */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-fuchsia-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-fuchsia-400 flex items-center gap-2">
                    <Fingerprint className="w-4 h-4" /> Identity Protection
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Credential Tools</span>
                      <span className="text-white">{monitorStats?.threat_summary?.credential_tools || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">LSASS Access</span>
                      <span className="text-white">{monitorStats?.threat_summary?.lsass_access || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Kerberos Anomalies</span>
                      <span className="text-white">{monitorStats?.threat_summary?.kerberos_anomalies || 0}</span>
                    </div>
                    <p className="text-slate-500">Credential theft, Pass-the-Hash, mimikatz detection</p>
                  </div>
                </CardContent>
              </Card>

              {/* ============================================= */}
              {/* NEW MONITORS - Migrated from Desktop Agent   */}
              {/* ============================================= */}

              {/* AutoThrottle Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-sky-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-sky-400 flex items-center gap-2">
                    <Cpu className="w-4 h-4" /> Auto Throttle
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Throttled Processes</span>
                      <span className="text-white">{monitorStats?.threat_summary?.throttled_processes || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Cryptominer Detected</span>
                      <span className="text-white">{monitorStats?.threat_summary?.cryptominers || 0}</span>
                    </div>
                    <p className="text-slate-500">CPU/memory throttling, T1496 resource hijacking</p>
                  </div>
                </CardContent>
              </Card>

              {/* Firewall Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-orange-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-orange-500 flex items-center gap-2">
                    <Flame className="w-4 h-4" /> Firewall Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Disabled Firewalls</span>
                      <span className="text-white">{monitorStats?.threat_summary?.firewall_disabled || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Suspicious Rules</span>
                      <span className="text-white">{monitorStats?.threat_summary?.firewall_rules || 0}</span>
                    </div>
                    <p className="text-slate-500">Cross-platform firewall state, T1562.004</p>
                  </div>
                </CardContent>
              </Card>

              {/* WebView2 Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-blue-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-blue-500 flex items-center gap-2">
                    <AppWindow className="w-4 h-4" /> WebView2 Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Suspicious Instances</span>
                      <span className="text-white">{monitorStats?.threat_summary?.webview2_suspicious || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Remote Debug Active</span>
                      <span className="text-white">{monitorStats?.threat_summary?.webview2_debug || 0}</span>
                    </div>
                    <p className="text-slate-500">WebView2 exploit detection (Windows), T1055</p>
                  </div>
                </CardContent>
              </Card>

              {/* CLI Telemetry Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-cyan-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-cyan-500 flex items-center gap-2">
                    <FileText className="w-4 h-4" /> CLI Telemetry
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Commands Captured</span>
                      <span className="text-white">{monitorStats?.threat_summary?.cli_commands || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">LOLBin Executions</span>
                      <span className="text-white">{monitorStats?.threat_summary?.cli_lolbins || 0}</span>
                    </div>
                    <p className="text-slate-500">SOAR integration, shell monitoring, T1059.*</p>
                  </div>
                </CardContent>
              </Card>

              {/* Hidden File Scanner */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-slate-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-slate-400 flex items-center gap-2">
                    <EyeOff className="w-4 h-4" /> Hidden File Scanner
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Hidden Files Found</span>
                      <span className="text-white">{monitorStats?.threat_summary?.hidden_files || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">ADS Detected</span>
                      <span className="text-white">{monitorStats?.threat_summary?.ads_found || 0}</span>
                    </div>
                    <p className="text-slate-500">NTFS ADS, hidden directories, T1564.*</p>
                  </div>
                </CardContent>
              </Card>

              {/* Alias/Rename Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-amber-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-amber-500 flex items-center gap-2">
                    <UserX className="w-4 h-4" /> Alias/Rename
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Renamed Executables</span>
                      <span className="text-white">{monitorStats?.threat_summary?.renamed_exes || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">PATH Hijack Risks</span>
                      <span className="text-white">{monitorStats?.threat_summary?.path_hijacks || 0}</span>
                    </div>
                    <p className="text-slate-500">Masquerading, PATH hijacking, T1036/T1574</p>
                  </div>
                </CardContent>
              </Card>

              {/* Privilege Escalation Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-red-600/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-red-600 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" /> Privilege Escalation
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Dangerous Privileges</span>
                      <span className="text-white">{monitorStats?.threat_summary?.dangerous_privs || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">SYSTEM Processes</span>
                      <span className="text-white">{monitorStats?.threat_summary?.system_processes || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Non-MS SYSTEM Tasks</span>
                      <span className="text-white">{monitorStats?.threat_summary?.system_tasks || 0}</span>
                    </div>
                    <p className="text-slate-500">SeDebugPrivilege, token manipulation, T1134</p>
                  </div>
                </CardContent>
              </Card>

              {/* ============================================= */}
              {/* NEW MONITORS - Unified Agent v2.0            */}
              {/* ============================================= */}

              {/* Trusted AI Detection Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-violet-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-violet-500 flex items-center gap-2">
                    <Sparkles className="w-4 h-4" /> Trusted AI Detection
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">AI Violations</span>
                      <span className="text-white">{monitorStats?.threat_summary?.trusted_ai_violations || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Untrusted Models</span>
                      <span className="text-white">{monitorStats?.threat_summary?.untrusted_models || 0}</span>
                    </div>
                    <p className="text-slate-500">LLM detection, model validation, T1588</p>
                  </div>
                </CardContent>
              </Card>

              {/* Bootkit Detection Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-rose-600/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-rose-600 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" /> Bootkit Detection
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Bootkit Threats</span>
                      <span className="text-white">{monitorStats?.threat_summary?.bootkit_threats || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">MBR Anomalies</span>
                      <span className="text-white">{monitorStats?.threat_summary?.mbr_anomalies || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">UEFI Violations</span>
                      <span className="text-white">{monitorStats?.threat_summary?.uefi_violations || 0}</span>
                    </div>
                    <p className="text-slate-500">MBR/VBR integrity, boot config, T1542</p>
                  </div>
                </CardContent>
              </Card>

              {/* CA Certificate Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-emerald-500/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-emerald-500 flex items-center gap-2">
                    <Award className="w-4 h-4" /> CA Certificate Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Rogue CA Certs</span>
                      <span className="text-white">{monitorStats?.threat_summary?.rogue_ca_certs || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Untrusted Roots</span>
                      <span className="text-white">{monitorStats?.threat_summary?.untrusted_roots || 0}</span>
                    </div>
                    <p className="text-slate-500">Root CA validation, cert pinning, T1553</p>
                  </div>
                </CardContent>
              </Card>

              {/* BIOS/UEFI Security Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-gray-400/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-gray-400 flex items-center gap-2">
                    <Settings className="w-4 h-4" /> BIOS/UEFI Security
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">BIOS Threats</span>
                      <span className="text-white">{monitorStats?.threat_summary?.bios_threats || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Secure Boot Disabled</span>
                      <span className="text-white">{monitorStats?.threat_summary?.secure_boot_disabled || 0}</span>
                    </div>
                    <p className="text-slate-500">Firmware integrity, Secure Boot, T1542.001</p>
                  </div>
                </CardContent>
              </Card>

              {/* Scheduled Task Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-blue-300/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-blue-300 flex items-center gap-2">
                    <Calendar className="w-4 h-4" /> Scheduled Task Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Suspicious Tasks</span>
                      <span className="text-white">{monitorStats?.threat_summary?.suspicious_tasks || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Hidden Tasks</span>
                      <span className="text-white">{monitorStats?.threat_summary?.hidden_tasks || 0}</span>
                    </div>
                    <p className="text-slate-500">Task Scheduler persistence, T1053.005</p>
                  </div>
                </CardContent>
              </Card>

              {/* Service Integrity Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-indigo-400/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-indigo-400 flex items-center gap-2">
                    <Cog className="w-4 h-4" /> Service Integrity
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Suspicious Services</span>
                      <span className="text-white">{monitorStats?.threat_summary?.suspicious_services || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">DLL Hijacks</span>
                      <span className="text-white">{monitorStats?.threat_summary?.service_dll_hijacks || 0}</span>
                    </div>
                    <p className="text-slate-500">Service path hijacking, T1543.003</p>
                  </div>
                </CardContent>
              </Card>

              {/* WMI Persistence Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-purple-300/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-purple-300 flex items-center gap-2">
                    <Code2 className="w-4 h-4" /> WMI Persistence
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Suspicious Consumers</span>
                      <span className="text-white">{monitorStats?.threat_summary?.wmi_consumers || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Malicious Subscriptions</span>
                      <span className="text-white">{monitorStats?.threat_summary?.wmi_subscriptions || 0}</span>
                    </div>
                    <p className="text-slate-500">WMI event subscriptions, T1546.003</p>
                  </div>
                </CardContent>
              </Card>

              {/* USB Device Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-pink-400/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-pink-400 flex items-center gap-2">
                    <Usb className="w-4 h-4" /> USB Device Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">USB Violations</span>
                      <span className="text-white">{monitorStats?.threat_summary?.usb_violations || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Unauthorized Devices</span>
                      <span className="text-white">{monitorStats?.threat_summary?.unauthorized_usb || 0}</span>
                    </div>
                    <p className="text-slate-500">USB device control, T1091/T1200</p>
                  </div>
                </CardContent>
              </Card>

              {/* Power State Monitor */}
              <Card className="bg-slate-900/50 border-slate-800 hover:border-yellow-300/50 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-yellow-300 flex items-center gap-2">
                    <Power className="w-4 h-4" /> Power State Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Power Anomalies</span>
                      <span className="text-white">{monitorStats?.threat_summary?.power_anomalies || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Wake-on-LAN Events</span>
                      <span className="text-white">{monitorStats?.threat_summary?.wake_on_lan_events || 0}</span>
                    </div>
                    <p className="text-slate-500">Sleep/wake monitoring, WoL detection</p>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Recent Alerts */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  Recent Monitor Alerts
                </CardTitle>
              </CardHeader>
              <CardContent>
                {monitorAlerts.length === 0 ? (
                  <div className="text-center py-8 text-slate-400">
                    <CheckCircle className="w-12 h-12 mx-auto mb-2 text-green-500/50" />
                    <p>No active alerts</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {monitorAlerts.map((alert, idx) => (
                      <div key={idx} className="p-3 bg-slate-800/50 rounded-lg border border-red-500/20">
                        <div className="flex items-center justify-between mb-1">
                          <Badge className="bg-red-500/20 text-red-400">{alert.monitor}</Badge>
                          <span className="text-xs text-slate-500">{alert.timestamp}</span>
                        </div>
                        <div className="text-sm text-white">
                          Agent: <span className="text-cyan-400">{alert.agent_id?.slice(0, 8)}...</span>
                          <span className="text-slate-400 ml-2">({alert.alert_count} alerts)</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* Agent Details Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedAgent(null)}>
          <Card className="bg-slate-900 border-slate-700 w-full max-w-2xl m-4" onClick={(e) => e.stopPropagation()}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <span className="text-2xl">{getPlatformIcon(selectedAgent.platform)}</span>
                {selectedAgent.hostname || selectedAgent.agent_id}
                <Badge className={getStatusColor(selectedAgent.status)}>{selectedAgent.status}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div><span className="text-slate-500">Agent ID:</span> <span className="text-white">{selectedAgent.agent_id}</span></div>
                <div><span className="text-slate-500">IP Address:</span> <span className="text-white">{selectedAgent.ip_address}</span></div>
                <div><span className="text-slate-500">Platform:</span> <span className="text-white">{selectedAgent.platform}</span></div>
                <div><span className="text-slate-500">Version:</span> <span className="text-white">{selectedAgent.version}</span></div>
              </div>
              <div className="grid grid-cols-4 gap-4 pt-4 border-t border-slate-700">
                <div className="text-center">
                  <p className="text-slate-500 text-xs">CPU</p>
                  <p className="text-white text-xl font-mono">{selectedAgent.cpu_usage?.toFixed(0) || 0}%</p>
                </div>
                <div className="text-center">
                  <p className="text-slate-500 text-xs">Memory</p>
                  <p className="text-white text-xl font-mono">{selectedAgent.memory_usage?.toFixed(0) || 0}%</p>
                </div>
                <div className="text-center">
                  <p className="text-slate-500 text-xs">Threats</p>
                  <p className="text-red-400 text-xl font-mono">{selectedAgent.threat_count || 0}</p>
                </div>
                <div className="text-center">
                  <p className="text-slate-500 text-xs">Connections</p>
                  <p className="text-cyan-400 text-xl font-mono">{selectedAgent.network_connections || 0}</p>
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button variant="outline" onClick={() => setSelectedAgent(null)}>Close</Button>
                <Button className="bg-cyan-600" onClick={() => { sendCommand(selectedAgent.agent_id, "scan"); setSelectedAgent(null); }}>
                  <Activity className="w-4 h-4 mr-2" /> Run Full Scan
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
