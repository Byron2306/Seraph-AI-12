import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Network, Server, Monitor, Smartphone, Laptop, Shield, 
  RefreshCw, Play, AlertTriangle, CheckCircle, XCircle,
  Wifi, WifiOff, Eye, Zap, Activity, Cpu, HardDrive,
  Users, Globe, Lock, Unlock, ChevronRight, Search,
  Download, Settings, Terminal, Radio, Tag, FolderPlus,
  Usb, Palette, X, Plus
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { toast } from 'sonner';

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API = rawBackendUrl ? `${rawBackendUrl}/api` : '/api';

const SwarmDashboard = () => {
  const { token } = useAuth();
  const [overview, setOverview] = useState(null);
  const [devices, setDevices] = useState([]);
  const [telemetry, setTelemetry] = useState([]);
  const [telemetryStats, setTelemetryStats] = useState(null);
  const [deployments, setDeployments] = useState([]);
  const [groups, setGroups] = useState([]);
  const [allTags, setAllTags] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [selectedTag, setSelectedTag] = useState(null);
  const [showGroupModal, setShowGroupModal] = useState(false);
  const [showTagModal, setShowTagModal] = useState(null);
  const [newGroup, setNewGroup] = useState({ name: '', description: '', color: '#06b6d4' });
  const [newTags, setNewTags] = useState('');

  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    try {
      const [overviewRes, devicesRes, telemetryRes, statsRes, deploymentsRes, groupsRes, tagsRes] = await Promise.all([
        axios.get(`${API}/swarm/overview`, { headers }),
        axios.get(`${API}/swarm/devices`, { headers }),
        axios.get(`${API}/swarm/telemetry?limit=50`, { headers }),
        axios.get(`${API}/swarm/telemetry/stats`, { headers }),
        axios.get(`${API}/swarm/deployment/status`, { headers }),
        axios.get(`${API}/swarm/groups`, { headers }),
        axios.get(`${API}/swarm/tags`, { headers })
      ]);
      
      setOverview(overviewRes.data);
      setDevices(devicesRes.data.devices || []);
      setTelemetry(telemetryRes.data.events || []);
      setTelemetryStats(statsRes.data);
      setDeployments(deploymentsRes.data.tasks || []);
      setGroups(groupsRes.data.groups || []);
      setAllTags(tagsRes.data.tags || []);
    } catch (err) {
      console.error('Failed to fetch swarm data:', err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const triggerNetworkScan = async () => {
    setScanning(true);
    try {
      await axios.post(`${API}/swarm/scan`, {}, { headers });
      toast.success('Network scan initiated');
      setTimeout(fetchData, 5000);
    } catch (err) {
      toast.error('Failed to start network scan');
    } finally {
      setScanning(false);
    }
  };

  const deployToDevice = async (ip) => {
    try {
      await axios.post(`${API}/swarm/deploy`, { device_ip: ip }, { headers });
      toast.success(`Deployment queued for ${ip}`);
      fetchData();
    } catch (err) {
      toast.error('Failed to queue deployment');
    }
  };

  const deployAll = async () => {
    setDeploying(true);
    try {
      const res = await axios.post(`${API}/swarm/deploy/batch`, {}, { headers });
      toast.success(`Batch deployment initiated for ${res.data.devices?.length || 0} devices`);
      fetchData();
    } catch (err) {
      toast.error('Failed to start batch deployment');
    } finally {
      setDeploying(false);
    }
  };

  const getDeviceIcon = (type) => {
    switch (type) {
      case 'workstation': return <Laptop className="w-5 h-5" />;
      case 'server': return <Server className="w-5 h-5" />;
      case 'mobile': return <Smartphone className="w-5 h-5" />;
      case 'network_device': return <Wifi className="w-5 h-5" />;
      default: return <Monitor className="w-5 h-5" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'deployed': return 'text-green-400 bg-green-500/20';
      case 'deploying': return 'text-blue-400 bg-blue-500/20';
      case 'failed': return 'text-red-400 bg-red-500/20';
      case 'queued': return 'text-yellow-400 bg-yellow-500/20';
      default: return 'text-slate-400 bg-slate-500/20';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400';
      case 'high': return 'bg-orange-500/20 text-orange-400';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400';
      case 'low': return 'bg-blue-500/20 text-blue-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  // Group management
  const createGroup = async () => {
    if (!newGroup.name.trim()) {
      toast.error('Group name is required');
      return;
    }
    try {
      await axios.post(`${API}/swarm/groups`, newGroup, { headers });
      toast.success('Group created');
      setShowGroupModal(false);
      setNewGroup({ name: '', description: '', color: '#06b6d4' });
      fetchData();
    } catch (err) {
      toast.error('Failed to create group');
    }
  };

  const assignToGroup = async (deviceIp, groupId) => {
    try {
      await axios.put(`${API}/swarm/devices/${deviceIp}/group?group_id=${groupId}`, {}, { headers });
      toast.success('Device assigned to group');
      fetchData();
    } catch (err) {
      toast.error('Failed to assign device');
    }
  };

  const updateDeviceTags = async (deviceIp) => {
    const tagsArray = newTags.split(',').map(t => t.trim()).filter(t => t);
    try {
      await axios.put(`${API}/swarm/devices/${deviceIp}/tags`, { tags: tagsArray }, { headers });
      toast.success('Tags updated');
      setShowTagModal(null);
      setNewTags('');
      fetchData();
    } catch (err) {
      toast.error('Failed to update tags');
    }
  };

  const deleteGroup = async (groupId) => {
    try {
      await axios.delete(`${API}/swarm/groups/${groupId}`, { headers });
      toast.success('Group deleted');
      setSelectedGroup(null);
      fetchData();
    } catch (err) {
      toast.error('Failed to delete group');
    }
  };

  // Filter devices by search, group, and tag
  const filteredDevices = devices.filter(d => {
    const matchesSearch = !searchQuery || 
      d.ip_address?.includes(searchQuery) || 
      d.hostname?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesGroup = !selectedGroup || d.group_id === selectedGroup;
    const matchesTag = !selectedTag || (d.tags && d.tags.includes(selectedTag));
    return matchesSearch && matchesGroup && matchesTag;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="swarm-dashboard">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Network className="w-8 h-8 text-cyan-400" />
            Swarm Command Center
          </h1>
          <p className="text-slate-400 mt-1">Network discovery, agent deployment, and real-time telemetry</p>
        </div>
        <div className="flex gap-3">
          <Button 
            onClick={triggerNetworkScan}
            disabled={scanning}
            className="bg-cyan-600 hover:bg-cyan-500"
            data-testid="scan-network-btn"
          >
            {scanning ? (
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Search className="w-4 h-4 mr-2" />
            )}
            Scan Network
          </Button>
          <Button 
            onClick={deployAll}
            disabled={deploying}
            className="bg-purple-600 hover:bg-purple-500"
            data-testid="deploy-all-btn"
          >
            {deploying ? (
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Download className="w-4 h-4 mr-2" />
            )}
            Deploy All
          </Button>
        </div>
      </div>

      {/* Overview Stats */}
      {overview && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="seraph-stat-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <Globe className="w-8 h-8 text-cyan-400" />
              <Badge className="bg-cyan-500/20 text-cyan-400">{overview.devices?.managed || 0} managed</Badge>
            </div>
            <div className="text-3xl font-bold text-white">{overview.devices?.total || 0}</div>
            <div className="text-slate-400 text-sm">Discovered Devices</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="seraph-stat-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <Shield className="w-8 h-8 text-green-400" />
              <Badge className="bg-green-500/20 text-green-400">{overview.agents?.online || 0} online</Badge>
            </div>
            <div className="text-3xl font-bold text-white">{overview.agents?.total || 0}</div>
            <div className="text-slate-400 text-sm">Active Agents</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="seraph-stat-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <Activity className="w-8 h-8 text-purple-400" />
              <Badge className="bg-red-500/20 text-red-400">{overview.telemetry?.critical || 0} critical</Badge>
            </div>
            <div className="text-3xl font-bold text-white">{overview.telemetry?.total_events || 0}</div>
            <div className="text-slate-400 text-sm">Telemetry Events</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="seraph-stat-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <Zap className="w-8 h-8 text-yellow-400" />
              <Badge className="bg-yellow-500/20 text-yellow-400">
                {overview.deployments?.success_rate?.toFixed(0) || 0}% success
              </Badge>
            </div>
            <div className="text-3xl font-bold text-white">{overview.deployments?.total || 0}</div>
            <div className="text-slate-400 text-sm">Deployments</div>
          </motion.div>
        </div>
      )}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-slate-800/50">
          <TabsTrigger value="setup" className="data-[state=active]:bg-yellow-500/20">
            <Terminal className="w-4 h-4 mr-2" /> Setup Scanner
          </TabsTrigger>
          <TabsTrigger value="overview" className="data-[state=active]:bg-cyan-500/20">
            <Globe className="w-4 h-4 mr-2" /> Devices
          </TabsTrigger>
          <TabsTrigger value="telemetry" className="data-[state=active]:bg-purple-500/20">
            <Activity className="w-4 h-4 mr-2" /> Telemetry
          </TabsTrigger>
          <TabsTrigger value="deployments" className="data-[state=active]:bg-green-500/20">
            <Download className="w-4 h-4 mr-2" /> Deployments
          </TabsTrigger>
        </TabsList>

        {/* Setup Tab - CRITICAL FOR REAL NETWORK SCANNING */}
        <TabsContent value="setup" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Scanner Setup */}
            <Card className="bg-gradient-to-br from-yellow-900/30 to-slate-900 border-yellow-500/50">
              <CardHeader>
                <CardTitle className="text-yellow-400 flex items-center gap-2">
                  <Search className="w-5 h-5" />
                  Network Scanner Setup
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 bg-slate-800/70 rounded-lg border border-slate-700">
                  <p className="text-slate-300 mb-4">
                    <strong className="text-yellow-400">Important:</strong> To discover devices on YOUR network, 
                    you must run the Network Scanner on a machine inside your LAN.
                  </p>
                  
                  <div className="space-y-3">
                    <h4 className="text-white font-medium">Step 1: Download Scanner</h4>
                    <Button
                      onClick={() => window.open(`${API}/swarm/agent/download/scanner`, '_blank')}
                      className="w-full bg-yellow-600 hover:bg-yellow-500"
                      data-testid="download-scanner-btn"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Download seraph_network_scanner.py
                    </Button>
                  </div>
                  
                  <div className="mt-4 space-y-2">
                    <h4 className="text-white font-medium">Step 2: Install Dependencies</h4>
                    <div className="space-y-2">
                      <div className="p-2 bg-slate-900 rounded">
                        <span className="text-yellow-400 text-xs font-bold">WINDOWS:</span>
                        <code className="block text-cyan-400 text-sm mt-1">pip install python-nmap paramiko requests</code>
                        <p className="text-slate-500 text-xs mt-1">Download nmap from <a href="https://nmap.org/download.html" target="_blank" rel="noopener noreferrer" className="text-cyan-400 underline">nmap.org/download.html</a></p>
                      </div>
                      <div className="p-2 bg-slate-900 rounded">
                        <span className="text-green-400 text-xs font-bold">LINUX:</span>
                        <code className="block text-cyan-400 text-sm mt-1">sudo apt install nmap && pip install python-nmap paramiko requests</code>
                      </div>
                      <div className="p-2 bg-slate-900 rounded">
                        <span className="text-blue-400 text-xs font-bold">macOS:</span>
                        <code className="block text-cyan-400 text-sm mt-1">brew install nmap && pip install python-nmap paramiko requests</code>
                      </div>
                    </div>
                  </div>
                  
                  <div className="mt-4 space-y-2">
                    <h4 className="text-white font-medium">Step 3: Run Scanner</h4>
                    <div className="space-y-2">
                      <div className="p-2 bg-slate-900 rounded">
                        <span className="text-yellow-400 text-xs font-bold">WINDOWS (PowerShell):</span>
                        <code className="block text-cyan-400 text-sm mt-1 whitespace-pre-wrap">{`python seraph_network_scanner.py --api-url "${window.location.origin}" --interval 60`}</code>
                      </div>
                      <div className="p-2 bg-slate-900 rounded">
                        <span className="text-green-400 text-xs font-bold">LINUX/macOS:</span>
                        <code className="block text-cyan-400 text-sm mt-1 whitespace-pre-wrap">{`sudo python3 seraph_network_scanner.py --api-url ${window.location.origin} --interval 60`}</code>
                      </div>
                    </div>
                    <p className="text-slate-400 text-sm">Run as Administrator (Windows) or with sudo (Linux/macOS) for best results</p>
                  </div>
                  
                  <div className="mt-4 space-y-2">
                    <h4 className="text-white font-medium">Options:</h4>
                    <ul className="text-slate-400 text-sm space-y-1">
                      <li><code className="text-cyan-400">--network 192.168.1.0/24</code> - Specify network range</li>
                      <li><code className="text-cyan-400">--once</code> - Single scan and exit</li>
                      <li><code className="text-cyan-400">--deploy IP --deploy-user root --deploy-pass xxx</code> - Deploy to device</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Mobile Setup */}
            <Card className="bg-gradient-to-br from-purple-900/30 to-slate-900 border-purple-500/50">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Smartphone className="w-5 h-5" />
                  Mobile Agent Setup
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 bg-slate-800/70 rounded-lg border border-slate-700">
                  <p className="text-slate-300 mb-4">
                    Monitor iOS and Android devices with the Seraph Mobile Agent.
                  </p>
                  
                  <div className="space-y-3">
                    <h4 className="text-white font-medium">Download Mobile Agent</h4>
                    <Button
                      onClick={() => window.open(`${API}/swarm/agent/download/mobile`, '_blank')}
                      className="w-full bg-purple-600 hover:bg-purple-500"
                      data-testid="download-mobile-btn"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Download seraph_mobile_agent.py
                    </Button>
                  </div>
                  
                  <div className="mt-4">
                    <h4 className="text-white font-medium mb-2">For iOS (Pythonista):</h4>
                    <ol className="text-slate-400 text-sm space-y-1 list-decimal list-inside">
                      <li>Install Pythonista from App Store</li>
                      <li>Copy agent script to Pythonista</li>
                      <li>Run with API URL parameter</li>
                    </ol>
                  </div>
                  
                  <div className="mt-4">
                    <h4 className="text-white font-medium mb-2">For Android (Termux):</h4>
                    <ol className="text-slate-400 text-sm space-y-1 list-decimal list-inside">
                      <li>Install Termux from F-Droid</li>
                      <li><code className="text-cyan-400">pkg install python</code></li>
                      <li><code className="text-cyan-400">pip install requests</code></li>
                      <li>Run: <code className="text-cyan-400">{`python seraph_mobile_agent.py --api-url "${window.location.origin}"`}</code></li>
                    </ol>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Desktop Agents */}
            <Card className="bg-gradient-to-br from-cyan-900/30 to-slate-900 border-cyan-500/50">
              <CardHeader>
                <CardTitle className="text-cyan-400 flex items-center gap-2">
                  <Laptop className="w-5 h-5" />
                  Desktop Agent Downloads
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-3">
                  <Button
                    onClick={() => window.open(`${API}/swarm/agent/download/linux`, '_blank')}
                    variant="outline"
                    className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/20"
                  >
                    <Server className="w-4 h-4 mr-2" />
                    Linux
                  </Button>
                  <Button
                    onClick={() => window.open(`${API}/swarm/agent/download/windows`, '_blank')}
                    variant="outline"
                    className="border-blue-500/50 text-blue-400 hover:bg-blue-500/20"
                  >
                    <Monitor className="w-4 h-4 mr-2" />
                    Windows
                  </Button>
                  <Button
                    onClick={() => window.open(`${API}/swarm/agent/download/macos`, '_blank')}
                    variant="outline"
                    className="border-slate-500/50 text-slate-400 hover:bg-slate-500/20"
                  >
                    <Laptop className="w-4 h-4 mr-2" />
                    macOS
                  </Button>
                </div>
                <div className="mt-4 space-y-2">
                  <p className="text-slate-400 text-sm">
                    Desktop agents require Python 3.8+ and will automatically register with the server.
                  </p>
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-yellow-400 text-xs font-bold">WINDOWS (PowerShell):</span>
                    <code className="block text-green-400 text-xs mt-1">{`python seraph_defender.py --api-url "${window.location.origin}" --monitor`}</code>
                  </div>
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-green-400 text-xs font-bold">LINUX/macOS:</span>
                    <code className="block text-green-400 text-xs mt-1">{`python3 seraph_defender.py --api-url ${window.location.origin} --monitor`}</code>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Commands */}
            <Card className="bg-gradient-to-br from-green-900/30 to-slate-900 border-green-500/50">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Terminal className="w-5 h-5" />
                  Quick Deploy Commands
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <h4 className="text-white font-medium text-sm mb-1">Windows (PowerShell as Admin):</h4>
                    <code className="block p-3 bg-slate-900 rounded text-green-400 text-xs overflow-x-auto">
                      {`Invoke-WebRequest -Uri "${window.location.origin}/api/swarm/agent/download/windows" -OutFile seraph_defender.py; python seraph_defender.py --api-url "${window.location.origin}" --monitor`}
                    </code>
                  </div>
                  <div>
                    <h4 className="text-white font-medium text-sm mb-1">Linux/macOS One-liner:</h4>
                    <code className="block p-3 bg-slate-900 rounded text-green-400 text-xs overflow-x-auto">
                      {`curl -sL ${window.location.origin}/api/swarm/agent/download/linux -o seraph_defender.py && python3 seraph_defender.py --api-url ${window.location.origin} --monitor`}
                    </code>
                  </div>
                  <div>
                    <h4 className="text-white font-medium text-sm mb-1">Deploy via SSH (from scanner):</h4>
                    <code className="block p-3 bg-slate-900 rounded text-green-400 text-xs overflow-x-auto">
                      {`python seraph_network_scanner.py --deploy 192.168.1.100 --deploy-user root --deploy-pass YOUR_PASSWORD --api-url "${window.location.origin}"`}
                    </code>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Devices Tab */}
        <TabsContent value="overview" className="mt-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-white flex items-center gap-2">
                  <Network className="w-5 h-5 text-cyan-400" />
                  Discovered Devices ({filteredDevices.length})
                </CardTitle>
                <Input
                  placeholder="Search devices..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-64 bg-slate-800 border-slate-700"
                />
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <AnimatePresence>
                  {filteredDevices.map((device, idx) => (
                    <motion.div
                      key={device.ip_address}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                      transition={{ delay: idx * 0.05 }}
                      className="p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-cyan-500/50 transition-all"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className={`p-2 rounded-lg ${device.is_managed ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
                            {getDeviceIcon(device.device_type)}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-white font-medium">{device.ip_address}</span>
                              {device.hostname && (
                                <span className="text-slate-400 text-sm">({device.hostname})</span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge variant="outline" className="text-xs">
                                {device.os_type || 'Unknown OS'}
                              </Badge>
                              <Badge variant="outline" className="text-xs">
                                {device.device_type || 'Unknown'}
                              </Badge>
                              {device.vendor && (
                                <Badge variant="outline" className="text-xs text-slate-400">
                                  {device.vendor}
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          {/* Risk Score */}
                          <div className="text-right">
                            <div className={`text-sm font-medium ${
                              device.risk_score >= 50 ? 'text-red-400' : 
                              device.risk_score >= 25 ? 'text-yellow-400' : 'text-green-400'
                            }`}>
                              Risk: {device.risk_score || 0}%
                            </div>
                            <div className="text-xs text-slate-500">
                              {device.open_ports?.length || 0} open ports
                            </div>
                          </div>

                          {/* Status */}
                          <Badge className={getStatusColor(device.deployment_status)}>
                            {device.deployment_status || 'discovered'}
                          </Badge>

                          {/* Actions */}
                          {!device.is_managed && device.os_type && ['windows', 'linux', 'macos'].includes(device.os_type) && (
                            <Button
                              size="sm"
                              onClick={() => deployToDevice(device.ip_address)}
                              className="bg-purple-600 hover:bg-purple-500"
                            >
                              <Download className="w-4 h-4" />
                            </Button>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>

                {filteredDevices.length === 0 && (
                  <div className="text-center py-12 text-slate-400">
                    <Network className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No devices found. Click "Scan Network" to discover devices.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Telemetry Tab */}
        <TabsContent value="telemetry" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            {/* Telemetry Stats */}
            {telemetryStats && (
              <>
                <Card className="bg-slate-900/50 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-slate-400">Events by Type</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {Object.entries(telemetryStats.by_type || {}).slice(0, 6).map(([type, count]) => (
                        <div key={type} className="flex justify-between items-center">
                          <span className="text-slate-300 text-sm">{type.replace('.', ' ')}</span>
                          <Badge variant="outline">{count}</Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900/50 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-slate-400">Events by Severity</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {Object.entries(telemetryStats.by_severity || {}).map(([sev, count]) => (
                        <div key={sev} className="flex justify-between items-center">
                          <Badge className={getSeverityColor(sev)}>{sev}</Badge>
                          <span className="text-white font-medium">{count}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900/50 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-slate-400">Top Hosts</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {Object.entries(telemetryStats.by_host || {}).slice(0, 5).map(([host, count]) => (
                        <div key={host} className="flex justify-between items-center">
                          <span className="text-slate-300 text-sm truncate max-w-[150px]">{host}</span>
                          <Badge variant="outline">{count}</Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </div>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-purple-400" />
                Live Telemetry Feed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {telemetry.map((event, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="p-3 bg-slate-800/50 rounded border border-slate-700"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <Badge className={getSeverityColor(event.severity)}>
                          {event.severity}
                        </Badge>
                        <div>
                          <span className="text-cyan-400 font-mono text-sm">
                            {event.event_type}
                          </span>
                          <span className="text-slate-500 text-sm ml-2">
                            from {event.host_id}
                          </span>
                        </div>
                      </div>
                      <span className="text-slate-500 text-xs">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    {event.data?.message && (
                      <p className="text-slate-300 text-sm mt-2 pl-20">
                        {event.data.message}
                      </p>
                    )}
                  </motion.div>
                ))}

                {telemetry.length === 0 && (
                  <div className="text-center py-8 text-slate-400">
                    <Radio className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No telemetry events yet. Deploy agents to start receiving data.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Deployments Tab */}
        <TabsContent value="deployments" className="mt-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Download className="w-5 h-5 text-green-400" />
                Deployment Tasks ({deployments.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {deployments.map((task, idx) => (
                  <div
                    key={idx}
                    className="p-4 bg-slate-800/50 rounded-lg border border-slate-700"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-white font-medium">{task.device_ip}</span>
                        {task.device_hostname && (
                          <span className="text-slate-400 text-sm ml-2">({task.device_hostname})</span>
                        )}
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline" className="text-xs">{task.os_type}</Badge>
                          <Badge variant="outline" className="text-xs">{task.method}</Badge>
                          <span className="text-slate-500 text-xs">
                            Attempts: {task.attempts}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge className={getStatusColor(task.status)}>
                          {task.status === 'deployed' && <CheckCircle className="w-3 h-3 mr-1" />}
                          {task.status === 'failed' && <XCircle className="w-3 h-3 mr-1" />}
                          {task.status === 'deploying' && <RefreshCw className="w-3 h-3 mr-1 animate-spin" />}
                          {task.status}
                        </Badge>
                      </div>
                    </div>
                    {task.error_message && (
                      <div className="mt-2 p-2 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-sm">
                        {task.error_message}
                      </div>
                    )}
                  </div>
                ))}

                {deployments.length === 0 && (
                  <div className="text-center py-8 text-slate-400">
                    <Download className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No deployment tasks yet.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SwarmDashboard;
