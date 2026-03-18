import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Monitor, 
  Cpu,
  HardDrive,
  Wifi,
  Clock,
  RefreshCw,
  Download,
  CheckCircle,
  XCircle,
  Activity,
  Server,
  Globe,
  AlertTriangle,
  ChevronDown,
  Terminal,
  Shield
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Progress } from '../components/ui/progress';
import { toast } from 'sonner';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AgentCard = ({ agent }) => {
  const isOnline = agent.status === 'online';
  const systemInfo = agent.system_info || {};
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`bg-slate-900/50 backdrop-blur-md border rounded overflow-hidden ${
        isOnline ? 'border-green-500/30' : 'border-slate-700'
      }`}
    >
      <div className={`p-4 ${isOnline ? 'bg-green-500/10' : 'bg-slate-800/30'} border-b border-slate-800`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className={`w-10 h-10 rounded flex items-center justify-center ${
              isOnline ? 'bg-green-500/20' : 'bg-slate-700'
            }`}>
              <Monitor className={`w-5 h-5 ${isOnline ? 'text-green-400' : 'text-slate-500'}`} />
            </div>
            <div>
              <h3 className="font-medium text-white">{agent.name}</h3>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className={`text-xs ${
                  isOnline ? 'text-green-400 border-green-500/50' : 'text-slate-500 border-slate-600'
                }`}>
                  {isOnline ? (
                    <><CheckCircle className="w-3 h-3 mr-1" /> Online</>
                  ) : (
                    <><XCircle className="w-3 h-3 mr-1" /> Offline</>
                  )}
                </Badge>
                {agent.os && (
                  <Badge variant="outline" className="text-xs text-slate-400 border-slate-600">
                    {agent.os}
                  </Badge>
                )}
              </div>
            </div>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-500">Agent ID</p>
            <p className="text-xs font-mono text-slate-400">{agent.id.slice(0, 8)}...</p>
          </div>
        </div>
      </div>

      {isOnline && systemInfo && (
        <div className="p-4 space-y-4">
          {/* System Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <Cpu className="w-3 h-3" /> CPU
                </span>
                <span className="text-xs text-cyan-400">{systemInfo.cpu_percent || 0}%</span>
              </div>
              <Progress value={systemInfo.cpu_percent || 0} className="h-1.5" />
            </div>
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <HardDrive className="w-3 h-3" /> Memory
                </span>
                <span className="text-xs text-cyan-400">{systemInfo.memory_percent || 0}%</span>
              </div>
              <Progress value={systemInfo.memory_percent || 0} className="h-1.5" />
            </div>
          </div>

          {/* Network Interfaces */}
          {systemInfo.network_interfaces && systemInfo.network_interfaces.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-2">Network Interfaces</p>
              <div className="space-y-1">
                {systemInfo.network_interfaces.slice(0, 3).map((iface, i) => (
                  <div key={i} className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">{iface.name}</span>
                    <span className="font-mono text-white">{iface.ip}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Last Heartbeat */}
          <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800">
            <span className="text-slate-500 flex items-center gap-1">
              <Clock className="w-3 h-3" /> Last Heartbeat
            </span>
            <span className="text-slate-400">
              {new Date(agent.last_heartbeat).toLocaleString()}
            </span>
          </div>
        </div>
      )}
    </motion.div>
  );
};

const DiscoveredHostCard = ({ host }) => (
  <div className="p-3 bg-slate-800/30 border border-slate-700 rounded">
    <div className="flex items-center justify-between mb-2">
      <div className="flex items-center gap-2">
        <Server className="w-4 h-4 text-cyan-400" />
        <span className="font-mono text-white">{host.ip}</span>
      </div>
      <Badge variant="outline" className="text-xs text-slate-400 border-slate-600">
        {host.vendor || 'Unknown'}
      </Badge>
    </div>
    <div className="text-xs text-slate-500">
      <p>Hostname: {host.hostname || 'N/A'}</p>
      <p>MAC: {host.mac || 'N/A'}</p>
      <p>Last seen: {new Date(host.last_seen).toLocaleString()}</p>
    </div>
  </div>
);

const AgentsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [agents, setAgents] = useState([]);
  const [discoveredHosts, setDiscoveredHosts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [agentsRes, hostsRes] = await Promise.all([
        axios.get(`${API}/agents`, { headers: getAuthHeaders() }),
        axios.get(`${API}/network/discovered-hosts`, { headers: getAuthHeaders() })
      ]);
      setAgents(agentsRes.data);
      setDiscoveredHosts(hostsRes.data);
    } catch (error) {
      console.error('Failed to fetch agent data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const downloadAgent = () => {
    window.open(`${API}/agent/download/installer`, '_blank');
    toast.success('Downloading Defender Security Suite installer...', {
      description: 'Run with: python defender_installer.py'
    });
  };

  const downloadAdvancedAgent = () => {
    window.open(`${API}/agent/download/advanced-agent`, '_blank');
    toast.success('Downloading Advanced Security Agent...', {
      description: 'Run with: python advanced_agent.py --connect --api-url <your-server>'
    });
  };

  const stats = {
    total: agents.length,
    online: agents.filter(a => a.status === 'online').length,
    offline: agents.filter(a => a.status !== 'online').length,
    hosts: discoveredHosts.length
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="agents-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
            <Monitor className="w-7 h-7 text-cyan-400" />
            Security Agents
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Monitor local agents and discovered network hosts
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            className="border-slate-700 text-slate-300"
            onClick={fetchData}
            data-testid="refresh-agents-btn"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                className="bg-cyan-600 hover:bg-cyan-500"
                onClick={() => toast.info('Select an agent package from the dropdown')}
                data-testid="download-agent-btn"
              >
                <Download className="w-4 h-4 mr-2" />
                Download Agent
                <ChevronDown className="w-4 h-4 ml-2" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-slate-900 border-slate-700">
              <DropdownMenuItem 
                onClick={downloadAdvancedAgent}
                className="text-white hover:bg-slate-800 cursor-pointer"
              >
                <Terminal className="w-4 h-4 mr-2 text-cyan-400" />
                <div>
                  <p className="font-medium">Advanced Agent (Recommended)</p>
                  <p className="text-xs text-slate-400">Real-time commands, WebSocket support</p>
                </div>
              </DropdownMenuItem>
              <DropdownMenuItem 
                onClick={downloadAgent}
                className="text-white hover:bg-slate-800 cursor-pointer"
              >
                <Shield className="w-4 h-4 mr-2 text-green-400" />
                <div>
                  <p className="font-medium">Defender Installer</p>
                  <p className="text-xs text-slate-400">Full security suite with GUI</p>
                </div>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Agents', value: stats.total, color: 'cyan', icon: Monitor },
          { label: 'Online', value: stats.online, color: 'green', icon: CheckCircle },
          { label: 'Offline', value: stats.offline, color: 'slate', icon: XCircle },
          { label: 'Discovered Hosts', value: stats.hosts, color: 'blue', icon: Globe }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4"
          >
            <div className="flex items-center gap-2 mb-1">
              <stat.icon className={`w-4 h-4 text-${stat.color}-400`} />
              <p className="text-slate-400 text-sm">{stat.label}</p>
            </div>
            <p className={`text-2xl font-mono font-bold text-${stat.color}-400`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Setup Instructions */}
      {agents.length === 0 && !loading && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-amber-500/10 border border-amber-500/30 rounded p-6"
        >
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-semibold text-white mb-2">No Agents Connected</h3>
              <p className="text-slate-400 text-sm mb-4">
                To protect your network, download and run one of the agent options:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                {/* Advanced Agent Option */}
                <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded">
                  <h4 className="text-cyan-400 font-semibold mb-2 flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Advanced Agent (Recommended)
                  </h4>
                  <p className="text-slate-400 text-xs mb-3">Real-time WebSocket commands, all scan types</p>
                  <ol className="list-decimal list-inside space-y-1 text-xs text-slate-300">
                    <li>Download: <code className="bg-slate-800 px-1 rounded">advanced_agent.py</code></li>
                    <li>Install: <code className="bg-slate-800 px-1 rounded">pip install psutil requests websocket-client</code></li>
                    <li>Connect: <code className="bg-slate-800 px-1 rounded text-[10px]">python advanced_agent.py --connect --api-url {window.location.origin}</code></li>
                  </ol>
                </div>
                
                {/* Defender Suite Option */}
                <div className="p-4 bg-green-500/10 border border-green-500/30 rounded">
                  <h4 className="text-green-400 font-semibold mb-2 flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Defender Security Suite
                  </h4>
                  <p className="text-slate-400 text-xs mb-3">Full suite with GUI and auto-install</p>
                  <ol className="list-decimal list-inside space-y-1 text-xs text-slate-300">
                    <li>Download: <code className="bg-slate-800 px-1 rounded">defender_installer.py</code></li>
                    <li>Run: <code className="bg-slate-800 px-1 rounded">python defender_installer.py</code></li>
                    <li>Start: <code className="bg-slate-800 px-1 rounded">~/.anti-ai-defense/start_defender.sh</code></li>
                  </ol>
                </div>
              </div>
              
              <div className="p-3 bg-slate-800/50 rounded border border-slate-700">
                <p className="text-xs text-slate-400 font-semibold mb-2">Agent Capabilities:</p>
                <div className="flex flex-wrap gap-2">
                  <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs">Process Monitor</span>
                  <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">Browser Scan</span>
                  <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">Credential Theft Detection</span>
                  <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">Persistence Scan</span>
                  <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 rounded text-xs">USB Monitor</span>
                  <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">WebSocket Commands</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connected Agents */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded"
        >
          <div className="p-4 border-b border-slate-800">
            <h3 className="font-mono font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-green-400" />
              Connected Agents
            </h3>
          </div>
          <ScrollArea className="h-96">
            <div className="p-4 space-y-4">
              {loading ? (
                <div className="text-center py-8 text-slate-400">
                  <div className="w-8 h-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mx-auto mb-4" />
                  Loading agents...
                </div>
              ) : agents.length > 0 ? (
                agents.map((agent) => (
                  <AgentCard key={agent.id} agent={agent} />
                ))
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <Monitor className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No agents connected</p>
                  <p className="text-xs mt-1">Download and run the agent on your local machine</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </motion.div>

        {/* Discovered Hosts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded"
        >
          <div className="p-4 border-b border-slate-800">
            <h3 className="font-mono font-semibold text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-400" />
              Discovered Network Hosts
            </h3>
          </div>
          <ScrollArea className="h-96">
            <div className="p-4 space-y-3">
              {discoveredHosts.length > 0 ? (
                discoveredHosts.map((host, i) => (
                  <DiscoveredHostCard key={host.ip || i} host={host} />
                ))
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <Wifi className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No hosts discovered yet</p>
                  <p className="text-xs mt-1">Network scans will populate this list</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </motion.div>
      </div>
    </div>
  );
};

export default AgentsPage;
