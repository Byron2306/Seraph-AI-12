import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import ForceGraph2D from 'react-force-graph-2d';
import { 
  Network, 
  RefreshCw, 
  Shield, 
  AlertTriangle, 
  Server,
  Wifi,
  Cloud,
  Monitor,
  Lock,
  Zap,
  Activity,
  AlertOctagon,
  Ban
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const NetworkTopologyPage = () => {
  const { getAuthHeaders } = useAuth();
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [liveThreats, setLiveThreats] = useState([]);
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [threatNodes, setThreatNodes] = useState(new Map());
  const graphRef = useRef();

  const fetchTopology = useCallback(async () => {
    try {
      setLoading(true);
      const [topoRes, threatsRes, alertsRes] = await Promise.all([
        axios.get(`${API}/network/topology`, { headers: getAuthHeaders() }),
        axios.get(`${API}/swarm/telemetry?severity=critical&limit=30`, { headers: getAuthHeaders() }),
        axios.get(`${API}/swarm/alerts/critical?limit=20`, { headers: getAuthHeaders() })
      ]);
      
      // Get threats and map them to nodes
      const threats = threatsRes.data.events || [];
      setLiveThreats(threats);
      
      const alerts = alertsRes.data.alerts || [];
      setCriticalAlerts(alerts);
      
      // Map threats to node IPs
      const threatMap = new Map();
      threats.forEach(t => {
        const ip = t.data?.remote_ip || t.data?.ip || t.host_id;
        if (ip) {
          if (!threatMap.has(ip)) {
            threatMap.set(ip, []);
          }
          threatMap.get(ip).push(t);
        }
      });
      setThreatNodes(threatMap);
      
      // Transform data for force graph with threat overlay
      const nodes = topoRes.data.nodes.map(node => {
        const hasThreats = threatMap.has(node.ip);
        const threatCount = hasThreats ? threatMap.get(node.ip).length : 0;
        
        return {
          ...node,
          val: node.type === 'attacker' ? 15 : hasThreats ? 14 : node.type === 'firewall' ? 12 : 10,
          color: hasThreats ? '#EF4444' : getNodeColor(node.status, node.type),
          hasThreats,
          threatCount,
          pulsing: hasThreats
        };
      });
      
      // Add dynamic threat nodes from telemetry
      const existingIps = new Set(nodes.map(n => n.ip));
      threatMap.forEach((threats, ip) => {
        if (!existingIps.has(ip) && ip && !ip.startsWith('127.')) {
          nodes.push({
            id: `threat-${ip}`,
            label: `Threat: ${ip}`,
            ip: ip,
            type: 'attacker',
            status: 'compromised',
            val: 15,
            color: '#EF4444',
            hasThreats: true,
            threatCount: threats.length,
            pulsing: true
          });
        }
      });
      
      const links = topoRes.data.links.map(link => ({
        source: link.source,
        target: link.target,
        type: link.type,
        color: link.type === 'attack' ? '#EF4444' : link.type === 'data_flow' ? '#3B82F6' : '#475569',
        width: link.type === 'attack' ? 3 : 1,
        curvature: link.type === 'attack' ? 0.3 : 0
      }));
      
      setGraphData({ nodes, links });
    } catch (error) {
      toast.error('Failed to load network topology');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  useEffect(() => {
    fetchTopology();
    // Auto-refresh for live threats
    const interval = setInterval(fetchTopology, 10000);
    return () => clearInterval(interval);
  }, [fetchTopology]);

  const getNodeColor = (status, type) => {
    if (type === 'attacker') return '#EF4444';
    switch (status) {
      case 'compromised': return '#EF4444';
      case 'suspicious': return '#F59E0B';
      case 'protected': return '#10B981';
      default: return '#3B82F6';
    }
  };

  const getNodeIcon = (type) => {
    switch (type) {
      case 'firewall': return '🛡️';
      case 'router': return '📡';
      case 'server': return '🖥️';
      case 'workstation': return '💻';
      case 'cloud': return '☁️';
      case 'attacker': return '⚠️';
      default: return '●';
    }
  };

  const handleNodeClick = useCallback((node) => {
    setSelectedNode(node);
    if (graphRef.current) {
      graphRef.current.centerAt(node.x, node.y, 1000);
      graphRef.current.zoom(2, 1000);
    }
  }, []);

  const nodeStats = {
    total: graphData.nodes.length,
    compromised: graphData.nodes.filter(n => n.status === 'compromised').length,
    suspicious: graphData.nodes.filter(n => n.status === 'suspicious').length,
    attackers: graphData.nodes.filter(n => n.type === 'attacker').length,
    liveThreats: liveThreats.length,
    criticalAlerts: criticalAlerts.filter(a => !a.acknowledged).length
  };

  return (
    <div className="p-6 lg:p-8 h-screen flex flex-col" data-testid="network-topology-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
            <Network className="w-7 h-7 text-cyan-400" />
            Network Topology
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Real-time network visualization with threat mapping
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            className="border-slate-700 text-slate-300 hover:bg-slate-800"
            onClick={fetchTopology}
            data-testid="refresh-topology-btn"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
        {[
          { label: 'Total Nodes', value: nodeStats.total, color: 'blue', icon: Server },
          { label: 'Live Threats', value: nodeStats.liveThreats, color: 'red', icon: AlertOctagon },
          { label: 'Critical Alerts', value: nodeStats.criticalAlerts, color: 'amber', icon: Zap },
          { label: 'Attackers', value: nodeStats.attackers, color: 'red', icon: AlertTriangle },
          { label: 'Compromised', value: nodeStats.compromised, color: 'red', icon: Shield },
          { label: 'Suspicious', value: nodeStats.suspicious, color: 'amber', icon: Wifi }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className={`bg-slate-900/50 backdrop-blur-md border rounded p-4 ${
              stat.label === 'Live Threats' && stat.value > 0 
                ? 'border-red-500/50 animate-pulse' 
                : 'border-slate-800'
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <stat.icon className={`w-4 h-4 text-${stat.color}-400`} />
              <p className="text-slate-400 text-sm">{stat.label}</p>
            </div>
            <p className={`text-2xl font-mono font-bold text-${stat.color}-400`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Main Content */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-6 min-h-0">
        {/* Graph */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="lg:col-span-3 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded overflow-hidden"
        >
          {loading ? (
            <div className="h-full flex items-center justify-center">
              <div className="text-blue-500 font-mono animate-pulse">Loading topology...</div>
            </div>
          ) : (
            <ForceGraph2D
              ref={graphRef}
              graphData={graphData}
              nodeLabel={node => `${node.label}\n${node.ip || ''}`}
              nodeColor={node => node.color}
              nodeVal={node => node.val}
              linkColor={link => link.color}
              linkWidth={link => link.width}
              linkCurvature={link => link.curvature}
              linkDirectionalArrowLength={link => link.type === 'attack' ? 6 : 0}
              linkDirectionalArrowRelPos={1}
              onNodeClick={handleNodeClick}
              backgroundColor="#020617"
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.label;
                const fontSize = 12/globalScale;
                ctx.font = `${fontSize}px JetBrains Mono`;
                
                // Draw node circle
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI);
                ctx.fillStyle = node.color;
                ctx.fill();
                
                // Add glow for attackers
                if (node.type === 'attacker' || node.status === 'compromised') {
                  ctx.shadowColor = node.color;
                  ctx.shadowBlur = 15;
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI);
                  ctx.fill();
                  ctx.shadowBlur = 0;
                }
                
                // Draw label
                ctx.fillStyle = '#F8FAFC';
                ctx.textAlign = 'center';
                ctx.fillText(label, node.x, node.y + node.val + fontSize + 2);
              }}
              cooldownTicks={100}
              d3VelocityDecay={0.3}
            />
          )}
        </motion.div>

        {/* Side Panel */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-4 overflow-y-auto max-h-full"
        >
          {/* Live Threats Panel */}
          {liveThreats.length > 0 && (
            <div className="bg-red-900/20 backdrop-blur-md border border-red-500/50 rounded p-4">
              <h3 className="font-mono font-semibold text-red-400 mb-3 flex items-center gap-2">
                <AlertOctagon className="w-4 h-4 animate-pulse" />
                Live Threats
              </h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {liveThreats.slice(0, 5).map((threat, idx) => (
                  <div key={idx} className="p-2 bg-red-950/50 rounded text-sm">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-red-300 font-medium truncate">{threat.event_type}</span>
                      <Badge className="bg-red-500/30 text-red-300 text-xs">{threat.severity}</Badge>
                    </div>
                    <p className="text-red-400/70 text-xs truncate">
                      {threat.data?.message || threat.host_id || 'Unknown source'}
                    </p>
                    {(threat.data?.remote_ip || threat.data?.ip) && (
                      <p className="text-red-400 text-xs font-mono mt-1">
                        IP: {threat.data.remote_ip || threat.data.ip}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Critical Alerts Panel */}
          {criticalAlerts.filter(a => !a.acknowledged).length > 0 && (
            <div className="bg-amber-900/20 backdrop-blur-md border border-amber-500/50 rounded p-4">
              <h3 className="font-mono font-semibold text-amber-400 mb-3 flex items-center gap-2">
                <Zap className="w-4 h-4" />
                Auto-Kill Alerts
              </h3>
              <div className="space-y-2 max-h-32 overflow-y-auto">
                {criticalAlerts.filter(a => !a.acknowledged).slice(0, 3).map((alert, idx) => (
                  <div key={idx} className="p-2 bg-amber-950/50 rounded text-sm">
                    <div className="flex items-center gap-2">
                      <Ban className="w-3 h-3 text-amber-400" />
                      <span className="text-amber-300 truncate">{alert.threat_title}</span>
                    </div>
                    <p className="text-amber-400/70 text-xs mt-1">{alert.alert_type}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Legend */}
          <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4">
            <h3 className="font-mono font-semibold text-white mb-3">Legend</h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-slate-400">Attacker / Compromised</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-amber-500" />
                <span className="text-slate-400">Suspicious</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-slate-400">Protected</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-slate-400">Normal</span>
              </div>
              <div className="flex items-center gap-2 mt-3 pt-3 border-t border-slate-700">
                <div className="w-6 h-0.5 bg-red-500" />
                <span className="text-slate-400">Attack Vector</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-6 h-0.5 bg-blue-500" />
                <span className="text-slate-400">Data Flow</span>
              </div>
            </div>
          </div>

          {/* Selected Node Info */}
          {selectedNode && (
            <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4">
              <h3 className="font-mono font-semibold text-white mb-3">Node Details</h3>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-slate-500">Name</p>
                  <p className="text-white font-medium">{selectedNode.label}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Type</p>
                  <Badge variant="outline" className="text-slate-300 border-slate-600 capitalize">
                    {selectedNode.type}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-slate-500">IP Address</p>
                  <p className="text-white font-mono">{selectedNode.ip || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Status</p>
                  <Badge 
                    variant="outline" 
                    className={`capitalize ${
                      selectedNode.status === 'compromised' ? 'text-red-400 border-red-500/50' :
                      selectedNode.status === 'suspicious' ? 'text-amber-400 border-amber-500/50' :
                      selectedNode.status === 'protected' ? 'text-green-400 border-green-500/50' :
                      'text-blue-400 border-blue-500/50'
                    }`}
                  >
                    {selectedNode.status}
                  </Badge>
                </div>
                {selectedNode.threat_count > 0 && (
                  <div>
                    <p className="text-xs text-slate-500">Active Threats</p>
                    <p className="text-red-400 font-mono">{selectedNode.threat_count}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Node Types */}
          <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4">
            <h3 className="font-mono font-semibold text-white mb-3">Node Types</h3>
            <div className="space-y-2 text-sm">
              {[
                { icon: Lock, label: 'Firewall', count: graphData.nodes.filter(n => n.type === 'firewall').length },
                { icon: Wifi, label: 'Router', count: graphData.nodes.filter(n => n.type === 'router').length },
                { icon: Server, label: 'Server', count: graphData.nodes.filter(n => n.type === 'server').length },
                { icon: Monitor, label: 'Workstation', count: graphData.nodes.filter(n => n.type === 'workstation').length },
                { icon: Cloud, label: 'Cloud', count: graphData.nodes.filter(n => n.type === 'cloud').length },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-400">
                    <item.icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </div>
                  <span className="text-white font-mono">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default NetworkTopologyPage;
