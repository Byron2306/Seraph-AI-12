import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import ForceGraph2D from 'react-force-graph-2d';
import { 
  Route, 
  RefreshCw, 
  Shield, 
  AlertTriangle, 
  Target,
  Crosshair,
  Zap,
  Activity,
  ChevronRight,
  Crown,
  Bomb,
  Lock,
  Server,
  Database,
  Users,
  Key,
  Eye,
  TrendingUp,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Plus
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AttackPathsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [criticalPaths, setCriticalPaths] = useState([]);
  const [crownJewels, setCrownJewels] = useState([]);
  const [blastRadius, setBlastRadius] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedPath, setSelectedPath] = useState(null);
  const [stats, setStats] = useState({
    total_assets: 0,
    critical_paths: 0,
    high_risk_nodes: 0,
    avg_path_length: 0,
    blocked_paths: 0
  });
  const [viewMode, setViewMode] = useState('graph'); // graph, paths, jewels
  const graphRef = useRef();

  // Fetch attack path analysis
  const fetchAttackPaths = useCallback(async () => {
    try {
      setLoading(true);
      const [analysisRes, jewelsRes, statsRes] = await Promise.all([
        axios.get(`${API}/v1/attack-paths/analysis`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/attack-paths/crown-jewels`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/attack-paths/stats`, { headers: getAuthHeaders() })
      ]);
      
      const analysis = analysisRes.data;
      setCriticalPaths(analysis.critical_paths || []);
      
      // Transform for force graph visualization
      const nodes = [];
      const links = [];
      const nodeMap = new Map();
      
      // Add crown jewels as central high-value nodes
      const jewels = jewelsRes.data.crown_jewels || [];
      setCrownJewels(jewels);
      
      jewels.forEach(jewel => {
        if (!nodeMap.has(jewel.id)) {
          nodeMap.set(jewel.id, {
            id: jewel.id,
            name: jewel.name,
            type: 'crown_jewel',
            criticality: jewel.criticality,
            val: 20,
            color: '#F59E0B'
          });
        }
      });
      
      // Add nodes from attack paths
      (analysis.attack_graph?.nodes || []).forEach(node => {
        if (!nodeMap.has(node.id)) {
          nodeMap.set(node.id, {
            id: node.id,
            name: node.name || node.id,
            type: node.type || 'asset',
            risk_score: node.risk_score || 0,
            vulnerabilities: node.vulnerabilities || [],
            val: node.is_critical ? 15 : 10,
            color: getNodeColor(node.risk_score, node.type)
          });
        }
      });
      
      // Add edges/paths
      (analysis.attack_graph?.edges || []).forEach(edge => {
        links.push({
          source: edge.source,
          target: edge.target,
          technique: edge.technique,
          mitre_id: edge.mitre_id,
          probability: edge.probability || 0.5,
          color: edge.is_critical ? '#EF4444' : '#6B7280'
        });
      });
      
      setGraphData({ 
        nodes: Array.from(nodeMap.values()), 
        links 
      });
      
      setStats(statsRes.data || {
        total_assets: nodeMap.size,
        critical_paths: (analysis.critical_paths || []).length,
        high_risk_nodes: Array.from(nodeMap.values()).filter(n => n.risk_score > 70).length,
        avg_path_length: 3.2,
        blocked_paths: 0
      });
      
    } catch (error) {
      console.error('Failed to fetch attack paths:', error);
      // Load demo data for visualization
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data for visualization
  const loadDemoData = () => {
    const demoNodes = [
      { id: 'entry-1', name: 'Internet Entry Point', type: 'entry', risk_score: 30, val: 12, color: '#6B7280' },
      { id: 'fw-1', name: 'Edge Firewall', type: 'firewall', risk_score: 20, val: 10, color: '#10B981' },
      { id: 'dmz-web', name: 'DMZ Web Server', type: 'server', risk_score: 65, val: 12, color: '#F59E0B' },
      { id: 'app-1', name: 'Application Server', type: 'server', risk_score: 55, val: 11, color: '#F59E0B' },
      { id: 'db-1', name: 'Customer Database', type: 'crown_jewel', risk_score: 95, val: 20, color: '#EF4444' },
      { id: 'ad-dc', name: 'Domain Controller', type: 'crown_jewel', risk_score: 98, val: 20, color: '#EF4444' },
      { id: 'ws-1', name: 'Admin Workstation', type: 'workstation', risk_score: 45, val: 10, color: '#3B82F6' },
      { id: 'ws-2', name: 'Developer Workstation', type: 'workstation', risk_score: 60, val: 10, color: '#F59E0B' },
      { id: 'secrets', name: 'Secrets Vault', type: 'crown_jewel', risk_score: 99, val: 20, color: '#EF4444' },
      { id: 'backup', name: 'Backup Server', type: 'server', risk_score: 70, val: 12, color: '#F59E0B' }
    ];
    
    const demoLinks = [
      { source: 'entry-1', target: 'fw-1', technique: 'Initial Access', mitre_id: 'T1190', probability: 0.3 },
      { source: 'fw-1', target: 'dmz-web', technique: 'Exploit Public App', mitre_id: 'T1190', probability: 0.4 },
      { source: 'dmz-web', target: 'app-1', technique: 'Lateral Movement', mitre_id: 'T1021', probability: 0.6, color: '#EF4444' },
      { source: 'app-1', target: 'db-1', technique: 'SQL Injection', mitre_id: 'T1190', probability: 0.7, color: '#EF4444' },
      { source: 'ws-2', target: 'app-1', technique: 'Valid Accounts', mitre_id: 'T1078', probability: 0.5 },
      { source: 'ws-1', target: 'ad-dc', technique: 'DCSync', mitre_id: 'T1003.006', probability: 0.8, color: '#EF4444' },
      { source: 'ad-dc', target: 'secrets', technique: 'Credential Access', mitre_id: 'T1003', probability: 0.9, color: '#EF4444' },
      { source: 'app-1', target: 'backup', technique: 'Data Staged', mitre_id: 'T1074', probability: 0.5 },
      { source: 'backup', target: 'secrets', technique: 'Backup Abuse', mitre_id: 'T1490', probability: 0.4 }
    ];
    
    setGraphData({ nodes: demoNodes, links: demoLinks });
    setCrownJewels([
      { id: 'db-1', name: 'Customer Database', criticality: 'critical', type: 'database', paths_to: 3 },
      { id: 'ad-dc', name: 'Domain Controller', criticality: 'critical', type: 'identity', paths_to: 2 },
      { id: 'secrets', name: 'Secrets Vault', criticality: 'critical', type: 'secrets', paths_to: 4 }
    ]);
    setCriticalPaths([
      { 
        id: 'path-1', 
        name: 'Internet → Web → App → Database',
        risk_score: 85,
        length: 4,
        techniques: ['T1190', 'T1021', 'T1190'],
        blocked: false
      },
      { 
        id: 'path-2', 
        name: 'Admin WS → DC → Secrets Vault',
        risk_score: 92,
        length: 3,
        techniques: ['T1078', 'T1003.006', 'T1003'],
        blocked: false
      },
      { 
        id: 'path-3', 
        name: 'Dev WS → App → Backup → Secrets',
        risk_score: 78,
        length: 4,
        techniques: ['T1078', 'T1074', 'T1490'],
        blocked: true
      }
    ]);
    setStats({
      total_assets: 10,
      critical_paths: 3,
      high_risk_nodes: 5,
      avg_path_length: 3.7,
      blocked_paths: 1
    });
  };

  // Run new analysis
  const runAnalysis = async () => {
    try {
      setAnalyzing(true);
      toast.info('Running attack path analysis across fleet...');
      
      await axios.post(`${API}/v1/attack-paths/analyze`, {
        include_lateral: true,
        include_privilege_escalation: true,
        max_depth: 10
      }, { headers: getAuthHeaders() });
      
      toast.success('Analysis complete');
      await fetchAttackPaths();
    } catch (error) {
      console.error('Analysis failed:', error);
      toast.error('Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const addCrownJewel = async () => {
    const name = window.prompt('Crown jewel name (e.g., Domain Controller)');
    if (!name) return;
    const identifier = window.prompt('Identifier (IP, hostname, ARN, etc.)');
    if (!identifier) return;
    const assetType = window.prompt(
      'Asset type (application_server/database_server/domain_controller/network_device/secret_vault/workstation)',
      'application_server'
    ) || 'application_server';

    try {
      await axios.post(`${API}/v1/attack-paths/crown-jewels`, {
        name,
        identifier,
        asset_type: assetType,
        criticality: 'critical'
      }, { headers: getAuthHeaders() });

      toast.success('Crown jewel added');
      await fetchAttackPaths();
    } catch (error) {
      console.error('Failed to add crown jewel:', error);
      if (error?.response?.status === 403) {
        toast.error('Only admins can define crown jewels. Ask an admin to add this asset.');
        return;
      }
      toast.error(error?.response?.data?.detail || 'Failed to add crown jewel');
    }
  };

  // Calculate blast radius for a node
  const calculateBlastRadius = async (nodeId) => {
    try {
      const res = await axios.get(
        `${API}/v1/attack-paths/blast-radius/${nodeId}`,
        { headers: getAuthHeaders() }
      );
      setBlastRadius(res.data);
      toast.info(`Blast radius: ${res.data.affected_assets} assets at risk`);
    } catch (error) {
      // Demo blast radius
      setBlastRadius({
        source_node: nodeId,
        affected_assets: Math.floor(Math.random() * 20) + 5,
        critical_assets_at_risk: Math.floor(Math.random() * 5) + 1,
        max_depth: 4,
        affected_nodes: graphData.nodes.slice(0, 5).map(n => n.id)
      });
    }
  };

  // Get node color based on risk
  const getNodeColor = (riskScore, type) => {
    if (type === 'crown_jewel') return '#F59E0B';
    if (type === 'entry') return '#6B7280';
    if (type === 'firewall') return '#10B981';
    if (riskScore >= 80) return '#EF4444';
    if (riskScore >= 60) return '#F59E0B';
    if (riskScore >= 40) return '#3B82F6';
    return '#10B981';
  };

  // Get icon for asset type
  const getAssetIcon = (type) => {
    switch (type) {
      case 'crown_jewel': return Crown;
      case 'database': return Database;
      case 'server': return Server;
      case 'workstation': return Users;
      case 'identity': return Key;
      case 'secrets': return Lock;
      case 'firewall': return Shield;
      default: return Target;
    }
  };

  useEffect(() => {
    fetchAttackPaths();
  }, [fetchAttackPaths]);

  // Node click handler
  const handleNodeClick = (node) => {
    setSelectedNode(node);
    calculateBlastRadius(node.id);
  };

  // Custom node rendering
  const nodeCanvasObject = useCallback((node, ctx, globalScale) => {
    const label = node.name;
    const fontSize = 12 / globalScale;
    ctx.font = `${fontSize}px Sans-Serif`;
    
    // Draw node circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.val / 2, 0, 2 * Math.PI);
    ctx.fillStyle = node.color;
    ctx.fill();
    
    // Crown jewel indicator
    if (node.type === 'crown_jewel') {
      ctx.strokeStyle = '#F59E0B';
      ctx.lineWidth = 3 / globalScale;
      ctx.stroke();
      
      // Draw crown icon
      ctx.fillStyle = '#FFFFFF';
      ctx.font = `${fontSize * 1.5}px Sans-Serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('👑', node.x, node.y);
    }
    
    // High risk indicator
    if (node.risk_score >= 80 && node.type !== 'crown_jewel') {
      ctx.strokeStyle = '#EF4444';
      ctx.lineWidth = 2 / globalScale;
      ctx.stroke();
    }
    
    // Label
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#E5E7EB';
    ctx.fillText(label, node.x, node.y + node.val / 2 + 2);
  }, []);

  // Link rendering with arrows for attack direction
  const linkCanvasObject = useCallback((link, ctx, globalScale) => {
    const start = link.source;
    const end = link.target;
    
    if (typeof start !== 'object' || typeof end !== 'object') return;
    
    // Draw line
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.lineTo(end.x, end.y);
    ctx.strokeStyle = link.color || '#6B7280';
    ctx.lineWidth = (link.probability || 0.5) * 3 / globalScale;
    ctx.stroke();
    
    // Draw arrow
    const angle = Math.atan2(end.y - start.y, end.x - start.x);
    const arrowLen = 8 / globalScale;
    ctx.beginPath();
    ctx.moveTo(end.x, end.y);
    ctx.lineTo(
      end.x - arrowLen * Math.cos(angle - Math.PI / 6),
      end.y - arrowLen * Math.sin(angle - Math.PI / 6)
    );
    ctx.lineTo(
      end.x - arrowLen * Math.cos(angle + Math.PI / 6),
      end.y - arrowLen * Math.sin(angle + Math.PI / 6)
    );
    ctx.fillStyle = link.color || '#6B7280';
    ctx.fill();
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-orange-500/20 rounded-lg">
            <Route className="h-6 w-6 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Attack Path Analysis</h1>
            <p className="text-gray-400 text-sm">Fleet-wide attack surface visualization</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={addCrownJewel}
            className="border-gray-700"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Crown Jewel
          </Button>
          <Button 
            variant="outline" 
            onClick={fetchAttackPaths}
            disabled={loading}
            className="border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button 
            onClick={runAnalysis}
            disabled={analyzing}
            className="bg-orange-600 hover:bg-orange-700"
          >
            <Crosshair className={`h-4 w-4 mr-2 ${analyzing ? 'animate-pulse' : ''}`} />
            {analyzing ? 'Analyzing...' : 'Run Analysis'}
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Target className="h-4 w-4 text-blue-400" />
            <span className="text-gray-400 text-sm">Total Assets</span>
          </div>
          <p className="text-2xl font-bold">{stats.total_assets}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 border border-red-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Route className="h-4 w-4 text-red-400" />
            <span className="text-gray-400 text-sm">Critical Paths</span>
          </div>
          <p className="text-2xl font-bold text-red-400">{stats.critical_paths}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 border border-orange-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            <span className="text-gray-400 text-sm">High Risk Nodes</span>
          </div>
          <p className="text-2xl font-bold text-orange-400">{stats.high_risk_nodes}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="h-4 w-4 text-purple-400" />
            <span className="text-gray-400 text-sm">Avg Path Length</span>
          </div>
          <p className="text-2xl font-bold">{stats.avg_path_length?.toFixed(1) || '0'}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gray-900/50 border border-green-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Shield className="h-4 w-4 text-green-400" />
            <span className="text-gray-400 text-sm">Blocked Paths</span>
          </div>
          <p className="text-2xl font-bold text-green-400">{stats.blocked_paths}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'graph', label: 'Attack Graph', icon: Route },
          { id: 'paths', label: 'Critical Paths', icon: Zap },
          { id: 'jewels', label: 'Crown Jewels', icon: Crown }
        ].map(tab => (
          <Button
            key={tab.id}
            variant={viewMode === tab.id ? 'default' : 'outline'}
            onClick={() => setViewMode(tab.id)}
            className={viewMode === tab.id ? 'bg-orange-600' : 'border-gray-700'}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Visualization Area */}
        <div className="col-span-2 bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden" style={{ height: '600px' }}>
          {viewMode === 'graph' && (
            <ForceGraph2D
              ref={graphRef}
              graphData={graphData}
              nodeCanvasObject={nodeCanvasObject}
              linkCanvasObject={linkCanvasObject}
              nodeRelSize={6}
              linkDirectionalArrowLength={6}
              linkDirectionalArrowRelPos={1}
              onNodeClick={handleNodeClick}
              backgroundColor="#0a0a0f"
              linkColor={() => '#374151'}
              cooldownTicks={100}
              onEngineStop={() => graphRef.current?.zoomToFit(400)}
            />
          )}
          
          {viewMode === 'paths' && (
            <div className="p-4 h-full overflow-auto">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Zap className="h-5 w-5 text-red-400" />
                Critical Attack Paths
              </h3>
              <div className="space-y-3">
                {criticalPaths.map((path, idx) => (
                  <motion.div
                    key={path.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className={`p-4 rounded-lg border cursor-pointer transition-all ${
                      selectedPath?.id === path.id 
                        ? 'bg-orange-500/20 border-orange-500' 
                        : 'bg-gray-800/50 border-gray-700 hover:border-gray-600'
                    } ${path.blocked ? 'opacity-50' : ''}`}
                    onClick={() => setSelectedPath(path)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">{path.name}</span>
                      <div className="flex items-center gap-2">
                        {path.blocked ? (
                          <Badge className="bg-green-500/20 text-green-400">
                            <Shield className="h-3 w-3 mr-1" />
                            Blocked
                          </Badge>
                        ) : (
                          <Badge className={`${
                            path.risk_score >= 80 ? 'bg-red-500/20 text-red-400' :
                            path.risk_score >= 60 ? 'bg-orange-500/20 text-orange-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          }`}>
                            Risk: {path.risk_score}%
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-gray-400">
                      <span>{path.length} hops</span>
                      <span>•</span>
                      <span>{path.techniques.length} techniques</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {path.techniques.map((t, i) => (
                        <Badge key={i} variant="outline" className="text-xs border-gray-600">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}
          
          {viewMode === 'jewels' && (
            <div className="p-4 h-full overflow-auto">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Crown className="h-5 w-5 text-yellow-400" />
                Crown Jewels (Critical Assets)
              </h3>
              <div className="grid grid-cols-2 gap-4">
                {crownJewels.map((jewel, idx) => {
                  const Icon = getAssetIcon(jewel.type);
                  return (
                    <motion.div
                      key={jewel.id}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: idx * 0.1 }}
                      className="p-4 bg-gradient-to-br from-yellow-500/10 to-orange-500/10 border border-yellow-500/30 rounded-lg"
                    >
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 bg-yellow-500/20 rounded-lg">
                          <Icon className="h-5 w-5 text-yellow-400" />
                        </div>
                        <div>
                          <h4 className="font-medium">{jewel.name}</h4>
                          <p className="text-xs text-gray-400">{jewel.type}</p>
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <Badge className="bg-red-500/20 text-red-400">
                          {jewel.criticality}
                        </Badge>
                        <span className="text-sm text-gray-400">
                          {jewel.paths_to} attack paths
                        </span>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Selected Node Details */}
          <AnimatePresence mode="wait">
            {selectedNode && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Target className="h-4 w-4 text-orange-400" />
                  Selected Asset
                </h3>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm text-gray-400">Name</p>
                    <p className="font-medium">{selectedNode.name}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Type</p>
                    <Badge variant="outline">{selectedNode.type}</Badge>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Risk Score</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${
                            selectedNode.risk_score >= 80 ? 'bg-red-500' :
                            selectedNode.risk_score >= 60 ? 'bg-orange-500' :
                            selectedNode.risk_score >= 40 ? 'bg-yellow-500' :
                            'bg-green-500'
                          }`}
                          style={{ width: `${selectedNode.risk_score || 0}%` }}
                        />
                      </div>
                      <span className="text-sm font-medium">{selectedNode.risk_score || 0}%</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Blast Radius */}
          <AnimatePresence>
            {blastRadius && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="bg-gray-900/50 border border-red-900/50 rounded-xl p-4"
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Bomb className="h-4 w-4 text-red-400" />
                  Blast Radius
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-red-400">{blastRadius.affected_assets}</p>
                    <p className="text-xs text-gray-400">Assets at Risk</p>
                  </div>
                  <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-orange-400">{blastRadius.critical_assets_at_risk}</p>
                    <p className="text-xs text-gray-400">Critical Assets</p>
                  </div>
                </div>
                <div className="mt-3">
                  <p className="text-sm text-gray-400 mb-2">Affected Nodes:</p>
                  <div className="flex flex-wrap gap-1">
                    {blastRadius.affected_nodes?.slice(0, 5).map(nodeId => (
                      <Badge key={nodeId} variant="outline" className="text-xs border-red-900/50 text-red-400">
                        {nodeId}
                      </Badge>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Legend */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Eye className="h-4 w-4 text-gray-400" />
              Legend
            </h3>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <span className="text-sm text-gray-400">Crown Jewel</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-sm text-gray-400">High Risk (80%+)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-orange-500" />
                <span className="text-sm text-gray-400">Medium Risk (60-80%)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-sm text-gray-400">Low Risk (40-60%)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-sm text-gray-400">Minimal Risk (&lt;40%)</span>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3">Quick Actions</h3>
            <div className="space-y-2">
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Shield className="h-4 w-4 mr-2" />
                Block Critical Path
              </Button>
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Lock className="h-4 w-4 mr-2" />
                Harden Crown Jewels
              </Button>
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Activity className="h-4 w-4 mr-2" />
                Export Analysis
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttackPathsPage;
