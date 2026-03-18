import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, AlertTriangle, CheckCircle, XCircle, Clock,
  Activity, Terminal, Zap, Eye, Lock, RefreshCw,
  ChevronRight, Play, Pause, Target, Radio, Cpu,
  Network, Server, AlertOctagon, ShieldAlert, Ban
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const CommandCenterPage = () => {
  const { token } = useAuth();
  const [pendingCommands, setPendingCommands] = useState([]);
  const [recentCommands, setRecentCommands] = useState([]);
  const [threats, setThreats] = useState([]);
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [actionInProgress, setActionInProgress] = useState({});

  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    try {
      const [pendingRes, historyRes, agentsRes, threatsRes] = await Promise.all([
        axios.get(`${API}/agent-commands/pending`, { headers }),
        axios.get(`${API}/agent-commands/history?limit=20`, { headers }),
        axios.get(`${API}/swarm/overview`, { headers }),
        axios.get(`${API}/swarm/telemetry?severity=critical&limit=50`, { headers })
      ]);

      setPendingCommands(pendingRes.data.commands || []);
      setRecentCommands(historyRes.data.commands || []);
      setStats(agentsRes.data);
      
      // Get critical threats that need action
      const criticalEvents = (threatsRes.data.events || []).filter(e => 
        e.severity === 'critical' || e.severity === 'high'
      );
      setThreats(criticalEvents);

      // Get connected agents
      const connectedRes = await axios.get(`${API}/agent-commands/agents/status`, { headers });
      setAgents(connectedRes.data.agents || []);
    } catch (err) {
      console.error('Failed to fetch command center data:', err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const approveCommand = async (commandId, approved) => {
    setActionInProgress(prev => ({ ...prev, [commandId]: true }));
    try {
      await axios.post(`${API}/agent-commands/${commandId}/approve`, 
        { approved, notes: '' },
        { headers }
      );
      toast.success(approved ? 'Command approved and sent to agent' : 'Command rejected');
      fetchData();
    } catch (err) {
      toast.error('Failed to process command');
    } finally {
      setActionInProgress(prev => ({ ...prev, [commandId]: false }));
    }
  };

  const sendQuickCommand = async (agentId, commandType, params) => {
    try {
      await axios.post(`${API}/agent-commands/create`, {
        agent_id: agentId,
        command_type: commandType,
        parameters: params,
        priority: 'high'
      }, { headers });
      toast.success('Command queued for approval');
      fetchData();
    } catch (err) {
      toast.error('Failed to create command');
    }
  };

  const respondToThreat = async (threat, action) => {
    const agentId = threat.host_id || threat.agent_id;
    if (!agentId) {
      toast.error('No agent associated with this threat');
      return;
    }

    let commandType = '';
    let params = {};

    switch (action) {
      case 'kill_process':
        commandType = 'kill_process';
        params = { pid: threat.data?.pid, process_name: threat.data?.name };
        break;
      case 'block_ip':
        commandType = 'block_ip';
        params = { ip_address: threat.data?.remote_ip || threat.data?.ip };
        break;
      case 'quarantine':
        commandType = 'quarantine_file';
        params = { file_path: threat.data?.filepath };
        break;
      case 'isolate':
        commandType = 'block_ip';
        params = { ip_address: '0.0.0.0', duration_hours: 24 }; // Network isolation
        break;
      default:
        return;
    }

    await sendQuickCommand(agentId, commandType, params);
  };

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/50';
    }
  };

  const getRiskStyle = (level) => {
    switch (level) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-600';
      case 'medium': return 'bg-yellow-600';
      case 'low': return 'bg-green-600';
      default: return 'bg-slate-600';
    }
  };

  const getStatusStyle = (status) => {
    switch (status) {
      case 'pending_approval': return 'bg-amber-500/20 text-amber-400';
      case 'approved': case 'sent_to_agent': return 'bg-blue-500/20 text-blue-400';
      case 'completed': return 'bg-green-500/20 text-green-400';
      case 'failed': case 'rejected': return 'bg-red-500/20 text-red-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2" style={{ borderColor: '#FDE68A' }}></div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6" data-testid="command-center-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <ShieldAlert className="w-8 h-8" style={{ color: '#FDE68A' }} />
            Command Center
          </h1>
          <p className="text-slate-400 mt-1">Threat Response & Agent Control</p>
        </div>
        <div className="flex items-center gap-3">
          {pendingCommands.length > 0 && (
            <motion.div
              animate={{ scale: [1, 1.05, 1] }}
              transition={{ repeat: Infinity, duration: 2 }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg"
              style={{ backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.5)' }}
            >
              <AlertOctagon className="w-5 h-5 text-red-400" />
              <span className="text-red-400 font-semibold">{pendingCommands.length} Pending Approval</span>
            </motion.div>
          )}
          <Button onClick={fetchData} variant="outline" style={{ borderColor: 'rgba(253, 230, 138, 0.3)' }}>
            <RefreshCw className="w-4 h-4 mr-2" style={{ color: '#FDE68A' }} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(253, 230, 138, 0.2)' }}>
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(253, 230, 138, 0.15)' }}>
              <Radio className="w-6 h-6" style={{ color: '#FDE68A' }} />
            </div>
            <div>
              <p className="text-3xl font-bold" style={{ color: '#FDE68A' }}>{stats.agents?.online || 0}</p>
              <p className="text-slate-400 text-sm">Agents Online</p>
            </div>
          </CardContent>
        </Card>

        <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(239, 68, 68, 0.15)' }}>
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <p className="text-3xl font-bold text-red-400">{pendingCommands.length}</p>
              <p className="text-slate-400 text-sm">Pending Commands</p>
            </div>
          </CardContent>
        </Card>

        <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(56, 189, 248, 0.15)' }}>
              <Activity className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <p className="text-3xl font-bold text-cyan-400">{threats.length}</p>
              <p className="text-slate-400 text-sm">Active Threats</p>
            </div>
          </CardContent>
        </Card>

        <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)' }}>
              <CheckCircle className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-3xl font-bold text-green-400">
                {recentCommands.filter(c => c.status === 'completed').length}
              </p>
              <p className="text-slate-400 text-sm">Commands Executed</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="approvals" className="w-full">
        <TabsList className="mb-4" style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)' }}>
          <TabsTrigger value="approvals" className="data-[state=active]:bg-red-500/20 data-[state=active]:text-red-400">
            <Clock className="w-4 h-4 mr-2" />
            Pending Approvals ({pendingCommands.length})
          </TabsTrigger>
          <TabsTrigger value="threats" className="data-[state=active]:bg-orange-500/20 data-[state=active]:text-orange-400">
            <AlertTriangle className="w-4 h-4 mr-2" />
            Active Threats ({threats.length})
          </TabsTrigger>
          <TabsTrigger value="agents" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400">
            <Server className="w-4 h-4 mr-2" />
            Agent Control
          </TabsTrigger>
          <TabsTrigger value="history" className="data-[state=active]:bg-slate-500/20">
            <Terminal className="w-4 h-4 mr-2" />
            Command History
          </TabsTrigger>
        </TabsList>

        {/* Pending Approvals Tab */}
        <TabsContent value="approvals" className="mt-4">
          {pendingCommands.length === 0 ? (
            <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
              <CardContent className="p-8 text-center">
                <CheckCircle className="w-16 h-16 mx-auto text-green-400 mb-4" />
                <h3 className="text-xl font-semibold text-white mb-2">All Clear</h3>
                <p className="text-slate-400">No commands pending approval</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {pendingCommands.map((cmd) => (
                <motion.div
                  key={cmd.command_id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="rounded-xl p-5"
                  style={{ 
                    backgroundColor: 'rgba(18, 24, 51, 0.9)',
                    border: '2px solid rgba(239, 68, 68, 0.4)'
                  }}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-start gap-4">
                      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${getRiskStyle(cmd.risk_level)}`}>
                        <Zap className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold text-white">{cmd.command_name}</h3>
                        <p className="text-slate-400 text-sm">Agent: {cmd.agent_id}</p>
                        <p className="text-slate-500 text-xs mt-1">
                          Created by {cmd.created_by} at {new Date(cmd.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={`${getRiskStyle(cmd.risk_level)} text-white`}>
                        {cmd.risk_level} risk
                      </Badge>
                      <Badge variant="outline" className="text-amber-400 border-amber-400">
                        {cmd.priority}
                      </Badge>
                    </div>
                  </div>

                  {/* Parameters */}
                  <div className="p-3 rounded-lg mb-4" style={{ backgroundColor: 'rgba(0, 0, 0, 0.3)' }}>
                    <p className="text-slate-400 text-xs mb-2">Parameters:</p>
                    <pre className="text-sm text-cyan-400 font-mono overflow-x-auto">
                      {JSON.stringify(cmd.parameters, null, 2)}
                    </pre>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-3">
                    <Button
                      className="flex-1 bg-green-600 hover:bg-green-700 text-white"
                      onClick={() => approveCommand(cmd.command_id, true)}
                      disabled={actionInProgress[cmd.command_id]}
                    >
                      {actionInProgress[cmd.command_id] ? (
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <CheckCircle className="w-4 h-4 mr-2" />
                      )}
                      Approve & Execute
                    </Button>
                    <Button
                      className="flex-1 bg-red-600 hover:bg-red-700 text-white"
                      onClick={() => approveCommand(cmd.command_id, false)}
                      disabled={actionInProgress[cmd.command_id]}
                    >
                      <XCircle className="w-4 h-4 mr-2" />
                      Reject
                    </Button>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Active Threats Tab */}
        <TabsContent value="threats" className="mt-4">
          {threats.length === 0 ? (
            <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
              <CardContent className="p-8 text-center">
                <Shield className="w-16 h-16 mx-auto text-green-400 mb-4" />
                <h3 className="text-xl font-semibold text-white mb-2">System Secure</h3>
                <p className="text-slate-400">No critical threats detected</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {threats.map((threat, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className={`rounded-xl p-4 border-2 ${getSeverityStyle(threat.severity)}`}
                  style={{ backgroundColor: 'rgba(18, 24, 51, 0.9)' }}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <Badge className={getSeverityStyle(threat.severity)}>
                        {threat.severity?.toUpperCase()}
                      </Badge>
                      <h3 className="text-white font-semibold mt-2">{threat.event_type}</h3>
                      <p className="text-slate-400 text-sm">Host: {threat.host_id || 'Unknown'}</p>
                    </div>
                    <span className="text-slate-500 text-xs">
                      {new Date(threat.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  {threat.data && (
                    <div className="p-2 rounded mb-3" style={{ backgroundColor: 'rgba(0,0,0,0.3)' }}>
                      <p className="text-slate-300 text-sm">
                        {threat.data.message || JSON.stringify(threat.data).substring(0, 100)}
                      </p>
                    </div>
                  )}

                  {/* Quick Response Actions */}
                  <div className="flex flex-wrap gap-2">
                    {threat.data?.pid && (
                      <Button
                        size="sm"
                        className="bg-red-600 hover:bg-red-700"
                        onClick={() => respondToThreat(threat, 'kill_process')}
                      >
                        <Ban className="w-3 h-3 mr-1" />
                        Kill Process
                      </Button>
                    )}
                    {(threat.data?.remote_ip || threat.data?.ip) && (
                      <Button
                        size="sm"
                        className="bg-orange-600 hover:bg-orange-700"
                        onClick={() => respondToThreat(threat, 'block_ip')}
                      >
                        <Lock className="w-3 h-3 mr-1" />
                        Block IP
                      </Button>
                    )}
                    {threat.data?.filepath && (
                      <Button
                        size="sm"
                        className="bg-yellow-600 hover:bg-yellow-700"
                        onClick={() => respondToThreat(threat, 'quarantine')}
                      >
                        <Shield className="w-3 h-3 mr-1" />
                        Quarantine
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-600"
                      onClick={() => setSelectedThreat(threat)}
                    >
                      <Eye className="w-3 h-3 mr-1" />
                      Details
                    </Button>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Agent Control Tab */}
        <TabsContent value="agents" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((agent) => (
              <Card 
                key={agent.agent_id}
                style={{ 
                  backgroundColor: 'rgba(18, 24, 51, 0.8)',
                  border: agent.connected ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(100, 116, 139, 0.3)'
                }}
              >
                <CardContent className="p-4">
                  <div className="flex items-center gap-3 mb-4">
                    <div className={`w-3 h-3 rounded-full ${agent.connected ? 'bg-green-400 animate-pulse' : 'bg-slate-500'}`} />
                    <div>
                      <p className="text-white font-medium">{agent.hostname || agent.agent_id}</p>
                      <p className="text-slate-500 text-xs">{agent.os} | {agent.ip_address}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'full_scan', { scan_types: ['all'] })}
                    >
                      <Target className="w-3 h-3 mr-1" />
                      Scan
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-purple-500/50 text-purple-400 hover:bg-purple-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'collect_forensics', { collection_type: 'quick' })}
                    >
                      <Cpu className="w-3 h-3 mr-1" />
                      Forensics
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-amber-500/50 text-amber-400 hover:bg-amber-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'restart_service', { service_name: 'seraph-defender' })}
                    >
                      <RefreshCw className="w-3 h-3 mr-1" />
                      Restart
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-green-500/50 text-green-400 hover:bg-green-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'update_agent', {})}
                    >
                      <Activity className="w-3 h-3 mr-1" />
                      Update
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            
            {agents.length === 0 && (
              <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)' }} className="col-span-full">
                <CardContent className="p-8 text-center">
                  <Server className="w-16 h-16 mx-auto text-slate-500 mb-4" />
                  <h3 className="text-xl font-semibold text-white mb-2">No Agents Registered</h3>
                  <p className="text-slate-400">Deploy Seraph Defender agents to your endpoints</p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        {/* Command History Tab */}
        <TabsContent value="history" className="mt-4">
          <Card style={{ backgroundColor: 'rgba(18, 24, 51, 0.8)', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
            <CardHeader>
              <CardTitle className="text-white">Recent Commands</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {recentCommands.map((cmd) => (
                  <div
                    key={cmd.command_id}
                    className="flex items-center justify-between p-3 rounded-lg"
                    style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        cmd.status === 'completed' ? 'bg-green-400' :
                        cmd.status === 'failed' ? 'bg-red-400' :
                        cmd.status === 'pending_approval' ? 'bg-amber-400' :
                        'bg-blue-400'
                      }`} />
                      <div>
                        <p className="text-white text-sm font-medium">{cmd.command_name}</p>
                        <p className="text-slate-500 text-xs">
                          {cmd.agent_id} • {new Date(cmd.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <Badge className={getStatusStyle(cmd.status)}>
                      {cmd.status.replace('_', ' ')}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Threat Detail Modal */}
      <AnimatePresence>
        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
            onClick={() => setSelectedThreat(null)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="max-w-2xl w-full rounded-xl p-6"
              style={{ backgroundColor: '#121833', border: '2px solid rgba(253, 230, 138, 0.3)' }}
              onClick={(e) => e.stopPropagation()}
            >
              <h2 className="text-xl font-bold text-white mb-4">Threat Details</h2>
              <div className="space-y-4">
                <div>
                  <p className="text-slate-400 text-sm">Event Type</p>
                  <p className="text-white">{selectedThreat.event_type}</p>
                </div>
                <div>
                  <p className="text-slate-400 text-sm">Severity</p>
                  <Badge className={getSeverityStyle(selectedThreat.severity)}>
                    {selectedThreat.severity}
                  </Badge>
                </div>
                <div>
                  <p className="text-slate-400 text-sm">Host</p>
                  <p className="text-white">{selectedThreat.host_id || 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-slate-400 text-sm">Timestamp</p>
                  <p className="text-white">{new Date(selectedThreat.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-slate-400 text-sm">Full Data</p>
                  <pre className="p-3 rounded-lg text-xs font-mono overflow-auto max-h-64 text-cyan-400" style={{ backgroundColor: 'rgba(0,0,0,0.3)' }}>
                    {JSON.stringify(selectedThreat.data, null, 2)}
                  </pre>
                </div>
              </div>
              <Button
                className="w-full mt-4"
                style={{ backgroundColor: '#FDE68A', color: '#0C1020' }}
                onClick={() => setSelectedThreat(null)}
              >
                Close
              </Button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CommandCenterPage;
