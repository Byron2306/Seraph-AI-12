import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Monitor, ArrowLeft, Activity, Clock, AlertTriangle, CheckCircle,
  XCircle, RefreshCw, Shield, Terminal, FileSearch, Wifi, WifiOff,
  Play, Send, Cpu, HardDrive, Globe, User, Calendar, ChevronRight,
  AlertCircle, Bug, FileWarning, Lock
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AgentDetailsPage = () => {
  const { agentId } = useParams();
  const navigate = useNavigate();
  const { token } = useAuth();
  const [agent, setAgent] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [scanResults, setScanResults] = useState([]);
  const [commandHistory, setCommandHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [sendingCommand, setSendingCommand] = useState(false);
  const [selectedCommand, setSelectedCommand] = useState('full_scan');

  const headers = { Authorization: `Bearer ${token}` };

  const fetchAgentData = useCallback(async () => {
    try {
      const [statusRes, alertsRes, scansRes, historyRes] = await Promise.all([
        axios.get(`${API}/agent-commands/agents/status`, { headers }),
        axios.get(`${API}/agent-commands/agents/${agentId}/alerts?limit=20`, { headers }),
        axios.get(`${API}/agent-commands/agents/${agentId}/scan-results?limit=10`, { headers }),
        axios.get(`${API}/agent-commands/history?agent_id=${agentId}&limit=20`, { headers })
      ]);

      const agentData = statusRes.data.agents?.find(a => a.agent_id === agentId);
      setAgent(agentData || null);
      setAlerts(alertsRes.data.alerts || []);
      setScanResults(scansRes.data.results || []);
      setCommandHistory(historyRes.data.commands || []);
    } catch (err) {
      console.error('Failed to fetch agent data:', err);
      toast.error('Failed to load agent details');
    } finally {
      setLoading(false);
    }
  }, [agentId, token]);

  useEffect(() => {
    fetchAgentData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchAgentData, 30000);
    return () => clearInterval(interval);
  }, [fetchAgentData]);

  const handleSendCommand = async (commandType) => {
    setSendingCommand(true);
    try {
      const params = getCommandParams(commandType);
      await axios.post(`${API}/agent-commands/create`, {
        agent_id: agentId,
        command_type: commandType,
        parameters: params,
        priority: 'high'
      }, { headers });
      
      toast.success(`Command "${commandType}" queued for approval`);
      fetchAgentData();
    } catch (err) {
      toast.error('Failed to send command');
    } finally {
      setSendingCommand(false);
    }
  };

  const getCommandParams = (type) => {
    switch (type) {
      case 'full_scan':
        return { scan_types: ['processes', 'files', 'network', 'persistence'] };
      case 'collect_forensics':
        return { collection_type: 'full' };
      default:
        return {};
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'completed': return 'text-green-400 bg-green-500/10';
      case 'pending_approval': return 'text-amber-400 bg-amber-500/10';
      case 'approved': return 'text-blue-400 bg-blue-500/10';
      case 'sent_to_agent': return 'text-cyan-400 bg-cyan-500/10';
      case 'failed': return 'text-red-400 bg-red-500/10';
      default: return 'text-slate-400 bg-slate-500/10';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (!agent) {
    return (
      <div className="p-6">
        <Button onClick={() => navigate('/agent-commands')} variant="ghost" className="mb-4">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Agent Commands
        </Button>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="py-12 text-center">
            <AlertCircle className="w-16 h-16 mx-auto mb-4 text-amber-400 opacity-50" />
            <h2 className="text-xl font-bold text-white mb-2">Agent Not Found</h2>
            <p className="text-slate-400">Agent ID: {agentId}</p>
            <p className="text-slate-500 text-sm mt-2">This agent may not have registered yet or has been removed.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="agent-details-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button onClick={() => navigate('/agent-commands')} variant="ghost" size="sm">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div className="flex items-center gap-3">
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${agent.connected ? 'bg-green-500/20' : 'bg-slate-800'}`}>
              <Monitor className={`w-6 h-6 ${agent.connected ? 'text-green-400' : 'text-slate-400'}`} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                {agent.hostname}
                {agent.connected ? (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                    <Wifi className="w-3 h-3 mr-1" />
                    Connected
                  </Badge>
                ) : (
                  <Badge className="bg-slate-500/20 text-slate-400 border-slate-500/30">
                    <WifiOff className="w-3 h-3 mr-1" />
                    Offline
                  </Badge>
                )}
              </h1>
              <p className="text-slate-400 text-sm font-mono">{agent.agent_id}</p>
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchAgentData} variant="outline" className="border-slate-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button 
            onClick={() => handleSendCommand('full_scan')} 
            disabled={sendingCommand}
            className="bg-cyan-600 hover:bg-cyan-500"
          >
            <Play className="w-4 h-4 mr-2" />
            Run Full Scan
          </Button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <Globe className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">OS</p>
              <p className="text-white font-medium text-sm">{agent.os || 'Unknown'}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Wifi className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">IP Address</p>
              <p className="text-white font-medium text-sm font-mono">{agent.ip_address || 'N/A'}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Alerts</p>
              <p className="text-2xl font-bold text-amber-400">{alerts.length}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
              <FileSearch className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Scans</p>
              <p className="text-2xl font-bold text-cyan-400">{scanResults.length}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Terminal className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Commands</p>
              <p className="text-2xl font-bold text-green-400">{commandHistory.length}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-2">
        {['overview', 'alerts', 'scans', 'commands'].map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab)}
            className={activeTab === tab ? 'bg-cyan-600 hover:bg-cyan-500' : 'text-slate-400'}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </Button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* System Info */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Monitor className="w-5 h-5 text-cyan-400" />
                System Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between py-2 border-b border-slate-800">
                  <span className="text-slate-400">Hostname</span>
                  <span className="text-white font-medium">{agent.hostname}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-800">
                  <span className="text-slate-400">Agent ID</span>
                  <span className="text-white font-mono text-sm">{agent.agent_id}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-800">
                  <span className="text-slate-400">Operating System</span>
                  <span className="text-white">{agent.os || 'Unknown'}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-800">
                  <span className="text-slate-400">IP Address</span>
                  <span className="text-white font-mono">{agent.ip_address || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-800">
                  <span className="text-slate-400">Agent Version</span>
                  <span className="text-white">{agent.security_status?.agent_version || 'Unknown'}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-800">
                  <span className="text-slate-400">Last Heartbeat</span>
                  <span className="text-white">
                    {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'Never'}
                  </span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-slate-400">Last Scan</span>
                  <span className="text-white">
                    {agent.last_scan ? new Date(agent.last_scan).toLocaleString() : 'Never'}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-green-400" />
                Quick Actions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                <Button 
                  onClick={() => handleSendCommand('full_scan')}
                  disabled={sendingCommand}
                  className="bg-cyan-600/20 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-600/30"
                >
                  <Shield className="w-4 h-4 mr-2" />
                  Full Scan
                </Button>
                <Button 
                  onClick={() => handleSendCommand('collect_forensics')}
                  disabled={sendingCommand}
                  className="bg-purple-600/20 border border-purple-500/30 text-purple-400 hover:bg-purple-600/30"
                >
                  <FileSearch className="w-4 h-4 mr-2" />
                  Collect Forensics
                </Button>
                <Button 
                  onClick={() => handleSendCommand('update_agent')}
                  disabled={sendingCommand}
                  className="bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600/30"
                >
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Update Agent
                </Button>
                <Button 
                  onClick={() => handleSendCommand('restart_service')}
                  disabled={sendingCommand}
                  className="bg-amber-600/20 border border-amber-500/30 text-amber-400 hover:bg-amber-600/30"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Restart Service
                </Button>
              </div>
              <p className="text-slate-500 text-xs mt-4 text-center">
                Commands require approval before execution
              </p>
            </CardContent>
          </Card>

          {/* Recent Alerts */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                  Recent Alerts
                </span>
                <Button size="sm" variant="ghost" onClick={() => setActiveTab('alerts')}>
                  View All <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {alerts.length > 0 ? (
                <div className="space-y-2">
                  {alerts.slice(0, 5).map((alert, idx) => (
                    <div key={idx} className={`p-3 rounded-lg border ${getSeverityColor(alert.severity)}`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-sm">{alert.alert_type}</span>
                        <Badge className={getSeverityColor(alert.severity)}>
                          {alert.severity}
                        </Badge>
                      </div>
                      <p className="text-sm opacity-80">{alert.message}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-slate-400">
                  <CheckCircle className="w-12 h-12 mx-auto mb-4 opacity-50 text-green-400" />
                  <p>No alerts from this agent</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Recent Scans */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <FileSearch className="w-5 h-5 text-cyan-400" />
                  Recent Scans
                </span>
                <Button size="sm" variant="ghost" onClick={() => setActiveTab('scans')}>
                  View All <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {scanResults.length > 0 ? (
                <div className="space-y-2">
                  {scanResults.slice(0, 5).map((scan, idx) => (
                    <div key={idx} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-white text-sm">{scan.scan_type}</span>
                        <span className="text-slate-400 text-xs">
                          {new Date(scan.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-slate-400 text-xs">
                        {JSON.stringify(scan.results).slice(0, 100)}...
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-slate-400">
                  <FileSearch className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No scan results yet</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Alerts Tab */}
      {activeTab === 'alerts' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              Agent Alerts ({alerts.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {alerts.length > 0 ? (
              <div className="space-y-3">
                {alerts.map((alert, idx) => (
                  <div key={idx} className={`p-4 rounded-lg border ${getSeverityColor(alert.severity)}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        <span className="font-medium">{alert.alert_type}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getSeverityColor(alert.severity)}>
                          {alert.severity}
                        </Badge>
                        <span className="text-xs opacity-70">
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    <p className="text-sm mb-2">{alert.message}</p>
                    {alert.details && (
                      <pre className="text-xs bg-black/30 p-2 rounded overflow-x-auto">
                        {JSON.stringify(alert.details, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-400">
                <CheckCircle className="w-16 h-16 mx-auto mb-4 opacity-50 text-green-400" />
                <p className="text-lg font-medium">No Alerts</p>
                <p className="text-sm">This agent has not reported any alerts</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Scans Tab */}
      {activeTab === 'scans' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <FileSearch className="w-5 h-5 text-cyan-400" />
              Scan Results ({scanResults.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {scanResults.length > 0 ? (
              <div className="space-y-4">
                {scanResults.map((scan, idx) => (
                  <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-cyan-400" />
                        <span className="font-medium text-white">{scan.scan_type}</span>
                      </div>
                      <span className="text-slate-400 text-sm">
                        {new Date(scan.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <pre className="text-sm bg-black/30 p-3 rounded overflow-x-auto text-slate-300">
                      {JSON.stringify(scan.results, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-400">
                <FileSearch className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg font-medium">No Scan Results</p>
                <p className="text-sm">Run a scan to see results here</p>
                <Button 
                  onClick={() => handleSendCommand('full_scan')}
                  className="mt-4 bg-cyan-600 hover:bg-cyan-500"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Run Full Scan
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Commands Tab */}
      {activeTab === 'commands' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Terminal className="w-5 h-5 text-green-400" />
              Command History ({commandHistory.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {commandHistory.length > 0 ? (
              <div className="space-y-3">
                {commandHistory.map((cmd, idx) => (
                  <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-green-400" />
                        <span className="font-medium text-white">{cmd.command_name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getStatusColor(cmd.status)}>
                          {cmd.status?.replace(/_/g, ' ')}
                        </Badge>
                        <Badge variant="outline" className="text-slate-400">
                          {cmd.priority}
                        </Badge>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4 text-sm text-slate-400 mb-2">
                      <div>Created: {new Date(cmd.created_at).toLocaleString()}</div>
                      <div>By: {cmd.created_by}</div>
                    </div>
                    <div className="text-xs bg-black/30 p-2 rounded">
                      <span className="text-slate-500">Parameters:</span>{' '}
                      <span className="text-slate-300">{JSON.stringify(cmd.parameters)}</span>
                    </div>
                    {cmd.result && (
                      <div className="mt-2 text-xs bg-green-500/10 p-2 rounded border border-green-500/30">
                        <span className="text-green-400">Result:</span>{' '}
                        <span className="text-slate-300">{JSON.stringify(cmd.result)}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-400">
                <Terminal className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg font-medium">No Commands Sent</p>
                <p className="text-sm">Send a command to see history here</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AgentDetailsPage;
