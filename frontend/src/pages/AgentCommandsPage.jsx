import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  Terminal, Shield, AlertTriangle, CheckCircle, XCircle,
  RefreshCw, Send, Clock, Activity, Cpu, HardDrive,
  Users, Eye, Lock, Trash2, Play, Pause, ChevronDown, ChevronRight, ExternalLink, Brain
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const AgentCommandsPage = () => {
  const navigate = useNavigate();
  const { token } = useAuth();
  const [agents, setAgents] = useState([]);
  const [connectedAgents, setConnectedAgents] = useState([]);
  const [pendingCommands, setPendingCommands] = useState([]);
  const [commandHistory, setCommandHistory] = useState([]);
  const [commandTypes, setCommandTypes] = useState({});
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [agentAlerts, setAgentAlerts] = useState([]);
  const [agentScans, setAgentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('agents');
  
  // Command creation form
  const [newCommand, setNewCommand] = useState({
    agent_id: '',
    command_type: '',
    parameters: {},
    priority: 'medium'
  });
  const [aiObjective, setAiObjective] = useState('Contain suspicious beaconing and collect forensics');
  const [aiRecommending, setAiRecommending] = useState(false);
  const [expandedAlerts, setExpandedAlerts] = useState({});

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [token]);

  const fetchData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [agentsRes, connectedRes, pendingRes, historyRes, typesRes] = await Promise.all([
        fetch(`${API_URL}/api/agent-commands/agents/status`, { headers }),
        fetch(`${API_URL}/api/agent-commands/agents/connected`, { headers }),
        fetch(`${API_URL}/api/agent-commands/pending`, { headers }),
        fetch(`${API_URL}/api/agent-commands/history?limit=50`, { headers }),
        fetch(`${API_URL}/api/agent-commands/types`, { headers })
      ]);

      if (agentsRes.ok) setAgents((await agentsRes.json()).agents || []);
      if (connectedRes.ok) setConnectedAgents((await connectedRes.json()).agents || []);
      if (pendingRes.ok) setPendingCommands((await pendingRes.json()).commands || []);
      if (historyRes.ok) setCommandHistory((await historyRes.json()).commands || []);
      if (typesRes.ok) setCommandTypes((await typesRes.json()).command_types || {});
    } catch (error) {
      console.error('Failed to fetch agent data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchAgentDetails = async (agentId) => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [alertsRes, scansRes] = await Promise.all([
        fetch(`${API_URL}/api/agent-commands/agents/${agentId}/alerts`, { headers }),
        fetch(`${API_URL}/api/agent-commands/agents/${agentId}/scan-results`, { headers })
      ]);

      if (alertsRes.ok) setAgentAlerts((await alertsRes.json()).alerts || []);
      if (scansRes.ok) setAgentScans((await scansRes.json()).results || []);
      setSelectedAgent(agentId);
    } catch (error) {
      toast.error('Failed to fetch agent details');
    }
  };

  const createCommand = async () => {
    if (!newCommand.agent_id || !newCommand.command_type) {
      toast.error('Select agent and command type');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/agent-commands/create`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newCommand)
      });

      if (response.ok) {
        toast.success('Command created - pending approval');
        setNewCommand({ agent_id: '', command_type: '', parameters: {}, priority: 'medium' });
        fetchData();
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to create command');
      }
    } catch (error) {
      toast.error('Failed to create command');
    }
  };

  const approveCommand = async (commandId, approved) => {
    try {
      const response = await fetch(`${API_URL}/api/agent-commands/${commandId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ approved, notes: '' })
      });

      if (response.ok) {
        toast.success(approved ? 'Command approved' : 'Command rejected');
        fetchData();
      } else {
        toast.error('Failed to update command');
      }
    } catch (error) {
      toast.error('Failed to update command');
    }
  };

  const recommendWithAI = async () => {
    setAiRecommending(true);
    try {
      const response = await fetch(`${API_URL}/api/agent-commands/recommend`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          objective: aiObjective,
          agent_id: newCommand.agent_id || selectedAgent || null,
          context: {
            selected_agent: selectedAgent,
            alert_count: agentAlerts.length,
            recent_scan_count: agentScans.length
          },
          max_recommendations: 3
        })
      });

      if (!response.ok) {
        toast.error('AI recommendation failed');
        return;
      }

      const data = await response.json();
      const first = data.recommended_commands?.[0];
      if (!first) {
        toast.warning('No recommendations returned');
        return;
      }

      setNewCommand((prev) => ({
        ...prev,
        command_type: first.command_type || prev.command_type,
        priority: first.priority || prev.priority,
        parameters: first.parameters || {}
      }));
      toast.success(`AI recommendation applied (${data.method || 'assistant'})`);
    } catch (error) {
      toast.error('AI recommendation failed');
    } finally {
      setAiRecommending(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'connected': return 'bg-green-500';
      case 'pending_approval': return 'bg-amber-500';
      case 'approved': case 'sent_to_agent': return 'bg-blue-500';
      case 'completed': return 'bg-green-500';
      case 'failed': case 'rejected': return 'bg-red-500';
      default: return 'bg-slate-500';
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'critical': return 'text-red-400 bg-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/20';
      case 'medium': return 'text-amber-400 bg-amber-500/20';
      case 'low': return 'text-green-400 bg-green-500/20';
      default: return 'text-slate-400 bg-slate-500/20';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-purple-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="agent-commands-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-purple-400" />
            Agent Command Center
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Send commands to agents and monitor responses
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 border border-green-500/30 rounded">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
            <span className="text-green-400 text-sm font-medium">
              {connectedAgents.length} Agent{connectedAgents.length !== 1 ? 's' : ''} Connected
            </span>
          </div>
          <Button onClick={fetchData} variant="outline" className="border-slate-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-green-500/20 flex items-center justify-center">
              <Activity className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{agents.length}</p>
              <p className="text-slate-400 text-sm">Registered Agents</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-amber-500/20 flex items-center justify-center">
              <Clock className="w-6 h-6 text-amber-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{pendingCommands.length}</p>
              <p className="text-slate-400 text-sm">Pending Approval</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
              <Send className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{commandHistory.length}</p>
              <p className="text-slate-400 text-sm">Total Commands</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <Terminal className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{Object.keys(commandTypes).length}</p>
              <p className="text-slate-400 text-sm">Command Types</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {['agents', 'pending', 'new-command', 'history'].map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab)}
            className={activeTab === tab ? 'bg-purple-600 hover:bg-purple-700' : 'text-slate-400'}
          >
            {tab === 'new-command' ? 'Send Command' : tab.charAt(0).toUpperCase() + tab.slice(1).replace('-', ' ')}
          </Button>
        ))}
      </div>

      {/* Agents Tab */}
      {activeTab === 'agents' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Registered Agents</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {agents.length === 0 ? (
                <p className="text-slate-500 text-center py-4">No agents registered yet. Run the advanced agent to connect.</p>
              ) : (
                agents.map((agent) => (
                  <div
                    key={agent.agent_id}
                    className={`p-4 rounded-lg border cursor-pointer transition-all ${
                      selectedAgent === agent.agent_id
                        ? 'bg-purple-500/10 border-purple-500/50'
                        : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'
                    }`}
                    onClick={() => fetchAgentDetails(agent.agent_id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-3 h-3 rounded-full ${agent.connected ? 'bg-green-400' : 'bg-slate-500'}`} />
                        <div>
                          <p className="text-white font-medium">{agent.hostname || agent.agent_id}</p>
                          <p className="text-slate-500 text-xs">{agent.os} | {agent.ip_address}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/agent-commands/${agent.agent_id}`);
                          }}
                        >
                          <ExternalLink className="w-4 h-4 mr-1" />
                          Details
                        </Button>
                        <ChevronRight className="w-5 h-5 text-slate-500" />
                      </div>
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          {/* Agent Details */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">
                {selectedAgent ? `Agent: ${selectedAgent}` : 'Select an Agent'}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {selectedAgent ? (
                <div className="space-y-4">
                  {/* Recent Alerts */}
                  <div>
                    <h4 className="text-white font-medium mb-2 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      Recent Alerts ({agentAlerts.length})
                    </h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {agentAlerts.length === 0 ? (
                        <p className="text-slate-500 text-sm">No alerts</p>
                      ) : (
                        agentAlerts.slice(0, 5).map((alert, idx) => (
                          <div key={idx} className={`p-2 rounded text-sm ${getRiskColor(alert.severity)}`}>
                            <div className="flex items-center justify-between">
                              <span className="font-medium">{alert.alert_type}</span>
                              <Badge variant="outline" className="text-xs">{alert.severity}</Badge>
                            </div>
                            <p className="text-slate-300 text-xs mt-1">{alert.message}</p>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Recent Scans */}
                  <div>
                    <h4 className="text-white font-medium mb-2 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-blue-400" />
                      Recent Scans ({agentScans.length})
                    </h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {agentScans.length === 0 ? (
                        <p className="text-slate-500 text-sm">No scans yet</p>
                      ) : (
                        agentScans.slice(0, 5).map((scan, idx) => (
                          <div key={idx} className="p-2 bg-slate-800 rounded text-sm">
                            <div className="flex items-center justify-between">
                              <span className="text-white">{scan.scan_type}</span>
                              <span className="text-slate-500 text-xs">
                                {new Date(scan.timestamp).toLocaleString()}
                              </span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <Button
                    className="w-full bg-purple-600 hover:bg-purple-700"
                    onClick={() => {
                      setNewCommand({ ...newCommand, agent_id: selectedAgent });
                      setActiveTab('new-command');
                    }}
                  >
                    <Send className="w-4 h-4 mr-2" />
                    Send Command to This Agent
                  </Button>
                </div>
              ) : (
                <p className="text-slate-500 text-center py-8">
                  Click on an agent to view details and alerts
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Pending Approval Tab */}
      {activeTab === 'pending' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Clock className="w-5 h-5 text-amber-400" />
              Commands Pending Approval
            </CardTitle>
          </CardHeader>
          <CardContent>
            {pendingCommands.length === 0 ? (
              <p className="text-slate-500 text-center py-8">No commands pending approval</p>
            ) : (
              <div className="space-y-3">
                {pendingCommands.map((cmd) => (
                  <div key={cmd.command_id} className="p-4 bg-slate-800/50 rounded-lg border border-amber-500/30">
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <p className="text-white font-medium">{cmd.command_name}</p>
                        <p className="text-slate-500 text-xs">
                          Agent: {cmd.agent_id} | Created by: {cmd.created_by}
                        </p>
                      </div>
                      <Badge className={getRiskColor(cmd.risk_level)}>{cmd.risk_level} risk</Badge>
                    </div>
                    
                    <div className="bg-slate-900 p-2 rounded text-xs font-mono text-slate-300 mb-3">
                      {JSON.stringify(cmd.parameters, null, 2)}
                    </div>
                    
                    <div className="flex gap-2">
                      <Button
                        className="flex-1 bg-green-600 hover:bg-green-700"
                        onClick={() => approveCommand(cmd.command_id, true)}
                      >
                        <CheckCircle className="w-4 h-4 mr-2" />
                        Approve
                      </Button>
                      <Button
                        className="flex-1 bg-red-600 hover:bg-red-700"
                        onClick={() => approveCommand(cmd.command_id, false)}
                      >
                        <XCircle className="w-4 h-4 mr-2" />
                        Reject
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* New Command Tab */}
      {activeTab === 'new-command' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Send className="w-5 h-5 text-purple-400" />
              Send Command to Agent
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Agent Selection */}
              <div>
                <label className="text-slate-400 text-sm mb-2 block">Select Agent</label>
                <select
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-white"
                  value={newCommand.agent_id}
                  onChange={(e) => setNewCommand({ ...newCommand, agent_id: e.target.value })}
                >
                  <option value="">-- Select Agent --</option>
                  {agents.map((agent) => (
                    <option key={agent.agent_id} value={agent.agent_id}>
                      {agent.hostname || agent.agent_id} {agent.connected ? '(connected)' : '(offline)'}
                    </option>
                  ))}
                </select>
              </div>

              {/* Command Type */}
              <div>
                <label className="text-slate-400 text-sm mb-2 block">Command Type</label>
                <select
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-white"
                  value={newCommand.command_type}
                  onChange={(e) => setNewCommand({ ...newCommand, command_type: e.target.value })}
                >
                  <option value="">-- Select Command --</option>
                  {Object.entries(commandTypes).map(([key, info]) => (
                    <option key={key} value={key}>
                      {info.name} ({info.risk_level} risk)
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Command Info */}
            {newCommand.command_type && commandTypes[newCommand.command_type] && (
              <div className="p-4 bg-slate-800/50 rounded-lg">
                <h4 className="text-white font-medium mb-2">{commandTypes[newCommand.command_type].name}</h4>
                <p className="text-slate-400 text-sm mb-3">{commandTypes[newCommand.command_type].description}</p>
                
                <div className="flex items-center gap-2 mb-3">
                  <Badge className={getRiskColor(commandTypes[newCommand.command_type].risk_level)}>
                    {commandTypes[newCommand.command_type].risk_level} risk
                  </Badge>
                </div>

                {/* Parameters */}
                {commandTypes[newCommand.command_type].parameters?.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-slate-400 text-sm">Parameters:</p>
                    {commandTypes[newCommand.command_type].parameters.map((param) => (
                      <div key={param}>
                        <label className="text-slate-500 text-xs mb-1 block">{param}</label>
                        <input
                          type="text"
                          className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white text-sm"
                          placeholder={param}
                          value={newCommand.parameters[param] || ''}
                          onChange={(e) => setNewCommand({
                            ...newCommand,
                            parameters: { ...newCommand.parameters, [param]: e.target.value }
                          })}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Priority */}
            <div>
              <label className="text-slate-400 text-sm mb-2 block">Priority</label>
              <div className="flex gap-2">
                {['low', 'medium', 'high', 'critical'].map((priority) => (
                  <Button
                    key={priority}
                    variant={newCommand.priority === priority ? 'default' : 'outline'}
                    className={newCommand.priority === priority ? 'bg-purple-600' : 'border-slate-700'}
                    onClick={() => setNewCommand({ ...newCommand, priority })}
                  >
                    {priority}
                  </Button>
                ))}
              </div>
            </div>

            <div className="p-4 bg-slate-800/40 rounded-lg border border-slate-700 space-y-3">
              <label className="text-slate-300 text-sm block">AI Objective</label>
              <textarea
                className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white text-sm"
                rows={2}
                value={aiObjective}
                onChange={(e) => setAiObjective(e.target.value)}
                placeholder="Describe what you want the agent to accomplish"
              />
              <Button
                type="button"
                variant="outline"
                className="border-purple-500/40 text-purple-300"
                onClick={recommendWithAI}
                disabled={aiRecommending || !aiObjective.trim()}
              >
                <Brain className={`w-4 h-4 mr-2 ${aiRecommending ? 'animate-pulse' : ''}`} />
                {aiRecommending ? 'Analyzing...' : 'Recommend With Ollama'}
              </Button>
            </div>

            <Button
              className="w-full bg-purple-600 hover:bg-purple-700"
              onClick={createCommand}
              disabled={!newCommand.agent_id || !newCommand.command_type}
            >
              <Send className="w-4 h-4 mr-2" />
              Send Command (Requires Approval)
            </Button>
          </CardContent>
        </Card>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white">Command History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {commandHistory.map((cmd) => (
                <div
                  key={cmd.command_id}
                  className="p-3 bg-slate-800/50 rounded-lg flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${getStatusColor(cmd.status)}`} />
                    <div>
                      <p className="text-white text-sm font-medium">{cmd.command_name}</p>
                      <p className="text-slate-500 text-xs">
                        {cmd.agent_id} | {new Date(cmd.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">{cmd.status}</Badge>
                    {cmd.result && (
                      <Badge className={cmd.result.success ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
                        {cmd.result.success ? 'Success' : 'Failed'}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AgentCommandsPage;
