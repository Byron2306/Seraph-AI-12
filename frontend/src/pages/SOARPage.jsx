import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Workflow, Play, Pause, Plus, Trash2, Edit, Clock, 
  CheckCircle, XCircle, AlertTriangle, Zap, Shield,
  ChevronRight, Settings, RefreshCw, Eye, Activity,
  Brain, Target, Terminal, Cpu, Network, Lock, Key, Tag, Archive
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const SOARPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [aiPlaybooks, setAiPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('all');

  const headers = { Authorization: `Bearer ${token}` };

  // AI-Agentic Defense Playbooks (loaded from YAML config)
  const AI_PLAYBOOK_DEFINITIONS = [
    {
      id: 'AI-RECON-DEGRADE-01',
      name: 'Machine-Paced Recon Loop — Degrade + Observe',
      trigger: 'cli.session_summary',
      description: 'Detect and slow down machine-paced reconnaissance. Applies soft throttle and latency injection.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', dominant_intents: ['recon'], burstiness: '≥ 0.75' },
      actions: ['tag_session', 'throttle_cli', 'inject_latency', 'capture_triage_bundle', 'notify'],
      severity: 'medium',
      status: 'active'
    },
    {
      id: 'AI-DECOY-HIT-CONTAIN-01',
      name: 'Decoy/Honey Token Hit — Immediate Containment',
      trigger: 'deception.hit',
      description: 'Immediately isolate host when a honey token is accessed. High confidence intrusion indicator.',
      category: 'ai_defense',
      conditions: { severity: ['high', 'critical'], token_accessed: true },
      actions: ['isolate_host', 'capture_triage_bundle', 'kill_process_tree', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    },
    {
      id: 'AI-CRED-ACCESS-RESP-01',
      name: 'Credential Access Pattern — Decoy + Credential Controls',
      trigger: 'cli.session_summary',
      description: 'AI-style credential access detected. Triggers credential rotation and hard throttling.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', dominant_intents: ['credential_access'] },
      actions: ['rotate_credentials', 'throttle_cli', 'inject_latency', 'capture_triage_bundle', 'notify'],
      severity: 'high',
      status: 'active'
    },
    {
      id: 'AI-PIVOT-CONTAIN-01',
      name: 'Autonomous Pivot / Toolchain Switching — Contain Fast',
      trigger: 'cli.session_summary',
      description: 'Fast tool switching with lateral movement intent. Immediate host isolation.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', tool_switch_latency: '≤ 300ms', dominant_intents: ['lateral_movement', 'privilege_escalation'] },
      actions: ['isolate_host', 'capture_triage_bundle', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    },
    {
      id: 'AI-EXFIL-PREP-CUT-01',
      name: 'Exfil Prep — Cut Egress + Snapshot',
      trigger: 'cli.session_summary',
      description: 'Detect data staging and exfiltration preparation. Cut network egress immediately.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', dominant_intents: ['exfil_prep', 'data_staging'] },
      actions: ['isolate_host', 'capture_triage_bundle', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    },
    {
      id: 'AI-HIGHCONF-ERADICATE-01',
      name: 'High Confidence Agentic Intrusion — Full Containment',
      trigger: 'cli.session_summary',
      description: 'Machine likelihood ≥ 0.92 with decoy touched. Full containment and eradication.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.92', decoy_touched: true },
      actions: ['isolate_host', 'kill_process_tree', 'capture_memory_snapshot', 'capture_triage_bundle', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    }
  ];

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, playbooksRes, templatesRes, executionsRes] = await Promise.all([
        axios.get(`${API}/soar/stats`, { headers }),
        axios.get(`${API}/soar/playbooks`, { headers }),
        axios.get(`${API}/soar/templates`, { headers }),
        axios.get(`${API}/soar/executions?limit=20`, { headers })
      ]);
      setStats(statsRes.data);
      setPlaybooks(playbooksRes.data.playbooks || []);
      setTemplates(templatesRes.data.templates || []);
      setAiPlaybooks(AI_PLAYBOOK_DEFINITIONS);
      setExecutions(executionsRes.data.executions || []);
    } catch (err) {
      toast.error('Failed to load SOAR data');
    } finally {
      setLoading(false);
    }
  };

  const handleTogglePlaybook = async (playbookId) => {
    try {
      await axios.post(`${API}/soar/playbooks/${playbookId}/toggle`, {}, { headers });
      toast.success('Playbook status updated');
      fetchData();
    } catch (err) {
      toast.error('Failed to toggle playbook');
    }
  };

  const handleExecutePlaybook = async (playbookId) => {
    try {
      const res = await axios.post(`${API}/soar/playbooks/${playbookId}/execute`, {
        trigger_type: 'manual',
        severity: 'medium'
      }, { headers });
      toast.success('Playbook executed successfully');
      fetchData();
    } catch (err) {
      toast.error('Failed to execute playbook');
    }
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'completed': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'failed': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'partial': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'running': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getTriggerIcon = (trigger) => {
    switch(trigger) {
      case 'malware_found': return <Shield className="w-4 h-4 text-red-400" />;
      case 'ransomware_detected': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'ioc_match': return <Zap className="w-4 h-4 text-amber-400" />;
      case 'suspicious_process': return <Activity className="w-4 h-4 text-purple-400" />;
      case 'honeypot_triggered': return <Eye className="w-4 h-4 text-cyan-400" />;
      case 'cli.session_summary': return <Brain className="w-4 h-4 text-purple-400" />;
      case 'deception.hit': return <Target className="w-4 h-4 text-red-400" />;
      default: return <Workflow className="w-4 h-4 text-slate-400" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getActionIcon = (action) => {
    if (action.includes('isolate') || action.includes('block')) return <Lock className="w-3 h-3" />;
    if (action.includes('kill') || action.includes('terminate')) return <XCircle className="w-3 h-3" />;
    if (action.includes('capture') || action.includes('triage') || action.includes('memory')) return <Terminal className="w-3 h-3" />;
    if (action.includes('notify') || action.includes('alert')) return <Activity className="w-3 h-3" />;
    if (action.includes('throttle') || action.includes('latency') || action.includes('tarpit')) return <Cpu className="w-3 h-3" />;
    if (action.includes('decoy') || action.includes('honeypot') || action.includes('disinfo')) return <Shield className="w-3 h-3" />;
    if (action.includes('rotate') || action.includes('credential')) return <Key className="w-3 h-3" />;
    if (action.includes('tag') || action.includes('session')) return <Tag className="w-3 h-3" />;
    if (action.includes('quarantine') || action.includes('sandbox')) return <Archive className="w-3 h-3" />;
    return <Zap className="w-3 h-3" />;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="soar-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Workflow className="w-6 h-6 text-cyan-400" />
            SOAR Playbooks
          </h1>
          <p className="text-slate-400 text-sm mt-1">Security Orchestration, Automation & Response</p>
        </div>
        <Button onClick={fetchData} variant="outline" className="border-cyan-500/50 text-cyan-400">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
              <Workflow className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Total Playbooks</p>
              <p className="text-2xl font-bold text-white">{stats?.total_playbooks || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Play className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Active</p>
              <p className="text-2xl font-bold text-green-400">{stats?.active_playbooks || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Executions</p>
              <p className="text-2xl font-bold text-white">{stats?.total_executions || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Success Rate</p>
              <p className="text-2xl font-bold text-green-400">{stats?.success_rate || 0}%</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <XCircle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Failed</p>
              <p className="text-2xl font-bold text-red-400">{stats?.executions_failed || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Playbooks Section with Tabs */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Workflow className="w-5 h-5 text-cyan-400" />
              Playbooks
            </div>
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="bg-slate-800/50">
                <TabsTrigger value="all" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400">
                  All ({playbooks.length})
                </TabsTrigger>
                <TabsTrigger value="templates" className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400">
                  Templates ({templates.length})
                </TabsTrigger>
                <TabsTrigger value="ai" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400">
                  <Brain className="w-4 h-4 mr-1" />
                  AI Defense ({aiPlaybooks.length})
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Standard Playbooks */}
          {activeTab === 'all' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {playbooks.map((pb) => (
                <motion.div
                  key={pb.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className={`p-4 rounded-lg border ${pb.status === 'active' ? 'bg-slate-800/50 border-slate-700' : 'bg-slate-900/30 border-slate-800'}`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {getTriggerIcon(pb.trigger)}
                      <div>
                        <h3 className="text-white font-medium">{pb.name}</h3>
                        <p className="text-slate-400 text-xs">{pb.description}</p>
                      </div>
                    </div>
                    <Switch 
                      checked={pb.status === 'active'} 
                      onCheckedChange={() => handleTogglePlaybook(pb.id)}
                    />
                  </div>

                  <div className="flex flex-wrap gap-2 mb-3">
                    <Badge variant="outline" className="text-xs text-cyan-400 border-cyan-500/30">
                      {pb.trigger.replace(/_/g, ' ')}
                    </Badge>
                    <Badge variant="outline" className="text-xs text-purple-400 border-purple-500/30">
                      {pb.steps?.length || 0} steps
                    </Badge>
                    {pb.execution_count > 0 && (
                      <Badge variant="outline" className="text-xs text-green-400 border-green-500/30">
                        {pb.execution_count} runs
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {pb.last_executed ? new Date(pb.last_executed).toLocaleString() : 'Never executed'}
                    </span>
                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 px-2 text-slate-400 hover:text-white"
                        onClick={() => setSelectedPlaybook(pb)}
                      >
                        <Eye className="w-4 h-4" />
                      </Button>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 px-2 text-green-400 hover:text-green-300"
                        onClick={() => handleExecutePlaybook(pb.id)}
                        disabled={pb.status !== 'active'}
                      >
                        <Play className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          {/* Templates Library */}
          {activeTab === 'templates' && (
            <div className="space-y-4">
              <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg mb-4">
                <div className="flex items-center gap-3 mb-2">
                  <Shield className="w-6 h-6 text-green-400" />
                  <div>
                    <h3 className="text-white font-semibold">Playbook Templates Library</h3>
                    <p className="text-slate-400 text-sm">Pre-built response templates for common security scenarios</p>
                  </div>
                </div>
                <p className="text-green-300 text-xs">
                  Click "Deploy" to create a new playbook from any template. Templates include data breach, credential theft, APT detection, and more.
                </p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {templates.map((tpl, idx) => (
                  <motion.div
                    key={tpl.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-green-500/50 transition-all"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                          <Shield className="w-5 h-5 text-green-400" />
                        </div>
                        <div>
                          <h3 className="text-white font-medium">{tpl.name}</h3>
                          <p className="text-slate-400 text-xs mt-1 line-clamp-2">{tpl.description}</p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex flex-wrap gap-2 mb-3">
                      <Badge variant="outline" className="text-xs text-cyan-400 border-cyan-500/30">
                        {tpl.category?.replace(/_/g, ' ')}
                      </Badge>
                      <Badge variant="outline" className="text-xs text-purple-400 border-purple-500/30">
                        {tpl.steps?.length || 0} steps
                      </Badge>
                      {tpl.is_official && (
                        <Badge variant="outline" className="text-xs text-green-400 border-green-500/30">
                          Official
                        </Badge>
                      )}
                    </div>

                    {tpl.tags && tpl.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {tpl.tags.slice(0, 4).map((tag, i) => (
                          <span key={i} className="px-2 py-0.5 rounded text-xs bg-slate-700 text-slate-300">
                            {tag}
                          </span>
                        ))}
                        {tpl.tags.length > 4 && (
                          <span className="px-2 py-0.5 rounded text-xs bg-slate-700 text-slate-400">
                            +{tpl.tags.length - 4}
                          </span>
                        )}
                      </div>
                    )}
                    
                    <div className="flex items-center justify-between pt-2 border-t border-slate-700">
                      <span className="text-xs text-slate-500">{tpl.id}</span>
                      <Button 
                        size="sm" 
                        className="h-7 bg-green-500/20 hover:bg-green-500/30 text-green-400"
                        onClick={() => {
                          toast.success(`Template "${tpl.name}" ready to deploy`);
                        }}
                      >
                        <Plus className="w-3 h-3 mr-1" />
                        Deploy
                      </Button>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}

          {/* AI-Agentic Defense Playbooks */}
          {activeTab === 'ai' && (
            <div className="space-y-4">
              <div className="p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg mb-4">
                <div className="flex items-center gap-3 mb-2">
                  <Brain className="w-6 h-6 text-purple-400" />
                  <div>
                    <h3 className="text-white font-semibold">AI-Agentic Defense Playbook Pack</h3>
                    <p className="text-slate-400 text-sm">Machine-paced intrusion detection and autonomous response</p>
                  </div>
                </div>
                <p className="text-purple-300 text-xs">
                  These playbooks analyze CLI session patterns via the Cognition Engine to detect and disrupt AI-driven attacks.
                  Responses follow the "Slow & Poison" philosophy: degrade operations before full containment.
                </p>
              </div>
              
              <div className="grid grid-cols-1 gap-4">
                {aiPlaybooks.map((pb, idx) => (
                  <motion.div
                    key={pb.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="p-4 rounded-lg bg-gradient-to-r from-purple-500/10 to-slate-800/50 border border-purple-500/30 hover:border-purple-500/50 transition-all"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                          {getTriggerIcon(pb.trigger)}
                        </div>
                        <div>
                          <h3 className="text-white font-medium">{pb.name}</h3>
                          <p className="text-slate-400 text-sm mt-1">{pb.description}</p>
                        </div>
                      </div>
                      <Badge className={getSeverityColor(pb.severity)}>
                        {pb.severity.toUpperCase()}
                      </Badge>
                    </div>
                    
                    {/* Trigger Conditions */}
                    <div className="mb-3 p-3 bg-slate-900/50 rounded-lg">
                      <p className="text-slate-400 text-xs mb-2 font-semibold">TRIGGER CONDITIONS</p>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(pb.conditions).map(([key, value]) => (
                          <span key={key} className="px-2 py-1 rounded text-xs bg-slate-800 text-slate-300">
                            <span className="text-cyan-400">{key.replace(/_/g, ' ')}</span>: {Array.isArray(value) ? value.join(', ') : String(value)}
                          </span>
                        ))}
                      </div>
                    </div>
                    
                    {/* Actions */}
                    <div className="mb-3">
                      <p className="text-slate-400 text-xs mb-2 font-semibold">RESPONSE ACTIONS</p>
                      <div className="flex flex-wrap gap-2">
                        {pb.actions.map((action, i) => (
                          <span key={i} className="px-2 py-1 rounded text-xs bg-purple-500/20 text-purple-300 flex items-center gap-1">
                            {getActionIcon(action)}
                            {action.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span className="flex items-center gap-1 text-purple-400">
                        <Cpu className="w-3 h-3" />
                        ID: {pb.id}
                      </span>
                      <Badge variant="outline" className="text-green-400 border-green-500/30">
                        <CheckCircle className="w-3 h-3 mr-1" />
                        {pb.status}
                      </Badge>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Executions */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-400" />
            Recent Executions
          </CardTitle>
        </CardHeader>
        <CardContent>
          {executions.length > 0 ? (
            <div className="space-y-2">
              {executions.map((exec) => (
                <div key={exec.id} 
                  className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center gap-4">
                    <div className={`w-8 h-8 rounded flex items-center justify-center ${getStatusColor(exec.status)}`}>
                      {exec.status === 'completed' ? <CheckCircle className="w-4 h-4" /> :
                       exec.status === 'failed' ? <XCircle className="w-4 h-4" /> :
                       exec.status === 'partial' ? <AlertTriangle className="w-4 h-4" /> :
                       <RefreshCw className="w-4 h-4 animate-spin" />}
                    </div>
                    <div>
                      <p className="text-white text-sm font-medium">{exec.playbook_name}</p>
                      <p className="text-slate-400 text-xs">
                        {exec.step_results?.length || 0} steps executed
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge variant="outline" className={getStatusColor(exec.status)}>
                      {exec.status}
                    </Badge>
                    <span className="text-slate-500 text-xs">
                      {new Date(exec.started_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No executions yet</p>
              <p className="text-sm">Playbooks will run automatically when triggered</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Playbook Detail Modal */}
      {selectedPlaybook && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedPlaybook(null)}>
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-slate-800 border border-slate-700 rounded-lg w-full max-w-2xl max-h-[80vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="p-6 border-b border-slate-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {getTriggerIcon(selectedPlaybook.trigger)}
                  <div>
                    <h2 className="text-lg font-semibold text-white">{selectedPlaybook.name}</h2>
                    <p className="text-sm text-slate-400">{selectedPlaybook.description}</p>
                  </div>
                </div>
                <button onClick={() => setSelectedPlaybook(null)} className="text-slate-400 hover:text-white">
                  ×
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Trigger</h3>
                <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30">
                  {selectedPlaybook.trigger.replace(/_/g, ' ').toUpperCase()}
                </Badge>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Conditions</h3>
                <pre className="text-xs bg-slate-900 p-3 rounded overflow-auto text-slate-300">
                  {JSON.stringify(selectedPlaybook.trigger_conditions, null, 2)}
                </pre>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Steps ({selectedPlaybook.steps?.length || 0})</h3>
                <div className="space-y-2">
                  {selectedPlaybook.steps?.map((step, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-3 bg-slate-900/50 rounded-lg">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs font-bold">
                        {idx + 1}
                      </div>
                      <div className="flex-1">
                        <p className="text-white text-sm font-medium">
                          {step.action.replace(/_/g, ' ').toUpperCase()}
                        </p>
                        <p className="text-slate-400 text-xs">
                          Timeout: {step.timeout}s | Continue on failure: {step.continue_on_failure ? 'Yes' : 'No'}
                        </p>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex gap-3 pt-4 border-t border-slate-700">
                <Button 
                  className="flex-1 bg-green-600 hover:bg-green-500"
                  onClick={() => {
                    handleExecutePlaybook(selectedPlaybook.id);
                    setSelectedPlaybook(null);
                  }}
                  disabled={selectedPlaybook.status !== 'active'}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Execute Now
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default SOARPage;
