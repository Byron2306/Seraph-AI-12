import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Brain, Shield, AlertTriangle, Activity, Eye, Target,
  Zap, Lock, Unlock, RefreshCw, ChevronRight, Search,
  Database, Clock, Users, Cpu, Network, Terminal,
  TrendingUp, BarChart3, PieChart, FileText, BookOpen,
  Crosshair, Radio, Bot, AlertOctagon, ShieldAlert,
  Gauge, Timer, GitBranch
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { Progress } from '../components/ui/progress';
import { toast } from 'sonner';
import { API_ROOT as API } from '../lib/api';


const AIThreatIntelligence = () => {
  const { token } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  
  // AATL State
  const [aatlSummary, setAatlSummary] = useState(null);
  const [assessments, setAssessments] = useState([]);
  const [strategies, setStrategies] = useState({});
  const [lifecycleStages, setLifecycleStages] = useState({});
  
  // AATR State
  const [aatrSummary, setAatrSummary] = useState(null);
  const [registryEntries, setRegistryEntries] = useState([]);
  const [indicators, setIndicators] = useState([]);
  const [selectedEntry, setSelectedEntry] = useState(null);
  
  // Combined Intelligence
  const [dashboard, setDashboard] = useState(null);

  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [
        dashboardRes,
        aatlSummaryRes,
        assessmentsRes,
        strategiesRes,
        stagesRes,
        aatrSummaryRes,
        entriesRes,
        indicatorsRes
      ] = await Promise.all([
        axios.get(`${API}/ai-threats/intelligence/dashboard`, { headers }),
        axios.get(`${API}/ai-threats/aatl/summary`, { headers }),
        axios.get(`${API}/ai-threats/aatl/assessments?min_threat=0&limit=50`, { headers }),
        axios.get(`${API}/ai-threats/aatl/response-strategies`, { headers }),
        axios.get(`${API}/ai-threats/aatl/lifecycle-stages`, { headers }),
        axios.get(`${API}/ai-threats/aatr/summary`, { headers }),
        axios.get(`${API}/ai-threats/aatr/entries?active_only=true`, { headers }),
        axios.get(`${API}/ai-threats/aatr/indicators`, { headers })
      ]);
      
      setDashboard(dashboardRes.data);
      setAatlSummary(aatlSummaryRes.data);
      setAssessments(assessmentsRes.data.assessments || []);
      setStrategies(strategiesRes.data.strategies || {});
      setLifecycleStages(stagesRes.data.stages || {});
      setAatrSummary(aatrSummaryRes.data);
      setRegistryEntries(entriesRes.data.entries || []);
      setIndicators(indicatorsRes.data.indicators || []);
    } catch (err) {
      console.error('Failed to fetch AI threat intelligence:', err);
      toast.error('Failed to load AI threat intelligence');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getActorTypeIcon = (type) => {
    switch (type) {
      case 'autonomous_agent': return <Bot className="w-5 h-5 text-red-400" />;
      case 'ai_assisted': return <Brain className="w-5 h-5 text-orange-400" />;
      case 'automated_script': return <Terminal className="w-5 h-5 text-yellow-400" />;
      case 'human': return <Users className="w-5 h-5 text-green-400" />;
      default: return <Eye className="w-5 h-5 text-slate-400" />;
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getStrategyColor = (strategy) => {
    switch (strategy) {
      case 'observe': return 'bg-blue-500/20 text-blue-400';
      case 'slow': return 'bg-cyan-500/20 text-cyan-400';
      case 'poison': return 'bg-purple-500/20 text-purple-400';
      case 'deceive': return 'bg-pink-500/20 text-pink-400';
      case 'contain': return 'bg-orange-500/20 text-orange-400';
      case 'eradicate': return 'bg-red-500/20 text-red-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-slate-400';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="ai-threat-intelligence">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Brain className="w-8 h-8 text-purple-400" />
            AI Threat Intelligence
          </h1>
          <p className="text-slate-400 mt-1">
            Autonomous Agent Threat Layer (AATL) & AI Threat Registry (AATR)
          </p>
        </div>
        <Button onClick={fetchData} variant="outline" className="border-purple-500/50">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Overview Stats */}
      {dashboard && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="seraph-stat-card p-4 border-l-4 border-purple-500"
          >
            <div className="flex items-center justify-between mb-2">
              <Brain className="w-8 h-8 text-purple-400" />
              <Badge className={getThreatColor(dashboard.combined_threat_score >= 50 ? 'high' : 'medium')}>
                {dashboard.combined_threat_score?.toFixed(0)}% AI Activity
              </Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.aatl?.total_sessions || 0}
            </div>
            <div className="text-slate-400 text-sm">Monitored Sessions</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="seraph-stat-card p-4 border-l-4 border-red-500"
          >
            <div className="flex items-center justify-between mb-2">
              <Bot className="w-8 h-8 text-red-400" />
              <Badge className="bg-red-500/20 text-red-400">Autonomous</Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.aatl?.autonomous_agent_sessions || 0}
            </div>
            <div className="text-slate-400 text-sm">AI Agent Detections</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="seraph-stat-card p-4 border-l-4 border-cyan-500"
          >
            <div className="flex items-center justify-between mb-2">
              <Database className="w-8 h-8 text-cyan-400" />
              <Badge className="bg-cyan-500/20 text-cyan-400">Registry</Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.aatr?.total_entries || 0}
            </div>
            <div className="text-slate-400 text-sm">Known Threat Types</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="seraph-stat-card p-4 border-l-4 border-yellow-500"
          >
            <div className="flex items-center justify-between mb-2">
              <AlertTriangle className="w-8 h-8 text-yellow-400" />
              <Badge className="bg-yellow-500/20 text-yellow-400">Active</Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.active_threat_types || 0}
            </div>
            <div className="text-slate-400 text-sm">Active Threat Types</div>
          </motion.div>
        </div>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-slate-800/50">
          <TabsTrigger value="overview" className="data-[state=active]:bg-purple-500/20">
            <Eye className="w-4 h-4 mr-2" /> AATL Overview
          </TabsTrigger>
          <TabsTrigger value="assessments" className="data-[state=active]:bg-red-500/20">
            <Target className="w-4 h-4 mr-2" /> Threat Assessments
          </TabsTrigger>
          <TabsTrigger value="registry" className="data-[state=active]:bg-cyan-500/20">
            <Database className="w-4 h-4 mr-2" /> AATR Registry
          </TabsTrigger>
          <TabsTrigger value="indicators" className="data-[state=active]:bg-yellow-500/20">
            <Crosshair className="w-4 h-4 mr-2" /> Detection Indicators
          </TabsTrigger>
        </TabsList>

        {/* AATL Overview Tab */}
        <TabsContent value="overview" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Actor Type Distribution */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Users className="w-5 h-5 text-purple-400" />
                  Actor Type Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(aatlSummary?.by_actor_type || {}).map(([type, data]) => (
                    <div key={type} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                      <div className="flex items-center gap-3">
                        {getActorTypeIcon(type)}
                        <div>
                          <span className="text-white capitalize">{type.replace('_', ' ')}</span>
                          <div className="text-xs text-slate-400">
                            Avg Threat: {data.avg_threat?.toFixed(0) || 0}%
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <Badge variant="outline">{data.count || 0}</Badge>
                        <div className="text-xs text-slate-500 mt-1">
                          Max: {data.max_threat?.toFixed(0) || 0}%
                        </div>
                      </div>
                    </div>
                  ))}
                  {Object.keys(aatlSummary?.by_actor_type || {}).length === 0 && (
                    <div className="text-center py-8 text-slate-400">
                      <Bot className="w-12 h-12 mx-auto mb-2 opacity-50" />
                      <p>No AATL assessments yet</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Lifecycle Stage Distribution */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <GitBranch className="w-5 h-5 text-cyan-400" />
                  Attack Lifecycle Stages
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(aatlSummary?.by_lifecycle_stage || {}).map(([stage, count]) => (
                    <div key={stage} className="flex items-center gap-3">
                      <div className="w-32 text-sm text-slate-400 capitalize">
                        {stage.replace('_', ' ')}
                      </div>
                      <div className="flex-1">
                        <Progress 
                          value={(count / (aatlSummary?.total_sessions || 1)) * 100} 
                          className="h-2"
                        />
                      </div>
                      <Badge variant="outline" className="w-12 justify-center">{count}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Response Strategies */}
            <Card className="bg-slate-900/50 border-slate-800 lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-green-400" />
                  AI-Specific Response Strategies
                </CardTitle>
                <CardDescription>
                  Strategies designed for countering autonomous AI agents
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                  {Object.entries(strategies).map(([key, strategy]) => (
                    <div 
                      key={key}
                      className={`p-4 rounded-lg border border-slate-700 hover:border-slate-600 transition-all ${getStrategyColor(key)}`}
                    >
                      <div className="text-lg font-semibold mb-1">{strategy.name}</div>
                      <div className="text-xs opacity-80 mb-2">{strategy.description}</div>
                      <div className="text-xs space-y-1">
                        {strategy.actions?.slice(0, 2).map((action, i) => (
                          <div key={i} className="flex items-center gap-1">
                            <ChevronRight className="w-3 h-3" />
                            {action}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Threat Assessments Tab */}
        <TabsContent value="assessments" className="mt-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Target className="w-5 h-5 text-red-400" />
                Active AATL Assessments ({assessments.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <AnimatePresence>
                  {assessments.map((assessment, idx) => (
                    <motion.div
                      key={`${assessment.host_id}-${assessment.session_id}`}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-purple-500/50 transition-all"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          {getActorTypeIcon(assessment.actor_type)}
                          <div>
                            <div className="text-white font-medium">
                              {assessment.host_id} / {assessment.session_id}
                            </div>
                            <div className="text-sm text-slate-400">
                              {assessment.actor_type?.replace('_', ' ')} • 
                              Confidence: {(assessment.actor_confidence * 100)?.toFixed(0)}%
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getThreatColor(assessment.threat_level)}>
                            {assessment.threat_level} ({assessment.threat_score?.toFixed(0)}%)
                          </Badge>
                          <Badge className={getStrategyColor(assessment.recommended_strategy)}>
                            {assessment.recommended_strategy}
                          </Badge>
                        </div>
                      </div>

                      {/* Machine vs Human Score */}
                      <div className="grid grid-cols-2 gap-4 mb-3">
                        <div>
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className="text-slate-400">Machine Plausibility</span>
                            <span className="text-red-400">{(assessment.machine_plausibility * 100)?.toFixed(0)}%</span>
                          </div>
                          <Progress 
                            value={assessment.machine_plausibility * 100} 
                            className="h-2 bg-slate-700"
                          />
                        </div>
                        <div>
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className="text-slate-400">Human Plausibility</span>
                            <span className="text-green-400">{(assessment.human_plausibility * 100)?.toFixed(0)}%</span>
                          </div>
                          <Progress 
                            value={assessment.human_plausibility * 100} 
                            className="h-2 bg-slate-700"
                          />
                        </div>
                      </div>

                      {/* Intent & Stage */}
                      <div className="flex flex-wrap gap-2 mb-3">
                        <Badge variant="outline" className="text-purple-400 border-purple-500/30">
                          <Brain className="w-3 h-3 mr-1" />
                          Intent: {assessment.intent_accumulation?.primary_intent || 'unknown'}
                        </Badge>
                        <Badge variant="outline" className="text-cyan-400 border-cyan-500/30">
                          <GitBranch className="w-3 h-3 mr-1" />
                          Stage: {assessment.lifecycle_stage?.replace('_', ' ')}
                        </Badge>
                        <Badge variant="outline" className="text-yellow-400 border-yellow-500/30">
                          <Target className="w-3 h-3 mr-1" />
                          Goal Convergence: {(assessment.intent_accumulation?.goal_convergence_score * 100)?.toFixed(0)}%
                        </Badge>
                      </div>

                      {/* Indicators */}
                      {assessment.indicators?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {assessment.indicators.map((indicator, i) => (
                            <span key={i} className="px-2 py-1 rounded text-xs bg-slate-700 text-slate-300">
                              {indicator}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Recommended Actions */}
                      {assessment.recommended_actions?.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-slate-700">
                          <div className="text-xs text-slate-400 mb-2">Recommended Actions:</div>
                          <div className="flex flex-wrap gap-2">
                            {assessment.recommended_actions.map((action, i) => (
                              <Badge key={i} variant="outline" className="text-xs">
                                {action.replace('_', ' ')}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </motion.div>
                  ))}
                </AnimatePresence>

                {assessments.length === 0 && (
                  <div className="text-center py-12 text-slate-400">
                    <Target className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No threat assessments yet. CLI events will generate AATL assessments.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AATR Registry Tab */}
        <TabsContent value="registry" className="mt-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-cyan-400" />
                Autonomous AI Threat Registry ({registryEntries.length} Active Threats)
              </CardTitle>
              <CardDescription>
                Defensive intelligence catalog of AI agent frameworks and behavior patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {registryEntries.map((entry, idx) => (
                  <motion.div
                    key={entry.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className={`p-4 rounded-lg border transition-all cursor-pointer ${
                      selectedEntry?.id === entry.id 
                        ? 'bg-purple-500/10 border-purple-500/50' 
                        : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'
                    }`}
                    onClick={() => setSelectedEntry(selectedEntry?.id === entry.id ? null : entry)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                          entry.risk_profile === 'critical' ? 'bg-red-500/20' :
                          entry.risk_profile === 'high' ? 'bg-orange-500/20' :
                          'bg-yellow-500/20'
                        }`}>
                          <Bot className={`w-6 h-6 ${getRiskColor(entry.risk_profile)}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-white font-semibold">{entry.name}</span>
                            <Badge variant="outline" className="text-xs">{entry.id}</Badge>
                          </div>
                          <div className="text-sm text-slate-400">
                            {entry.classification?.replace('_', ' ')}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getThreatColor(entry.risk_profile)}>
                          {entry.risk_profile}
                        </Badge>
                        <Badge variant="outline" className={
                          entry.threat_status === 'active' ? 'text-green-400 border-green-500/30' :
                          entry.threat_status === 'emerging' ? 'text-yellow-400 border-yellow-500/30' :
                          'text-slate-400'
                        }>
                          {entry.threat_status}
                        </Badge>
                      </div>
                    </div>

                    <p className="text-slate-300 text-sm mb-3">{entry.description}</p>

                    {/* Expanded Details */}
                    <AnimatePresence>
                      {selectedEntry?.id === entry.id && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          className="mt-4 pt-4 border-t border-slate-700 space-y-4"
                        >
                          {/* Observed Capabilities */}
                          <div>
                            <h4 className="text-sm font-semibold text-slate-400 mb-2">Observed Capabilities</h4>
                            <div className="flex flex-wrap gap-2">
                              {entry.observed_capabilities?.map((cap, i) => (
                                <Badge key={i} variant="outline" className="text-cyan-400 border-cyan-500/30">
                                  {cap}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          {/* Known Misuse Patterns */}
                          <div>
                            <h4 className="text-sm font-semibold text-slate-400 mb-2">Known Misuse Patterns</h4>
                            <ul className="list-disc list-inside text-sm text-slate-300 space-y-1">
                              {entry.known_misuse_patterns?.map((pattern, i) => (
                                <li key={i}>{pattern}</li>
                              ))}
                            </ul>
                          </div>

                          {/* Recommended Defenses */}
                          <div>
                            <h4 className="text-sm font-semibold text-slate-400 mb-2">Recommended Defenses</h4>
                            <div className="flex flex-wrap gap-2">
                              {entry.recommended_defenses?.map((defense, i) => (
                                <Badge key={i} className="bg-green-500/20 text-green-400">
                                  <Shield className="w-3 h-3 mr-1" />
                                  {defense}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          {/* Metadata */}
                          <div className="text-xs text-slate-500 flex gap-4">
                            <span>First Observed: {entry.first_observed}</span>
                            <span>Last Updated: {entry.last_updated}</span>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Detection Indicators Tab */}
        <TabsContent value="indicators" className="mt-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-yellow-400" />
                Defensive Detection Indicators ({indicators.length})
              </CardTitle>
              <CardDescription>
                Behavioral markers for identifying autonomous AI agents
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {['timing', 'behavior', 'syntax', 'tool_usage'].map(category => {
                  const categoryIndicators = indicators.filter(i => i.category === category);
                  if (categoryIndicators.length === 0) return null;
                  
                  return (
                    <div key={category} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                      <h3 className="text-white font-semibold mb-3 capitalize flex items-center gap-2">
                        {category === 'timing' && <Timer className="w-4 h-4 text-blue-400" />}
                        {category === 'behavior' && <Activity className="w-4 h-4 text-purple-400" />}
                        {category === 'syntax' && <Terminal className="w-4 h-4 text-green-400" />}
                        {category === 'tool_usage' && <Cpu className="w-4 h-4 text-orange-400" />}
                        {category.replace('_', ' ')} Indicators
                      </h3>
                      <div className="space-y-2">
                        {categoryIndicators.map((indicator, i) => (
                          <div key={i} className="p-2 bg-slate-900/50 rounded text-sm">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-slate-300 font-mono text-xs">
                                {indicator.indicator}
                              </span>
                              <Badge variant="outline" className="text-xs">
                                {(indicator.confidence * 100).toFixed(0)}%
                              </Badge>
                            </div>
                            <p className="text-slate-500 text-xs">{indicator.description}</p>
                            <div className="text-xs text-slate-600 mt-1">
                              From: {indicator.threat_name}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AIThreatIntelligence;
