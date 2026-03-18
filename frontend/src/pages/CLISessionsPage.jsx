import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Terminal, Activity, AlertTriangle, Shield, RefreshCw,
  Brain, Zap, Clock, Target, Eye, TrendingUp, 
  AlertCircle, CheckCircle, XCircle, ChevronRight,
  Cpu, Monitor, User, Play, Pause
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Progress } from '../components/ui/progress';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const CLISessionsPage = () => {
  const { token } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [commands, setCommands] = useState([]);
  const [deceptionHits, setDeceptionHits] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    try {
      // Fetch session summaries from all hosts
      const [sessionsRes, hitsRes] = await Promise.all([
        axios.get(`${API}/cli/sessions/all?limit=50`, { headers }).catch(() => ({ data: { summaries: [] } })),
        axios.get(`${API}/deception/hits?limit=20`, { headers }).catch(() => ({ data: { hits: [] } }))
      ]);

      setSessions(sessionsRes.data.summaries || []);
      setDeceptionHits(hitsRes.data.hits || []);

      // Calculate stats
      const allSessions = sessionsRes.data.summaries || [];
      const highRisk = allSessions.filter(s => s.machine_likelihood >= 0.8);
      const criticalRisk = allSessions.filter(s => s.machine_likelihood >= 0.92);
      const avgML = allSessions.length > 0 
        ? allSessions.reduce((sum, s) => sum + s.machine_likelihood, 0) / allSessions.length 
        : 0;

      setStats({
        totalSessions: allSessions.length,
        highRiskSessions: highRisk.length,
        criticalRiskSessions: criticalRisk.length,
        averageML: avgML,
        deceptionHits: (hitsRes.data.hits || []).length
      });

    } catch (err) {
      console.error('Failed to fetch CLI session data:', err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  const fetchSessionCommands = async (hostId, sessionId) => {
    try {
      const res = await axios.get(`${API}/cli/commands/${hostId}?session_id=${sessionId}&limit=100`, { headers });
      setCommands(res.data.commands || []);
    } catch (err) {
      console.error('Failed to fetch commands:', err);
      setCommands([]);
    }
  };

  useEffect(() => {
    fetchData();
    
    if (autoRefresh) {
      const interval = setInterval(fetchData, 10000); // Refresh every 10s
      return () => clearInterval(interval);
    }
  }, [fetchData, autoRefresh]);

  const handleSessionClick = (session) => {
    setSelectedSession(session);
    fetchSessionCommands(session.host_id, session.session_id);
  };

  const getMachineLikelihoodColor = (ml) => {
    if (ml >= 0.92) return 'text-red-400 bg-red-500/20';
    if (ml >= 0.80) return 'text-orange-400 bg-orange-500/20';
    if (ml >= 0.60) return 'text-yellow-400 bg-yellow-500/20';
    return 'text-green-400 bg-green-500/20';
  };

  const getMachineLikelihoodLabel = (ml) => {
    if (ml >= 0.92) return 'CRITICAL';
    if (ml >= 0.80) return 'HIGH';
    if (ml >= 0.60) return 'MEDIUM';
    return 'LOW';
  };

  const getIntentColor = (intent) => {
    const colors = {
      recon: 'bg-blue-500/20 text-blue-400',
      credential_access: 'bg-red-500/20 text-red-400',
      lateral_movement: 'bg-purple-500/20 text-purple-400',
      privilege_escalation: 'bg-orange-500/20 text-orange-400',
      persistence: 'bg-amber-500/20 text-amber-400',
      defense_evasion: 'bg-slate-500/20 text-slate-400',
      exfil_prep: 'bg-pink-500/20 text-pink-400',
      data_staging: 'bg-cyan-500/20 text-cyan-400'
    };
    return colors[intent] || 'bg-slate-500/20 text-slate-400';
  };

  return (
    <div className="p-6 space-y-6" data-testid="cli-sessions-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Brain className="w-8 h-8 text-purple-400" />
            AI-Agentic Detection Dashboard
          </h1>
          <p className="text-slate-400 mt-1">
            Real-time analysis of CLI sessions for machine-paced behavior patterns
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant={autoRefresh ? "default" : "outline"}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={autoRefresh ? "bg-green-600 hover:bg-green-500" : "border-slate-700"}
          >
            {autoRefresh ? <Play className="w-4 h-4 mr-2" /> : <Pause className="w-4 h-4 mr-2" />}
            {autoRefresh ? 'Live' : 'Paused'}
          </Button>
          <Button onClick={fetchData} variant="outline" className="border-slate-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <Terminal className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Sessions Analyzed</p>
              <p className="text-2xl font-bold text-white">{stats.totalSessions || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-orange-500/30 rounded-lg p-4"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-orange-500/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">High Risk (≥80%)</p>
              <p className="text-2xl font-bold text-orange-400">{stats.highRiskSessions || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-red-500/30 rounded-lg p-4"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
              <Zap className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Critical (≥92%)</p>
              <p className="text-2xl font-bold text-red-400">{stats.criticalRiskSessions || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
              <TrendingUp className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Avg ML Score</p>
              <p className="text-2xl font-bold text-cyan-400">{((stats.averageML || 0) * 100).toFixed(0)}%</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-slate-900/50 border border-pink-500/30 rounded-lg p-4"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-pink-500/20 flex items-center justify-center">
              <Target className="w-5 h-5 text-pink-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Deception Hits</p>
              <p className="text-2xl font-bold text-pink-400">{stats.deceptionHits || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sessions List */}
        <Card className="lg:col-span-1 bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-purple-400" />
              Recent Sessions
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-[600px] overflow-y-auto">
            {loading ? (
              <div className="flex justify-center py-8">
                <RefreshCw className="w-8 h-8 animate-spin text-purple-400" />
              </div>
            ) : sessions.length > 0 ? (
              <div className="space-y-2">
                {sessions.map((session, idx) => (
                  <motion.div
                    key={`${session.host_id}-${session.session_id}-${idx}`}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      selectedSession?.session_id === session.session_id
                        ? 'bg-purple-500/20 border-purple-500/50'
                        : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'
                    }`}
                    onClick={() => handleSessionClick(session)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Monitor className="w-4 h-4 text-slate-400" />
                        <span className="text-white font-medium text-sm">{session.host_id}</span>
                      </div>
                      <Badge className={getMachineLikelihoodColor(session.machine_likelihood)}>
                        {getMachineLikelihoodLabel(session.machine_likelihood)} {(session.machine_likelihood * 100).toFixed(0)}%
                      </Badge>
                    </div>
                    
                    {/* ML Score Bar */}
                    <div className="mb-2">
                      <Progress 
                        value={session.machine_likelihood * 100} 
                        className="h-1.5"
                      />
                    </div>
                    
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span className="flex items-center gap-1">
                        <User className="w-3 h-3" />
                        {session.user}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(session.window_end).toLocaleTimeString()}
                      </span>
                    </div>
                    
                    {/* Intents */}
                    {session.dominant_intents?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {session.dominant_intents.slice(0, 3).map((intent, i) => (
                          <span key={i} className={`px-1.5 py-0.5 rounded text-[10px] ${getIntentColor(intent)}`}>
                            {intent}
                          </span>
                        ))}
                      </div>
                    )}
                    
                    {session.decoy_touched && (
                      <div className="mt-2 flex items-center gap-1 text-red-400 text-xs">
                        <Target className="w-3 h-3" />
                        DECOY TOUCHED
                      </div>
                    )}
                  </motion.div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-400">
                <Brain className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No CLI sessions analyzed yet</p>
                <p className="text-sm mt-2">Sessions appear when agents send CLI events</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Session Details */}
        <Card className="lg:col-span-2 bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Eye className="w-5 h-5 text-cyan-400" />
              Session Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selectedSession ? (
              <div className="space-y-6">
                {/* Session Overview */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-3 bg-slate-800/50 rounded-lg">
                    <p className="text-slate-400 text-xs mb-1">Machine Likelihood</p>
                    <p className={`text-2xl font-bold ${getMachineLikelihoodColor(selectedSession.machine_likelihood).split(' ')[0]}`}>
                      {(selectedSession.machine_likelihood * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div className="p-3 bg-slate-800/50 rounded-lg">
                    <p className="text-slate-400 text-xs mb-1">Burstiness</p>
                    <p className="text-2xl font-bold text-amber-400">
                      {(selectedSession.burstiness_score * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div className="p-3 bg-slate-800/50 rounded-lg">
                    <p className="text-slate-400 text-xs mb-1">Tool Switch Latency</p>
                    <p className="text-2xl font-bold text-cyan-400">
                      {selectedSession.tool_switch_latency_ms}ms
                    </p>
                  </div>
                  <div className="p-3 bg-slate-800/50 rounded-lg">
                    <p className="text-slate-400 text-xs mb-1">Goal Persistence</p>
                    <p className="text-2xl font-bold text-purple-400">
                      {(selectedSession.goal_persistence * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>

                {/* Risk Indicators */}
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <h4 className="text-white font-medium mb-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-amber-400" />
                    Risk Indicators
                  </h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-sm">Machine-Like Timing</span>
                      <div className="flex items-center gap-2">
                        <Progress value={selectedSession.machine_likelihood * 100} className="w-24 h-2" />
                        {selectedSession.machine_likelihood >= 0.8 ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        )}
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-sm">Command Burstiness</span>
                      <div className="flex items-center gap-2">
                        <Progress value={selectedSession.burstiness_score * 100} className="w-24 h-2" />
                        {selectedSession.burstiness_score >= 0.75 ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        )}
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-sm">Fast Tool Switching</span>
                      <div className="flex items-center gap-2">
                        <span className="text-white text-sm">{selectedSession.tool_switch_latency_ms}ms</span>
                        {selectedSession.tool_switch_latency_ms <= 300 ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        )}
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-sm">Decoy Interaction</span>
                      <div className="flex items-center gap-2">
                        {selectedSession.decoy_touched ? (
                          <>
                            <span className="text-red-400 text-sm font-bold">TOUCHED</span>
                            <XCircle className="w-4 h-4 text-red-400" />
                          </>
                        ) : (
                          <>
                            <span className="text-green-400 text-sm">Clean</span>
                            <CheckCircle className="w-4 h-4 text-green-400" />
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Detected Intents */}
                {selectedSession.dominant_intents?.length > 0 && (
                  <div className="p-4 bg-slate-800/30 rounded-lg">
                    <h4 className="text-white font-medium mb-3 flex items-center gap-2">
                      <Target className="w-4 h-4 text-purple-400" />
                      Detected Intents
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {selectedSession.dominant_intents.map((intent, i) => (
                        <span key={i} className={`px-3 py-1.5 rounded-lg text-sm font-medium ${getIntentColor(intent)}`}>
                          {intent.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Command Stream */}
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <h4 className="text-white font-medium mb-3 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-green-400" />
                    Command Stream ({commands.length})
                  </h4>
                  <div className="max-h-64 overflow-y-auto space-y-1">
                    {commands.length > 0 ? commands.map((cmd, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm font-mono">
                        <span className="text-slate-500 text-xs whitespace-nowrap">
                          {new Date(cmd.timestamp).toLocaleTimeString()}
                        </span>
                        <span className="text-green-400">$</span>
                        <span className="text-slate-300 break-all">{cmd.command}</span>
                      </div>
                    )) : (
                      <p className="text-slate-400 text-sm">No commands in this session</p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-16 text-slate-400">
                <Eye className="w-16 h-16 mx-auto mb-4 opacity-30" />
                <p className="text-lg">Select a session to view analysis</p>
                <p className="text-sm mt-2">Click on a session from the list to see detailed metrics</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Deception Hits */}
      {deceptionHits.length > 0 && (
        <Card className="bg-red-900/20 border-red-500/30">
          <CardHeader>
            <CardTitle className="text-red-400 flex items-center gap-2">
              <Target className="w-5 h-5" />
              Recent Deception Hits
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {deceptionHits.slice(0, 6).map((hit, idx) => (
                <div key={idx} className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">{hit.host_id}</span>
                    <Badge className="bg-red-500/20 text-red-400">{hit.severity}</Badge>
                  </div>
                  <p className="text-slate-400 text-sm mb-2">Token: {hit.token_id}</p>
                  <p className="text-slate-500 text-xs">
                    {new Date(hit.timestamp).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default CLISessionsPage;
