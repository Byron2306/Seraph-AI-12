import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  GitBranch, Search, RefreshCw, Shield, AlertTriangle, 
  Target, Activity, Zap, CheckCircle, Clock, 
  TrendingUp, Link as LinkIcon, Users, Brain
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const CorrelationPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [correlations, setCorrelations] = useState([]);
  const [autoActions, setAutoActions] = useState([]);
  const [autoCorrelate, setAutoCorrelate] = useState(true);
  const [loading, setLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [aiSummary, setAiSummary] = useState(null);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStats();
    fetchCorrelations();
    fetchAutoActions();
  }, [token]);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/correlation/stats`, { headers });
      setStats(res.data);
      setAutoCorrelate(res.data.auto_correlate_enabled);
    } catch (err) {
      toast.error('Failed to fetch correlation stats');
    }
  };

  const fetchCorrelations = async () => {
    try {
      const res = await axios.get(`${API}/correlation/history?limit=20`, { headers });
      setCorrelations(res.data.correlations || []);
    } catch (err) {
      console.error('Failed to fetch correlations');
    }
  };

  const fetchAutoActions = async () => {
    try {
      const res = await axios.get(`${API}/correlation/auto-actions?limit=10`, { headers });
      setAutoActions(res.data.actions || []);
    } catch (err) {
      console.error('Failed to fetch auto-actions');
    }
  };

  const handleCorrelateAll = async () => {
    setCorrelating(true);
    try {
      const res = await axios.post(`${API}/correlation/all-active`, {}, { headers });
      toast.success(`Correlated ${res.data.summary?.total || 0} threats`);
      if (Array.isArray(res.data.correlations) && res.data.correlations.length > 0) {
        setCorrelations(res.data.correlations);
      } else {
        fetchCorrelations();
      }
      setAiSummary(res.data.ai_summary || null);
      fetchStats();
    } catch (err) {
      toast.error('Failed to correlate threats');
    } finally {
      setCorrelating(false);
    }
  };

  const handleToggleAutoCorrelate = async () => {
    try {
      const newValue = !autoCorrelate;
      await axios.post(`${API}/correlation/settings?auto_correlate=${newValue}`, {}, { headers });
      setAutoCorrelate(newValue);
      toast.success(`Auto-correlation ${newValue ? 'enabled' : 'disabled'}`);
    } catch (err) {
      toast.error('Failed to update settings');
    }
  };

  const getConfidenceColor = (confidence) => {
    switch(confidence) {
      case 'high': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'medium': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  return (
    <div className="p-6 space-y-6" data-testid="correlation-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-purple-400" />
            Threat Correlation
          </h1>
          <p className="text-slate-400 text-sm mt-1">Automated threat intelligence correlation engine</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-sm">Auto-Correlate</span>
            <Switch 
              checked={autoCorrelate} 
              onCheckedChange={handleToggleAutoCorrelate}
              data-testid="auto-correlate-switch"
            />
          </div>
          <Button 
            onClick={handleCorrelateAll} 
            disabled={correlating}
            className="bg-purple-600 hover:bg-purple-700"
            data-testid="correlate-all-btn"
          >
            <Brain className={`w-4 h-4 mr-2 ${correlating ? 'animate-pulse' : ''}`} />
            {correlating ? 'Correlating...' : 'Correlate All'}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <GitBranch className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Cached Correlations</p>
              <p className="text-2xl font-bold text-white">{stats?.cached_correlations || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <Users className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Known Threat Actors</p>
              <p className="text-2xl font-bold text-white">{stats?.known_threat_actors || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Target className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Campaign Patterns</p>
              <p className="text-2xl font-bold text-white">{stats?.campaign_patterns || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className={`p-4 rounded-lg border ${autoCorrelate ? 'bg-green-500/10 border-green-500/30' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${autoCorrelate ? 'bg-green-500/20' : 'bg-slate-800'}`}>
              <Zap className={`w-5 h-5 ${autoCorrelate ? 'text-green-400' : 'text-slate-400'}`} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Auto-Correlation</p>
              <p className={`font-bold ${autoCorrelate ? 'text-green-400' : 'text-slate-400'}`}>
                {autoCorrelate ? 'ENABLED' : 'DISABLED'}
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {aiSummary && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              AI Correlation Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-slate-200 text-sm mb-3">{aiSummary.conclusion || 'No conclusion returned'}</p>
            {Array.isArray(aiSummary.recommendations) && aiSummary.recommendations.length > 0 && (
              <ul className="space-y-1 text-slate-300 text-sm list-disc list-inside">
                {aiSummary.recommendations.slice(0, 5).map((rec, idx) => (
                  <li key={idx}>{rec}</li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}

      {/* Recent Correlations */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <LinkIcon className="w-5 h-5 text-purple-400" />
            Recent Correlations
          </CardTitle>
        </CardHeader>
        <CardContent>
          {correlations.length > 0 ? (
            <div className="space-y-3">
              {correlations.map((corr) => (
                <div key={corr.correlation_id} 
                  className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <Target className="w-5 h-5 text-amber-400" />
                      <p className="text-white font-medium">Threat: {corr.threat_id}</p>
                    </div>
                    <Badge variant="outline" className={getConfidenceColor(corr.confidence)}>
                      {corr.confidence?.toUpperCase() || 'NONE'} Confidence
                    </Badge>
                  </div>
                  
                  {corr.attribution?.threat_actor && (
                    <div className="flex items-center gap-2 mb-2">
                      <Users className="w-4 h-4 text-red-400" />
                      <span className="text-red-400 text-sm">
                        Actor: {corr.attribution.threat_actor}
                      </span>
                    </div>
                  )}

                  {corr.attribution?.campaign && (
                    <div className="flex items-center gap-2 mb-2">
                      <Target className="w-4 h-4 text-amber-400" />
                      <span className="text-amber-400 text-sm">
                        Campaign: {corr.attribution.campaign}
                      </span>
                    </div>
                  )}

                  <div className="flex gap-4 mt-3 text-xs text-slate-400">
                    <span>Matched IOCs: {corr.matched_indicators?.length || 0}</span>
                    <span>Related: {corr.related_indicators?.length || 0}</span>
                    <span>Mitigations: {corr.mitigations?.length || 0}</span>
                  </div>

                  {corr.enrichment_data?.mitre_tactics?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {corr.enrichment_data.mitre_tactics.map((tactic, i) => (
                        <Badge key={i} variant="outline" className="text-xs text-cyan-400 border-cyan-500/30">
                          {tactic}
                        </Badge>
                      ))}
                    </div>
                  )}

                  <p className="text-slate-500 text-xs mt-2 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(corr.timestamp).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <GitBranch className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No correlations yet</p>
              <p className="text-sm">Click "Correlate All" to analyze active threats</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Auto-Actions */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Zap className="w-5 h-5 text-green-400" />
            Automated Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          {autoActions.length > 0 ? (
            <div className="space-y-2">
              {autoActions.map((action, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <div>
                      <p className="text-white text-sm">
                        {action.actions?.join(', ') || 'No actions'}
                      </p>
                      <p className="text-slate-400 text-xs">
                        Threat: {action.threat_id} | Correlation: {action.correlation_id}
                      </p>
                    </div>
                  </div>
                  <span className="text-slate-500 text-xs">
                    {new Date(action.timestamp).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-6 text-slate-400">
              <Zap className="w-10 h-10 mx-auto mb-3 opacity-50" />
              <p className="text-sm">No automated actions taken yet</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Attribution Info */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-red-400" />
            Threat Actor Database
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {['APT28 (Fancy Bear)', 'APT29 (Cozy Bear)', 'Lazarus Group', 'APT41', 'FIN7'].map((actor, i) => (
              <div key={i} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Users className="w-4 h-4 text-red-400" />
                  <span className="text-white font-medium text-sm">{actor}</span>
                </div>
                <p className="text-slate-400 text-xs">
                  Known TTPs: {i % 2 === 0 ? 'Spearphishing, Supply Chain' : 'Ransomware, Cryptomining'}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default CorrelationPage;
