import React, { useMemo, useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Clock, AlertTriangle, Shield, Activity, FileText,
  ChevronRight, RefreshCw, Download,
  User, Zap, Eye, Network, GitBranch, FileSearch, Link2
} from 'lucide-react';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const KILL_CHAIN_PHASES = [
  'reconnaissance',
  'weaponization',
  'delivery',
  'exploitation',
  'installation',
  'command_and_control',
  'actions_on_objectives'
];

const TimelinePage = () => {
  const [loading, setLoading] = useState(true);
  const [timelines, setTimelines] = useState([]);
  const [selectedTimeline, setSelectedTimeline] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  const [relatedData, setRelatedData] = useState([]);
  const [loadingRelated, setLoadingRelated] = useState(false);

  const [correlationData, setCorrelationData] = useState(null);
  const [loadingCorrelation, setLoadingCorrelation] = useState(false);

  const [reportType, setReportType] = useState('technical');
  const [loadingReport, setLoadingReport] = useState(false);
  const [reportText, setReportText] = useState('');

  const [artifactType, setArtifactType] = useState('log');
  const [artifactName, setArtifactName] = useState('');
  const [artifactDescription, setArtifactDescription] = useState('');
  const [artifactSha, setArtifactSha] = useState('');
  const [selectedArtifactId, setSelectedArtifactId] = useState('');
  const [custodyAction, setCustodyAction] = useState('transferred');
  const [custodyNotes, setCustodyNotes] = useState('');
  const [custodyReport, setCustodyReport] = useState('');

  const token = localStorage.getItem('token');
  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};

  const fetchTimelines = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API}/api/timelines/recent?limit=20`, {
        headers: authHeaders
      });
      if (response.ok) {
        const data = await response.json();
        setTimelines(data.timelines || []);
      }
    } catch (err) {
      console.error('Failed to fetch timelines:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadTimeline = async (threatId) => {
    setLoadingTimeline(true);
    setSelectedTimeline(threatId);
    setReportText('');
    setCustodyReport('');
    setRelatedData([]);
    try {
      const [timelineResp, relatedResp] = await Promise.all([
        fetch(`${API}/api/timeline/${threatId}`, { headers: authHeaders }),
        fetch(`${API}/api/timeline/${threatId}/related-incidents`, { headers: authHeaders })
      ]);

      if (timelineResp.ok) {
        const data = await timelineResp.json();
        setTimelineData(data);
      } else {
        toast.error('Failed to load timeline');
      }

      if (relatedResp.ok) {
        const related = await relatedResp.json();
        setRelatedData(related.related_incidents || []);
      }
    } catch (err) {
      toast.error('Failed to load timeline');
    } finally {
      setLoadingTimeline(false);
    }
  };

  const exportTimeline = async (threatId, format) => {
    try {
      const response = await fetch(`${API}/api/timeline/${threatId}/export?format=${format}`, {
        headers: authHeaders
      });
      if (response.ok) {
        const data = await response.json();
        if (format === 'markdown') {
          const blob = new Blob([data.markdown], { type: 'text/markdown' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `timeline_${threatId}.md`;
          a.click();
        } else {
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `timeline_${threatId}.json`;
          a.click();
        }
        toast.success('Timeline exported');
      }
    } catch (err) {
      toast.error('Export failed');
    }
  };

  useEffect(() => {
    fetchTimelines();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchRelatedIncidents = async () => {
    if (!selectedTimeline) return;
    setLoadingRelated(true);
    try {
      const response = await fetch(`${API}/api/timeline/${selectedTimeline}/related-incidents`, {
        headers: authHeaders
      });
      if (!response.ok) {
        toast.error('Failed to load related incidents');
        return;
      }
      const data = await response.json();
      setRelatedData(data.related_incidents || []);
    } catch (err) {
      toast.error('Failed to load related incidents');
    } finally {
      setLoadingRelated(false);
    }
  };

  const runCorrelation = async () => {
    setLoadingCorrelation(true);
    try {
      const response = await fetch(`${API}/api/timeline/correlate/all?preload_limit=25`, {
        headers: authHeaders
      });
      if (!response.ok) {
        toast.error('Correlation run failed');
        return;
      }
      const data = await response.json();
      setCorrelationData(data);
      toast.success(`Correlation complete (${data.correlations?.length || 0} links)`);
    } catch (err) {
      toast.error('Correlation run failed');
    } finally {
      setLoadingCorrelation(false);
    }
  };

  const generateReport = async () => {
    if (!selectedTimeline) return;
    setLoadingReport(true);
    try {
      const response = await fetch(`${API}/api/timeline/${selectedTimeline}/report?type=${reportType}`, {
        headers: authHeaders
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        toast.error(err?.detail?.message || 'Failed to generate report');
        return;
      }
      const data = await response.json();
      setReportText(data.report || '');
      toast.success(`${reportType} report generated`);
    } catch (err) {
      toast.error('Failed to generate report');
    } finally {
      setLoadingReport(false);
    }
  };

  const downloadReport = () => {
    if (!reportText || !selectedTimeline) return;
    const blob = new Blob([reportText], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `timeline_${selectedTimeline}_${reportType}.md`;
    a.click();
  };

  const registerArtifact = async () => {
    if (!artifactName.trim() || !artifactDescription.trim()) {
      toast.error('Artifact name and description are required');
      return;
    }
    try {
      const response = await fetch(`${API}/api/timeline/artifacts/register`, {
        method: 'POST',
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifact_type: artifactType,
          name: artifactName,
          description: artifactDescription,
          hash_sha256: artifactSha || null
        })
      });
      if (!response.ok) {
        toast.error('Artifact registration failed');
        return;
      }
      const data = await response.json();
      const artifactId = data?.artifact?.artifact_id;
      setSelectedArtifactId(artifactId || '');
      toast.success(`Artifact registered (${artifactId})`);
    } catch (err) {
      toast.error('Artifact registration failed');
    }
  };

  const appendCustody = async () => {
    if (!selectedArtifactId.trim()) {
      toast.error('Artifact ID is required for custody update');
      return;
    }
    try {
      const response = await fetch(`${API}/api/timeline/artifacts/${selectedArtifactId}/custody`, {
        method: 'POST',
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: custodyAction, notes: custodyNotes })
      });
      if (!response.ok) {
        toast.error('Custody update failed');
        return;
      }
      toast.success('Custody entry appended');
    } catch (err) {
      toast.error('Custody update failed');
    }
  };

  const loadCustodyReport = async () => {
    if (!selectedArtifactId.trim()) {
      toast.error('Artifact ID is required to load custody report');
      return;
    }
    try {
      const response = await fetch(`${API}/api/timeline/artifacts/${selectedArtifactId}/custody-report`, {
        headers: authHeaders
      });
      if (!response.ok) {
        toast.error('Failed to load custody report');
        return;
      }
      const data = await response.json();
      setCustodyReport(data.report_markdown || '');
    } catch (err) {
      toast.error('Failed to load custody report');
    }
  };

  const formatDate = (isoString) => {
    if (!isoString) return 'N/A';
    const d = new Date(isoString);
    return Number.isNaN(d.getTime()) ? String(isoString) : d.toLocaleString();
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-green-500/20 text-green-400 border-green-500/30'
    };
    return colors[severity] || colors.medium;
  };

  const getEventIcon = (eventType) => {
    const icons = {
      detection: AlertTriangle,
      alert: Activity,
      response: Zap,
      quarantine: Shield,
      block: Shield,
      forensics: FileText,
      user_action: User
    };
    return icons[eventType] || Activity;
  };

  const graphLayout = useMemo(() => {
    const nodes = timelineData?.attack_graph?.nodes || [];
    const edges = timelineData?.attack_graph?.edges || [];
    const width = 760;
    const height = 320;
    const radius = Math.max(80, Math.min(140, nodes.length * 6));
    const centerX = width / 2;
    const centerY = height / 2;
    const displayNodes = nodes.slice(0, 24);

    const positioned = displayNodes.map((node, idx) => {
      const angle = (idx / Math.max(displayNodes.length, 1)) * Math.PI * 2;
      const jitter = (idx % 3) * 6;
      return {
        ...node,
        x: centerX + Math.cos(angle) * (radius + jitter),
        y: centerY + Math.sin(angle) * (radius + jitter)
      };
    });

    const byId = Object.fromEntries(positioned.map((n) => [n.node_id, n]));
    const displayEdges = edges
      .filter((e) => byId[e.source_id] && byId[e.target_id])
      .slice(0, 80);

    return { width, height, nodes: positioned, edges: displayEdges, byId };
  }, [timelineData]);

  const killChainData = timelineData?.kill_chain_mapping?.kill_chain_mapping || {};
  const killChainCoverage = timelineData?.kill_chain_mapping?.phase_coverage;
  const killChainCurrentStage = timelineData?.kill_chain_mapping?.current_stage;
  const mitreData = timelineData?.mitre_mapping || {};
  const attackGraphMeta = timelineData?.attack_graph?.metadata || {};
  const criticalNodes = timelineData?.attack_graph?.critical_nodes || [];
  const attackPaths = timelineData?.attack_graph?.attack_paths || [];
  const playbooks = timelineData?.playbook_suggestions || [];
  const evidenceChain = timelineData?.evidence_chain || [];
  const relatedIncidents = timelineData?.related_incidents || [];
  const metrics = timelineData?.metrics || {};

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'visual', label: 'Visual' },
    { id: 'reports', label: 'Reports' },
    { id: 'correlation', label: 'Correlation' },
    { id: 'evidence', label: 'Evidence' }
  ];

  return (
    <div className="space-y-6" data-testid="timeline-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-cyan-500/20">
            <Clock className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-mono font-bold">Threat Timeline</h1>
            <p className="text-slate-400 text-sm">Reconstruct and analyze threat incidents</p>
          </div>
        </div>
        <button
          onClick={fetchTimelines}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline List */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden"
        >
          <div className="p-4 border-b border-slate-700">
            <h3 className="font-semibold">Recent Incidents</h3>
            <p className="text-xs text-slate-400">{timelines.length} threats with timelines</p>
          </div>
          
          <div className="max-h-[600px] overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              </div>
            ) : timelines.length === 0 ? (
              <div className="text-center py-12 text-slate-500">
                <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No threat timelines available</p>
              </div>
            ) : (
              timelines.map((t, idx) => (
                <motion.div
                  key={t.threat_id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: idx * 0.05 }}
                  onClick={() => loadTimeline(t.threat_id)}
                  className={`p-4 border-b border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors ${
                    selectedTimeline === t.threat_id ? 'bg-cyan-500/10 border-l-2 border-l-cyan-500' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(t.severity)}`}>
                      {t.severity}
                    </span>
                    <span className="text-xs text-slate-500">{t.event_count} events</span>
                  </div>
                  <p className="font-semibold text-sm truncate">{t.threat_name}</p>
                  <p className="text-xs text-slate-400 mt-1">{t.threat_type}</p>
                  <p className="text-xs text-slate-500 mt-1">{formatDate(t.first_seen)}</p>
                </motion.div>
              ))
            )}
          </div>
        </motion.div>

        {/* Timeline Detail */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden"
        >
          {!selectedTimeline ? (
            <div className="flex items-center justify-center h-[600px] text-slate-500">
              <div className="text-center">
                <Eye className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>Select a threat to view its timeline</p>
              </div>
            </div>
          ) : loadingTimeline ? (
            <div className="flex items-center justify-center h-[600px]">
              <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
            </div>
          ) : timelineData ? (
            <>
              {/* Header */}
              <div className="p-4 border-b border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-lg">{timelineData.threat_name}</h3>
                    <div className="flex items-center gap-3 mt-1">
                      <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(timelineData.severity)}`}>
                        {timelineData.severity}
                      </span>
                      <span className="text-xs text-slate-400">{timelineData.threat_type}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        timelineData.status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                        timelineData.status === 'active' ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {timelineData.status}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => exportTimeline(selectedTimeline, 'json')}
                      className="p-2 hover:bg-slate-700 rounded"
                      title="Export JSON"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => exportTimeline(selectedTimeline, 'markdown')}
                      className="p-2 hover:bg-slate-700 rounded"
                      title="Export Markdown"
                    >
                      <FileText className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                {/* Summary */}
                {timelineData.summary && (
                  <p className="text-sm text-slate-300 mt-3 p-3 bg-slate-900/50 rounded">
                    {timelineData.summary}
                  </p>
                )}
              </div>

              {/* Impact Assessment */}
              {timelineData.impact_assessment && (
                <div className="p-4 border-b border-slate-700 bg-slate-900/30">
                  <h4 className="text-sm font-semibold mb-2">Impact Assessment</h4>
                  <div className="grid grid-cols-3 gap-4 text-xs">
                    <div>
                      <span className="text-slate-400">Response Time</span>
                      <p className="font-mono text-white">
                        {timelineData.impact_assessment.response_time_minutes !== null
                          ? `${timelineData.impact_assessment.response_time_minutes} min`
                          : 'N/A'}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Total Events</span>
                      <p className="font-mono text-white">{timelineData.impact_assessment.total_events}</p>
                    </div>
                    <div>
                      <span className="text-slate-400">Contained</span>
                      <p className={`font-mono ${timelineData.impact_assessment.contained ? 'text-green-400' : 'text-red-400'}`}>
                        {timelineData.impact_assessment.contained ? 'Yes' : 'No'}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <div className="px-4 pt-3 border-b border-slate-700 bg-slate-900/30">
                <div className="flex flex-wrap gap-2">
                  {tabs.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-3 py-1.5 rounded text-xs border transition-colors ${
                        activeTab === tab.id
                          ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                          : 'bg-slate-800/60 border-slate-700 text-slate-300 hover:bg-slate-700'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              {activeTab === 'overview' && (
                <>
                  {/* Events Timeline */}
                  <div className="p-4 max-h-[350px] overflow-y-auto">
                    <h4 className="text-sm font-semibold mb-4">Event Timeline</h4>
                    <div className="relative">
                      <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-slate-700"></div>

                      {timelineData.events?.map((event, idx) => {
                        const Icon = getEventIcon(event.event_type);
                        return (
                          <motion.div
                            key={event.id}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: idx * 0.05 }}
                            className="relative pl-10 pb-6"
                          >
                            <div className={`absolute left-2 w-5 h-5 rounded-full flex items-center justify-center ${
                              event.severity === 'critical' ? 'bg-red-500' :
                              event.severity === 'high' ? 'bg-orange-500' :
                              event.severity === 'warning' ? 'bg-yellow-500' :
                              'bg-cyan-500'
                            }`}>
                              <Icon className="w-3 h-3 text-white" />
                            </div>

                            <div className="bg-slate-900/50 rounded p-3 border border-slate-700">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-semibold text-sm">{event.title}</span>
                                <span className="text-xs text-slate-500">{formatDate(event.timestamp)}</span>
                              </div>
                              <p className="text-xs text-slate-400">{event.description}</p>
                              <div className="flex items-center gap-2 mt-2 text-xs">
                                <span className="text-slate-500">{event.event_type}</span>
                                <span className="text-slate-600">•</span>
                                <span className="text-slate-500">{event.source}</span>
                              </div>
                            </div>
                          </motion.div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Enterprise Analysis Snapshot */}
                  <div className="p-4 border-t border-slate-700 bg-slate-900/20 space-y-4">
                    <h4 className="text-sm font-semibold">Enterprise Analysis Snapshot</h4>

                    {/* Metrics */}
                    {Object.keys(metrics).length > 0 && (
                      <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                        <p className="text-xs font-semibold text-slate-200 mb-2">Metrics</p>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                          <div>
                            <p className="text-slate-400">Total Events</p>
                            <p className="text-white font-mono">{metrics.total_events ?? 'N/A'}</p>
                          </div>
                          <div>
                            <p className="text-slate-400">Response Time</p>
                            <p className="text-white font-mono">{metrics.response_time_minutes ?? 'N/A'} min</p>
                          </div>
                          <div>
                            <p className="text-slate-400">MITRE Techniques</p>
                            <p className="text-white font-mono">{metrics.mitre_techniques_count ?? 0}</p>
                          </div>
                          <div>
                            <p className="text-slate-400">Kill Chain Coverage</p>
                            <p className="text-white font-mono">
                              {typeof metrics.kill_chain_coverage === 'number'
                                ? `${Math.round(metrics.kill_chain_coverage * 100)}%`
                                : 'N/A'}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Root Cause */}
                    {timelineData.root_cause?.found && (
                      <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                        <p className="text-xs font-semibold text-slate-200 mb-2">Root Cause</p>
                        <p className="text-sm text-white">{timelineData.root_cause.title || 'Unknown root event'}</p>
                        <div className="mt-2 text-xs text-slate-400 flex flex-wrap gap-3">
                          <span>Confidence: {Math.round((timelineData.root_cause.confidence || 0) * 100)}%</span>
                          <span>Type: {timelineData.root_cause.event_type || 'N/A'}</span>
                          <span>Time: {formatDate(timelineData.root_cause.timestamp)}</span>
                        </div>
                      </div>
                    )}

                {/* Attack Graph */}
                {timelineData.attack_graph && (
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <p className="text-xs font-semibold text-slate-200 mb-2">Attack Graph</p>
                    <div className="grid grid-cols-3 gap-3 text-xs mb-3">
                      <div>
                        <p className="text-slate-400">Nodes</p>
                        <p className="text-white font-mono">{attackGraphMeta.total_nodes ?? 0}</p>
                      </div>
                      <div>
                        <p className="text-slate-400">Edges</p>
                        <p className="text-white font-mono">{attackGraphMeta.total_edges ?? 0}</p>
                      </div>
                      <div>
                        <p className="text-slate-400">Compromised</p>
                        <p className="text-white font-mono">{attackGraphMeta.compromised_nodes ?? 0}</p>
                      </div>
                    </div>
                    {criticalNodes.length > 0 && (
                      <div className="mb-2">
                        <p className="text-xs text-slate-300 mb-1">Critical Nodes</p>
                        <div className="text-xs text-slate-400 space-y-1">
                          {criticalNodes.slice(0, 4).map((n) => (
                            <p key={n.node_id}>- {n.label} ({n.type}) score={n.criticality}</p>
                          ))}
                        </div>
                      </div>
                    )}
                    {attackPaths.length > 0 && (
                      <div>
                        <p className="text-xs text-slate-300 mb-1">Attack Paths</p>
                        <div className="text-xs text-slate-400 space-y-1">
                          {attackPaths.slice(0, 3).map((path, idx) => (
                            <p key={`${idx}-${path.join('-')}`}>{idx + 1}. {path.join(' -> ')}</p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Kill Chain + MITRE */}
                {(Object.keys(killChainData).length > 0 || Object.keys(mitreData).length > 0) && (
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <p className="text-xs font-semibold text-slate-200 mb-2">Kill Chain and MITRE</p>
                    <div className="text-xs text-slate-400 mb-2 flex flex-wrap gap-3">
                      <span>Current Stage: {killChainCurrentStage || 'unknown'}</span>
                      <span>
                        Coverage: {typeof killChainCoverage?.coverage_percentage === 'number'
                          ? `${Math.round(killChainCoverage.coverage_percentage)}%`
                          : 'N/A'}
                      </span>
                    </div>
                    {Object.keys(killChainData).length > 0 && (
                      <div className="mb-2">
                        <p className="text-xs text-slate-300 mb-1">Kill Chain Phases</p>
                        <div className="text-xs text-slate-400 space-y-1">
                          {Object.entries(killChainData)
                            .filter(([, events]) => Array.isArray(events) && events.length > 0)
                            .slice(0, 6)
                            .map(([phase, events]) => (
                              <p key={phase}>- {phase}: {events.length} event(s)</p>
                            ))}
                        </div>
                      </div>
                    )}
                    {Object.keys(mitreData).length > 0 && (
                      <div>
                        <p className="text-xs text-slate-300 mb-1">MITRE Techniques</p>
                        <div className="text-xs text-slate-400 space-y-1">
                          {Object.entries(mitreData).slice(0, 8).map(([technique, eventIds]) => (
                            <p key={technique}>- {technique}: {Array.isArray(eventIds) ? eventIds.length : 0} event(s)</p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Playbook Suggestions */}
                {playbooks.length > 0 && (
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <p className="text-xs font-semibold text-slate-200 mb-2">Playbook Suggestions</p>
                    <div className="text-xs text-slate-400 space-y-2">
                      {playbooks.slice(0, 3).map((pb) => (
                        <div key={pb.playbook_id || pb.name} className="border border-slate-700 rounded p-2">
                          <p className="text-slate-200">{pb.name || 'Unnamed playbook'}</p>
                          <p>Priority: {pb.priority ?? 'N/A'} | Automated: {pb.automated ? 'Yes' : 'No'} | ETA: {pb.estimated_time_minutes ?? 'N/A'} min</p>
                          <p className="text-slate-500">{pb.description || ''}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Evidence Chain */}
                {evidenceChain.length > 0 && (
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <p className="text-xs font-semibold text-slate-200 mb-2">Evidence Chain</p>
                    <div className="text-xs text-slate-400 space-y-1">
                      {evidenceChain.slice(0, 8).map((item, idx) => (
                        <p key={`${item.artifact_id || 'evidence'}-${idx}`}>
                          - {item.artifact_id || 'N/A'} ({item.type || item.artifact_type || 'unknown'}) collected {formatDate(item.collected_at)}
                        </p>
                      ))}
                    </div>
                  </div>
                )}

                    {/* Related Incidents */}
                    {(relatedData.length > 0 || relatedIncidents.length > 0) && (
                      <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                        <p className="text-xs font-semibold text-slate-200 mb-2">Related Incidents</p>
                        <div className="text-xs text-slate-400 space-y-1">
                          {(relatedData.length ? relatedData : relatedIncidents).slice(0, 8).map((incident, idx) => (
                            <p key={`${incident?.threat_id || incident}-${idx}`}>
                              - {incident?.threat_id || incident} {incident?.score ? `(score ${incident.score.toFixed(2)})` : ''}
                            </p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}

              {activeTab === 'visual' && (
                <div className="p-4 space-y-4">
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <div className="flex items-center gap-2 mb-2 text-slate-200 text-sm font-semibold">
                      <Network className="w-4 h-4 text-cyan-400" />
                      Attack Graph Visualization
                    </div>
                    {graphLayout.nodes.length === 0 ? (
                      <p className="text-xs text-slate-500">No graph entities available for this timeline.</p>
                    ) : (
                      <svg viewBox={`0 0 ${graphLayout.width} ${graphLayout.height}`} className="w-full h-[320px] rounded bg-slate-950/70 border border-slate-800">
                        {graphLayout.edges.map((e, i) => {
                          const s = graphLayout.byId[e.source_id];
                          const t = graphLayout.byId[e.target_id];
                          if (!s || !t) return null;
                          return (
                            <line
                              key={`${e.edge_id || 'edge'}-${i}`}
                              x1={s.x}
                              y1={s.y}
                              x2={t.x}
                              y2={t.y}
                              stroke="rgba(148,163,184,0.35)"
                              strokeWidth="1.5"
                            />
                          );
                        })}
                        {graphLayout.nodes.map((n) => (
                          <g key={n.node_id}>
                            <circle
                              cx={n.x}
                              cy={n.y}
                              r="9"
                              fill={n.compromised ? 'rgba(239,68,68,0.9)' : 'rgba(34,211,238,0.9)'}
                              stroke="rgba(15,23,42,0.8)"
                              strokeWidth="2"
                            />
                            <text x={n.x + 12} y={n.y + 3} fill="rgba(226,232,240,0.95)" fontSize="11">
                              {(n.label || n.node_id || '').slice(0, 24)}
                            </text>
                          </g>
                        ))}
                      </svg>
                    )}
                  </div>

                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <div className="flex items-center gap-2 mb-3 text-slate-200 text-sm font-semibold">
                      <GitBranch className="w-4 h-4 text-emerald-400" />
                      Kill Chain Progression
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-7 gap-2">
                      {KILL_CHAIN_PHASES.map((phase) => {
                        const hasEvents = Array.isArray(killChainData?.[phase]) && killChainData[phase].length > 0;
                        const isCurrent = killChainCurrentStage === phase;
                        return (
                          <div
                            key={phase}
                            className={`rounded border px-2 py-2 text-[11px] ${
                              isCurrent
                                ? 'border-cyan-500 bg-cyan-500/20 text-cyan-200'
                                : hasEvents
                                  ? 'border-emerald-600 bg-emerald-500/10 text-emerald-300'
                                  : 'border-slate-700 bg-slate-900/70 text-slate-400'
                            }`}
                          >
                            <p className="font-semibold">{phase.replaceAll('_', ' ')}</p>
                            <p>{hasEvents ? `${killChainData[phase].length} event(s)` : 'no events'}</p>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'reports' && (
                <div className="p-4 space-y-4">
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <div className="flex flex-wrap items-center gap-2 mb-3">
                      <select
                        value={reportType}
                        onChange={(e) => setReportType(e.target.value)}
                        className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs"
                      >
                        <option value="executive">executive</option>
                        <option value="technical">technical</option>
                        <option value="forensic">forensic</option>
                        <option value="compliance">compliance</option>
                      </select>
                      <button
                        onClick={generateReport}
                        disabled={loadingReport}
                        className="px-3 py-1.5 text-xs rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-60"
                      >
                        {loadingReport ? 'Generating...' : 'Generate Report'}
                      </button>
                      <button
                        onClick={downloadReport}
                        disabled={!reportText}
                        className="px-3 py-1.5 text-xs rounded border border-slate-600 hover:bg-slate-700 disabled:opacity-50"
                      >
                        <Download className="w-3 h-3 inline mr-1" />Download
                      </button>
                    </div>
                    <textarea
                      value={reportText}
                      onChange={(e) => setReportText(e.target.value)}
                      placeholder="Generated report will appear here..."
                      className="w-full h-[300px] bg-slate-950 border border-slate-700 rounded p-3 text-xs text-slate-200"
                    />
                  </div>
                </div>
              )}

              {activeTab === 'correlation' && (
                <div className="p-4 space-y-4">
                  <div className="flex gap-2">
                    <button
                      onClick={fetchRelatedIncidents}
                      disabled={loadingRelated}
                      className="px-3 py-1.5 text-xs rounded border border-slate-600 hover:bg-slate-700"
                    >
                      {loadingRelated ? 'Refreshing...' : 'Refresh Related'}
                    </button>
                    <button
                      onClick={runCorrelation}
                      disabled={loadingCorrelation}
                      className="px-3 py-1.5 text-xs rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60"
                    >
                      {loadingCorrelation ? 'Running...' : 'Run Global Correlation'}
                    </button>
                  </div>

                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <div className="flex items-center gap-2 text-sm font-semibold mb-2">
                      <Link2 className="w-4 h-4 text-amber-400" /> Related Incidents
                    </div>
                    {(relatedData.length > 0 ? relatedData : relatedIncidents).length === 0 ? (
                      <p className="text-xs text-slate-500">No related incidents found yet.</p>
                    ) : (
                      <div className="space-y-2 text-xs">
                        {(relatedData.length > 0 ? relatedData : relatedIncidents).map((r, idx) => (
                          <div key={`${r.threat_id || r}-${idx}`} className="border border-slate-700 rounded p-2 text-slate-300">
                            <p className="font-semibold">{r.threat_id || r}</p>
                            {r.relationship && <p>Relationship: {r.relationship}</p>}
                            {typeof r.score === 'number' && <p>Score: {r.score.toFixed(2)}</p>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {correlationData && (
                    <div className="bg-slate-900/50 border border-slate-700 rounded p-3 text-xs text-slate-300">
                      <p>Preloaded: {correlationData.preloaded_timelines || 0}</p>
                      <p>Total timelines: {correlationData.total_timelines || 0}</p>
                      <p>Correlation links: {(correlationData.correlations || []).length}</p>
                      <p>Campaigns: {(correlationData.campaigns || []).length}</p>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'evidence' && (
                <div className="p-4 space-y-4">
                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <div className="flex items-center gap-2 text-sm font-semibold mb-3">
                      <FileSearch className="w-4 h-4 text-violet-400" /> Register Artifact
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                      <input value={artifactType} onChange={(e) => setArtifactType(e.target.value)} placeholder="artifact type" className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5" />
                      <input value={artifactName} onChange={(e) => setArtifactName(e.target.value)} placeholder="artifact name" className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5" />
                      <input value={artifactSha} onChange={(e) => setArtifactSha(e.target.value)} placeholder="sha256 (optional)" className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5" />
                      <input value={selectedArtifactId} onChange={(e) => setSelectedArtifactId(e.target.value)} placeholder="artifact id for custody actions" className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5" />
                    </div>
                    <textarea value={artifactDescription} onChange={(e) => setArtifactDescription(e.target.value)} placeholder="artifact description" className="mt-2 w-full bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs" />
                    <button onClick={registerArtifact} className="mt-2 px-3 py-1.5 text-xs rounded bg-violet-600 hover:bg-violet-500">Register Artifact</button>
                  </div>

                  <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                    <p className="text-sm font-semibold mb-2">Custody Workflow</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                      <input value={custodyAction} onChange={(e) => setCustodyAction(e.target.value)} placeholder="custody action" className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5" />
                      <input value={custodyNotes} onChange={(e) => setCustodyNotes(e.target.value)} placeholder="custody notes" className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5" />
                    </div>
                    <div className="mt-2 flex gap-2">
                      <button onClick={appendCustody} className="px-3 py-1.5 text-xs rounded border border-slate-600 hover:bg-slate-700">Append Custody</button>
                      <button onClick={loadCustodyReport} className="px-3 py-1.5 text-xs rounded bg-cyan-700 hover:bg-cyan-600">Load Custody Report</button>
                    </div>
                    {custodyReport && (
                      <textarea
                        value={custodyReport}
                        onChange={(e) => setCustodyReport(e.target.value)}
                        className="mt-2 w-full h-[220px] bg-slate-950 border border-slate-700 rounded p-2 text-xs"
                      />
                    )}
                  </div>

                  {evidenceChain.length > 0 && (
                    <div className="bg-slate-900/50 border border-slate-700 rounded p-3">
                      <p className="text-sm font-semibold mb-2">Current Timeline Evidence</p>
                      <div className="text-xs text-slate-400 space-y-1 max-h-[180px] overflow-auto">
                        {evidenceChain.slice(0, 20).map((item, idx) => (
                          <p key={`${item.artifact_id || 'ev'}-${idx}`}>
                            - {item.artifact_id || 'N/A'} | {item.type || item.artifact_type || 'unknown'} | {formatDate(item.collected_at)}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Recommendations */}
              {timelineData.recommendations?.length > 0 && (
                <div className="p-4 border-t border-slate-700 bg-amber-500/5">
                  <h4 className="text-sm font-semibold mb-2 text-amber-400">Recommendations</h4>
                  <ul className="text-xs space-y-1 text-slate-300">
                    {timelineData.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <ChevronRight className="w-3 h-3 text-amber-400 flex-shrink-0 mt-0.5" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : null}
        </motion.div>
      </div>
    </div>
  );
};

export default TimelinePage;
