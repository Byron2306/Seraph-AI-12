import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ScrollText, Search, Filter, RefreshCw, Download,
  User, Shield, Settings, AlertTriangle, Activity,
  Clock, ChevronDown, Eye
} from 'lucide-react';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const AuditLogPage = () => {
  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({
    category: '',
    severity: '',
    actor: ''
  });
  const [selectedLog, setSelectedLog] = useState(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      if (filters.category) params.append('category', filters.category);
      if (filters.severity) params.append('severity', filters.severity);
      if (filters.actor) params.append('actor', filters.actor);
      params.append('limit', '200');
      
      const [logsRes, statsRes] = await Promise.all([
        fetch(`${API}/api/audit/logs?${params}`, { headers: { Authorization: `Bearer ${token}` } }),
        fetch(`${API}/api/audit/stats`, { headers: { Authorization: `Bearer ${token}` } })
      ]);
      
      if (logsRes.ok) {
        const data = await logsRes.json();
        setLogs(data.logs || []);
      }
      if (statsRes.ok) {
        setStats(await statsRes.json());
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [filters]);

  const formatDate = (isoString) => {
    return new Date(isoString).toLocaleString();
  };

  const getCategoryIcon = (category) => {
    const icons = {
      authentication: User,
      authorization: Shield,
      user_action: Activity,
      system_event: Settings,
      security_event: AlertTriangle,
      threat_response: Shield,
      configuration: Settings,
      agent_event: Activity
    };
    return icons[category] || Activity;
  };

  const getCategoryColor = (category) => {
    const colors = {
      authentication: 'text-blue-400 bg-blue-500/20',
      authorization: 'text-purple-400 bg-purple-500/20',
      user_action: 'text-cyan-400 bg-cyan-500/20',
      system_event: 'text-slate-400 bg-slate-500/20',
      security_event: 'text-red-400 bg-red-500/20',
      threat_response: 'text-orange-400 bg-orange-500/20',
      configuration: 'text-amber-400 bg-amber-500/20',
      agent_event: 'text-green-400 bg-green-500/20'
    };
    return colors[category] || 'text-slate-400 bg-slate-500/20';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      info: 'text-cyan-400',
      warning: 'text-amber-400',
      critical: 'text-red-400'
    };
    return colors[severity] || 'text-slate-400';
  };

  const exportLogs = () => {
    const csv = [
      'Timestamp,Category,Action,Actor,Description,Severity,Result',
      ...logs.map(log => 
        `"${log.timestamp}","${log.category}","${log.action}","${log.actor || ''}","${log.description}","${log.severity}","${log.result}"`
      )
    ].join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_logs_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    toast.success('Audit logs exported');
  };

  return (
    <div className="space-y-6" data-testid="audit-log-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-amber-500/20">
            <ScrollText className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-mono font-bold">Audit Logs</h1>
            <p className="text-slate-400 text-sm">Complete activity and security audit trail</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportLogs}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <p className="text-xs text-slate-400 mb-1">Total Entries</p>
            <p className="text-2xl font-mono font-bold text-white">{stats.total?.toLocaleString()}</p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <p className="text-xs text-slate-400 mb-1">Security Events</p>
            <p className="text-2xl font-mono font-bold text-red-400">
              {stats.by_category?.security_event || 0}
            </p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <p className="text-xs text-slate-400 mb-1">Threat Responses</p>
            <p className="text-2xl font-mono font-bold text-orange-400">
              {stats.by_category?.threat_response || 0}
            </p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <p className="text-xs text-slate-400 mb-1">Critical Events</p>
            <p className="text-2xl font-mono font-bold text-amber-400">
              {stats.by_severity?.critical || 0}
            </p>
          </motion.div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-400">Filters:</span>
        </div>
        
        <select
          value={filters.category}
          onChange={(e) => setFilters({...filters, category: e.target.value})}
          className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm focus:border-cyan-500 outline-none"
        >
          <option value="">All Categories</option>
          <option value="authentication">Authentication</option>
          <option value="authorization">Authorization</option>
          <option value="user_action">User Action</option>
          <option value="system_event">System Event</option>
          <option value="security_event">Security Event</option>
          <option value="threat_response">Threat Response</option>
          <option value="configuration">Configuration</option>
          <option value="agent_event">Agent Event</option>
        </select>
        
        <select
          value={filters.severity}
          onChange={(e) => setFilters({...filters, severity: e.target.value})}
          className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm focus:border-cyan-500 outline-none"
        >
          <option value="">All Severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </select>
        
        <input
          type="text"
          placeholder="Filter by actor..."
          value={filters.actor}
          onChange={(e) => setFilters({...filters, actor: e.target.value})}
          className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm focus:border-cyan-500 outline-none w-48"
        />
      </div>

      {/* Logs Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden"
      >
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            <ScrollText className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No audit logs found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-900/50 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="px-4 py-3 text-left">Timestamp</th>
                  <th className="px-4 py-3 text-left">Category</th>
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left">Actor</th>
                  <th className="px-4 py-3 text-left">Description</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-center">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {logs.map((log, idx) => {
                  const Icon = getCategoryIcon(log.category);
                  return (
                    <motion.tr
                      key={log.id || idx}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.01 }}
                      className="hover:bg-slate-700/30"
                    >
                      <td className="px-4 py-3 text-slate-400 text-xs font-mono whitespace-nowrap">
                        {formatDate(log.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className={`p-1 rounded ${getCategoryColor(log.category)}`}>
                            <Icon className="w-3 h-3" />
                          </div>
                          <span className="text-xs">{log.category}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{log.action}</td>
                      <td className="px-4 py-3 text-slate-400 text-xs max-w-32 truncate">
                        {log.actor || '-'}
                      </td>
                      <td className="px-4 py-3 text-xs max-w-xs truncate">
                        {log.description}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs ${getSeverityColor(log.severity)}`}>
                          {log.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {log.details && Object.keys(log.details).length > 0 && (
                          <button
                            onClick={() => setSelectedLog(log)}
                            className="p-1 hover:bg-slate-700 rounded"
                          >
                            <Eye className="w-4 h-4 text-slate-400" />
                          </button>
                        )}
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Detail Modal */}
      {selectedLog && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedLog(null)}
        >
          <motion.div
            initial={{ scale: 0.9 }}
            animate={{ scale: 1 }}
            className="bg-slate-800 border border-slate-700 rounded-lg w-full max-w-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 border-b border-slate-700 flex items-center justify-between">
              <h3 className="font-semibold">Audit Log Details</h3>
              <button onClick={() => setSelectedLog(null)} className="p-1 hover:bg-slate-700 rounded">
                <Eye className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-slate-400 text-xs">Timestamp</span>
                  <p className="font-mono text-xs">{formatDate(selectedLog.timestamp)}</p>
                </div>
                <div>
                  <span className="text-slate-400 text-xs">Category</span>
                  <p>{selectedLog.category}</p>
                </div>
                <div>
                  <span className="text-slate-400 text-xs">Action</span>
                  <p>{selectedLog.action}</p>
                </div>
                <div>
                  <span className="text-slate-400 text-xs">Severity</span>
                  <p className={getSeverityColor(selectedLog.severity)}>{selectedLog.severity}</p>
                </div>
              </div>
              <div>
                <span className="text-slate-400 text-xs">Actor</span>
                <p className="text-sm">{selectedLog.actor || '-'}</p>
              </div>
              <div>
                <span className="text-slate-400 text-xs">Description</span>
                <p className="text-sm">{selectedLog.description}</p>
              </div>
              {selectedLog.details && Object.keys(selectedLog.details).length > 0 && (
                <div>
                  <span className="text-slate-400 text-xs">Details</span>
                  <pre className="text-xs bg-slate-900 p-3 rounded mt-1 overflow-auto max-h-48">
                    {JSON.stringify(selectedLog.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default AuditLogPage;
