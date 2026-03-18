import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, Trash2, RotateCcw, AlertTriangle, FileWarning,
  HardDrive, Clock, Search, RefreshCw, Eye, Download,
  Check, X, Filter, ChevronDown
} from 'lucide-react';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const QuarantinePage = () => {
  const [loading, setLoading] = useState(true);
  const [entries, setEntries] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [filter, setFilter] = useState({ status: '', threat_type: '' });
  const [actionLoading, setActionLoading] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const headers = { Authorization: `Bearer ${token}` };
      
      const [entriesRes, summaryRes] = await Promise.all([
        fetch(`${API}/api/quarantine?status=${filter.status}&threat_type=${filter.threat_type}`, { headers }),
        fetch(`${API}/api/quarantine/summary`, { headers })
      ]);
      
      if (entriesRes.ok) {
        const data = await entriesRes.json();
        // Backend returns array directly, not wrapped in { entries: [] }
        setEntries(Array.isArray(data) ? data : (data.entries || []));
      }
      
      if (summaryRes.ok) {
        const data = await summaryRes.json();
        // Map backend response to expected format
        setSummary({
          total_entries: data.total_files || 0,
          by_status: data.by_status || {},
          by_threat_type: data.by_threat_type || {},
          storage: data.storage || {}
        });
      }
    } catch (err) {
      console.error('Failed to fetch quarantine data:', err);
      toast.error('Failed to load quarantine data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [filter]);

  const handleRestore = async (entryId) => {
    if (!window.confirm('Are you sure you want to restore this file? It may be infected.')) {
      return;
    }
    
    setActionLoading(entryId);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/quarantine/${entryId}/restore`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        toast.success('File restored successfully');
        fetchData();
        setSelectedEntry(null);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to restore file');
      }
    } catch (err) {
      toast.error('Failed to restore file');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (entryId) => {
    if (!window.confirm('Are you sure you want to permanently delete this file? This action cannot be undone.')) {
      return;
    }
    
    setActionLoading(entryId);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/quarantine/${entryId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        toast.success('File permanently deleted');
        fetchData();
        setSelectedEntry(null);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to delete file');
      }
    } catch (err) {
      toast.error('Failed to delete file');
    } finally {
      setActionLoading(null);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (isoString) => {
    return new Date(isoString).toLocaleString();
  };

  const getSeverityColor = (threatType) => {
    const colors = {
      'malware': 'text-red-400 bg-red-500/20',
      'virus': 'text-red-400 bg-red-500/20',
      'ransomware': 'text-red-400 bg-red-500/20',
      'trojan': 'text-orange-400 bg-orange-500/20',
      'spyware': 'text-orange-400 bg-orange-500/20',
      'adware': 'text-yellow-400 bg-yellow-500/20',
      'unknown': 'text-slate-400 bg-slate-500/20'
    };
    return colors[threatType?.toLowerCase()] || colors.unknown;
  };

  const getStatusColor = (status) => {
    const colors = {
      'quarantined': 'text-amber-400 bg-amber-500/20',
      'restored': 'text-green-400 bg-green-500/20',
      'deleted': 'text-red-400 bg-red-500/20'
    };
    return colors[status] || 'text-slate-400 bg-slate-500/20';
  };

  return (
    <div className="space-y-6" data-testid="quarantine-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-amber-500/20">
            <Shield className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-mono font-bold">Quarantine</h1>
            <p className="text-slate-400 text-sm">Manage isolated malware and infected files</p>
          </div>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded transition-colors"
          data-testid="refresh-quarantine-btn"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <div className="flex items-center gap-2 text-slate-400 mb-1">
              <FileWarning className="w-4 h-4" />
              <span className="text-xs">Total Entries</span>
            </div>
            <p className="text-2xl font-mono font-bold text-white">{summary.total_entries}</p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <div className="flex items-center gap-2 text-amber-400 mb-1">
              <Shield className="w-4 h-4" />
              <span className="text-xs">Quarantined</span>
            </div>
            <p className="text-2xl font-mono font-bold text-amber-400">{summary.by_status?.quarantined || 0}</p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <div className="flex items-center gap-2 text-green-400 mb-1">
              <RotateCcw className="w-4 h-4" />
              <span className="text-xs">Restored</span>
            </div>
            <p className="text-2xl font-mono font-bold text-green-400">{summary.by_status?.restored || 0}</p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <div className="flex items-center gap-2 text-red-400 mb-1">
              <Trash2 className="w-4 h-4" />
              <span className="text-xs">Deleted</span>
            </div>
            <p className="text-2xl font-mono font-bold text-red-400">{summary.by_status?.deleted || 0}</p>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
          >
            <div className="flex items-center gap-2 text-cyan-400 mb-1">
              <HardDrive className="w-4 h-4" />
              <span className="text-xs">Storage Used</span>
            </div>
            <p className="text-2xl font-mono font-bold text-cyan-400">
              {summary.storage?.total_size_mb || 0} MB
            </p>
            <p className="text-xs text-slate-500">
              {summary.storage?.usage_percent || 0}% of {summary.storage?.max_size_mb || 1000} MB
            </p>
          </motion.div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-400">Filters:</span>
        </div>
        
        <select
          value={filter.status}
          onChange={(e) => setFilter({...filter, status: e.target.value})}
          className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm focus:border-cyan-500 outline-none"
        >
          <option value="">All Status</option>
          <option value="quarantined">Quarantined</option>
          <option value="restored">Restored</option>
          <option value="deleted">Deleted</option>
        </select>
        
        <select
          value={filter.threat_type}
          onChange={(e) => setFilter({...filter, threat_type: e.target.value})}
          className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm focus:border-cyan-500 outline-none"
        >
          <option value="">All Threats</option>
          <option value="malware">Malware</option>
          <option value="virus">Virus</option>
          <option value="ransomware">Ransomware</option>
          <option value="trojan">Trojan</option>
          <option value="spyware">Spyware</option>
        </select>
      </div>

      {/* Entries Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden"
      >
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
          </div>
        ) : entries.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400">No quarantined files found</p>
            <p className="text-sm text-slate-500 mt-1">
              Files detected by YARA or ClamAV will appear here when auto-quarantine is enabled
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-900/50 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="px-4 py-3 text-left">Threat</th>
                  <th className="px-4 py-3 text-left">Original Path</th>
                  <th className="px-4 py-3 text-left">Type</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Size</th>
                  <th className="px-4 py-3 text-left">Source</th>
                  <th className="px-4 py-3 text-left">Date</th>
                  <th className="px-4 py-3 text-center">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {entries.map((entry, index) => (
                  <motion.tr
                    key={entry.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: index * 0.02 }}
                    className="hover:bg-slate-700/30 cursor-pointer"
                    onClick={() => setSelectedEntry(entry)}
                    data-testid={`quarantine-entry-${entry.id}`}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <span className="font-mono text-white">{entry.threat_name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs max-w-xs truncate">
                      {entry.original_path}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(entry.threat_type)}`}>
                        {entry.threat_type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${getStatusColor(entry.status)}`}>
                        {entry.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                      {formatBytes(entry.file_size)}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {entry.detection_source}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {formatDate(entry.quarantined_at)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-center gap-2" onClick={(e) => e.stopPropagation()}>
                        {entry.status === 'quarantined' && (
                          <>
                            <button
                              onClick={() => handleRestore(entry.id)}
                              disabled={actionLoading === entry.id}
                              className="p-1.5 hover:bg-green-500/20 rounded text-green-400 disabled:opacity-50"
                              title="Restore file"
                            >
                              <RotateCcw className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleDelete(entry.id)}
                              disabled={actionLoading === entry.id}
                              className="p-1.5 hover:bg-red-500/20 rounded text-red-400 disabled:opacity-50"
                              title="Delete permanently"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => setSelectedEntry(entry)}
                          className="p-1.5 hover:bg-slate-700 rounded text-slate-400"
                          title="View details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Detail Modal */}
      {selectedEntry && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedEntry(null)}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-slate-800 border border-slate-700 rounded-lg w-full max-w-2xl max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 border-b border-slate-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded bg-red-500/20">
                    <AlertTriangle className="w-6 h-6 text-red-400" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold">{selectedEntry.threat_name}</h2>
                    <p className="text-sm text-slate-400">Quarantine Entry Details</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEntry(null)}
                  className="p-2 hover:bg-slate-700 rounded"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-slate-400">Entry ID</label>
                  <p className="font-mono text-sm">{selectedEntry.id}</p>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Status</label>
                  <p className={`inline-block px-2 py-0.5 rounded text-sm ${getStatusColor(selectedEntry.status)}`}>
                    {selectedEntry.status}
                  </p>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Threat Type</label>
                  <p className={`inline-block px-2 py-0.5 rounded text-sm ${getSeverityColor(selectedEntry.threat_type)}`}>
                    {selectedEntry.threat_type}
                  </p>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Detection Source</label>
                  <p className="text-sm">{selectedEntry.detection_source}</p>
                </div>
                <div>
                  <label className="text-xs text-slate-400">File Size</label>
                  <p className="font-mono text-sm">{formatBytes(selectedEntry.file_size)}</p>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Quarantined At</label>
                  <p className="text-sm">{formatDate(selectedEntry.quarantined_at)}</p>
                </div>
              </div>
              
              <div>
                <label className="text-xs text-slate-400">Original Path</label>
                <p className="font-mono text-sm bg-slate-900 px-3 py-2 rounded break-all">
                  {selectedEntry.original_path}
                </p>
              </div>
              
              <div>
                <label className="text-xs text-slate-400">Quarantine Path</label>
                <p className="font-mono text-sm bg-slate-900 px-3 py-2 rounded break-all">
                  {selectedEntry.quarantine_path}
                </p>
              </div>
              
              <div>
                <label className="text-xs text-slate-400">File Hash (SHA-256)</label>
                <p className="font-mono text-xs bg-slate-900 px-3 py-2 rounded break-all">
                  {selectedEntry.file_hash}
                </p>
              </div>
              
              {selectedEntry.agent_name && (
                <div>
                  <label className="text-xs text-slate-400">Detected By Agent</label>
                  <p className="text-sm">{selectedEntry.agent_name}</p>
                </div>
              )}
              
              {selectedEntry.status === 'quarantined' && (
                <div className="flex gap-3 pt-4 border-t border-slate-700">
                  <button
                    onClick={() => handleRestore(selectedEntry.id)}
                    disabled={actionLoading === selectedEntry.id}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 rounded font-semibold disabled:opacity-50"
                  >
                    <RotateCcw className="w-4 h-4" />
                    Restore File
                  </button>
                  <button
                    onClick={() => handleDelete(selectedEntry.id)}
                    disabled={actionLoading === selectedEntry.id}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 rounded font-semibold disabled:opacity-50"
                  >
                    <Trash2 className="w-4 h-4" />
                    Delete Permanently
                  </button>
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default QuarantinePage;
