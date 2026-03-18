import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, Zap, Ban, Clock, Activity, AlertTriangle,
  Phone, Bot, RefreshCw, Play, Pause, Check, X,
  Server, Globe, Unlock, FileText, Settings2, Send
} from 'lucide-react';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const ThreatResponsePage = () => {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [history, setHistory] = useState([]);
  const [settings, setSettings] = useState(null);
  const [openclawStatus, setOpenclawStatus] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);
  const [blockForm, setBlockForm] = useState({ ip: '', reason: '', duration: 24 });

  const fetchData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const headers = { Authorization: `Bearer ${token}` };
      
      const [statsRes, blockedRes, historyRes, settingsRes, openclawRes] = await Promise.all([
        fetch(`${API}/api/threat-response/stats`, { headers }),
        fetch(`${API}/api/threat-response/blocked-ips`, { headers }),
        fetch(`${API}/api/threat-response/history?limit=20`, { headers }),
        fetch(`${API}/api/threat-response/settings`, { headers }),
        fetch(`${API}/api/threat-response/openclaw/status`, { headers })
      ]);
      
      if (statsRes.ok) setStats(await statsRes.json());
      if (blockedRes.ok) setBlockedIPs((await blockedRes.json()).blocked_ips || []);
      if (historyRes.ok) setHistory((await historyRes.json()).history || []);
      if (settingsRes.ok) setSettings(await settingsRes.json());
      if (openclawRes.ok) setOpenclawStatus(await openclawRes.json());
    } catch (err) {
      console.error('Failed to fetch data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleBlockIP = async () => {
    if (!blockForm.ip) {
      toast.error('Please enter an IP address');
      return;
    }
    
    setActionLoading('block');
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/threat-response/block-ip`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          ip: blockForm.ip,
          reason: blockForm.reason || 'Manual block',
          duration_hours: parseInt(blockForm.duration) || 24
        })
      });
      
      if (response.ok) {
        toast.success(`IP ${blockForm.ip} blocked successfully`);
        setBlockForm({ ip: '', reason: '', duration: 24 });
        fetchData();
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to block IP');
      }
    } catch (err) {
      toast.error('Failed to block IP');
    } finally {
      setActionLoading(null);
    }
  };

  const handleUnblockIP = async (ip) => {
    setActionLoading(ip);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/threat-response/unblock-ip/${ip}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        toast.success(`IP ${ip} unblocked`);
        fetchData();
      } else {
        toast.error('Failed to unblock IP');
      }
    } catch (err) {
      toast.error('Failed to unblock IP');
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleAutoBlock = async () => {
    setActionLoading('toggle');
    try {
      const token = localStorage.getItem('token');
      const newState = !settings?.auto_response?.auto_block_enabled;
      const response = await fetch(`${API}/api/threat-response/settings/auto-block?enabled=${newState}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        toast.success(`Agentic Auto-Block ${newState ? 'enabled' : 'disabled'}`);
        fetchData();
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to toggle auto-block');
      }
    } catch (err) {
      toast.error('Failed to toggle auto-block');
    } finally {
      setActionLoading(null);
    }
  };

  const handleTestSMS = async () => {
    setActionLoading('sms');
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/threat-response/test-sms`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        toast.success(data.message);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to send test SMS');
      }
    } catch (err) {
      toast.error('Failed to send test SMS');
    } finally {
      setActionLoading(null);
    }
  };

  const formatDate = (isoString) => {
    return new Date(isoString).toLocaleString();
  };

  const getActionIcon = (action) => {
    const icons = {
      'block_ip': Ban,
      'unblock_ip': Unlock,
      'send_alert': Phone,
      'collect_forensics': FileText,
      'notify_soc': AlertTriangle
    };
    return icons[action] || Zap;
  };

  const getStatusColor = (status) => {
    const colors = {
      'success': 'text-green-400 bg-green-500/20',
      'failed': 'text-red-400 bg-red-500/20',
      'pending': 'text-yellow-400 bg-yellow-500/20'
    };
    return colors[status] || 'text-slate-400 bg-slate-500/20';
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="threat-response-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-red-500/20">
            <Zap className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-mono font-bold">Automated Response</h1>
            <p className="text-slate-400 text-sm">Autonomous threat detection and mitigation</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleToggleAutoBlock}
            disabled={actionLoading === 'toggle'}
            className={`flex items-center gap-2 px-4 py-2 rounded font-semibold transition-all ${
              settings?.auto_response?.auto_block_enabled 
                ? 'bg-green-600 hover:bg-green-500 text-white' 
                : 'bg-slate-700 hover:bg-slate-600 text-slate-300'
            }`}
            data-testid="auto-block-toggle"
          >
            {settings?.auto_response?.auto_block_enabled ? (
              <>
                <Play className="w-4 h-4" />
                <span>Auto-Block ON</span>
              </>
            ) : (
              <>
                <Pause className="w-4 h-4" />
                <span>Auto-Block OFF</span>
              </>
            )}
          </button>
          <button
            onClick={fetchData}
            disabled={loading}
            className="p-2 bg-slate-700 hover:bg-slate-600 rounded"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
        >
          <div className="flex items-center gap-2 text-slate-400 mb-1">
            <Activity className="w-4 h-4" />
            <span className="text-xs">Total Responses</span>
          </div>
          <p className="text-2xl font-mono font-bold text-white">{stats?.total_responses || 0}</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
        >
          <div className="flex items-center gap-2 text-red-400 mb-1">
            <Ban className="w-4 h-4" />
            <span className="text-xs">Blocked IPs</span>
          </div>
          <p className="text-2xl font-mono font-bold text-red-400">{stats?.blocked_ips || 0}</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
        >
          <div className="flex items-center gap-2 text-amber-400 mb-1">
            <Globe className="w-4 h-4" />
            <span className="text-xs">Attack Sources</span>
          </div>
          <p className="text-2xl font-mono font-bold text-amber-400">{stats?.attack_sources || 0}</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
        >
          <div className="flex items-center gap-2 text-cyan-400 mb-1">
            <Phone className="w-4 h-4" />
            <span className="text-xs">SMS Alerts</span>
          </div>
          <p className="text-2xl font-mono font-bold text-cyan-400">
            {settings?.sms_alerts?.enabled ? (
              <Check className="w-6 h-6 text-green-400" />
            ) : (
              <X className="w-6 h-6 text-slate-500" />
            )}
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
        >
          <div className="flex items-center gap-2 text-purple-400 mb-1">
            <Bot className="w-4 h-4" />
            <span className="text-xs">OpenClaw AI</span>
          </div>
          <p className="text-2xl font-mono font-bold">
            {openclawStatus?.available ? (
              <Check className="w-6 h-6 text-green-400" />
            ) : openclawStatus?.enabled ? (
              <AlertTriangle className="w-6 h-6 text-amber-400" />
            ) : (
              <X className="w-6 h-6 text-slate-500" />
            )}
          </p>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Manual IP Block */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded bg-red-500/20">
              <Ban className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h3 className="font-semibold">Manual IP Block</h3>
              <p className="text-xs text-slate-400">Block suspicious IPs immediately</p>
            </div>
          </div>
          
          <div className="space-y-3">
            <div>
              <label className="text-xs text-slate-400 mb-1 block">IP Address</label>
              <input
                type="text"
                placeholder="192.168.1.100"
                value={blockForm.ip}
                onChange={(e) => setBlockForm({...blockForm, ip: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-red-500 outline-none text-sm font-mono"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Reason</label>
                <input
                  type="text"
                  placeholder="Suspicious activity"
                  value={blockForm.reason}
                  onChange={(e) => setBlockForm({...blockForm, reason: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Duration (hours)</label>
                <input
                  type="number"
                  value={blockForm.duration}
                  onChange={(e) => setBlockForm({...blockForm, duration: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
                />
              </div>
            </div>
            <button
              onClick={handleBlockIP}
              disabled={actionLoading === 'block'}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 rounded font-semibold disabled:opacity-50"
            >
              <Ban className="w-4 h-4" />
              {actionLoading === 'block' ? 'Blocking...' : 'Block IP'}
            </button>
          </div>
        </motion.div>

        {/* Currently Blocked IPs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded bg-amber-500/20">
                <Shield className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="font-semibold">Blocked IPs ({blockedIPs.length})</h3>
                <p className="text-xs text-slate-400">Currently blocked addresses</p>
              </div>
            </div>
          </div>
          
          <div className="max-h-64 overflow-y-auto space-y-2">
            {blockedIPs.length === 0 ? (
              <div className="text-center py-8 text-slate-500">
                <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No IPs currently blocked</p>
              </div>
            ) : (
              blockedIPs.map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 bg-slate-900/50 rounded border border-slate-700"
                >
                  <div>
                    <p className="font-mono text-white">{item.ip}</p>
                    <p className="text-xs text-slate-400 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      Expires: {formatDate(item.expires)}
                    </p>
                  </div>
                  <button
                    onClick={() => handleUnblockIP(item.ip)}
                    disabled={actionLoading === item.ip}
                    className="px-3 py-1.5 bg-green-600/20 hover:bg-green-600/40 text-green-400 rounded text-sm flex items-center gap-1"
                  >
                    <Unlock className="w-3 h-3" />
                    Unblock
                  </button>
                </div>
              ))
            )}
          </div>
        </motion.div>

        {/* Integration Status */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded bg-purple-500/20">
              <Settings2 className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h3 className="font-semibold">Integration Status</h3>
              <p className="text-xs text-slate-400">Connected services and AI agents</p>
            </div>
          </div>
          
          <div className="space-y-3">
            {/* SMS Alerts */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 rounded">
              <div className="flex items-center gap-3">
                <Phone className={`w-5 h-5 ${settings?.sms_alerts?.enabled ? 'text-green-400' : 'text-slate-500'}`} />
                <div>
                  <p className="font-semibold text-sm">Twilio SMS</p>
                  <p className="text-xs text-slate-400">
                    {settings?.sms_alerts?.contacts_count || 0} contacts configured
                  </p>
                </div>
              </div>
              {settings?.sms_alerts?.enabled && (
                <button
                  onClick={handleTestSMS}
                  disabled={actionLoading === 'sms'}
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 rounded text-xs flex items-center gap-1"
                >
                  <Send className="w-3 h-3" />
                  Test
                </button>
              )}
            </div>
            
            {/* OpenClaw AI */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 rounded">
              <div className="flex items-center gap-3">
                <Bot className={`w-5 h-5 ${openclawStatus?.available ? 'text-green-400' : openclawStatus?.enabled ? 'text-amber-400' : 'text-slate-500'}`} />
                <div>
                  <p className="font-semibold text-sm">OpenClaw AI Agent</p>
                  <p className="text-xs text-slate-400">
                    {openclawStatus?.available ? 'Connected & Ready' : openclawStatus?.enabled ? 'Enabled (Offline)' : 'Not configured'}
                  </p>
                </div>
              </div>
              <div className={`px-2 py-1 rounded text-xs ${openclawStatus?.available ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
                {openclawStatus?.available ? 'Online' : 'Offline'}
              </div>
            </div>
            
            {/* Firewall */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 rounded">
              <div className="flex items-center gap-3">
                <Server className="w-5 h-5 text-blue-400" />
                <div>
                  <p className="font-semibold text-sm">Firewall Integration</p>
                  <p className="text-xs text-slate-400">
                    iptables/firewalld/ufw auto-detection
                  </p>
                </div>
              </div>
              <div className="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400">
                Active
              </div>
            </div>
          </div>
        </motion.div>

        {/* Response History */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded bg-cyan-500/20">
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="font-semibold">Response History</h3>
              <p className="text-xs text-slate-400">Recent automated actions</p>
            </div>
          </div>
          
          <div className="max-h-64 overflow-y-auto space-y-2">
            {history.length === 0 ? (
              <div className="text-center py-8 text-slate-500">
                <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No response history yet</p>
              </div>
            ) : (
              history.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-900/50 rounded border border-slate-700"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      item.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      item.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {item.severity}
                    </span>
                    <span className="text-xs text-slate-500">{formatDate(item.timestamp)}</span>
                  </div>
                  <p className="text-sm font-semibold">{item.threat_type}</p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {item.results?.map((result, ridx) => {
                      const Icon = getActionIcon(result.action);
                      return (
                        <span
                          key={ridx}
                          className={`px-2 py-0.5 rounded text-xs flex items-center gap-1 ${getStatusColor(result.status)}`}
                        >
                          <Icon className="w-3 h-3" />
                          {result.action.replace('_', ' ')}
                        </span>
                      );
                    })}
                  </div>
                </div>
              ))
            )}
          </div>
        </motion.div>
      </div>

      {/* Configuration Info */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-lg p-6"
      >
        <div className="flex items-start gap-4">
          <Bot className="w-8 h-8 text-purple-400 flex-shrink-0" />
          <div>
            <h3 className="font-semibold text-lg mb-2">Agentic Security System</h3>
            <p className="text-sm text-slate-300 mb-4">
              This system autonomously responds to threats using AI-powered decision making. 
              When enabled, it can automatically block malicious IPs, send emergency SMS alerts, 
              collect forensic data, and leverage OpenClaw AI for advanced threat analysis.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div className="p-3 bg-slate-800/50 rounded">
                <p className="text-slate-400 mb-1">Auto-Block Threshold</p>
                <p className="font-mono text-white">{settings?.auto_response?.critical_threat_threshold || 3} attacks</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded">
                <p className="text-slate-400 mb-1">Block Duration</p>
                <p className="font-mono text-white">{settings?.auto_response?.block_duration_hours || 24} hours</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded">
                <p className="text-slate-400 mb-1">SMS Triggers</p>
                <p className="font-mono text-white">Critical threats</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded">
                <p className="text-slate-400 mb-1">Forensics</p>
                <p className="font-mono text-white">Auto-collect</p>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default ThreatResponsePage;
