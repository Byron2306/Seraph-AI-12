import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  ShieldCheck, Monitor, Lock, Unlock, AlertTriangle, CheckCircle,
  XCircle, RefreshCw, Plus, Eye, Activity, Laptop, Server,
  Smartphone, Wifi, Clock, User, Ban, ShieldOff
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const ZeroTrustPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [devices, setDevices] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [accessLogs, setAccessLogs] = useState([]);
  const [showRegisterDevice, setShowRegisterDevice] = useState(false);
  const [newDevice, setNewDevice] = useState({
    device_id: '',
    device_name: '',
    device_type: 'workstation',
    os_info: { name: '', version: '' },
    security_posture: {
      antivirus_enabled: true,
      firewall_enabled: true,
      disk_encrypted: false,
      os_outdated: false
    }
  });
  const [testResource, setTestResource] = useState('/api/dashboard/stats');
  const [loading, setLoading] = useState(true);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, devicesRes, policiesRes, logsRes] = await Promise.all([
        axios.get(`${API}/zero-trust/stats`, { headers }),
        axios.get(`${API}/zero-trust/devices`, { headers }),
        axios.get(`${API}/zero-trust/policies`, { headers }),
        axios.get(`${API}/zero-trust/access-logs?limit=20`, { headers })
      ]);
      setStats(statsRes.data);
      setDevices(devicesRes.data.devices || []);
      setPolicies(policiesRes.data.policies || []);
      setAccessLogs(logsRes.data.logs || []);
    } catch (err) {
      toast.error('Failed to load Zero Trust data');
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterDevice = async () => {
    if (!newDevice.device_id || !newDevice.device_name) {
      toast.error('Device ID and name are required');
      return;
    }
    try {
      await axios.post(`${API}/zero-trust/devices`, newDevice, { headers });
      toast.success('Device registered');
      setShowRegisterDevice(false);
      setNewDevice({
        device_id: '',
        device_name: '',
        device_type: 'workstation',
        os_info: { name: '', version: '' },
        security_posture: {
          antivirus_enabled: true,
          firewall_enabled: true,
          disk_encrypted: false,
          os_outdated: false
        }
      });
      fetchData();
    } catch (err) {
      toast.error('Failed to register device');
    }
  };

  const handleEvaluateAccess = async () => {
    try {
      const res = await axios.post(`${API}/zero-trust/evaluate`, {
        resource: testResource,
        device_id: devices[0]?.device_id || 'unknown',
        auth_method: 'password'
      }, { headers });
      
      const decision = res.data.decision;
      if (decision === 'allow') {
        toast.success(`Access ALLOWED (Score: ${res.data.trust_score})`);
      } else if (decision === 'challenge') {
        toast.warning(`Access CHALLENGED: ${res.data.challenge_reason}`);
      } else {
        toast.error(`Access DENIED (Score: ${res.data.trust_score})`);
      }
      fetchData();
    } catch (err) {
      toast.error('Failed to evaluate access');
    }
  };

  const handleBlockDevice = async (deviceId, deviceName) => {
    if (!window.confirm(`Block device "${deviceName}"? This will set trust score to 0 and trigger a remediation command.`)) {
      return;
    }
    try {
      const res = await axios.post(`${API}/zero-trust/devices/${deviceId}/block`, {
        device_id: deviceId,
        reason: 'Manual block by administrator',
        trigger_remediation: true
      }, { headers });
      
      toast.success(`Device "${deviceName}" blocked. ${res.data.remediation_commands?.length || 0} remediation command(s) queued.`);
      fetchData();
    } catch (err) {
      toast.error('Failed to block device');
    }
  };

  const handleUnblockDevice = async (deviceId, deviceName) => {
    try {
      await axios.post(`${API}/zero-trust/devices/${deviceId}/unblock`, {}, { headers });
      toast.success(`Device "${deviceName}" unblocked`);
      fetchData();
    } catch (err) {
      toast.error('Failed to unblock device');
    }
  };

  const getDeviceIcon = (type) => {
    switch(type) {
      case 'workstation': return <Monitor className="w-4 h-4" />;
      case 'laptop': return <Laptop className="w-4 h-4" />;
      case 'mobile': return <Smartphone className="w-4 h-4" />;
      case 'server': return <Server className="w-4 h-4" />;
      default: return <Wifi className="w-4 h-4" />;
    }
  };

  const getTrustColor = (level) => {
    switch(level) {
      case 'trusted': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'high': return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      case 'medium': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'low': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'untrusted': return 'text-red-400 bg-red-500/10 border-red-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getDecisionColor = (decision) => {
    switch(decision) {
      case 'allow': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'challenge': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'deny': return 'text-red-400 bg-red-500/10 border-red-500/30';
      default: return 'text-slate-400';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="zero-trust-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
            Zero Trust Security
          </h1>
          <p className="text-slate-400 text-sm mt-1">Never trust, always verify - continuous access evaluation</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchData} variant="outline" className="border-cyan-500/50 text-cyan-400">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={() => setShowRegisterDevice(true)} className="bg-cyan-600 hover:bg-cyan-500">
            <Plus className="w-4 h-4 mr-2" />
            Register Device
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
              <Monitor className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Devices</p>
              <p className="text-2xl font-bold text-white">{stats?.devices?.total || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Compliant</p>
              <p className="text-2xl font-bold text-green-400">{stats?.devices?.compliant || 0}</p>
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
              <p className="text-slate-400 text-sm">Avg Trust Score</p>
              <p className="text-2xl font-bold text-white">{stats?.average_trust_score || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Unlock className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Allow Rate</p>
              <p className="text-2xl font-bold text-green-400">{stats?.access_decisions?.allow_rate || 0}%</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <Lock className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Denied</p>
              <p className="text-2xl font-bold text-red-400">{stats?.access_decisions?.denied || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Test Access Evaluation */}
      <Card className="bg-slate-900/50 border-cyan-500/30">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Eye className="w-5 h-5 text-cyan-400" />
            Test Access Evaluation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Resource path (e.g., /api/admin/users)"
              value={testResource}
              onChange={(e) => setTestResource(e.target.value)}
              className="bg-slate-800 border-slate-700 text-white flex-1"
            />
            <Button onClick={handleEvaluateAccess} className="bg-cyan-600 hover:bg-cyan-500">
              <ShieldCheck className="w-4 h-4 mr-2" />
              Evaluate Access
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Register Device Form */}
      {showRegisterDevice && (
        <Card className="bg-slate-900/50 border-cyan-500/30">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Plus className="w-5 h-5 text-cyan-400" />
              Register Device
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Device ID *</label>
                <Input
                  placeholder="e.g., LAPTOP-ABC123"
                  value={newDevice.device_id}
                  onChange={(e) => setNewDevice({...newDevice, device_id: e.target.value})}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Device Name *</label>
                <Input
                  placeholder="e.g., John's Laptop"
                  value={newDevice.device_name}
                  onChange={(e) => setNewDevice({...newDevice, device_name: e.target.value})}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Device Type</label>
                <select
                  value={newDevice.device_type}
                  onChange={(e) => setNewDevice({...newDevice, device_type: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white"
                >
                  <option value="workstation">Workstation</option>
                  <option value="laptop">Laptop</option>
                  <option value="mobile">Mobile</option>
                  <option value="server">Server</option>
                  <option value="iot">IoT</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <label className="flex items-center gap-2 text-sm text-slate-400">
                <input
                  type="checkbox"
                  checked={newDevice.security_posture.antivirus_enabled}
                  onChange={(e) => setNewDevice({
                    ...newDevice,
                    security_posture: {...newDevice.security_posture, antivirus_enabled: e.target.checked}
                  })}
                  className="rounded"
                />
                Antivirus Enabled
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-400">
                <input
                  type="checkbox"
                  checked={newDevice.security_posture.firewall_enabled}
                  onChange={(e) => setNewDevice({
                    ...newDevice,
                    security_posture: {...newDevice.security_posture, firewall_enabled: e.target.checked}
                  })}
                  className="rounded"
                />
                Firewall Enabled
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-400">
                <input
                  type="checkbox"
                  checked={newDevice.security_posture.disk_encrypted}
                  onChange={(e) => setNewDevice({
                    ...newDevice,
                    security_posture: {...newDevice.security_posture, disk_encrypted: e.target.checked}
                  })}
                  className="rounded"
                />
                Disk Encrypted
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-400">
                <input
                  type="checkbox"
                  checked={newDevice.security_posture.os_outdated}
                  onChange={(e) => setNewDevice({
                    ...newDevice,
                    security_posture: {...newDevice.security_posture, os_outdated: e.target.checked}
                  })}
                  className="rounded"
                />
                OS Outdated
              </label>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleRegisterDevice} className="bg-cyan-600 hover:bg-cyan-500">
                Register Device
              </Button>
              <Button onClick={() => setShowRegisterDevice(false)} variant="outline">
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Devices */}
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Monitor className="w-5 h-5 text-cyan-400" />
              Registered Devices ({devices.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {devices.length > 0 ? (
              <div className="space-y-3">
                {devices.map((device) => (
                  <div key={device.device_id} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        {getDeviceIcon(device.device_type)}
                        <div>
                          <p className="text-white font-medium">{device.device_name}</p>
                          <p className="text-slate-400 text-xs font-mono">{device.device_id}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={getTrustColor(device.trust_level)}>
                          {device.trust_level} ({device.trust_score})
                        </Badge>
                        {device.trust_level === 'untrusted' ? (
                          <Button
                            size="sm"
                            variant="outline"
                            className="border-green-500/50 text-green-400 hover:bg-green-500/10"
                            onClick={() => handleUnblockDevice(device.device_id, device.device_name)}
                          >
                            <Unlock className="w-3 h-3 mr-1" />
                            Unblock
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                            onClick={() => handleBlockDevice(device.device_id, device.device_name)}
                          >
                            <Ban className="w-3 h-3 mr-1" />
                            Block
                          </Button>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-2 text-xs">
                      {device.is_compliant ? (
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                          <CheckCircle className="w-3 h-3 mr-1" />
                          Compliant
                        </Badge>
                      ) : (
                        <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                          <XCircle className="w-3 h-3 mr-1" />
                          Non-Compliant
                        </Badge>
                      )}
                      <Badge variant="outline" className="text-slate-400">
                        {device.device_type}
                      </Badge>
                    </div>
                    {device.compliance_issues?.length > 0 && (
                      <div className="mt-2 text-xs text-red-400">
                        Issues: {device.compliance_issues.join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-slate-400">
                <Monitor className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No devices registered</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Access Policies */}
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-purple-400" />
              Access Policies ({policies.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {policies.map((policy) => (
                <div key={policy.id} className={`p-3 rounded-lg border ${policy.is_active ? 'bg-slate-800/50 border-slate-700' : 'bg-slate-900/30 border-slate-800 opacity-60'}`}>
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-white font-medium text-sm">{policy.name}</p>
                    <Badge variant="outline" className={getTrustColor(policy.required_trust_level)}>
                      {policy.required_trust_level}
                    </Badge>
                  </div>
                  <p className="text-slate-400 text-xs mb-2">{policy.description}</p>
                  <div className="flex gap-2 text-xs">
                    <Badge variant="outline" className="text-cyan-400 border-cyan-500/30 font-mono">
                      {policy.resource_pattern}
                    </Badge>
                    {policy.require_mfa && (
                      <Badge className="bg-purple-500/20 text-purple-400">MFA Required</Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Access Logs */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-400" />
            Recent Access Evaluations
          </CardTitle>
        </CardHeader>
        <CardContent>
          {accessLogs.length > 0 ? (
            <div className="space-y-2">
              {accessLogs.map((log) => (
                <div key={log.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <div className="flex items-center gap-4">
                    <div className={`w-8 h-8 rounded flex items-center justify-center ${getDecisionColor(log.decision)}`}>
                      {log.decision === 'allow' ? <Unlock className="w-4 h-4" /> :
                       log.decision === 'deny' ? <Lock className="w-4 h-4" /> :
                       <AlertTriangle className="w-4 h-4" />}
                    </div>
                    <div>
                      <p className="text-white text-sm font-mono">{log.resource}</p>
                      <p className="text-slate-400 text-xs">
                        Score: {log.trust_score} | Device: {log.device_id}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className={getDecisionColor(log.decision)}>
                      {log.decision.toUpperCase()}
                    </Badge>
                    <span className="text-slate-500 text-xs">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No access evaluations yet</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default ZeroTrustPage;
