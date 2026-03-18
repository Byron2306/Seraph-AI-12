import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  Smartphone,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Lock,
  Unlock,
  Wifi,
  WifiOff,
  Eye,
  Plus,
  Trash2,
  Activity,
  Cpu,
  Layers,
  AlertCircle,
  Settings
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const MobileSecurityPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [devices, setDevices] = useState([]);
  const [threats, setThreats] = useState([]);
  const [appAnalyses, setAppAnalyses] = useState([]);
  const [policies, setPolicies] = useState({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  
  const [deviceForm, setDeviceForm] = useState({
    device_name: '',
    platform: 'android',
    os_version: '',
    model: '',
    serial_number: '',
    user_email: ''
  });
  const [appForm, setAppForm] = useState({
    package_name: '',
    app_name: '',
    version: '',
    platform: 'android',
    permissions: '',
    is_sideloaded: false
  });
  const [analysisResult, setAnalysisResult] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const responses = await Promise.all([
        fetch(`${API_URL}/api/mobile-security/stats`, { headers }),
        fetch(`${API_URL}/api/mobile-security/dashboard`, { headers }),
        fetch(`${API_URL}/api/mobile-security/devices`, { headers }),
        fetch(`${API_URL}/api/mobile-security/threats`, { headers }),
        fetch(`${API_URL}/api/mobile-security/app-analyses`, { headers }),
        fetch(`${API_URL}/api/mobile-security/policies`, { headers })
      ]);

      if (responses[0].ok) setStats(await responses[0].json());
      if (responses[1].ok) setDashboard(await responses[1].json());
      if (responses[2].ok) {
        const data = await responses[2].json();
        setDevices(data.devices || []);
      }
      if (responses[3].ok) {
        const data = await responses[3].json();
        setThreats(data.threats || []);
      }
      if (responses[4].ok) {
        const data = await responses[4].json();
        setAppAnalyses(data.analyses || []);
      }
      if (responses[5].ok) {
        const data = await responses[5].json();
        setPolicies(data.policies || {});
      }
    } catch (error) {
      console.error('Failed to fetch mobile security data:', error);
    } finally {
      setLoading(false);
    }
  };

  const registerDevice = async () => {
    if (!deviceForm.device_name || !deviceForm.serial_number) {
      toast.error('Device name and serial number are required');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/mobile-security/devices`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(deviceForm)
      });

      if (response.ok) {
        toast.success('Device registered successfully');
        setDeviceForm({ device_name: '', platform: 'android', os_version: '', model: '', serial_number: '', user_email: '' });
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to register device');
    }
  };

  const unenrollDevice = async (deviceId) => {
    try {
      const response = await fetch(`${API_URL}/api/mobile-security/devices/${deviceId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        toast.success('Device unenrolled');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to unenroll device');
    }
  };

  const resolveThreat = async (threatId) => {
    try {
      const response = await fetch(`${API_URL}/api/mobile-security/threats/${threatId}/resolve`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ resolution_notes: 'Resolved via dashboard' })
      });
      if (response.ok) {
        toast.success('Threat marked as resolved');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to resolve threat');
    }
  };

  const analyzeApp = async () => {
    if (!appForm.package_name || !appForm.app_name) {
      toast.error('Package name and app name are required');
      return;
    }

    try {
      const payload = { ...appForm, permissions: appForm.permissions ? appForm.permissions.split(',').map(p => p.trim()) : [] };
      const response = await fetch(`${API_URL}/api/mobile-security/analyze-app`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        const result = await response.json();
        setAnalysisResult(result);
        toast.success(`App analyzed: ${result.risk_level} risk`);
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to analyze app');
    }
  };

  const checkCompliance = async (deviceId) => {
    try {
      const response = await fetch(`${API_URL}/api/mobile-security/devices/${deviceId}/compliance`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const result = await response.json();
        setSelectedDevice({ ...devices.find(d => d.device_id === deviceId), compliance: result });
        toast.success('Compliance check complete');
      }
    } catch (error) {
      toast.error('Failed to check compliance');
    }
  };

  const getStatusBadge = (status) => {
    const colors = {
      compliant: 'bg-green-500/20 text-green-400',
      non_compliant: 'bg-yellow-500/20 text-yellow-400',
      at_risk: 'bg-orange-500/20 text-orange-400',
      compromised: 'bg-red-500/20 text-red-400',
      offline: 'bg-slate-500/20 text-slate-400',
      pending: 'bg-blue-500/20 text-blue-400'
    };
    return colors[status] || colors.pending;
  };

  const getSeverityBadge = (severity) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400',
      high: 'bg-orange-500/20 text-orange-400',
      medium: 'bg-yellow-500/20 text-yellow-400',
      low: 'bg-blue-500/20 text-blue-400',
      info: 'bg-slate-500/20 text-slate-400'
    };
    return colors[severity] || colors.info;
  };

  const getPlatformIcon = (platform) => platform === 'ios' ? '🍎' : '🤖';

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading Mobile Security...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Smartphone className="h-8 w-8 text-blue-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">Mobile Security</h1>
              <p className="text-slate-400">Mobile threat defense, device management, and app security</p>
            </div>
          </div>
          <Button onClick={fetchData} variant="outline" className="border-slate-700">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/20">
                  <Smartphone className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Total Devices</p>
                  <p className="text-2xl font-bold text-white">{stats?.total_devices || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/20">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Active Threats</p>
                  <p className="text-2xl font-bold text-white">{stats?.active_threats || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-green-500/20">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Compliant</p>
                  <p className="text-2xl font-bold text-white">{stats?.by_status?.compliant || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-orange-500/20">
                  <AlertCircle className="h-5 w-5 text-orange-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">At Risk</p>
                  <p className="text-2xl font-bold text-white">{(stats?.by_status?.at_risk || 0) + (stats?.by_status?.compromised || 0)}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/20">
                  <Layers className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Apps Analyzed</p>
                  <p className="text-2xl font-bold text-white">{stats?.app_analyses || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="flex gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
          {['overview', 'devices', 'threats', 'apps', 'compliance'].map((tab) => (
            <Button key={tab} variant={activeTab === tab ? 'default' : 'ghost'} onClick={() => setActiveTab(tab)} className={activeTab === tab ? 'bg-blue-600' : 'text-slate-400'}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </Button>
          ))}
        </div>

        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-blue-400" />
                  Platform Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {stats?.by_platform && Object.entries(stats.by_platform).map(([platform, count]) => (
                  <div key={platform} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                    <span className="text-slate-300 flex items-center gap-2">{getPlatformIcon(platform)} {platform.toUpperCase()}</span>
                    <Badge className="bg-blue-500/20 text-blue-400">{count}</Badge>
                  </div>
                ))}
                {(!stats?.by_platform || Object.keys(stats.by_platform).length === 0) && (
                  <p className="text-slate-500 text-center py-4">No devices registered</p>
                )}
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="h-5 w-5 text-green-400" />
                  Security Features
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {stats?.features && Object.entries(stats.features).map(([feature, enabled]) => (
                  <div key={feature} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                    <span className="text-slate-300">{feature.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                    <Badge className={enabled ? "bg-green-500/20 text-green-400" : "bg-slate-500/20 text-slate-400"}>{enabled ? 'Active' : 'Inactive'}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'devices' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Plus className="h-5 w-5 text-green-400" />
                  Register Device
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <input type="text" placeholder="Device name" value={deviceForm.device_name} onChange={(e) => setDeviceForm({ ...deviceForm, device_name: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <select value={deviceForm.platform} onChange={(e) => setDeviceForm({ ...deviceForm, platform: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white">
                  <option value="android">Android</option>
                  <option value="ios">iOS</option>
                </select>
                <input type="text" placeholder="OS version (e.g., 14.0)" value={deviceForm.os_version} onChange={(e) => setDeviceForm({ ...deviceForm, os_version: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <input type="text" placeholder="Model (e.g., Pixel 8)" value={deviceForm.model} onChange={(e) => setDeviceForm({ ...deviceForm, model: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <input type="text" placeholder="Serial number" value={deviceForm.serial_number} onChange={(e) => setDeviceForm({ ...deviceForm, serial_number: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <input type="email" placeholder="User email (optional)" value={deviceForm.user_email} onChange={(e) => setDeviceForm({ ...deviceForm, user_email: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <Button onClick={registerDevice} className="w-full bg-green-600 hover:bg-green-700">Register Device</Button>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800 lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Smartphone className="h-5 w-5 text-blue-400" />
                  Registered Devices ({devices.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-[500px] overflow-auto">
                  {devices.map((device, index) => (
                    <div key={index} className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-2xl">{getPlatformIcon(device.platform)}</span>
                          <div>
                            <span className="text-white font-medium">{device.device_name}</span>
                            <span className="text-slate-400 text-sm ml-2">{device.model}</span>
                          </div>
                        </div>
                        <Badge className={getStatusBadge(device.status)}>{device.status}</Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-sm text-slate-400 mb-3">
                        <div>OS: {device.platform} {device.os_version}</div>
                        <div>Serial: {device.serial_number}</div>
                        <div>Risk: {Math.round(device.risk_score * 100)}%</div>
                        <div>Compliance: {device.compliance_score}%</div>
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => checkCompliance(device.device_id)} className="border-blue-500/50 text-blue-400">Check Compliance</Button>
                        <Button size="sm" variant="outline" onClick={() => unenrollDevice(device.device_id)} className="border-red-500/50 text-red-400"><Trash2 className="h-4 w-4" /></Button>
                      </div>
                    </div>
                  ))}
                  {devices.length === 0 && <p className="text-slate-500 text-center py-8">No devices registered</p>}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'threats' && (
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-red-400" />
                Active Threats ({threats.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {threats.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No active threats</p>
              ) : (
                <div className="space-y-3">
                  {threats.map((threat, index) => (
                    <div key={index} className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white font-medium">{threat.title}</span>
                        <Badge className={getSeverityBadge(threat.severity)}>{threat.severity}</Badge>
                      </div>
                      <p className="text-sm text-slate-400 mb-2">{threat.description}</p>
                      <div className="flex items-center justify-between text-sm">
                        <div className="text-slate-500">
                          <span className="mr-4">Category: {threat.category}</span>
                          {threat.mitre_technique && <span>MITRE: {threat.mitre_technique}</span>}
                        </div>
                        <Button size="sm" variant="outline" onClick={() => resolveThreat(threat.threat_id)} className="border-green-500/50 text-green-400 hover:bg-green-500/20">
                          <CheckCircle className="h-4 w-4 mr-1" />Resolve
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'apps' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Layers className="h-5 w-5 text-purple-400" />
                  Analyze App
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <input type="text" placeholder="Package name (com.example.app)" value={appForm.package_name} onChange={(e) => setAppForm({ ...appForm, package_name: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <input type="text" placeholder="App name" value={appForm.app_name} onChange={(e) => setAppForm({ ...appForm, app_name: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <input type="text" placeholder="Version" value={appForm.version} onChange={(e) => setAppForm({ ...appForm, version: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <select value={appForm.platform} onChange={(e) => setAppForm({ ...appForm, platform: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white">
                  <option value="android">Android</option>
                  <option value="ios">iOS</option>
                </select>
                <input type="text" placeholder="Permissions (comma-separated)" value={appForm.permissions} onChange={(e) => setAppForm({ ...appForm, permissions: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white" />
                <label className="flex items-center gap-2 text-slate-400">
                  <input type="checkbox" checked={appForm.is_sideloaded} onChange={(e) => setAppForm({ ...appForm, is_sideloaded: e.target.checked })} className="rounded" />
                  Sideloaded (not from official store)
                </label>
                <Button onClick={analyzeApp} className="w-full bg-purple-600 hover:bg-purple-700">Analyze App Security</Button>
              </CardContent>
            </Card>

            {analysisResult && (
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <Eye className="h-5 w-5 text-cyan-400" />
                    Analysis Result
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                      <span className="text-slate-300">App</span>
                      <span className="text-white">{analysisResult.app_name}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                      <span className="text-slate-300">Risk Level</span>
                      <Badge className={getSeverityBadge(analysisResult.risk_level)}>{analysisResult.risk_level}</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                      <span className="text-slate-300">Safe</span>
                      {analysisResult.is_safe ? <CheckCircle className="h-5 w-5 text-green-400" /> : <XCircle className="h-5 w-5 text-red-400" />}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {activeTab === 'compliance' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="h-5 w-5 text-green-400" />
                  Compliance Overview
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 rounded-lg bg-green-500/10 text-center">
                    <p className="text-3xl font-bold text-green-400">{dashboard?.compliance_overview?.compliant || 0}</p>
                    <p className="text-sm text-slate-400">Compliant</p>
                  </div>
                  <div className="p-4 rounded-lg bg-yellow-500/10 text-center">
                    <p className="text-3xl font-bold text-yellow-400">{dashboard?.compliance_overview?.non_compliant || 0}</p>
                    <p className="text-sm text-slate-400">Non-Compliant</p>
                  </div>
                  <div className="p-4 rounded-lg bg-orange-500/10 text-center">
                    <p className="text-3xl font-bold text-orange-400">{dashboard?.compliance_overview?.at_risk || 0}</p>
                    <p className="text-sm text-slate-400">At Risk</p>
                  </div>
                  <div className="p-4 rounded-lg bg-red-500/10 text-center">
                    <p className="text-3xl font-bold text-red-400">{dashboard?.compliance_overview?.compromised || 0}</p>
                    <p className="text-sm text-slate-400">Compromised</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Settings className="h-5 w-5 text-blue-400" />
                  Security Policy
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {policies.default && Object.entries(policies.default).filter(([key]) => key !== 'name' && key !== 'blocked_apps' && key !== 'risky_apps').map(([key, value]) => (
                  <div key={key} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                    <span className="text-slate-300">{key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                    {typeof value === 'boolean' ? (
                      <Badge className={value ? "bg-green-500/20 text-green-400" : "bg-slate-500/20 text-slate-400"}>{value ? 'Required' : 'Optional'}</Badge>
                    ) : (
                      <span className="text-white">{String(value)}</span>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default MobileSecurityPage;
