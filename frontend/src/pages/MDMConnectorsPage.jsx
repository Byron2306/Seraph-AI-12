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
  Server,
  Settings,
  Plus,
  Trash2,
  Play,
  Wifi,
  WifiOff,
  Link,
  Unlink,
  Power,
  RotateCcw,
  HardDrive,
  Users,
  Activity,
  Search
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const MDMConnectorsPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState({ connectors: {}, total_devices: 0 });
  const [devices, setDevices] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [platforms, setPlatforms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedDevice, setSelectedDevice] = useState(null);
  
  // Add connector form
  const [connectorForm, setConnectorForm] = useState({
    name: '',
    platform: 'intune',
    config: {
      tenant_id: '',
      client_id: '',
      client_secret: ''
    }
  });

  useEffect(() => {
    fetchData();
    fetchPlatforms();
  }, [token]);

  const fetchData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [statusRes, devicesRes, policiesRes] = await Promise.all([
        fetch(`${API_URL}/api/mdm/status`, { headers }),
        fetch(`${API_URL}/api/mdm/devices`, { headers }),
        fetch(`${API_URL}/api/mdm/policies`, { headers })
      ]);

      if (statusRes.ok) setStatus(await statusRes.json());
      if (devicesRes.ok) {
        const data = await devicesRes.json();
        setDevices(data.devices || []);
      }
      if (policiesRes.ok) {
        const data = await policiesRes.json();
        setPolicies(data.policies || []);
      }
    } catch (error) {
      console.error('Failed to fetch MDM data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchPlatforms = async () => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/platforms`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setPlatforms(data.platforms || []);
      }
    } catch (error) {
      console.error('Failed to fetch platforms:', error);
    }
  };

  const addConnector = async () => {
    if (!connectorForm.name || !connectorForm.platform) {
      toast.error('Please fill in connector name and platform');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/mdm/connectors`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(connectorForm)
      });

      if (response.ok) {
        toast.success('Connector added successfully');
        setConnectorForm({ name: '', platform: 'intune', config: { tenant_id: '', client_id: '', client_secret: '' } });
        fetchData();
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to add connector');
      }
    } catch (error) {
      toast.error('Error adding connector');
    }
  };

  const removeConnector = async (name) => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/connectors/${name}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Connector removed');
        fetchData();
      } else {
        toast.error('Failed to remove connector');
      }
    } catch (error) {
      toast.error('Error removing connector');
    }
  };

  const connectConnector = async (name) => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/connectors/${name}/connect`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(result.message);
        fetchData();
      } else {
        toast.error('Failed to connect');
      }
    } catch (error) {
      toast.error('Error connecting');
    }
  };

  const disconnectConnector = async (name) => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/connectors/${name}/disconnect`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Disconnected');
        fetchData();
      } else {
        toast.error('Failed to disconnect');
      }
    } catch (error) {
      toast.error('Error disconnecting');
    }
  };

  const connectAll = async () => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/connect-all`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const results = await response.json();
        toast.success('Connected to all platforms');
        fetchData();
      } else {
        toast.error('Failed to connect all');
      }
    } catch (error) {
      toast.error('Error connecting all');
    }
  };

  const syncDevices = async () => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/sync/now`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`Synced ${result.devices_synced} devices, ${result.policies_synced} policies`);
        fetchData();
      } else {
        toast.error('Sync failed');
      }
    } catch (error) {
      toast.error('Error syncing');
    }
  };

  const executeAction = async (deviceId, action) => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/devices/${deviceId}/action`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ action })
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`Action ${action}: ${result.status}`);
      } else {
        toast.error('Action failed');
      }
    } catch (error) {
      toast.error('Error executing action');
    }
  };

  const lockDevice = async (deviceId) => {
    try {
      const response = await fetch(`${API_URL}/api/mdm/devices/${deviceId}/lock`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Device locked');
      } else {
        toast.error('Failed to lock device');
      }
    } catch (error) {
      toast.error('Error locking device');
    }
  };

  const wipeDevice = async (deviceId) => {
    if (!window.confirm('Are you sure you want to WIPE this device? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/mdm/devices/${deviceId}/wipe`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Wipe command sent');
      } else {
        toast.error('Failed to wipe device');
      }
    } catch (error) {
      toast.error('Error wiping device');
    }
  };

  const getComplianceColor = (state) => {
    switch (state) {
      case 'compliant': return 'bg-green-600';
      case 'noncompliant': return 'bg-red-600';
      case 'unknown': return 'bg-slate-600';
      case 'in_grace_period': return 'bg-yellow-600';
      default: return 'bg-slate-600';
    }
  };

  const getPlatformIcon = (platform) => {
    switch (platform) {
      case 'intune': return '🪟';
      case 'jamf': return '🍎';
      case 'workspace_one': return '🌐';
      case 'google_workspace': return '📱';
      default: return '📱';
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'connectors', label: 'Connectors', icon: Link },
    { id: 'devices', label: 'Devices', icon: Smartphone },
    { id: 'policies', label: 'Policies', icon: Shield },
    { id: 'platforms', label: 'Platforms', icon: Server }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="mdm-connectors-page">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Smartphone className="w-8 h-8 text-cyan-400" />
            MDM Connectors
          </h1>
          <p className="text-slate-400 mt-1">Enterprise Mobile Device Management Integration</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={syncDevices} variant="outline" className="border-green-500/30 text-green-400">
            <RefreshCw className="w-4 h-4 mr-2" />
            Sync All
          </Button>
          <Button onClick={connectAll} variant="outline" className="border-cyan-500/30 text-cyan-400">
            <Link className="w-4 h-4 mr-2" />
            Connect All
          </Button>
          <Button onClick={fetchData} variant="outline" className="border-slate-500/30 text-slate-400">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-700 pb-2">
        {tabs.map(tab => (
          <Button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            variant={activeTab === tab.id ? 'default' : 'ghost'}
            className={activeTab === tab.id ? 'bg-cyan-600' : 'text-slate-400'}
            data-testid={`tab-${tab.id}`}
          >
            <tab.icon className="w-4 h-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Total Devices</p>
                    <p className="text-3xl font-bold text-white">{status.total_devices}</p>
                  </div>
                  <Smartphone className="w-10 h-10 text-cyan-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Active Connectors</p>
                    <p className="text-3xl font-bold text-green-400">
                      {Object.values(status.connectors || {}).filter(c => c.connected).length}
                    </p>
                  </div>
                  <Link className="w-10 h-10 text-green-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Compliant</p>
                    <p className="text-3xl font-bold text-green-400">
                      {devices.filter(d => d.compliance_state === 'compliant').length}
                    </p>
                  </div>
                  <CheckCircle className="w-10 h-10 text-green-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Non-Compliant</p>
                    <p className="text-3xl font-bold text-red-400">
                      {devices.filter(d => d.compliance_state === 'noncompliant').length}
                    </p>
                  </div>
                  <XCircle className="w-10 h-10 text-red-400" />
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Link className="w-5 h-5 text-cyan-400" />
                  Connector Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                {Object.keys(status.connectors || {}).length === 0 ? (
                  <p className="text-slate-400 text-center py-4">No connectors configured</p>
                ) : (
                  <div className="space-y-3">
                    {Object.entries(status.connectors || {}).map(([name, info]) => (
                      <div key={name} className="flex justify-between items-center p-3 bg-slate-900/50 rounded-lg">
                        <div className="flex items-center gap-3">
                          {info.connected ? (
                            <Wifi className="w-5 h-5 text-green-400" />
                          ) : (
                            <WifiOff className="w-5 h-5 text-red-400" />
                          )}
                          <div>
                            <p className="text-white font-medium">{name}</p>
                            <p className="text-slate-400 text-sm">{info.device_count} devices</p>
                          </div>
                        </div>
                        <Badge className={info.connected ? 'bg-green-600' : 'bg-red-600'}>
                          {info.connected ? 'Connected' : 'Disconnected'}
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  Compliance Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {['compliant', 'noncompliant', 'unknown', 'in_grace_period'].map(state => {
                    const count = devices.filter(d => d.compliance_state === state).length;
                    const percentage = devices.length > 0 ? (count / devices.length * 100).toFixed(1) : 0;
                    return (
                      <div key={state} className="flex items-center gap-3">
                        <Badge className={getComplianceColor(state)}>{state.replace('_', ' ')}</Badge>
                        <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${getComplianceColor(state)}`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                        <span className="text-white text-sm w-16 text-right">{count} ({percentage}%)</span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* Connectors Tab */}
      {activeTab === 'connectors' && (
        <div className="space-y-6">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Plus className="w-5 h-5 text-cyan-400" />
                Add MDM Connector
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-slate-400 text-sm">Connector Name</label>
                  <input
                    type="text"
                    className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                    placeholder="My Intune"
                    value={connectorForm.name}
                    onChange={(e) => setConnectorForm({ ...connectorForm, name: e.target.value })}
                  />
                </div>
                <div>
                  <label className="text-slate-400 text-sm">Platform</label>
                  <select
                    className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                    value={connectorForm.platform}
                    onChange={(e) => setConnectorForm({ ...connectorForm, platform: e.target.value })}
                  >
                    <option value="intune">Microsoft Intune</option>
                    <option value="jamf">JAMF Pro</option>
                    <option value="workspace_one">VMware Workspace ONE</option>
                    <option value="google_workspace">Google Workspace</option>
                  </select>
                </div>
              </div>
              
              {connectorForm.platform === 'intune' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="text-slate-400 text-sm">Tenant ID</label>
                    <input
                      type="text"
                      className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                      placeholder="Azure AD Tenant ID"
                      value={connectorForm.config.tenant_id}
                      onChange={(e) => setConnectorForm({
                        ...connectorForm,
                        config: { ...connectorForm.config, tenant_id: e.target.value }
                      })}
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Client ID</label>
                    <input
                      type="text"
                      className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                      placeholder="App Registration Client ID"
                      value={connectorForm.config.client_id}
                      onChange={(e) => setConnectorForm({
                        ...connectorForm,
                        config: { ...connectorForm.config, client_id: e.target.value }
                      })}
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Client Secret</label>
                    <input
                      type="password"
                      className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                      placeholder="App Registration Secret"
                      value={connectorForm.config.client_secret}
                      onChange={(e) => setConnectorForm({
                        ...connectorForm,
                        config: { ...connectorForm.config, client_secret: e.target.value }
                      })}
                    />
                  </div>
                </div>
              )}

              {connectorForm.platform === 'jamf' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="text-slate-400 text-sm">Server URL</label>
                    <input
                      type="text"
                      className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                      placeholder="https://your-jamf.jamfcloud.com"
                      value={connectorForm.config.server_url || ''}
                      onChange={(e) => setConnectorForm({
                        ...connectorForm,
                        config: { ...connectorForm.config, server_url: e.target.value }
                      })}
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Client ID</label>
                    <input
                      type="text"
                      className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                      placeholder="API Client ID"
                      value={connectorForm.config.client_id}
                      onChange={(e) => setConnectorForm({
                        ...connectorForm,
                        config: { ...connectorForm.config, client_id: e.target.value }
                      })}
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Client Secret</label>
                    <input
                      type="password"
                      className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                      placeholder="API Client Secret"
                      value={connectorForm.config.client_secret}
                      onChange={(e) => setConnectorForm({
                        ...connectorForm,
                        config: { ...connectorForm.config, client_secret: e.target.value }
                      })}
                    />
                  </div>
                </div>
              )}

              <Button onClick={addConnector} className="bg-cyan-600 hover:bg-cyan-700">
                <Plus className="w-4 h-4 mr-2" /> Add Connector
              </Button>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Link className="w-5 h-5 text-cyan-400" />
                Configured Connectors
              </CardTitle>
            </CardHeader>
            <CardContent>
              {Object.keys(status.connectors || {}).length === 0 ? (
                <p className="text-slate-400 text-center py-8">No connectors configured. Add one above.</p>
              ) : (
                <div className="space-y-4">
                  {Object.entries(status.connectors || {}).map(([name, info]) => (
                    <div key={name} className="p-4 bg-slate-900/50 rounded-lg border border-slate-600">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{getPlatformIcon(name)}</span>
                          <div>
                            <p className="text-white font-medium">{name}</p>
                            <p className="text-slate-400 text-sm">
                              {info.device_count} devices • Last sync: {info.last_sync || 'Never'}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={info.connected ? 'bg-green-600' : 'bg-red-600'}>
                            {info.connected ? 'Connected' : 'Disconnected'}
                          </Badge>
                          {info.connected ? (
                            <Button size="sm" variant="outline" onClick={() => disconnectConnector(name)}>
                              <Unlink className="w-4 h-4 mr-1" /> Disconnect
                            </Button>
                          ) : (
                            <Button size="sm" onClick={() => connectConnector(name)} className="bg-green-600">
                              <Link className="w-4 h-4 mr-1" /> Connect
                            </Button>
                          )}
                          <Button size="sm" variant="destructive" onClick={() => removeConnector(name)}>
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Devices Tab */}
      {activeTab === 'devices' && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Smartphone className="w-5 h-5 text-cyan-400" />
              Managed Devices ({devices.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {devices.length === 0 ? (
              <p className="text-slate-400 text-center py-8">No devices found. Connect to an MDM platform and sync.</p>
            ) : (
              <div className="space-y-4">
                {devices.map((device, index) => (
                  <div key={index} className="p-4 bg-slate-900/50 rounded-lg border border-slate-600">
                    <div className="flex justify-between items-start">
                      <div className="flex items-start gap-4">
                        <div className="text-3xl">
                          {device.platform === 'ios' || device.platform === 'macos' ? '🍎' : 
                           device.platform === 'android' ? '🤖' : 
                           device.platform === 'windows' ? '🪟' : '📱'}
                        </div>
                        <div>
                          <p className="text-white font-medium">{device.device_name || 'Unnamed Device'}</p>
                          <p className="text-slate-400 text-sm">{device.model} • {device.os_version}</p>
                          <p className="text-slate-500 text-sm">Serial: {device.serial_number}</p>
                          {device.user_display_name && (
                            <p className="text-slate-500 text-sm flex items-center gap-1">
                              <Users className="w-3 h-3" /> {device.user_display_name}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <Badge className={getComplianceColor(device.compliance_state)}>
                          {device.compliance_state}
                        </Badge>
                        <div className="flex gap-1">
                          {device.is_encrypted && <Badge className="bg-green-600/50">Encrypted</Badge>}
                          {device.is_supervised && <Badge className="bg-blue-600/50">Supervised</Badge>}
                          {device.is_jailbroken && <Badge className="bg-red-600">Jailbroken</Badge>}
                        </div>
                        <div className="flex gap-2 mt-2">
                          <Button size="sm" onClick={() => executeAction(device.device_id, 'sync')}>
                            <RefreshCw className="w-4 h-4" />
                          </Button>
                          <Button size="sm" onClick={() => lockDevice(device.device_id)} className="bg-yellow-600">
                            <Lock className="w-4 h-4" />
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => wipeDevice(device.device_id)}>
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                    <div className="mt-3 pt-3 border-t border-slate-700 flex gap-4 text-sm">
                      <span className="text-slate-400">
                        Enrolled: {device.enrollment_date ? new Date(device.enrollment_date).toLocaleDateString() : 'N/A'}
                      </span>
                      <span className="text-slate-400">
                        Last Sync: {device.last_sync ? new Date(device.last_sync).toLocaleString() : 'N/A'}
                      </span>
                      <span className="text-slate-400">
                        Platform: {device.mdm_platform}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Policies Tab */}
      {activeTab === 'policies' && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Compliance Policies ({policies.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {policies.length === 0 ? (
              <p className="text-slate-400 text-center py-8">No policies found. Sync with MDM platforms to fetch policies.</p>
            ) : (
              <div className="space-y-4">
                {policies.map((policy, index) => (
                  <div key={index} className="p-4 bg-slate-900/50 rounded-lg border border-slate-600">
                    <div className="flex justify-between items-start">
                      <div>
                        <p className="text-white font-medium">{policy.name}</p>
                        <p className="text-slate-400 text-sm">Platform: {policy.platform}</p>
                      </div>
                      <Badge className="bg-cyan-600">{policy.policy_id}</Badge>
                    </div>
                    {policy.settings && Object.keys(policy.settings).length > 0 && (
                      <div className="mt-3 pt-3 border-t border-slate-700">
                        <p className="text-slate-400 text-sm mb-2">Settings</p>
                        <div className="grid grid-cols-2 gap-2">
                          {Object.entries(policy.settings).map(([key, value]) => (
                            <div key={key} className="text-sm">
                              <span className="text-slate-500">{key}: </span>
                              <span className="text-white">{String(value)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Platforms Tab */}
      {activeTab === 'platforms' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {platforms.map((platform, index) => (
            <Card key={index} className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <span className="text-2xl">{getPlatformIcon(platform.id)}</span>
                  {platform.name}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 mb-4">{platform.description}</p>
                <div>
                  <p className="text-slate-300 text-sm font-medium mb-2">Required Configuration:</p>
                  <div className="space-y-1">
                    {platform.config_required?.map((config, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <div className="w-2 h-2 bg-cyan-400 rounded-full" />
                        <span className="text-slate-400 text-sm">{config}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

export default MDMConnectorsPage;
