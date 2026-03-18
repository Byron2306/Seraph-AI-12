import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Cpu, Shield, Activity, HardDrive, Usb, Eye,
  FileSearch, RefreshCw, AlertTriangle, CheckCircle, 
  XCircle, FolderTree, Lock, Brain, Database
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = (!envBackendUrl || envBackendUrl.includes('localhost')) ? '/api' : `${envBackendUrl}/api`;

const EDRPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [processTree, setProcessTree] = useState([]);
  const [fimEvents, setFimEvents] = useState([]);
  const [usbDevices, setUsbDevices] = useState([]);
  const [telemetry, setTelemetry] = useState(null);
  const [newPath, setNewPath] = useState('');
  const [loading, setLoading] = useState(false);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStatus();
    fetchTelemetry();
  }, [token]);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API}/edr/status`, { headers });
      setStatus(res.data);
    } catch (err) {
      toast.error('Failed to fetch EDR status');
    }
  };

  const fetchTelemetry = async () => {
    try {
      const res = await axios.get(`${API}/edr/telemetry`, { headers });
      setTelemetry(res.data);
    } catch (err) {
      console.error('Failed to fetch telemetry');
    }
  };

  const fetchProcessTree = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/edr/process-tree`, { headers });
      setProcessTree(res.data.process_tree || []);
      toast.success(`Loaded ${res.data.count || 0} process trees`);
    } catch (err) {
      toast.error('Failed to fetch process tree');
    } finally {
      setLoading(false);
    }
  };

  const fetchFIMStatus = async () => {
    try {
      const res = await axios.post(`${API}/edr/fim/check`, {}, { headers });
      setFimEvents(res.data.events || []);
      if (res.data.has_violations) {
        toast.warning(`Found ${res.data.count} integrity violations!`);
      } else {
        toast.success('All files intact');
      }
    } catch (err) {
      toast.error('Failed to check file integrity');
    }
  };

  const handleCreateBaseline = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/edr/fim/baseline`, {}, { headers });
      toast.success(`Baseline created: ${res.data.files_baselined} files`);
      fetchStatus();
    } catch (err) {
      toast.error('Failed to create baseline');
    } finally {
      setLoading(false);
    }
  };

  const handleAddMonitorPath = async () => {
    if (!newPath.trim()) return;
    try {
      await axios.post(`${API}/edr/fim/monitor`, { path: newPath.trim() }, { headers });
      toast.success('Path added to monitoring');
      setNewPath('');
      fetchStatus();
    } catch (err) {
      toast.error('Failed to add path');
    }
  };

  const fetchUSBDevices = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/edr/usb/devices`, { headers });
      setUsbDevices(res.data.devices || []);
      toast.success(`Found ${res.data.count || 0} USB devices`);
    } catch (err) {
      toast.error('Failed to scan USB devices');
    } finally {
      setLoading(false);
    }
  };

  const handleAllowDevice = async (vendorId, productId) => {
    try {
      await axios.post(`${API}/edr/usb/allow`, { vendor_id: vendorId, product_id: productId }, { headers });
      toast.success('Device allowed');
      fetchUSBDevices();
    } catch (err) {
      toast.error('Failed to allow device');
    }
  };

  const handleBlockDevice = async (vendorId, productId) => {
    try {
      await axios.post(`${API}/edr/usb/block`, { vendor_id: vendorId, product_id: productId }, { headers });
      toast.success('Device blocked');
      fetchUSBDevices();
    } catch (err) {
      toast.error('Failed to block device');
    }
  };

  const renderProcessNode = (node, depth = 0) => {
    if (!node || !node.process) return null;
    const proc = node.process;
    
    return (
      <div key={proc.pid} className="ml-4 border-l border-slate-700 pl-4">
        <div className={`p-2 my-1 rounded ${proc.is_suspicious ? 'bg-red-500/10 border border-red-500/30' : 'bg-slate-800/50'}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className={`w-4 h-4 ${proc.is_suspicious ? 'text-red-400' : 'text-cyan-400'}`} />
              <span className="text-white text-sm font-medium">{proc.name}</span>
              <span className="text-slate-500 text-xs">PID: {proc.pid}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400 text-xs">CPU: {proc.cpu_percent}%</span>
              <span className="text-slate-400 text-xs">MEM: {proc.memory_percent}%</span>
              {proc.is_suspicious && (
                <Badge variant="destructive" className="text-xs">Suspicious</Badge>
              )}
            </div>
          </div>
          {proc.suspicion_reasons?.length > 0 && (
            <div className="mt-1 text-xs text-red-400">
              {proc.suspicion_reasons.join(', ')}
            </div>
          )}
        </div>
        {node.children?.map(child => renderProcessNode(child, depth + 1))}
      </div>
    );
  };

  return (
    <div className="p-6 space-y-6" data-testid="edr-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-green-400" />
            EDR & Memory Forensics
          </h1>
          <p className="text-slate-400 text-sm mt-1">Endpoint detection, file integrity & USB control</p>
        </div>
        <Button onClick={fetchTelemetry} variant="outline" className="border-green-500/50 text-green-400">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh Telemetry
        </Button>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-lg border ${status?.fim?.enabled ? 'bg-green-500/10 border-green-500/30' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${status?.fim?.enabled ? 'bg-green-500/20' : 'bg-slate-800'}`}>
              <FileSearch className={`w-5 h-5 ${status?.fim?.enabled ? 'text-green-400' : 'text-slate-400'}`} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">File Integrity</p>
              <p className={`font-bold ${status?.fim?.enabled ? 'text-green-400' : 'text-slate-400'}`}>
                {status?.fim?.enabled ? 'ENABLED' : 'DISABLED'}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Baselined Files</p>
              <p className="text-2xl font-bold text-white">{status?.fim?.baselined_files || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className={`p-4 rounded-lg border ${status?.memory_forensics?.volatility_installed ? 'bg-green-500/10 border-green-500/30' : 'bg-amber-500/10 border-amber-500/30'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${status?.memory_forensics?.volatility_installed ? 'bg-green-500/20' : 'bg-amber-500/20'}`}>
              <Brain className={`w-5 h-5 ${status?.memory_forensics?.volatility_installed ? 'text-green-400' : 'text-amber-400'}`} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Volatility</p>
              <p className={`font-bold ${status?.memory_forensics?.volatility_installed ? 'text-green-400' : 'text-amber-400'}`}>
                {status?.memory_forensics?.volatility_installed ? 'INSTALLED' : 'NOT FOUND'}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <Activity className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Active Processes</p>
              <p className="text-2xl font-bold text-white">{telemetry?.process_count || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Telemetry Overview */}
      {telemetry && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              System Telemetry
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                <p className="text-2xl font-bold text-cyan-400">{Math.round(telemetry.cpu_usage || 0)}%</p>
                <p className="text-slate-400 text-xs">CPU Usage</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                <p className="text-2xl font-bold text-green-400">{Math.round(telemetry.memory_usage || 0)}%</p>
                <p className="text-slate-400 text-xs">Memory Usage</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                <p className="text-2xl font-bold text-amber-400">{Math.round(telemetry.disk_usage || 0)}%</p>
                <p className="text-slate-400 text-xs">Disk Usage</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                <p className="text-2xl font-bold text-blue-400">{telemetry.network_connections || 0}</p>
                <p className="text-slate-400 text-xs">Network Conns</p>
              </div>
              <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                <p className="text-2xl font-bold text-purple-400">{telemetry.open_files || 0}</p>
                <p className="text-slate-400 text-xs">Open Files</p>
              </div>
            </div>
            
            {telemetry.suspicious_activity?.length > 0 && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <span className="text-red-400 font-medium">Suspicious Activity Detected</span>
                </div>
                {telemetry.suspicious_activity.map((item, idx) => (
                  <div key={idx} className="text-sm text-slate-300 mt-1">
                    PID {item.pid}: {item.name} - {item.reasons?.join(', ')}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Process Tree */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white flex items-center gap-2">
            <FolderTree className="w-5 h-5 text-cyan-400" />
            Process Tree
          </CardTitle>
          <Button onClick={fetchProcessTree} disabled={loading} variant="outline" size="sm">
            <Eye className="w-4 h-4 mr-1" />
            {loading ? 'Loading...' : 'Load Tree'}
          </Button>
        </CardHeader>
        <CardContent>
          {processTree.length > 0 ? (
            <div className="max-h-96 overflow-y-auto">
              {processTree.slice(0, 10).map(node => renderProcessNode(node))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <FolderTree className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>Click "Load Tree" to view process hierarchy</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* File Integrity Monitoring */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-green-400" />
            File Integrity Monitoring
          </CardTitle>
          <div className="flex gap-2">
            <Button onClick={handleCreateBaseline} disabled={loading} variant="outline" size="sm">
              <Database className="w-4 h-4 mr-1" />
              Create Baseline
            </Button>
            <Button onClick={fetchFIMStatus} variant="outline" size="sm">
              <Shield className="w-4 h-4 mr-1" />
              Check Integrity
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-4">
            <Input
              placeholder="/path/to/monitor"
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={handleAddMonitorPath}>
              Add Path
            </Button>
          </div>

          {status?.fim?.paths?.length > 0 && (
            <div className="mb-4">
              <p className="text-slate-400 text-sm mb-2">Monitored Paths:</p>
              <div className="flex flex-wrap gap-2">
                {status.fim.paths.map((path, idx) => (
                  <Badge key={idx} variant="outline" className="text-green-400 border-green-500/30">
                    {path}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {fimEvents.length > 0 ? (
            <div className="space-y-2">
              {fimEvents.map((event) => (
                <div key={event.event_id} 
                  className={`p-3 rounded-lg border ${event.severity === 'critical' ? 'bg-red-500/10 border-red-500/30' : 'bg-amber-500/10 border-amber-500/30'}`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className={`w-4 h-4 ${event.severity === 'critical' ? 'text-red-400' : 'text-amber-400'}`} />
                      <span className="text-white text-sm">{event.file_path}</span>
                    </div>
                    <Badge variant="outline" className={event.severity === 'critical' ? 'text-red-400 border-red-500/30' : 'text-amber-400 border-amber-500/30'}>
                      {event.event_type}
                    </Badge>
                  </div>
                  <p className="text-slate-500 text-xs mt-1">
                    {new Date(event.timestamp).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-6 text-slate-400">
              <CheckCircle className="w-10 h-10 mx-auto mb-3 text-green-400 opacity-50" />
              <p className="text-sm">No integrity violations detected</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* USB Device Control */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white flex items-center gap-2">
            <Usb className="w-5 h-5 text-purple-400" />
            USB Device Control
          </CardTitle>
          <Button onClick={fetchUSBDevices} disabled={loading} variant="outline" size="sm">
            <RefreshCw className={`w-4 h-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
            Scan Devices
          </Button>
        </CardHeader>
        <CardContent>
          {usbDevices.length > 0 ? (
            <div className="space-y-2">
              {usbDevices.map((device) => (
                <div key={device.device_id} 
                  className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center gap-4">
                    <div className={`w-10 h-10 rounded flex items-center justify-center ${device.status === 'allowed' ? 'bg-green-500/10' : device.status === 'blocked' ? 'bg-red-500/10' : 'bg-slate-700'}`}>
                      <Usb className={`w-5 h-5 ${device.status === 'allowed' ? 'text-green-400' : device.status === 'blocked' ? 'text-red-400' : 'text-slate-400'}`} />
                    </div>
                    <div>
                      <p className="text-white font-medium">{device.vendor_name || 'Unknown Device'}</p>
                      <p className="text-slate-400 text-sm font-mono">
                        {device.vendor_id}:{device.product_id}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={
                      device.status === 'allowed' ? 'text-green-400 border-green-500/30' :
                      device.status === 'blocked' ? 'text-red-400 border-red-500/30' :
                      'text-slate-400 border-slate-500/30'
                    }>
                      {device.status}
                    </Badge>
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="text-green-400 border-green-500/30"
                      onClick={() => handleAllowDevice(device.vendor_id, device.product_id)}
                    >
                      Allow
                    </Button>
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="text-red-400 border-red-500/30"
                      onClick={() => handleBlockDevice(device.vendor_id, device.product_id)}
                    >
                      Block
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Usb className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>Click "Scan Devices" to detect USB devices</p>
              <p className="text-sm">Requires Linux with lsusb installed</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Memory Forensics Info */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Brain className="w-5 h-5 text-amber-400" />
            Memory Forensics
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="p-4 bg-slate-800/50 rounded-lg">
            <div className="flex items-center gap-4 mb-4">
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${status?.memory_forensics?.volatility_installed ? 'bg-green-500/20' : 'bg-amber-500/20'}`}>
                <Brain className={`w-6 h-6 ${status?.memory_forensics?.volatility_installed ? 'text-green-400' : 'text-amber-400'}`} />
              </div>
              <div>
                <p className="text-white font-medium">Volatility 3</p>
                <p className="text-slate-400 text-sm">
                  {status?.memory_forensics?.volatility_installed 
                    ? `Installed at: ${status.memory_forensics.volatility_path}`
                    : 'Not installed. Install with: pip install volatility3'
                  }
                </p>
              </div>
            </div>
            
            <div className="text-slate-400 text-sm">
              <p className="mb-2">Supported analysis types:</p>
              <div className="flex flex-wrap gap-2">
                {['Process List', 'Process Tree', 'Malfind', 'Network Scan', 'Command Lines'].map((type, idx) => (
                  <Badge key={idx} variant="outline" className="text-cyan-400 border-cyan-500/30">
                    {type}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default EDRPage;
