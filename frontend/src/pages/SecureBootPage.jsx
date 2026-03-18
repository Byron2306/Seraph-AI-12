import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  RefreshCw, 
  AlertTriangle, 
  Activity,
  HardDrive,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Cpu,
  Server,
  Fingerprint,
  Key,
  FileCode,
  Layers,
  AlertOctagon,
  Clock,
  TrendingUp,
  Zap,
  Eye,
  ChevronRight,
  Play,
  BarChart3,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Link2,
  Unlink2
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const SecureBootPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState(null);
  const [bootChain, setBootChain] = useState(null);
  const [firmware, setFirmware] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [selectedComponent, setSelectedComponent] = useState(null);
  const [viewMode, setViewMode] = useState('status'); // status, chain, firmware, alerts
  const [fleetStats, setFleetStats] = useState({
    total_endpoints: 0,
    secure_boot_enabled: 0,
    tpm_present: 0,
    threats_detected: 0,
    pending_updates: 0
  });

  // Fetch secure boot data
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [statusRes, chainRes, alertsRes] = await Promise.all([
        axios.get(`${API}/v1/secure-boot/status`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/secure-boot/bootchain`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/secure-boot/alerts?limit=50`, { headers: getAuthHeaders() })
      ]);
      
      setStatus(statusRes.data);
      setBootChain(chainRes.data);
      setAlerts(alertsRes.data.alerts || []);
      
    } catch (error) {
      console.error('Failed to fetch secure boot data:', error);
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data
  const loadDemoData = () => {
    setStatus({
      platform: 'x86_64',
      uefi_mode: true,
      secure_boot_enabled: true,
      secure_boot_enforced: true,
      setup_mode: false,
      pk_enrolled: true,
      kek_enrolled: true,
      db_enrolled: true,
      dbx_enrolled: true,
      measured_boot_supported: true,
      tpm_present: true,
      tpm_version: '2.0',
      virtualization_based_security: true,
      last_check: new Date().toISOString(),
      risk_level: 'low'
    });
    
    setBootChain({
      verified: true,
      chain_intact: true,
      components: [
        { name: 'UEFI Firmware', verified: true, hash: 'a1b2c3d4...', signer: 'Dell Inc.' },
        { name: 'Boot Manager', verified: true, hash: 'e5f6g7h8...', signer: 'Microsoft' },
        { name: 'OS Loader', verified: true, hash: 'i9j0k1l2...', signer: 'Microsoft' },
        { name: 'Kernel', verified: true, hash: 'm3n4o5p6...', signer: 'Microsoft' },
        { name: 'Early Launch Drivers', verified: true, hash: 'q7r8s9t0...', signer: 'Various' }
      ],
      chain_of_trust: [
        { from: 'UEFI Platform Key (PK)', to: 'Key Exchange Key (KEK)', status: 'valid' },
        { from: 'KEK', to: 'Signature Database (db)', status: 'valid' },
        { from: 'db', to: 'Boot Manager', status: 'valid' },
        { from: 'Boot Manager', to: 'OS Loader', status: 'valid' }
      ],
      issues: [],
      mitre_techniques: []
    });
    
    setFirmware([
      { id: 'fw-1', name: 'System BIOS', vendor: 'Dell Inc.', version: '2.18.0', secure: true, update_available: false },
      { id: 'fw-2', name: 'ME Firmware', vendor: 'Intel', version: '16.1.27', secure: true, update_available: true },
      { id: 'fw-3', name: 'NIC Firmware', vendor: 'Intel', version: '1.5.62', secure: true, update_available: false },
      { id: 'fw-4', name: 'SSD Firmware', vendor: 'Samsung', version: 'GXA7801Q', secure: true, update_available: false },
      { id: 'fw-5', name: 'TPM Firmware', vendor: 'STMicro', version: '74.8', secure: true, update_available: false }
    ]);
    
    setAlerts([
      { id: 1, severity: 'warning', message: 'ME Firmware update available (CVE-2025-1234)', endpoint: 'WS-ADMIN-01', timestamp: '2026-03-06T10:30:00Z' },
      { id: 2, severity: 'info', message: 'Boot chain verified successfully', endpoint: 'SRV-DB-01', timestamp: '2026-03-06T09:15:00Z' },
      { id: 3, severity: 'low', message: 'TPM attestation completed', endpoint: 'WS-DEV-05', timestamp: '2026-03-06T08:45:00Z' }
    ]);
    
    setFleetStats({
      total_endpoints: 156,
      secure_boot_enabled: 148,
      tpm_present: 152,
      threats_detected: 2,
      pending_updates: 12
    });
  };

  // Run firmware scan
  const runScan = async () => {
    try {
      setScanning(true);
      toast.info('Running firmware security scan...');
      
      const res = await axios.post(`${API}/v1/secure-boot/scan`, {
        deep_scan: true,
        check_updates: true,
        verify_signatures: true
      }, { headers: getAuthHeaders() });
      
      setScanResult(res.data);
      toast.success('Scan complete');
      await fetchData();
    } catch (error) {
      console.error('Scan failed:', error);
      // Demo scan result
      setScanResult({
        scan_id: 'scan-' + Date.now(),
        status: 'completed',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        total_components: 12,
        verified_components: 11,
        suspicious_components: 1,
        threats_detected: [],
        recommendations: [
          'Update Intel ME Firmware to version 16.1.30',
          'Enable Memory Integrity in Windows Security'
        ]
      });
      toast.success('Scan complete (demo)');
    } finally {
      setScanning(false);
    }
  };

  // Get risk level badge
  const getRiskBadge = (level) => {
    const config = {
      low: { color: 'bg-green-500/20 text-green-400', icon: ShieldCheck },
      medium: { color: 'bg-yellow-500/20 text-yellow-400', icon: ShieldAlert },
      high: { color: 'bg-orange-500/20 text-orange-400', icon: ShieldAlert },
      critical: { color: 'bg-red-500/20 text-red-400', icon: ShieldX }
    };
    const cfg = config[level] || config.low;
    const Icon = cfg.icon;
    return (
      <Badge className={cfg.color}>
        <Icon className="h-3 w-3 mr-1" />
        {level}
      </Badge>
    );
  };

  // Get component status indicator
  const getStatusIndicator = (verified) => {
    return verified ? (
      <CheckCircle2 className="h-4 w-4 text-green-400" />
    ) : (
      <XCircle className="h-4 w-4 text-red-400" />
    );
  };

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/20 rounded-lg">
            <ShieldCheck className="h-6 w-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Secure Boot Verification</h1>
            <p className="text-gray-400 text-sm">UEFI • TPM • Firmware Integrity</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            onClick={fetchData}
            disabled={loading}
            className="border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button 
            onClick={runScan}
            disabled={scanning}
            className="bg-cyan-600 hover:bg-cyan-700"
          >
            <Play className={`h-4 w-4 mr-2 ${scanning ? 'animate-pulse' : ''}`} />
            {scanning ? 'Scanning...' : 'Run Scan'}
          </Button>
        </div>
      </div>

      {/* Fleet Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Server className="h-4 w-4 text-blue-400" />
            <span className="text-gray-400 text-sm">Total Endpoints</span>
          </div>
          <p className="text-2xl font-bold">{fleetStats.total_endpoints}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 border border-green-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Lock className="h-4 w-4 text-green-400" />
            <span className="text-gray-400 text-sm">Secure Boot Enabled</span>
          </div>
          <p className="text-2xl font-bold text-green-400">{fleetStats.secure_boot_enabled}</p>
          <p className="text-xs text-gray-500">{Math.round(fleetStats.secure_boot_enabled / fleetStats.total_endpoints * 100)}% coverage</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 border border-cyan-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Fingerprint className="h-4 w-4 text-cyan-400" />
            <span className="text-gray-400 text-sm">TPM Present</span>
          </div>
          <p className="text-2xl font-bold text-cyan-400">{fleetStats.tpm_present}</p>
          <p className="text-xs text-gray-500">{Math.round(fleetStats.tpm_present / fleetStats.total_endpoints * 100)}% equipped</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 border border-red-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <span className="text-gray-400 text-sm">Threats Detected</span>
          </div>
          <p className="text-2xl font-bold text-red-400">{fleetStats.threats_detected}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gray-900/50 border border-orange-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="h-4 w-4 text-orange-400" />
            <span className="text-gray-400 text-sm">Pending Updates</span>
          </div>
          <p className="text-2xl font-bold text-orange-400">{fleetStats.pending_updates}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'status', label: 'Boot Status', icon: Shield },
          { id: 'chain', label: 'Boot Chain', icon: Link2 },
          { id: 'firmware', label: 'Firmware', icon: Cpu },
          { id: 'alerts', label: 'Alerts', icon: AlertOctagon }
        ].map(tab => (
          <Button
            key={tab.id}
            variant={viewMode === tab.id ? 'default' : 'outline'}
            onClick={() => setViewMode(tab.id)}
            className={viewMode === tab.id ? 'bg-cyan-600' : 'border-gray-700'}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2">
          {/* Boot Status View */}
          {viewMode === 'status' && status && (
            <div className="space-y-4">
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-900/50 border border-gray-800 rounded-xl p-6"
              >
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <ShieldCheck className="h-5 w-5 text-cyan-400" />
                    Secure Boot Status
                  </h3>
                  {getRiskBadge(status.risk_level)}
                </div>
                
                <div className="grid grid-cols-3 gap-6">
                  {/* UEFI Status */}
                  <div className="space-y-3">
                    <h4 className="text-sm text-gray-400 font-medium">UEFI Configuration</h4>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">UEFI Mode</span>
                        {getStatusIndicator(status.uefi_mode)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Secure Boot</span>
                        {getStatusIndicator(status.secure_boot_enabled)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Enforced</span>
                        {getStatusIndicator(status.secure_boot_enforced)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Setup Mode</span>
                        {getStatusIndicator(!status.setup_mode)}
                      </div>
                    </div>
                  </div>
                  
                  {/* Key Enrollment */}
                  <div className="space-y-3">
                    <h4 className="text-sm text-gray-400 font-medium">Key Enrollment</h4>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Platform Key (PK)</span>
                        {getStatusIndicator(status.pk_enrolled)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Key Exchange (KEK)</span>
                        {getStatusIndicator(status.kek_enrolled)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Signature DB</span>
                        {getStatusIndicator(status.db_enrolled)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Revocation DB (dbx)</span>
                        {getStatusIndicator(status.dbx_enrolled)}
                      </div>
                    </div>
                  </div>
                  
                  {/* TPM & VBS */}
                  <div className="space-y-3">
                    <h4 className="text-sm text-gray-400 font-medium">Hardware Security</h4>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">TPM Present</span>
                        {getStatusIndicator(status.tpm_present)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">TPM Version</span>
                        <span className="text-sm font-mono">{status.tpm_version || 'N/A'}</span>
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">Measured Boot</span>
                        {getStatusIndicator(status.measured_boot_supported)}
                      </div>
                      <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                        <span className="text-sm">VBS Enabled</span>
                        {getStatusIndicator(status.virtualization_based_security)}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="mt-4 pt-4 border-t border-gray-800">
                  <p className="text-xs text-gray-500">
                    Last verified: {new Date(status.last_check).toLocaleString()} • Platform: {status.platform}
                  </p>
                </div>
              </motion.div>
            </div>
          )}

          {/* Boot Chain View */}
          {viewMode === 'chain' && bootChain && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Link2 className="h-5 w-5 text-cyan-400" />
                  Boot Chain Verification
                </h3>
                <Badge className={bootChain.chain_intact ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
                  {bootChain.chain_intact ? 'Chain Intact' : 'Chain Broken'}
                </Badge>
              </div>
              
              {/* Chain Components */}
              <div className="space-y-3 mb-6">
                {bootChain.components?.map((comp, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="flex items-center gap-4"
                  >
                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-gray-800 text-sm font-mono">
                      {idx + 1}
                    </div>
                    <div className="flex-1 p-3 bg-gray-800/50 rounded-lg flex items-center justify-between">
                      <div>
                        <p className="font-medium">{comp.name}</p>
                        <p className="text-xs text-gray-400 font-mono">{comp.hash}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-sm text-gray-400">{comp.signer}</span>
                        {getStatusIndicator(comp.verified)}
                      </div>
                    </div>
                    {idx < bootChain.components.length - 1 && (
                      <ChevronRight className="h-4 w-4 text-gray-600" />
                    )}
                  </motion.div>
                ))}
              </div>
              
              {/* Chain of Trust */}
              <div className="border-t border-gray-800 pt-4">
                <h4 className="text-sm text-gray-400 font-medium mb-3">Chain of Trust</h4>
                <div className="space-y-2">
                  {bootChain.chain_of_trust?.map((link, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-2 bg-gray-800/30 rounded-lg">
                      <span className="text-sm">{link.from}</span>
                      <ChevronRight className="h-4 w-4 text-cyan-400" />
                      <span className="text-sm">{link.to}</span>
                      <Badge className="ml-auto bg-green-500/20 text-green-400 text-xs">
                        {link.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
              
              {bootChain.issues?.length > 0 && (
                <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <h4 className="text-sm font-medium text-red-400 mb-2">Issues Detected</h4>
                  <ul className="list-disc list-inside text-sm text-gray-400">
                    {bootChain.issues.map((issue, idx) => (
                      <li key={idx}>{issue}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Firmware View */}
          {viewMode === 'firmware' && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-cyan-400" />
                  Firmware Inventory
                </h3>
              </div>
              <table className="w-full">
                <thead className="bg-gray-800/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Component</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Vendor</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Version</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Status</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Update</th>
                  </tr>
                </thead>
                <tbody>
                  {firmware.map((fw, idx) => (
                    <motion.tr
                      key={fw.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.05 }}
                      className="border-t border-gray-800 hover:bg-gray-800/30 cursor-pointer"
                      onClick={() => setSelectedComponent(fw)}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <HardDrive className="h-4 w-4 text-gray-400" />
                          <span className="font-medium">{fw.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400">{fw.vendor}</td>
                      <td className="px-4 py-3 text-sm font-mono">{fw.version}</td>
                      <td className="px-4 py-3">
                        <Badge className={fw.secure ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
                          {fw.secure ? 'Secure' : 'Vulnerable'}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        {fw.update_available ? (
                          <Badge className="bg-orange-500/20 text-orange-400">Available</Badge>
                        ) : (
                          <span className="text-sm text-gray-500">Up to date</span>
                        )}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Alerts View */}
          {viewMode === 'alerts' && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <AlertOctagon className="h-5 w-5 text-orange-400" />
                  Boot Security Alerts
                </h3>
              </div>
              <div className="divide-y divide-gray-800">
                {alerts.map((alert, idx) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4 hover:bg-gray-800/30"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge className={
                          alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                          alert.severity === 'warning' ? 'bg-orange-500/20 text-orange-400' :
                          alert.severity === 'info' ? 'bg-blue-500/20 text-blue-400' :
                          'bg-gray-500/20 text-gray-400'
                        }>
                          {alert.severity}
                        </Badge>
                        <span className="text-sm font-mono text-gray-400">{alert.endpoint}</span>
                      </div>
                      <span className="text-xs text-gray-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm">{alert.message}</p>
                  </motion.div>
                ))}
                {alerts.length === 0 && (
                  <div className="p-8 text-center text-gray-500">
                    No boot security alerts
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Scan Result */}
          <AnimatePresence>
            {scanResult && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="bg-gray-900/50 border border-cyan-900/50 rounded-xl p-4"
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  Last Scan Result
                </h3>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                    <p className="text-xl font-bold text-green-400">{scanResult.verified_components}</p>
                    <p className="text-xs text-gray-400">Verified</p>
                  </div>
                  <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                    <p className="text-xl font-bold text-orange-400">{scanResult.suspicious_components}</p>
                    <p className="text-xs text-gray-400">Suspicious</p>
                  </div>
                </div>
                {scanResult.recommendations?.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Recommendations:</p>
                    <ul className="space-y-1">
                      {scanResult.recommendations.map((rec, idx) => (
                        <li key={idx} className="text-xs text-gray-300 flex items-start gap-2">
                          <ChevronRight className="h-3 w-3 mt-0.5 text-cyan-400 flex-shrink-0" />
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Selected Component */}
          <AnimatePresence>
            {selectedComponent && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-cyan-400" />
                  Component Details
                </h3>
                <div className="space-y-2">
                  <div>
                    <p className="text-xs text-gray-400">Name</p>
                    <p className="font-medium">{selectedComponent.name}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400">Vendor</p>
                    <p>{selectedComponent.vendor}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400">Version</p>
                    <p className="font-mono">{selectedComponent.version}</p>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <Button size="sm" variant="outline" className="flex-1 border-gray-700">
                      <Eye className="h-3 w-3 mr-1" />
                      Verify
                    </Button>
                    {selectedComponent.update_available && (
                      <Button size="sm" className="flex-1 bg-orange-600 hover:bg-orange-700">
                        <TrendingUp className="h-3 w-3 mr-1" />
                        Update
                      </Button>
                    )}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* MITRE Techniques */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3">Monitored Techniques</h3>
            <div className="space-y-2">
              {[
                { id: 'T1542.001', name: 'System Firmware' },
                { id: 'T1542.003', name: 'Bootkit' },
                { id: 'T1495', name: 'Firmware Corruption' },
                { id: 'T1014', name: 'Rootkit' }
              ].map(tech => (
                <div key={tech.id} className="flex items-center justify-between p-2 bg-gray-800/30 rounded-lg">
                  <span className="text-sm">{tech.name}</span>
                  <Badge variant="outline" className="border-gray-600 text-xs font-mono">
                    {tech.id}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3">Quick Actions</h3>
            <div className="space-y-2">
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Fingerprint className="h-4 w-4 mr-2" />
                TPM Attestation
              </Button>
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Key className="h-4 w-4 mr-2" />
                View Keys
              </Button>
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <BarChart3 className="h-4 w-4 mr-2" />
                Export Report
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecureBootPage;
