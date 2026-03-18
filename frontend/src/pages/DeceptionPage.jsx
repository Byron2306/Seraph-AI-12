import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  RefreshCw, 
  AlertTriangle, 
  Target,
  Crosshair,
  Zap,
  Activity,
  Eye,
  EyeOff,
  Layers,
  Network,
  Users,
  Clock,
  TrendingUp,
  Filter,
  ChevronRight,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Flame,
  Fingerprint,
  Ban,
  Timer,
  Gauge,
  Radio,
  Radar,
  Skull,
  Siren
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const DeceptionPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState(null);
  const [capabilities, setCapabilities] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [events, setEvents] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [stats, setStats] = useState({
    active_campaigns: 0,
    total_events: 0,
    blocked_ips: 0,
    decoys_triggered: 0,
    avg_risk_score: 0
  });
  const [viewMode, setViewMode] = useState('overview'); // overview, campaigns, events
  const [eventFilter, setEventFilter] = useState(null);

  // Fetch deception status and data
  const fetchDeceptionData = useCallback(async () => {
    try {
      setLoading(true);
      const [statusRes, capabilitiesRes, campaignsRes, eventsRes] = await Promise.all([
        axios.get(`${API}/v1/deception/status`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/deception/capabilities`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/deception/campaigns?min_events=1&limit=50`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/deception/events?limit=100`, { headers: getAuthHeaders() })
      ]);
      
      setStatus(statusRes.data);
      setCapabilities(capabilitiesRes.data.capabilities || []);
      setCampaigns(campaignsRes.data.campaigns || []);
      setEvents(eventsRes.data.events || []);
      
      // Calculate stats
      const campaignList = campaignsRes.data.campaigns || [];
      const eventList = eventsRes.data.events || [];
      
      setStats({
        active_campaigns: campaignList.length,
        total_events: eventList.length,
        blocked_ips: eventList.filter(e => e.route === 'trap_sink' || e.escalation_level === 'hard_ban').length,
        decoys_triggered: eventList.filter(e => e.decoy_triggered).length,
        avg_risk_score: eventList.length > 0 
          ? Math.round(eventList.reduce((sum, e) => sum + (e.score || 0), 0) / eventList.length)
          : 0
      });
      
    } catch (error) {
      console.error('Failed to fetch deception data:', error);
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data
  const loadDemoData = () => {
    setStatus({
      engine: 'Seraph Deception Engine',
      status: 'active',
      uptime: '14d 6h 32m',
      pebbles_enabled: true,
      mystique_enabled: true,
      stonewall_enabled: true
    });
    
    setCapabilities([
      {
        name: 'Pebbles',
        description: 'Campaign-based attack correlation via behavioral fingerprints',
        features: ['fingerprint_tracking', 'campaign_correlation', 'cross_session_linking'],
        status: 'active'
      },
      {
        name: 'Mystique',
        description: 'Self-adapting deception parameters based on attacker behavior',
        features: ['adaptive_friction', 'adaptive_tarpit', 'dynamic_thresholds'],
        status: 'active'
      },
      {
        name: 'Stonewall',
        description: 'Progressive escalation for persistent attackers',
        features: ['soft_ban', 'hard_ban', 'automatic_blocklisting'],
        status: 'active'
      }
    ]);
    
    setCampaigns([
      {
        id: 'campaign-001',
        name: 'APT-Recon-2026-A',
        first_seen: '2026-03-01T08:15:00Z',
        last_seen: '2026-03-06T14:32:00Z',
        event_count: 47,
        unique_ips: 8,
        fingerprint_id: 'fp-8a3b2c1d',
        escalation_level: 'hard_ban',
        routes: ['friction', 'trap_sink', 'honeypot']
      },
      {
        id: 'campaign-002',
        name: 'Scanner-Bot-Fleet',
        first_seen: '2026-03-04T12:00:00Z',
        last_seen: '2026-03-06T13:45:00Z',
        event_count: 234,
        unique_ips: 42,
        fingerprint_id: 'fp-9d8e7f6g',
        escalation_level: 'soft_ban',
        routes: ['friction', 'disinformation']
      },
      {
        id: 'campaign-003',
        name: 'Credential-Spray',
        first_seen: '2026-03-05T22:30:00Z',
        last_seen: '2026-03-06T02:15:00Z',
        event_count: 89,
        unique_ips: 15,
        fingerprint_id: 'fp-1a2b3c4d',
        escalation_level: 'hard_ban',
        routes: ['trap_sink']
      }
    ]);
    
    setEvents([
      { id: 1, ip: '45.33.32.156', path: '/api/login', score: 85, route: 'trap_sink', escalation_level: 'hard_ban', campaign_id: 'campaign-001', timestamp: '2026-03-06T14:32:00Z', decoy_triggered: true },
      { id: 2, ip: '192.168.1.100', path: '/admin', score: 65, route: 'friction', escalation_level: 'soft_ban', campaign_id: 'campaign-002', timestamp: '2026-03-06T14:28:00Z', decoy_triggered: false },
      { id: 3, ip: '10.0.0.55', path: '/api/users', score: 45, route: 'pass_through', escalation_level: 'none', campaign_id: null, timestamp: '2026-03-06T14:25:00Z', decoy_triggered: false },
      { id: 4, ip: '203.0.113.50', path: '/.env', score: 92, route: 'honeypot', escalation_level: 'hard_ban', campaign_id: 'campaign-003', timestamp: '2026-03-06T14:20:00Z', decoy_triggered: true },
      { id: 5, ip: '198.51.100.23', path: '/wp-admin', score: 78, route: 'disinformation', escalation_level: 'soft_ban', campaign_id: 'campaign-002', timestamp: '2026-03-06T14:15:00Z', decoy_triggered: false }
    ]);
    
    setStats({
      active_campaigns: 3,
      total_events: 370,
      blocked_ips: 65,
      decoys_triggered: 23,
      avg_risk_score: 72
    });
  };

  // Get route badge
  const getRouteBadge = (route) => {
    const routeConfig = {
      pass_through: { color: 'bg-green-500/20 text-green-400', icon: CheckCircle2 },
      friction: { color: 'bg-yellow-500/20 text-yellow-400', icon: Timer },
      trap_sink: { color: 'bg-red-500/20 text-red-400', icon: Skull },
      honeypot: { color: 'bg-purple-500/20 text-purple-400', icon: Radar },
      disinformation: { color: 'bg-blue-500/20 text-blue-400', icon: EyeOff }
    };
    const config = routeConfig[route] || { color: 'bg-gray-500/20 text-gray-400', icon: Activity };
    const Icon = config.icon;
    return (
      <Badge className={config.color}>
        <Icon className="h-3 w-3 mr-1" />
        {route?.replace('_', ' ')}
      </Badge>
    );
  };

  // Get escalation badge
  const getEscalationBadge = (level) => {
    const levelConfig = {
      none: { color: 'bg-gray-500/20 text-gray-400' },
      soft_ban: { color: 'bg-orange-500/20 text-orange-400' },
      hard_ban: { color: 'bg-red-500/20 text-red-400' }
    };
    const config = levelConfig[level] || levelConfig.none;
    return <Badge className={config.color}>{level?.replace('_', ' ') || 'none'}</Badge>;
  };

  // Get capability icon
  const getCapabilityIcon = (name) => {
    switch (name) {
      case 'Pebbles': return Fingerprint;
      case 'Mystique': return Eye;
      case 'Stonewall': return Ban;
      default: return Shield;
    }
  };

  // Get capability color
  const getCapabilityColor = (name) => {
    switch (name) {
      case 'Pebbles': return 'from-blue-500/20 to-cyan-500/20 border-blue-500/30';
      case 'Mystique': return 'from-purple-500/20 to-pink-500/20 border-purple-500/30';
      case 'Stonewall': return 'from-red-500/20 to-orange-500/20 border-red-500/30';
      default: return 'from-gray-500/20 to-gray-500/20 border-gray-500/30';
    }
  };

  const deployDecoy = async () => {
    try {
      const payload = {
        host_id: 'deception-engine',
        decoy_type: 'credentials',
        decoys: [
          `svc_trap_${Date.now()}`,
          `api_key_honey_${Math.floor(Math.random() * 10000)}`
        ],
        placement: 'standard'
      };

      const res = await axios.post(`${API}/v1/deception/decoy/deploy`, payload, {
        headers: getAuthHeaders()
      });

      const count = res.data?.details?.count ?? payload.decoys.length;
      toast.success(`Decoy deployment queued (${count} decoys)`);
      await fetchDeceptionData();
    } catch (error) {
      console.error('Decoy deployment failed:', error);
      toast.error('Failed to deploy decoy');
    }
  };

  useEffect(() => {
    fetchDeceptionData();
  }, [fetchDeceptionData]);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/20 rounded-lg">
            <Eye className="h-6 w-6 text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Deception Engine</h1>
            <p className="text-gray-400 text-sm">Pebbles • Mystique • Stonewall</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            onClick={fetchDeceptionData}
            disabled={loading}
            className="border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button className="bg-purple-600 hover:bg-purple-700" onClick={deployDecoy} disabled={loading}>
            <Siren className="h-4 w-4 mr-2" />
            Deploy Decoy
          </Button>
        </div>
      </div>

      {/* Engine Status */}
      {status && (
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 p-4 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${status.status === 'active' ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                <span className="font-medium">{status.engine}</span>
              </div>
              <span className="text-gray-400">|</span>
              <span className="text-sm text-gray-400">Uptime: {status.uptime}</span>
            </div>
            <div className="flex gap-3">
              {status.pebbles_enabled && (
                <Badge className="bg-blue-500/20 text-blue-400">
                  <Fingerprint className="h-3 w-3 mr-1" />
                  Pebbles
                </Badge>
              )}
              {status.mystique_enabled && (
                <Badge className="bg-purple-500/20 text-purple-400">
                  <Eye className="h-3 w-3 mr-1" />
                  Mystique
                </Badge>
              )}
              {status.stonewall_enabled && (
                <Badge className="bg-red-500/20 text-red-400">
                  <Ban className="h-3 w-3 mr-1" />
                  Stonewall
                </Badge>
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
            <Network className="h-4 w-4 text-blue-400" />
            <span className="text-gray-400 text-sm">Active Campaigns</span>
          </div>
          <p className="text-2xl font-bold">{stats.active_campaigns}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Activity className="h-4 w-4 text-purple-400" />
            <span className="text-gray-400 text-sm">Total Events</span>
          </div>
          <p className="text-2xl font-bold">{stats.total_events}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 border border-red-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Ban className="h-4 w-4 text-red-400" />
            <span className="text-gray-400 text-sm">Blocked IPs</span>
          </div>
          <p className="text-2xl font-bold text-red-400">{stats.blocked_ips}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 border border-orange-900/50 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Radar className="h-4 w-4 text-orange-400" />
            <span className="text-gray-400 text-sm">Decoys Triggered</span>
          </div>
          <p className="text-2xl font-bold text-orange-400">{stats.decoys_triggered}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gray-900/50 border border-gray-800 rounded-xl p-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <Gauge className="h-4 w-4 text-yellow-400" />
            <span className="text-gray-400 text-sm">Avg Risk Score</span>
          </div>
          <p className="text-2xl font-bold">{stats.avg_risk_score}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'overview', label: 'Capabilities', icon: Layers },
          { id: 'campaigns', label: 'Campaigns', icon: Network },
          { id: 'events', label: 'Events', icon: Activity }
        ].map(tab => (
          <Button
            key={tab.id}
            variant={viewMode === tab.id ? 'default' : 'outline'}
            onClick={() => setViewMode(tab.id)}
            className={viewMode === tab.id ? 'bg-purple-600' : 'border-gray-700'}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content Area */}
        <div className="col-span-2">
          {/* Capabilities Overview */}
          {viewMode === 'overview' && (
            <div className="space-y-4">
              {capabilities.map((cap, idx) => {
                const Icon = getCapabilityIcon(cap.name);
                return (
                  <motion.div
                    key={cap.name}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className={`p-6 bg-gradient-to-br ${getCapabilityColor(cap.name)} border rounded-xl`}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-gray-800/50 rounded-lg">
                          <Icon className="h-6 w-6" />
                        </div>
                        <div>
                          <h3 className="text-xl font-bold">{cap.name}</h3>
                          <p className="text-gray-400 text-sm">{cap.description}</p>
                        </div>
                      </div>
                      <Badge className={cap.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}>
                        {cap.status || 'active'}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {cap.features?.map(feature => (
                        <Badge key={feature} variant="outline" className="border-gray-600">
                          {feature.replace(/_/g, ' ')}
                        </Badge>
                      ))}
                    </div>
                  </motion.div>
                );
              })}
              
              {/* Route Decisions Legend */}
              <div className="p-4 bg-gray-900/50 border border-gray-800 rounded-xl">
                <h3 className="font-semibold mb-3">Route Decisions</h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex items-center gap-2">
                    {getRouteBadge('pass_through')}
                    <span className="text-sm text-gray-400">Allow request</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getRouteBadge('friction')}
                    <span className="text-sm text-gray-400">Add delays</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getRouteBadge('trap_sink')}
                    <span className="text-sm text-gray-400">Contain & block</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getRouteBadge('honeypot')}
                    <span className="text-sm text-gray-400">Redirect to decoy</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getRouteBadge('disinformation')}
                    <span className="text-sm text-gray-400">Feed fake data</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Campaigns */}
          {viewMode === 'campaigns' && (
            <div className="space-y-3">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Network className="h-5 w-5 text-blue-400" />
                Attack Campaigns (Pebbles Tracking)
              </h3>
              {campaigns.map((campaign, idx) => (
                <motion.div
                  key={campaign.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    selectedCampaign?.id === campaign.id 
                      ? 'bg-purple-500/20 border-purple-500' 
                      : 'bg-gray-800/50 border-gray-700 hover:border-gray-600'
                  }`}
                  onClick={() => setSelectedCampaign(campaign)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Skull className="h-4 w-4 text-red-400" />
                      <span className="font-medium">{campaign.name}</span>
                    </div>
                    {getEscalationBadge(campaign.escalation_level)}
                  </div>
                  
                  <div className="grid grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-gray-400">Events</p>
                      <p className="font-medium">{campaign.event_count}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Unique IPs</p>
                      <p className="font-medium">{campaign.unique_ips}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">First Seen</p>
                      <p className="font-medium">{new Date(campaign.first_seen).toLocaleDateString()}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Last Seen</p>
                      <p className="font-medium">{new Date(campaign.last_seen).toLocaleDateString()}</p>
                    </div>
                  </div>
                  
                  <div className="flex gap-1 mt-3">
                    {campaign.routes?.map(route => getRouteBadge(route))}
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          {/* Events */}
          {viewMode === 'events' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Activity className="h-5 w-5 text-purple-400" />
                  Recent Deception Events
                </h3>
                <div className="flex gap-2">
                  {['all', 'trap_sink', 'honeypot', 'friction'].map(filter => (
                    <Button
                      key={filter}
                      variant="outline"
                      size="sm"
                      onClick={() => setEventFilter(eventFilter === filter ? null : filter)}
                      className={eventFilter === filter ? 'bg-purple-600 border-purple-500' : 'border-gray-700'}
                    >
                      {filter === 'all' ? 'All' : filter.replace('_', ' ')}
                    </Button>
                  ))}
                </div>
              </div>
              
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-800/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Time</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">IP</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Path</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Score</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Route</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Escalation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events
                      .filter(e => !eventFilter || eventFilter === 'all' || e.route === eventFilter)
                      .map((event, idx) => (
                        <motion.tr
                          key={event.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: idx * 0.03 }}
                          className="border-t border-gray-800 hover:bg-gray-800/30"
                        >
                          <td className="px-4 py-3 text-sm">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="px-4 py-3 text-sm font-mono">
                            {event.ip}
                            {event.decoy_triggered && (
                              <Radar className="inline h-3 w-3 ml-2 text-orange-400" />
                            )}
                          </td>
                          <td className="px-4 py-3 text-sm font-mono text-gray-400 truncate max-w-[200px]">
                            {event.path}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-12 h-2 bg-gray-700 rounded-full overflow-hidden">
                                <div 
                                  className={`h-full ${
                                    event.score >= 80 ? 'bg-red-500' :
                                    event.score >= 60 ? 'bg-orange-500' :
                                    event.score >= 40 ? 'bg-yellow-500' :
                                    'bg-green-500'
                                  }`}
                                  style={{ width: `${event.score}%` }}
                                />
                              </div>
                              <span className="text-sm">{event.score}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {getRouteBadge(event.route)}
                          </td>
                          <td className="px-4 py-3">
                            {getEscalationBadge(event.escalation_level)}
                          </td>
                        </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Selected Campaign Details */}
          <AnimatePresence mode="wait">
            {selectedCampaign && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="bg-gray-900/50 border border-purple-900/50 rounded-xl p-4"
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Skull className="h-4 w-4 text-red-400" />
                  Campaign Details
                </h3>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm text-gray-400">Name</p>
                    <p className="font-medium">{selectedCampaign.name}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Fingerprint ID</p>
                    <p className="font-mono text-sm">{selectedCampaign.fingerprint_id}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="text-sm text-gray-400">Total Events</p>
                      <p className="font-bold text-xl">{selectedCampaign.event_count}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400">Unique IPs</p>
                      <p className="font-bold text-xl">{selectedCampaign.unique_ips}</p>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400 mb-1">Escalation</p>
                    {getEscalationBadge(selectedCampaign.escalation_level)}
                  </div>
                  <Button variant="outline" className="w-full border-red-900/50 text-red-400 hover:bg-red-500/10">
                    <Ban className="h-4 w-4 mr-2" />
                    Block All Campaign IPs
                  </Button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Quick Risk Assessment */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Gauge className="h-4 w-4 text-yellow-400" />
              Risk Assessment
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-sm text-gray-400">IP Address</label>
                <input 
                  type="text" 
                  placeholder="e.g., 192.168.1.100"
                  className="w-full mt-1 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-purple-500 focus:outline-none"
                />
              </div>
              <Button className="w-full bg-purple-600 hover:bg-purple-700">
                <Crosshair className="h-4 w-4 mr-2" />
                Assess Risk
              </Button>
            </div>
          </div>

          {/* Escalation Levels */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-red-400" />
              Stonewall Escalation
            </h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                <span className="text-sm">Soft Ban Threshold</span>
                <span className="font-mono text-sm">Score ≥ 60</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                <span className="text-sm">Hard Ban Threshold</span>
                <span className="font-mono text-sm">Score ≥ 80</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
                <span className="text-sm">Auto-Block Threshold</span>
                <span className="font-mono text-sm">Score ≥ 95</span>
              </div>
            </div>
          </div>

          {/* Decoy Types */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <h3 className="font-semibold mb-3">Active Decoys</h3>
            <div className="space-y-2">
              {[
                { type: 'Honey Credentials', count: 12, triggered: 3 },
                { type: 'Fake Endpoints', count: 8, triggered: 5 },
                { type: 'Canary Files', count: 24, triggered: 2 },
                { type: 'DNS Sinkholes', count: 4, triggered: 8 }
              ].map(decoy => (
                <div key={decoy.type} className="flex items-center justify-between p-2 bg-gray-800/30 rounded-lg">
                  <span className="text-sm">{decoy.type}</span>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="border-gray-600 text-xs">{decoy.count}</Badge>
                    {decoy.triggered > 0 && (
                      <Badge className="bg-orange-500/20 text-orange-400 text-xs">{decoy.triggered} hit</Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DeceptionPage;
