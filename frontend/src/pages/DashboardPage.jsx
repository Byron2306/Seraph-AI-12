import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Cpu, 
  Target,
  Bug,
  Network,
  TrendingUp,
  Clock,
  ChevronRight,
  Zap
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell,
  Tooltip
} from 'recharts';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const StatCard = ({ icon: Icon, label, value, subValue, color, glow }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={`bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5 hover:border-${color}-500/50 transition-all duration-300`}
    style={{ boxShadow: glow ? `0 0 30px rgba(${color === 'red' ? '239,68,68' : color === 'green' ? '16,185,129' : color === 'amber' ? '245,158,11' : '59,130,246'}, 0.1)` : 'none' }}
  >
    <div className="flex items-start justify-between">
      <div>
        <p className="text-slate-400 text-sm mb-1">{label}</p>
        <p className={`text-3xl font-mono font-bold text-${color}-400`}>{value}</p>
        {subValue && <p className="text-xs text-slate-500 mt-1">{subValue}</p>}
      </div>
      <div className={`w-10 h-10 rounded bg-${color}-500/10 flex items-center justify-center`}>
        <Icon className={`w-5 h-5 text-${color}-400`} />
      </div>
    </div>
  </motion.div>
);

const ThreatCard = ({ threat }) => {
  const severityColors = {
    critical: 'red',
    high: 'amber',
    medium: 'yellow',
    low: 'green'
  };
  const color = severityColors[threat.severity] || 'blue';

  return (
    <div className={`p-4 bg-slate-800/30 border-l-2 border-${color}-500 rounded-r hover:bg-slate-800/50 transition-colors`}>
      <div className="flex items-start justify-between mb-2">
        <h4 className="font-medium text-white text-sm">{threat.name}</h4>
        <Badge variant="outline" className={`text-${color}-400 border-${color}-500/50 text-xs`}>
          {threat.severity}
        </Badge>
      </div>
      <p className="text-xs text-slate-400 mb-2">{threat.type} • {threat.source_ip || 'Unknown source'}</p>
      <div className="flex items-center justify-between">
        <span className={`text-xs px-2 py-1 rounded bg-${threat.status === 'active' ? 'red' : threat.status === 'contained' ? 'amber' : 'green'}-500/10 text-${threat.status === 'active' ? 'red' : threat.status === 'contained' ? 'amber' : 'green'}-400`}>
          {threat.status}
        </span>
        <span className="text-xs text-slate-500">
          {new Date(threat.created_at).toLocaleTimeString()}
        </span>
      </div>
    </div>
  );
};

const AlertItem = ({ alert }) => {
  const severityColors = {
    critical: 'red',
    high: 'amber',
    medium: 'yellow',
    low: 'green'
  };
  const color = severityColors[alert.severity] || 'blue';

  return (
    <div className="flex items-start gap-3 p-3 hover:bg-slate-800/30 rounded transition-colors">
      <div className={`w-2 h-2 rounded-full mt-2 bg-${color}-500 ${alert.status === 'new' ? 'animate-pulse' : ''}`} />
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white font-medium truncate">{alert.title}</p>
        <p className="text-xs text-slate-400 truncate">{alert.message}</p>
        <p className="text-xs text-slate-500 mt-1">{new Date(alert.created_at).toLocaleString()}</p>
      </div>
      <Badge variant="outline" className={`text-${color}-400 border-${color}-500/50 text-xs flex-shrink-0`}>
        {alert.type}
      </Badge>
    </div>
  );
};

const DashboardPage = () => {
  const navigate = useNavigate();
  const { getAuthHeaders } = useAuth();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Seed data first
        await axios.post(`${API}/dashboard/seed`, {}, { headers: getAuthHeaders() }).catch(() => {});
        
        // Fetch dashboard stats
        const response = await axios.get(`${API}/dashboard/stats`, {
          headers: getAuthHeaders()
        });
        setStats(response.data);
      } catch (error) {
        toast.error('Failed to fetch dashboard data');
        console.error(error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [getAuthHeaders]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading threat data...</div>
      </div>
    );
  }

  // Chart data
  const threatTypeData = Object.entries(stats?.threats_by_type || {}).map(([name, value]) => ({
    name: name.replace('_', ' ').toUpperCase(),
    value
  }));

  const severityData = Object.entries(stats?.threats_by_severity || {}).map(([name, value]) => ({
    name,
    value
  }));

  const COLORS = ['#EF4444', '#F59E0B', '#FBBF24', '#10B981'];

  // Simulated time series data for the area chart
  const timeSeriesData = Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, '0')}:00`,
    threats: Math.floor(Math.random() * 15) + 5,
    blocked: Math.floor(Math.random() * 12) + 3,
  }));

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="dashboard-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white">Threat Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Real-time security monitoring and threat intelligence</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-2 bg-green-500/10 border border-green-500/30 rounded">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs font-mono text-green-400">LIVE</span>
          </div>
          <Button 
            variant="outline" 
            className="border-slate-700 text-slate-300 hover:bg-slate-800"
            onClick={() => window.location.reload()}
            data-testid="refresh-dashboard-btn"
          >
            <Activity className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={AlertTriangle}
          label="Active Threats"
          value={stats?.active_threats || 0}
          subValue={`${stats?.total_threats || 0} total detected`}
          color="red"
          glow={stats?.active_threats > 0}
        />
        <StatCard
          icon={Shield}
          label="Contained"
          value={stats?.contained_threats || 0}
          subValue="Awaiting resolution"
          color="amber"
        />
        <StatCard
          icon={Target}
          label="Resolved"
          value={stats?.resolved_threats || 0}
          subValue="Threats eliminated"
          color="green"
        />
        <StatCard
          icon={Cpu}
          label="AI Scans Today"
          value={stats?.ai_scans_today || 0}
          subValue="Behavioral analyses"
          color="blue"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Activity Chart */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="lg:col-span-2 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-mono font-semibold text-white">Threat Activity</h3>
              <p className="text-xs text-slate-400">24-hour threat detection timeline</p>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-red-500" />
                <span className="text-slate-400">Detected</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-green-500" />
                <span className="text-slate-400">Blocked</span>
              </div>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <defs>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis 
                  dataKey="time" 
                  axisLine={false} 
                  tickLine={false}
                  tick={{ fill: '#64748B', fontSize: 10 }}
                  interval={3}
                />
                <YAxis 
                  axisLine={false} 
                  tickLine={false}
                  tick={{ fill: '#64748B', fontSize: 10 }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#0F172A', 
                    border: '1px solid #1E293B',
                    borderRadius: '4px'
                  }}
                  labelStyle={{ color: '#94A3B8' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="threats" 
                  stroke="#EF4444" 
                  fillOpacity={1} 
                  fill="url(#threatGrad)" 
                />
                <Area 
                  type="monotone" 
                  dataKey="blocked" 
                  stroke="#10B981" 
                  fillOpacity={1} 
                  fill="url(#blockedGrad)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Threat Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
        >
          <div className="mb-4">
            <h3 className="font-mono font-semibold text-white">Threat Distribution</h3>
            <p className="text-xs text-slate-400">By severity level</p>
          </div>
          <div className="h-48 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#0F172A', 
                    border: '1px solid #1E293B',
                    borderRadius: '4px'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-4">
            {severityData.map((item, i) => (
              <div key={item.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded" style={{ backgroundColor: COLORS[i] }} />
                <span className="text-xs text-slate-400 capitalize">{item.name}</span>
                <span className="text-xs text-white font-mono ml-auto">{item.value}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Bottom Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Threats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded"
        >
          <div className="p-5 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="font-mono font-semibold text-white">Recent Threats</h3>
              <p className="text-xs text-slate-400">Latest detected threats</p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="text-slate-400 hover:text-blue-400"
              onClick={() => navigate('/threats')}
            >
              View All <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          </div>
          <ScrollArea className="h-80">
            <div className="p-4 space-y-3">
              {stats?.recent_threats?.length > 0 ? (
                stats.recent_threats.map((threat) => (
                  <ThreatCard key={threat.id} threat={threat} />
                ))
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No threats detected</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </motion.div>

        {/* Recent Alerts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded"
        >
          <div className="p-5 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h3 className="font-mono font-semibold text-white">Alert Feed</h3>
              {stats?.critical_alerts > 0 && (
                <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                  {stats.critical_alerts} Critical
                </Badge>
              )}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="text-slate-400 hover:text-blue-400"
              onClick={() => navigate('/alerts')}
            >
              View All <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          </div>
          <ScrollArea className="h-80">
            <div className="divide-y divide-slate-800">
              {stats?.recent_alerts?.length > 0 ? (
                stats.recent_alerts.map((alert) => (
                  <AlertItem key={alert.id} alert={alert} />
                ))
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <Zap className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No alerts</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </motion.div>
      </div>

      {/* System Health Bar */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-green-400" />
            <h3 className="font-mono font-semibold text-white">System Health</h3>
          </div>
          <span className="text-2xl font-mono font-bold text-green-400">
            {stats?.system_health?.toFixed(1) || 100}%
          </span>
        </div>
        <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-green-500 to-emerald-400 transition-all duration-500"
            style={{ width: `${stats?.system_health || 100}%` }}
          />
        </div>
        <div className="flex items-center justify-between mt-3 text-xs text-slate-400">
          <span>Defense modules operational</span>
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </motion.div>
    </div>
  );
};

export default DashboardPage;
