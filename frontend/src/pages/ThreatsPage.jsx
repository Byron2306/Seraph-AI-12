import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  AlertTriangle, 
  Shield, 
  Target,
  Plus,
  Filter,
  Clock,
  Server,
  Globe,
  Bug,
  Bot,
  Network,
  Mail
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Textarea } from '../components/ui/textarea';
import { ScrollArea } from '../components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from '../components/ui/dialog';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const ThreatTypeIcon = ({ type }) => {
  const icons = {
    ai_agent: Bot,
    malware: Bug,
    botnet: Network,
    phishing: Mail,
    ransomware: Shield
  };
  const Icon = icons[type] || AlertTriangle;
  return <Icon className="w-5 h-5" />;
};

const ThreatCard = ({ threat, onStatusChange }) => {
  const severityColors = {
    critical: { bg: 'bg-red-500/10', border: 'border-red-500', text: 'text-red-400' },
    high: { bg: 'bg-amber-500/10', border: 'border-amber-500', text: 'text-amber-400' },
    medium: { bg: 'bg-yellow-500/10', border: 'border-yellow-500', text: 'text-yellow-400' },
    low: { bg: 'bg-green-500/10', border: 'border-green-500', text: 'text-green-400' }
  };

  const statusColors = {
    active: 'bg-red-500/20 text-red-400',
    contained: 'bg-amber-500/20 text-amber-400',
    resolved: 'bg-green-500/20 text-green-400'
  };

  const colors = severityColors[threat.severity] || severityColors.medium;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`bg-slate-900/50 backdrop-blur-md border ${colors.border}/30 rounded overflow-hidden hover:border-${threat.severity === 'critical' ? 'red' : threat.severity === 'high' ? 'amber' : 'blue'}-500/50 transition-all duration-300`}
    >
      {/* Header */}
      <div className={`p-4 ${colors.bg} border-b border-slate-800`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className={`w-10 h-10 rounded ${colors.bg} flex items-center justify-center ${colors.text}`}>
              <ThreatTypeIcon type={threat.type} />
            </div>
            <div>
              <h3 className="font-medium text-white">{threat.name}</h3>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className={`${colors.text} ${colors.border}/50 text-xs`}>
                  {threat.severity}
                </Badge>
                <Badge variant="outline" className="text-slate-400 border-slate-600 text-xs">
                  {threat.type.replace('_', ' ')}
                </Badge>
              </div>
            </div>
          </div>
          <span className={`text-xs px-2 py-1 rounded ${statusColors[threat.status]}`}>
            {threat.status}
          </span>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 space-y-3">
        {threat.description && (
          <p className="text-sm text-slate-400">{threat.description}</p>
        )}

        <div className="grid grid-cols-2 gap-3 text-sm">
          {threat.source_ip && (
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-slate-500" />
              <span className="text-slate-400">Source: <span className="text-white font-mono">{threat.source_ip}</span></span>
            </div>
          )}
          {threat.target_system && (
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-slate-500" />
              <span className="text-slate-400">Target: <span className="text-white">{threat.target_system}</span></span>
            </div>
          )}
        </div>

        {threat.indicators?.length > 0 && (
          <div className="pt-2">
            <p className="text-xs text-slate-500 mb-2">Indicators:</p>
            <div className="flex flex-wrap gap-1">
              {threat.indicators.map((indicator, i) => (
                <Badge key={i} variant="outline" className="text-xs text-slate-400 border-slate-700">
                  {indicator}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Clock className="w-3 h-3" />
          {new Date(threat.created_at).toLocaleString()}
        </div>
        <div className="flex items-center gap-2">
          {threat.status === 'active' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs border-amber-700 text-amber-400 hover:bg-amber-500/10"
              onClick={() => onStatusChange(threat.id, 'contained')}
              data-testid={`contain-threat-${threat.id}`}
            >
              <Target className="w-3 h-3 mr-1" />
              Contain
            </Button>
          )}
          {threat.status !== 'resolved' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs border-green-700 text-green-400 hover:bg-green-500/10"
              onClick={() => onStatusChange(threat.id, 'resolved')}
              data-testid={`resolve-threat-${threat.id}`}
            >
              <Shield className="w-3 h-3 mr-1" />
              Resolve
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  );
};

const ThreatsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newThreat, setNewThreat] = useState({
    name: '',
    type: 'ai_agent',
    severity: 'high',
    source_ip: '',
    target_system: '',
    description: '',
    indicators: []
  });

  const fetchThreats = async () => {
    try {
      const params = {};
      if (statusFilter !== 'all') params.status = statusFilter;
      if (severityFilter !== 'all') params.severity = severityFilter;
      
      const response = await axios.get(`${API}/threats`, {
        headers: getAuthHeaders(),
        params
      });
      setThreats(response.data);
    } catch (error) {
      toast.error('Failed to fetch threats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [statusFilter, severityFilter]);

  const handleStatusChange = async (threatId, newStatus) => {
    try {
      await axios.patch(
        `${API}/threats/${threatId}/status?status=${newStatus}`,
        {},
        { headers: getAuthHeaders() }
      );
      toast.success(`Threat ${newStatus}`);
      fetchThreats();
    } catch (error) {
      toast.error('Failed to update threat');
    }
  };

  const handleAddThreat = async () => {
    try {
      await axios.post(`${API}/threats`, newThreat, {
        headers: getAuthHeaders()
      });
      toast.success('Threat logged successfully');
      setShowAddDialog(false);
      setNewThreat({
        name: '',
        type: 'ai_agent',
        severity: 'high',
        source_ip: '',
        target_system: '',
        description: '',
        indicators: []
      });
      fetchThreats();
    } catch (error) {
      toast.error('Failed to add threat');
    }
  };

  const threatStats = {
    total: threats.length,
    active: threats.filter(t => t.status === 'active').length,
    contained: threats.filter(t => t.status === 'contained').length,
    resolved: threats.filter(t => t.status === 'resolved').length
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="threats-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
            <AlertTriangle className="w-7 h-7 text-amber-400" />
            Threat Management
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Track and manage detected security threats
          </p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button
              className="bg-blue-600 hover:bg-blue-500 shadow-glow-blue"
              onClick={() => setShowAddDialog(true)}
              data-testid="add-threat-btn"
            >
              <Plus className="w-4 h-4 mr-2" />
              Log Threat
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-slate-900 border-slate-800 max-w-md">
            <DialogHeader>
              <DialogTitle className="text-white font-mono">Log New Threat</DialogTitle>
              <DialogDescription className="text-slate-400">
                Enter details about the detected threat
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label className="text-slate-300">Threat Name</Label>
                <Input
                  value={newThreat.name}
                  onChange={(e) => setNewThreat({ ...newThreat, name: e.target.value })}
                  className="bg-slate-950 border-slate-700 text-white"
                  placeholder="e.g., Suspicious AI Agent Activity"
                  data-testid="threat-name-input"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-slate-300">Type</Label>
                  <Select value={newThreat.type} onValueChange={(v) => setNewThreat({ ...newThreat, type: v })}>
                    <SelectTrigger className="bg-slate-950 border-slate-700" data-testid="threat-type-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-700">
                      <SelectItem value="ai_agent">AI Agent</SelectItem>
                      <SelectItem value="malware">Malware</SelectItem>
                      <SelectItem value="botnet">Botnet</SelectItem>
                      <SelectItem value="phishing">Phishing</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-slate-300">Severity</Label>
                  <Select value={newThreat.severity} onValueChange={(v) => setNewThreat({ ...newThreat, severity: v })}>
                    <SelectTrigger className="bg-slate-950 border-slate-700" data-testid="threat-severity-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-700">
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label className="text-slate-300">Source IP</Label>
                <Input
                  value={newThreat.source_ip}
                  onChange={(e) => setNewThreat({ ...newThreat, source_ip: e.target.value })}
                  className="bg-slate-950 border-slate-700 text-white"
                  placeholder="e.g., 192.168.1.100"
                  data-testid="threat-ip-input"
                />
              </div>
              <div>
                <Label className="text-slate-300">Target System</Label>
                <Input
                  value={newThreat.target_system}
                  onChange={(e) => setNewThreat({ ...newThreat, target_system: e.target.value })}
                  className="bg-slate-950 border-slate-700 text-white"
                  placeholder="e.g., Production Server"
                  data-testid="threat-target-input"
                />
              </div>
              <div>
                <Label className="text-slate-300">Description</Label>
                <Textarea
                  value={newThreat.description}
                  onChange={(e) => setNewThreat({ ...newThreat, description: e.target.value })}
                  className="bg-slate-950 border-slate-700 text-white"
                  placeholder="Describe the threat..."
                  data-testid="threat-description-input"
                />
              </div>
              <Button 
                onClick={handleAddThreat} 
                className="w-full bg-blue-600 hover:bg-blue-500"
                disabled={!newThreat.name}
                data-testid="submit-threat-btn"
              >
                Log Threat
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Threats', value: threatStats.total, color: 'blue' },
          { label: 'Active', value: threatStats.active, color: 'red' },
          { label: 'Contained', value: threatStats.contained, color: 'amber' },
          { label: 'Resolved', value: threatStats.resolved, color: 'green' }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4"
          >
            <p className="text-slate-400 text-sm">{stat.label}</p>
            <p className={`text-2xl font-mono font-bold text-${stat.color}-400`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-400">Filter:</span>
        </div>
        
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40 bg-slate-950 border-slate-700" data-testid="threat-status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-700">
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="contained">Contained</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>

        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40 bg-slate-950 border-slate-700" data-testid="threat-severity-filter">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-700">
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Button
          variant="outline"
          size="sm"
          className="ml-auto border-slate-700 text-slate-400"
          onClick={fetchThreats}
          data-testid="refresh-threats-btn"
        >
          Refresh
        </Button>
      </div>

      {/* Threats Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">
          <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mx-auto mb-4" />
          Loading threats...
        </div>
      ) : threats.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {threats.map((threat) => (
            <ThreatCard 
              key={threat.id} 
              threat={threat} 
              onStatusChange={handleStatusChange}
            />
          ))}
        </div>
      ) : (
        <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-12 text-center">
          <Shield className="w-12 h-12 mx-auto mb-4 text-slate-600" />
          <h3 className="text-lg font-medium text-slate-400 mb-2">No Threats Found</h3>
          <p className="text-sm text-slate-500">
            {statusFilter !== 'all' || severityFilter !== 'all' 
              ? 'Try adjusting your filters' 
              : 'System is secure - no threats detected'}
          </p>
        </div>
      )}
    </div>
  );
};

export default ThreatsPage;
