import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Radar, 
  Plus,
  Activity,
  AlertTriangle,
  Eye,
  Server,
  Wifi,
  Database,
  Globe,
  Clock,
  RefreshCw
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

const honeypotTypeIcons = {
  ssh: Server,
  http: Globe,
  ftp: Database,
  smb: Wifi,
  database: Database
};

const HoneypotCard = ({ honeypot, onRefresh }) => {
  const Icon = honeypotTypeIcons[honeypot.type] || Server;
  const { getAuthHeaders } = useAuth();
  const [interactions, setInteractions] = useState([]);
  const [showInteractions, setShowInteractions] = useState(false);

  const fetchInteractions = async () => {
    try {
      const response = await axios.get(`${API}/honeypots/${honeypot.id}/interactions`, {
        headers: getAuthHeaders()
      });
      setInteractions(response.data);
    } catch (error) {
      console.error('Failed to fetch interactions');
    }
  };

  useEffect(() => {
    if (showInteractions) {
      fetchInteractions();
    }
  }, [showInteractions]);

  const statusColors = {
    active: 'bg-green-500/20 text-green-400 border-green-500/30',
    inactive: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
    triggered: 'bg-red-500/20 text-red-400 border-red-500/30 animate-pulse'
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded overflow-hidden hover:border-slate-700 transition-all"
    >
      <div className={`p-4 ${honeypot.status === 'triggered' ? 'bg-red-500/10' : 'bg-slate-800/30'} border-b border-slate-800`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className={`w-10 h-10 rounded flex items-center justify-center ${
              honeypot.status === 'triggered' ? 'bg-red-500/20' : 'bg-cyan-500/20'
            }`}>
              <Icon className={`w-5 h-5 ${honeypot.status === 'triggered' ? 'text-red-400' : 'text-cyan-400'}`} />
            </div>
            <div>
              <h3 className="font-medium text-white">{honeypot.name}</h3>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className="text-xs text-slate-400 border-slate-600 uppercase">
                  {honeypot.type}
                </Badge>
                <Badge variant="outline" className={`text-xs ${statusColors[honeypot.status]}`}>
                  {honeypot.status}
                </Badge>
              </div>
            </div>
          </div>
          <div className="text-right">
            <p className="text-2xl font-mono font-bold text-cyan-400">{honeypot.interactions}</p>
            <p className="text-xs text-slate-500">interactions</p>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-3">
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-slate-500" />
            <span className="text-slate-400">IP: <span className="text-white font-mono">{honeypot.ip}</span></span>
          </div>
          <div className="flex items-center gap-2">
            <Wifi className="w-4 h-4 text-slate-500" />
            <span className="text-slate-400">Port: <span className="text-white font-mono">{honeypot.port}</span></span>
          </div>
        </div>

        {honeypot.description && (
          <p className="text-sm text-slate-400">{honeypot.description}</p>
        )}

        {honeypot.last_interaction && (
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Clock className="w-3 h-3" />
            Last interaction: {new Date(honeypot.last_interaction).toLocaleString()}
          </div>
        )}
      </div>

      <div className="p-4 border-t border-slate-800 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          Created: {new Date(honeypot.created_at).toLocaleDateString()}
        </span>
        <Button
          size="sm"
          variant="outline"
          className="text-xs border-slate-700 text-slate-400 hover:text-cyan-400"
          onClick={() => setShowInteractions(!showInteractions)}
          data-testid={`view-interactions-${honeypot.id}`}
        >
          <Eye className="w-3 h-3 mr-1" />
          {showInteractions ? 'Hide' : 'View'} Interactions
        </Button>
      </div>

      {showInteractions && (
        <div className="border-t border-slate-800 p-4">
          <h4 className="text-sm font-medium text-white mb-3">Recent Interactions</h4>
          {interactions.length > 0 ? (
            <ScrollArea className="h-40">
              <div className="space-y-2">
                {interactions.map((interaction) => (
                  <div 
                    key={interaction.id} 
                    className={`p-2 rounded text-xs ${
                      interaction.threat_level === 'high' ? 'bg-red-500/10 border border-red-500/30' :
                      interaction.threat_level === 'medium' ? 'bg-amber-500/10 border border-amber-500/30' :
                      'bg-slate-800/50 border border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate-400">{interaction.action}</span>
                      <Badge variant="outline" className={`text-xs ${
                        interaction.threat_level === 'high' ? 'text-red-400 border-red-500/30' :
                        interaction.threat_level === 'medium' ? 'text-amber-400 border-amber-500/30' :
                        'text-green-400 border-green-500/30'
                      }`}>
                        {interaction.threat_level}
                      </Badge>
                    </div>
                    <p className="text-slate-500">
                      From: {interaction.source_ip} • {new Date(interaction.timestamp).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            </ScrollArea>
          ) : (
            <p className="text-sm text-slate-500 text-center py-4">No interactions recorded</p>
          )}
        </div>
      )}
    </motion.div>
  );
};

const HoneypotsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [honeypots, setHoneypots] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newHoneypot, setNewHoneypot] = useState({
    name: '',
    type: 'ssh',
    ip: '',
    port: 22,
    description: ''
  });

  const fetchHoneypots = async () => {
    try {
      const response = await axios.get(`${API}/honeypots`, {
        headers: getAuthHeaders()
      });
      setHoneypots(response.data);
    } catch (error) {
      if (error.response?.status === 403) {
        toast.error('Permission denied. Admin access required.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHoneypots();
  }, []);

  const handleAddHoneypot = async () => {
    try {
      await axios.post(`${API}/honeypots`, newHoneypot, {
        headers: getAuthHeaders()
      });
      toast.success('Honeypot deployed successfully');
      setShowAddDialog(false);
      setNewHoneypot({ name: '', type: 'ssh', ip: '', port: 22, description: '' });
      fetchHoneypots();
    } catch (error) {
      if (error.response?.status === 403) {
        toast.error('Permission denied. Write access required to deploy honeypots.');
      } else {
        toast.error('Failed to deploy honeypot');
      }
    }
  };

  const stats = {
    total: honeypots.length,
    active: honeypots.filter(h => h.status === 'active').length,
    triggered: honeypots.filter(h => h.status === 'triggered').length,
    totalInteractions: honeypots.reduce((sum, h) => sum + h.interactions, 0)
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="honeypots-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
            <Radar className="w-7 h-7 text-cyan-400" />
            Honeypot System
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Deploy and monitor deceptive security traps
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            className="border-slate-700 text-slate-300"
            onClick={fetchHoneypots}
            data-testid="refresh-honeypots-btn"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
            <DialogTrigger asChild>
              <Button
                className="bg-cyan-600 hover:bg-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.3)]"
                onClick={() => setShowAddDialog(true)}
                data-testid="deploy-honeypot-btn"
              >
                <Plus className="w-4 h-4 mr-2" />
                Deploy Honeypot
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-slate-900 border-slate-800 max-w-md">
              <DialogHeader>
                <DialogTitle className="text-white font-mono">Deploy New Honeypot</DialogTitle>
                <DialogDescription className="text-slate-400">
                  Configure a deceptive service to attract and monitor attackers
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div>
                  <Label className="text-slate-300">Honeypot Name</Label>
                  <Input
                    value={newHoneypot.name}
                    onChange={(e) => setNewHoneypot({ ...newHoneypot, name: e.target.value })}
                    className="bg-slate-950 border-slate-700 text-white"
                    placeholder="e.g., SSH Trap Alpha"
                    data-testid="honeypot-name-input"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-slate-300">Type</Label>
                    <Select value={newHoneypot.type} onValueChange={(v) => setNewHoneypot({ ...newHoneypot, type: v })}>
                      <SelectTrigger className="bg-slate-950 border-slate-700" data-testid="honeypot-type-select">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-slate-900 border-slate-700">
                        <SelectItem value="ssh">SSH</SelectItem>
                        <SelectItem value="http">HTTP</SelectItem>
                        <SelectItem value="ftp">FTP</SelectItem>
                        <SelectItem value="smb">SMB</SelectItem>
                        <SelectItem value="database">Database</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-slate-300">Port</Label>
                    <Input
                      type="number"
                      value={newHoneypot.port}
                      onChange={(e) => setNewHoneypot({ ...newHoneypot, port: parseInt(e.target.value) })}
                      className="bg-slate-950 border-slate-700 text-white"
                      data-testid="honeypot-port-input"
                    />
                  </div>
                </div>
                <div>
                  <Label className="text-slate-300">IP Address</Label>
                  <Input
                    value={newHoneypot.ip}
                    onChange={(e) => setNewHoneypot({ ...newHoneypot, ip: e.target.value })}
                    className="bg-slate-950 border-slate-700 text-white"
                    placeholder="e.g., 10.0.5.100"
                    data-testid="honeypot-ip-input"
                  />
                </div>
                <div>
                  <Label className="text-slate-300">Description</Label>
                  <Textarea
                    value={newHoneypot.description}
                    onChange={(e) => setNewHoneypot({ ...newHoneypot, description: e.target.value })}
                    className="bg-slate-950 border-slate-700 text-white"
                    placeholder="Optional description..."
                    data-testid="honeypot-desc-input"
                  />
                </div>
                <Button 
                  onClick={handleAddHoneypot} 
                  className="w-full bg-cyan-600 hover:bg-cyan-500"
                  disabled={!newHoneypot.name || !newHoneypot.ip}
                  data-testid="submit-honeypot-btn"
                >
                  Deploy Honeypot
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Honeypots', value: stats.total, color: 'cyan', icon: Radar },
          { label: 'Active', value: stats.active, color: 'green', icon: Activity },
          { label: 'Triggered', value: stats.triggered, color: 'red', icon: AlertTriangle },
          { label: 'Total Interactions', value: stats.totalInteractions, color: 'amber', icon: Eye }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4"
          >
            <div className="flex items-center gap-2 mb-1">
              <stat.icon className={`w-4 h-4 text-${stat.color}-400`} />
              <p className="text-slate-400 text-sm">{stat.label}</p>
            </div>
            <p className={`text-2xl font-mono font-bold text-${stat.color}-400`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Honeypots Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">
          <div className="w-8 h-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mx-auto mb-4" />
          Loading honeypots...
        </div>
      ) : honeypots.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {honeypots.map((honeypot) => (
            <HoneypotCard key={honeypot.id} honeypot={honeypot} onRefresh={fetchHoneypots} />
          ))}
        </div>
      ) : (
        <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-12 text-center">
          <Radar className="w-12 h-12 mx-auto mb-4 text-slate-600" />
          <h3 className="text-lg font-medium text-slate-400 mb-2">No Honeypots Deployed</h3>
          <p className="text-sm text-slate-500 mb-4">
            Deploy deceptive services to detect and analyze attacker behavior
          </p>
          <Button
            onClick={() => setShowAddDialog(true)}
            className="bg-cyan-600 hover:bg-cyan-500"
            data-testid="deploy-first-honeypot-btn"
          >
            <Plus className="w-4 h-4 mr-2" />
            Deploy First Honeypot
          </Button>
        </div>
      )}
    </div>
  );
};

export default HoneypotsPage;
