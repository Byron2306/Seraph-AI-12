import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Key, Plus, Trash2, Eye, EyeOff, Copy, AlertTriangle,
  Shield, Clock, MapPin, RefreshCw, CheckCircle, XCircle,
  FileKey, Database, Lock, Wifi
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Switch } from '../components/ui/switch';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const HoneyTokensPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [tokens, setTokens] = useState([]);
  const [accesses, setAccesses] = useState([]);
  const [showValues, setShowValues] = useState({});
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newToken, setNewToken] = useState({
    name: '',
    token_type: 'api_key',
    description: '',
    location: ''
  });
  const [loading, setLoading] = useState(true);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, tokensRes, accessesRes] = await Promise.all([
        axios.get(`${API}/honey-tokens/stats`, { headers }),
        axios.get(`${API}/honey-tokens`, { headers }),
        axios.get(`${API}/honey-tokens/accesses/list?limit=20`, { headers })
      ]);
      setStats(statsRes.data);
      setTokens(tokensRes.data.tokens || []);
      setAccesses(accessesRes.data.accesses || []);
    } catch (err) {
      toast.error('Failed to load honey tokens');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateToken = async () => {
    if (!newToken.name || !newToken.token_type) {
      toast.error('Name and type are required');
      return;
    }
    try {
      await axios.post(`${API}/honey-tokens`, newToken, { headers });
      toast.success('Honey token created');
      setShowCreateForm(false);
      setNewToken({ name: '', token_type: 'api_key', description: '', location: '' });
      fetchData();
    } catch (err) {
      toast.error('Failed to create token');
    }
  };

  const handleToggleToken = async (tokenId) => {
    try {
      await axios.post(`${API}/honey-tokens/${tokenId}/toggle`, {}, { headers });
      toast.success('Token status updated');
      fetchData();
    } catch (err) {
      toast.error('Failed to toggle token');
    }
  };

  const handleDeleteToken = async (tokenId) => {
    if (!confirm('Delete this honey token?')) return;
    try {
      await axios.delete(`${API}/honey-tokens/${tokenId}`, { headers });
      toast.success('Token deleted');
      fetchData();
    } catch (err) {
      toast.error('Failed to delete token');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const getTypeIcon = (type) => {
    switch(type) {
      case 'api_key': return <Key className="w-4 h-4 text-cyan-400" />;
      case 'aws_key': return <Wifi className="w-4 h-4 text-amber-400" />;
      case 'database_cred': return <Database className="w-4 h-4 text-green-400" />;
      case 'password': return <Lock className="w-4 h-4 text-purple-400" />;
      case 'jwt_token': return <FileKey className="w-4 h-4 text-blue-400" />;
      default: return <Key className="w-4 h-4 text-slate-400" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-amber-400" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="honey-tokens-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Key className="w-6 h-6 text-amber-400" />
            Honey Tokens
          </h1>
          <p className="text-slate-400 text-sm mt-1">Deception technology - detect credential theft</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchData} variant="outline" className="border-amber-500/50 text-amber-400">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={() => setShowCreateForm(true)} className="bg-amber-600 hover:bg-amber-500">
            <Plus className="w-4 h-4 mr-2" />
            Create Token
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Key className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Total Tokens</p>
              <p className="text-2xl font-bold text-white">{stats?.total_tokens || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Shield className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Active</p>
              <p className="text-2xl font-bold text-green-400">{stats?.active_tokens || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Total Accesses</p>
              <p className="text-2xl font-bold text-red-400">{stats?.total_accesses || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className={`p-4 rounded-lg border ${stats?.unacknowledged_alerts > 0 ? 'bg-red-500/10 border-red-500/30 animate-pulse' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${stats?.unacknowledged_alerts > 0 ? 'bg-red-500/20' : 'bg-slate-800'}`}>
              <AlertTriangle className={`w-5 h-5 ${stats?.unacknowledged_alerts > 0 ? 'text-red-400' : 'text-slate-400'}`} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Unacknowledged</p>
              <p className={`text-2xl font-bold ${stats?.unacknowledged_alerts > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                {stats?.unacknowledged_alerts || 0}
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Create Token Form */}
      {showCreateForm && (
        <Card className="bg-slate-900/50 border-amber-500/30">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Plus className="w-5 h-5 text-amber-400" />
              Create Honey Token
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Name *</label>
                <Input
                  placeholder="e.g., AWS Production Key"
                  value={newToken.name}
                  onChange={(e) => setNewToken({...newToken, name: e.target.value})}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Type *</label>
                <select
                  value={newToken.token_type}
                  onChange={(e) => setNewToken({...newToken, token_type: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white"
                >
                  <option value="api_key">API Key</option>
                  <option value="aws_key">AWS Access Key</option>
                  <option value="database_cred">Database Credential</option>
                  <option value="password">Password</option>
                  <option value="jwt_token">JWT Token</option>
                  <option value="oauth_token">OAuth Token</option>
                  <option value="ssh_key">SSH Key</option>
                  <option value="webhook_url">Webhook URL</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Location</label>
                <Input
                  placeholder="e.g., ~/.aws/credentials"
                  value={newToken.location}
                  onChange={(e) => setNewToken({...newToken, location: e.target.value})}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="text-sm text-slate-400 mb-1 block">Description</label>
                <Input
                  placeholder="Purpose of this honey token"
                  value={newToken.description}
                  onChange={(e) => setNewToken({...newToken, description: e.target.value})}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <Button onClick={handleCreateToken} className="bg-amber-600 hover:bg-amber-500">
                Create Token
              </Button>
              <Button onClick={() => setShowCreateForm(false)} variant="outline">
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tokens List */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-amber-400" />
            Deployed Tokens ({tokens.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {tokens.map((t) => (
              <div key={t.id} className={`p-4 rounded-lg border ${t.is_active ? 'bg-slate-800/50 border-slate-700' : 'bg-slate-900/30 border-slate-800 opacity-60'}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    {getTypeIcon(t.token_type)}
                    <div>
                      <p className="text-white font-medium">{t.name}</p>
                      <p className="text-slate-400 text-xs">{t.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={t.is_active} onCheckedChange={() => handleToggleToken(t.id)} />
                    <Button size="sm" variant="ghost" onClick={() => handleDeleteToken(t.id)}>
                      <Trash2 className="w-4 h-4 text-red-400" />
                    </Button>
                  </div>
                </div>
                
                <div className="flex items-center gap-4 text-xs text-slate-500 mb-2">
                  <span className="flex items-center gap-1">
                    <MapPin className="w-3 h-3" />
                    {t.location || 'Not specified'}
                  </span>
                  <Badge variant="outline" className="text-xs">
                    {t.token_type.replace(/_/g, ' ')}
                  </Badge>
                  {t.access_count > 0 && (
                    <Badge variant="destructive" className="text-xs">
                      {t.access_count} accesses!
                    </Badge>
                  )}
                </div>

                <div className="flex items-center gap-2 mt-2 p-2 bg-slate-900/50 rounded font-mono text-xs">
                  <span className="text-slate-400 flex-1 truncate">
                    {showValues[t.id] ? t.token_value : '••••••••••••••••••••'}
                  </span>
                  <Button size="sm" variant="ghost" onClick={() => setShowValues({...showValues, [t.id]: !showValues[t.id]})}>
                    {showValues[t.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => copyToClipboard(t.token_value)}>
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Recent Accesses */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            Access Alerts
          </CardTitle>
        </CardHeader>
        <CardContent>
          {accesses.length > 0 ? (
            <div className="space-y-2">
              {accesses.map((access) => (
                <div key={access.id} className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      <div>
                        <p className="text-white font-medium">{access.token_name}</p>
                        <p className="text-red-400 text-xs">
                          Accessed from {access.source_ip}
                        </p>
                      </div>
                    </div>
                    <Badge variant="destructive">CRITICAL</Badge>
                  </div>
                  <p className="text-slate-400 text-xs mt-2 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(access.accessed_at).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <CheckCircle className="w-12 h-12 mx-auto mb-4 text-green-400 opacity-50" />
              <p>No honey tokens have been accessed</p>
              <p className="text-sm">This is good - no attacker activity detected</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default HoneyTokensPage;
