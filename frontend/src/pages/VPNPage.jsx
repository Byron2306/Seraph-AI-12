import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Shield, Play, Square, Plus, Trash2, Download,
  Users, Key, Lock, Unlock, Globe, Activity, CheckCircle, XCircle
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API = rawBackendUrl ? `${rawBackendUrl}/api` : '/api';

const VPNPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [peers, setPeers] = useState([]);
  const [newPeerName, setNewPeerName] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedPeerConfig, setSelectedPeerConfig] = useState(null);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStatus();
    fetchPeers();
  }, [token]);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API}/vpn/status`, { headers });
      setStatus(res.data);
    } catch (err) {
      toast.error('Failed to fetch VPN status');
    }
  };

  const fetchPeers = async () => {
    try {
      const res = await axios.get(`${API}/vpn/peers`, { headers });
      setPeers(res.data.peers || []);
    } catch (err) {
      console.error('Failed to fetch peers');
    }
  };

  const handleInitialize = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/vpn/initialize`, {}, { headers });
      if (res.data?.status === 'error') {
        toast.error(res.data?.error || 'Failed to initialize VPN');
      } else {
        toast.success('VPN server initialized');
        await fetchStatus();
      }
    } catch (err) {
      toast.error('Failed to initialize VPN');
    } finally {
      setLoading(false);
    }
  };

  const handleStart = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/vpn/start`, {}, { headers });
      if (res.data?.status === 'error') {
        toast.error(res.data?.error || 'Failed to start VPN');
      } else {
        toast.success('VPN start requested');
        await fetchStatus();
      }
    } catch (err) {
      toast.error('Failed to start VPN');
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/vpn/stop`, {}, { headers });
      if (res.data?.status === 'error') {
        toast.error(res.data?.error || 'Failed to stop VPN');
      } else {
        toast.info('VPN server stopped');
        await fetchStatus();
      }
    } catch (err) {
      toast.error('Failed to stop VPN');
    } finally {
      setLoading(false);
    }
  };

  const handleAddPeer = async () => {
    if (!newPeerName.trim()) return;
    try {
      await axios.post(`${API}/vpn/peers`, { name: newPeerName.trim() }, { headers });
      toast.success('Peer added');
      setNewPeerName('');
      fetchPeers();
    } catch (err) {
      toast.error('Failed to add peer');
    }
  };

  const handleRemovePeer = async (peerId) => {
    try {
      await axios.delete(`${API}/vpn/peers/${peerId}`, { headers });
      toast.success('Peer removed');
      fetchPeers();
    } catch (err) {
      toast.error('Failed to remove peer');
    }
  };

  const handleGetConfig = async (peerId, peerName) => {
    try {
      const res = await axios.get(`${API}/vpn/peers/${peerId}/config`, { headers });
      // Create downloadable file
      const blob = new Blob([res.data], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${peerName || peerId}.conf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success(`Config downloaded: ${peerName}.conf`);
    } catch (err) {
      toast.error('Failed to get peer config');
    }
  };

  const handleToggleKillSwitch = async () => {
    try {
      if (status?.kill_switch?.enabled) {
        await axios.post(`${API}/vpn/kill-switch/disable`, {}, { headers });
        toast.info('Kill switch disabled');
      } else {
        await axios.post(`${API}/vpn/kill-switch/enable`, {}, { headers });
        toast.success('Kill switch enabled');
      }
      fetchStatus();
    } catch (err) {
      toast.error('Failed to toggle kill switch');
    }
  };

  const serverStatus = status?.server?.status || 'unknown';

  return (
    <div className="space-y-6" data-testid="vpn-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-indigo-400" />
            VPN Integration
          </h1>
          <p className="text-slate-400 text-sm mt-1">WireGuard VPN server management</p>
        </div>
        <div className="flex gap-2">
          {serverStatus === 'not_installed' ? (
            <Button onClick={handleInitialize} disabled={loading}>
              <Key className="w-4 h-4 mr-2" />
              Initialize Server
            </Button>
          ) : serverStatus === 'running' ? (
            <Button onClick={handleStop} disabled={loading} variant="destructive">
              <Square className="w-4 h-4 mr-2" />
              Stop Server
            </Button>
          ) : (
            <Button onClick={handleStart} disabled={loading} className="bg-green-600 hover:bg-green-700">
              <Play className="w-4 h-4 mr-2" />
              Start Server
            </Button>
          )}
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-lg border ${serverStatus === 'running' ? 'bg-green-500/10 border-green-500/30' : serverStatus === 'not_installed' ? 'bg-amber-500/10 border-amber-500/30' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${serverStatus === 'running' ? 'bg-green-500/20' : serverStatus === 'not_installed' ? 'bg-amber-500/20' : 'bg-slate-800'}`}>
              {serverStatus === 'running' ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : serverStatus === 'not_installed' ? (
                <XCircle className="w-5 h-5 text-amber-400" />
              ) : (
                <Activity className="w-5 h-5 text-slate-400" />
              )}
            </div>
            <div>
              <p className="text-slate-400 text-sm">Server Status</p>
              <p className={`font-bold capitalize ${serverStatus === 'running' ? 'text-green-400' : serverStatus === 'not_installed' ? 'text-amber-400' : 'text-slate-400'}`}>
                {serverStatus.replace(/_/g, ' ')}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Users className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Connected Peers</p>
              <p className="text-2xl font-bold text-white">{peers.length}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <Globe className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Port</p>
              <p className="text-2xl font-bold text-white">{status?.config?.port || 51820}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className={`p-4 rounded-lg border cursor-pointer ${status?.kill_switch?.enabled ? 'bg-green-500/10 border-green-500/30' : 'bg-slate-900/50 border-slate-800'}`}
          onClick={handleToggleKillSwitch}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${status?.kill_switch?.enabled ? 'bg-green-500/20' : 'bg-slate-800'}`}>
              {status?.kill_switch?.enabled ? 
                <Lock className="w-5 h-5 text-green-400" /> : 
                <Unlock className="w-5 h-5 text-slate-400" />
              }
            </div>
            <div>
              <p className="text-slate-400 text-sm">Kill Switch</p>
              <p className={`font-bold ${status?.kill_switch?.enabled ? 'text-green-400' : 'text-slate-400'}`}>
                {status?.kill_switch?.enabled ? 'Enabled' : 'Disabled'}
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Peer Management */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-blue-400" />
            VPN Peers
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-4">
            <Input
              placeholder="Peer name (e.g., agent-001)"
              value={newPeerName}
              onChange={(e) => setNewPeerName(e.target.value)}
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={handleAddPeer}>
              <Plus className="w-4 h-4 mr-1" />
              Add Peer
            </Button>
          </div>

          {peers.length > 0 ? (
            <div className="space-y-2">
              {peers.map((peer) => (
                <div key={peer.peer_id} 
                  className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded bg-indigo-500/10 flex items-center justify-center">
                      <Users className="w-5 h-5 text-indigo-400" />
                    </div>
                    <div>
                      <p className="text-white font-medium">{peer.name}</p>
                      <p className="text-slate-400 text-sm font-mono">{peer.allowed_ips}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={peer.status === 'active' ? 'text-green-400 border-green-500/30' : 'text-slate-400 border-slate-500/30'}>
                      {peer.status}
                    </Badge>
                    <Button size="sm" variant="outline" onClick={() => handleGetConfig(peer.peer_id, peer.name)} data-testid={`download-peer-${peer.peer_id}`}>
                      <Download className="w-4 h-4" />
                    </Button>
                    <Button size="sm" variant="destructive" onClick={() => handleRemovePeer(peer.peer_id)}>
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No VPN peers configured</p>
              <p className="text-sm">Add peers to allow secure connections</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Peer Config Modal */}
      {selectedPeerConfig && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-amber-400" />
              Peer Configuration
            </CardTitle>
            <Button size="sm" variant="ghost" onClick={() => setSelectedPeerConfig(null)}>
              Close
            </Button>
          </CardHeader>
          <CardContent>
            <pre className="bg-slate-800 p-4 rounded-lg text-green-400 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
              {selectedPeerConfig}
            </pre>
            <p className="text-slate-400 text-sm mt-4">
              Copy this configuration to the client's WireGuard config file.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Installation Note */}
      {serverStatus === 'not_installed' && (
        <Card className="bg-amber-500/10 border-amber-500/30">
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <Shield className="w-8 h-8 text-amber-400" />
              <div>
                <p className="text-amber-400 font-medium">WireGuard Not Installed</p>
                <p className="text-slate-400 text-sm">
                  Install WireGuard on your server: <code className="bg-slate-800 px-2 py-1 rounded text-xs">apt install wireguard</code>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Server Info */}
      {status?.server?.public_key && (
        <Card className="bg-indigo-500/10 border-indigo-500/30">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-indigo-400" />
              Server Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-slate-400 text-sm mb-1">Server Public Key</p>
                <code className="text-xs font-mono text-white bg-slate-800 px-2 py-1 rounded block overflow-x-auto">
                  {status.server.public_key}
                </code>
              </div>
              <div>
                <p className="text-slate-400 text-sm mb-1">VPN Endpoint</p>
                <code className="text-xs font-mono text-white bg-slate-800 px-2 py-1 rounded block">
                  {window.location.hostname}:{status?.config?.port || 51820}
                </code>
              </div>
            </div>
            <div className="mt-4 p-3 bg-slate-800/50 rounded border border-slate-700">
              <p className="text-sm text-slate-300 mb-2">
                <strong>How to connect:</strong>
              </p>
              <ol className="text-xs text-slate-400 list-decimal list-inside space-y-1">
                <li>Add a VPN peer using the form above</li>
                <li>Download the peer configuration file</li>
                <li>Import into WireGuard client on your device</li>
                <li>Connect and verify VPN status</li>
              </ol>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default VPNPage;
