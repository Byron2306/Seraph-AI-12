import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  ShieldAlert, Play, Square, FileText, FolderLock, 
  AlertTriangle, Activity, Eye, Trash2, Plus, CheckCircle
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const RansomwarePage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [canaries, setCanaries] = useState(null);
  const [protectedFolders, setProtectedFolders] = useState([]);
  const [newFolder, setNewFolder] = useState('');
  const [loading, setLoading] = useState(false);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStatus();
    fetchCanaries();
    fetchProtectedFolders();
  }, [token]);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API}/ransomware/status`, { headers });
      setStatus(res.data);
    } catch (err) {
      toast.error('Failed to fetch ransomware status');
    }
  };

  const fetchCanaries = async () => {
    try {
      const res = await axios.get(`${API}/ransomware/canaries`, { headers });
      setCanaries(res.data);
    } catch (err) {
      console.error('Failed to fetch canaries');
    }
  };

  const fetchProtectedFolders = async () => {
    try {
      const res = await axios.get(`${API}/ransomware/protected-folders`, { headers });
      setProtectedFolders(res.data);
    } catch (err) {
      console.error('Failed to fetch protected folders');
    }
  };

  const handleStartProtection = async () => {
    setLoading(true);
    try {
      await axios.post(`${API}/ransomware/start`, {}, { headers });
      toast.success('Ransomware protection started');
      fetchStatus();
    } catch (err) {
      toast.error('Failed to start protection');
    } finally {
      setLoading(false);
    }
  };

  const handleStopProtection = async () => {
    setLoading(true);
    try {
      await axios.post(`${API}/ransomware/stop`, {}, { headers });
      toast.info('Ransomware protection stopped');
      fetchStatus();
    } catch (err) {
      toast.error('Failed to stop protection');
    } finally {
      setLoading(false);
    }
  };

  const handleDeployCanaries = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/ransomware/canaries/deploy`, {}, { headers });
      toast.success(`Deployed ${res.data.canaries?.length || 0} canary files`);
      fetchCanaries();
    } catch (err) {
      toast.error('Failed to deploy canaries');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckCanaries = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/ransomware/canaries/check`, {}, { headers });
      if (res.data.triggered_count > 0) {
        toast.error(`ALERT: ${res.data.triggered_count} canaries triggered!`);
      } else {
        toast.success('All canaries intact');
      }
      fetchCanaries();
    } catch (err) {
      toast.error('Failed to check canaries');
    } finally {
      setLoading(false);
    }
  };

  const handleAddFolder = async () => {
    if (!newFolder.trim()) return;
    try {
      await axios.post(`${API}/ransomware/protected-folders`, { path: newFolder.trim() }, { headers });
      toast.success('Folder added to protection');
      setNewFolder('');
      fetchProtectedFolders();
    } catch (err) {
      toast.error('Failed to add folder');
    }
  };

  return (
    <div className="space-y-6" data-testid="ransomware-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-red-400" />
            Ransomware Protection
          </h1>
          <p className="text-slate-400 text-sm mt-1">Canary files, behavioral detection & folder protection</p>
        </div>
        <div className="flex gap-2">
          {status?.protection_active ? (
            <Button onClick={handleStopProtection} variant="destructive" disabled={loading}>
              <Square className="w-4 h-4 mr-2" />
              Stop Protection
            </Button>
          ) : (
            <Button onClick={handleStartProtection} disabled={loading} className="bg-green-600 hover:bg-green-700">
              <Play className="w-4 h-4 mr-2" />
              Start Protection
            </Button>
          )}
        </div>
      </div>

      {/* Status */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-lg border ${status?.protection_active ? 'bg-green-500/10 border-green-500/30' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${status?.protection_active ? 'bg-green-500/20' : 'bg-slate-800'}`}>
              <Activity className={`w-5 h-5 ${status?.protection_active ? 'text-green-400' : 'text-slate-400'}`} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Protection Status</p>
              <p className={`font-bold ${status?.protection_active ? 'text-green-400' : 'text-slate-400'}`}>
                {status?.protection_active ? 'ACTIVE' : 'INACTIVE'}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <FileText className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Active Canaries</p>
              <p className="text-2xl font-bold text-white">{canaries?.active_canaries || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className={`p-4 rounded-lg border ${canaries?.triggered_canaries > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${canaries?.triggered_canaries > 0 ? 'bg-red-500/20' : 'bg-slate-800'}`}>
              <AlertTriangle className={`w-5 h-5 ${canaries?.triggered_canaries > 0 ? 'text-red-400' : 'text-slate-400'}`} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Triggered Canaries</p>
              <p className={`text-2xl font-bold ${canaries?.triggered_canaries > 0 ? 'text-red-400' : 'text-white'}`}>
                {canaries?.triggered_canaries || 0}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <FolderLock className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Protected Folders</p>
              <p className="text-2xl font-bold text-white">{protectedFolders.length}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Canary Management */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-amber-400" />
            Canary Files
          </CardTitle>
          <div className="flex gap-2">
            <Button onClick={handleDeployCanaries} disabled={loading} variant="outline" size="sm">
              <Plus className="w-4 h-4 mr-1" />
              Deploy Canaries
            </Button>
            <Button onClick={handleCheckCanaries} disabled={loading} variant="outline" size="sm">
              <Eye className="w-4 h-4 mr-1" />
              Check Integrity
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {canaries?.canary_locations?.length > 0 ? (
            <div className="space-y-2">
              {canaries.canary_locations.map((path, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-amber-400" />
                    <span className="text-slate-300 font-mono text-sm">{path}</span>
                  </div>
                  <Badge variant="outline" className="text-green-400 border-green-500/30">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    Active
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No canary files deployed</p>
              <p className="text-sm">Click "Deploy Canaries" to create decoy files</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Protected Folders */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <FolderLock className="w-5 h-5 text-blue-400" />
            Protected Folders
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-4">
            <Input
              placeholder="/path/to/protect"
              value={newFolder}
              onChange={(e) => setNewFolder(e.target.value)}
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={handleAddFolder}>
              <Plus className="w-4 h-4 mr-1" />
              Add
            </Button>
          </div>
          
          {protectedFolders.length > 0 ? (
            <div className="space-y-2">
              {protectedFolders.map((folder, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <div className="flex items-center gap-2">
                    <FolderLock className="w-4 h-4 text-blue-400" />
                    <span className="text-slate-300 font-mono text-sm">{folder.path}</span>
                  </div>
                  <Badge variant="outline" className="text-blue-400 border-blue-500/30">Protected</Badge>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <FolderLock className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No folders protected</p>
              <p className="text-sm">Add folders to protect from ransomware</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default RansomwarePage;
