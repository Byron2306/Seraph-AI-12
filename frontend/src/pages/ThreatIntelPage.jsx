import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Database, Search, RefreshCw, Shield, AlertTriangle, 
  Globe, Hash, Link as LinkIcon, CheckCircle, XCircle,
  TrendingUp, Clock, Activity
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const ThreatIntelPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [searchValue, setSearchValue] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [recentMatches, setRecentMatches] = useState([]);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStats();
    fetchRecentMatches();
  }, [token]);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/stats`, { headers });
      setStats(res.data);
    } catch (err) {
      toast.error('Failed to fetch threat intel stats');
    }
  };

  const fetchRecentMatches = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/matches/recent?limit=20`, { headers });
      setRecentMatches(res.data);
    } catch (err) {
      console.error('Failed to fetch recent matches');
    }
  };

  const handleSearch = async () => {
    if (!searchValue.trim()) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API}/threat-intel/check`, 
        { value: searchValue.trim() }, 
        { headers }
      );
      setSearchResult(res.data);
      if (res.data.matched) {
        toast.warning('Threat indicator matched!');
      } else {
        toast.success('No threats found');
      }
    } catch (err) {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateFeeds = async () => {
    setUpdating(true);
    try {
      const res = await axios.post(`${API}/threat-intel/update`, {}, { headers });
      toast.success(`Feeds updated: ${res.data.stats?.total_indicators || 0} indicators`);
      fetchStats();
    } catch (err) {
      toast.error('Failed to update feeds');
    } finally {
      setUpdating(false);
    }
  };

  const getTypeIcon = (type) => {
    switch(type) {
      case 'ip': return <Globe className="w-4 h-4" />;
      case 'domain': return <Globe className="w-4 h-4" />;
      case 'url': return <LinkIcon className="w-4 h-4" />;
      case 'md5': case 'sha1': case 'sha256': return <Hash className="w-4 h-4" />;
      default: return <Database className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6" data-testid="threat-intel-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-blue-400" />
            Threat Intelligence
          </h1>
          <p className="text-slate-400 text-sm mt-1">Real-time IOC lookup against threat feeds</p>
        </div>
        <Button 
          onClick={handleUpdateFeeds} 
          disabled={updating}
          variant="outline"
          className="border-blue-500/50 text-blue-400 hover:bg-blue-500/10"
          data-testid="update-feeds-btn"
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${updating ? 'animate-spin' : ''}`} />
          {updating ? 'Updating...' : 'Update Feeds'}
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} 
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Total Indicators</p>
              <p className="text-2xl font-bold text-white">{stats?.total_indicators?.toLocaleString() || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Activity className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Active Feeds</p>
              <p className="text-2xl font-bold text-white">{stats?.enabled_feeds?.length || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Globe className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">IP Indicators</p>
              <p className="text-2xl font-bold text-white">{stats?.by_type?.ip?.toLocaleString() || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <LinkIcon className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">URL Indicators</p>
              <p className="text-2xl font-bold text-white">{stats?.by_type?.url?.toLocaleString() || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* IOC Search */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-blue-400" />
            IOC Lookup
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter IP, domain, URL, or file hash..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="bg-slate-800 border-slate-700 text-white"
              data-testid="ioc-search-input"
            />
            <Button onClick={handleSearch} disabled={loading} data-testid="ioc-search-btn">
              {loading ? 'Searching...' : 'Search'}
            </Button>
          </div>

          {searchResult && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }} 
              animate={{ opacity: 1, y: 0 }}
              className={`mt-4 p-4 rounded-lg border ${searchResult.matched ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}
            >
              <div className="flex items-center gap-2 mb-2">
                {searchResult.matched ? (
                  <XCircle className="w-5 h-5 text-red-400" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-green-400" />
                )}
                <span className={`font-semibold ${searchResult.matched ? 'text-red-400' : 'text-green-400'}`}>
                  {searchResult.matched ? 'THREAT DETECTED' : 'No Threat Found'}
                </span>
              </div>
              <p className="text-slate-400 text-sm">
                Type: {searchResult.query_type} | Value: {searchResult.query_value}
              </p>
              {searchResult.indicator && (
                <div className="mt-2 p-2 bg-slate-800/50 rounded">
                  <p className="text-white text-sm">Source: {searchResult.indicator.source}</p>
                  <p className="text-slate-400 text-sm">Level: {searchResult.indicator.threat_level}</p>
                  <p className="text-slate-400 text-sm">Confidence: {searchResult.indicator.confidence}%</p>
                </div>
              )}
            </motion.div>
          )}
        </CardContent>
      </Card>

      {/* Feed Status */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-green-400" />
            Feed Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {stats?.by_feed && Object.entries(stats.by_feed).map(([name, data]) => (
              <div key={name} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white font-medium capitalize">{name.replace(/_/g, ' ')}</p>
                    <p className="text-slate-400 text-sm">{data.total?.toLocaleString() || 0} indicators</p>
                  </div>
                  <Badge variant="outline" className="text-green-400 border-green-500/30">Active</Badge>
                </div>
                {data.last_updated && (
                  <p className="text-slate-500 text-xs mt-2 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Last updated: {new Date(data.last_updated).toLocaleString()}
                  </p>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatIntelPage;
