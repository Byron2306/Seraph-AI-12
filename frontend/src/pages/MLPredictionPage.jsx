import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  Brain, 
  Activity, 
  TrendingUp, 
  AlertTriangle, 
  Shield,
  Network,
  Cpu,
  FileText,
  User,
  RefreshCw,
  ChevronRight,
  Target,
  Zap
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');
const PREDICTION_ENDPOINTS = {
  network: '/api/ml/predict/network',
  process: '/api/ml/predict/process',
  file: '/api/ml/predict/file',
  user: '/api/ml/predict/user'
};

const MLPredictionPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [predictionForm, setPredictionForm] = useState({
    type: 'network',
    data: {}
  });

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const [statsRes, predsRes] = await Promise.all([
        fetch(`${API_URL}/api/ml/stats`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/ml/predictions?limit=20`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (statsRes.ok) {
        setStats(await statsRes.json());
      }
      if (predsRes.ok) {
        const data = await predsRes.json();
        setPredictions(data.predictions || []);
      }
    } catch (error) {
      console.error('Failed to fetch ML data:', error);
    } finally {
      setLoading(false);
    }
  };

  const runPrediction = async (type, data) => {
    try {
      const endpoint = PREDICTION_ENDPOINTS[type];
      if (!endpoint) {
        toast.error(`Unsupported prediction type: ${type}`);
        return;
      }

      const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`Prediction complete: ${result.category} (Score: ${result.threat_score})`);
        fetchData();
        return result;
      }
    } catch (error) {
      toast.error('Prediction failed');
    }
  };

  const getRiskColor = (risk) => {
    const colors = {
      critical: 'text-red-400 bg-red-400/10',
      high: 'text-orange-400 bg-orange-400/10',
      medium: 'text-yellow-400 bg-yellow-400/10',
      low: 'text-blue-400 bg-blue-400/10',
      info: 'text-slate-400 bg-slate-400/10'
    };
    return colors[risk] || colors.info;
  };

  const getTypeIcon = (type) => {
    const icons = {
      network: <Network className="w-4 h-4" />,
      process: <Cpu className="w-4 h-4" />,
      file: <FileText className="w-4 h-4" />,
      user: <User className="w-4 h-4" />
    };
    return icons[type] || <Activity className="w-4 h-4" />;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading ML Engine...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6" data-testid="ml-prediction-page">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <Brain className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">ML Threat Prediction</h1>
              <p className="text-slate-400">Machine learning-powered threat detection and prediction</p>
            </div>
          </div>
          <Button onClick={fetchData} variant="outline" className="border-slate-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Total Predictions</p>
                <p className="text-2xl font-bold text-white">{stats?.total_predictions || 0}</p>
              </div>
              <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                <Activity className="w-6 h-6 text-blue-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Avg Threat Score</p>
                <p className="text-2xl font-bold text-white">{stats?.average_threat_score || 0}</p>
              </div>
              <div className="w-12 h-12 rounded-lg bg-orange-500/20 flex items-center justify-center">
                <TrendingUp className="w-6 h-6 text-orange-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Avg Confidence</p>
                <p className="text-2xl font-bold text-white">{((stats?.average_confidence || 0) * 100).toFixed(0)}%</p>
              </div>
              <div className="w-12 h-12 rounded-lg bg-green-500/20 flex items-center justify-center">
                <Target className="w-6 h-6 text-green-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Model Version</p>
                <p className="text-2xl font-bold text-white">{stats?.model_version || '1.0.0'}</p>
              </div>
              <div className="w-12 h-12 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <Brain className="w-6 h-6 text-purple-400" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {['overview', 'predict', 'models'].map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab)}
            className={activeTab === tab ? 'bg-purple-600 hover:bg-purple-700' : 'text-slate-400'}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </Button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Predictions */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Zap className="w-5 h-5 text-purple-400" />
                Recent Predictions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {predictions.length === 0 ? (
                  <p className="text-slate-500 text-center py-8">No predictions yet</p>
                ) : (
                  predictions.slice(0, 8).map((pred) => (
                    <div
                      key={pred.prediction_id}
                      className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <div className="text-slate-400">
                          {getTypeIcon(pred.entity_type)}
                        </div>
                        <div>
                          <p className="text-white text-sm font-medium">{pred.entity_id}</p>
                          <p className="text-slate-500 text-xs">{pred.category}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(pred.risk_level)}`}>
                          {pred.risk_level}
                        </span>
                        <span className="text-slate-400 text-sm font-mono">{pred.threat_score}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* By Category */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
                Predictions by Category
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {Object.entries(stats?.by_category || {}).map(([category, count]) => (
                  <div key={category} className="flex items-center justify-between">
                    <span className="text-slate-300 capitalize">{category.replace(/_/g, ' ')}</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-purple-500 rounded-full"
                          style={{ width: `${Math.min((count / (stats?.total_predictions || 1)) * 100, 100)}%` }}
                        />
                      </div>
                      <span className="text-slate-400 text-sm font-mono w-8">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* By Risk Level */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-400" />
                Predictions by Risk Level
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                {['critical', 'high', 'medium', 'low'].map((level) => (
                  <div key={level} className={`p-4 rounded-lg ${getRiskColor(level)}`}>
                    <p className="text-2xl font-bold">{stats?.by_risk_level?.[level] || 0}</p>
                    <p className="text-sm capitalize">{level}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* By Entity Type */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Cpu className="w-5 h-5 text-blue-400" />
                Predictions by Entity Type
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                {['network', 'process', 'file', 'user'].map((type) => (
                  <div 
                    key={type}
                    className="p-4 bg-slate-800/50 rounded-lg flex items-center gap-3"
                  >
                    {getTypeIcon(type)}
                    <div>
                      <p className="text-white font-bold">{stats?.by_entity_type?.[type] || 0}</p>
                      <p className="text-slate-400 text-sm capitalize">{type}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'predict' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Network Prediction */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-400" />
                Network Traffic Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <label className="text-slate-400 text-sm">Source IP</label>
                  <input
                    type="text"
                    placeholder="192.168.1.100"
                    className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                    id="network-ip"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-sm">Bytes In</label>
                    <input
                      type="number"
                      placeholder="10000"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="network-bytes-in"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Bytes Out</label>
                    <input
                      type="number"
                      placeholder="5000"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="network-bytes-out"
                    />
                  </div>
                </div>
                <Button 
                  className="w-full bg-blue-600 hover:bg-blue-700"
                  onClick={() => runPrediction('network', {
                    source_ip: document.getElementById('network-ip')?.value || '192.168.1.100',
                    bytes_in: parseInt(document.getElementById('network-bytes-in')?.value) || 10000,
                    bytes_out: parseInt(document.getElementById('network-bytes-out')?.value) || 5000
                  })}
                >
                  Analyze Network Traffic
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Process Prediction */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Cpu className="w-5 h-5 text-green-400" />
                Process Behavior Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <label className="text-slate-400 text-sm">Process Name</label>
                  <input
                    type="text"
                    placeholder="suspicious.exe"
                    className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                    id="process-name"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-sm">CPU Usage %</label>
                    <input
                      type="number"
                      placeholder="50"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="process-cpu"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Memory MB</label>
                    <input
                      type="number"
                      placeholder="200"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="process-mem"
                    />
                  </div>
                </div>
                <Button 
                  className="w-full bg-green-600 hover:bg-green-700"
                  onClick={() => runPrediction('process', {
                    process_name: document.getElementById('process-name')?.value || 'suspicious.exe',
                    cpu_usage: parseFloat(document.getElementById('process-cpu')?.value) || 50,
                    memory_usage: parseFloat(document.getElementById('process-mem')?.value) || 200
                  })}
                >
                  Analyze Process
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* File Prediction */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-orange-400" />
                File Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <label className="text-slate-400 text-sm">Filename</label>
                  <input
                    type="text"
                    placeholder="malware.exe"
                    className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                    id="file-name"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-sm">Entropy</label>
                    <input
                      type="number"
                      step="0.1"
                      placeholder="7.5"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="file-entropy"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Size (KB)</label>
                    <input
                      type="number"
                      placeholder="1024"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="file-size"
                    />
                  </div>
                </div>
                <Button 
                  className="w-full bg-orange-600 hover:bg-orange-700"
                  onClick={() => runPrediction('file', {
                    filename: document.getElementById('file-name')?.value || 'malware.exe',
                    entropy: parseFloat(document.getElementById('file-entropy')?.value) || 7.5,
                    size: parseInt(document.getElementById('file-size')?.value) * 1024 || 1024000
                  })}
                >
                  Analyze File
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* User Prediction (UEBA) */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <User className="w-5 h-5 text-purple-400" />
                User Behavior Analysis (UEBA)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <label className="text-slate-400 text-sm">Username</label>
                  <input
                    type="text"
                    placeholder="john.doe"
                    className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                    id="user-name"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-sm">Login Hour</label>
                    <input
                      type="number"
                      min="0"
                      max="23"
                      placeholder="3"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="user-hour"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-sm">Failed Logins</label>
                    <input
                      type="number"
                      placeholder="5"
                      className="w-full mt-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white"
                      id="user-failures"
                    />
                  </div>
                </div>
                <Button 
                  className="w-full bg-purple-600 hover:bg-purple-700"
                  onClick={() => runPrediction('user', {
                    user_id: 'user_' + Date.now(),
                    username: document.getElementById('user-name')?.value || 'john.doe',
                    login_hour: parseInt(document.getElementById('user-hour')?.value) || 3,
                    failed_logins: parseInt(document.getElementById('user-failures')?.value) || 5
                  })}
                >
                  Analyze User Behavior
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'models' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Model Information */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Brain className="w-5 h-5 text-purple-400" />
                Active ML Models
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(stats?.models || {}).map(([name, desc]) => (
                  <div key={name} className="p-4 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-medium capitalize">{name.replace(/_/g, ' ')}</span>
                      <span className="px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">Active</span>
                    </div>
                    <p className="text-slate-400 text-sm">{desc}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Available Categories */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
                Threat Categories
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2">
                {(stats?.available_categories || []).map((cat) => (
                  <div key={cat} className="p-3 bg-slate-800/50 rounded-lg">
                    <span className="text-slate-300 text-sm capitalize">{cat.replace(/_/g, ' ')}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Risk Levels */}
          <Card className="bg-slate-900/50 border-slate-800 lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-400" />
                Risk Level Thresholds
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-5 gap-4">
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-center">
                  <p className="text-red-400 font-bold text-lg">Critical</p>
                  <p className="text-slate-400 text-sm">Score ≥ 80</p>
                </div>
                <div className="p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg text-center">
                  <p className="text-orange-400 font-bold text-lg">High</p>
                  <p className="text-slate-400 text-sm">Score ≥ 60</p>
                </div>
                <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-center">
                  <p className="text-yellow-400 font-bold text-lg">Medium</p>
                  <p className="text-slate-400 text-sm">Score ≥ 40</p>
                </div>
                <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg text-center">
                  <p className="text-blue-400 font-bold text-lg">Low</p>
                  <p className="text-slate-400 text-sm">Score ≥ 20</p>
                </div>
                <div className="p-4 bg-slate-500/10 border border-slate-500/30 rounded-lg text-center">
                  <p className="text-slate-400 font-bold text-lg">Info</p>
                  <p className="text-slate-400 text-sm">Score &lt; 20</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default MLPredictionPage;
