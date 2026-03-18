import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  BarChart3, 
  Activity, 
  PieChart, 
  Map,
  RefreshCw,
  Download,
  Settings,
  CheckCircle,
  XCircle,
  Database,
  Play,
  Eye
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = (!envBackendUrl || envBackendUrl.includes('localhost')) ? '/api' : `${envBackendUrl}/api`;

// Simple chart components for live preview
const MetricCard = ({ title, value }) => (
  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
    <p className="text-3xl font-bold text-white">{value}</p>
    <p className="text-slate-400 text-sm">{title}</p>
  </div>
);

const PieChartSimple = ({ data, title }) => {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const colors = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4'];
  
  return (
    <div className="bg-slate-800/50 rounded-lg p-4">
      <p className="text-white font-medium mb-3">{title}</p>
      <div className="space-y-2">
        {data.slice(0, 5).map((item, idx) => (
          <div key={idx} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: colors[idx % colors.length] }}></div>
            <span className="text-slate-300 text-sm flex-1">{item.label}</span>
            <span className="text-slate-400 text-sm">{item.value} ({total > 0 ? Math.round(item.value / total * 100) : 0}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const BarChartSimple = ({ data, title }) => {
  const maxValue = Math.max(...data.map(d => d.value), 1);
  
  return (
    <div className="bg-slate-800/50 rounded-lg p-4">
      <p className="text-white font-medium mb-3">{title}</p>
      <div className="space-y-2">
        {data.slice(0, 6).map((item, idx) => (
          <div key={idx}>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-slate-300 truncate">{item.label}</span>
              <span className="text-slate-400">{item.value}</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div 
                className="h-full bg-pink-500 rounded-full transition-all" 
                style={{ width: `${(item.value / maxValue) * 100}%` }}
              ></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const LineChartSimple = ({ data, title }) => {
  const maxValue = Math.max(...data.map(d => d.value), 1);
  
  return (
    <div className="bg-slate-800/50 rounded-lg p-4">
      <p className="text-white font-medium mb-3">{title}</p>
      <div className="flex items-end gap-1 h-24">
        {data.map((item, idx) => (
          <div key={idx} className="flex-1 flex flex-col items-center">
            <div 
              className="w-full bg-pink-500/80 rounded-t transition-all"
              style={{ height: `${(item.value / maxValue) * 100}%`, minHeight: '4px' }}
            ></div>
            <span className="text-slate-500 text-xs mt-1">{item.date?.slice(5) || idx}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const TableSimple = ({ data, title }) => (
  <div className="bg-slate-800/50 rounded-lg p-4">
    <p className="text-white font-medium mb-3">{title}</p>
    <div className="space-y-2 max-h-48 overflow-y-auto">
      {(data || []).slice(0, 5).map((row, idx) => (
        <div key={idx} className="text-xs text-slate-300 p-2 bg-slate-700/50 rounded">
          {Object.entries(row).slice(0, 3).map(([key, val]) => (
            <span key={key} className="mr-2">
              <span className="text-slate-500">{key}:</span> {String(val).slice(0, 30)}
            </span>
          ))}
        </div>
      ))}
    </div>
  </div>
);

const KibanaDashboardsPage = () => {
  const { token } = useAuth();
  const [dashboards, setDashboards] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedDashboard, setSelectedDashboard] = useState(null);
  const [liveData, setLiveData] = useState(null);
  const [loadingLive, setLoadingLive] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboards');

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const [dashboardsRes, statusRes] = await Promise.all([
        fetch(`${API_URL}/kibana/dashboards`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/kibana/status`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (dashboardsRes.ok) {
        const data = await dashboardsRes.json();
        setDashboards(data.dashboards || []);
      }
      if (statusRes.ok) {
        setStatus(await statusRes.json());
      }
    } catch (error) {
      console.error('Failed to fetch Kibana data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchDashboardDetails = async (dashboardId) => {
    try {
      const response = await fetch(`${API_URL}/kibana/dashboards/${dashboardId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setSelectedDashboard({ id: dashboardId, ...data });
      }
    } catch (error) {
      console.error('Failed to fetch dashboard details:', error);
    }
  };

  const fetchLiveData = async (dashboardId) => {
    setLoadingLive(true);
    try {
      const response = await fetch(`${API_URL}/kibana/live-data/${dashboardId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setLiveData(data);
        toast.success('Live data loaded');
      }
    } catch (error) {
      toast.error('Failed to fetch live data');
    } finally {
      setLoadingLive(false);
    }
  };

  const exportDashboard = async (dashboardId) => {
    try {
      const response = await fetch(`${API_URL}/kibana/dashboards/${dashboardId}/export`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${dashboardId}.ndjson`;
        a.click();
        toast.success('Dashboard exported');
      }
    } catch (error) {
      toast.error('Failed to export dashboard');
    }
  };

  const exportAllDashboards = async () => {
    try {
      const response = await fetch(`${API_URL}/kibana/export-all`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'all-security-dashboards.ndjson';
        a.click();
        toast.success('All dashboards exported');
      }
    } catch (error) {
      toast.error('Failed to export dashboards');
    }
  };

  const setupIndexPattern = async () => {
    try {
      const response = await fetch(`${API_URL}/kibana/setup-index`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          toast.success('Index pattern created successfully');
        } else {
          toast.error(result.error || 'Failed to create index pattern');
        }
      }
    } catch (error) {
      toast.error('Failed to setup index pattern');
    }
  };

  const getDashboardIcon = (id) => {
    const icons = {
      'security-overview': <Activity className="w-5 h-5" />,
      'threat-intelligence': <Database className="w-5 h-5" />,
      'geo-threat-map': <Map className="w-5 h-5" />,
      'mitre-attack': <BarChart3 className="w-5 h-5" />,
      'endpoint-security': <Settings className="w-5 h-5" />,
      'playbook-analytics': <PieChart className="w-5 h-5" />
    };
    return icons[id] || <BarChart3 className="w-5 h-5" />;
  };

  const getPanelTypeColor = (type) => {
    const colors = {
      metric: 'bg-blue-500/20 text-blue-400',
      pie: 'bg-purple-500/20 text-purple-400',
      bar: 'bg-green-500/20 text-green-400',
      line: 'bg-orange-500/20 text-orange-400',
      table: 'bg-cyan-500/20 text-cyan-400',
      map: 'bg-red-500/20 text-red-400',
      heatmap: 'bg-yellow-500/20 text-yellow-400'
    };
    return colors[type] || 'bg-slate-500/20 text-slate-400';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading Kibana Dashboards...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6" data-testid="kibana-dashboards-page">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-pink-500/20 flex items-center justify-center">
              <BarChart3 className="w-6 h-6 text-pink-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Kibana Dashboards</h1>
              <p className="text-slate-400">Pre-built security dashboards for Elasticsearch/Kibana</p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button onClick={exportAllDashboards} variant="outline" className="border-slate-700">
              <Download className="w-4 h-4 mr-2" />
              Export All
            </Button>
            <Button onClick={fetchData} variant="outline" className="border-slate-700">
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      {/* Status Card */}
      <Card className="bg-slate-900/50 border-slate-800 mb-6">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                {status?.configured ? (
                  <CheckCircle className="w-5 h-5 text-green-400" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-400" />
                )}
                <span className="text-slate-300">
                  {status?.configured ? 'Kibana Connected' : 'Kibana Not Configured'}
                </span>
              </div>
              <div className="text-slate-500 text-sm">
                {status?.dashboards_available || 0} dashboards available
              </div>
            </div>
            <Button 
              onClick={setupIndexPattern} 
              className="bg-pink-600 hover:bg-pink-700"
              disabled={!status?.configured}
            >
              <Database className="w-4 h-4 mr-2" />
              Setup Index Pattern
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {['dashboards', 'details', 'live'].map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab)}
            className={activeTab === tab ? 'bg-pink-600 hover:bg-pink-700' : 'text-slate-400'}
          >
            {tab === 'live' ? (
              <>
                <Play className="w-4 h-4 mr-1" />
                Live Preview
              </>
            ) : (
              tab.charAt(0).toUpperCase() + tab.slice(1)
            )}
          </Button>
        ))}
      </div>

      {activeTab === 'dashboards' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {dashboards.map((dashboard) => (
            <Card 
              key={dashboard.id} 
              className="bg-slate-900/50 border-slate-800 cursor-pointer hover:border-pink-500/50 transition-colors"
              onClick={() => {
                fetchDashboardDetails(dashboard.id);
                setActiveTab('details');
              }}
            >
              <CardContent className="p-6">
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-10 h-10 rounded-lg bg-pink-500/20 flex items-center justify-center text-pink-400">
                    {getDashboardIcon(dashboard.id)}
                  </div>
                  <div className="flex-1">
                    <h3 className="text-white font-medium">{dashboard.title}</h3>
                    <p className="text-slate-500 text-xs">{dashboard.panel_count} panels</p>
                  </div>
                </div>
                <p className="text-slate-400 text-sm mb-4">{dashboard.description}</p>
                <div className="flex gap-2">
                  <Button 
                    size="sm" 
                    variant="outline" 
                    className="border-slate-700 text-slate-300"
                    onClick={(e) => {
                      e.stopPropagation();
                      exportDashboard(dashboard.id);
                    }}
                  >
                    <Download className="w-3 h-3 mr-1" />
                    Export
                  </Button>
                  <Button 
                    size="sm" 
                    className="bg-pink-600 hover:bg-pink-700"
                    onClick={(e) => {
                      e.stopPropagation();
                      fetchLiveData(dashboard.id);
                      setActiveTab('live');
                    }}
                  >
                    <Eye className="w-3 h-3 mr-1" />
                    Preview
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {activeTab === 'details' && selectedDashboard && (
        <div className="space-y-6">
          {/* Dashboard Overview */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                {getDashboardIcon(selectedDashboard.id)}
                {selectedDashboard.title}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-slate-400 mb-4">{selectedDashboard.description}</p>
              <Button onClick={() => exportDashboard(selectedDashboard.id)} className="bg-pink-600 hover:bg-pink-700">
                <Download className="w-4 h-4 mr-2" />
                Export Dashboard
              </Button>
            </CardContent>
          </Card>

          {/* Panels */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Dashboard Panels</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(selectedDashboard.panels || []).map((panel, idx) => (
                  <div key={idx} className="p-4 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-medium">{panel.title}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getPanelTypeColor(panel.type)}`}>
                        {panel.type}
                      </span>
                    </div>
                    {panel.field && (
                      <p className="text-slate-500 text-xs">Field: {panel.field}</p>
                    )}
                    {panel.timeRange && (
                      <p className="text-slate-500 text-xs">Time: {panel.timeRange}</p>
                    )}
                    {panel.columns && (
                      <p className="text-slate-500 text-xs">Columns: {panel.columns.join(', ')}</p>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Back Button */}
          <Button 
            variant="outline" 
            className="border-slate-700"
            onClick={() => setActiveTab('dashboards')}
          >
            Back to Dashboards
          </Button>
        </div>
      )}

      {activeTab === 'details' && !selectedDashboard && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-8 text-center">
            <p className="text-slate-500">Select a dashboard to view details</p>
          </CardContent>
        </Card>
      )}

      {activeTab === 'live' && (
        <div className="space-y-6">
          {/* Dashboard Selector for Live Preview */}
          {!liveData && !loadingLive && (
            <Card className="bg-slate-900/50 border-slate-800">
              <CardContent className="p-6">
                <h3 className="text-white font-medium mb-4">Select a Dashboard for Live Preview</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {dashboards.map((dashboard) => (
                    <Button
                      key={dashboard.id}
                      variant="outline"
                      className="border-slate-700 justify-start"
                      onClick={() => fetchLiveData(dashboard.id)}
                    >
                      {getDashboardIcon(dashboard.id)}
                      <span className="ml-2 truncate">{dashboard.title}</span>
                    </Button>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {loadingLive && (
            <Card className="bg-slate-900/50 border-slate-800">
              <CardContent className="p-8 text-center">
                <RefreshCw className="w-8 h-8 animate-spin text-pink-400 mx-auto mb-4" />
                <p className="text-slate-400">Loading live dashboard data...</p>
              </CardContent>
            </Card>
          )}

          {liveData && !loadingLive && (
            <>
              {/* Live Dashboard Header */}
              <Card className="bg-slate-900/50 border-slate-800">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-pink-500/20 flex items-center justify-center text-pink-400">
                        <Activity className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium">{liveData.title}</h3>
                        <p className="text-slate-500 text-xs">
                          Generated: {new Date(liveData.generated_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="outline" 
                        className="border-slate-700"
                        onClick={() => fetchLiveData(liveData.dashboard_id)}
                      >
                        <RefreshCw className="w-4 h-4 mr-1" />
                        Refresh
                      </Button>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="text-slate-400"
                        onClick={() => setLiveData(null)}
                      >
                        Change Dashboard
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Live Dashboard Panels */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {liveData.panels.map((panel, idx) => {
                  if (panel.type === 'metric' && panel.data) {
                    return <MetricCard key={idx} title={panel.title} value={panel.data.value || 0} />;
                  }
                  if (panel.type === 'pie' && panel.data?.length > 0) {
                    return <PieChartSimple key={idx} title={panel.title} data={panel.data} />;
                  }
                  if (panel.type === 'bar' && panel.data?.length > 0) {
                    return <BarChartSimple key={idx} title={panel.title} data={panel.data} />;
                  }
                  if (panel.type === 'line' && panel.data?.length > 0) {
                    return <LineChartSimple key={idx} title={panel.title} data={panel.data} />;
                  }
                  if (panel.type === 'table' && panel.data) {
                    return <TableSimple key={idx} title={panel.title} data={panel.data} />;
                  }
                  if (panel.type === 'map' && panel.data) {
                    return (
                      <div key={idx} className="bg-slate-800/50 rounded-lg p-4">
                        <p className="text-white font-medium mb-3">{panel.title}</p>
                        <div className="space-y-2">
                          {panel.data.map((point, i) => (
                            <div key={i} className="flex justify-between text-sm">
                              <span className="text-slate-300">{point.country}</span>
                              <span className="text-pink-400">{point.count} attacks</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  }
                  if (panel.type === 'heatmap' && panel.data) {
                    return (
                      <div key={idx} className="bg-slate-800/50 rounded-lg p-4 md:col-span-2">
                        <p className="text-white font-medium mb-3">{panel.title}</p>
                        <div className="grid grid-cols-6 gap-1 text-xs">
                          <div></div>
                          {panel.data.techniques?.slice(0, 5).map((t, i) => (
                            <div key={i} className="text-slate-500 text-center truncate">{t}</div>
                          ))}
                          {panel.data.tactics?.slice(0, 5).map((tactic, ti) => (
                            <>
                              <div key={`t-${ti}`} className="text-slate-400 truncate">{tactic}</div>
                              {panel.data.values?.[ti]?.slice(0, 5).map((val, vi) => (
                                <div 
                                  key={`v-${ti}-${vi}`}
                                  className="h-6 rounded flex items-center justify-center text-white"
                                  style={{ 
                                    backgroundColor: `rgba(236, 72, 153, ${Math.min(val / 15, 1)})` 
                                  }}
                                >
                                  {val}
                                </div>
                              ))}
                            </>
                          ))}
                        </div>
                      </div>
                    );
                  }
                  return (
                    <div key={idx} className="bg-slate-800/50 rounded-lg p-4">
                      <p className="text-white font-medium">{panel.title}</p>
                      <p className="text-slate-500 text-sm">Type: {panel.type}</p>
                      <p className="text-slate-600 text-xs mt-2">
                        {panel.error || 'No data available'}
                      </p>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default KibanaDashboardsPage;
