import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  Cloud, Shield, AlertTriangle, CheckCircle, XCircle, RefreshCw,
  Server, Lock, Database, Globe, Activity, TrendingUp, TrendingDown,
  Eye, FileText, Play, Settings, ChevronDown, ChevronRight,
  AlertCircle, Info, Layers, Filter, Download, Search
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const CSPMPage = () => {
  const navigate = useNavigate();
  const { token } = useAuth();
  
  // State
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedProvider, setSelectedProvider] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  
  // Data
  const [posture, setPosture] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [providers, setProviders] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);
  const [resources, setResources] = useState([]);
  const [checks, setChecks] = useState([]);
  const [compliance, setCompliance] = useState({});
  
  // Expanded state
  const [expandedFindings, setExpandedFindings] = useState({});

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, [token]);

  const fetchDashboardData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [dashboardRes, postureRes, providersRes, findingsRes, scansRes] = await Promise.all([
        fetch(`${API_URL}/api/v1/cspm/dashboard`, { headers }),
        fetch(`${API_URL}/api/v1/cspm/posture`, { headers }),
        fetch(`${API_URL}/api/v1/cspm/providers`, { headers }),
        fetch(`${API_URL}/api/v1/cspm/findings?limit=100`, { headers }),
        fetch(`${API_URL}/api/v1/cspm/scans`, { headers })
      ]);

      if (dashboardRes.ok) setDashboard(await dashboardRes.json());
      if (postureRes.ok) setPosture(await postureRes.json());
      if (providersRes.ok) setProviders(await providersRes.json());
      if (findingsRes.ok) {
        const data = await findingsRes.json();
        setFindings(data.findings || []);
      }
      if (scansRes.ok) {
        const data = await scansRes.json();
        setScans(data.scans || []);
      }
    } catch (error) {
      console.error('Failed to fetch CSPM data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchCompliance = async (framework) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/cspm/compliance/${framework}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setCompliance(prev => ({ ...prev, [framework]: data }));
      }
    } catch (error) {
      console.error(`Failed to fetch ${framework} compliance:`, error);
    }
  };

  const startScan = async () => {
    setScanning(true);
    try {
      const response = await fetch(`${API_URL}/api/v1/cspm/scan`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          providers: selectedProvider === 'all' ? null : [selectedProvider]
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data?.status === 'not_configured') {
          toast.error(data?.message || 'No cloud providers configured');
        } else {
          toast.success(`Scan started: ${data.scan_id}`);
        }
        setTimeout(fetchDashboardData, 5000);
      } else {
        toast.error('Failed to start scan');
      }
    } catch (error) {
      toast.error('Error starting scan');
    } finally {
      setScanning(false);
    }
  };

  const configureProvider = async () => {
    const provider = window.prompt('Provider (aws | azure | gcp)', selectedProvider === 'all' ? 'aws' : selectedProvider);
    if (!provider) return;

    const p = provider.trim().toLowerCase();
    const accountId = window.prompt('Account/Subscription/Project ID');
    if (!accountId) return;

    let payload = { provider: p, account_id: accountId };

    if (p === 'aws') {
      const awsAccessKey = window.prompt('AWS Access Key ID');
      const awsSecretKey = window.prompt('AWS Secret Access Key');
      if (!awsAccessKey || !awsSecretKey) {
        toast.error('AWS access key and secret key are required');
        return;
      }
      payload = { ...payload, aws_access_key: awsAccessKey, aws_secret_key: awsSecretKey };
    } else if (p === 'azure') {
      const tenantId = window.prompt('Azure Tenant ID');
      const clientId = window.prompt('Azure Client ID');
      const clientSecret = window.prompt('Azure Client Secret');
      const subscriptionId = window.prompt('Azure Subscription ID', accountId);
      if (!tenantId || !clientId || !clientSecret || !subscriptionId) {
        toast.error('Azure tenant/client/subscription credentials are required');
        return;
      }
      payload = {
        ...payload,
        azure_tenant_id: tenantId,
        azure_client_id: clientId,
        azure_client_secret: clientSecret,
        azure_subscription_id: subscriptionId
      };
    } else if (p === 'gcp') {
      const projectId = window.prompt('GCP Project ID', accountId);
      const keyPath = window.prompt('GCP service account key path (on backend host)');
      if (!projectId || !keyPath) {
        toast.error('GCP project ID and key path are required');
        return;
      }
      payload = {
        ...payload,
        gcp_project_id: projectId,
        gcp_service_account_key_path: keyPath
      };
    } else {
      toast.error('Unsupported provider. Use aws, azure, or gcp.');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/v1/cspm/providers`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        toast.success(`${p.toUpperCase()} provider configured`);
        await fetchDashboardData();
      } else {
        const err = await response.json().catch(() => ({}));
        toast.error(err?.detail || 'Failed to configure provider');
      }
    } catch (error) {
      toast.error('Provider configuration failed');
    }
  };

  const updateFindingStatus = async (findingId, status, reason) => {
    try {
      const response = await fetch(`${API_URL}/api/v1/cspm/findings/${findingId}/status`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status, reason })
      });
      
      if (response.ok) {
        toast.success('Finding status updated');
        fetchDashboardData();
      }
    } catch (error) {
      toast.error('Failed to update finding');
    }
  };

  const exportFindings = async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/cspm/export?format=csv`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cspm-findings-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        toast.success('Findings exported');
      }
    } catch (error) {
      toast.error('Export failed');
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getGradeColor = (grade) => {
    const colors = {
      'A+': 'bg-green-500', 'A': 'bg-green-500', 'A-': 'bg-green-400',
      'B+': 'bg-blue-500', 'B': 'bg-blue-400', 'B-': 'bg-blue-300',
      'C+': 'bg-yellow-500', 'C': 'bg-yellow-400', 'C-': 'bg-yellow-300',
      'D+': 'bg-orange-500', 'D': 'bg-orange-400', 'D-': 'bg-orange-300',
      'F': 'bg-red-500'
    };
    return colors[grade] || 'bg-gray-500';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': 'bg-red-500/20 text-red-400 border-red-500/30',
      'high': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      'medium': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'low': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      'info': 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    };
    return colors[severity?.toLowerCase()] || colors.info;
  };

  const getProviderIcon = (provider) => {
    const icons = {
      'aws': '🔶',
      'azure': '🔷',
      'gcp': '🔴'
    };
    return icons[provider?.toLowerCase()] || '☁️';
  };

  const filteredFindings = findings.filter(f => {
    if (selectedProvider !== 'all' && f.provider?.toLowerCase() !== selectedProvider.toLowerCase()) return false;
    if (severityFilter !== 'all' && f.severity?.toLowerCase() !== severityFilter.toLowerCase()) return false;
    return true;
  });

  const latestFailedScan = scans.find(s => s.status === 'failed');

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <span className="text-gray-400">Loading Cloud Security Posture...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Cloud className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Cloud Security Posture Management</h1>
            <p className="text-gray-400 text-sm">Fleet-wide multi-cloud security visibility</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            onClick={configureProvider}
            className="border-gray-600 text-gray-300 hover:bg-gray-800"
          >
            <Settings className="w-4 h-4 mr-2" />
            Configure Provider
          </Button>
          <Button
            variant="outline"
            onClick={exportFindings}
            className="border-gray-600 text-gray-300 hover:bg-gray-800"
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button
            onClick={startScan}
            disabled={scanning}
            className="bg-cyan-600 hover:bg-cyan-700"
          >
            {scanning ? (
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            {scanning ? 'Scanning...' : 'Start Scan'}
          </Button>
        </div>
      </div>

      {latestFailedScan && (
        <Card className="bg-red-950/20 border-red-900/40 mb-6">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5" />
              <div>
                <p className="text-red-300 font-medium">Latest cloud scan failed ({latestFailedScan.provider?.toUpperCase()})</p>
                <p className="text-red-200/80 text-sm">
                  {latestFailedScan.error_message || 'Authentication or API access failed. Verify provider credentials and cloud read permissions.'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-gray-800 pb-2">
        {['overview', 'findings', 'compliance', 'resources', 'scans'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-t-lg capitalize transition-colors ${
              activeTab === tab
                ? 'bg-cyan-600/20 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Posture Score Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Overall Score */}
            <Card className="bg-[#12121a] border-gray-800">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Security Score</p>
                    <p className={`text-4xl font-bold ${getScoreColor(posture?.overall_score || 0)}`}>
                      {posture?.overall_score?.toFixed(0) || 0}%
                    </p>
                  </div>
                  <div className={`w-16 h-16 rounded-full flex items-center justify-center ${getGradeColor(posture?.grade)}`}>
                    <span className="text-2xl font-bold text-white">{posture?.grade || 'N/A'}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 mt-2">
                  {posture?.trend === 'improving' ? (
                    <TrendingUp className="w-4 h-4 text-green-400" />
                  ) : posture?.trend === 'declining' ? (
                    <TrendingDown className="w-4 h-4 text-red-400" />
                  ) : (
                    <Activity className="w-4 h-4 text-gray-400" />
                  )}
                  <span className="text-xs text-gray-400 capitalize">{posture?.trend || 'stable'}</span>
                </div>
              </CardContent>
            </Card>

            {/* Total Resources */}
            <Card className="bg-[#12121a] border-gray-800">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Cloud Resources</p>
                    <p className="text-3xl font-bold text-white">{posture?.total_resources || 0}</p>
                  </div>
                  <Server className="w-10 h-10 text-blue-400" />
                </div>
                <p className="text-xs text-gray-500 mt-2">Across all cloud accounts</p>
              </CardContent>
            </Card>

            {/* Open Findings */}
            <Card className="bg-[#12121a] border-gray-800">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Open Findings</p>
                    <p className="text-3xl font-bold text-yellow-400">{posture?.open_findings || 0}</p>
                  </div>
                  <AlertTriangle className="w-10 h-10 text-yellow-400" />
                </div>
                <p className="text-xs text-gray-500 mt-2">Requiring attention</p>
              </CardContent>
            </Card>

            {/* Configured Providers */}
            <Card className="bg-[#12121a] border-gray-800">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Cloud Providers</p>
                    <p className="text-3xl font-bold text-purple-400">{providers.length}</p>
                  </div>
                  <Globe className="w-10 h-10 text-purple-400" />
                </div>
                <div className="flex gap-2 mt-2">
                  {providers.map(p => (
                    <span key={p.provider} className="text-lg">{getProviderIcon(p.provider)}</span>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Severity Breakdown & Provider Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Severity Breakdown */}
            <Card className="bg-[#12121a] border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <AlertCircle className="w-5 h-5 text-red-400" />
                  Findings by Severity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {['critical', 'high', 'medium', 'low'].map(severity => {
                    const count = posture?.severity_breakdown?.[severity] || 0;
                    const total = posture?.total_findings || 1;
                    const percentage = (count / total) * 100;
                    return (
                      <div key={severity} className="space-y-1">
                        <div className="flex justify-between text-sm">
                          <span className="capitalize text-gray-300">{severity}</span>
                          <span className="text-gray-400">{count}</span>
                        </div>
                        <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              severity === 'critical' ? 'bg-red-500' :
                              severity === 'high' ? 'bg-orange-500' :
                              severity === 'medium' ? 'bg-yellow-500' :
                              'bg-blue-500'
                            }`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Provider Breakdown */}
            <Card className="bg-[#12121a] border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Cloud className="w-5 h-5 text-cyan-400" />
                  Findings by Provider
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {Object.entries(posture?.provider_breakdown || {}).map(([provider, count]) => (
                    <div key={provider} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{getProviderIcon(provider)}</span>
                        <span className="text-white uppercase font-medium">{provider}</span>
                      </div>
                      <Badge variant="outline" className="text-gray-300 border-gray-600">
                        {count} findings
                      </Badge>
                    </div>
                  ))}
                  {Object.keys(posture?.provider_breakdown || {}).length === 0 && (
                    <p className="text-gray-500 text-center py-4">No providers configured</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Compliance Summary */}
          <Card className="bg-[#12121a] border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-green-400" />
                Compliance Frameworks
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {['CIS', 'NIST', 'SOC2', 'PCI_DSS'].map(framework => {
                  const score = dashboard?.compliance_summary?.[framework] || 0;
                  return (
                    <div
                      key={framework}
                      className="p-4 bg-gray-800/50 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors"
                      onClick={() => {
                        fetchCompliance(framework);
                        setActiveTab('compliance');
                      }}
                    >
                      <p className="text-gray-400 text-sm">{framework.replace('_', '-')}</p>
                      <p className={`text-2xl font-bold ${getScoreColor(score)}`}>
                        {score.toFixed(0)}%
                      </p>
                      <div className="h-1 bg-gray-700 rounded-full mt-2 overflow-hidden">
                        <div
                          className={`h-full ${score >= 80 ? 'bg-green-500' : score >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                          style={{ width: `${score}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Top Risks */}
          <Card className="bg-[#12121a] border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                Top Risks Across Fleet
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(dashboard?.top_risks || []).slice(0, 5).map((risk, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg hover:bg-gray-700/50 transition-colors">
                    <div className="flex items-center gap-3">
                      <span className="text-lg">{getProviderIcon(risk.provider)}</span>
                      <div>
                        <p className="text-white font-medium">{risk.title}</p>
                        <p className="text-gray-400 text-sm">{risk.resource_type} • {risk.affected_resources} resources</p>
                      </div>
                    </div>
                    <Badge className={getSeverityColor(risk.severity)}>
                      {risk.severity}
                    </Badge>
                  </div>
                ))}
                {(!dashboard?.top_risks || dashboard.top_risks.length === 0) && (
                  <p className="text-gray-500 text-center py-4">No critical risks detected</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-4 mb-4">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={selectedProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white"
              >
                <option value="all">All Providers</option>
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
              </select>
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <div className="ml-auto text-gray-400 text-sm">
              {filteredFindings.length} findings
            </div>
          </div>

          {/* Findings List */}
          <div className="space-y-3">
            {filteredFindings.map((finding) => (
              <Card key={finding.id} className="bg-[#12121a] border-gray-800">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <button
                        onClick={() => setExpandedFindings(prev => ({ ...prev, [finding.id]: !prev[finding.id] }))}
                        className="mt-1"
                      >
                        {expandedFindings[finding.id] ? (
                          <ChevronDown className="w-4 h-4 text-gray-400" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-gray-400" />
                        )}
                      </button>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-lg">{getProviderIcon(finding.provider)}</span>
                          <h3 className="text-white font-medium">{finding.title}</h3>
                          <Badge className={getSeverityColor(finding.severity)}>
                            {finding.severity}
                          </Badge>
                        </div>
                        <p className="text-gray-400 text-sm">{finding.description}</p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                          <span>{finding.resource_type}</span>
                          <span>{finding.resource_id}</span>
                          <span>{finding.region}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={
                        finding.status === 'open' ? 'border-yellow-500 text-yellow-400' :
                        finding.status === 'resolved' ? 'border-green-500 text-green-400' :
                        finding.status === 'suppressed' ? 'border-gray-500 text-gray-400' :
                        'border-blue-500 text-blue-400'
                      }>
                        {finding.status}
                      </Badge>
                    </div>
                  </div>
                  
                  {expandedFindings[finding.id] && (
                    <div className="mt-4 pt-4 border-t border-gray-800 space-y-3">
                      <div>
                        <p className="text-gray-400 text-sm font-medium">Recommendation</p>
                        <p className="text-gray-300">{finding.recommendation}</p>
                      </div>
                      {finding.compliance_frameworks && (
                        <div>
                          <p className="text-gray-400 text-sm font-medium">Compliance</p>
                          <div className="flex gap-2 mt-1">
                            {finding.compliance_frameworks.map(f => (
                              <Badge key={f} variant="outline" className="text-gray-300">
                                {f}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => updateFindingStatus(finding.id, 'acknowledged', 'Acknowledged by operator')}
                          className="border-blue-500 text-blue-400 hover:bg-blue-500/20"
                        >
                          Acknowledge
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => updateFindingStatus(finding.id, 'resolved', 'Marked as resolved')}
                          className="border-green-500 text-green-400 hover:bg-green-500/20"
                        >
                          Resolve
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => updateFindingStatus(finding.id, 'suppressed', 'False positive')}
                          className="border-gray-500 text-gray-400 hover:bg-gray-500/20"
                        >
                          Suppress
                        </Button>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
            {filteredFindings.length === 0 && (
              <div className="text-center py-12 text-gray-500">
                <CheckCircle className="w-12 h-12 mx-auto mb-4 text-green-400" />
                <p>No findings match the current filters</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {['CIS', 'NIST', 'SOC2', 'PCI_DSS'].map(framework => (
              <Card key={framework} className="bg-[#12121a] border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center justify-between">
                    <span>{framework.replace('_', '-')} Compliance</span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => fetchCompliance(framework)}
                      className="border-gray-600"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </Button>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {compliance[framework] ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <span className="text-gray-400">Overall Score</span>
                        <span className={`text-2xl font-bold ${getScoreColor(compliance[framework].score)}`}>
                          {compliance[framework].score?.toFixed(0)}%
                        </span>
                      </div>
                      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${
                            compliance[framework].score >= 80 ? 'bg-green-500' :
                            compliance[framework].score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                          }`}
                          style={{ width: `${compliance[framework].score}%` }}
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-4 pt-2">
                        <div className="text-center p-2 bg-gray-800/50 rounded">
                          <p className="text-2xl font-bold text-green-400">{compliance[framework].passed_checks || 0}</p>
                          <p className="text-xs text-gray-400">Passed</p>
                        </div>
                        <div className="text-center p-2 bg-gray-800/50 rounded">
                          <p className="text-2xl font-bold text-red-400">{compliance[framework].failed_checks || 0}</p>
                          <p className="text-xs text-gray-400">Failed</p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      <p>Click refresh to load compliance data</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Resources Tab */}
      {activeTab === 'resources' && (
        <Card className="bg-[#12121a] border-gray-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-purple-400" />
              Discovered Resources
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(dashboard?.resource_counts || {}).map(([type, count]) => (
                <div key={type} className="p-4 bg-gray-800/50 rounded-lg">
                  <p className="text-gray-400 text-sm capitalize">{type.replace('_', ' ')}</p>
                  <p className="text-2xl font-bold text-white">{count}</p>
                </div>
              ))}
            </div>
            {Object.keys(dashboard?.resource_counts || {}).length === 0 && (
              <p className="text-gray-500 text-center py-8">Run a scan to discover resources</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Scans Tab */}
      {activeTab === 'scans' && (
        <div className="space-y-4">
          <Card className="bg-[#12121a] border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                Scan History
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {scans.map(scan => (
                  <div key={scan.scan_id} className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
                    <div className="flex items-center gap-4">
                      <div className={`w-3 h-3 rounded-full ${
                        scan.status === 'completed' ? 'bg-green-500' :
                        scan.status === 'running' ? 'bg-blue-500 animate-pulse' :
                        scan.status === 'failed' ? 'bg-red-500' : 'bg-gray-500'
                      }`} />
                      <div>
                        <p className="text-white font-medium">{scan.scan_id}</p>
                        <p className="text-gray-400 text-sm">
                          {new Date(scan.started_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-sm text-gray-400">{scan.findings_count || 0} findings</p>
                        <p className="text-xs text-gray-500">{scan.resources_scanned || 0} resources</p>
                        {scan.status === 'failed' && scan.error_message && (
                          <p className="text-xs text-red-400 max-w-xs truncate">{scan.error_message}</p>
                        )}
                      </div>
                      <Badge variant="outline" className={
                        scan.status === 'completed' ? 'border-green-500 text-green-400' :
                        scan.status === 'running' ? 'border-blue-500 text-blue-400' :
                        'border-red-500 text-red-400'
                      }>
                        {scan.status}
                      </Badge>
                    </div>
                  </div>
                ))}
                {scans.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    <Search className="w-12 h-12 mx-auto mb-4" />
                    <p>No scans recorded yet</p>
                    <Button onClick={startScan} className="mt-4 bg-cyan-600 hover:bg-cyan-700">
                      Start First Scan
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default CSPMPage;
