import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  Mail,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Lock,
  Unlock,
  User,
  Users,
  Globe,
  FileText,
  Search,
  Plus,
  Trash2,
  Eye,
  Link2,
  Inbox,
  Send
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const EmailProtectionPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [quarantine, setQuarantine] = useState([]);
  const [protectedUsers, setProtectedUsers] = useState({ executives: [], vip_users: [] });
  const [blockedSenders, setBlockedSenders] = useState([]);
  const [trustedDomains, setTrustedDomains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Analysis forms
  const [emailForm, setEmailForm] = useState({
    sender: '',
    recipient: '',
    subject: '',
    body: ''
  });
  const [urlInput, setUrlInput] = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  
  // Add forms
  const [newProtectedUser, setNewProtectedUser] = useState({ email: '', name: '', title: '', user_type: 'vip' });
  const [newBlockedSender, setNewBlockedSender] = useState('');
  const [newTrustedDomain, setNewTrustedDomain] = useState('');

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [statsRes, quarantineRes, protectedRes, blockedRes, trustedRes] = await Promise.all([
        fetch(`${API_URL}/api/email-protection/stats`, { headers }),
        fetch(`${API_URL}/api/email-protection/quarantine`, { headers }),
        fetch(`${API_URL}/api/email-protection/protected-users`, { headers }),
        fetch(`${API_URL}/api/email-protection/blocked-senders`, { headers }),
        fetch(`${API_URL}/api/email-protection/trusted-domains`, { headers })
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (quarantineRes.ok) {
        const data = await quarantineRes.json();
        setQuarantine(data.quarantine || []);
      }
      if (protectedRes.ok) setProtectedUsers(await protectedRes.json());
      if (blockedRes.ok) {
        const data = await blockedRes.json();
        setBlockedSenders(data.blocked_senders || []);
      }
      if (trustedRes.ok) {
        const data = await trustedRes.json();
        setTrustedDomains(data.trusted_domains || []);
      }
    } catch (error) {
      console.error('Failed to fetch email protection data:', error);
    } finally {
      setLoading(false);
    }
  };

  const analyzeEmail = async () => {
    if (!emailForm.sender || !emailForm.recipient || !emailForm.subject) {
      toast.error('Please fill in sender, recipient, and subject');
      return;
    }

    setAnalyzing(true);
    try {
      const response = await fetch(`${API_URL}/api/email-protection/analyze`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(emailForm)
      });

      if (response.ok) {
        const result = await response.json();
        setAnalysisResult(result);
        toast.success(`Email analyzed: ${result.overall_risk} risk`);
      } else {
        toast.error('Failed to analyze email');
      }
    } catch (error) {
      toast.error('Error analyzing email');
    } finally {
      setAnalyzing(false);
    }
  };

  const analyzeURL = async () => {
    if (!urlInput.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    setAnalyzing(true);
    try {
      const response = await fetch(`${API_URL}/api/email-protection/analyze-url`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: urlInput })
      });

      if (response.ok) {
        const result = await response.json();
        setAnalysisResult(result);
        toast.success(`URL analyzed: ${result.risk_level} risk`);
      }
    } catch (error) {
      toast.error('Error analyzing URL');
    } finally {
      setAnalyzing(false);
    }
  };

  const checkAuthentication = async () => {
    if (!domainInput.trim()) {
      toast.error('Please enter a domain');
      return;
    }

    setAnalyzing(true);
    try {
      const response = await fetch(`${API_URL}/api/email-protection/check-authentication`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domain: domainInput })
      });

      if (response.ok) {
        const result = await response.json();
        setAnalysisResult(result);
        toast.success('Domain authentication checked');
      }
    } catch (error) {
      toast.error('Error checking authentication');
    } finally {
      setAnalyzing(false);
    }
  };

  const releaseFromQuarantine = async (assessmentId) => {
    try {
      const response = await fetch(`${API_URL}/api/email-protection/quarantine/${assessmentId}/release`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Email released from quarantine');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to release email');
    }
  };

  const addProtectedUser = async () => {
    if (!newProtectedUser.email) {
      toast.error('Email is required');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/email-protection/protected-users`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newProtectedUser)
      });

      if (response.ok) {
        toast.success('Protected user added');
        setNewProtectedUser({ email: '', name: '', title: '', user_type: 'vip' });
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to add protected user');
    }
  };

  const addBlockedSender = async () => {
    if (!newBlockedSender.trim()) return;

    try {
      const response = await fetch(`${API_URL}/api/email-protection/blocked-senders`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sender: newBlockedSender })
      });

      if (response.ok) {
        toast.success('Sender blocked');
        setNewBlockedSender('');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to block sender');
    }
  };

  const removeBlockedSender = async (sender) => {
    try {
      const response = await fetch(`${API_URL}/api/email-protection/blocked-senders/${encodeURIComponent(sender)}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Sender unblocked');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to unblock sender');
    }
  };

  const addTrustedDomain = async () => {
    if (!newTrustedDomain.trim()) return;

    try {
      const response = await fetch(`${API_URL}/api/email-protection/trusted-domains`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domain: newTrustedDomain })
      });

      if (response.ok) {
        toast.success('Domain added to trusted list');
        setNewTrustedDomain('');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to add trusted domain');
    }
  };

  const getRiskBadge = (risk) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      safe: 'bg-green-500/20 text-green-400 border-green-500/30'
    };
    return colors[risk] || colors.safe;
  };

  const getAuthBadge = (result) => {
    if (result === 'pass') return 'bg-green-500/20 text-green-400';
    if (result === 'fail' || result === 'softfail') return 'bg-red-500/20 text-red-400';
    return 'bg-yellow-500/20 text-yellow-400';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading Email Protection...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Mail className="h-8 w-8 text-blue-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">Email Protection</h1>
              <p className="text-slate-400">Advanced email security with SPF/DKIM/DMARC, phishing detection, and DLP</p>
            </div>
          </div>
          <Button onClick={fetchData} variant="outline" className="border-slate-700">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/20">
                  <FileText className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Total Assessed</p>
                  <p className="text-2xl font-bold text-white">{stats?.total_assessed || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/20">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Quarantined</p>
                  <p className="text-2xl font-bold text-white">{stats?.quarantined || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/20">
                  <Users className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Protected Users</p>
                  <p className="text-2xl font-bold text-white">{(stats?.protected_executives || 0) + (stats?.vip_users || 0)}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-orange-500/20">
                  <XCircle className="h-5 w-5 text-orange-400" />
                </div>
                <div>
                  <p className="text-sm text-slate-400">Blocked Senders</p>
                  <p className="text-2xl font-bold text-white">{stats?.blocked_senders || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-slate-800 pb-2">
          {['overview', 'analyze', 'quarantine', 'protection', 'blocklist'].map((tab) => (
            <Button
              key={tab}
              variant={activeTab === tab ? 'default' : 'ghost'}
              onClick={() => setActiveTab(tab)}
              className={activeTab === tab ? 'bg-blue-600' : 'text-slate-400'}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </Button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Features */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="h-5 w-5 text-green-400" />
                  Protection Features
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {stats?.features && Object.entries(stats.features).map(([feature, enabled]) => (
                  <div key={feature} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                    <span className="text-slate-300">{feature.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                    {enabled ? (
                      <Badge className="bg-green-500/20 text-green-400">Enabled</Badge>
                    ) : (
                      <Badge className="bg-slate-500/20 text-slate-400">Disabled</Badge>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Threat Distribution */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  Threat Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {stats?.by_threat_type && Object.entries(stats.by_threat_type).map(([threat, count]) => (
                  <div key={threat} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
                    <span className="text-slate-300">{threat.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                    <Badge className="bg-red-500/20 text-red-400">{count}</Badge>
                  </div>
                ))}
                {(!stats?.by_threat_type || Object.keys(stats.by_threat_type).length === 0) && (
                  <p className="text-slate-500 text-center py-4">No threats detected yet</p>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'analyze' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Email Analysis */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Mail className="h-5 w-5 text-blue-400" />
                  Analyze Email
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <input
                  type="email"
                  placeholder="Sender email"
                  value={emailForm.sender}
                  onChange={(e) => setEmailForm({ ...emailForm, sender: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <input
                  type="email"
                  placeholder="Recipient email"
                  value={emailForm.recipient}
                  onChange={(e) => setEmailForm({ ...emailForm, recipient: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <input
                  type="text"
                  placeholder="Subject"
                  value={emailForm.subject}
                  onChange={(e) => setEmailForm({ ...emailForm, subject: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <textarea
                  placeholder="Email body"
                  value={emailForm.body}
                  onChange={(e) => setEmailForm({ ...emailForm, body: e.target.value })}
                  rows={4}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <Button onClick={analyzeEmail} disabled={analyzing} className="w-full bg-blue-600 hover:bg-blue-700">
                  {analyzing ? 'Analyzing...' : 'Analyze Email'}
                </Button>
              </CardContent>
            </Card>

            {/* URL & Domain Analysis */}
            <div className="space-y-6">
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <Link2 className="h-5 w-5 text-purple-400" />
                    Analyze URL
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <input
                    type="url"
                    placeholder="https://example.com/path"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                  />
                  <Button onClick={analyzeURL} disabled={analyzing} className="w-full bg-purple-600 hover:bg-purple-700">
                    Analyze URL
                  </Button>
                </CardContent>
              </Card>

              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <Globe className="h-5 w-5 text-green-400" />
                    Check Domain Authentication
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <input
                    type="text"
                    placeholder="example.com"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                  />
                  <Button onClick={checkAuthentication} disabled={analyzing} className="w-full bg-green-600 hover:bg-green-700">
                    Check SPF/DKIM/DMARC
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Analysis Results */}
            {analysisResult && (
              <Card className="bg-slate-900 border-slate-800 lg:col-span-2">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <Eye className="h-5 w-5 text-cyan-400" />
                    Analysis Results
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="bg-slate-800 p-4 rounded-lg overflow-auto text-sm text-slate-300 max-h-96">
                    {JSON.stringify(analysisResult, null, 2)}
                  </pre>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {activeTab === 'quarantine' && (
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Inbox className="h-5 w-5 text-red-400" />
                Quarantined Emails ({quarantine.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {quarantine.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No emails in quarantine</p>
              ) : (
                <div className="space-y-3">
                  {quarantine.map((item, index) => (
                    <div key={index} className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white font-medium">{item.assessment?.subject || 'No subject'}</span>
                        <Badge className={getRiskBadge(item.assessment?.overall_risk)}>
                          {item.assessment?.overall_risk || 'unknown'}
                        </Badge>
                      </div>
                      <div className="text-sm text-slate-400 mb-2">
                        From: {item.assessment?.sender} → {item.assessment?.recipient}
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-500">{item.quarantined_at}</span>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => releaseFromQuarantine(item.assessment?.assessment_id)}
                          className="border-green-500/50 text-green-400 hover:bg-green-500/20"
                        >
                          <Unlock className="h-4 w-4 mr-1" />
                          Release
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'protection' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Add Protected User */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <User className="h-5 w-5 text-purple-400" />
                  Add Protected User
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <input
                  type="email"
                  placeholder="Email address"
                  value={newProtectedUser.email}
                  onChange={(e) => setNewProtectedUser({ ...newProtectedUser, email: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <input
                  type="text"
                  placeholder="Name (for executives)"
                  value={newProtectedUser.name}
                  onChange={(e) => setNewProtectedUser({ ...newProtectedUser, name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <input
                  type="text"
                  placeholder="Title (for executives)"
                  value={newProtectedUser.title}
                  onChange={(e) => setNewProtectedUser({ ...newProtectedUser, title: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                />
                <select
                  value={newProtectedUser.user_type}
                  onChange={(e) => setNewProtectedUser({ ...newProtectedUser, user_type: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                >
                  <option value="vip">VIP User</option>
                  <option value="executive">Executive</option>
                </select>
                <Button onClick={addProtectedUser} className="w-full bg-purple-600 hover:bg-purple-700">
                  <Plus className="h-4 w-4 mr-2" />
                  Add Protected User
                </Button>
              </CardContent>
            </Card>

            {/* Protected Users List */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Users className="h-5 w-5 text-green-400" />
                  Protected Users ({protectedUsers.executives?.length + protectedUsers.vip_users?.length || 0})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {protectedUsers.executives?.length > 0 && (
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-slate-400 mb-2">Executives</h4>
                    {protectedUsers.executives.map((exec, index) => (
                      <div key={index} className="flex items-center justify-between p-2 rounded bg-slate-800/50 mb-2">
                        <div>
                          <span className="text-white">{exec.email}</span>
                          <span className="text-slate-400 text-sm ml-2">({exec.name || exec.title || 'Executive'})</span>
                        </div>
                        <Badge className="bg-purple-500/20 text-purple-400">Executive</Badge>
                      </div>
                    ))}
                  </div>
                )}
                {protectedUsers.vip_users?.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-slate-400 mb-2">VIP Users</h4>
                    {protectedUsers.vip_users.map((email, index) => (
                      <div key={index} className="flex items-center justify-between p-2 rounded bg-slate-800/50 mb-2">
                        <span className="text-white">{email}</span>
                        <Badge className="bg-blue-500/20 text-blue-400">VIP</Badge>
                      </div>
                    ))}
                  </div>
                )}
                {(protectedUsers.executives?.length === 0 && protectedUsers.vip_users?.length === 0) && (
                  <p className="text-slate-500 text-center py-4">No protected users configured</p>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'blocklist' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Blocked Senders */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <XCircle className="h-5 w-5 text-red-400" />
                  Blocked Senders ({blockedSenders.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="sender@domain.com or @domain.com"
                    value={newBlockedSender}
                    onChange={(e) => setNewBlockedSender(e.target.value)}
                    className="flex-1 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                  />
                  <Button onClick={addBlockedSender} className="bg-red-600 hover:bg-red-700">
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {blockedSenders.map((sender, index) => (
                    <div key={index} className="flex items-center justify-between p-2 rounded bg-slate-800/50">
                      <span className="text-white">{sender}</span>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeBlockedSender(sender)}
                        className="text-red-400 hover:text-red-300 hover:bg-red-500/20"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                  {blockedSenders.length === 0 && (
                    <p className="text-slate-500 text-center py-4">No blocked senders</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Trusted Domains */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                  Trusted Domains ({trustedDomains.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="trusted-domain.com"
                    value={newTrustedDomain}
                    onChange={(e) => setNewTrustedDomain(e.target.value)}
                    className="flex-1 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white"
                  />
                  <Button onClick={addTrustedDomain} className="bg-green-600 hover:bg-green-700">
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {trustedDomains.map((domain, index) => (
                    <div key={index} className="flex items-center justify-between p-2 rounded bg-slate-800/50">
                      <span className="text-white">{domain}</span>
                      <Badge className="bg-green-500/20 text-green-400">Trusted</Badge>
                    </div>
                  ))}
                  {trustedDomains.length === 0 && (
                    <p className="text-slate-500 text-center py-4">No trusted domains configured</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default EmailProtectionPage;
