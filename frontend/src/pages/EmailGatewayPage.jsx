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
  Server,
  Settings,
  Plus,
  Trash2,
  Play,
  Ban,
  List,
  FileText,
  Activity
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const EmailGatewayPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [quarantine, setQuarantine] = useState([]);
  const [policies, setPolicies] = useState({});
  const [blocklists, setBlocklists] = useState({ sender_blocklist: [], domain_blocklist: [], ip_blocklist: [] });
  const [allowlists, setAllowlists] = useState({ sender_allowlist: [], domain_allowlist: [], ip_allowlist: [] });
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Add forms
  const [blocklistForm, setBlocklistForm] = useState({ value: '', list_type: 'sender' });
  const [allowlistForm, setAllowlistForm] = useState({ value: '', list_type: 'sender' });
  const [emailTestForm, setEmailTestForm] = useState({
    envelope_from: '',
    envelope_to: '',
    subject: '',
    body: '',
    client_ip: ''
  });
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [statsRes, quarantineRes, policiesRes, blocklistsRes, allowlistsRes] = await Promise.all([
        fetch(`${API_URL}/api/email-gateway/stats`, { headers }),
        fetch(`${API_URL}/api/email-gateway/quarantine`, { headers }),
        fetch(`${API_URL}/api/email-gateway/policies`, { headers }),
        fetch(`${API_URL}/api/email-gateway/blocklist`, { headers }),
        fetch(`${API_URL}/api/email-gateway/allowlist`, { headers })
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (quarantineRes.ok) {
        const data = await quarantineRes.json();
        setQuarantine(data.quarantine || []);
      }
      if (policiesRes.ok) {
        const data = await policiesRes.json();
        setPolicies(data.policies || {});
      }
      if (blocklistsRes.ok) setBlocklists(await blocklistsRes.json());
      if (allowlistsRes.ok) setAllowlists(await allowlistsRes.json());
    } catch (error) {
      console.error('Failed to fetch email gateway data:', error);
    } finally {
      setLoading(false);
    }
  };

  const testEmail = async () => {
    if (!emailTestForm.envelope_from || !emailTestForm.subject) {
      toast.error('Please fill in sender and subject');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/email-gateway/process`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...emailTestForm,
          envelope_to: emailTestForm.envelope_to ? [emailTestForm.envelope_to] : []
        })
      });

      if (response.ok) {
        const result = await response.json();
        setTestResult(result);
        toast.success(`Email processed: ${result.action}`);
      } else {
        toast.error('Failed to process email');
      }
    } catch (error) {
      toast.error('Error processing email');
    }
  };

  const addToBlocklist = async () => {
    if (!blocklistForm.value) {
      toast.error('Please enter a value');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/email-gateway/blocklist`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(blocklistForm)
      });

      if (response.ok) {
        toast.success(`Added to ${blocklistForm.list_type} blocklist`);
        setBlocklistForm({ value: '', list_type: 'sender' });
        fetchData();
      } else {
        toast.error('Failed to add to blocklist');
      }
    } catch (error) {
      toast.error('Error adding to blocklist');
    }
  };

  const removeFromBlocklist = async (value, listType) => {
    try {
      const response = await fetch(`${API_URL}/api/email-gateway/blocklist?value=${encodeURIComponent(value)}&list_type=${listType}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Removed from blocklist');
        fetchData();
      } else {
        toast.error('Failed to remove from blocklist');
      }
    } catch (error) {
      toast.error('Error removing from blocklist');
    }
  };

  const addToAllowlist = async () => {
    if (!allowlistForm.value) {
      toast.error('Please enter a value');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/email-gateway/allowlist`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(allowlistForm)
      });

      if (response.ok) {
        toast.success(`Added to ${allowlistForm.list_type} allowlist`);
        setAllowlistForm({ value: '', list_type: 'sender' });
        fetchData();
      } else {
        toast.error('Failed to add to allowlist');
      }
    } catch (error) {
      toast.error('Error adding to allowlist');
    }
  };

  const releaseFromQuarantine = async (quarantineId) => {
    try {
      const response = await fetch(`${API_URL}/api/email-gateway/quarantine/${quarantineId}/release`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Message released from quarantine');
        fetchData();
      } else {
        toast.error('Failed to release message');
      }
    } catch (error) {
      toast.error('Error releasing message');
    }
  };

  const deleteFromQuarantine = async (quarantineId) => {
    try {
      const response = await fetch(`${API_URL}/api/email-gateway/quarantine/${quarantineId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Message deleted from quarantine');
        fetchData();
      } else {
        toast.error('Failed to delete message');
      }
    } catch (error) {
      toast.error('Error deleting message');
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'quarantine', label: 'Quarantine', icon: AlertTriangle },
    { id: 'blocklist', label: 'Blocklist', icon: Ban },
    { id: 'allowlist', label: 'Allowlist', icon: CheckCircle },
    { id: 'policies', label: 'Policies', icon: Settings },
    { id: 'test', label: 'Test Email', icon: Play }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="email-gateway-page">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Server className="w-8 h-8 text-cyan-400" />
            Email Gateway
          </h1>
          <p className="text-slate-400 mt-1">SMTP relay and real-time email interception</p>
        </div>
        <Button onClick={fetchData} variant="outline" className="border-cyan-500/30 text-cyan-400">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-700 pb-2">
        {tabs.map(tab => (
          <Button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            variant={activeTab === tab.id ? 'default' : 'ghost'}
            className={activeTab === tab.id ? 'bg-cyan-600' : 'text-slate-400'}
            data-testid={`tab-${tab.id}`}
          >
            <tab.icon className="w-4 h-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Total Processed</p>
                    <p className="text-3xl font-bold text-white">{stats?.total_processed || 0}</p>
                  </div>
                  <Mail className="w-10 h-10 text-cyan-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Accepted</p>
                    <p className="text-3xl font-bold text-green-400">{stats?.accepted || 0}</p>
                  </div>
                  <CheckCircle className="w-10 h-10 text-green-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Rejected</p>
                    <p className="text-3xl font-bold text-red-400">{stats?.rejected || 0}</p>
                  </div>
                  <XCircle className="w-10 h-10 text-red-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Quarantined</p>
                    <p className="text-3xl font-bold text-yellow-400">{stats?.quarantined || 0}</p>
                  </div>
                  <AlertTriangle className="w-10 h-10 text-yellow-400" />
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  Gateway Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Mode</span>
                  <Badge className="bg-cyan-600">{stats?.mode || 'inline'}</Badge>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Avg Processing Time</span>
                  <span className="text-white">{stats?.avg_processing_time_ms?.toFixed(2) || '0'} ms</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Threats Blocked</span>
                  <span className="text-red-400 font-bold">{stats?.threats_blocked || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Deferred Messages</span>
                  <span className="text-yellow-400">{stats?.deferred || 0}</span>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <List className="w-5 h-5 text-cyan-400" />
                  Lists Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Sender Blocklist</span>
                  <span className="text-white">{stats?.sender_blocklist_size || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Domain Blocklist</span>
                  <span className="text-white">{stats?.domain_blocklist_size || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">IP Blocklist</span>
                  <span className="text-white">{stats?.ip_blocklist_size || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Quarantine Size</span>
                  <span className="text-yellow-400">{stats?.quarantine_size || 0}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* Quarantine Tab */}
      {activeTab === 'quarantine' && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              Quarantined Messages ({quarantine.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {quarantine.length === 0 ? (
              <p className="text-slate-400 text-center py-8">No quarantined messages</p>
            ) : (
              <div className="space-y-4">
                {quarantine.map((item, index) => (
                  <div key={index} className="p-4 bg-slate-900/50 rounded-lg border border-slate-600">
                    <div className="flex justify-between items-start mb-2">
                      <div>
                        <p className="text-white font-medium">{item.message?.subject || 'No Subject'}</p>
                        <p className="text-slate-400 text-sm">From: {item.message?.envelope_from || 'Unknown'}</p>
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" onClick={() => releaseFromQuarantine(item.decision_id)} className="bg-green-600 hover:bg-green-700">
                          <Play className="w-4 h-4 mr-1" /> Release
                        </Button>
                        <Button size="sm" variant="destructive" onClick={() => deleteFromQuarantine(item.decision_id)}>
                          <Trash2 className="w-4 h-4 mr-1" /> Delete
                        </Button>
                      </div>
                    </div>
                    <p className="text-slate-500 text-sm">Reason: {item.reason}</p>
                    <p className="text-slate-500 text-sm">Quarantined: {item.quarantined_at}</p>
                    {item.threats?.length > 0 && (
                      <div className="flex gap-2 mt-2">
                        {item.threats.map((threat, i) => (
                          <Badge key={i} variant="destructive">{threat}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Blocklist Tab */}
      {activeTab === 'blocklist' && (
        <div className="space-y-6">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Plus className="w-5 h-5 text-cyan-400" />
                Add to Blocklist
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4">
                <select
                  className="bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                  value={blocklistForm.list_type}
                  onChange={(e) => setBlocklistForm({ ...blocklistForm, list_type: e.target.value })}
                >
                  <option value="sender">Sender</option>
                  <option value="domain">Domain</option>
                  <option value="ip">IP Address</option>
                </select>
                <input
                  type="text"
                  className="flex-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                  placeholder="Enter value to block..."
                  value={blocklistForm.value}
                  onChange={(e) => setBlocklistForm({ ...blocklistForm, value: e.target.value })}
                />
                <Button onClick={addToBlocklist} className="bg-red-600 hover:bg-red-700">
                  <Ban className="w-4 h-4 mr-2" /> Block
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {['sender', 'domain', 'ip'].map(listType => (
              <Card key={listType} className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white capitalize">{listType} Blocklist</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {blocklists[`${listType}_blocklist`]?.map((item, i) => (
                      <div key={i} className="flex justify-between items-center p-2 bg-slate-900/50 rounded">
                        <span className="text-white text-sm">{item}</span>
                        <Button size="sm" variant="ghost" onClick={() => removeFromBlocklist(item, listType)}>
                          <Trash2 className="w-4 h-4 text-red-400" />
                        </Button>
                      </div>
                    ))}
                    {(!blocklists[`${listType}_blocklist`] || blocklists[`${listType}_blocklist`].length === 0) && (
                      <p className="text-slate-500 text-center py-4">Empty</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Allowlist Tab */}
      {activeTab === 'allowlist' && (
        <div className="space-y-6">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Plus className="w-5 h-5 text-cyan-400" />
                Add to Allowlist
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4">
                <select
                  className="bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                  value={allowlistForm.list_type}
                  onChange={(e) => setAllowlistForm({ ...allowlistForm, list_type: e.target.value })}
                >
                  <option value="sender">Sender</option>
                  <option value="domain">Domain</option>
                  <option value="ip">IP Address</option>
                </select>
                <input
                  type="text"
                  className="flex-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                  placeholder="Enter value to allow..."
                  value={allowlistForm.value}
                  onChange={(e) => setAllowlistForm({ ...allowlistForm, value: e.target.value })}
                />
                <Button onClick={addToAllowlist} className="bg-green-600 hover:bg-green-700">
                  <CheckCircle className="w-4 h-4 mr-2" /> Allow
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {['sender', 'domain', 'ip'].map(listType => (
              <Card key={listType} className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white capitalize">{listType} Allowlist</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {allowlists[`${listType}_allowlist`]?.map((item, i) => (
                      <div key={i} className="flex justify-between items-center p-2 bg-slate-900/50 rounded">
                        <span className="text-white text-sm">{item}</span>
                      </div>
                    ))}
                    {(!allowlists[`${listType}_allowlist`] || allowlists[`${listType}_allowlist`].length === 0) && (
                      <p className="text-slate-500 text-center py-4">Empty</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Policies Tab */}
      {activeTab === 'policies' && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Settings className="w-5 h-5 text-cyan-400" />
              Gateway Policies
            </CardTitle>
          </CardHeader>
          <CardContent>
            {Object.keys(policies).length === 0 ? (
              <p className="text-slate-400 text-center py-8">No policies configured</p>
            ) : (
              <div className="space-y-4">
                {Object.entries(policies).map(([name, settings]) => (
                  <div key={name} className="p-4 bg-slate-900/50 rounded-lg border border-slate-600">
                    <h3 className="text-white font-medium mb-2">{name}</h3>
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(settings || {}).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-slate-400 text-sm">{key.replace(/_/g, ' ')}</span>
                          <span className="text-white text-sm">{String(value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Test Email Tab */}
      {activeTab === 'test' && (
        <div className="space-y-6">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Play className="w-5 h-5 text-cyan-400" />
                Test Email Processing
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-slate-400 text-sm">From (Sender)</label>
                  <input
                    type="email"
                    className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                    placeholder="sender@example.com"
                    value={emailTestForm.envelope_from}
                    onChange={(e) => setEmailTestForm({ ...emailTestForm, envelope_from: e.target.value })}
                  />
                </div>
                <div>
                  <label className="text-slate-400 text-sm">To (Recipient)</label>
                  <input
                    type="email"
                    className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                    placeholder="recipient@company.com"
                    value={emailTestForm.envelope_to}
                    onChange={(e) => setEmailTestForm({ ...emailTestForm, envelope_to: e.target.value })}
                  />
                </div>
              </div>
              <div>
                <label className="text-slate-400 text-sm">Subject</label>
                <input
                  type="text"
                  className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                  placeholder="Email subject"
                  value={emailTestForm.subject}
                  onChange={(e) => setEmailTestForm({ ...emailTestForm, subject: e.target.value })}
                />
              </div>
              <div>
                <label className="text-slate-400 text-sm">Body</label>
                <textarea
                  className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2 h-32"
                  placeholder="Email body content..."
                  value={emailTestForm.body}
                  onChange={(e) => setEmailTestForm({ ...emailTestForm, body: e.target.value })}
                />
              </div>
              <div>
                <label className="text-slate-400 text-sm">Client IP (optional)</label>
                <input
                  type="text"
                  className="w-full mt-1 bg-slate-900 border-slate-600 text-white rounded px-3 py-2"
                  placeholder="192.168.1.1"
                  value={emailTestForm.client_ip}
                  onChange={(e) => setEmailTestForm({ ...emailTestForm, client_ip: e.target.value })}
                />
              </div>
              <Button onClick={testEmail} className="bg-cyan-600 hover:bg-cyan-700">
                <Play className="w-4 h-4 mr-2" /> Process Email
              </Button>
            </CardContent>
          </Card>

          {testResult && (
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyan-400" />
                  Processing Result
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-slate-400 text-sm">Action</p>
                    <Badge className={
                      testResult.action === 'accept' ? 'bg-green-600' :
                      testResult.action === 'reject' ? 'bg-red-600' :
                      testResult.action === 'quarantine' ? 'bg-yellow-600' :
                      'bg-slate-600'
                    }>
                      {testResult.action}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Threat Score</p>
                    <p className="text-white">{(testResult.threat_score * 100).toFixed(1)}%</p>
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Reason</p>
                    <p className="text-white">{testResult.reason}</p>
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Processing Time</p>
                    <p className="text-white">{testResult.processing_time_ms?.toFixed(2)} ms</p>
                  </div>
                </div>
                {testResult.threats_detected?.length > 0 && (
                  <div className="mt-4">
                    <p className="text-slate-400 text-sm mb-2">Threats Detected</p>
                    <div className="flex gap-2">
                      {testResult.threats_detected.map((threat, i) => (
                        <Badge key={i} variant="destructive">{threat}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
};

export default EmailGatewayPage;
