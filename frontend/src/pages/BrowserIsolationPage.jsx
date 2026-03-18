import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  Globe, 
  Shield, 
  Activity, 
  Ban,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Link2,
  Eye,
  Plus,
  Trash2,
  Lock
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const BrowserIsolationPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [blockedDomains, setBlockedDomains] = useState([]);
  const [modes, setModes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('sessions');
  const [urlInput, setUrlInput] = useState('');
  const [selectedMode, setSelectedMode] = useState('full');
  const [newDomain, setNewDomain] = useState('');
  const [urlAnalysis, setUrlAnalysis] = useState(null);
  const [activeSession, setActiveSession] = useState(null);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const [statsRes, sessionsRes, domainsRes, modesRes] = await Promise.all([
        fetch(`${API_URL}/api/browser-isolation/stats`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/browser-isolation/sessions`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/browser-isolation/blocked-domains`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/browser-isolation/modes`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (sessionsRes.ok) {
        const data = await sessionsRes.json();
        setSessions(data.sessions || []);
      }
      if (domainsRes.ok) {
        const data = await domainsRes.json();
        setBlockedDomains(data.domains || []);
      }
      if (modesRes.ok) {
        const data = await modesRes.json();
        setModes(data.modes || []);
      }
    } catch (error) {
      console.error('Failed to fetch browser isolation data:', error);
    } finally {
      setLoading(false);
    }
  };

  const analyzeURL = async () => {
    if (!urlInput.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/browser-isolation/analyze-url`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: urlInput })
      });

      if (response.ok) {
        const result = await response.json();
        setUrlAnalysis(result);
        if (result.is_blocked) {
          toast.error(`URL is blocked: ${result.reasons.join(', ')}`);
        } else {
          toast.success(`URL analyzed: ${result.threat_level} threat level`);
        }
      }
    } catch (error) {
      toast.error('Failed to analyze URL');
    }
  };

  const createSession = async () => {
    if (!urlInput.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    setCreating(true);
    try {
      const response = await fetch(`${API_URL}/api/browser-isolation/sessions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
          url: urlInput,
          isolation_mode: selectedMode
        })
      });

      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          toast.success(`Isolated session created!`);
          // Set as active session to display
          setActiveSession({
            session_id: result.session_id,
            url: urlInput,
            safe_url: result.safe_url,
            isolation_mode: selectedMode,
            threat_level: result.threat_level,
            category: result.category
          });
          setActiveTab('browser');
          fetchData();
        } else {
          toast.error(result.error || 'Failed to create session');
        }
      }
    } catch (error) {
      toast.error('Failed to create session');
    } finally {
      setCreating(false);
    }
  };

  const endSession = async (sessionId) => {
    try {
      const response = await fetch(`${API_URL}/api/browser-isolation/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success('Session ended');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to end session');
    }
  };

  const addBlockedDomain = async () => {
    if (!newDomain.trim()) return;

    try {
      const response = await fetch(`${API_URL}/api/browser-isolation/blocked-domains`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domain: newDomain })
      });

      if (response.ok) {
        toast.success(`Domain ${newDomain} blocked`);
        setNewDomain('');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to block domain');
    }
  };

  const removeBlockedDomain = async (domain) => {
    try {
      const response = await fetch(`${API_URL}/api/browser-isolation/blocked-domains/${encodeURIComponent(domain)}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        toast.success(`Domain ${domain} unblocked`);
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to unblock domain');
    }
  };

  const getThreatColor = (level) => {
    const colors = {
      malicious: 'text-red-400 bg-red-400/10 border-red-500/30',
      high: 'text-orange-400 bg-orange-400/10 border-orange-500/30',
      medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-500/30',
      low: 'text-blue-400 bg-blue-400/10 border-blue-500/30',
      safe: 'text-green-400 bg-green-400/10 border-green-500/30'
    };
    return colors[level] || colors.low;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading Browser Isolation...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6" data-testid="browser-isolation-page">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-cyan-500/20 flex items-center justify-center">
              <Globe className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Browser Isolation</h1>
              <p className="text-slate-400">Secure remote browsing with content isolation</p>
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
                <p className="text-slate-400 text-sm">Total Sessions</p>
                <p className="text-2xl font-bold text-white">{stats?.total_sessions || 0}</p>
              </div>
              <Globe className="w-8 h-8 text-cyan-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Active Sessions</p>
                <p className="text-2xl font-bold text-white">{stats?.active_sessions || 0}</p>
              </div>
              <Activity className="w-8 h-8 text-green-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Blocked Domains</p>
                <p className="text-2xl font-bold text-white">{stats?.blocked_domains || 0}</p>
              </div>
              <Ban className="w-8 h-8 text-red-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Threats Blocked</p>
                <p className="text-2xl font-bold text-white">{stats?.total_threats_blocked || 0}</p>
              </div>
              <Shield className="w-8 h-8 text-orange-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* URL Input Section */}
      <Card className="bg-slate-900/50 border-slate-800 mb-6">
        <CardContent className="p-4">
          <div className="mb-4 p-3 bg-cyan-500/10 border border-cyan-500/30 rounded">
            <p className="text-cyan-400 text-sm font-medium mb-1">How to use Browser Isolation:</p>
            <ol className="text-xs text-slate-300 list-decimal list-inside space-y-1">
              <li><strong>Analyze URL</strong> - Check if a URL is safe before visiting</li>
              <li><strong>Start Isolated Session</strong> - Browse untrusted sites in a secure container</li>
              <li>Choose isolation mode: <strong>Full</strong> (safest), <strong>CDR</strong> (sanitized), <strong>Read-only</strong>, or <strong>Pixel push</strong></li>
            </ol>
          </div>
          <div className="flex flex-col gap-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Enter URL to browse securely (e.g., https://example.com)"
                className="flex-1 bg-slate-800 border border-slate-700 rounded px-4 py-2 text-white"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                data-testid="isolation-url-input"
              />
              <select
                className="bg-slate-800 border border-slate-700 rounded px-4 py-2 text-white"
                value={selectedMode}
                onChange={(e) => setSelectedMode(e.target.value)}
              >
                {modes.map((mode) => (
                  <option key={mode.id} value={mode.id}>{mode.name}</option>
                ))}
              </select>
            </div>
            <div className="flex gap-2">
              <Button onClick={analyzeURL} variant="outline" className="border-slate-700">
                <Eye className="w-4 h-4 mr-2" />
                Analyze URL
              </Button>
              <Button onClick={createSession} disabled={creating} className="bg-cyan-600 hover:bg-cyan-700">
                {creating ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Lock className="w-4 h-4 mr-2" />
                )}
                Start Isolated Session
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* URL Analysis Result */}
      {urlAnalysis && (
        <Card className={`mb-6 ${getThreatColor(urlAnalysis.threat_level)} border`}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white font-medium">{urlAnalysis.url}</p>
                <p className="text-sm mt-1">Domain: {urlAnalysis.domain} | Category: {urlAnalysis.category}</p>
              </div>
              <div className="flex items-center gap-4">
                {urlAnalysis.is_blocked ? (
                  <span className="flex items-center gap-2 text-red-400">
                    <Ban className="w-5 h-5" />
                    BLOCKED
                  </span>
                ) : (
                  <span className="flex items-center gap-2 text-green-400">
                    <CheckCircle className="w-5 h-5" />
                    ALLOWED
                  </span>
                )}
                <span className="px-3 py-1 rounded font-medium capitalize">
                  {urlAnalysis.threat_level}
                </span>
              </div>
            </div>
            {urlAnalysis.reasons && urlAnalysis.reasons.length > 0 && (
              <div className="mt-3">
                <p className="text-sm font-medium mb-1">Analysis:</p>
                <ul className="text-sm list-disc list-inside">
                  {urlAnalysis.reasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {['sessions', 'browser', 'blocklist', 'modes'].map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab)}
            className={activeTab === tab ? 'bg-cyan-600 hover:bg-cyan-700' : 'text-slate-400'}
          >
            {tab === 'browser' ? (
              <span className="flex items-center gap-2">
                <Globe className="w-4 h-4" />
                Browser View {activeSession && <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />}
              </span>
            ) : (
              tab.charAt(0).toUpperCase() + tab.slice(1)
            )}
          </Button>
        ))}
      </div>

      {/* Browser View Tab - Shows iframe with isolated content */}
      {activeTab === 'browser' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                Isolated Browser View
              </CardTitle>
              {activeSession && (
                <Button 
                  size="sm" 
                  variant="destructive" 
                  onClick={() => {
                    endSession(activeSession.session_id);
                    setActiveSession(null);
                  }}
                >
                  <Trash2 className="w-4 h-4 mr-1" />
                  End Session
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {activeSession ? (
              <div className="space-y-4">
                {/* Session Info Bar */}
                <div className="flex items-center justify-between p-3 bg-slate-800 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Lock className="w-5 h-5 text-green-400" />
                    <div>
                      <p className="text-white text-sm font-medium">Secure Session Active</p>
                      <p className="text-slate-400 text-xs">Mode: {activeSession.isolation_mode} | Threat: {activeSession.threat_level}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400 font-mono truncate max-w-md">{activeSession.url}</span>
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="border-slate-600"
                      onClick={() => window.open(activeSession.url, '_blank', 'noopener,noreferrer')}
                    >
                      Open in New Tab
                    </Button>
                  </div>
                </div>

                {/* Isolated Browser Frame */}
                <div className="relative bg-white rounded-lg overflow-hidden" style={{ height: '500px' }}>
                  <div className="absolute top-0 left-0 right-0 bg-slate-800 text-white px-3 py-1 text-xs flex items-center gap-2 z-10">
                    <Shield className="w-3 h-3 text-green-400" />
                    <span className="text-green-400">ISOLATED</span>
                    <span className="text-slate-400">|</span>
                    <span className="truncate flex-1">{activeSession.url}</span>
                  </div>
                  <iframe
                    src={activeSession.url}
                    className="w-full h-full border-0 pt-6"
                    sandbox="allow-scripts allow-same-origin"
                    referrerPolicy="no-referrer"
                    title="Isolated Browser"
                  />
                </div>

                <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded text-amber-400 text-sm">
                  <AlertTriangle className="w-4 h-4 inline-block mr-2" />
                  <strong>Note:</strong> Some sites may not load due to security headers (X-Frame-Options). 
                  In production, this would use a secure proxy or pixel-streaming approach.
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-slate-400">
                <Globe className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p className="text-lg font-medium mb-2">No Active Session</p>
                <p className="text-sm">Enter a URL above and click "Start Isolated Session" to browse securely.</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === 'sessions' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              Active Isolated Sessions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {sessions.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No active sessions. Start one by entering a URL above.</p>
              ) : (
                sessions.map((session) => (
                  <div
                    key={session.session_id}
                    className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg"
                  >
                    <div className="flex items-center gap-4">
                      <Globe className="w-5 h-5 text-cyan-400" />
                      <div>
                        <p className="text-white font-medium">{session.original_url}</p>
                        <p className="text-slate-500 text-xs">Mode: {session.isolation_mode} | Started: {new Date(session.started_at).toLocaleString()}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getThreatColor(session.threat_level)}`}>
                        {session.threat_level}
                      </span>
                      <Button
                        size="sm"
                        variant="outline"
                        className="border-cyan-500 text-cyan-400"
                        onClick={() => {
                          setActiveSession({
                            session_id: session.session_id,
                            url: session.original_url,
                            safe_url: session.sanitized_url,
                            isolation_mode: session.isolation_mode,
                            threat_level: session.threat_level
                          });
                          setActiveTab('browser');
                        }}
                      >
                        <Eye className="w-4 h-4 mr-1" />
                        Open
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-red-400 hover:text-red-300"
                        onClick={() => endSession(session.session_id)}
                      >
                        End Session
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === 'blocklist' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Ban className="w-5 h-5 text-red-400" />
              Blocked Domains
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 mb-4">
              <input
                type="text"
                placeholder="Enter domain to block (e.g., malicious-site.com)"
                className="flex-1 bg-slate-800 border border-slate-700 rounded px-4 py-2 text-white"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
              />
              <Button onClick={addBlockedDomain} className="bg-red-600 hover:bg-red-700">
                <Plus className="w-4 h-4 mr-2" />
                Block Domain
              </Button>
            </div>
            <div className="space-y-2 max-h-96 overflow-auto">
              {blockedDomains.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No blocked domains yet</p>
              ) : (
                blockedDomains.map((domain) => (
                  <div
                    key={domain}
                    className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg"
                  >
                    <span className="text-white font-mono">{domain}</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-red-400 hover:text-red-300"
                      onClick={() => removeBlockedDomain(domain)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === 'modes' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {modes.map((mode) => (
            <Card key={mode.id} className="bg-slate-900/50 border-slate-800">
              <CardContent className="p-6">
                <div className="flex items-center gap-4 mb-3">
                  <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                    <Lock className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="text-white font-medium">{mode.name}</h3>
                    <p className="text-slate-500 text-xs uppercase">{mode.id}</p>
                  </div>
                </div>
                <p className="text-slate-400 text-sm">{mode.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

export default BrowserIsolationPage;
