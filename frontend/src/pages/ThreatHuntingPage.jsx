import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Switch } from "../components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Search,
  Shield,
  AlertTriangle,
  Activity,
  Brain,
  RefreshCw,
  Target,
  Crosshair,
  FileSearch,
  ChevronRight,
  ChevronDown,
  Check,
  X
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

export default function ThreatHuntingPage() {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [rules, setRules] = useState([]);
  const [matches, setMatches] = useState([]);
  const [tactics, setTactics] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const [expandedRules, setExpandedRules] = useState({});
  const [hypotheses, setHypotheses] = useState([]);
  const [hypothesisMethod, setHypothesisMethod] = useState(null);
  const [generatingHypotheses, setGeneratingHypotheses] = useState(false);

  useEffect(() => {
    fetchAll();
  }, []);

  const fetchAll = async () => {
    await Promise.all([
      fetchStatus(),
      fetchRules(),
      fetchMatches(),
      fetchTactics()
    ]);
    setLoading(false);
  };

  const fetchStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/api/hunting/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setStatus(data);
    } catch (error) {
      toast.error("Failed to fetch hunting status");
    }
  };

  const fetchRules = async () => {
    try {
      const response = await fetch(`${API_URL}/api/hunting/rules`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setRules(data.rules || []);
    } catch (error) {
      toast.error("Failed to fetch rules");
    }
  };

  const fetchMatches = async () => {
    try {
      const response = await fetch(`${API_URL}/api/hunting/matches/high-severity`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setMatches(data.matches || []);
    } catch (error) {
      toast.error("Failed to fetch matches");
    }
  };

  const fetchTactics = async () => {
    try {
      const response = await fetch(`${API_URL}/api/hunting/tactics`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setTactics(data.tactics || []);
    } catch (error) {
      toast.error("Failed to fetch tactics");
    }
  };

  const toggleRule = async (ruleId, enabled) => {
    try {
      const response = await fetch(`${API_URL}/api/hunting/rules/${ruleId}/toggle`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ enabled })
      });
      
      if (response.ok) {
        setRules(rules.map(r => 
          r.rule_id === ruleId ? { ...r, enabled } : r
        ));
        toast.success(`Rule ${enabled ? 'enabled' : 'disabled'}`);
      }
    } catch (error) {
      toast.error("Failed to toggle rule");
    }
  };

  const generateHypotheses = async () => {
    setGeneratingHypotheses(true);
    try {
      const response = await fetch(`${API_URL}/api/hunting/hypotheses/generate`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          focus: "active high-severity threat hunting",
          recent_matches: matches.slice(0, 10)
        })
      });

      if (response.ok) {
        const data = await response.json();
        setHypotheses(data.hypotheses || []);
        setHypothesisMethod(data.method || null);
        toast.success("AI hypotheses generated");
      } else {
        toast.error("Failed to generate hypotheses");
      }
    } catch (error) {
      toast.error("Failed to generate hypotheses");
    } finally {
      setGeneratingHypotheses(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: "bg-red-500",
      high: "bg-orange-500",
      medium: "bg-yellow-500",
      low: "bg-green-500"
    };
    return colors[severity] || "bg-slate-500";
  };

  const getTacticName = (tacticId) => {
    const names = {
      "TA0001": "Initial Access",
      "TA0002": "Execution",
      "TA0003": "Persistence",
      "TA0004": "Privilege Escalation",
      "TA0005": "Defense Evasion",
      "TA0006": "Credential Access",
      "TA0007": "Discovery",
      "TA0008": "Lateral Movement",
      "TA0009": "Collection",
      "TA0010": "Exfiltration",
      "TA0011": "Command and Control",
      "TA0040": "Impact"
    };
    return names[tacticId] || tacticId;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Threat Hunting...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Crosshair className="w-6 h-6 text-red-500" />
            MITRE ATT&CK Threat Hunting
          </h1>
          <p className="text-slate-400">Automated threat detection based on MITRE ATT&CK framework</p>
        </div>
        <Button onClick={fetchAll} variant="outline" size="sm">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
        <Button onClick={generateHypotheses} variant="outline" size="sm" disabled={generatingHypotheses}>
          <Brain className={`w-4 h-4 mr-2 ${generatingHypotheses ? 'animate-pulse' : ''}`} />
          {generatingHypotheses ? 'Generating...' : 'Generate Hypotheses'}
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-slate-900/50 border-slate-800" data-testid="stat-rules">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Rules Loaded</p>
                <p className="text-2xl font-bold text-cyan-400">{status?.rules_loaded || 0}</p>
              </div>
              <FileSearch className="w-8 h-8 text-cyan-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="stat-hunts">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Hunts Executed</p>
                <p className="text-2xl font-bold text-purple-400">{status?.hunts_executed || 0}</p>
              </div>
              <Search className="w-8 h-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-red-900/50" data-testid="stat-matches">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Matches Found</p>
                <p className="text-2xl font-bold text-red-400">{status?.matches_found || 0}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="stat-tactics">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Tactics Covered</p>
                <p className="text-2xl font-bold text-green-400">{status?.tactics_covered || 0}</p>
              </div>
              <Target className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="stat-techniques">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Techniques</p>
                <p className="text-2xl font-bold text-yellow-400">{status?.techniques_covered || 0}</p>
              </div>
              <Shield className="w-8 h-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {hypotheses.length > 0 && (
        <Card className="bg-slate-900/50 border-slate-800" data-testid="hunting-hypotheses-card">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              AI Hunting Hypotheses
            </CardTitle>
            {hypothesisMethod && (
              <CardDescription>Method: {hypothesisMethod}</CardDescription>
            )}
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {hypotheses.map((h, idx) => (
                <li key={idx} className="text-slate-200 text-sm bg-slate-800/50 rounded p-3 border border-slate-700">
                  {h}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="overview" data-testid="tab-overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="rules" data-testid="tab-rules">
            <FileSearch className="w-4 h-4 mr-2" />
            Hunting Rules
          </TabsTrigger>
          <TabsTrigger value="matches" data-testid="tab-matches">
            <AlertTriangle className="w-4 h-4 mr-2" />
            Matches
          </TabsTrigger>
          <TabsTrigger value="matrix" data-testid="tab-matrix">
            <Target className="w-4 h-4 mr-2" />
            ATT&CK Matrix
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">Recent Critical Matches</CardTitle>
              </CardHeader>
              <CardContent>
                {matches.filter(m => m.severity === 'critical').length === 0 ? (
                  <p className="text-slate-400 text-center py-4">No critical matches</p>
                ) : (
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {matches.filter(m => m.severity === 'critical').slice(0, 5).map((match, i) => (
                      <div key={i} className="p-3 bg-red-900/20 border border-red-900/50 rounded">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-white">{match.rule_name}</span>
                          <Badge variant="destructive">{match.mitre_technique}</Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          Confidence: {(match.confidence * 100).toFixed(0)}%
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">Tactics Coverage</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {tactics.map((tactic) => (
                    <div key={tactic.tactic_id} className="flex items-center justify-between p-2 bg-slate-800/50 rounded">
                      <div>
                        <span className="text-white">{getTacticName(tactic.tactic_id)}</span>
                        <span className="text-xs text-slate-400 ml-2">({tactic.tactic_id})</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{tactic.techniques.length} techniques</Badge>
                        <Badge variant="secondary">{tactic.rule_count} rules</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Rules Tab */}
        <TabsContent value="rules" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Hunting Rules ({rules.length})</CardTitle>
              <CardDescription>Click to expand rule details</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-[600px] overflow-y-auto">
                {rules.map((rule) => (
                  <div key={rule.rule_id} className="border border-slate-700 rounded-lg overflow-hidden">
                    <div 
                      className="flex items-center justify-between p-3 bg-slate-800/50 cursor-pointer hover:bg-slate-800"
                      onClick={() => setExpandedRules(prev => ({ ...prev, [rule.rule_id]: !prev[rule.rule_id] }))}
                    >
                      <div className="flex items-center gap-3">
                        {expandedRules[rule.rule_id] ? (
                          <ChevronDown className="w-4 h-4 text-slate-400" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-slate-400" />
                        )}
                        <div className={`w-2 h-2 rounded-full ${getSeverityColor(rule.severity)}`} />
                        <span className="font-medium text-white">{rule.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{rule.mitre_technique}</Badge>
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={(checked) => toggleRule(rule.rule_id, checked)}
                          onClick={(e) => e.stopPropagation()}
                        />
                      </div>
                    </div>
                    {expandedRules[rule.rule_id] && (
                      <div className="p-4 bg-slate-900/50 border-t border-slate-700">
                        <p className="text-slate-300 mb-3">{rule.description}</p>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-slate-400">Tactic:</span>
                            <span className="text-white ml-2">{getTacticName(rule.mitre_tactic)}</span>
                          </div>
                          <div>
                            <span className="text-slate-400">Severity:</span>
                            <Badge className={`ml-2 ${getSeverityColor(rule.severity)}`}>{rule.severity}</Badge>
                          </div>
                          <div>
                            <span className="text-slate-400">Data Sources:</span>
                            <div className="flex gap-1 mt-1">
                              {rule.data_sources?.map((ds, i) => (
                                <Badge key={i} variant="secondary" className="text-xs">{ds}</Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400">Response Actions:</span>
                            <div className="flex gap-1 mt-1 flex-wrap">
                              {rule.response_actions?.slice(0, 3).map((action, i) => (
                                <Badge key={i} variant="outline" className="text-xs">{action}</Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Matches Tab */}
        <TabsContent value="matches" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">High Severity Matches ({matches.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {matches.length === 0 ? (
                <div className="text-center py-8">
                  <Check className="w-12 h-12 text-green-500 mx-auto mb-2" />
                  <p className="text-slate-400">No high-severity threats detected</p>
                </div>
              ) : (
                <div className="space-y-3 max-h-[500px] overflow-y-auto">
                  {matches.map((match, i) => (
                    <div 
                      key={i} 
                      className={`p-4 rounded-lg border ${
                        match.severity === 'critical' ? 'bg-red-900/20 border-red-900/50' : 'bg-orange-900/20 border-orange-900/50'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h3 className="font-medium text-white">{match.rule_name}</h3>
                          <p className="text-sm text-slate-400">{match.rule_id}</p>
                        </div>
                        <div className="flex gap-2">
                          <Badge variant={match.severity === 'critical' ? 'destructive' : 'secondary'}>
                            {match.severity}
                          </Badge>
                          <Badge variant="outline">{match.mitre_technique}</Badge>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm mt-3">
                        <div>
                          <span className="text-slate-400">Tactic:</span>
                          <span className="text-white ml-2">{getTacticName(match.mitre_tactic)}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Confidence:</span>
                          <span className="text-white ml-2">{(match.confidence * 100).toFixed(0)}%</span>
                        </div>
                        <div className="col-span-2">
                          <span className="text-slate-400">Matched Indicators:</span>
                          <div className="flex gap-1 mt-1 flex-wrap">
                            {match.matched_indicators?.map((ind, j) => (
                              <Badge key={j} variant="secondary" className="text-xs font-mono">{ind}</Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-slate-500 mt-2">
                        Detected: {new Date(match.timestamp).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ATT&CK Matrix Tab */}
        <TabsContent value="matrix" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">MITRE ATT&CK Coverage Matrix</CardTitle>
              <CardDescription>Tactics and techniques covered by hunting rules</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {tactics.map((tactic) => (
                  <div key={tactic.tactic_id} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-medium text-white">{getTacticName(tactic.tactic_id)}</h3>
                      <Badge variant="outline" className="text-xs">{tactic.tactic_id}</Badge>
                    </div>
                    <div className="space-y-1">
                      {tactic.techniques.map((tech, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <div className="w-2 h-2 rounded-full bg-green-500" />
                          <span className="text-slate-300 font-mono">{tech}</span>
                        </div>
                      ))}
                    </div>
                    <div className="mt-3 pt-3 border-t border-slate-700 text-xs text-slate-400">
                      {tactic.rule_count} hunting rules active
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
