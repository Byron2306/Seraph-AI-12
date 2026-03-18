import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Brain,
  Network,
  Shield,
  Key,
  Cpu,
  Database,
  Activity,
  Zap,
  Lock,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Settings,
  Terminal,
  Eye,
  MessageSquare
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || "").trim();
const API_URL = (!envBackendUrl || envBackendUrl.includes("localhost")) ? "/api" : `${envBackendUrl}/api`;

export default function AdvancedServicesPage() {
  const { user, token } = useAuth();
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  
  // MCP State
  const [mcpTools, setMcpTools] = useState([]);
  const [mcpExecutions, setMcpExecutions] = useState([]);
  
  // Vector Memory State
  const [memoryQuery, setMemoryQuery] = useState("");
  const [memoryResults, setMemoryResults] = useState([]);
  const [searchingMemory, setSearchingMemory] = useState(false);
  
  // VNS State
  const [vnsFlows, setVnsFlows] = useState([]);
  const [vnsBeacons, setVnsBeacons] = useState([]);
  
  // AI State
  const [aiQuery, setAiQuery] = useState("");
  const [aiResponse, setAiResponse] = useState(null);
  const [analyzeData, setAnalyzeData] = useState({ title: "", description: "", command_line: "" });
  const [aiAnalysis, setAiAnalysis] = useState(null);
  
  // Ollama State
  const [ollamaConfig, setOllamaConfig] = useState({ base_url: "http://host.docker.internal:11434", model: "mistral" });
  
  // Quantum State
  const [quantumKeypairs, setQuantumKeypairs] = useState([]);

  useEffect(() => {
    fetchDashboard();
  }, []);

  const fetchDashboard = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/dashboard`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setDashboard(data);
    } catch (error) {
      toast.error("Failed to fetch dashboard");
    } finally {
      setLoading(false);
    }
  };

  const fetchMCPTools = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/mcp/tools`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setMcpTools(data.tools || []);
    } catch (error) {
      toast.error("Failed to fetch MCP tools");
    }
  };

  const searchMemory = async () => {
    if (!memoryQuery.trim()) return;
    setSearchingMemory(true);
    try {
      const response = await fetch(`${API_URL}/advanced/memory/search`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ query: memoryQuery, top_k: 10 })
      });
      const data = await response.json();
      setMemoryResults(data.results || []);
    } catch (error) {
      toast.error("Search failed");
    } finally {
      setSearchingMemory(false);
    }
  };

  const fetchVNSFlows = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/vns/flows?suspicious_only=true&limit=20`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setVnsFlows(data.flows || []);
    } catch (error) {
      toast.error("Failed to fetch VNS flows");
    }
  };

  const fetchVNSBeacons = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/vns/beacons`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setVnsBeacons(data.beacons || []);
    } catch (error) {
      toast.error("Failed to fetch beacons");
    }
  };

  const queryAI = async () => {
    if (!aiQuery.trim()) return;
    try {
      const response = await fetch(`${API_URL}/advanced/ai/query`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ question: aiQuery })
      });
      const data = await response.json();
      setAiResponse(data);
    } catch (error) {
      toast.error("AI query failed");
    }
  };

  const analyzeThreat = async () => {
    if (!analyzeData.title.trim()) return;
    try {
      const response = await fetch(`${API_URL}/advanced/ai/analyze`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(analyzeData)
      });
      const data = await response.json();
      setAiAnalysis(data);
      toast.success("Threat analyzed");
    } catch (error) {
      toast.error("Analysis failed");
    }
  };

  const configureOllama = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/ai/ollama/configure`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(ollamaConfig)
      });
      const data = await response.json();
      if (data.status === "connected") {
        toast.success(`Connected to Ollama! Models: ${data.available_models?.join(", ")}`);
      } else {
        toast.warning(data.note || data.error);
      }
      fetchDashboard();
    } catch (error) {
      toast.error("Failed to configure Ollama");
    }
  };

  const generateQuantumKey = async (algorithm) => {
    try {
      const endpoint = algorithm === "kyber"
        ? `${API_URL}/advanced/quantum/keypair/kyber`
        : `${API_URL}/advanced/quantum/keypair/dilithium`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      toast.success(`Generated ${algorithm.toUpperCase()} keypair: ${data.key_id}`);
      fetchDashboard();
    } catch (error) {
      toast.error("Key generation failed");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Advanced Services...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Advanced Security Services</h1>
          <p className="text-slate-400">Enterprise-grade security infrastructure</p>
        </div>
        <Button onClick={fetchDashboard} variant="outline" size="sm">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-slate-900/50 border-slate-800" data-testid="mcp-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">MCP Tools</p>
                <p className="text-2xl font-bold text-cyan-400">{dashboard?.mcp?.tools_registered || 0}</p>
              </div>
              <Terminal className="w-8 h-8 text-cyan-500" />
            </div>
            <p className="text-xs text-slate-500 mt-2">
              {dashboard?.mcp?.total_executions || 0} executions
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="memory-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Vector Memory</p>
                <p className="text-2xl font-bold text-purple-400">{dashboard?.memory?.total_entries || 0}</p>
              </div>
              <Database className="w-8 h-8 text-purple-500" />
            </div>
            <p className="text-xs text-slate-500 mt-2">
              {dashboard?.memory?.total_cases || 0} cases
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="vns-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">VNS Flows</p>
                <p className="text-2xl font-bold text-green-400">{dashboard?.vns?.total_flows || 0}</p>
              </div>
              <Network className="w-8 h-8 text-green-500" />
            </div>
            <p className="text-xs text-slate-500 mt-2">
              {dashboard?.vns?.suspicious_flows || 0} suspicious
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="quantum-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Quantum Keys</p>
                <p className="text-2xl font-bold text-yellow-400">{dashboard?.quantum?.keypairs?.total || 0}</p>
              </div>
              <Key className="w-8 h-8 text-yellow-500" />
            </div>
            <p className="text-xs text-slate-500 mt-2">
              {dashboard?.quantum?.mode || "simulation"}
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800" data-testid="ai-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">AI Analyses</p>
                <p className="text-2xl font-bold text-pink-400">{dashboard?.ai?.analyses_performed || 0}</p>
              </div>
              <Brain className="w-8 h-8 text-pink-500" />
            </div>
            <Badge 
              variant={dashboard?.ai?.ollama?.status === "connected" ? "success" : "secondary"}
              className="mt-2"
            >
              {dashboard?.ai?.ollama?.status || "disconnected"}
            </Badge>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="overview" data-testid="tab-overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="mcp" data-testid="tab-mcp">
            <Terminal className="w-4 h-4 mr-2" />
            MCP Server
          </TabsTrigger>
          <TabsTrigger value="memory" data-testid="tab-memory">
            <Database className="w-4 h-4 mr-2" />
            Vector Memory
          </TabsTrigger>
          <TabsTrigger value="vns" data-testid="tab-vns">
            <Network className="w-4 h-4 mr-2" />
            VNS
          </TabsTrigger>
          <TabsTrigger value="quantum" data-testid="tab-quantum">
            <Key className="w-4 h-4 mr-2" />
            Quantum
          </TabsTrigger>
          <TabsTrigger value="ai" data-testid="tab-ai">
            <Brain className="w-4 h-4 mr-2" />
            AI Reasoning
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* MCP Status */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-cyan-400" />
                  Model Context Protocol (MCP)
                </CardTitle>
                <CardDescription>Governed tool bus for agent operations</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Tools Registered</span>
                    <span className="text-white">{dashboard?.mcp?.tools_registered}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Pending Requests</span>
                    <span className="text-white">{dashboard?.mcp?.pending_requests}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Total Executions</span>
                    <span className="text-white">{dashboard?.mcp?.total_executions}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* VNS Status */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Network className="w-5 h-5 text-green-400" />
                  Virtual Network Sensor (VNS)
                </CardTitle>
                <CardDescription>Independent network truth source</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Total Flows</span>
                    <span className="text-white">{dashboard?.vns?.total_flows}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Suspicious DNS</span>
                    <span className="text-red-400">{dashboard?.vns?.suspicious_dns}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Beacon Detections</span>
                    <span className="text-orange-400">{dashboard?.vns?.beacon_detections}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">TLS Fingerprints</span>
                    <span className="text-white">{dashboard?.vns?.tls_fingerprints}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quantum Status */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-yellow-400" />
                  Quantum Security
                </CardTitle>
                <CardDescription>Post-quantum cryptography</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Mode</span>
                    <Badge variant="outline">{dashboard?.quantum?.mode}</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Kyber Keys</span>
                    <span className="text-white">{dashboard?.quantum?.keypairs?.kyber}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Dilithium Keys</span>
                    <span className="text-white">{dashboard?.quantum?.keypairs?.dilithium}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    Algorithms: {dashboard?.quantum?.algorithms?.kem?.join(", ")}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* AI Status */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Brain className="w-5 h-5 text-pink-400" />
                  AI Reasoning Engine
                </CardTitle>
                <CardDescription>Local threat analysis with Ollama</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">MITRE Techniques</span>
                    <span className="text-white">{dashboard?.ai?.mitre_techniques_loaded}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Threat Patterns</span>
                    <span className="text-white">{dashboard?.ai?.threat_patterns_loaded}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Ollama</span>
                    <Badge variant={dashboard?.ai?.ollama?.status === "connected" ? "success" : "secondary"}>
                      {dashboard?.ai?.ollama?.status}
                    </Badge>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    {dashboard?.ai?.ollama?.note}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* MCP Tab */}
        <TabsContent value="mcp" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-white">MCP Tool Registry</CardTitle>
                <Button onClick={fetchMCPTools} variant="outline" size="sm">
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Load Tools
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {mcpTools.length === 0 ? (
                <p className="text-slate-400 text-center py-4">Click "Load Tools" to view available MCP tools</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {mcpTools.map((tool) => (
                    <div key={tool.tool_id} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                      <div className="flex items-center gap-2 mb-2">
                        <Terminal className="w-4 h-4 text-cyan-400" />
                        <span className="font-medium text-white">{tool.name}</span>
                      </div>
                      <p className="text-sm text-slate-400 mb-2">{tool.description}</p>
                      <div className="flex gap-2">
                        <Badge variant="outline">{tool.category}</Badge>
                        <Badge variant="secondary">v{tool.version}</Badge>
                      </div>
                      <div className="mt-2 text-xs text-slate-500">
                        Trust: {tool.required_trust_state} | Rate: {tool.rate_limit}/hr
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vector Memory Tab */}
        <TabsContent value="memory" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Semantic Memory Search</CardTitle>
              <CardDescription>Search incident cases and threat intel by meaning</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 mb-4">
                <Input
                  placeholder="Search for threats, incidents, IOCs..."
                  value={memoryQuery}
                  onChange={(e) => setMemoryQuery(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && searchMemory()}
                  className="bg-slate-800 border-slate-700"
                  data-testid="memory-search-input"
                />
                <Button onClick={searchMemory} disabled={searchingMemory}>
                  <Search className="w-4 h-4 mr-2" />
                  {searchingMemory ? "Searching..." : "Search"}
                </Button>
              </div>
              {memoryResults.length > 0 && (
                <div className="space-y-2">
                  {memoryResults.map((result) => (
                    <div key={result.entry_id} className="p-3 bg-slate-800/50 rounded border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <Badge variant="outline">{result.namespace}</Badge>
                        <span className="text-xs text-slate-400">
                          Similarity: {(result.similarity * 100).toFixed(1)}%
                        </span>
                      </div>
                      <p className="text-sm text-slate-300">{result.content}</p>
                      <div className="flex gap-2 mt-2">
                        <Badge variant="secondary">{result.trust_level}</Badge>
                        <span className="text-xs text-slate-500">
                          Confidence: {(result.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Memory Statistics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-purple-400">{dashboard?.memory?.total_entries || 0}</p>
                  <p className="text-sm text-slate-400">Total Entries</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-blue-400">{dashboard?.memory?.total_cases || 0}</p>
                  <p className="text-sm text-slate-400">Incident Cases</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-red-400">{dashboard?.memory?.total_intel || 0}</p>
                  <p className="text-sm text-slate-400">Threat Intel</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-cyan-400">{dashboard?.memory?.embedding_dimension || 128}</p>
                  <p className="text-sm text-slate-400">Embedding Dim</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* VNS Tab */}
        <TabsContent value="vns" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-white">Suspicious Flows</CardTitle>
                  <Button onClick={fetchVNSFlows} variant="outline" size="sm">
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {vnsFlows.length === 0 ? (
                  <p className="text-slate-400 text-center py-4">No suspicious flows detected</p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {vnsFlows.map((flow) => (
                      <div key={flow.flow_id} className="p-3 bg-slate-800/50 rounded border border-red-900/50">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-mono text-sm">
                            {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}
                          </span>
                          <Badge variant="destructive">{flow.threat_score}</Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          {flow.direction} | {flow.service}
                        </div>
                        {flow.threat_indicators?.length > 0 && (
                          <div className="mt-2">
                            {flow.threat_indicators.map((ind, i) => (
                              <Badge key={i} variant="outline" className="mr-1 text-xs">{ind}</Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-white">C2 Beacon Detections</CardTitle>
                  <Button onClick={fetchVNSBeacons} variant="outline" size="sm">
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {vnsBeacons.length === 0 ? (
                  <p className="text-slate-400 text-center py-4">No beacons detected</p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {vnsBeacons.map((beacon) => (
                      <div key={beacon.detection_id} className="p-3 bg-slate-800/50 rounded border border-orange-900/50">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-mono text-sm">
                            {beacon.src_ip} → {beacon.dst_ip}:{beacon.dst_port}
                          </span>
                          <Badge variant={beacon.is_confirmed ? "destructive" : "secondary"}>
                            {beacon.is_confirmed ? "Confirmed" : "Suspected"}
                          </Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          Interval: {beacon.interval_seconds?.toFixed(1)}s | Jitter: {beacon.interval_jitter?.toFixed(2)}
                        </div>
                        <div className="text-xs text-slate-500">
                          Confidence: {(beacon.confidence * 100).toFixed(0)}% | Algorithm: {beacon.algorithm}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">VNS Statistics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-green-400">{dashboard?.vns?.total_flows || 0}</p>
                  <p className="text-sm text-slate-400">Total Flows</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-red-400">{dashboard?.vns?.suspicious_flows || 0}</p>
                  <p className="text-sm text-slate-400">Suspicious</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-blue-400">{dashboard?.vns?.total_dns_queries || 0}</p>
                  <p className="text-sm text-slate-400">DNS Queries</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-orange-400">{dashboard?.vns?.beacon_detections || 0}</p>
                  <p className="text-sm text-slate-400">Beacons</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-purple-400">{dashboard?.vns?.tls_fingerprints || 0}</p>
                  <p className="text-sm text-slate-400">TLS FPs</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Quantum Tab */}
        <TabsContent value="quantum" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Quantum Key Generation</CardTitle>
              <CardDescription>Generate post-quantum cryptographic keys</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
                  <h3 className="font-medium text-white mb-2">KYBER (Key Encapsulation)</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    NIST-selected post-quantum KEM. Used for key exchange.
                  </p>
                  <Button onClick={() => generateQuantumKey("kyber")} className="w-full">
                    <Key className="w-4 h-4 mr-2" />
                    Generate KYBER-768 Keypair
                  </Button>
                </div>
                <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
                  <h3 className="font-medium text-white mb-2">DILITHIUM (Digital Signatures)</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    NIST-selected post-quantum signature scheme.
                  </p>
                  <Button onClick={() => generateQuantumKey("dilithium")} className="w-full">
                    <Shield className="w-4 h-4 mr-2" />
                    Generate DILITHIUM-3 Keypair
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Quantum Security Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400">Mode</span>
                  <Badge variant="outline">{dashboard?.quantum?.mode}</Badge>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400">Hash Algorithm</span>
                  <span className="text-white font-mono">{dashboard?.quantum?.algorithms?.hash}</span>
                </div>
                <div className="p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400 block mb-2">Supported KEM Algorithms</span>
                  <div className="flex gap-2">
                    {dashboard?.quantum?.algorithms?.kem?.map((alg) => (
                      <Badge key={alg} variant="secondary">{alg}</Badge>
                    ))}
                  </div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400 block mb-2">Supported Signature Algorithms</span>
                  <div className="flex gap-2">
                    {dashboard?.quantum?.algorithms?.signatures?.map((alg) => (
                      <Badge key={alg} variant="secondary">{alg}</Badge>
                    ))}
                  </div>
                </div>
                <div className="p-3 bg-yellow-900/20 border border-yellow-700/50 rounded text-sm text-yellow-300">
                  {dashboard?.quantum?.note}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Tab */}
        <TabsContent value="ai" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Ollama Configuration */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Settings className="w-5 h-5" />
                  Ollama Configuration
                </CardTitle>
                <CardDescription>Configure local LLM for enhanced reasoning</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-slate-400 block mb-1">Ollama URL</label>
                    <Input
                      value={ollamaConfig.base_url}
                      onChange={(e) => setOllamaConfig({ ...ollamaConfig, base_url: e.target.value })}
                      placeholder="http://host.docker.internal:11434"
                      className="bg-slate-800 border-slate-700"
                      data-testid="ollama-url-input"
                    />
                    <p className="text-xs text-slate-500 mt-1">
                      Use <code>http://host.docker.internal:11434</code> when Ollama runs on the host.
                    </p>
                  </div>
                  <div>
                    <label className="text-sm text-slate-400 block mb-1">Model</label>
                    <Input
                      value={ollamaConfig.model}
                      onChange={(e) => setOllamaConfig({ ...ollamaConfig, model: e.target.value })}
                      placeholder="mistral"
                      className="bg-slate-800 border-slate-700"
                    />
                  </div>
                  <Button onClick={configureOllama} className="w-full">
                    <Zap className="w-4 h-4 mr-2" />
                    Connect to Ollama
                  </Button>
                  <div className="p-3 bg-slate-800/50 rounded">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Status</span>
                      <Badge variant={dashboard?.ai?.ollama?.status === "connected" ? "success" : "secondary"}>
                        {dashboard?.ai?.ollama?.status}
                      </Badge>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* AI Query */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <MessageSquare className="w-5 h-5" />
                  Security Query
                </CardTitle>
                <CardDescription>Ask about MITRE techniques, threats, and responses</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <Input
                    value={aiQuery}
                    onChange={(e) => setAiQuery(e.target.value)}
                    onKeyPress={(e) => e.key === "Enter" && queryAI()}
                    placeholder="e.g., Tell me about MITRE technique T1003"
                    className="bg-slate-800 border-slate-700"
                    data-testid="ai-query-input"
                  />
                  <Button onClick={queryAI} className="w-full">
                    <Brain className="w-4 h-4 mr-2" />
                    Query AI
                  </Button>
                  {aiResponse && (
                    <div className="p-3 bg-slate-800/50 rounded border border-slate-700">
                      <p className="text-white mb-2">{aiResponse.conclusion}</p>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">Confidence: {(aiResponse.confidence * 100).toFixed(0)}%</Badge>
                        <span className="text-xs text-slate-500">{aiResponse.model_used}</span>
                      </div>
                      {aiResponse.recommendations?.length > 0 && (
                        <div className="mt-2">
                          <span className="text-xs text-slate-400">Recommendations:</span>
                          <ul className="list-disc list-inside text-sm text-slate-300 mt-1">
                            {aiResponse.recommendations.map((rec, i) => (
                              <li key={i}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Threat Analysis */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                Threat Analysis
              </CardTitle>
              <CardDescription>Analyze threats with AI reasoning</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <Input
                  value={analyzeData.title}
                  onChange={(e) => setAnalyzeData({ ...analyzeData, title: e.target.value })}
                  placeholder="Threat title (e.g., Mimikatz Detected)"
                  className="bg-slate-800 border-slate-700"
                  data-testid="analyze-title-input"
                />
                <Input
                  value={analyzeData.description}
                  onChange={(e) => setAnalyzeData({ ...analyzeData, description: e.target.value })}
                  placeholder="Description"
                  className="bg-slate-800 border-slate-700"
                />
                <Input
                  value={analyzeData.command_line}
                  onChange={(e) => setAnalyzeData({ ...analyzeData, command_line: e.target.value })}
                  placeholder="Command line (optional)"
                  className="bg-slate-800 border-slate-700"
                />
              </div>
              <Button onClick={analyzeThreat} className="mb-4">
                <Eye className="w-4 h-4 mr-2" />
                Analyze Threat
              </Button>
              {aiAnalysis && (
                <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-white">{aiAnalysis.threat_type?.replace(/_/g, " ")}</h3>
                    <div className="flex gap-2">
                      <Badge variant={aiAnalysis.severity === "critical" ? "destructive" : "secondary"}>
                        {aiAnalysis.severity}
                      </Badge>
                      <Badge variant="outline">Risk: {aiAnalysis.risk_score}/100</Badge>
                    </div>
                  </div>
                  <p className="text-slate-300 mb-4">{aiAnalysis.description}</p>
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <span className="text-sm text-slate-400">MITRE Techniques</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {aiAnalysis.mitre_techniques?.map((t) => (
                          <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <span className="text-sm text-slate-400">Playbook</span>
                      <p className="text-white font-mono text-sm mt-1">{aiAnalysis.playbook_id || "None"}</p>
                    </div>
                  </div>
                  <div>
                    <span className="text-sm text-slate-400">Recommended Actions</span>
                    <ul className="list-disc list-inside text-sm text-slate-300 mt-1">
                      {aiAnalysis.recommended_actions?.slice(0, 5).map((action, i) => (
                        <li key={i}>{action}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
