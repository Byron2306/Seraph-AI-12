import { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  FileText, 
  Download,
  Brain,
  RefreshCw,
  AlertTriangle,
  Shield,
  TrendingUp,
  Clock
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const ReportsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(false);
  const [aiSummary, setAiSummary] = useState(null);
  const [generatingSummary, setGeneratingSummary] = useState(false);

  const downloadPDFReport = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/reports/threat-intelligence`, {
        headers: getAuthHeaders(),
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `threat_report_${new Date().toISOString().split('T')[0]}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      toast.success('Report downloaded successfully');
    } catch (error) {
      if (error.response?.status === 403) {
        toast.error('Permission denied. Export permission required.');
      } else {
        toast.error('Failed to generate report');
      }
    } finally {
      setLoading(false);
    }
  };

  const generateAISummary = async () => {
    setGeneratingSummary(true);
    try {
      const response = await axios.post(`${API}/reports/ai-summary`, {}, {
        headers: getAuthHeaders()
      });
      setAiSummary(response.data);
      toast.success('AI summary generated');
    } catch (error) {
      if (error.response?.status === 403) {
        toast.error('Permission denied. Export permission required.');
      } else {
        toast.error('Failed to generate AI summary');
      }
    } finally {
      setGeneratingSummary(false);
    }
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="reports-page">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
          <FileText className="w-7 h-7 text-emerald-400" />
          Reports & Intelligence
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Generate threat intelligence reports and AI-powered summaries
        </p>
      </div>

      {/* Report Options */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* PDF Report Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded overflow-hidden"
        >
          <div className="p-6 border-b border-slate-800 bg-emerald-500/10">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded bg-emerald-500/20 flex items-center justify-center">
                <FileText className="w-6 h-6 text-emerald-400" />
              </div>
              <div>
                <h3 className="font-mono font-semibold text-white">Threat Intelligence Report</h3>
                <p className="text-sm text-slate-400">Comprehensive PDF report</p>
              </div>
            </div>
          </div>
          
          <div className="p-6 space-y-4">
            <p className="text-sm text-slate-400">
              Generate a detailed PDF report including:
            </p>
            <ul className="space-y-2 text-sm">
              {[
                'Executive summary with key metrics',
                'Active threat analysis',
                'Recent alerts overview',
                'System health status',
                'Threat distribution charts'
              ].map((item, i) => (
                <li key={i} className="flex items-center gap-2 text-slate-300">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  {item}
                </li>
              ))}
            </ul>
            
            <Button
              onClick={downloadPDFReport}
              disabled={loading}
              className="w-full bg-emerald-600 hover:bg-emerald-500 shadow-glow-green"
              data-testid="download-pdf-btn"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Generating...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Download className="w-4 h-4" />
                  Download PDF Report
                </span>
              )}
            </Button>
          </div>
        </motion.div>

        {/* AI Summary Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded overflow-hidden"
        >
          <div className="p-6 border-b border-slate-800 bg-purple-500/10">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded bg-purple-500/20 flex items-center justify-center">
                <Brain className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <h3 className="font-mono font-semibold text-white">AI Executive Summary</h3>
                <p className="text-sm text-slate-400">GPT-4o powered analysis</p>
              </div>
            </div>
          </div>
          
          <div className="p-6 space-y-4">
            <p className="text-sm text-slate-400">
              Get an AI-generated executive summary:
            </p>
            <ul className="space-y-2 text-sm">
              {[
                'Overall risk assessment',
                'Key findings and insights',
                'Recommended immediate actions',
                'Trend analysis',
                'Threat actor attribution'
              ].map((item, i) => (
                <li key={i} className="flex items-center gap-2 text-slate-300">
                  <TrendingUp className="w-4 h-4 text-purple-400" />
                  {item}
                </li>
              ))}
            </ul>
            
            <Button
              onClick={generateAISummary}
              disabled={generatingSummary}
              className="w-full bg-purple-600 hover:bg-purple-500 shadow-glow-purple"
              data-testid="generate-ai-summary-btn"
            >
              {generatingSummary ? (
                <span className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analyzing...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Brain className="w-4 h-4" />
                  Generate AI Summary
                </span>
              )}
            </Button>
          </div>
        </motion.div>
      </div>

      {/* AI Summary Result */}
      {aiSummary && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-900/50 backdrop-blur-md border border-purple-500/30 rounded overflow-hidden"
        >
          <div className="p-4 border-b border-slate-800 bg-purple-500/10 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Brain className="w-5 h-5 text-purple-400" />
              <h3 className="font-mono font-semibold text-white">AI Executive Summary</h3>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Clock className="w-3 h-3" />
              {new Date(aiSummary.generated_at).toLocaleString()}
            </div>
          </div>
          
          <div className="p-6">
            <div className="flex items-center gap-4 mb-4">
              <Badge variant="outline" className="text-purple-400 border-purple-500/50">
                {aiSummary.data_points.threats_analyzed} threats analyzed
              </Badge>
              <Badge variant="outline" className="text-purple-400 border-purple-500/50">
                {aiSummary.data_points.alerts_analyzed} alerts analyzed
              </Badge>
            </div>
            
            <ScrollArea className="h-80">
              <div className="prose prose-invert prose-sm max-w-none">
                <pre className="whitespace-pre-wrap bg-slate-950/50 p-4 rounded font-sans text-slate-300 text-sm leading-relaxed">
                  {aiSummary.summary}
                </pre>
              </div>
            </ScrollArea>
          </div>
          
          <div className="p-4 border-t border-slate-800 flex items-center justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              className="border-slate-700 text-slate-400"
              onClick={generateAISummary}
              data-testid="regenerate-summary-btn"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Regenerate
            </Button>
          </div>
        </motion.div>
      )}

      {/* Report History */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-6"
      >
        <h3 className="font-mono font-semibold text-white mb-4">Report Types Available</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { 
              title: 'Threat Intelligence', 
              desc: 'Complete threat landscape overview', 
              format: 'PDF',
              icon: AlertTriangle,
              color: 'red'
            },
            { 
              title: 'AI Executive Summary', 
              desc: 'AI-powered threat analysis', 
              format: 'JSON/Text',
              icon: Brain,
              color: 'purple'
            },
            { 
              title: 'Network Analysis', 
              desc: 'Topology and attack vectors', 
              format: 'Coming Soon',
              icon: Shield,
              color: 'cyan'
            }
          ].map((report, i) => (
            <div 
              key={i} 
              className="p-4 bg-slate-800/30 border border-slate-700 rounded"
            >
              <div className="flex items-center gap-3 mb-2">
                <report.icon className={`w-5 h-5 text-${report.color}-400`} />
                <h4 className="font-medium text-white">{report.title}</h4>
              </div>
              <p className="text-xs text-slate-400 mb-2">{report.desc}</p>
              <Badge variant="outline" className="text-xs text-slate-500 border-slate-600">
                {report.format}
              </Badge>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );
};

export default ReportsPage;
