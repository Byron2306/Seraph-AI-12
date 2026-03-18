import { useState, useEffect, useRef } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Activity,
  AlertTriangle,
  Shield,
  RefreshCw,
  Filter,
  Maximize2,
  Download,
  ZoomIn,
  ZoomOut,
  Map
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

export default function TacticalHeatmapPage() {
  const { token } = useAuth();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState("24h");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [heatmapData, setHeatmapData] = useState([]);
  const canvasRef = useRef(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 30000);
    return () => clearInterval(interval);
  }, [timeRange, filterSeverity]);

  useEffect(() => {
    if (heatmapData.length > 0) {
      drawHeatmap();
    }
  }, [heatmapData]);

  const fetchThreats = async () => {
    try {
      const response = await fetch(`${API_URL}/api/threats?limit=200`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      
      // Process threats for heatmap
      const processedThreats = (data.threats || data || []).map(t => ({
        ...t,
        x: Math.random() * 100,
        y: Math.random() * 100,
        intensity: getSeverityIntensity(t.severity)
      }));
      
      setThreats(processedThreats);
      calculateStats(processedThreats);
      processHeatmapData(processedThreats);
    } catch (error) {
      toast.error("Failed to fetch threat data");
    } finally {
      setLoading(false);
    }
  };

  const getSeverityIntensity = (severity) => {
    const map = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25 };
    return map[severity?.toLowerCase()] || 0.3;
  };

  const calculateStats = (threatList) => {
    const stats = {
      total: threatList.length,
      critical: threatList.filter(t => t.severity === "critical").length,
      high: threatList.filter(t => t.severity === "high").length,
      medium: threatList.filter(t => t.severity === "medium").length,
      low: threatList.filter(t => t.severity === "low").length
    };
    setStats(stats);
  };

  const processHeatmapData = (threatList) => {
    // Group threats by type and severity for heatmap visualization
    const typeGroups = {};
    
    threatList.forEach(threat => {
      const type = threat.type || "unknown";
      if (!typeGroups[type]) {
        typeGroups[type] = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
      }
      typeGroups[type][threat.severity || "low"]++;
      typeGroups[type].total++;
    });
    
    // Convert to array for visualization
    const heatData = Object.entries(typeGroups).map(([type, counts], index) => ({
      type,
      ...counts,
      x: (index % 5) * 20 + 10,
      y: Math.floor(index / 5) * 20 + 10,
      intensity: (counts.critical * 4 + counts.high * 3 + counts.medium * 2 + counts.low) / (counts.total * 4)
    }));
    
    setHeatmapData(heatData);
  };

  const drawHeatmap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    
    // Clear canvas
    ctx.fillStyle = "#0f172a";
    ctx.fillRect(0, 0, width, height);
    
    // Draw grid
    ctx.strokeStyle = "#1e293b";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 10; i++) {
      ctx.beginPath();
      ctx.moveTo(i * (width / 10), 0);
      ctx.lineTo(i * (width / 10), height);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(0, i * (height / 10));
      ctx.lineTo(width, i * (height / 10));
      ctx.stroke();
    }
    
    // Draw heat spots for each threat type
    heatmapData.forEach((data) => {
      const x = (data.x / 100) * width;
      const y = (data.y / 100) * height;
      const radius = Math.max(30, data.total * 5);
      
      // Create radial gradient
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius);
      
      // Color based on intensity
      if (data.intensity > 0.7) {
        gradient.addColorStop(0, "rgba(239, 68, 68, 0.9)"); // Red
        gradient.addColorStop(0.5, "rgba(239, 68, 68, 0.5)");
        gradient.addColorStop(1, "rgba(239, 68, 68, 0)");
      } else if (data.intensity > 0.4) {
        gradient.addColorStop(0, "rgba(249, 115, 22, 0.9)"); // Orange
        gradient.addColorStop(0.5, "rgba(249, 115, 22, 0.5)");
        gradient.addColorStop(1, "rgba(249, 115, 22, 0)");
      } else {
        gradient.addColorStop(0, "rgba(34, 197, 94, 0.9)"); // Green
        gradient.addColorStop(0.5, "rgba(34, 197, 94, 0.5)");
        gradient.addColorStop(1, "rgba(34, 197, 94, 0)");
      }
      
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();
      
      // Draw label
      ctx.fillStyle = "#ffffff";
      ctx.font = "12px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(data.type.slice(0, 15), x, y + radius + 15);
      ctx.fillText(`(${data.total})`, x, y + radius + 28);
    });
    
    // Draw legend
    ctx.fillStyle = "#94a3b8";
    ctx.font = "11px Inter, sans-serif";
    ctx.textAlign = "left";
    ctx.fillText("Threat Intensity:", 10, height - 40);
    
    // Legend colors
    const legendColors = [
      { color: "#22c55e", label: "Low" },
      { color: "#f97316", label: "Medium" },
      { color: "#ef4444", label: "High/Critical" }
    ];
    
    legendColors.forEach((item, i) => {
      ctx.fillStyle = item.color;
      ctx.fillRect(10 + i * 80, height - 30, 15, 15);
      ctx.fillStyle = "#94a3b8";
      ctx.fillText(item.label, 30 + i * 80, height - 18);
    });
  };

  const exportHeatmap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const link = document.createElement("a");
    link.download = `seraph-heatmap-${new Date().toISOString().split("T")[0]}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
    toast.success("Heatmap exported");
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Tactical Heatmap...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Map className="w-6 h-6 text-red-500" />
            Tactical Threat Heatmap
          </h1>
          <p className="text-slate-400">AI-prioritized threat visualization</p>
        </div>
        <div className="flex gap-2">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-32 bg-slate-800 border-slate-700">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last Hour</SelectItem>
              <SelectItem value="24h">Last 24h</SelectItem>
              <SelectItem value="7d">Last 7 Days</SelectItem>
              <SelectItem value="30d">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
          <Select value={filterSeverity} onValueChange={setFilterSeverity}>
            <SelectTrigger className="w-32 bg-slate-800 border-slate-700">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={fetchThreats} variant="outline" size="icon">
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button onClick={exportHeatmap} variant="outline" size="icon">
            <Download className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-slate-900/50 border-slate-800" data-testid="stat-total">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Total Threats</p>
                <p className="text-2xl font-bold text-white">{stats.total}</p>
              </div>
              <Shield className="w-8 h-8 text-cyan-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-red-900/50" data-testid="stat-critical">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Critical</p>
                <p className="text-2xl font-bold text-red-500">{stats.critical}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-orange-900/50" data-testid="stat-high">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">High</p>
                <p className="text-2xl font-bold text-orange-500">{stats.high}</p>
              </div>
              <Activity className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-yellow-900/50" data-testid="stat-medium">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Medium</p>
                <p className="text-2xl font-bold text-yellow-500">{stats.medium}</p>
              </div>
              <Activity className="w-8 h-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-green-900/50" data-testid="stat-low">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Low</p>
                <p className="text-2xl font-bold text-green-500">{stats.low}</p>
              </div>
              <Activity className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Heatmap Canvas */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Threat Distribution Heatmap</CardTitle>
          <CardDescription>Visual representation of threat concentration by type</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <canvas
              ref={canvasRef}
              width={800}
              height={500}
              className="w-full rounded-lg border border-slate-700"
              style={{ maxHeight: "500px" }}
              data-testid="heatmap-canvas"
            />
          </div>
        </CardContent>
      </Card>

      {/* Threat Type Breakdown */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Threat Type Analysis</CardTitle>
          <CardDescription>Breakdown by threat category</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {heatmapData.map((data) => (
              <div
                key={data.type}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700"
              >
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-medium text-white">{data.type.replace(/_/g, " ")}</h3>
                  <Badge variant={data.intensity > 0.7 ? "destructive" : data.intensity > 0.4 ? "secondary" : "outline"}>
                    {data.total}
                  </Badge>
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between text-sm">
                    <span className="text-red-400">Critical</span>
                    <span className="text-white">{data.critical}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-orange-400">High</span>
                    <span className="text-white">{data.high}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-yellow-400">Medium</span>
                    <span className="text-white">{data.medium}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-green-400">Low</span>
                    <span className="text-white">{data.low}</span>
                  </div>
                </div>
                {/* Intensity bar */}
                <div className="mt-3 h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      data.intensity > 0.7 ? "bg-red-500" : data.intensity > 0.4 ? "bg-orange-500" : "bg-green-500"
                    }`}
                    style={{ width: `${data.intensity * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
