import React, { useEffect, useState } from 'react';
import { Card, CardContent } from '../components/ui/card';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Button } from '../components/ui/button';
import { Shield, Database, Eye, Zap, TrendingUp, Clock } from 'lucide-react';

const API = process.env.REACT_APP_BACKEND_URL ? `${process.env.REACT_APP_BACKEND_URL}/api` : '/api';

const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4'];

export default function AggregatedEDMDLPPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(`${API}/edm-dlp/aggregated-stats`);
        if (response.ok) {
          const data = await response.json();
          setStats(data);
        }
      } catch (error) {
        // Handle error
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center"><div className="text-blue-500 font-mono animate-pulse">Loading EDM/DLP telemetry...</div></div>;
  }

  // Example chart data
  const edmHitData = stats?.edm_hits_timeline || [];
  const dlpScanData = stats?.dlp_scans_timeline || [];
  const edmPieData = stats?.edm_hits_by_dataset || [];
  const dlpPieData = stats?.dlp_policy_violations || [];

  // Example test payload for backend EDM/DLP aggregation
  const testPayload = {
    agent_id: 'test-agent-001',
    status: 'online',
    cpu_usage: 12.5,
    memory_usage: 34.2,
    disk_usage: 78.1,
    threat_count: 2,
    network_connections: 5,
    alerts: [],
    telemetry: {},
    edm_hits: [
      {
        dataset_id: 'edm-dataset-01',
        record_id: 'rec-123',
        fingerprint: 'abc123def456',
        host: 'host-01',
        process: 'proc-01',
        file_path_masked: '/tmp/file.txt',
        source: 'dlp',
        timestamp: new Date().toISOString(),
        additional_info: 'Test EDM hit'
      }
    ],
    monitors: {
      dlp: {
        scans: 10,
        policy_violations: 2,
        suppression_events: 1,
        timeline: [
          { time: '2026-03-07T12:00:00Z', scans: 2, violations: 0 },
          { time: '2026-03-07T13:00:00Z', scans: 3, violations: 1 },
          { time: '2026-03-07T14:00:00Z', scans: 5, violations: 1 }
        ]
      }
    }
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="aggregated-edm-dlp-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white">Aggregated EDM & DLP Telemetry</h1>
          <p className="text-slate-400 text-sm mt-1">Global view of exact data match and data loss prevention events</p>
        </div>
        <Button variant="outline" className="border-slate-700 text-slate-300 hover:bg-slate-800" onClick={() => window.location.reload()}>
          <TrendingUp className="w-4 h-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">EDM Hits</p>
                <p className="text-xl font-bold text-blue-400">{stats?.total_edm_hits || 0}</p>
              </div>
              <Database className="w-6 h-6 text-blue-500" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">DLP Scans</p>
                <p className="text-xl font-bold text-amber-400">{stats?.total_dlp_scans || 0}</p>
              </div>
              <Eye className="w-6 h-6 text-amber-500" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Policy Violations</p>
                <p className="text-xl font-bold text-red-400">{stats?.total_policy_violations || 0}</p>
              </div>
              <Shield className="w-6 h-6 text-red-500" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400">Suppression Events</p>
                <p className="text-xl font-bold text-purple-400">{stats?.total_suppression_events || 0}</p>
              </div>
              <Zap className="w-6 h-6 text-purple-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Timeline Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <h3 className="font-mono font-semibold text-white mb-2">EDM Hits Timeline</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={edmHitData}>
                  <XAxis dataKey="time" tick={{ fill: '#64748B', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#64748B', fontSize: 10 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #1E293B', borderRadius: '4px' }} labelStyle={{ color: '#94A3B8' }} />
                  <Area type="monotone" dataKey="hits" stroke="#3b82f6" fillOpacity={1} fill="#3b82f6" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <h3 className="font-mono font-semibold text-white mb-2">DLP Scans Timeline</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={dlpScanData}>
                  <XAxis dataKey="time" tick={{ fill: '#64748B', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#64748B', fontSize: 10 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #1E293B', borderRadius: '4px' }} labelStyle={{ color: '#94A3B8' }} />
                  <Area type="monotone" dataKey="scans" stroke="#f59e0b" fillOpacity={1} fill="#f59e0b" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Pie Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <h3 className="font-mono font-semibold text-white mb-2">EDM Hits by Dataset</h3>
            <PieChart width={300} height={200}>
              <Pie data={edmPieData} dataKey="value" nameKey="dataset" cx="50%" cy="50%" outerRadius={80}>
                {edmPieData.map((entry, index) => (
                  <Cell key={`cell-edm-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #1E293B', borderRadius: '4px' }} />
            </PieChart>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <h3 className="font-mono font-semibold text-white mb-2">DLP Policy Violations</h3>
            <PieChart width={300} height={200}>
              <Pie data={dlpPieData} dataKey="value" nameKey="policy" cx="50%" cy="50%" outerRadius={80}>
                {dlpPieData.map((entry, index) => (
                  <Cell key={`cell-dlp-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #1E293B', borderRadius: '4px' }} />
            </PieChart>
          </CardContent>
        </Card>
      </div>

      {/* Timeline Feed */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardContent className="p-4">
          <h3 className="font-mono font-semibold text-white mb-2">EDM/DLP Event Timeline</h3>
          <ScrollArea className="h-80">
            <div className="space-y-3">
              {stats?.event_timeline?.length > 0 ? (
                stats.event_timeline.map((event, idx) => (
                  <div key={idx} className="flex items-center gap-3 p-3 bg-slate-800/30 rounded">
                    <Badge variant="outline" className="text-blue-400 border-blue-500/50 text-xs flex-shrink-0">
                      {event.type}
                    </Badge>
                    <span className="text-xs text-slate-400">{event.description}</span>
                    <span className="text-xs text-slate-500 ml-auto">{new Date(event.timestamp).toLocaleString()}</span>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <Clock className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No EDM/DLP events</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
