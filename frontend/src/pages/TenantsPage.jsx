import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Building2,
  Users,
  Shield,
  Plus,
  RefreshCw,
  CheckCircle,
  XCircle,
  Crown,
  Zap,
  Activity,
  Key,
  Settings,
  Trash2
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

export default function TenantsPage() {
  const { token } = useAuth();
  const [tenants, setTenants] = useState([]);
  const [stats, setStats] = useState(null);
  const [tiers, setTiers] = useState({});
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newTenant, setNewTenant] = useState({
    name: "",
    contact_email: "",
    tier: "starter",
    trial_days: 14
  });

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      
      const [tenantsRes, statsRes, tiersRes] = await Promise.all([
        fetch(`${API_URL}/api/tenants/`, { headers }),
        fetch(`${API_URL}/api/tenants/stats`, { headers }),
        fetch(`${API_URL}/api/tenants/tiers`, { headers })
      ]);
      
      const tenantsData = await tenantsRes.json();
      const statsData = await statsRes.json();
      const tiersData = await tiersRes.json();
      
      setTenants(tenantsData.tenants || []);
      setStats(statsData);
      setTiers(tiersData);
    } catch (error) {
      toast.error("Failed to load tenant data");
    } finally {
      setLoading(false);
    }
  };

  const createTenant = async () => {
    try {
      const response = await fetch(`${API_URL}/api/tenants/`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(newTenant)
      });
      
      if (response.ok) {
        toast.success("Tenant created successfully");
        setShowCreateForm(false);
        setNewTenant({ name: "", contact_email: "", tier: "starter", trial_days: 14 });
        fetchData();
      } else {
        const error = await response.json();
        toast.error(error.detail || "Failed to create tenant");
      }
    } catch (error) {
      toast.error("Error creating tenant");
    }
  };

  const deleteTenant = async (tenantId) => {
    if (!confirm("Are you sure you want to suspend this tenant?")) return;
    
    try {
      const response = await fetch(`${API_URL}/api/tenants/${tenantId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        toast.success("Tenant suspended");
        fetchData();
      } else {
        toast.error("Failed to suspend tenant");
      }
    } catch (error) {
      toast.error("Error suspending tenant");
    }
  };

  const generateApiKey = async (tenantId) => {
    try {
      const response = await fetch(`${API_URL}/api/tenants/${tenantId}/api-key`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        toast.success("API Key generated! Copy it now - it won't be shown again.");
        navigator.clipboard.writeText(data.api_key);
        toast.info("API key copied to clipboard");
      } else {
        toast.error("Failed to generate API key");
      }
    } catch (error) {
      toast.error("Error generating API key");
    }
  };

  const getTierBadge = (tier) => {
    const colors = {
      free: "bg-gray-500/20 text-gray-400 border-gray-500/30",
      starter: "bg-blue-500/20 text-blue-400 border-blue-500/30",
      professional: "bg-purple-500/20 text-purple-400 border-purple-500/30",
      enterprise: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    };
    return colors[tier] || colors.free;
  };

  const getStatusBadge = (status) => {
    const colors = {
      active: "bg-green-500/20 text-green-400 border-green-500/30",
      trial: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
      suspended: "bg-red-500/20 text-red-400 border-red-500/30",
      pending: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    };
    return colors[status] || colors.pending;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Tenants...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Building2 className="w-6 h-6 text-cyan-500" />
            Multi-Tenant Management
          </h1>
          <p className="text-slate-400">Manage organizations and their resource quotas</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchData} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={() => setShowCreateForm(true)} className="bg-cyan-600 hover:bg-cyan-700">
            <Plus className="w-4 h-4 mr-2" />
            New Tenant
          </Button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Total Tenants</p>
                  <p className="text-2xl font-bold text-white">{stats.total_tenants}</p>
                </div>
                <Building2 className="w-8 h-8 text-cyan-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Active</p>
                  <p className="text-2xl font-bold text-green-400">{stats.active_tenants}</p>
                </div>
                <CheckCircle className="w-8 h-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Total Users</p>
                  <p className="text-2xl font-bold text-blue-400">{stats.total_users}</p>
                </div>
                <Users className="w-8 h-8 text-blue-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Total Agents</p>
                  <p className="text-2xl font-bold text-purple-400">{stats.total_agents}</p>
                </div>
                <Shield className="w-8 h-8 text-purple-500" />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Create Tenant Form */}
      {showCreateForm && (
        <Card className="bg-slate-900/50 border-cyan-500/50">
          <CardHeader>
            <CardTitle className="text-white">Create New Tenant</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label className="text-slate-300">Organization Name</Label>
                <Input
                  placeholder="Acme Corporation"
                  value={newTenant.name}
                  onChange={(e) => setNewTenant({ ...newTenant, name: e.target.value })}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-slate-300">Contact Email</Label>
                <Input
                  type="email"
                  placeholder="admin@acme.com"
                  value={newTenant.contact_email}
                  onChange={(e) => setNewTenant({ ...newTenant, contact_email: e.target.value })}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-slate-300">Tier</Label>
                <div className="flex gap-2">
                  {["free", "starter", "professional", "enterprise"].map((tier) => (
                    <Button
                      key={tier}
                      variant={newTenant.tier === tier ? "default" : "outline"}
                      size="sm"
                      onClick={() => setNewTenant({ ...newTenant, tier })}
                      className={newTenant.tier === tier ? getTierBadge(tier) : ""}
                    >
                      {tier === "enterprise" && <Crown className="w-3 h-3 mr-1" />}
                      {tier.charAt(0).toUpperCase() + tier.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <Label className="text-slate-300">Trial Days</Label>
                <Input
                  type="number"
                  value={newTenant.trial_days}
                  onChange={(e) => setNewTenant({ ...newTenant, trial_days: parseInt(e.target.value) })}
                  className="bg-slate-800 border-slate-700 text-white w-24"
                  min={0}
                  max={90}
                />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => setShowCreateForm(false)}>Cancel</Button>
              <Button onClick={createTenant} className="bg-cyan-600 hover:bg-cyan-700">
                <Plus className="w-4 h-4 mr-2" />
                Create Tenant
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tenants List */}
      <Tabs defaultValue="list" className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="list">Tenants List</TabsTrigger>
          <TabsTrigger value="tiers">Tier Comparison</TabsTrigger>
        </TabsList>

        <TabsContent value="list">
          <div className="grid grid-cols-1 gap-4">
            {tenants.map((tenant) => (
              <Card key={tenant.id} className="bg-slate-900/50 border-slate-800 hover:border-slate-700 transition-colors">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 rounded-lg bg-slate-800 flex items-center justify-center">
                        <Building2 className="w-6 h-6 text-cyan-400" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium text-lg">{tenant.name}</h3>
                        <p className="text-slate-400 text-sm">{tenant.contact_email}</p>
                        <p className="text-slate-500 text-xs mt-1">ID: {tenant.id}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={getTierBadge(tenant.tier)}>
                        {tenant.tier === "enterprise" && <Crown className="w-3 h-3 mr-1" />}
                        {tenant.tier}
                      </Badge>
                      <Badge className={getStatusBadge(tenant.status)}>
                        {tenant.status}
                      </Badge>
                    </div>
                  </div>

                  <div className="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between">
                    <div className="flex gap-6 text-sm">
                      <div className="flex items-center gap-2">
                        <Users className="w-4 h-4 text-blue-400" />
                        <span className="text-slate-300">{tenant.users || 0} users</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-purple-400" />
                        <span className="text-slate-300">{tenant.agents || 0} agents</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Activity className="w-4 h-4 text-green-400" />
                        <span className="text-slate-300">Created: {new Date(tenant.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => generateApiKey(tenant.id)}
                        className="text-yellow-400 border-yellow-500/30 hover:bg-yellow-500/10"
                      >
                        <Key className="w-4 h-4 mr-1" />
                        API Key
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-red-400 border-red-500/30 hover:bg-red-500/10"
                        onClick={() => deleteTenant(tenant.id)}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="tiers">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {Object.entries(tiers).map(([tierName, tierData]) => (
              <Card key={tierName} className={`bg-slate-900/50 border-slate-800 ${tierName === 'enterprise' ? 'border-yellow-500/50' : ''}`}>
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    {tierName === 'enterprise' && <Crown className="w-5 h-5 text-yellow-400" />}
                    {tierData.name}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Agents</span>
                      <span className="text-white">{tierData.quota.max_agents === -1 ? 'Unlimited' : tierData.quota.max_agents}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Users</span>
                      <span className="text-white">{tierData.quota.max_users === -1 ? 'Unlimited' : tierData.quota.max_users}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Playbooks</span>
                      <span className="text-white">{tierData.quota.max_playbooks === -1 ? 'Unlimited' : tierData.quota.max_playbooks}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">API Calls/Day</span>
                      <span className="text-white">{tierData.quota.max_api_calls_per_day === -1 ? 'Unlimited' : tierData.quota.max_api_calls_per_day.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Storage</span>
                      <span className="text-white">{tierData.quota.max_storage_gb === -1 ? 'Unlimited' : `${tierData.quota.max_storage_gb} GB`}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Retention</span>
                      <span className="text-white">{tierData.quota.max_retention_days} days</span>
                    </div>
                  </div>
                  
                  <div className="pt-3 border-t border-slate-800">
                    <p className="text-xs text-slate-400 mb-2">Features:</p>
                    <div className="flex flex-wrap gap-1">
                      {tierData.quota.features.slice(0, 5).map((feature, i) => (
                        <Badge key={i} variant="outline" className="text-xs text-slate-300 border-slate-600">
                          {feature.replace(/_/g, ' ')}
                        </Badge>
                      ))}
                      {tierData.quota.features.length > 5 && (
                        <Badge variant="outline" className="text-xs text-slate-400">
                          +{tierData.quota.features.length - 5}
                        </Badge>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
