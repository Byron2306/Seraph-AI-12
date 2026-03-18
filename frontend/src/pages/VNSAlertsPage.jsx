import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Badge } from "../components/ui/badge";
import { Switch } from "../components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Bell,
  Mail,
  MessageSquare,
  Settings,
  Send,
  CheckCircle,
  XCircle,
  Activity,
  RefreshCw,
  Shield,
  AlertTriangle,
  Eye
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

export default function VNSAlertsPage() {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [testingSlack, setTestingSlack] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);
  const [savingConfig, setSavingConfig] = useState(false);
  
  // Configuration state
  const [slackWebhook, setSlackWebhook] = useState("");
  const [emailConfig, setEmailConfig] = useState({
    smtp_host: "",
    smtp_port: 587,
    smtp_user: "",
    smtp_password: "",
    from_address: "",
    to_addresses: ""
  });
  const [minSeverity, setMinSeverity] = useState("high");
  const [cooldownMinutes, setCooldownMinutes] = useState(5);

  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/api/advanced/alerts/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setStatus(data);
    } catch (error) {
      toast.error("Failed to fetch alert status");
    } finally {
      setLoading(false);
    }
  };

  const saveConfiguration = async () => {
    setSavingConfig(true);
    try {
      const response = await fetch(`${API_URL}/api/advanced/alerts/configure`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          slack_webhook: slackWebhook,
          email_config: {
            smtp_host: emailConfig.smtp_host,
            smtp_port: parseInt(emailConfig.smtp_port),
            smtp_user: emailConfig.smtp_user,
            smtp_password: emailConfig.smtp_password,
            from_address: emailConfig.from_address,
            to_addresses: emailConfig.to_addresses.split(",").map(e => e.trim()).filter(Boolean)
          },
          min_severity: minSeverity,
          cooldown_minutes: parseInt(cooldownMinutes)
        })
      });
      
      if (response.ok) {
        toast.success("Alert configuration saved");
        fetchStatus();
      } else {
        toast.error("Failed to save configuration");
      }
    } catch (error) {
      toast.error("Error saving configuration");
    } finally {
      setSavingConfig(false);
    }
  };

  const testAlert = async (channel) => {
    if (channel === "slack") setTestingSlack(true);
    else setTestingEmail(true);
    
    try {
      const response = await fetch(`${API_URL}/api/advanced/alerts/test`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ channel })
      });
      
      const data = await response.json();
      
      if (data.results?.[channel] === "success") {
        toast.success(`${channel === "slack" ? "Slack" : "Email"} test alert sent!`);
      } else {
        toast.error(`${channel === "slack" ? "Slack" : "Email"} test failed: ${data.results?.[channel] || "No response"}`);
      }
    } catch (error) {
      toast.error(`Test failed: ${error.message}`);
    } finally {
      if (channel === "slack") setTestingSlack(false);
      else setTestingEmail(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Alert Configuration...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bell className="w-6 h-6 text-yellow-500" />
            VNS Alerting Pipeline
          </h1>
          <p className="text-slate-400">Configure Slack and Email notifications for VNS detections</p>
        </div>
        <Button onClick={fetchStatus} variant="outline" size="sm" data-testid="refresh-alerts-btn">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className={`bg-slate-900/50 border-slate-800 ${status?.enabled ? 'border-green-500/50' : 'border-red-500/50'}`}>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Service Status</p>
                <p className="text-xl font-bold text-white flex items-center gap-2 mt-1">
                  {status?.enabled ? (
                    <>
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      <span className="text-green-400">Enabled</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-5 h-5 text-red-500" />
                      <span className="text-red-400">Disabled</span>
                    </>
                  )}
                </p>
              </div>
              <Shield className="w-8 h-8 text-cyan-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Slack Alerts</p>
                <p className="text-2xl font-bold text-purple-400">{status?.stats?.slack_alerts_sent || 0}</p>
              </div>
              <MessageSquare className="w-8 h-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Email Alerts</p>
                <p className="text-2xl font-bold text-blue-400">{status?.stats?.email_alerts_sent || 0}</p>
              </div>
              <Mail className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Suppressed</p>
                <p className="text-2xl font-bold text-orange-400">{status?.stats?.alerts_suppressed || 0}</p>
              </div>
              <Eye className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Configuration Tabs */}
      <Tabs defaultValue="slack" className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="slack" data-testid="tab-slack">
            <MessageSquare className="w-4 h-4 mr-2" />
            Slack Webhook
          </TabsTrigger>
          <TabsTrigger value="email" data-testid="tab-email">
            <Mail className="w-4 h-4 mr-2" />
            Email SMTP
          </TabsTrigger>
          <TabsTrigger value="settings" data-testid="tab-settings">
            <Settings className="w-4 h-4 mr-2" />
            Alert Settings
          </TabsTrigger>
        </TabsList>

        {/* Slack Configuration */}
        <TabsContent value="slack">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <MessageSquare className="w-5 h-5 text-purple-400" />
                Slack Webhook Configuration
              </CardTitle>
              <CardDescription>
                Configure Slack incoming webhook for real-time alerts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label className="text-slate-300">Webhook URL</Label>
                <Input
                  type="password"
                  placeholder="https://hooks.slack.com/services/..."
                  value={slackWebhook}
                  onChange={(e) => setSlackWebhook(e.target.value)}
                  className="bg-slate-800 border-slate-700 text-white"
                  data-testid="slack-webhook-input"
                />
                <p className="text-xs text-slate-500">
                  Create a webhook at: Slack {">"} Apps {">"} Incoming Webhooks {">"} Add New Webhook
                </p>
              </div>

              <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${status?.slack_configured ? 'bg-green-500' : 'bg-red-500'}`} />
                  <span className="text-white">
                    {status?.slack_configured ? "Slack webhook configured" : "Slack not configured"}
                  </span>
                </div>
                <Button
                  onClick={() => testAlert("slack")}
                  disabled={!slackWebhook && !status?.slack_configured || testingSlack}
                  size="sm"
                  className="bg-purple-600 hover:bg-purple-700"
                  data-testid="test-slack-btn"
                >
                  {testingSlack ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Send className="w-4 h-4 mr-2" />
                  )}
                  Test Slack
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Email Configuration */}
        <TabsContent value="email">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Mail className="w-5 h-5 text-blue-400" />
                Email SMTP Configuration
              </CardTitle>
              <CardDescription>
                Configure SMTP server for email alerts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-slate-300">SMTP Host</Label>
                  <Input
                    placeholder="smtp.gmail.com"
                    value={emailConfig.smtp_host}
                    onChange={(e) => setEmailConfig({ ...emailConfig, smtp_host: e.target.value })}
                    className="bg-slate-800 border-slate-700 text-white"
                    data-testid="smtp-host-input"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">SMTP Port</Label>
                  <Input
                    type="number"
                    placeholder="587"
                    value={emailConfig.smtp_port}
                    onChange={(e) => setEmailConfig({ ...emailConfig, smtp_port: e.target.value })}
                    className="bg-slate-800 border-slate-700 text-white"
                    data-testid="smtp-port-input"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">SMTP Username</Label>
                  <Input
                    placeholder="your-email@gmail.com"
                    value={emailConfig.smtp_user}
                    onChange={(e) => setEmailConfig({ ...emailConfig, smtp_user: e.target.value })}
                    className="bg-slate-800 border-slate-700 text-white"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">SMTP Password</Label>
                  <Input
                    type="password"
                    placeholder="App password or SMTP password"
                    value={emailConfig.smtp_password}
                    onChange={(e) => setEmailConfig({ ...emailConfig, smtp_password: e.target.value })}
                    className="bg-slate-800 border-slate-700 text-white"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">From Address</Label>
                  <Input
                    placeholder="seraph@yourdomain.com"
                    value={emailConfig.from_address}
                    onChange={(e) => setEmailConfig({ ...emailConfig, from_address: e.target.value })}
                    className="bg-slate-800 border-slate-700 text-white"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">To Addresses (comma-separated)</Label>
                  <Input
                    placeholder="admin@company.com, soc@company.com"
                    value={emailConfig.to_addresses}
                    onChange={(e) => setEmailConfig({ ...emailConfig, to_addresses: e.target.value })}
                    className="bg-slate-800 border-slate-700 text-white"
                    data-testid="email-to-input"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${status?.email_configured ? 'bg-green-500' : 'bg-red-500'}`} />
                  <span className="text-white">
                    {status?.email_configured 
                      ? `Email configured (${status?.email_recipients} recipients)` 
                      : "Email not configured"}
                  </span>
                </div>
                <Button
                  onClick={() => testAlert("email")}
                  disabled={!emailConfig.smtp_host && !status?.email_configured || testingEmail}
                  size="sm"
                  className="bg-blue-600 hover:bg-blue-700"
                  data-testid="test-email-btn"
                >
                  {testingEmail ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Send className="w-4 h-4 mr-2" />
                  )}
                  Test Email
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Alert Settings */}
        <TabsContent value="settings">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Settings className="w-5 h-5 text-cyan-400" />
                Alert Settings
              </CardTitle>
              <CardDescription>
                Configure alert thresholds and behavior
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <Label className="text-slate-300">Minimum Severity</Label>
                  <div className="flex gap-2">
                    {["low", "medium", "high", "critical"].map((sev) => (
                      <Button
                        key={sev}
                        variant={minSeverity === sev ? "default" : "outline"}
                        size="sm"
                        onClick={() => setMinSeverity(sev)}
                        className={minSeverity === sev ? 
                          sev === "critical" ? "bg-red-600" :
                          sev === "high" ? "bg-orange-600" :
                          sev === "medium" ? "bg-yellow-600" : "bg-green-600"
                          : ""
                        }
                        data-testid={`severity-${sev}-btn`}
                      >
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </Button>
                    ))}
                  </div>
                  <p className="text-xs text-slate-500">
                    Only alerts at or above this severity will be sent
                  </p>
                </div>

                <div className="space-y-3">
                  <Label className="text-slate-300">Cooldown Period (minutes)</Label>
                  <Input
                    type="number"
                    value={cooldownMinutes}
                    onChange={(e) => setCooldownMinutes(e.target.value)}
                    className="bg-slate-800 border-slate-700 text-white w-32"
                    min={1}
                    max={60}
                    data-testid="cooldown-input"
                  />
                  <p className="text-xs text-slate-500">
                    Prevent duplicate alerts within this time window
                  </p>
                </div>
              </div>

              <div className="p-4 bg-slate-800/50 rounded-lg">
                <h4 className="text-white font-medium mb-3">Alert Types Enabled</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { name: "Suspicious Flows", icon: Activity },
                    { name: "C2 Beacons", icon: AlertTriangle },
                    { name: "DNS Anomalies", icon: Shield },
                    { name: "Canary Triggers", icon: Bell }
                  ].map((type) => (
                    <div key={type.name} className="flex items-center gap-2 p-2 bg-slate-700/50 rounded">
                      <type.icon className="w-4 h-4 text-cyan-400" />
                      <span className="text-sm text-slate-300">{type.name}</span>
                      <CheckCircle className="w-4 h-4 text-green-400 ml-auto" />
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button
          onClick={saveConfiguration}
          disabled={savingConfig}
          className="bg-cyan-600 hover:bg-cyan-700"
          data-testid="save-config-btn"
        >
          {savingConfig ? (
            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
          ) : (
            <CheckCircle className="w-4 h-4 mr-2" />
          )}
          Save Configuration
        </Button>
      </div>

      {/* Setup Guide */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Quick Setup Guide</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <h4 className="text-cyan-400 font-medium">Slack Setup</h4>
            <ol className="list-decimal list-inside text-slate-300 space-y-1 text-sm">
              <li>Go to your Slack workspace settings</li>
              <li>Navigate to Apps {">"} Custom Integrations {">"} Incoming Webhooks</li>
              <li>Click "Add New Webhook to Workspace"</li>
              <li>Choose a channel for alerts (e.g., #security-alerts)</li>
              <li>Copy the webhook URL and paste above</li>
            </ol>
          </div>
          <div className="space-y-3">
            <h4 className="text-blue-400 font-medium">Email Setup (Gmail Example)</h4>
            <ol className="list-decimal list-inside text-slate-300 space-y-1 text-sm">
              <li>SMTP Host: smtp.gmail.com</li>
              <li>SMTP Port: 587 (TLS) or 465 (SSL)</li>
              <li>Enable "App Passwords" in your Google Account security settings</li>
              <li>Generate an app password for "Mail"</li>
              <li>Use the app password (not your regular password)</li>
            </ol>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
