import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Settings, Bell, Mail, MessageSquare, Database, 
  Save, TestTube, Check, X, AlertCircle, RefreshCw,
  Shield, Key, Server, Send
} from 'lucide-react';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const SettingsPage = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [settings, setSettings] = useState({
    slack_enabled: false,
    slack_webhook_url: '',
    email_enabled: false,
    sendgrid_api_key: '',
    email_from: '',
    email_to: '',
    elasticsearch_enabled: false,
    elasticsearch_url: '',
    elasticsearch_api_key: ''
  });
  const [formData, setFormData] = useState({
    slack_webhook_url: '',
    sendgrid_api_key: '',
    sender_email: '',
    alert_recipients: '',
    elasticsearch_url: '',
    elasticsearch_api_key: ''
  });
  const [elasticStatus, setElasticStatus] = useState(null);

  const fetchSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/settings/notifications`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setSettings(data);
      }
    } catch (err) {
      console.error('Failed to fetch settings:', err);
    } finally {
      setLoading(false);
    }
  };

  const checkElasticStatus = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/settings/elasticsearch/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setElasticStatus(data);
      }
    } catch (err) {
      setElasticStatus({ status: 'error', message: err.message });
    }
  };

  useEffect(() => {
    fetchSettings();
    checkElasticStatus();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      const token = localStorage.getItem('token');
      const payload = {};
      
      if (formData.slack_webhook_url) payload.slack_webhook_url = formData.slack_webhook_url;
      if (formData.sendgrid_api_key) payload.sendgrid_api_key = formData.sendgrid_api_key;
      if (formData.sender_email) payload.sender_email = formData.sender_email;
      if (formData.alert_recipients) payload.alert_recipients = formData.alert_recipients.split(',').map(e => e.trim());
      if (formData.elasticsearch_url) payload.elasticsearch_url = formData.elasticsearch_url;
      if (formData.elasticsearch_api_key) payload.elasticsearch_api_key = formData.elasticsearch_api_key;
      
      const response = await fetch(`${API}/api/settings/notifications`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(payload)
      });
      
      if (response.ok) {
        toast.success('Settings saved successfully');
        fetchSettings();
        checkElasticStatus();
        setFormData({
          slack_webhook_url: '',
          sendgrid_api_key: '',
          sender_email: '',
          alert_recipients: '',
          elasticsearch_url: '',
          elasticsearch_api_key: ''
        });
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to save settings');
      }
    } catch (err) {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async (channel) => {
    setTesting(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/settings/notifications/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ channel })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.results) {
          Object.entries(data.results).forEach(([ch, result]) => {
            if (result === true) {
              toast.success(`${ch} test notification sent!`);
            } else if (result === 'Not configured') {
              toast.warning(`${ch} is not configured`);
            } else {
              toast.error(`${ch} test failed`);
            }
          });
        }
      } else {
        toast.error('Test failed');
      }
    } catch (err) {
      toast.error('Test failed: ' + err.message);
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="settings-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-purple-500/20">
            <Settings className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-mono font-bold">Settings</h1>
            <p className="text-slate-400 text-sm">Configure notifications and integrations</p>
          </div>
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded font-semibold transition-colors disabled:opacity-50"
          data-testid="save-settings-btn"
        >
          <Save className="w-4 h-4" />
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Slack Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded bg-purple-500/20">
                <MessageSquare className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h3 className="font-semibold">Slack Integration</h3>
                <p className="text-xs text-slate-400">Send alerts to Slack channels</p>
              </div>
            </div>
            <div className={`px-2 py-1 rounded text-xs ${settings.slack_enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
              {settings.slack_enabled ? 'Active' : 'Inactive'}
            </div>
          </div>
          
          <div className="space-y-4">
            <div>
              <label className="text-sm text-slate-400 mb-1 block">Webhook URL</label>
              <input
                type="password"
                placeholder={settings.slack_webhook_url ? '••••••••••••••••' : 'https://hooks.slack.com/services/...'}
                value={formData.slack_webhook_url}
                onChange={(e) => setFormData({...formData, slack_webhook_url: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
              />
              <p className="text-xs text-slate-500 mt-1">
                Get webhook URL from Slack App settings → Incoming Webhooks
              </p>
            </div>
            
            <button
              onClick={() => handleTest('slack')}
              disabled={testing || !settings.slack_enabled}
              className="flex items-center gap-2 px-3 py-1.5 bg-purple-600 hover:bg-purple-500 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <TestTube className="w-4 h-4" />
              Test Slack
            </button>
          </div>
        </motion.div>

        {/* Email Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded bg-blue-500/20">
                <Mail className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <h3 className="font-semibold">Email Notifications</h3>
                <p className="text-xs text-slate-400">Send alerts via SendGrid</p>
              </div>
            </div>
            <div className={`px-2 py-1 rounded text-xs ${settings.email_enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
              {settings.email_enabled ? 'Active' : 'Inactive'}
            </div>
          </div>
          
          <div className="space-y-4">
            <div>
              <label className="text-sm text-slate-400 mb-1 block">SendGrid API Key</label>
              <input
                type="password"
                placeholder={settings.sendgrid_api_key ? '••••••••••••••••' : 'SG.xxxxxxxx'}
                value={formData.sendgrid_api_key}
                onChange={(e) => setFormData({...formData, sendgrid_api_key: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
              />
            </div>
            
            <div>
              <label className="text-sm text-slate-400 mb-1 block">Sender Email</label>
              <input
                type="email"
                placeholder={settings.email_from || 'alerts@yourdomain.com'}
                value={formData.sender_email}
                onChange={(e) => setFormData({...formData, sender_email: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
              />
            </div>
            
            <div>
              <label className="text-sm text-slate-400 mb-1 block">
                Alert Recipients
              </label>
              <input
                type="text"
                placeholder="email1@example.com, email2@example.com"
                value={formData.alert_recipients}
                onChange={(e) => setFormData({...formData, alert_recipients: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
              />
            </div>
            
            <button
              onClick={() => handleTest('email')}
              disabled={testing || !settings.email_enabled}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Send className="w-4 h-4" />
              Test Email
            </button>
          </div>
        </motion.div>

        {/* Elasticsearch/Kibana Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 lg:col-span-2"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded bg-amber-500/20">
                <Database className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="font-semibold">Elasticsearch / Kibana</h3>
                <p className="text-xs text-slate-400">Log aggregation and visualization</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {elasticStatus && (
                <div className={`px-2 py-1 rounded text-xs flex items-center gap-1 ${
                  elasticStatus.status === 'connected' ? 'bg-green-500/20 text-green-400' : 
                  elasticStatus.status === 'not_configured' ? 'bg-slate-700 text-slate-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  {elasticStatus.status === 'connected' ? <Check className="w-3 h-3" /> : 
                   elasticStatus.status === 'not_configured' ? <AlertCircle className="w-3 h-3" /> :
                   <X className="w-3 h-3" />}
                  {elasticStatus.status}
                </div>
              )}
              <button
                onClick={checkElasticStatus}
                className="p-1 hover:bg-slate-700 rounded"
              >
                <RefreshCw className="w-4 h-4 text-slate-400" />
              </button>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-slate-400 mb-1 block">Elasticsearch URL</label>
              <input
                type="text"
                placeholder="https://your-cluster.es.region.aws.found.io:9243"
                value={formData.elasticsearch_url}
                onChange={(e) => setFormData({...formData, elasticsearch_url: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
              />
            </div>
            
            <div>
              <label className="text-sm text-slate-400 mb-1 block">API Key (optional)</label>
              <input
                type="password"
                placeholder="Base64 encoded API key"
                value={formData.elasticsearch_api_key}
                onChange={(e) => setFormData({...formData, elasticsearch_api_key: e.target.value})}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 outline-none text-sm"
              />
            </div>
          </div>
          
          <div className="mt-4 p-3 bg-slate-900/50 rounded border border-slate-700">
            <h4 className="text-sm font-semibold mb-2">Kibana Integration</h4>
            <p className="text-xs text-slate-400 mb-2">
              Security events are indexed to <code className="text-cyan-400">security-events-YYYY.MM</code> pattern.
              Configure Kibana to visualize this data:
            </p>
            <ol className="text-xs text-slate-400 list-decimal list-inside space-y-1">
              <li>Go to Kibana → Management → Index Patterns</li>
              <li>Create pattern: <code className="text-cyan-400">security-events-*</code></li>
              <li>Set time field to <code className="text-cyan-400">@timestamp</code></li>
              <li>Create dashboards using Discover or Visualize</li>
            </ol>
          </div>
        </motion.div>

        {/* Notification Thresholds */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 lg:col-span-2"
        >
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded bg-red-500/20">
              <Bell className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h3 className="font-semibold">Notification Thresholds</h3>
              <p className="text-xs text-slate-400">Control which severity levels trigger notifications</p>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-900/50 rounded border border-slate-700">
              <div className="flex items-center gap-2 mb-2">
                <MessageSquare className="w-4 h-4 text-purple-400" />
                <span className="font-semibold text-sm">Slack</span>
              </div>
              <p className="text-xs text-slate-400 mb-2">Receives alerts for:</p>
              <div className="flex flex-wrap gap-1">
                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">Critical</span>
                <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs">High</span>
                <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">Medium</span>
              </div>
            </div>
            
            <div className="p-4 bg-slate-900/50 rounded border border-slate-700">
              <div className="flex items-center gap-2 mb-2">
                <Mail className="w-4 h-4 text-blue-400" />
                <span className="font-semibold text-sm">Email</span>
              </div>
              <p className="text-xs text-slate-400 mb-2">Receives alerts for:</p>
              <div className="flex flex-wrap gap-1">
                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">Critical</span>
                <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs">High</span>
              </div>
            </div>
            
            <div className="p-4 bg-slate-900/50 rounded border border-slate-700">
              <div className="flex items-center gap-2 mb-2">
                <Database className="w-4 h-4 text-amber-400" />
                <span className="font-semibold text-sm">Elasticsearch</span>
              </div>
              <p className="text-xs text-slate-400 mb-2">Logs all events:</p>
              <div className="flex flex-wrap gap-1">
                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">Critical</span>
                <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs">High</span>
                <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">Medium</span>
                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">Low</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default SettingsPage;
