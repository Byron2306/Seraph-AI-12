import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Chrome,
  Shield,
  Download,
  Code,
  FileCode,
  ExternalLink,
  AlertTriangle,
  CheckCircle,
  Globe,
  Lock,
  Eye,
  Fingerprint,
  Zap
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

export default function BrowserExtensionPage() {
  const { token } = useAuth();
  const [activeTab, setActiveTab] = useState("overview");

  const downloadExtension = () => {
    // Direct download from backend
    window.open(`${API_URL}/api/extension/download`, '_blank');
    toast.success("Extension download started!");
  };

  const features = [
    {
      icon: Shield,
      title: "Real-time Threat Detection",
      description: "Monitors browser activity for malicious scripts, XSS attempts, and suspicious behavior"
    },
    {
      icon: Lock,
      title: "Phishing Protection",
      description: "Warns users before visiting known phishing sites and suspicious domains"
    },
    {
      icon: Eye,
      title: "Privacy Guard",
      description: "Detects and blocks tracking scripts, fingerprinting attempts, and data exfiltration"
    },
    {
      icon: Fingerprint,
      title: "Session Monitoring",
      description: "Monitors for session hijacking attempts and cookie theft"
    },
    {
      icon: Zap,
      title: "AI-Powered Analysis",
      description: "Sends suspicious scripts to Seraph AI for deep behavioral analysis"
    },
    {
      icon: Globe,
      title: "DNS Security",
      description: "Detects DNS-based attacks and suspicious domain requests"
    }
  ];

  const manifestCode = `{
  "manifest_version": 3,
  "name": "Seraph AI Browser Defender",
  "version": "1.0.0",
  "description": "Real-time browser protection powered by Seraph AI",
  "permissions": [
    "webRequest",
    "webNavigation",
    "storage",
    "tabs",
    "alarms"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  }
}`;

  const backgroundCode = `// Seraph AI Browser Extension - Background Service Worker
const SERAPH_API = "${API_URL}";
let alertQueue = [];
let isProcessing = false;

// Initialize
chrome.runtime.onInstalled.addListener(() => {
  console.log("Seraph AI Browser Defender installed");
  chrome.storage.local.set({
    enabled: true,
    blockedCount: 0,
    alertsCount: 0,
    lastSync: Date.now()
  });
});

// Web request listener for suspicious activity
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!details.url) return;
    
    const url = new URL(details.url);
    const suspiciousPatterns = [
      /eval\\s*\\(/,
      /document\\.cookie/,
      /localStorage/,
      /XMLHttpRequest.*password/i,
      /fetch.*credentials/i,
      /\\.(exe|bat|ps1|vbs)$/i
    ];
    
    // Check for suspicious patterns in URL
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(details.url)) {
        queueAlert({
          type: "suspicious_request",
          url: details.url,
          tabId: details.tabId,
          timestamp: Date.now()
        });
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Navigation listener for phishing detection
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame
  
  try {
    const url = new URL(details.url);
    const domain = url.hostname;
    
    // Check against known bad domains
    const response = await fetch(\`\${SERAPH_API}/api/extension/check-domain\`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain })
    });
    
    if (response.ok) {
      const result = await response.json();
      if (result.is_malicious) {
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(\`blocked.html?domain=\${encodeURIComponent(domain)}&reason=\${encodeURIComponent(result.reason)}\`)
        });
        
        chrome.storage.local.get("blockedCount", (data) => {
          chrome.storage.local.set({ blockedCount: (data.blockedCount || 0) + 1 });
        });
      }
    }
  } catch (error) {
    console.error("Domain check failed:", error);
  }
});

// Queue alert for batch processing
function queueAlert(alert) {
  alertQueue.push(alert);
  chrome.storage.local.get("alertsCount", (data) => {
    chrome.storage.local.set({ alertsCount: (data.alertsCount || 0) + 1 });
  });
  processAlertQueue();
}

// Process alerts in batches
async function processAlertQueue() {
  if (isProcessing || alertQueue.length === 0) return;
  
  isProcessing = true;
  const alerts = alertQueue.splice(0, 10);
  
  try {
    await fetch(\`\${SERAPH_API}/api/extension/report-alerts\`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alerts })
    });
  } catch (error) {
    console.error("Failed to send alerts:", error);
    alertQueue.unshift(...alerts); // Re-queue on failure
  }
  
  isProcessing = false;
  if (alertQueue.length > 0) {
    setTimeout(processAlertQueue, 1000);
  }
}

// Sync with server periodically
chrome.alarms.create("sync", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "sync") {
    processAlertQueue();
    chrome.storage.local.set({ lastSync: Date.now() });
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SUSPICIOUS_SCRIPT") {
    queueAlert({
      type: "suspicious_script",
      url: sender.tab?.url,
      tabId: sender.tab?.id,
      script: message.script,
      timestamp: Date.now()
    });
    sendResponse({ received: true });
  }
  return true;
});`;

  const contentCode = `// Seraph AI Browser Extension - Content Script
(function() {
  'use strict';
  
  // Monitor for suspicious script injections
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.tagName === 'SCRIPT') {
          const scriptContent = node.textContent || node.src || '';
          
          const suspiciousPatterns = [
            /eval\\s*\\(/,
            /Function\\s*\\(/,
            /document\\.write/,
            /innerHTML\\s*=/,
            /document\\.cookie/,
            /localStorage\\.setItem/,
            /sessionStorage\\.setItem/,
            /XMLHttpRequest.*POST.*password/i,
            /fetch.*credentials.*include/i,
            /\\\\x[0-9a-f]{2}/gi, // Hex encoded strings
            /fromCharCode/,
            /atob\\s*\\(/
          ];
          
          for (const pattern of suspiciousPatterns) {
            if (pattern.test(scriptContent)) {
              chrome.runtime.sendMessage({
                type: 'SUSPICIOUS_SCRIPT',
                script: scriptContent.substring(0, 500),
                pattern: pattern.toString()
              });
              break;
            }
          }
        }
      });
    });
  });
  
  observer.observe(document, {
    childList: true,
    subtree: true
  });
  
  // Protect against XSS via URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  for (const [key, value] of urlParams.entries()) {
    if (/<script|javascript:|on\\w+=/i.test(value)) {
      chrome.runtime.sendMessage({
        type: 'SUSPICIOUS_SCRIPT',
        script: \`XSS attempt in URL parameter: \${key}=\${value}\`,
        pattern: 'url_xss'
      });
    }
  }
  
  // Monitor console for suspicious activity
  const originalConsoleLog = console.log;
  console.log = function(...args) {
    const message = args.join(' ');
    if (/error|exception|failed|unauthorized/i.test(message) && 
        /password|token|cookie|session/i.test(message)) {
      chrome.runtime.sendMessage({
        type: 'SUSPICIOUS_SCRIPT',
        script: \`Suspicious console output: \${message.substring(0, 200)}\`,
        pattern: 'console_leak'
      });
    }
    return originalConsoleLog.apply(console, args);
  };
  
  // Protect clipboard
  document.addEventListener('copy', (e) => {
    if (e.target !== document.activeElement && 
        document.activeElement.tagName !== 'INPUT' &&
        document.activeElement.tagName !== 'TEXTAREA') {
      chrome.runtime.sendMessage({
        type: 'SUSPICIOUS_SCRIPT',
        script: 'Possible clipboard hijacking attempt',
        pattern: 'clipboard_hijack'
      });
    }
  });
  
  console.log('[Seraph AI] Browser protection active');
})();`;

  const popupHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      width: 320px;
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #f1f5f9;
    }
    .header {
      padding: 16px;
      background: rgba(59, 130, 246, 0.1);
      border-bottom: 1px solid rgba(59, 130, 246, 0.3);
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .header img { width: 32px; height: 32px; }
    .header h1 { font-size: 14px; font-weight: 600; }
    .status {
      padding: 12px 16px;
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
    }
    .status-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: #22c55e;
    }
    .stats {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      padding: 16px;
    }
    .stat {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 12px;
      text-align: center;
    }
    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: #3b82f6;
    }
    .stat-label {
      font-size: 11px;
      color: #94a3b8;
      margin-top: 4px;
    }
    .footer {
      padding: 12px 16px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      text-align: center;
      font-size: 11px;
      color: #64748b;
    }
  </style>
</head>
<body>
  <div class="header">
    <img src="icons/icon32.png" alt="Seraph AI">
    <h1>Seraph AI Defender</h1>
  </div>
  <div class="status">
    <div class="status-dot"></div>
    <span>Protection Active</span>
  </div>
  <div class="stats">
    <div class="stat">
      <div class="stat-value" id="blocked">0</div>
      <div class="stat-label">Sites Blocked</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="alerts">0</div>
      <div class="stat-label">Threats Detected</div>
    </div>
  </div>
  <div class="footer">
    Powered by Seraph AI Defense System
  </div>
  <script src="popup.js"></script>
</body>
</html>`;

  const popupJs = `chrome.storage.local.get(['blockedCount', 'alertsCount'], (data) => {
  document.getElementById('blocked').textContent = data.blockedCount || 0;
  document.getElementById('alerts').textContent = data.alertsCount || 0;
});`;

  const copyToClipboard = (text, name) => {
    navigator.clipboard.writeText(text);
    toast.success(`${name} copied to clipboard`);
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Chrome className="w-6 h-6 text-blue-500" />
            Browser Extension
          </h1>
          <p className="text-slate-400">Seraph AI Browser Defender - Real-time protection for web browsers</p>
        </div>
        <Button onClick={downloadExtension} className="bg-blue-600 hover:bg-blue-700" data-testid="download-extension-btn">
          <Download className="w-4 h-4 mr-2" />
          Download Extension
        </Button>
      </div>

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {features.map((feature, index) => (
          <Card key={index} className="bg-slate-900/50 border-slate-800" data-testid={`feature-card-${index}`}>
            <CardContent className="pt-6">
              <div className="flex items-start gap-4">
                <div className="p-2 bg-blue-500/10 rounded-lg">
                  <feature.icon className="w-6 h-6 text-blue-400" />
                </div>
                <div>
                  <h3 className="font-medium text-white">{feature.title}</h3>
                  <p className="text-sm text-slate-400 mt-1">{feature.description}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Code Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="overview" data-testid="tab-overview">
            <Shield className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="manifest" data-testid="tab-manifest">
            <FileCode className="w-4 h-4 mr-2" />
            manifest.json
          </TabsTrigger>
          <TabsTrigger value="background" data-testid="tab-background">
            <Code className="w-4 h-4 mr-2" />
            background.js
          </TabsTrigger>
          <TabsTrigger value="content" data-testid="tab-content">
            <Code className="w-4 h-4 mr-2" />
            content.js
          </TabsTrigger>
          <TabsTrigger value="popup" data-testid="tab-popup">
            <Globe className="w-4 h-4 mr-2" />
            popup.html
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Installation Guide</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <h4 className="text-cyan-400 font-medium">Chrome / Edge / Brave</h4>
                <ol className="list-decimal list-inside text-slate-300 space-y-2 text-sm">
                  <li>Download the extension files using the button above</li>
                  <li>Create a new folder and save all files (manifest.json, background.js, content.js, popup.html, popup.js)</li>
                  <li>Create an "icons" folder with PNG icons (16x16, 48x48, 128x128)</li>
                  <li>Open your browser and navigate to <code className="bg-slate-800 px-2 py-1 rounded">chrome://extensions</code></li>
                  <li>Enable "Developer mode" in the top right corner</li>
                  <li>Click "Load unpacked" and select your extension folder</li>
                  <li>The Seraph AI icon should appear in your browser toolbar</li>
                </ol>
              </div>
              
              <div className="p-4 bg-yellow-900/20 border border-yellow-700/50 rounded-lg">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
                  <div>
                    <h5 className="text-yellow-400 font-medium">Important</h5>
                    <p className="text-sm text-slate-300 mt-1">
                      Make sure to update the <code className="bg-slate-800 px-1 rounded">SERAPH_API</code> variable in background.js 
                      with your actual Seraph AI server URL for the extension to communicate with your server.
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="manifest">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-white">manifest.json</CardTitle>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => copyToClipboard(manifestCode, "manifest.json")}
              >
                Copy
              </Button>
            </CardHeader>
            <CardContent>
              <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono">
                {manifestCode}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="background">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-white">background.js</CardTitle>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => copyToClipboard(backgroundCode, "background.js")}
              >
                Copy
              </Button>
            </CardHeader>
            <CardContent>
              <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono max-h-[500px]">
                {backgroundCode}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="content">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-white">content.js</CardTitle>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => copyToClipboard(contentCode, "content.js")}
              >
                Copy
              </Button>
            </CardHeader>
            <CardContent>
              <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono max-h-[500px]">
                {contentCode}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="popup">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-white">popup.html & popup.js</CardTitle>
              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => copyToClipboard(popupHtml, "popup.html")}
                >
                  Copy HTML
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => copyToClipboard(popupJs, "popup.js")}
                >
                  Copy JS
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="text-slate-400 text-sm mb-2">popup.html</h4>
                <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono max-h-[300px]">
                  {popupHtml}
                </pre>
              </div>
              <div>
                <h4 className="text-slate-400 text-sm mb-2">popup.js</h4>
                <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono">
                  {popupJs}
                </pre>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
