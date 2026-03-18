// Seraph AI Browser Extension - Background Service Worker
// Configure your Seraph AI server URL here
const SERAPH_API = "https://seraph-security.preview.emergentagent.com";

let alertQueue = [];
let isProcessing = false;
let blockedCount = 0;
let alertsCount = 0;

// Suspicious patterns to detect
const SUSPICIOUS_PATTERNS = [
  /eval\s*\(/,
  /document\.cookie/,
  /localStorage/,
  /XMLHttpRequest.*password/i,
  /fetch.*credentials/i,
  /\.(exe|bat|ps1|vbs|scr)$/i
];

const SUSPICIOUS_PORTS = [4444, 5555, 6666, 6667, 31337, 12345, 27374];

// Known malicious domain patterns
const MALICIOUS_DOMAINS = [
  /\.onion$/,
  /\.bit$/,
  /dyndns\./i,
  /no-ip\./i,
  /ngrok\.io$/,
  /\.tk$/,
  /\.ml$/,
  /\.ga$/,
  /\.cf$/
];

// Initialize on install
chrome.runtime.onInstalled.addListener(() => {
  console.log("[Seraph AI] Browser Defender installed");
  chrome.storage.local.set({
    enabled: true,
    blockedCount: 0,
    alertsCount: 0,
    lastSync: Date.now(),
    protectionActive: true
  });
});

// Check if domain is suspicious
function isDomainSuspicious(hostname) {
  for (const pattern of MALICIOUS_DOMAINS) {
    if (pattern.test(hostname)) {
      return true;
    }
  }
  return false;
}

// Check if URL contains suspicious patterns
function isUrlSuspicious(url) {
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(url)) {
      return true;
    }
  }
  return false;
}

// Web request listener for suspicious activity
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!details.url) return;
    
    try {
      const url = new URL(details.url);
      
      // Check for suspicious patterns in URL
      if (isUrlSuspicious(details.url)) {
        queueAlert({
          type: "suspicious_request",
          url: details.url,
          tabId: details.tabId,
          timestamp: Date.now(),
          reason: "Suspicious URL pattern detected"
        });
      }
      
      // Check for suspicious ports
      const port = parseInt(url.port);
      if (port && SUSPICIOUS_PORTS.includes(port)) {
        queueAlert({
          type: "suspicious_port",
          url: details.url,
          port: port,
          tabId: details.tabId,
          timestamp: Date.now(),
          reason: `Connection to suspicious port ${port}`
        });
      }
    } catch (e) {
      // Invalid URL, ignore
    }
  },
  { urls: ["<all_urls>"] }
);

// Navigation listener for phishing detection
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame
  
  try {
    const url = new URL(details.url);
    const domain = url.hostname;
    
    // Check against local patterns first
    if (isDomainSuspicious(domain)) {
      // Block the navigation
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(`blocked.html?domain=${encodeURIComponent(domain)}&reason=suspicious_domain`)
      });
      
      incrementBlocked();
      
      queueAlert({
        type: "blocked_navigation",
        domain: domain,
        url: details.url,
        tabId: details.tabId,
        timestamp: Date.now(),
        reason: "Suspicious domain blocked"
      });
      
      return;
    }
    
    // Check against Seraph AI server (async, non-blocking)
    checkDomainWithServer(domain, details.tabId, details.url);
    
  } catch (error) {
    console.error("[Seraph AI] Navigation check failed:", error);
  }
});

// Check domain with Seraph AI server
async function checkDomainWithServer(domain, tabId, originalUrl) {
  try {
    const response = await fetch(`${SERAPH_API}/api/extension/check-domain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain })
    });
    
    if (response.ok) {
      const result = await response.json();
      if (result.is_malicious) {
        chrome.tabs.update(tabId, {
          url: chrome.runtime.getURL(`blocked.html?domain=${encodeURIComponent(domain)}&reason=${encodeURIComponent(result.reason)}`)
        });
        incrementBlocked();
      }
    }
  } catch (error) {
    // Server unavailable, continue with local checks only
    console.debug("[Seraph AI] Server check failed, using local protection only");
  }
}

// Increment blocked count
function incrementBlocked() {
  chrome.storage.local.get("blockedCount", (data) => {
    blockedCount = (data.blockedCount || 0) + 1;
    chrome.storage.local.set({ blockedCount });
  });
}

// Queue alert for batch processing
function queueAlert(alert) {
  alertQueue.push(alert);
  chrome.storage.local.get("alertsCount", (data) => {
    alertsCount = (data.alertsCount || 0) + 1;
    chrome.storage.local.set({ alertsCount });
  });
  processAlertQueue();
}

// Process alerts in batches
async function processAlertQueue() {
  if (isProcessing || alertQueue.length === 0) return;
  
  isProcessing = true;
  const alerts = alertQueue.splice(0, 10);
  
  try {
    await fetch(`${SERAPH_API}/api/extension/report-alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alerts })
    });
  } catch (error) {
    console.debug("[Seraph AI] Failed to send alerts:", error);
    // Re-queue on failure (only once)
    if (alerts[0] && !alerts[0].retried) {
      alerts.forEach(a => a.retried = true);
      alertQueue.unshift(...alerts);
    }
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
      script: message.script?.substring(0, 500),
      pattern: message.pattern,
      timestamp: Date.now()
    });
    sendResponse({ received: true });
  } else if (message.type === "GET_STATUS") {
    chrome.storage.local.get(["blockedCount", "alertsCount", "protectionActive"], (data) => {
      sendResponse({
        blockedCount: data.blockedCount || 0,
        alertsCount: data.alertsCount || 0,
        protectionActive: data.protectionActive !== false
      });
    });
    return true; // Keep channel open for async response
  }
  return true;
});

console.log("[Seraph AI] Background service worker started");
