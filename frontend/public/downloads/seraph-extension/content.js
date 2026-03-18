// Seraph AI Browser Extension - Content Script
(function() {
  'use strict';
  
  // Suspicious patterns to detect in scripts
  const SUSPICIOUS_PATTERNS = [
    { pattern: /eval\s*\(/, name: 'eval' },
    { pattern: /Function\s*\(/, name: 'Function constructor' },
    { pattern: /document\.write/, name: 'document.write' },
    { pattern: /innerHTML\s*=/, name: 'innerHTML assignment' },
    { pattern: /document\.cookie/, name: 'cookie access' },
    { pattern: /localStorage\.setItem/, name: 'localStorage write' },
    { pattern: /sessionStorage\.setItem/, name: 'sessionStorage write' },
    { pattern: /XMLHttpRequest.*POST.*password/i, name: 'password POST' },
    { pattern: /fetch.*credentials.*include/i, name: 'credentialed fetch' },
    { pattern: /\\x[0-9a-f]{2}/gi, name: 'hex encoded' },
    { pattern: /fromCharCode/, name: 'char code conversion' },
    { pattern: /atob\s*\(/, name: 'base64 decode' },
    { pattern: /btoa\s*\(/, name: 'base64 encode' },
    { pattern: /\.src\s*=\s*['"]data:/, name: 'data URI injection' }
  ];
  
  // Monitor for suspicious script injections
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.tagName === 'SCRIPT') {
          analyzeScript(node);
        }
        // Also check for iframes
        if (node.tagName === 'IFRAME') {
          analyzeIframe(node);
        }
      });
    });
  });
  
  // Analyze script content
  function analyzeScript(scriptNode) {
    const scriptContent = scriptNode.textContent || scriptNode.src || '';
    
    for (const { pattern, name } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(scriptContent)) {
        reportSuspicious(`Suspicious pattern detected: ${name}`, scriptContent, name);
        break;
      }
    }
  }
  
  // Analyze iframe for suspicious behavior
  function analyzeIframe(iframe) {
    const src = iframe.src || '';
    
    // Check for data URI iframes (potential XSS)
    if (src.startsWith('data:') || src.startsWith('javascript:')) {
      reportSuspicious('Suspicious iframe detected', src, 'suspicious_iframe');
    }
    
    // Check for hidden iframes (often used in attacks)
    const style = window.getComputedStyle(iframe);
    if (style.display === 'none' || style.visibility === 'hidden' ||
        iframe.width === '0' || iframe.height === '0' ||
        parseInt(style.width) <= 1 || parseInt(style.height) <= 1) {
      reportSuspicious('Hidden iframe detected', src, 'hidden_iframe');
    }
  }
  
  // Report suspicious activity to background script
  function reportSuspicious(message, content, patternName) {
    try {
      chrome.runtime.sendMessage({
        type: 'SUSPICIOUS_SCRIPT',
        script: content.substring(0, 500),
        pattern: patternName,
        message: message,
        url: window.location.href
      });
    } catch (e) {
      // Extension context might be invalidated
      console.debug('[Seraph AI] Could not report:', e);
    }
  }
  
  // Start observing
  observer.observe(document, {
    childList: true,
    subtree: true
  });
  
  // Protect against XSS via URL parameters
  function checkUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    for (const [key, value] of urlParams.entries()) {
      if (/<script|javascript:|on\w+=/i.test(value)) {
        reportSuspicious(
          `XSS attempt in URL parameter: ${key}`,
          value,
          'url_xss'
        );
      }
    }
  }
  checkUrlParams();
  
  // Protect clipboard from hijacking
  let clipboardProtectionTriggered = false;
  document.addEventListener('copy', (e) => {
    // Only alert once per page
    if (clipboardProtectionTriggered) return;
    
    const activeEl = document.activeElement;
    if (activeEl !== e.target && 
        activeEl.tagName !== 'INPUT' &&
        activeEl.tagName !== 'TEXTAREA' &&
        !activeEl.isContentEditable) {
      clipboardProtectionTriggered = true;
      reportSuspicious(
        'Possible clipboard hijacking attempt',
        `Target: ${e.target.tagName}, Active: ${activeEl.tagName}`,
        'clipboard_hijack'
      );
    }
  });
  
  // Protect against keyloggers
  const keyloggerPatterns = [
    /getAsyncKeyState/i,
    /keyboard.*hook/i,
    /keydown.*capture/i
  ];
  
  // Monitor for form submissions to untrusted domains
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.tagName !== 'FORM') return;
    
    const action = form.action || '';
    const currentDomain = window.location.hostname;
    
    try {
      const actionUrl = new URL(action, window.location.href);
      if (actionUrl.hostname !== currentDomain && 
          !actionUrl.hostname.endsWith('.' + currentDomain)) {
        // Cross-domain form submission
        const hasPassword = form.querySelector('input[type="password"]');
        if (hasPassword) {
          reportSuspicious(
            'Cross-domain password form submission',
            `From: ${currentDomain} To: ${actionUrl.hostname}`,
            'cross_domain_password'
          );
        }
      }
    } catch (e) {
      // Invalid URL
    }
  }, true);
  
  // Protection badge indicator
  function showProtectionBadge() {
    if (document.getElementById('seraph-ai-badge')) return;
    
    const badge = document.createElement('div');
    badge.id = 'seraph-ai-badge';
    badge.style.cssText = `
      position: fixed;
      bottom: 10px;
      right: 10px;
      width: 8px;
      height: 8px;
      background: #22c55e;
      border-radius: 50%;
      z-index: 2147483647;
      pointer-events: none;
      opacity: 0.7;
      box-shadow: 0 0 4px #22c55e;
    `;
    
    // Remove after 3 seconds
    setTimeout(() => {
      badge.style.transition = 'opacity 1s';
      badge.style.opacity = '0';
      setTimeout(() => badge.remove(), 1000);
    }, 3000);
    
    document.body?.appendChild(badge);
  }
  
  // Show badge when page loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', showProtectionBadge);
  } else {
    showProtectionBadge();
  }
  
  console.log('[Seraph AI] Browser protection active');
})();
