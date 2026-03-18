// Seraph AI Browser Extension - Popup Script

const SERAPH_DASHBOARD = "https://seraph-security.preview.emergentagent.com";

// Update stats from storage
function updateStats() {
  chrome.storage.local.get(['blockedCount', 'alertsCount', 'protectionActive'], (data) => {
    document.getElementById('blocked').textContent = data.blockedCount || 0;
    document.getElementById('alerts').textContent = data.alertsCount || 0;
    
    const isActive = data.protectionActive !== false;
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const toggleBtn = document.getElementById('toggleBtn');
    
    if (isActive) {
      statusDot.classList.remove('inactive');
      statusText.textContent = 'Protection Active';
      toggleBtn.textContent = 'Disable Protection';
    } else {
      statusDot.classList.add('inactive');
      statusText.textContent = 'Protection Disabled';
      toggleBtn.textContent = 'Enable Protection';
    }
  });
}

// Toggle protection
document.getElementById('toggleBtn').addEventListener('click', () => {
  chrome.storage.local.get('protectionActive', (data) => {
    const newState = data.protectionActive === false;
    chrome.storage.local.set({ protectionActive: newState }, () => {
      updateStats();
    });
  });
});

// Open dashboard
document.getElementById('dashboardBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: SERAPH_DASHBOARD });
});

// Initial load
updateStats();

// Listen for storage changes
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local') {
    updateStats();
  }
});
