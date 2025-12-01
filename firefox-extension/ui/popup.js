// Popup script
document.addEventListener('DOMContentLoaded', async () => {
  // Load settings
  const settings = await browser.storage.local.get(['isEnabled']);
  const isEnabled = settings.isEnabled !== false;
  document.getElementById('toggleProtection').checked = isEnabled;
  
  // Load checked scripts
  loadScripts();
  
  // Toggle protection
  document.getElementById('toggleProtection').addEventListener('change', (e) => {
    browser.storage.local.set({ isEnabled: e.target.checked });
  });
  
  // Open options
  document.getElementById('btnOptions').addEventListener('click', () => {
    browser.runtime.openOptionsPage();
  });
});

async function loadScripts() {
  const response = await browser.runtime.sendMessage({ action: 'getCheckedScripts' });
  const scripts = response.scripts || [];
  
  // Sort by timestamp (newest first)
  scripts.sort((a, b) => b.timestamp - a.timestamp);
  
  // Take last 10
  const recentScripts = scripts.slice(0, 10);
  
  // Update stats
  const totalChecked = scripts.length;
  const totalMalware = scripts.filter(s => s.status === 'malware').length;
  
  document.getElementById('totalChecked').textContent = totalChecked;
  document.getElementById('totalMalware').textContent = totalMalware;
  
  // Render scripts list
  const listEl = document.getElementById('scriptsList');
  
  if (recentScripts.length === 0) {
    listEl.innerHTML = '<div class="empty-state">Chưa có dữ liệu</div>';
    return;
  }
  
  listEl.innerHTML = recentScripts.map(script => {
    const url = new URL(script.url);
    const shortUrl = url.hostname + url.pathname.slice(0, 30) + '...';
    const statusClass = script.status === 'malware' ? 'status-malware' : 'status-clean';
    const statusText = script.status === 'malware' ? '⚠️ Malware' : '✓ Clean';
    
    return `
      <div class="script-item">
        <div class="script-url" title="${script.url}">${shortUrl}</div>
        <span class="script-status ${statusClass}">${statusText}</span>
      </div>
    `;
  }).join('');
}
