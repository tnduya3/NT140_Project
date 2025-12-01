// Options page script
let whitelist = [];
let customHashes = [];

// Load settings
async function loadSettings() {
  const result = await browser.storage.local.get([
    'whitelist', 
    'customHashes', 
    'vtApiKey', 
    'dbPreferences'
  ]);
  
  whitelist = result.whitelist || [];
  customHashes = result.customHashes || [];
  
  // Load VirusTotal settings
  document.getElementById('vtApiKey').value = result.vtApiKey || '';
  
  const prefs = result.dbPreferences || {};
  document.getElementById('useVirusTotal').checked = prefs.useVirusTotal !== false;
  document.getElementById('useLocalDB').checked = prefs.useLocalDB === true;
  
  renderWhitelist();
  renderCustomHashes();
}

// Render whitelist
function renderWhitelist() {
  const listEl = document.getElementById('whitelistList');
  
  if (whitelist.length === 0) {
    listEl.innerHTML = '<div class="empty-list">Chưa có domain nào</div>';
    return;
  }
  
  listEl.innerHTML = whitelist.map((domain, index) => `
    <div class="list-item">
      <span>${domain}</span>
      <button class="btn-remove" data-index="${index}">Xóa</button>
    </div>
  `).join('');
  
  // Add remove handlers
  listEl.querySelectorAll('.btn-remove').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const index = parseInt(e.target.dataset.index);
      removeFromWhitelist(index);
    });
  });
}

// Render custom hashes
function renderCustomHashes() {
  const listEl = document.getElementById('customHashesList');
  
  if (customHashes.length === 0) {
    listEl.innerHTML = '<div class="empty-list">Chưa có hash nào</div>';
    return;
  }
  
  listEl.innerHTML = customHashes.map((item, index) => {
    const date = new Date(item.timestamp).toLocaleString('vi-VN');
    return `
      <div class="hash-item">
        <div class="hash-value">${item.hash}</div>
        <div class="hash-meta">
          ${item.type || 'Unknown'} • ${date}
          ${item.description ? `<br>${item.description}` : ''}
        </div>
        <button class="btn-remove" data-index="${index}" style="margin-top: 8px;">Xóa</button>
      </div>
    `;
  }).join('');
  
  // Add remove handlers
  listEl.querySelectorAll('.btn-remove').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const index = parseInt(e.target.dataset.index);
      removeCustomHash(index);
    });
  });
}

// Add to whitelist
async function addToWhitelist() {
  const input = document.getElementById('whitelistInput');
  const domain = input.value.trim();
  
  if (!domain) return;
  
  if (whitelist.includes(domain)) {
    alert('Domain này đã có trong whitelist!');
    return;
  }
  
  whitelist.push(domain);
  await browser.storage.local.set({ whitelist });
  
  input.value = '';
  renderWhitelist();
  showSuccess();
}

// Remove from whitelist
async function removeFromWhitelist(index) {
  whitelist.splice(index, 1);
  await browser.storage.local.set({ whitelist });
  renderWhitelist();
  showSuccess();
}

// Add custom hash
async function addCustomHash() {
  const hash = document.getElementById('hashInput').value.trim();
  const type = document.getElementById('hashType').value.trim();
  const description = document.getElementById('hashDescription').value.trim();
  
  if (!hash) {
    alert('Vui lòng nhập hash!');
    return;
  }
  
  // Validate hash format
  const hashLower = hash.toLowerCase();
  const isMD5 = /^[a-f0-9]{32}$/.test(hashLower);
  const isSHA1 = /^[a-f0-9]{40}$/.test(hashLower);
  const isSHA256 = /^[a-f0-9]{64}$/.test(hashLower);
  
  if (!isMD5 && !isSHA1 && !isSHA256) {
    alert('Hash không hợp lệ! Phải là MD5 (32 ký tự), SHA1 (40 ký tự), hoặc SHA256 (64 ký tự)');
    return;
  }
  
  customHashes.push({
    hash: hashLower,
    type: type || 'Unknown',
    description: description,
    timestamp: Date.now()
  });
  
  await browser.storage.local.set({ customHashes });
  
  // Clear inputs
  document.getElementById('hashInput').value = '';
  document.getElementById('hashType').value = '';
  document.getElementById('hashDescription').value = '';
  
  renderCustomHashes();
  showSuccess();
}

// Remove custom hash
async function removeCustomHash(index) {
  customHashes.splice(index, 1);
  await browser.storage.local.set({ customHashes });
  renderCustomHashes();
  showSuccess();
}

// Show success message
function showSuccess() {
  const msg = document.getElementById('successMessage');
  msg.style.display = 'block';
  setTimeout(() => {
    msg.style.display = 'none';
  }, 2000);
}

// Export settings
function exportSettings() {
  const data = {
    whitelist,
    customHashes,
    exportDate: new Date().toISOString()
  };
  
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `malware-checker-config-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// Import settings
function importSettings() {
  document.getElementById('importFile').click();
}

document.getElementById('importFile').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    
    if (data.whitelist) whitelist = data.whitelist;
    if (data.customHashes) customHashes = data.customHashes;
    
    await browser.storage.local.set({ whitelist, customHashes });
    
    renderWhitelist();
    renderCustomHashes();
    showSuccess();
  } catch (err) {
    alert('Lỗi khi import: ' + err.message);
  }
});

// Event listeners
document.getElementById('btnAddWhitelist').addEventListener('click', addToWhitelist);
document.getElementById('whitelistInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') addToWhitelist();
});

document.getElementById('btnAddHash').addEventListener('click', addCustomHash);
document.getElementById('btnExport').addEventListener('click', exportSettings);
document.getElementById('btnImport').addEventListener('click', importSettings);
document.getElementById('btnExportML').addEventListener('click', exportMLData);

// Export ML training data
async function exportMLData() {
  const response = await browser.runtime.sendMessage({ action: 'exportMLData' });
  
  if (response.success) {
    alert(`Đã export ${response.count} records thành công!`);
  } else {
    alert('Lỗi: ' + response.error);
  }
}

// Initialize
loadSettings();
