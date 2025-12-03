// Background script - Main logic (simplified)
const pendingChecks = new Map(); // tabId -> {url, scripts: []}
const checkedScripts = new Map(); // url -> {sha256, status, timestamp}
const approvedTabs = new Map(); // tabId -> {url, timestamp}

// Load whitelist và settings
let whitelist = [];
let isEnabled = true;

// Analyze script: compute SHA256 and check IP literals against IpDB
async function analyzeScript(content, url) {
  // 1. Calculate SHA256 hash
  const sha256 = await HashUtils.calculateSHA256(content);

  // Log calculated hash
  try {
    console.info('[Malware Checker] Calculated SHA256 for', url, sha256);
  } catch (e) {}

  if (!sha256) {
    console.error('[Malware Checker] Failed to calculate hash');
    return {
      sha256: null,
      hashResult: { found: false },
      ipMatches: [],
      status: 'error'
    };
  }

  // 2. Check hash against database
  const hashResult = await HashDB.checkHash(sha256);

  // Log hash DB check result
  try {
    console.info('[Malware Checker] HashDB result for', sha256, hashResult);
  } catch (e) {}

  // 3. Scan for IP literals in the script and check IpDB
  const ipRegex = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
  const ips = Array.from(new Set((content.match(ipRegex) || []).map(s => s.trim())));
  const ipMatches = [];
  if (typeof IpDB !== 'undefined' && IpDB && IpDB.isIpBlacklisted) {
    for (const ip of ips) {
      try {
        const res = await IpDB.isIpBlacklisted(ip);
        if (res && res.found) ipMatches.push(res);
      } catch (e) {
        // ignore per-IP errors
      }
    }
  }

  // 4. Determine status: hash match OR any blacklisted IP -> malware
  let status = 'clean';
  if (hashResult && hashResult.found) {
    status = 'malware';
  } else if (ipMatches.length > 0) {
    status = 'malware';
  }

  return {
    sha256,
    hashResult,
    ipMatches,
    status
  };
}

// Fetch page and extract script URLs
async function fetchPageScripts(url) {
  try {
    const response = await fetch(url);
    const html = await response.text();
    
    // Extract script URLs
    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    const scripts = [];
    let match;
    
    while ((match = scriptRegex.exec(html)) !== null) {
      let scriptUrl = match[1];
      
      // Convert relative to absolute
      if (scriptUrl.startsWith('//')) {
        scriptUrl = 'https:' + scriptUrl;
      } else if (scriptUrl.startsWith('/')) {
        const urlObj = new URL(url);
        scriptUrl = urlObj.origin + scriptUrl;
      } else if (!scriptUrl.startsWith('http')) {
        const urlObj = new URL(url);
        const basePath = urlObj.pathname.substring(0, urlObj.pathname.lastIndexOf('/') + 1);
        scriptUrl = urlObj.origin + basePath + scriptUrl;
      }
      
      scripts.push(scriptUrl);
    }
    
    return scripts;
  } catch (err) {
    console.error('[Malware Checker] Failed to fetch page:', err);
    return [];
  }
}

// Download and analyze a script
async function downloadAndAnalyzeScript(url) {
  try {
    const response = await fetch(url);
    const content = await response.text();
        
    // Timeout protection
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), 10000)
    );
    
    const analysis = await Promise.race([
      analyzeScript(content, url),
      timeoutPromise
    ]).catch(err => ({
      status: 'error',
      error: err.message
    }));

    // Store simplified result
    checkedScripts.set(url, {
      sha256: analysis.sha256,
      status: analysis.status,
      matchType: analysis.hashResult?.type || 'SHA256',
      hashSource: analysis.hashResult?.source || 'none',
      ipMatches: analysis.ipMatches || [],
      timestamp: Date.now()
    });

    return analysis;
  } catch (err) {
    console.error('[Malware Checker] Download error:', err);
    return { status: 'error', error: err.message };
  }
}

// Initialize
browser.storage.local.get(['whitelist', 'isEnabled', 'customHashes', 'dbPreferences']).then(async result => {
  whitelist = result.whitelist || [];
  isEnabled = result.isEnabled !== false;
  
  if (result.customHashes) {
    HashDB.addCustomHashes(result.customHashes);
  }
  
  // Initialize HashDB preferences
  if (result.dbPreferences) {
    await HashDB.setPreferences(result.dbPreferences);
  } else {
    // Set default: use Tempico
    await HashDB.setPreferences({ useTempico: true });
  }
});

// Listen for storage changes
browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.whitelist) whitelist = changes.whitelist.newValue || [];
    if (changes.isEnabled) isEnabled = changes.isEnabled.newValue;
    if (changes.customHashes) HashDB.addCustomHashes(changes.customHashes.newValue);
  }
});

// Check if domain is whitelisted
function isWhitelisted(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    return whitelist.some(pattern => {
      if (pattern.startsWith('*.')) {
        const baseDomain = pattern.slice(2);
        return domain.endsWith(baseDomain);
      }
      return domain === pattern;
    });
  } catch (e) {
    return false;
  }
}

// Intercept main document requests
browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (!isEnabled) return {};
    
    if (details.type !== 'main_frame') return {};
    
    const url = details.url;
    const tabId = details.tabId;
    
    // Skip internal pages
    if (url.startsWith('about:') || url.startsWith('moz-extension:')) {
      return {};
    }
    
    // Check if already approved
    const approved = approvedTabs.get(tabId);
    if (approved && approved.url === url) {
      const timeSinceApproval = Date.now() - approved.timestamp;
      if (timeSinceApproval < 10000) {
        console.log('[Malware Checker] Already approved:', url);
        return {};
      } else {
        approvedTabs.delete(tabId);
      }
    }
    
    // Fetch page and extract scripts (async, don't wait)
    fetchPageScripts(url).then(scripts => {
      const pending = pendingChecks.get(tabId);
      if (pending) {
        pending.scripts = scripts.map(url => ({ url, status: 'pending' }));

        // Start analyzing
        scripts.forEach(scriptUrl => {
          downloadAndAnalyzeScript(scriptUrl).then(analysis => {
            const script = pending.scripts.find(s => s.url === scriptUrl);
            if (script) {
              script.status = analysis.status;
              script.sha256 = analysis.sha256;
              script.ipMatches = analysis.ipMatches || [];
              script.hashResult = analysis.hashResult || { found: false };
              script.matchType = 'SHA256';
            }
          });
        });
      }
    });
    
    // Initialize pending check
    // Try to capture the tab's current URL (the page user was on before this navigation)
    let previousUrl = null;
    try {
      const tabInfo = await browser.tabs.get(tabId);
      previousUrl = tabInfo && tabInfo.url ? tabInfo.url : null;
    } catch (e) {
      // ignore - may fail for some internal tabs
    }

    pendingChecks.set(tabId, {
      url: url,
      previousUrl: previousUrl,
      scripts: [],
      startTime: Date.now()
    });
    
    // Redirect to blocking page
    // Include previous URL so the blocking UI can navigate back if requested
    const blockingUrl = browser.runtime.getURL('ui/blocking.html') +
               '?url=' + encodeURIComponent(url) +
               '&tabId=' + tabId +
               (previousUrl ? '&previous=' + encodeURIComponent(previousUrl) : '');
    
    return { redirectUrl: blockingUrl };
  },
  { urls: ['<all_urls>'] },
  ['blocking']
);

// Clean up approved tabs when tab is closed
browser.tabs.onRemoved.addListener((tabId) => {
  approvedTabs.delete(tabId);
  pendingChecks.delete(tabId);
});

// Message handler from blocking page
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkStatus') {
    const tabId = message.tabId;
    const pending = pendingChecks.get(tabId);
    
    if (!pending) {
      sendResponse({ status: 'no_check' });
      return;
    }
    
    // Check if all scripts are checked
    const allChecked = pending.scripts.length > 0 && pending.scripts.every(s => s.status !== 'pending');
    const hasMalware = pending.scripts.some(s => s.status === 'malware');
    const hasSuspect = pending.scripts.some(s => s.status === 'suspect');
    
    sendResponse({
      status: allChecked ? 'complete' : 'checking',
      hasMalware: hasMalware,
      hasSuspect: hasSuspect,
      scripts: pending.scripts,
      totalScripts: pending.scripts.length
    });
    
    // Clean up if complete
    if (allChecked) {
      setTimeout(() => pendingChecks.delete(tabId), 5000);
    }
  }
  
  
  if (message.action === 'approveTab') {
    const tabId = message.tabId;
    const url = message.url;
    
    approvedTabs.set(tabId, {
      url: url,
      timestamp: Date.now()
    });
    
    sendResponse({ success: true });
  }
  
  if (message.action === 'getCheckedScripts') {
    const scripts = Array.from(checkedScripts.entries()).map(([url, data]) => ({
      url,
      ...data
    }));
    sendResponse({ scripts });
  }
  
  if (message.action === 'addToWhitelist') {
    const domain = message.domain;
    if (!whitelist.includes(domain)) {
      whitelist.push(domain);
      browser.storage.local.set({ whitelist });
    }
    sendResponse({ success: true });
  }
  
  if (message.action === 'submitHash') {
    browser.storage.local.get('customHashes').then(result => {
      const customHashes = result.customHashes || [];
      customHashes.push({
        hash: message.hash,
        type: message.type,
        description: message.description,
        timestamp: Date.now()
      });
      browser.storage.local.set({ customHashes });
      HashDB.addCustomHashes(customHashes);
      sendResponse({ success: true });
    });
    return true;
  }
});
