// Background script - Main logic
const pendingChecks = new Map(); // tabId -> {url, scripts: []}
const checkedScripts = new Map(); // url -> {hash, status, timestamp}
const approvedTabs = new Map(); // tabId -> {url, timestamp}
const mlExportData = []; // Store features for ML training

// Load whitelist và settings
let whitelist = [];
let isEnabled = true;

// Analyze script: hash check + feature extraction + scoring
async function analyzeScript(content, url) {
  // 1. Calculate SHA256 hash only
  const sha256 = await HashUtils.calculateSHA256(content);
  
  if (!sha256) {
    console.error('[Malware Checker] Failed to calculate hash');
    return {
      sha256: null,
      hashResult: { found: false },
      features: null,
      score: null,
      status: 'error'
    };
  }
  
  // 2. Check hash against database
  const hashResult = await HashDB.checkHash(sha256);
  
  // 3. Extract features (static analysis) - always do this
  const featureResult = await FeatureExtractor.extractFeatures(content, url);
  
  if (!featureResult.success) {
    return {
      sha256,
      hashResult,
      features: featureResult.features,
      score: null,
      status: 'error'
    };
  }
  
  // 4. Calculate risk score with multi-factor assessment
  // Hash match adds +40 points, not auto-block
  const score = Scorer.calculateScore(featureResult.features, hashResult);
  
  // 5. Determine status based on score
  let status = 'clean';
  if (score.action === 'block') {
    status = 'malware';
    console.warn(`[Malware Checker] Blocked by scoring: ${score.score}/100`);
  } else if (score.action === 'suspect') {
    status = 'suspect';
  }
  
  // 6. Store for ML export
  const mlData = Scorer.exportForML(featureResult.features, score);
  mlExportData.push(mlData);
  
  // Keep only last 100 entries
  if (mlExportData.length > 100) {
    mlExportData.shift();
  }
  
  return {
    sha256,
    hashResult,
    features: featureResult.features,
    score,
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
    
    // Store result
    checkedScripts.set(url, {
      sha256: analysis.sha256,
      status: analysis.status,
      matchType: analysis.hashResult?.type || 'SHA256',
      score: analysis.score,
      features: analysis.features,
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
        pending.scripts = scripts.map(url => ({
          url,
          status: 'pending'
        }));
        
        // Start analyzing
        scripts.forEach(scriptUrl => {
          downloadAndAnalyzeScript(scriptUrl).then(analysis => {
            const script = pending.scripts.find(s => s.url === scriptUrl);
            if (script) {
              script.status = analysis.status;
              script.score = analysis.score;
              script.features = analysis.features;
              script.sha256 = analysis.sha256;
              
              // Store hash result info
              if (analysis.hashResult) {
                script.matchType = 'SHA256';
                script.classification = analysis.hashResult.classification;
                script.severity = analysis.hashResult.severity;
                script.source = analysis.hashResult.source;
              } else {
                script.matchType = 'SHA256';
                script.source = 'none';
              }
            }
          });
        });
      }
    });
    
    // Initialize pending check
    pendingChecks.set(tabId, {
      url: url,
      scripts: [],
      startTime: Date.now()
    });
    
    // Redirect to blocking page
    const blockingUrl = browser.runtime.getURL('ui/blocking.html') + 
                       '?url=' + encodeURIComponent(url) + 
                       '&tabId=' + tabId;
    
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
  
  if (message.action === 'exportMLData') {
    const dataStr = JSON.stringify(mlExportData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    browser.downloads.download({
      url: url,
      filename: `malware-features-${Date.now()}.json`,
      saveAs: true
    }).then(() => {
      URL.revokeObjectURL(url);
      sendResponse({ success: true, count: mlExportData.length });
    }).catch(err => {
      sendResponse({ success: false, error: err.message });
    });
    
    return true;
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
