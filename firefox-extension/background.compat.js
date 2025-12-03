// Compatibility background script - keeps analysis logic but adds a tabs.update fallback
// This file mirrors background.js behavior but attempts a safe fallback when onBeforeRequest
// redirect isn't honored by the browser (useful for Safari / some Chromium MV3 environments).

const pendingChecksCompat = new Map(); // tabId -> { url, previousUrl, scripts: [] }
const checkedScriptsCompat = new Map();
const approvedTabsCompat = new Map();

let whitelistCompat = [];
let isEnabledCompat = true;

// copy of analyzeScript from main background (assumes HashUtils, HashDB, IpDB are loaded)
async function analyzeScriptCompat(content, url) {
  const sha256 = await HashUtils.calculateSHA256(content);
  console.info('[Malware Checker Compat] Calculated SHA256 for', url, sha256);

  if (!sha256) return { sha256: null, hashResult: { found: false }, ipMatches: [], status: 'error' };

  const hashResult = await HashDB.checkHash(sha256);
  console.info('[Malware Checker Compat] HashDB result for', sha256, hashResult);

  const ipRegex = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
  const ips = Array.from(new Set((content.match(ipRegex) || []).map(s => s.trim())));
  const ipMatches = [];
  if (typeof IpDB !== 'undefined' && IpDB && IpDB.isIpBlacklisted) {
    for (const ip of ips) {
      try {
        const res = await IpDB.isIpBlacklisted(ip);
        if (res && res.found) ipMatches.push(res);
      } catch (e) {}
    }
  }

  let status = 'clean';
  if (hashResult && hashResult.found) status = 'malware';
  else if (ipMatches.length > 0) status = 'malware';

  return { sha256, hashResult, ipMatches, status };
}

async function fetchPageScriptsCompat(url) {
  try {
    const response = await fetch(url);
    const html = await response.text();
    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    const scripts = [];
    let match;
    while ((match = scriptRegex.exec(html)) !== null) {
      let scriptUrl = match[1];
      if (scriptUrl.startsWith('//')) scriptUrl = 'https:' + scriptUrl;
      else if (scriptUrl.startsWith('/')) {
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
    console.error('[Malware Checker Compat] Failed to fetch page:', err);
    return [];
  }
}

async function downloadAndAnalyzeScriptCompat(url) {
  try {
    const response = await fetch(url);
    const content = await response.text();
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000));
    const analysis = await Promise.race([analyzeScriptCompat(content, url), timeoutPromise]).catch(err => ({ status: 'error', error: err.message }));

    checkedScriptsCompat.set(url, {
      sha256: analysis.sha256,
      status: analysis.status,
      matchType: analysis.hashResult?.type || 'SHA256',
      hashSource: analysis.hashResult?.source || 'none',
      ipMatches: analysis.ipMatches || [],
      timestamp: Date.now()
    });

    return analysis;
  } catch (err) {
    console.error('[Malware Checker Compat] Download error:', err);
    return { status: 'error', error: err.message };
  }
}

// Helper to open blocking UI in the tab (fallback if redirect isn't honored)
async function openBlockingTabCompat(tabId, url, previousUrl) {
  const blockingUrl = browser.runtime.getURL('ui/blocking.html') +
                       '?url=' + encodeURIComponent(url) +
                       '&tabId=' + tabId +
                       (previousUrl ? '&previous=' + encodeURIComponent(previousUrl) : '');
  try {
    await browser.tabs.update(tabId, { url: blockingUrl });
    console.info('[Malware Checker Compat] openBlockingTab: updated tab', tabId, blockingUrl);
  } catch (err) {
    console.warn('[Malware Checker Compat] tabs.update failed, creating new tab', err);
    try {
      await browser.tabs.create({ url: blockingUrl });
    } catch (e) {
      console.error('[Malware Checker Compat] tabs.create also failed', e);
    }
  }
}

// Initialize preferences from storage (mirrors background.js)
browser.storage.local.get(['whitelist', 'isEnabled', 'customHashes', 'dbPreferences']).then(async result => {
  whitelistCompat = result.whitelist || [];
  isEnabledCompat = result.isEnabled !== false;
  if (result.customHashes) HashDB.addCustomHashes(result.customHashes);
  if (result.dbPreferences) await HashDB.setPreferences(result.dbPreferences);
  else await HashDB.setPreferences({ useTempico: true });
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.whitelist) whitelistCompat = changes.whitelist.newValue || [];
    if (changes.isEnabled) isEnabledCompat = changes.isEnabled.newValue;
    if (changes.customHashes) HashDB.addCustomHashes(changes.customHashes.newValue);
  }
});

function isWhitelistedCompat(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    return whitelistCompat.some(pattern => {
      if (pattern.startsWith('*.')) {
        const baseDomain = pattern.slice(2);
        return domain.endsWith(baseDomain);
      }
      return domain === pattern;
    });
  } catch (e) { return false; }
}

// Main onBeforeRequest listener (tries to return redirectUrl like original, but schedules a fallback)
browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (!isEnabledCompat) return {};
    if (details.type !== 'main_frame') return {};

    const url = details.url;
    const tabId = details.tabId;
    if (url.startsWith('about:') || url.startsWith('moz-extension:')) return {};

    const approved = approvedTabsCompat.get(tabId);
    if (approved && approved.url === url) {
      const timeSinceApproval = Date.now() - approved.timestamp;
      if (timeSinceApproval < 10000) return {};
      else approvedTabsCompat.delete(tabId);
    }

    // capture previous url if possible
    let previousUrl = null;
    try {
      const tabInfo = await browser.tabs.get(tabId);
      previousUrl = tabInfo && tabInfo.url ? tabInfo.url : null;
    } catch (e) {}

    // Start fetching scripts asynchronously
    fetchPageScriptsCompat(url).then(scripts => {
      const pending = pendingChecksCompat.get(tabId);
      if (pending) {
        pending.scripts = scripts.map(u => ({ url: u, status: 'pending' }));
        scripts.forEach(scriptUrl => {
          downloadAndAnalyzeScriptCompat(scriptUrl).then(analysis => {
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

    pendingChecksCompat.set(tabId, { url, previousUrl, scripts: [], startTime: Date.now() });

    const blockingUrl = browser.runtime.getURL('ui/blocking.html') +
                         '?url=' + encodeURIComponent(url) +
                         '&tabId=' + tabId +
                         (previousUrl ? '&previous=' + encodeURIComponent(previousUrl) : '');

    // Attempt to return redirectUrl (as before). Some browsers will honor this.
    const redirectResponse = { redirectUrl: blockingUrl };

    // Schedule a fallback check shortly after navigation — if the browser didn't redirect,
    // programmatically navigate the tab to the blocking UI.
    setTimeout(async () => {
      try {
        const tab = await browser.tabs.get(tabId);
        if (!tab) return;
        // If current tab URL is not the blocking UI, assume redirect wasn't honored
        if (!tab.url || !tab.url.startsWith(browser.runtime.getURL('ui/blocking.html'))) {
          console.warn('[Malware Checker Compat] Redirect not honored, using tabs.update fallback', { tabId, url: tab.url });
          await openBlockingTabCompat(tabId, url, previousUrl);
        }
      } catch (e) {
        // ignore errors retrieving tab
      }
    }, 600);

    return redirectResponse;
  },
  { urls: ['<all_urls>'] },
  ['blocking']
);

browser.tabs.onRemoved.addListener((tabId) => {
  approvedTabsCompat.delete(tabId);
  pendingChecksCompat.delete(tabId);
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkStatus') {
    const tabId = message.tabId;
    const pending = pendingChecksCompat.get(tabId);
    if (!pending) { sendResponse({ status: 'no_check' }); return; }
    const allChecked = pending.scripts.length > 0 && pending.scripts.every(s => s.status !== 'pending');
    const hasMalware = pending.scripts.some(s => s.status === 'malware');
    const hasSuspect = pending.scripts.some(s => s.status === 'suspect');
    sendResponse({ status: allChecked ? 'complete' : 'checking', hasMalware, hasSuspect, scripts: pending.scripts, totalScripts: pending.scripts.length });
    if (allChecked) setTimeout(() => pendingChecksCompat.delete(tabId), 5000);
  }

  if (message.action === 'approveTab') {
    const tabId = message.tabId; const url = message.url;
    approvedTabsCompat.set(tabId, { url, timestamp: Date.now() });
    sendResponse({ success: true });
  }

  if (message.action === 'getCheckedScripts') {
    const scripts = Array.from(checkedScriptsCompat.entries()).map(([u, data]) => ({ url: u, ...data }));
    sendResponse({ scripts });
  }

  if (message.action === 'addToWhitelist') {
    const domain = message.domain; if (!whitelistCompat.includes(domain)) { whitelistCompat.push(domain); browser.storage.local.set({ whitelist: whitelistCompat }); }
    sendResponse({ success: true });
  }

  if (message.action === 'submitHash') {
    browser.storage.local.get('customHashes').then(result => {
      const customHashes = result.customHashes || [];
      customHashes.push({ hash: message.hash, type: message.type, description: message.description, timestamp: Date.now() });
      browser.storage.local.set({ customHashes });
      HashDB.addCustomHashes(customHashes);
      sendResponse({ success: true });
    });
    return true;
  }
});
