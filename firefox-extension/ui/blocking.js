// Simplified blocking page (no animations)
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');
const tabId = parseInt(urlParams.get('tabId'));
const previousUrl = urlParams.get('previous');

const targetEl = document.getElementById('targetUrl');
if (targetEl) targetEl.textContent = targetUrl || '';

let checkInterval;
let checkCount = 0;

document.addEventListener('DOMContentLoaded', () => {
  startScanning();
});

// Start the scanning process (polling checkStatus)
function startScanning() {
  checkInterval = setInterval(async () => {
    checkCount++;
    let response;
    try {
      response = await browser.runtime.sendMessage({ action: 'checkStatus', tabId });
    } catch (err) {
      console.error('[Blocking] checkStatus sendMessage failed', err);
      response = null;
    }
    if (!response || response.status === 'no_check') {
      console.info('[Blocking] no pending check, redirecting immediately', { tabId, targetUrl });
      redirectToTarget();
      return;
    }

    const { status, scripts = [], totalScripts = 0 } = response;
    console.debug('[Blocking] checkStatus response', { tabId, status, scriptsCount: scripts.length, totalScripts });

    const checkedScripts = scripts.filter(s => s.status !== 'pending').length;
    updateProgress(checkedScripts, totalScripts);

    // Count threats (hash matches or ip matches)
    const maliciousScripts = scripts.filter(s => s.status === 'malware');
    const ipThreats = scripts.filter(s => s.ipMatches && s.ipMatches.length > 0 && s.status !== 'malware');
    const threatCount = maliciousScripts.length + ipThreats.length;
    setNumber('riskScore', threatCount);

    if (status === 'complete') {
      clearInterval(checkInterval);
      if (threatCount > 0) showMalwareWarning(scripts);
      else {
        showSuccess();
        setTimeout(() => redirectToTarget(), 1500);
      }
    }

    if (checkCount > 60) {
      clearInterval(checkInterval);
      showTimeout();
    }
  }, 500);
}

// Update progress with animation
function updateProgress(checked, total) {
  const progress = total > 0 ? Math.round((checked / total) * 100) : 0;
  const progressBar = document.getElementById('progressBar');
  if (progressBar) progressBar.style.width = progress + '%';
  setNumber('checkedCount', checked);
  setNumber('totalCount', total);
}

function setNumber(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

// Show success state
function showSuccess() {
  const title = document.getElementById('title');
  const status = document.getElementById('status');
  if (title) title.textContent = 'AN TOÀN';
  if (status) status.textContent = 'Không phát hiện mã độc. Đang chuyển hướng...';
}

// Show malware warning
function showMalwareWarning(scripts) {
  const details = scripts.filter(s => s.status === 'malware' || (s.ipMatches && s.ipMatches.length > 0)).map(s => {
    const shortUrl = s.url.length > 80 ? s.url.substring(0, 80) + '...' : s.url;
    const hash = s.sha256 || 'n/a';
    const hashSource = s.hashResult?.source || (s.hashResult && s.hashResult.found ? 'local' : 'none');
    const ipList = (s.ipMatches || []).map(im => im.ip || (im.meta && (im.meta.IP || im.meta.ip)) || JSON.stringify(im)).join(', ');
    return `<div class="script-item"><div class="script-url" title="${s.url}">${shortUrl}</div><div>Hash: ${hash}</div><div>Hash source: ${hashSource}</div>${ipList ? `<div>IP matches: ${ipList}</div>` : ''}</div>`;
  }).join('');

  const warningEl = document.getElementById('warningMalware');
  const detailsEl = document.getElementById('malwareDetails');
  const container = document.getElementById('mainContainer');
  if (detailsEl) detailsEl.innerHTML = details;
  if (container) container.classList.add('warning-malware');
  if (warningEl) warningEl.hidden = false;
}

// Show suspect warning
function showSuspectWarning(scripts) {
  const suspectScripts = scripts.filter(s => s.status === 'suspect');
  const details = suspectScripts.map(s => `<div class="script-item"><div class="script-url">${s.url}</div></div>`).join('');
  const detailsEl = document.getElementById('suspectDetails');
  const warningEl = document.getElementById('warningSuspect');
  if (detailsEl) detailsEl.innerHTML = details;
  if (warningEl) warningEl.hidden = false;
}

// Show timeout state
function showTimeout() {
  document.getElementById('title').textContent = 'HẾT THỜI GIAN';
  document.getElementById('status').textContent = 'Không thể hoàn thành kiểm tra. Đang chuyển hướng...';
  // Simple visual change, then redirect after a short delay
  const container = document.querySelector('.container');
  if (container) container.style.borderColor = '#ffaa00';
  setTimeout(() => {
    console.info('[Blocking] timeout reached, redirecting', { tabId, targetUrl });
    redirectToTarget();
  }, 3000);
}

// Create success particles effect
function createSuccessParticles() {
  // Removed particle animation dependency; keep this as a no-op placeholder
  // so other code can call it safely without anime.js.
  const container = document.querySelector('.container');
  if (!container) return;
  // Small visual flash using CSS transitions
  container.style.transition = 'box-shadow 400ms ease-out';
  container.style.boxShadow = '0 0 20px rgba(0,255,136,0.6)';
  setTimeout(() => {
    container.style.boxShadow = '';
  }, 600);
}

// Redirect to target URL
async function redirectToTarget() {
  // Notify background script to approve this tab
  await browser.runtime.sendMessage({
    action: 'approveTab',
    tabId: tabId,
    url: targetUrl
  });
  // Simple fade-out then navigate
  const container = document.querySelector('.container');
  if (container) {
    container.style.transition = 'opacity 300ms ease-out, transform 300ms ease-out';
    container.style.opacity = '0';
    container.style.transform = 'scale(0.95)';
    setTimeout(() => {
      window.location.href = targetUrl || '/';
    }, 350);
  } else {
    window.location.href = targetUrl || '/';
  }
}

// Button event handlers
function navigateBack() {
  console.info('[Blocking] navigateBack called', { tabId, previousUrl });
  if (previousUrl) {
    // Navigate directly to previous URL
    window.location.href = previousUrl;
  } else {
    // Fallback to history.back() if no explicit previous URL
    try {
      window.history.back();
    } catch (e) {
      window.close();
    }
  }
}

document.getElementById('btnBlockMalware')?.addEventListener('click', () => navigateBack());
document.getElementById('btnContinueMalware')?.addEventListener('click', () => redirectToTarget());
document.getElementById('btnBlockSuspect')?.addEventListener('click', () => navigateBack());
document.getElementById('btnContinueSuspect')?.addEventListener('click', () => redirectToTarget());