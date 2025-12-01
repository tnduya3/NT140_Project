// Enhanced blocking page with anime.js animations
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');
const tabId = parseInt(urlParams.get('tabId'));

document.getElementById('targetUrl').textContent = targetUrl;

let checkInterval;
let checkCount = 0;
let animationTimeline;

// Initialize animations when page loads
document.addEventListener('DOMContentLoaded', () => {
  initializeAnimations();
  createBackgroundParticles();
  startScanning();
});

// Create animated background particles
function createBackgroundParticles() {
  const particlesContainer = document.getElementById('particles');
  const particleCount = 50;
  
  for (let i = 0; i < particleCount; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.top = Math.random() * 100 + '%';
    particlesContainer.appendChild(particle);
    
    // Animate particle
    anime({
      targets: particle,
      translateX: () => anime.random(-100, 100),
      translateY: () => anime.random(-100, 100),
      scale: [0, 1, 0],
      opacity: [0, 0.8, 0],
      duration: () => anime.random(3000, 6000),
      delay: () => anime.random(0, 2000),
      loop: true,
      easing: 'easeInOutSine'
    });
  }
}

// Create scanning dots animation on circles
function createScanningDots() {
  const scanDots = document.getElementById('scanDots');
  
  // Dots on middle circle
  const middleDotCount = 6;
  const middleRadius = 100;
  
  for (let i = 0; i < middleDotCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'dot';
    
    const angle = (i / middleDotCount) * 360;
    const x = Math.cos(angle * Math.PI / 180) * middleRadius;
    const y = Math.sin(angle * Math.PI / 180) * middleRadius;
    
    dot.style.left = `calc(50% + ${x}px)`;
    dot.style.top = `calc(50% + ${y}px)`;
    dot.style.background = '#ff0080';
    
    scanDots.appendChild(dot);
    
    // Animate dot
    anime({
      targets: dot,
      scale: [0, 1.5, 0],
      opacity: [0, 1, 0],
      duration: 2000,
      delay: i * 333,
      loop: true,
      easing: 'easeInOutQuad'
    });
  }
  
  // Dots on inner circle
  const innerDotCount = 4;
  const innerRadius = 70;
  
  for (let i = 0; i < innerDotCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'dot';
    
    const angle = (i / innerDotCount) * 360 + 45; // Offset by 45 degrees
    const x = Math.cos(angle * Math.PI / 180) * innerRadius;
    const y = Math.sin(angle * Math.PI / 180) * innerRadius;
    
    dot.style.left = `calc(50% + ${x}px)`;
    dot.style.top = `calc(50% + ${y}px)`;
    dot.style.background = '#00ffcc';
    
    scanDots.appendChild(dot);
    
    // Animate dot
    anime({
      targets: dot,
      scale: [0, 1.3, 0],
      opacity: [0, 1, 0],
      duration: 1800,
      delay: i * 450,
      loop: true,
      easing: 'easeInOutQuad'
    });
  }
}

// Initialize all animations
function initializeAnimations() {
  // Create scanning dots
  createScanningDots();
  
  // Rings are animated via CSS, no need for anime.js here
  
  // Animate container entrance
  anime({
    targets: '.container',
    scale: [0.8, 1],
    opacity: [0, 1],
    duration: 1000,
    easing: 'easeOutElastic(1, .8)'
  });
}

// Start the scanning process
function startScanning() {
  checkInterval = setInterval(async () => {
    checkCount++;
    
    const response = await browser.runtime.sendMessage({
      action: 'checkStatus',
      tabId: tabId
    });
    
    if (response.status === 'no_check') {
      redirectToTarget();
      return;
    }
    
    const { status, hasMalware, hasSuspect, scripts, totalScripts } = response;
    
    // Update UI
    const checkedScripts = scripts.filter(s => s.status !== 'pending').length;
    updateProgress(checkedScripts, totalScripts);
    
    // Calculate average risk score
    const completedScripts = scripts.filter(s => s.status !== 'pending' && s.score);
    const avgScore = completedScripts.length > 0 
      ? Math.round(completedScripts.reduce((sum, s) => sum + (s.score?.score || 0), 0) / completedScripts.length)
      : 0;
    
    animateNumber('riskScore', avgScore);
    
    // Check if complete
    if (status === 'complete') {
      clearInterval(checkInterval);
      
      if (hasMalware) {
        showMalwareWarning(scripts);
      } else if (hasSuspect) {
        showSuspectWarning(scripts);
      } else {
        showSuccess();
        setTimeout(() => redirectToTarget(), 2000);
      }
    }
    
    // Timeout after 30 seconds
    if (checkCount > 60) {
      clearInterval(checkInterval);
      showTimeout();
    }
  }, 500);
}

// Update progress with animation
function updateProgress(checked, total) {
  const progress = total > 0 ? (checked / total) * 100 : 0;
  
  // Animate progress bar
  anime({
    targets: '#progressBar',
    width: progress + '%',
    duration: 500,
    easing: 'easeOutQuad'
  });
  
  // Animate numbers
  animateNumber('checkedCount', checked);
  animateNumber('totalCount', total);
}

// Animate number changes
function animateNumber(elementId, targetValue) {
  const element = document.getElementById(elementId);
  const currentValue = parseInt(element.textContent) || 0;
  
  if (currentValue !== targetValue) {
    anime({
      targets: { value: currentValue },
      value: targetValue,
      duration: 800,
      easing: 'easeOutQuad',
      update: function(anim) {
        element.textContent = Math.round(anim.animatables[0].target.value);
      }
    });
  }
}

// Show success state
function showSuccess() {
  // Change colors to green
  anime({
    targets: '.container',
    borderColor: '#00ff88',
    duration: 1000
  });
  
  anime({
    targets: '.shield-icon',
    background: 'linear-gradient(135deg, #00ff88, #00cc66)',
    scale: [1, 1.3, 1.1],
    duration: 1000,
    easing: 'easeOutElastic(1, .6)'
  });
  
  // Update text
  document.getElementById('title').textContent = '✅ AN TOÀN';
  document.getElementById('status').textContent = 'Không phát hiện mã độc. Đang chuyển hướng...';
  
  // Hide scanner rings
  anime({
    targets: '.scanner-ring',
    opacity: 0.3,
    duration: 500
  });
  
  // Success particles
  createSuccessParticles();
}

// Show malware warning
function showMalwareWarning(scripts) {
  const maliciousScripts = scripts.filter(s => s.status === 'malware');
  
  // Hide main content
  anime({
    targets: '.scanner-container, .progress-container, .stats, .url-display',
    opacity: 0,
    translateY: -30,
    duration: 500
  });
  
  // Change container style
  const container = document.getElementById('mainContainer');
  container.classList.add('warning-malware');
  
  // Show warning
  setTimeout(() => {
    const warningEl = document.getElementById('warningMalware');
    warningEl.classList.add('active');
    
    anime({
      targets: '#warningMalware',
      opacity: [0, 1],
      scale: [0.8, 1],
      duration: 800,
      easing: 'easeOutElastic(1, .8)'
    });
    
    // Show details
    const details = maliciousScripts.map(s => {
      const shortUrl = s.url.length > 50 ? s.url.substring(0, 50) + '...' : s.url;
      
      // Get detection info
      const source = s.source || 'unknown';
      const classification = s.classification || null;
      const severity = s.severity;
      const matchType = s.matchType || 'SHA256';
      
      let detectionInfo = '';
      let sourceDisplay = source;
      
      if (source === 'tempico' && classification) {
        detectionInfo = classification;
        if (severity !== undefined) {
          detectionInfo += ` (Severity: ${severity}/10)`;
        }
        sourceDisplay = 'Tempico Labs';
      } else if (source === 'custom') {
        detectionInfo = 'Custom blacklist';
        sourceDisplay = 'User defined';
      } else if (source === 'none') {
        // This is from static analysis scoring
        detectionInfo = 'Suspicious behavior detected';
        sourceDisplay = 'Static analysis';
      } else {
        detectionInfo = `Malware detected`;
        if (severity !== undefined) {
          detectionInfo += ` (Severity: ${severity}/10)`;
        }
      }
      
      return `
        <div class="script-item">
          <div class="script-score high-risk">⚠️ MALWARE DETECTED</div>
          <div class="script-url" title="${s.url}">${shortUrl}</div>
          <div class="warning-reason">${detectionInfo}</div>
          <div class="warning-reason">Source: ${sourceDisplay}</div>
          <div class="warning-reason">Hash: SHA256</div>
        </div>
      `;
    }).join('');
    
    document.getElementById('malwareDetails').innerHTML = details;
    
    // Glitch effect
    setInterval(() => {
      anime({
        targets: '.glitch',
        translateX: [0, -2, 2, 0],
        translateY: [0, 2, -2, 0],
        duration: 100
      });
    }, 2000);
    
  }, 500);
}

// Show suspect warning
function showSuspectWarning(scripts) {
  const suspectScripts = scripts.filter(s => s.status === 'suspect');
  
  // Hide main content
  anime({
    targets: '.scanner-container, .progress-container, .stats, .url-display',
    opacity: 0,
    translateY: -30,
    duration: 500
  });
  
  // Change container style
  const container = document.getElementById('mainContainer');
  container.classList.add('warning-suspect');
  
  // Show warning
  setTimeout(() => {
    const warningEl = document.getElementById('warningSuspect');
    warningEl.classList.add('active');
    
    anime({
      targets: '#warningSuspect',
      opacity: [0, 1],
      scale: [0.8, 1],
      duration: 800,
      easing: 'easeOutElastic(1, .8)'
    });
    
    // Show details
    const details = suspectScripts.map(s => {
      const reasons = s.score?.reasons || [];
      const shortUrl = s.url.length > 60 ? s.url.substring(0, 60) + '...' : s.url;
      const score = s.score?.score || 0;
      
      let riskClass = 'low-risk';
      if (score >= 70) riskClass = 'high-risk';
      else if (score >= 40) riskClass = 'medium-risk';
      
      return `
        <div class="script-item">
          <div class="script-score ${riskClass}">🔍 Score: ${score}/100</div>
          <div class="script-url">${shortUrl}</div>
          ${reasons.slice(0, 4).map(r => `<div class="warning-reason">${r}</div>`).join('')}
        </div>
      `;
    }).join('');
    
    document.getElementById('suspectDetails').innerHTML = details;
    
  }, 500);
}

// Show timeout state
function showTimeout() {
  document.getElementById('title').textContent = 'HẾT THỜI GIAN';
  document.getElementById('status').textContent = 'Không thể hoàn thành kiểm tra. Đang chuyển hướng...';
  
  anime({
    targets: '.container',
    borderColor: '#ffaa00',
    duration: 1000
  });
  
  setTimeout(() => redirectToTarget(), 3000);
}

// Create success particles effect
function createSuccessParticles() {
  const container = document.querySelector('.container');
  
  for (let i = 0; i < 20; i++) {
    const particle = document.createElement('div');
    particle.style.position = 'absolute';
    particle.style.width = '4px';
    particle.style.height = '4px';
    particle.style.background = '#00ff88';
    particle.style.borderRadius = '50%';
    particle.style.pointerEvents = 'none';
    particle.style.left = '50%';
    particle.style.top = '50%';
    
    container.appendChild(particle);
    
    anime({
      targets: particle,
      translateX: () => anime.random(-200, 200),
      translateY: () => anime.random(-200, 200),
      scale: [0, 1, 0],
      opacity: [1, 0],
      duration: 2000,
      easing: 'easeOutQuad',
      complete: () => particle.remove()
    });
  }
}

// Redirect to target URL
async function redirectToTarget() {
  // Notify background script to approve this tab
  await browser.runtime.sendMessage({
    action: 'approveTab',
    tabId: tabId,
    url: targetUrl
  });
  
  // Animate exit
  anime({
    targets: '.container',
    scale: 0.8,
    opacity: 0,
    duration: 500,
    easing: 'easeInBack(1.7)',
    complete: () => {
      setTimeout(() => {
        window.location.href = targetUrl;
      }, 100);
    }
  });
}

// Button event handlers
document.getElementById('btnBlockMalware')?.addEventListener('click', () => {
  anime({
    targets: '.container',
    scale: 0,
    opacity: 0,
    duration: 300,
    complete: () => window.close()
  });
});

document.getElementById('btnContinueMalware')?.addEventListener('click', () => {
  redirectToTarget();
});

document.getElementById('btnBlockSuspect')?.addEventListener('click', () => {
  anime({
    targets: '.container',
    scale: 0,
    opacity: 0,
    duration: 300,
    complete: () => window.close()
  });
});

document.getElementById('btnContinueSuspect')?.addEventListener('click', () => {
  redirectToTarget();
});