// Tempico Labs (itsecurity.ee) API - Simple single hash lookup
const TempicoAPI = {
  
  // API configuration
  config: {
    // Note: Endpoint might need adjustment based on API docs
    endpoint: 'https://api.itsecurity.ee/v4/hash/',
    timeout: 10000,
    severityThreshold: 5 // Consider malware if severity >= 5
  },
  
  // Check single hash using GET
  async checkHash(hash, hashType = 'auto') {
    try {
      // Accept either a pre-computed hash string OR raw input (string, ArrayBuffer, Uint8Array, Blob/File)
      if (!hash) {
        return { found: false, source: 'tempico', message: 'Invalid hash' };
      }

      // If caller passed raw bytes/file instead of a hash string, compute SHA256 hex (preferred)
      if (typeof hash !== 'string') {
        if (typeof CryptoUtils !== 'undefined' && CryptoUtils.calculateSHA256Hex) {
          try {
            const computed = await CryptoUtils.calculateSHA256Hex(hash);
            if (!computed) {
              return { found: false, source: 'tempico', message: 'Failed to compute hash from input' };
            }
            console.log('[Tempico] Computed SHA256 from input for lookup');
            hash = computed;
            hashType = 'sha256';
          } catch (e) {
            console.error('[Tempico] Error computing hash from input:', e);
            return { found: false, source: 'tempico', message: 'Error computing hash from input' };
          }
        } else {
          return { found: false, source: 'tempico', message: 'Invalid hash (non-string) and CryptoUtils unavailable' };
        }
      }

      const cleanHash = hash.toLowerCase().trim();
      
      // Validate hash format and length
      if (!/^[a-f0-9]+$/.test(cleanHash)) {
        console.warn('[Tempico] Invalid hash format:', cleanHash);
        return { found: false, source: 'tempico', message: 'Invalid hash format' };
      }
      
      // Check hash length (MD5=32, SHA1=40, SHA256=64)
      const validLengths = [32, 40, 64];
      if (!validLengths.includes(cleanHash.length)) {
        console.warn(`[Tempico] Invalid hash length: ${cleanHash.length}, expected 32/40/64`);
        return { found: false, source: 'tempico', message: 'Invalid hash length' };
      }
      
      console.log(`[Tempico] Checking hash: ${cleanHash.substring(0, 16)}... (length: ${cleanHash.length})`);
      
      // Make GET request
      const url = `${this.config.endpoint}${cleanHash}`;
      console.log(`[Tempico] Request URL: ${url}`);
      
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Mozilla/5.0 Firefox Extension'
        }
      });
      
      console.log(`[Tempico] Response status: ${response.status}`);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[Tempico] HTTP ${response.status}:`, errorText);
        throw new Error(`HTTP ${response.status}: ${errorText.substring(0, 100)}`);
      }
      
      const data = await response.json();
      console.log('[Tempico] API Response:', data);
      
      // Parse response
      return this.parseResponse(data, cleanHash, hashType);
      
    } catch (error) {
      console.error('[Tempico] API error:', error);
      return {
        found: false,
        error: error.message,
        source: 'tempico'
      };
    }
  },
  
  // Parse API response
  parseResponse(data, hash, hashType) {
    // Check if request was successful
    if (!data.success) {
      return {
        found: false,
        source: 'tempico',
        message: 'API request failed'
      };
    }
    
    // Check payload
    if (!data.payload || data.payload.length === 0) {
      return {
        found: false,
        source: 'tempico',
        message: 'Hash not found in database'
      };
    }
    
    const item = data.payload[0];
    
    // Check if found and infected
    const found = item.found === true;
    const infected = item.infected === true;
    const severity = item.severity || 0;
    
    // Determine if malicious
    const isMalicious = infected && severity >= this.config.severityThreshold;
    
    return {
      found: isMalicious,
      source: 'tempico',
      type: hashType.toUpperCase(),
      
      // Hash information
      md5: item.md5,
      sha1: item.sha1,
      sha256: item.sha256,
      
      // Detection information
      infected: infected,
      classification: item.classification || 'Unknown',
      severity: severity,
      
      // File information
      magic: item.magic,
      size: item.size,
      
      // Timestamps
      createdAt: item.created_at,
      lastScan: item.last_scan,
      lastAccess: item.last_access,
      
      // Risk assessment
      riskLevel: this.calculateRiskLevel(severity, infected),
      
      // Message
      message: isMalicious 
        ? `${item.classification} (Severity: ${severity}/10)`
        : infected 
          ? `Low severity (${severity}/10)`
          : 'Clean or not found'
    };
  },
  
  // Calculate risk level
  calculateRiskLevel(severity, infected) {
    if (!infected) return 'clean';
    
    if (severity >= 8) return 'critical';
    if (severity >= 6) return 'high';
    if (severity >= 4) return 'medium';
    if (severity >= 2) return 'low';
    return 'minimal';
  },
  
  // Check multiple hashes (try each one)
  async checkHashes(hashes) {
    // Try SHA256 first (most reliable)
    // Normalize inputs: allow file/ArrayBuffer/Uint8Array for any provided hash and compute canonical hex
    if (hashes.sha256) {
      let h = hashes.sha256;
      if (typeof h !== 'string' && typeof CryptoUtils !== 'undefined' && CryptoUtils.calculateSHA256Hex) {
        try { h = await CryptoUtils.calculateSHA256Hex(h); } catch (e) { console.warn('[Tempico] Failed to compute sha256 from input', e); }
      }
      if (h) {
        const result = await this.checkHash(h, 'sha256');
        if (result.found === true) return result;
      }
    }
    
    // Try SHA1
    if (hashes.sha1) {
      let h = hashes.sha1;
      if (typeof h !== 'string' && typeof CryptoUtils !== 'undefined' && CryptoUtils.calculateSHA1Hex) {
        try { h = await CryptoUtils.calculateSHA1Hex(h); } catch (e) { console.warn('[Tempico] Failed to compute sha1 from input', e); }
      }
      if (h) {
        const result = await this.checkHash(h, 'sha1');
        if (result.found === true) return result;
      }
    }
    
    // Try MD5
    if (hashes.md5) {
      let h = hashes.md5;
      if (typeof h !== 'string' && typeof CryptoUtils !== 'undefined' && CryptoUtils.calculateMD5Hex) {
        try { h = await CryptoUtils.calculateMD5Hex(h); } catch (e) { console.warn('[Tempico] Failed to compute md5 from input', e); }
      }
      if (h) {
        const result = await this.checkHash(h, 'md5');
        if (result.found === true) return result;
      }
    }
    
    // None found
    return { 
      found: false, 
      source: 'tempico',
      message: 'Hash not found in database'
    };
  },
  
  // Set severity threshold
  setThreshold(threshold) {
    this.config.severityThreshold = Math.max(0, Math.min(10, threshold));
  },
  
  // Get current threshold
  getThreshold() {
    return this.config.severityThreshold;
  },
};
