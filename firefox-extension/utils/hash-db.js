// Hash database - Simple SHA256 only
const HashDB = {
  customHashes: [],
  useTempico: true,
  
  addCustomHashes(hashes) {
    this.customHashes = hashes || [];
  },
  
  async setPreferences(preferences) {
    this.useTempico = preferences.useTempico !== false;
    await browser.storage.local.set({ 
      dbPreferences: { useTempico: this.useTempico }
    });
  },
  
  async loadPreferences() {
    const result = await browser.storage.local.get(['dbPreferences']);
    const prefs = result.dbPreferences || {};
    this.useTempico = prefs.useTempico !== false;
  },
  
  // Check SHA256 hash only
  async checkHash(sha256) {
    // Check custom hashes first
    for (const custom of this.customHashes) {
      if (custom.hash === sha256) {
        return { 
          found: true, 
          type: 'SHA256',
          source: 'custom',
          description: custom.description,
          severity: 10,
          riskLevel: 'high'
        };
      }
    }
    
    // Check Tempico
    if (this.useTempico && sha256) {
      try {
        const result = await TempicoAPI.checkHash(sha256);
        if (result.found === true) {
          return result;
        }
        
        if (result.error) {
          console.warn('[HashDB] Tempico error:', result.error);
        }
      } catch (error) {
        console.error('[HashDB] Tempico exception:', error);
      }
    }
    
    return { 
      found: false, 
      source: 'none',
      message: 'Hash not found'
    };
  }
};
