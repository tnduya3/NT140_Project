// IP DB loader and lookup (loads CSV files packaged in the extension)
const IpDB = {
  ipMap: new Map(), // ip -> metadata object
  loaded: false,

  // Load index.json then load each CSV listed
  async loadAll() {
    try {
      // Prefer cached remote text if present
      try {
        const stored = await browser.storage.local.get(['ip_remote_text']);
        if (stored && stored.ip_remote_text) {
          this.parseCsv(stored.ip_remote_text);
          this.loaded = true;
          console.log('[IpDB] loaded from cached remote text', this.ipMap.size);
          return;
        }
      } catch (e) { /* ignore storage errors */ }

      // Fallback: load packaged files
      const idxUrl = browser.runtime.getURL('IP/index.json');
      const idxResp = await fetch(idxUrl);
      if (!idxResp.ok) {
        console.warn('[IpDB] index.json not found in extension package');
        this.loaded = true;
        return;
      }
      const files = await idxResp.json();
      if (!Array.isArray(files)) return;

      for (const fname of files) {
        try {
          const url = browser.runtime.getURL(`IP/${fname}`);
          const resp = await fetch(url);
          if (!resp.ok) continue;
          const text = await resp.text();
          this.parseCsv(text);
        } catch (e) {
          console.warn('[IpDB] failed to load', fname, e);
        }
      }

      this.loaded = true;
      console.log('[IpDB] loaded', this.ipMap.size, 'IPs');
    } catch (error) {
      console.error('[IpDB] loadAll error:', error);
      this.loaded = true;
    }
  },

  // Load from provided CSV text (used by DBUpdater)
  loadFromText(text) {
    try {
      this.ipMap.clear();
      this.parseCsv(text);
      this.loaded = true;
      console.log('[IpDB] loaded from provided text', this.ipMap.size);
    } catch (e) {
      console.warn('[IpDB] loadFromText failed', e);
    }
  },

  // Parse a CSV text; expects header with IP in first column or column named "IP"
  parseCsv(text) {
    const lines = text.split(/\r?\n/).filter(Boolean);
    if (lines.length === 0) return;
    // Determine header columns
    let headers = [];
    const first = lines[0];
    if (first.toLowerCase().includes('ip') && first.includes(',')) {
      headers = first.split(',').map(h => h.trim());
      lines.shift();
    }

    for (const line of lines) {
      const cols = line.split(',').map(c => c.trim());
      if (cols.length === 0) continue;
      const ip = cols[0];
      if (!ip) continue;
      if (!this.isValidIpString(ip)) continue;
      const meta = {};
      if (headers.length) {
        headers.forEach((h, i) => { meta[h] = cols[i] || ''; });
      } else {
        // best effort: try to fill known fields
        meta.ip = ip;
        meta.source = cols[1] || '';
      }
      this.ipMap.set(ip, meta);
    }
  },

  isValidIpString(s) {
    if (!s || typeof s !== 'string') return false;
    const v4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
    const v6 = /:/;
    return v4.test(s) || v6.test(s);
  },

  // Check if an IP string is blacklisted (exact match only)
  async isIpBlacklisted(ip) {
    console.debug('[IpDB] isIpBlacklisted called for', ip, 'loaded=', this.loaded, 'mapSize=', this.ipMap.size);
    // Ensure loaded (but don't block long)
    if (!this.loaded) {
      // fire-and-forget load (but await once if not started)
      if (typeof this._loading === 'undefined') {
        console.debug('[IpDB] starting background load');
        this._loading = this.loadAll();
      }
      try { await this._loading; } catch (e) { console.warn('[IpDB] background load failed during check', e); }
    }

    const found = this.ipMap.has(ip);
    if (found) {
      console.info('[IpDB] IP matched blacklist:', ip, 'meta=', this.ipMap.get(ip));
      return { found: true, ip, meta: this.ipMap.get(ip) };
    }

    console.debug('[IpDB] IP not found in blacklist:', ip);
    return { found: false };
  },

  getAll() {
    return Array.from(this.ipMap.keys());
  }
};

// Kick off load in background
try { IpDB.loadAll().catch(e => console.warn('[IpDB] background load failed', e)); } catch (e) {}
