// Hash database - Simple SHA256 only
const HashDB = {
  customHashes: [],
  useTempico: true,

  // local packaged hashes (Set for O(1) lookup)
  localHashes: new Set(),
  // Shard cache: prefix (eg 'ab') -> Set of hashes
  shardCache: {},
  // Ongoing shard load promises to coalesce concurrent requests
  shardPromises: {},

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

  // Load local SHA256 files bundled in the extension
  async loadLocalHashes() {
    try {
      const idxUrl = browser.runtime.getURL('SHA256/index.json');
      const idxResp = await fetch(idxUrl);
      const files = await idxResp.json();
      if (!Array.isArray(files)) return;

      for (const fname of files) {
        try {
          const url = browser.runtime.getURL(`SHA256/${fname}`);
          const resp = await fetch(url);
          if (!resp.ok) continue;
          const text = await resp.text();
          const lines = text.split(/\r?\n/);
          for (let l of lines) {
            if (!l) continue;
            l = l.trim().toLowerCase();
            if (/^[a-f0-9]{64}$/.test(l)) this.localHashes.add(l);
          }
        } catch (e) {
          console.warn('[HashDB] failed to load local SHA256 file', fname, e);
        }
      }

    } catch (error) {
      console.error('[HashDB] loadLocalHashes error:', error);
    }
  },

  // Load cached remote text from storage.local (if DBUpdater saved it)
  async loadCachedRemote() {
    try {
      const stored = await browser.storage.local.get(['sha256_remote_text']);
      const text = stored && stored.sha256_remote_text;
      if (!text) return;
      const lines = text.split(/\r?\n/);
      let count = 0;
      for (let l of lines) {
        if (!l) continue;
        l = l.trim().toLowerCase();
        if (/^[a-f0-9]{64}$/.test(l)) { this.localHashes.add(l); count++; }
      }
    } catch (e) {
      console.warn('[HashDB] loadCachedRemote failed', e);
    }
  },

  // Load a per-prefix shard on-demand. Prefix should be hex string (e.g. 'ab')
  async loadShard(prefix) {
    if (!prefix || typeof prefix !== 'string') return new Set();
    prefix = prefix.toLowerCase();

    // If a load is already in progress, return the same promise
    if (this.shardPromises[prefix]) return this.shardPromises[prefix];

    const loadPromise = (async () => {
      try {
        // Check storage.local for a cached shard saved by DBUpdater (keyed by sha256_shard_<prefix>)
        const key = `sha256_shard_${prefix}`;
        const stored = await browser.storage.local.get([key]);
        const text = stored && stored[key];
        const set = new Set();
        if (text) {
          const lines = text.split(/\r?\n/);
          for (let l of lines) {
            if (!l) continue;
            l = l.trim().toLowerCase();
            if (/^[a-f0-9]{64}$/.test(l)) set.add(l);
          }
          this.shardCache[prefix] = set;
          return set;
        }

        // Try to load packaged shard: SHA256/shards/<prefix>.txt
        try {
          const url = browser.runtime.getURL(`SHA256/shards/${prefix}.txt`);
          const resp = await fetch(url);
          if (resp && resp.ok) {
            const t = await resp.text();
            const lines = t.split(/\r?\n/);
            for (let l of lines) {
              if (!l) continue;
              l = l.trim().toLowerCase();
              if (/^[a-f0-9]{64}$/.test(l)) set.add(l);
            }
            this.shardCache[prefix] = set;
            return set;
          } else {
            console.debug('[HashDB] packaged shard not found for prefix', prefix);
          }
        } catch (e) {
          // ignore fetch errors; treat as empty shard
        }

        // No shard available -> cache empty set to avoid repeated requests
        this.shardCache[prefix] = set;
        return set;
      } finally {
        // cleanup promise entry
        delete this.shardPromises[prefix];
      }
    })();

    this.shardPromises[prefix] = loadPromise;
    return loadPromise;
  },

  // Check SHA256 hash only
  async checkHash(sha256) {
    // Normalize
    if (!sha256 || typeof sha256 !== 'string') return { found: false, source: 'none' };
    const clean = sha256.toLowerCase().trim();

    // 1) Check local packaged hashes first (legacy small files)
    if (this.localHashes.has(clean)) {
      return {
        found: true,
        type: 'SHA256',
        source: 'local',
        description: 'Matched local SHA256 DB',
        severity: 10,
        riskLevel: 'high'
      };
    }

    // 2) Try per-prefix shard lookup (on-demand load)
    try {
      const prefix = clean.slice(0, 2);
      const shard = await this.loadShard(prefix);
      if (shard && shard.has(clean)) {
        return {
          found: true,
          type: 'SHA256',
          source: `shard:${prefix}`,
          description: `Matched packaged shard ${prefix}`,
          severity: 10,
          riskLevel: 'high'
        };
      }
    } catch (e) {
      // If shard loading fails, continue to next checks
      console.warn('[HashDB] shard load failed', e);
    }

    // Check custom hashes next
    for (const custom of this.customHashes) {
      if (custom.hash === clean) {
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

    // No remote API calls (Tempico) — rely on local and cached remote DBs only
    return { 
      found: false, 
      source: 'none',
      message: 'Hash not found'
    };
  }
};
