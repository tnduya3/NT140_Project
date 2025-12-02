// DB Updater - fetch metadata, download remote DB files, verify checksum and cache locally
const DBUpdater = {
  // Base URL - change to your cloud location when ready
  config: {
    baseUrl: '', // e.g. 'https://cdn.example.com/db'
    endpoints: {
      sha256: 'sha256/metadata.json',
      ip: 'ip/metadata.json'
    },
    // optional: how many minutes between automatic checks
    autoCheckMinutes: 60
  },

  // Helper to compute SHA256 hex of ArrayBuffer
  async sha256Hex(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Fetch JSON metadata for a type
  async fetchMetadata(type) {
    if (!this.config.baseUrl) throw new Error('DBUpdater.baseUrl not configured');
    const ep = this.config.endpoints[type];
    if (!ep) throw new Error('Unknown DB type: ' + type);
    const url = `${this.config.baseUrl.replace(/\/$/, '')}/${ep}`;
    const resp = await fetch(url, { cache: 'no-cache' });
    if (!resp.ok) throw new Error(`Metadata fetch failed: ${resp.status}`);
    return resp.json();
  },

  // Download file as ArrayBuffer and verify expected sha256 hex
  async downloadAndVerify(url, expectedSha256) {
    const resp = await fetch(url, { cache: 'no-cache' });
    if (!resp.ok) throw new Error(`Download failed: ${resp.status}`);
    const buf = await resp.arrayBuffer();
    const hex = await this.sha256Hex(buf);
    if (expectedSha256 && hex !== expectedSha256.toLowerCase()) {
      throw new Error(`Checksum mismatch: expected ${expectedSha256}, got ${hex}`);
    }
    // return text decoded (assume utf-8)
    const decoder = new TextDecoder('utf-8');
    return { text: decoder.decode(buf), sha256: hex };
  },

  // Download JSON index that lists per-shard files (expected format: { shards: [{ prefix, url, sha256 }, ...], version })
  async downloadShardIndex(url) {
    const resp = await fetch(url, { cache: 'no-cache' });
    if (!resp.ok) throw new Error(`Shard index fetch failed: ${resp.status}`);
    return resp.json();
  },

  // Given a shard index object, download each shard if needed and save into storage.local
  async downloadAndCacheShards(shardIndex) {
    if (!shardIndex || !Array.isArray(shardIndex.shards)) return { updated: false };
    const prefixes = [];
    for (const entry of shardIndex.shards) {
      const prefix = (entry.prefix || '').toLowerCase();
      if (!prefix || !entry.url) continue;
      prefixes.push(prefix);
      const metaKey = `sha256_shard_meta_${prefix}`;
      const dataKey = `sha256_shard_${prefix}`;

      const stored = await browser.storage.local.get([metaKey]);
      const oldMeta = stored[metaKey] || {};
      // If sha256 matches and version/stamp matches, skip
      if (entry.sha256 && oldMeta.sha256 && entry.sha256.toLowerCase() === oldMeta.sha256) {
        continue;
      }

      try {
        const downloaded = await this.downloadAndVerify(entry.url, entry.sha256);
        // Save shard text and its metadata
        const toSet = {};
        toSet[dataKey] = downloaded.text;
        toSet[metaKey] = { sha256: downloaded.sha256, url: entry.url, updatedAt: Date.now() };
        await browser.storage.local.set(toSet);
      } catch (e) {
        console.warn('[DBUpdater] shard download/verify failed for', prefix, e);
      }
    }

    // Save shards index of available prefixes
    await browser.storage.local.set({ sha256_shards_index: prefixes });

    // Clear in-memory shard cache if HashDB is present so next lookup picks up cached shards
    try { if (typeof HashDB !== 'undefined' && HashDB && HashDB.shardCache) HashDB.shardCache = {}; } catch (e) {}

    return { updated: true, count: prefixes.length };
  },

  // Check and update both DB types
  async checkAndUpdateAll() {
    const results = {};
    try {
      // SHA256
      try {
        const meta = await this.fetchMetadata('sha256');
        // meta expected: { version, url, sha256 }
        const stored = await browser.storage.local.get(['sha256_remote_metadata']);
        const old = stored.sha256_remote_metadata || {};
        // Two modes supported:
        // 1) meta.shardIndexUrl present -> fetch shard index and download per-shard files
        // 2) fallback -> download full sha256 text as before
        if (meta.shardIndexUrl) {
          const shardIndex = await this.downloadShardIndex(meta.shardIndexUrl);
          const shardResult = await this.downloadAndCacheShards(shardIndex);
          // save metadata including shardIndexUrl and meta
          await browser.storage.local.set({ sha256_remote_metadata: meta, sha256_shardindex_metadata: { version: shardIndex.version || meta.version, fetchedAt: Date.now() } });
          results.sha256 = { updated: true, mode: 'shards', details: shardResult };
        } else if (meta.version !== old.version || meta.sha256 !== old.sha256) {
          const downloaded = await this.downloadAndVerify(meta.url, meta.sha256);
          await browser.storage.local.set({ sha256_remote_text: downloaded.text, sha256_remote_metadata: meta });
          results.sha256 = { updated: true, version: meta.version };
          // notify HashDB to reload cached remote if available
          if (typeof HashDB !== 'undefined' && HashDB && HashDB.loadCachedRemote) {
            try { await HashDB.loadCachedRemote(); } catch (e) { console.warn('[DBUpdater] HashDB reload failed', e); }
          }
        } else {
          results.sha256 = { updated: false, version: meta.version };
        }
      } catch (e) {
        results.sha256 = { error: e.message };
      }

      // IP
      try {
        const meta = await this.fetchMetadata('ip');
        const stored = await browser.storage.local.get(['ip_remote_metadata']);
        const old = stored.ip_remote_metadata || {};
        if (meta.version !== old.version || meta.sha256 !== old.sha256) {
          const downloaded = await this.downloadAndVerify(meta.url, meta.sha256);
          await browser.storage.local.set({ ip_remote_text: downloaded.text, ip_remote_metadata: meta });
          results.ip = { updated: true, version: meta.version };
          if (typeof IpDB !== 'undefined' && IpDB && IpDB.loadFromText) {
            try { IpDB.loadFromText(downloaded.text); } catch (e) { console.warn('[DBUpdater] IpDB reload failed', e); }
          }
        } else {
          results.ip = { updated: false, version: meta.version };
        }
      } catch (e) {
        results.ip = { error: e.message };
      }

      return results;
    } catch (e) {
      console.error('[DBUpdater] checkAndUpdateAll error', e);
      throw e;
    }
  },

  // Simple scheduler using browser.alarms (optional)
  schedulePeriodic(minutes) {
    try {
      if (typeof browser.alarms === 'undefined') return;
      browser.alarms.create('db-updater-check', { periodInMinutes: minutes || this.config.autoCheckMinutes });
      browser.alarms.onAlarm.addListener(async (alarm) => {
        if (alarm && alarm.name === 'db-updater-check') {
          try { await this.checkAndUpdateAll(); } catch (e) { console.warn('[DBUpdater] periodic check failed', e); }
        }
      });
    } catch (e) {
      console.warn('[DBUpdater] schedulePeriodic not available', e);
    }
  }
};

// Export to global for other modules
try { window.DBUpdater = DBUpdater; } catch (e) { /* background scripts may not have window */ }
