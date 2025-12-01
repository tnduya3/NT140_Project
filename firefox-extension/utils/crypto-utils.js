// Crypto utilities for hash calculation
const CryptoUtils = {
  // Internal helper: normalize input to ArrayBuffer
  async _toArrayBuffer(content) {
    // Accepts: string, ArrayBuffer, Uint8Array, Blob/File
    if (content == null) return null;

    // If already ArrayBuffer
    if (content instanceof ArrayBuffer) return content;

    // If Uint8Array
    if (ArrayBuffer.isView(content)) return content.buffer;

    // If Blob or File (browser)
    if (typeof Blob !== 'undefined' && content instanceof Blob) {
      return await content.arrayBuffer();
    }

    // If string -> encode with UTF-8
    if (typeof content === 'string') {
      return new TextEncoder().encode(content).buffer;
    }

    // Fallback: try to JSON stringify then encode
    try {
      return new TextEncoder().encode(String(content)).buffer;
    } catch (e) {
      console.error('[CryptoUtils] _toArrayBuffer failed:', e);
      return null;
    }
  },

  // Internal helper: convert ArrayBuffer to hex string (lowercase)
  _arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    // map + padStart ensures leading zeros are preserved
    return Array.prototype.map.call(bytes, x => x.toString(16).padStart(2, '0')).join('');
  },

  // Internal helper: convert ArrayBuffer to base64
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  },

  // Internal helper: convert Uint8Array to CryptoJS WordArray (robust)
  _uint8ToWordArray(u8) {
    const words = [];
    for (let i = 0; i < u8.length; i += 4) {
      words.push(
        ((u8[i]     & 0xff) << 24) |
        (((u8[i + 1] || 0) & 0xff) << 16) |
        (((u8[i + 2] || 0) & 0xff) << 8) |
        (((u8[i + 3] || 0) & 0xff))
      );
    }
    return CryptoJS.lib.WordArray.create(words, u8.length);
  },

  // Calculate MD5 hash using CryptoJS, accepting multiple input types
  async calculateMD5(content, options = {}) {
    try {
      // If CryptoJS available, prefer creating a WordArray from Uint8Array
      const buf = await this._toArrayBuffer(content);
      if (!buf) return null;

      const u8 = new Uint8Array(buf);

      if (typeof CryptoJS !== 'undefined' && CryptoJS.lib && CryptoJS.enc) {
        // create WordArray from typed array robustly
        const wordArray = this._uint8ToWordArray(u8);
        const hex = wordArray.toString(CryptoJS.enc.Hex);
        const hexLower = String(hex).toLowerCase();

        if (hexLower.length !== 32) {
          console.error(`[CryptoUtils] MD5 invalid length: ${hexLower.length}`);
          return null;
        }

        // Support output options: 'hex' (lower), 'hexUpper', 'base64'
        const fmt = options.format || 'hex';
        if (fmt === 'hexUpper') return hexLower.toUpperCase();
        if (fmt === 'base64') {
          // CryptoJS can output base64 via enc.Base64
          return wordArray.toString(CryptoJS.enc.Base64);
        }
        return hexLower;
      }

      // If CryptoJS not available, try a Web Crypto fallback (not standard for MD5)
      console.error('[CryptoUtils] CryptoJS not found: MD5 requires CryptoJS in this environment');
      return null;
    } catch (e) {
      console.error('MD5 calculation error:', e);
      return null;
    }
  },

  // Calculate SHA1 hash using Web Crypto API, accepting multiple input types
  async calculateSHA1(content, options = {}) {
    try {
      const buf = await this._toArrayBuffer(content);
      if (!buf) return null;
      const hashBuffer = await crypto.subtle.digest('SHA-1', buf);
      const format = (options && options.format) || 'hex';

      if (format === 'base64') return this._arrayBufferToBase64(hashBuffer);

      const hexHash = this._arrayBufferToHex(hashBuffer);
      if (hexHash.length !== 40) {
        console.error(`[CryptoUtils] SHA1 invalid length: ${hexHash.length}`);
        return null;
      }

      return format === 'hexUpper' ? hexHash.toUpperCase() : hexHash;
    } catch (e) {
      console.error('SHA1 calculation error:', e);
      return null;
    }
  },

  // Calculate SHA256 hash using Web Crypto API, accepting multiple input types
  async calculateSHA256(content, options = {}) {
    try {
      const buf = await this._toArrayBuffer(content);
      if (!buf) return null;
      const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
      const format = (options && options.format) || 'hex';

      if (format === 'base64') return this._arrayBufferToBase64(hashBuffer);

      const hexHash = this._arrayBufferToHex(hashBuffer);
      if (hexHash.length !== 64) {
        console.error(`[CryptoUtils] SHA256 invalid length: ${hexHash.length}`);
        return null;
      }

      return format === 'hexUpper' ? hexHash.toUpperCase() : hexHash;
    } catch (e) {
      console.error('SHA256 calculation error:', e);
      return null;
    }
  },

  // Calculate all hashes at once
  // calculateHashes accepts optional formats object: { md5, sha1, sha256 }
  // each can be 'hex' (default, lowercase), 'hexUpper', or 'base64'
  async calculateHashes(content, formats = {}) {
    const [md5, sha1, sha256] = await Promise.all([
      this.calculateMD5(content, { format: formats.md5 || 'hex' }),
      this.calculateSHA1(content, { format: formats.sha1 || 'hex' }),
      this.calculateSHA256(content, { format: formats.sha256 || 'hex' })
    ]);

    // Log for debugging
    console.log('[CryptoUtils] Calculated hashes:', {
      md5: md5 ? `${md5.substring(0, 8)}... (${md5.length})` : 'null',
      sha1: sha1 ? `${sha1.substring(0, 8)}... (${sha1.length})` : 'null',
      sha256: sha256 ? `${sha256.substring(0, 8)}... (${sha256.length})` : 'null'
    });

    return { md5, sha1, sha256 };
  }
};

// Convenience wrappers that always return lowercase hex (common API format)
CryptoUtils.calculateMD5Hex = async function(content) {
  return await this.calculateMD5(content, { format: 'hex' });
};

CryptoUtils.calculateSHA1Hex = async function(content) {
  return await this.calculateSHA1(content, { format: 'hex' });
};

CryptoUtils.calculateSHA256Hex = async function(content) {
  return await this.calculateSHA256(content, { format: 'hex' });
};

// Export for Node.js and attach to window in browser contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CryptoUtils;
}

if (typeof window !== 'undefined') {
  window.CryptoUtils = CryptoUtils;
}
