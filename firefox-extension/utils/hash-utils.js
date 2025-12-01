// Simple hash utility - Only SHA256 for Tempico API
const HashUtils = {
  
  // Calculate SHA256 hash of content
  async calculateSHA256(content) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Validate
      if (hexHash.length !== 64) {
        console.error(`[HashUtils] Invalid SHA256 length: ${hexHash.length}`);
        return null;
      }
      
      // Validate format
      if (!/^[a-f0-9]{64}$/.test(hexHash)) {
        console.error(`[HashUtils] Invalid SHA256 format: ${hexHash}`);
        return null;
      }
      
      return hexHash;
    } catch (error) {
      console.error('[HashUtils] SHA256 calculation error:', error);
      return null;
    }
  },
};
