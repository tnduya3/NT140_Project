// Feature extractor removed. This extension now only computes SHA256 and performs IP lookups via IpDB.
// Keeping a minimal stub to avoid runtime "missing symbol" errors if any leftover code references it.
const FeatureExtractor = {
  async extractFeatures() {
    return { success: true, features: {} };
  }
};
