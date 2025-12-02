// Scorer removed. Extension no longer performs multi-factor scoring.
// Keep a minimal stub to avoid runtime errors if referenced.
const Scorer = {
  calculateScore() {
    return { score: 0, riskLevel: 'low', action: 'allow', breakdown: {} };
  },
  exportForML() { return null; }
};
