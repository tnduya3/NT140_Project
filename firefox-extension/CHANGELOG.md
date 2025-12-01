# Changelog

## [1.0.0] - 2024-11-30

### Added
- ✅ Hash checking (MD5, SHA1, SHA256)
- ✅ Malware database lookup (on-demand)
- ✅ Blocking page với loading animation
- ✅ Whitelist domains (support wildcard)
- ✅ Custom hash submission
- ✅ Popup UI để xem scripts đã check
- ✅ Options page để cấu hình
- ✅ Export/import settings

### Features v1.0
- Static analysis với AST parsing (acorn)
- Feature extraction (10+ features):
  - Dangerous function calls
  - Obfuscation detection
  - URL analysis
  - String entropy
  - Suspicious patterns
  - Code complexity
  - Domain checking
- Rule-based scoring (0-100)
- Risk levels: Low / Medium (Suspect) / High
- Suspect detection với user confirmation
- ML training data export
- Timeout protection (10s)
- Performance optimization

### Technical
- Firefox WebExtension API
- Web Crypto API (SHA1, SHA256)
- CryptoJS (MD5)
- Acorn (AST parser)
- filterResponseData for script interception

### Known Issues
- Database lookup có thể chậm với files lớn
- False positives với legitimate obfuscated code
- Chưa có ML model integration

## Roadmap

### [1.1.0] - Future
- [ ] ML model integration (TensorFlow.js)
- [ ] Caching cho database lookup
- [ ] Background database updates
- [ ] Community threat intelligence
- [ ] Behavioral analysis

### [1.2.0] - Future
- [ ] Browser action badge với stats
- [ ] Detailed scan reports
- [ ] Automatic whitelist learning
- [ ] Performance improvements
- [ ] Multi-language support
