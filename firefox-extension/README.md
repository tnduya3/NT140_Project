# JS Malware Hash Checker - Firefox Extension

Extension Firefox kiểm tra hash của JavaScript files để phát hiện malware trước khi thực thi.

## Tính năng

- ✅ **Chặn tạm thời**: Redirect sang trang chặn khi truy cập website mới
- 🔍 **Kiểm tra hash**: Tính MD5, SHA1, SHA256 của external JS files
- 🗄️ **Database lookup**: So sánh với database malware hashes
- ⚪ **Whitelist**: Bỏ qua kiểm tra cho các domain tin cậy
- 📝 **Custom hashes**: Thêm hash malware tự phát hiện
- 📊 **UI đơn giản**: Theo dõi các files đã kiểm tra

## Cài đặt

### 1. Chuẩn bị

Trước tiên cần download thư viện CryptoJS cho MD5:

```bash
cd firefox-extension
mkdir -p lib
curl -o lib/crypto-js.min.js https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js
```

### 2. Copy database hashes

Extension cần truy cập database hashes. Thêm vào `manifest.json`:

```json
"web_accessible_resources": [
  "ui/blocking.html",
  "../Malware-Hash-Database/MD5/*.txt",
  "../Malware-Hash-Database/SHA1/*.txt",
  "../Malware-Hash-Database/SHA256/*.txt"
]
```

### 3. Load extension vào Firefox

1. Mở Firefox và truy cập `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Chọn file `manifest.json` trong thư mục `firefox-extension`

## Cấu trúc thư mục

```
firefox-extension/
├── manifest.json          # Cấu hình extension
├── background.js          # Logic chính
├── lib/
│   └── crypto-js.min.js  # Thư viện MD5
├── utils/
│   ├── crypto-utils.js   # Tính hash
│   └── hash-db.js        # Query database
└── ui/
    ├── blocking.html     # Trang chặn
    ├── blocking.js
    ├── popup.html        # Popup icon
    ├── popup.js
    ├── options.html      # Trang cài đặt
    └── options.js
```

## Cách hoạt động

1. **User truy cập website** → Extension intercept request
2. **Kiểm tra whitelist** → Nếu có trong whitelist, cho phép ngay
3. **Redirect sang blocking page** → Hiển thị loading
4. **Tải và phân tích JS files**:
   - Tính hash SHA256
   - Lookup trong Tempico Labs database
   - Extract features (30+ indicators)
   - Static analysis với AST parsing
5. **Multi-factor risk assessment** (tổng 100 điểm):
   - Hash match từ Tempico: **+40 điểm** (không auto-block)
   - Static analysis suspicious: **+30 điểm**
   - Obfuscated code: **+20 điểm**
   - Unknown domain: **+10 điểm**
   - Suspicious patterns: **+20 điểm**
   - **Trusted sources (CDN)**: giảm 70% điểm
6. **Quyết định dựa trên tổng điểm**:
   - ✅ < 40 điểm: Clean → Cho phép
   - ⚠️ 40-69 điểm: Suspect → Cảnh báo, user quyết định
   - 🚫 ≥ 70 điểm: High risk → Block

## Sử dụng

### Thêm domain vào whitelist

1. Click icon extension trên toolbar
2. Click "Cài đặt"
3. Nhập domain (vd: `google.com` hoặc `*.cloudflare.com`)
4. Click "Thêm vào Whitelist"

### Thêm custom hash

1. Mở trang Cài đặt
2. Scroll xuống "Custom Hashes"
3. Nhập hash (MD5/SHA1/SHA256)
4. Nhập loại và mô tả
5. Click "Thêm Hash"

### Xem scripts đã kiểm tra

1. Click icon extension
2. Xem danh sách "Scripts gần đây"
3. Thống kê: Tổng đã kiểm tra / Phát hiện malware

## Lưu ý

- Extension chỉ check **external JavaScript files**, không check inline scripts
- Database lookup có thể chậm với files lớn (đang optimize)
- Whitelist hỗ trợ wildcard: `*.example.com`
- Custom hashes lưu local, không sync giữa devices
- **Parse fallback**: Nếu không parse được AST (ES modules, JSX, TypeScript), sẽ dùng regex analysis
- **Trusted CDN**: Tự động giảm điểm cho scripts từ CDN phổ biến

## Features

### ✅ Đã implement
- **Multi-factor risk assessment** - Đánh giá tổng hợp thay vì chỉ dựa vào hash
  - Hash match từ Tempico: +40 điểm (không auto-block)
  - Static analysis: +30 điểm
  - Obfuscation: +20 điểm
  - Unknown domain: +10 điểm
  - Trusted CDN auto-whitelist: giảm 70% điểm
  - **Chỉ block khi tổng ≥ 70 điểm**
- **Hash checking** với Tempico Labs API (SHA256)
  - Không cần API key
  - Không giới hạn requests
  - Phân loại chi tiết malware
  - Severity scoring (0-10)
- **Trusted sources whitelist**:
  - CDN: cdnjs, unpkg, jsdelivr, googleapis
  - Library paths: /lib/, /vendor/, /node_modules/
  - Tự động giảm false positive
- **Static analysis** với AST parsing (acorn)
- **Feature extraction** (30+ features)
- **Suspect detection** với user confirmation
- **ML data export** cho training
- **Whitelist domains** (wildcard support)
- **Custom hashes** blacklist
- **Anime.js UI** với cyberpunk theme

### 📋 TODO
- [ ] ML model integration (TensorFlow.js)
- [ ] Thêm icon cho extension
- [ ] Export/import scan logs
- [ ] Performance improvements
- [ ] Browser action badge với stats

## License

MIT
