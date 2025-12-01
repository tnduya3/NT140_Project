# Hướng dẫn cài đặt

## Bước 1: Chuẩn bị

Extension đã có sẵn thư viện CryptoJS trong thư mục `lib/`.

## Bước 2: Load extension vào Firefox

### Cách 1: Load Temporary (Development)

1. Mở Firefox
2. Gõ `about:debugging` vào address bar
3. Click "This Firefox" ở sidebar bên trái
4. Click nút "Load Temporary Add-on..."
5. Navigate đến thư mục `firefox-extension`
6. Chọn file `manifest.json`
7. Extension sẽ được load và icon xuất hiện trên toolbar

**Lưu ý**: Extension temporary sẽ bị remove khi restart Firefox.

### Cách 2: Package và Install (Production)

1. Install web-ext tool:
```bash
npm install -g web-ext
```

2. Build extension:
```bash
cd firefox-extension
web-ext build
```

3. File `.xpi` sẽ được tạo trong `web-ext-artifacts/`

4. Mở Firefox và kéo thả file `.xpi` vào browser để cài đặt

## Bước 3: Cấu hình

### Thêm whitelist domains

1. Click icon extension trên toolbar
2. Click "Cài đặt"
3. Thêm các domain tin cậy:
   - `google.com`
   - `*.cloudflare.com`
   - `*.googleapis.com`
   - `*.gstatic.com`
   - `*.jsdelivr.net`
   - `*.cdnjs.com`

### Test extension

1. Truy cập một website bất kỳ
2. Extension sẽ redirect sang blocking page
3. Sau vài giây sẽ redirect về trang gốc
4. Click icon extension để xem scripts đã check

### Test với samples

1. Mở Firefox Console (`Ctrl+Shift+K`)
2. Load test samples:
```javascript
// Copy nội dung từ test-samples.js
```
3. Test feature extraction:
```javascript
// Trong background script console
const result = await FeatureExtractor.extractFeatures(cleanCode, 'test.js');
const score = Scorer.calculateScore(result.features);
console.log('Score:', score);
```

## Troubleshooting

### Extension không hoạt động

- Kiểm tra console: `about:debugging` → Extension → Inspect
- Xem background script logs
- Kiểm tra permissions trong manifest.json

### Database không load được

- Đảm bảo thư mục `Malware-Hash-Database` nằm cùng cấp với `firefox-extension`
- Kiểm tra `web_accessible_resources` trong manifest.json
- Xem network tab trong blocking page

### Performance chậm

- Thêm nhiều domains vào whitelist
- Database lookup có thể mất vài giây với files lớn
- Đang optimize trong phiên bản tiếp theo

## Permissions

Extension cần các permissions sau:

- `webRequest`: Intercept HTTP requests
- `webRequestBlocking`: Block/modify requests
- `<all_urls>`: Access tất cả websites
- `storage`: Lưu settings local
- `tabs`: Quản lý tabs
- `notifications`: Hiển thị thông báo

## Uninstall

1. Gõ `about:addons`
2. Tìm "JS Malware Hash Checker"
3. Click "..." → Remove
