# EVT2 demo — Cảnh 1: Server/trung gian nghe lén

Cho khách thấy: một server LiveKit bị chiếm (hoặc một quản trị viên) vào phòng **ẩn** và xem được cuộc gọi khi
**không** có thiết bị, nhưng chỉ thấy nhiễu khi bật **QRNG-SDCARD** (hoặc mã hóa phần mềm).

`server-view.html` vào phòng bằng token **spy** (ẩn, chỉ nghe — hai máy đang gọi không hề thấy nó) và hiển thị mọi
luồng nhận được.

## Chuẩn bị (một lần, trên máy có API key/secret)

Tạo token spy, hạn 1 năm, cho phòng `evt2-test`:

```
set LIVEKIT_API_KEY=API...
set LIVEKIT_API_SECRET=...
py -3 tools/make_token.py --room evt2-test --hours 8760 --role spy server-xem
```

Lệnh in ra một token. Giữ lại để dán vào trang web.

## Chạy khi demo

1. Mở `demo/server-view.html` bằng trình duyệt (Chrome/Edge). Mở trực tiếp file là chạy được; nếu trình duyệt chặn,
   phục vụ qua localhost: `py -3 -m http.server 8000` trong thư mục repo rồi mở
   `http://localhost:8000/demo/server-view.html`.
2. Dán **URL** (`wss://...livekit.cloud`) và **token spy**, phòng để `evt2-test`, bấm **Vào phòng nghe lén**.
   - Mẹo chiếu nhanh: mở sẵn bằng
     `server-view.html#url=wss://...&token=<spy>&room=evt2-test` để khỏi dán tay.
3. Hai điện thoại gọi nhau trong cùng phòng `evt2-test`.

## Kịch bản trên sân khấu

1. **Tắt E2EE** trên hai máy → trang "server" **thấy rõ mặt, nghe rõ tiếng** (bấm "Bật tiếng").
2. Chuyển sang **Mã hóa qua App** → server chỉ thấy hình vỡ/đứng, tiếng nhiễu.
3. Chuyển sang **Mã hóa qua QRNG-SDCARD** → vẫn chỉ nhiễu, và trong điện thoại **không có khóa** để lấy (nối sang
   Cảnh 2).

## Lưu ý

- Media đã mã hóa vẫn là H.264/Opus hợp lệ ở phần header (board giữ start code + NAL header rõ), nên trình duyệt
  vẫn *cố* giải mã → ra hình vỡ/đứng, không phải "tuyết trắng". Đó vẫn là "không đọc được nội dung".
- Nhãn "server đọc mã hóa: NONE/GCM" là **server tưởng** gì: mã hóa phần mềm đánh dấu GCM; board mã hóa payload
  mà server không biết, nên server vẫn ghi NONE **dù nội dung không đọc được** — một điểm nhấn hay.
- Điểm bán đúng của thiết bị là **chống chính server/trung gian**, không phải "chống sniff trên đường truyền"
  (WebRTC đã có DTLS-SRTP từng chặng). Thuyết minh theo đúng điểm này.
- Token spy cho ai cầm cũng vào xem được phòng tới khi hết hạn — chỉ dùng cho demo, đừng công khai.
