

## 1. phần làm tiếp

- Hoàn thiện các hàm trong [client.cpp](src/client.cpp) để nạp khóa ký, tính `key_id`, lấy thời gian Unix, tạo nonce mới 8 byte và sinh chuỗi QR.
- In chuỗi QR ra terminal để test tích hợp trước. Nếu demo cần ảnh QR, em nối thêm phần vẽ QR bằng thư viện sẵn có.
- Build client thành chương trình riêng. `run.bat` build server từ `src/main.cpp`, còn `src/client.cpp` có `main()` riêng.

## 2. Định dạng client và server dùng chung

| Thứ tự | Trường | Số byte | Cách ghi |
| --- | --- | --- | --- |
| 1 | `version` | 1 | `0x01` |
| 2 | `key_id` | 8 | 8 byte đầu của SHA-256(public key), giữ nguyên thứ tự byte của digest |
| 3 | `timestamp` | 4 | Unix time tính bằng giây, `uint32_t` big-endian |
| 4 | `nonce` | 8 | Sinh mới mỗi lần tạo QR |

Em ký bằng **Ed25519** trên chuỗi byte `corp-qr-access-v1` nối với **đúng 21 byte** trong bảng. Prefix là chuỗi ASCII và bỏ ký tự kết thúc `\0`. Sau đó nối `payload (21 byte) + signature (64 byte)` và mã hóa **Base64url không padding**. Chuỗi cuối cùng dài **114 ký tự**. Em có thể dùng lại `qrgen::derive_key_id()` và `qrgen::build_signed_message()` trong [qrgen.hpp](header/qrgen.hpp) để hai bên dùng cùng quy ước.

## 3. Chạy server

Server cần trình biên dịch C++17 và thư viện phát triển libsodium. Mở terminal ở thư mục `assignment-M2`. Anh đã chạy trên Ubuntu WSL. Nếu em dùng Windows với MinGW, dùng `run.bat PUBLIC_KEY_HEX`.

```sh
mkdir -p build
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    src/main.cpp src/server.cpp src/Verifier.cpp src/qrgen.cpp \
    src/NonceCache.cpp src/PassbackCache.cpp -lsodium -o build/server
./build/server PUBLIC_KEY_HEX
```

Thay `PUBLIC_KEY_HEX` bằng **64 ký tự hex** của public key Ed25519 do client dùng. Khi server đang chờ nhập, em nhập mỗi lượt quét trên một dòng. Server trả mã quyết định trên terminal.

## 4. Test với QR do client sinh

Giữ server chạy trong **cùng một phiên**. Sinh QR ngay trước khi nhập. Server chấp nhận timestamp từ **30 giây trước đến 5 giây sau** thời điểm server nhận lượt quét.

| Lượt | Dòng nhập vào server | Kết quả mong đợi |
| --- | --- | --- |
| 1 | `IN <QR_A>` — QR mới từ client | `ALLOW` |
| 2 | `IN <QR_A>` — dán lại đúng chuỗi của lượt 1 ngay sau đó | `REPLAY` |
| 3 | `IN <QR_B>` — sinh QR mới bằng cùng cặp khóa | `PASSBACK` |
| 4 | `OUT <QR_C>` — sinh thêm QR mới bằng cùng cặp khóa | `ALLOW` |

Thay `<QR_A>`, `<QR_B>`, `<QR_C>` bằng chuỗi thật, bỏ dấu `<` và `>`. Nếu ra `UNKNOWN_KEY`, kiểm tra public key truyền vào và cách tính `key_id`. Nếu ra `BAD_SIGNATURE`, kiểm tra prefix và thứ tự 21 byte. Nếu ra `MALFORMED`, kiểm tra version và chuỗi Base64url 114 ký tự. Nếu ra `EXPIRED` hoặc `FUTURE`, sinh lại QR và đối chiếu giờ hai bên.

Em gửi lại anh **kết quả bốn lượt** và lệnh build client để anh chạy lại được. Bốn lượt trên kiểm tra đường đi từ **client sinh chuỗi QR → server xác minh → quyết định cổng mô phỏng**. Nếu demo dùng scanner thật, em chạy thêm một lượt với QR hiển thị để kiểm tra cả bước quét ảnh.

Server áp dụng nguyên lý Single Responsibility bằng cách tách xử lý định dạng QR, chống quét lại và quản lý trạng thái vào/ra thành các thành phần riêng. Verifier nhận các thành phần phụ thuộc qua constructor để thuận tiện cho kiểm thử. Ở phạm vi M2, các phụ thuộc vẫn dùng kiểu cụ thể, nên Dependency Inversion mới được áp dụng một phần.
Xem thêm [Security Flow](docs/Security%20Flow.md) và [hướng dẫn build/test server](docs/dependency.md).
