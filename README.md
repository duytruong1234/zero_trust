# HỆ THỐNG QUẢN LÝ VÀ PHÂN PHỐI ĐỀ THI - THPT HOÀNG VĂN THỤ
## Chức năng: Đăng nhập và Bảo mật Zero-Trust (2FA TOTP RFC 6238)

Dự án được xây dựng bằng **Python (FastAPI)** + **PostgreSQL 17** + **HTML/TailwindCSS/JS**, đáp ứng đầy đủ 100% các mục yêu cầu trong tài liệu đặc tả `CN_DangNhap.docx`.

---

## 1. Cấu trúc Thư mục
- `database/schema.sql`: Script khởi tạo 3 bảng PostgreSQL (`TaiKhoan`, `PhienDangNhap`, `NhatKyLog`) cùng hàm & Trigger nối chuỗi băm bất biến (`fn_tinh_bam_nhat_ky_log`, `fn_nhat_ky_log_noi_chuoi`).
- `security.py`: Module bảo mật xử lý:
  - Mã băm mật khẩu (`bcrypt`) & kiểm tra 4 tiêu chí độ mạnh mật khẩu.
  - Mã hóa & giải mã khóa bí mật TOTP (`bi_mat_otp_ma_hoa` kiểu `BYTEA`) bằng **AES-256-GCM + Master Key**.
  - Sinh và xác thực mã OTP 6 số chuẩn **RFC 6238 (`PyOTP`)** và sinh ảnh mã QR.
  - Băm `SHA-256` cho Session Token (`PhienDangNhap.ma_phien_bam`).
  - Tự động sinh Mã cán bộ (`GV`/`AD`/`HT` + 7 chữ số ngẫu nhiên) và Tên đăng nhập (`Tên_vai_trò.tên`).
- `db.py`: Kết nối PostgreSQL (`cn_dang_nhap`), tự động khởi tạo schema và nạp 10 tài khoản mẫu theo Mục 2 của đề.
- `app.py`: Máy chủ FastAPI cung cấp toàn bộ API Đăng nhập, Kích hoạt 2FA lần đầu, Xác thực OTP lần 2, Quản lý tài khoản (Tạo mới, Reset 2FA, Mở khóa), Nhật ký Log và Kiểm toán chuỗi băm Hash-Chain.
- `static/index.html`: Giao diện người dùng thiết kế chuẩn theo 4 hình mẫu trong đề kèm thanh công cụ giả lập IP/Mạng và `DEMO SIMULATOR TOTP`.

---

## 2. Hướng dẫn Chạy Hệ thống

### Bước 1: Cài đặt thư viện (nếu chưa có)
```powershell
pip install -r requirements.txt
```

### Bước 2: Khởi chạy Server
```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```
Truy cập trình duyệt tại địa chỉ: **http://127.0.0.1:8000**

---

## 3. Tài khoản Mẫu để Kiểm thử (Mật khẩu khởi tạo: `ThptHVT@2026`)

| STT | Mã cán bộ | Họ và tên | Tên đăng nhập | Email | Vai trò | Trạng thái 2FA mẫu |
|---|---|---|---|---|---|---|
| 1 | `GV1000458` | Nguyễn Văn Minh | `gv.minh` | `nguyenvanminh.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` (Lần đầu truy cập: Hiện mã QR + Khóa `JBSWY3DPEHPK3PXP` + Bắt buộc đổi mật khẩu) |
| 2 | `GV1324570` | Trần Thị Lan | `gv.lan` | `tranthilan.thpthoangvanthu@gmail.com` | Giáo viên | `TRUE` (Vào thẳng khi ở mạng trường `14.232.110.45`, hoặc hỏi 6 số OTP khi đổi sang IP/mạng lạ) |
| 3 | `GV1456278` | Lê Hoàng Nam | `gv.nam` | `lehoangnam.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 4 | `GV7869077` | Phạm Thị Hoa | `gv.hoa` | `phamthihoa.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 5 | `GV6790839` | Võ Quốc Huy | `gv.huy` | `voquochuy.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 6 | `GV1780839` | Nguyễn Thị Mai | `gv.mai` | `nguyenthimai.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 7 | `GV1428003` | Đặng Minh Tuấn | `gv.tuan` | `dangminhtuan.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 8 | `GV7802740` | Bùi Thị Ngọc | `gv.ngoc` | `buithingoc.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 9 | `GV1562839` | Hoàng Đức Anh | `gv.anh` | `hoangducanh.thpthoangvanthu@gmail.com` | Giáo viên | `FALSE` |
| 10 | `AD1568920` | Trần Văn Phúc | `admin.phuc` | `tranvanphuc.thpthoangvanthu@gmail.com` | Quản trị viên | `TRUE` (Quyền Admin quản lý tài khoản, Reset 2FA, Mở khóa, Kiểm toán Nhật ký Log) |
