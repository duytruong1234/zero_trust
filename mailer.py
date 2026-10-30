"""
Gửi email thật qua máy chủ SMTP (Kịch bản 9 - CN_CapTaiKhoanMoi):
"Hệ thống đã gửi mật khẩu khởi tạo tạm thời đến email của giáo viên."

Cấu hình trong file .env:
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USER=tai_khoan_gui@gmail.com
    SMTP_PASSWORD=mat_khau_ung_dung
    SMTP_FROM=THPT Hoang Van Thu <tai_khoan_gui@gmail.com>
    SMTP_SSL=false          (true nếu dùng cổng 465)

Không giả lập: nếu chưa cấu hình SMTP hoặc gửi lỗi, hàm trả về (False, lý do) để giao diện báo đúng sự thật.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Tuple

from dotenv import load_dotenv

load_dotenv()


def smtp_da_cau_hinh() -> bool:
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER") and os.getenv("SMTP_PASSWORD"))


def gui_email(den: str, tieu_de: str, noi_dung: str) -> Tuple[bool, str]:
    """Gửi email văn bản thuần qua SMTP. Trả về (thành công?, thông điệp)."""
    if not smtp_da_cau_hinh():
        return False, "Máy chủ chưa cấu hình SMTP (SMTP_HOST / SMTP_USER / SMTP_PASSWORD trong .env)."

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    nguoi_gui = os.getenv("SMTP_FROM", user)
    dung_ssl = os.getenv("SMTP_SSL", "false").strip().lower() in ("1", "true", "yes")

    msg = EmailMessage()
    msg["Subject"] = tieu_de
    msg["From"] = nguoi_gui
    msg["To"] = den
    msg.set_content(noi_dung)

    try:
        ctx = ssl.create_default_context()
        if dung_ssl:
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.starttls(context=ctx)
                s.login(user, password)
                s.send_message(msg)
        return True, f"Đã gửi email tới {den}."
    except Exception as exc:  # noqa: BLE001 - trả lý do lỗi thật về cho giao diện
        return False, f"Gửi email tới {den} thất bại: {exc}"


def gui_mat_khau_khoi_tao(email: str, ho_ten: str, ten_dang_nhap: str, mat_khau_tam: str) -> Tuple[bool, str]:
    """Soạn và gửi thư bàn giao mật khẩu khởi tạo tạm thời cho giáo viên mới."""
    noi_dung = (
        f"Kính gửi thầy/cô {ho_ten},\n\n"
        "Ban Quản trị Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ "
        "đã cấp tài khoản cho thầy/cô với thông tin sau:\n\n"
        f"  - Tên đăng nhập: {ten_dang_nhap}\n"
        f"  - Email nội bộ : {email}\n"
        f"  - Mật khẩu khởi tạo tạm thời: {mat_khau_tam}\n\n"
        "Ở lần đăng nhập đầu tiên, hệ thống sẽ yêu cầu thầy/cô quét mã QR bằng Google/Microsoft Authenticator "
        "và đổi mật khẩu cá nhân mới. Mã QR chỉ hiển thị DUY NHẤT 1 lần.\n\n"
        "Vui lòng không chia sẻ thư này cho bất kỳ ai.\n\n"
        "Trân trọng,\nQuản trị viên IT - THPT Hoàng Văn Thụ"
    )
    return gui_email(email, "[THPT Hoàng Văn Thụ] Thông tin tài khoản và mật khẩu khởi tạo", noi_dung)
