"""
Dịch vụ gửi email thực tế qua Gmail SMTP cho Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ.

Hỗ trợ cấu hình trực tiếp trong tệp .env bằng GMAIL_USER + GMAIL_APP_PASSWORD (hoặc bộ biến SMTP_*):
    GMAIL_USER=tai_khoan_he_thong@gmail.com
    GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587

Không giả lập: nếu chưa cấu hình hoặc máy chủ Google SMTP từ chối xác thực, các hàm trả về (False, lý do thực tế)
để giao diện thông báo chính xác cho người dùng và Quản trị viên.
"""
import base64
import html
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from typing import Optional, Tuple

from dotenv import load_dotenv

ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(ENV_PATH)


def lay_cau_hinh_smtp() -> dict:
    """Đọc cấu hình Gmail / SMTP mới nhất từ biến môi trường và tệp .env."""
    load_dotenv(ENV_PATH, override=True)

    user = (os.getenv("GMAIL_USER") or os.getenv("SMTP_USER") or "").strip()
    raw_password = (os.getenv("GMAIL_APP_PASSWORD") or os.getenv("SMTP_PASSWORD") or "").strip()
    # Google hiển thị App Password dạng 4 cụm 4 ký tự có khoảng trắng; chuẩn hóa về chuỗi liền 16 ký tự
    password = "".join(raw_password.split())

    host = (os.getenv("SMTP_HOST") or "").strip()
    if not host and user:
        host = "smtp.gmail.com"

    try:
        port = int((os.getenv("SMTP_PORT") or "587").strip())
    except ValueError:
        port = 587

    dung_ssl = (os.getenv("SMTP_SSL") or "").strip().lower() in ("1", "true", "yes") or port == 465

    raw_from = (os.getenv("SMTP_FROM") or "").strip()
    if raw_from:
        disp_name, addr = parseaddr(raw_from)
        from_header = formataddr((disp_name or "THPT Hoàng Văn Thụ", addr or user))
    elif user:
        from_header = formataddr(("THPT Hoàng Văn Thụ", user))
    else:
        from_header = ""

    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "from_header": from_header,
        "ssl": dung_ssl,
        "configured": bool(host and user and password),
    }


def smtp_da_cau_hinh() -> bool:
    return bool(lay_cau_hinh_smtp()["configured"])


def cap_nhat_cau_hinh_gmail_env(gmail_user: str, gmail_app_password: str) -> dict:
    """Cập nhật GMAIL_USER, GMAIL_APP_PASSWORD và bộ biến SMTP_* trực tiếp vào tệp .env và nạp lại ngay."""
    user_clean = (gmail_user or "").strip()
    pw_raw = (gmail_app_password or "").strip()
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

    updates = {
        "GMAIL_USER": user_clean,
        "SMTP_HOST": "smtp.gmail.com",
        "SMTP_PORT": "587",
        "SMTP_USER": user_clean,
        "SMTP_FROM": f"THPT Hoàng Văn Thụ <{user_clean}>",
        "SMTP_SSL": "false",
    }
    if pw_raw:
        updates["GMAIL_APP_PASSWORD"] = pw_raw
        updates["SMTP_PASSWORD"] = pw_raw

    seen_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        k = stripped.split("=", 1)[0].strip()
        if k in updates:
            new_lines.append(f"{k}={updates[k]}")
            seen_keys.add(k)
        else:
            new_lines.append(line)

    for k, v in updates.items():
        if k not in seen_keys:
            new_lines.append(f"{k}={v}")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines) + "\n")

    for k, v in updates.items():
        os.environ[k] = v

    return lay_cau_hinh_smtp()


def _phan_tich_loi_smtp(user: str, code: int, raw_msg) -> str:
    if isinstance(raw_msg, bytes):
        msg_txt = raw_msg.decode("utf-8", errors="replace").strip()
    else:
        msg_txt = str(raw_msg or "").strip()

    lower_txt = msg_txt.lower()
    if code == 534 or "webloginrequired" in lower_txt or "5.7.9" in lower_txt or "5.7.14" in lower_txt:
        return (
            f"Google từ chối đăng nhập SMTP cho {user} (mã 534 5.7.9 WebLoginRequired). "
            "Cách xử lý: (1) Mở https://mail.google.com và đảm bảo góc trên bên phải đang chọn đúng tài khoản "
            f"{user}; (2) Mở https://myaccount.google.com/notifications bấm 'Có, chính là tôi' nếu có cảnh báo bảo mật; "
            "(3) Mở https://myaccount.google.com/apppasswords (kiểm tra kỹ đúng avatar của "
            f"{user}, tránh nhầm sang Gmail mặc định khác trên trình duyệt) để tạo Mật khẩu ứng dụng 16 ký tự mới rồi cập nhật lại."
        )
    if code == 535 or "badcredentials" in lower_txt or "5.7.8" in lower_txt:
        return (
            f"Xác thực Gmail thất bại (mã 535) đối với {user}: "
            "Vui lòng kiểm tra lại GMAIL_USER và Mật khẩu ứng dụng 16 ký tự (GMAIL_APP_PASSWORD)."
        )
    return f"Máy chủ SMTP từ chối (mã {code}): {msg_txt}"


def _dang_nhap_smtp(smtp_conn: smtplib.SMTP, user: str, password: str) -> Tuple[bool, str]:
    """
    Thực hiện AUTH PLAIN trực tiếp để giữ nguyên mã phản hồi gốc (534/535) từ Gmail,
    tránh lỗi smtplib.login() thử tiếp AUTH LOGIN trên socket đã đóng gây mất thông báo gốc.
    """
    token = base64.b64encode(f"\0{user}\0{password}".encode("utf-8")).decode("ascii")
    code, resp = smtp_conn.docmd("AUTH PLAIN", token)
    if code in (235, 503):
        return True, "Xác thực Gmail SMTP thành công."
    return False, _phan_tich_loi_smtp(user, code, resp)


def kiem_tra_ket_noi_smtp() -> Tuple[bool, str]:
    """Kiểm tra kết nối và đăng nhập thực tế tới máy chủ Gmail SMTP (không gửi thư)."""
    cfg = lay_cau_hinh_smtp()
    if not cfg["configured"]:
        return False, "Máy chủ chưa cấu hình GMAIL_USER và GMAIL_APP_PASSWORD trong tệp .env."

    ctx = ssl.create_default_context()
    smtp_timeout = 5 if os.getenv("RENDER") else 15
    try:
        if cfg["ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ctx, timeout=smtp_timeout) as s:
                s.ehlo()
                ok, detail = _dang_nhap_smtp(s, cfg["user"], cfg["password"])
                if ok:
                    return True, f"Kết nối và xác thực thành công với {cfg['user']} ({cfg['host']}:{cfg['port']})."
                return False, detail
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=smtp_timeout) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
                ok, detail = _dang_nhap_smtp(s, cfg["user"], cfg["password"])
                if ok:
                    return True, f"Kết nối và xác thực thành công với {cfg['user']} ({cfg['host']}:{cfg['port']})."
                return False, detail
    except smtplib.SMTPResponseException as exc:
        return False, _phan_tich_loi_smtp(cfg["user"], exc.smtp_code, exc.smtp_error)
    except Exception as exc:  # noqa: BLE001
        if os.getenv("RENDER"):
            return (
                False,
                f"Không thể kết nối tới {cfg['host']}:{cfg['port']} ({exc}). Lưu ý: Gói Render Free chặn cổng SMTP 587/465 đi ra ngoài; hệ thống vẫn tự động hiển thị mật khẩu bàn giao một lần ngay trên màn hình Quản trị viên.",
            )
        return False, f"Không thể kết nối tới {cfg['host']}:{cfg['port']}: {exc}"


def _khung_html_truong(tieu_de_chinh: str, mo_ta_phu: str, than_html: str, chan_trang_luu_y: str = "") -> str:
    """Dựng khung HTML chuẩn hành chính của Trường THPT Hoàng Văn Thụ (không sử dụng emoji)."""
    ghi_chu_cuoi = (
        f'<p style="margin:16px 0 0;font-size:13px;color:#b45309;background:#fffbeb;border:1px solid #fde68a;'
        f'padding:10px 14px;border-radius:8px;">{chan_trang_luu_y}</p>'
        if chan_trang_luu_y
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="vi">
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:24px 12px;background:#f1f5f9;font-family:'Segoe UI',Arial,sans-serif;color:#0f172a;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;">
    <div style="background:#0f2862;color:#ffffff;padding:20px 26px;">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#bfdbfe;">
        HỆ THỐNG QUẢN LÝ VÀ PHÂN PHỐI ĐỀ THI NỘI BỘ
      </div>
      <div style="font-size:19px;font-weight:800;margin-top:4px;letter-spacing:0.02em;">
        TRƯỜNG THPT HOÀNG VĂN THỤ
      </div>
    </div>
    <div style="padding:24px 26px;font-size:14px;line-height:1.65;color:#1e293b;">
      <h2 style="margin:0 0 6px;font-size:18px;color:#0f172a;">{html.escape(tieu_de_chinh)}</h2>
      <p style="margin:0 0 18px;font-size:13px;color:#64748b;">{html.escape(mo_ta_phu)}</p>
      {than_html}
      {ghi_chu_cuoi}
      <div style="margin-top:24px;padding-top:16px;border-top:1px solid #e2e8f0;font-size:13px;color:#475569;">
        Trân trọng,<br>
        <strong>Ban Quản trị Hệ thống CNTT - Trường THPT Hoàng Văn Thụ</strong>
      </div>
    </div>
  </div>
</body>
</html>"""


def gui_email(den: str, tieu_de: str, noi_dung: str, noi_dung_html: Optional[str] = None) -> Tuple[bool, str]:
    """Gửi email (Plain Text kèm bản HTML nếu có) qua Gmail SMTP. Trả về (thành công?, thông điệp)."""
    cfg = lay_cau_hinh_smtp()
    if not cfg["configured"]:
        return False, "Máy chủ chưa cấu hình GMAIL_USER / GMAIL_APP_PASSWORD trong tệp .env."

    den_clean = (den or "").strip()
    if not den_clean or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", den_clean):
        return False, f"Địa chỉ email người nhận không hợp lệ: {den_clean}"

    msg = EmailMessage()
    msg["Subject"] = tieu_de
    msg["From"] = cfg["from_header"]
    msg["To"] = den_clean
    msg["Reply-To"] = cfg["user"]
    msg.set_content(noi_dung)
    if noi_dung_html:
        msg.add_alternative(noi_dung_html, subtype="html")

    ctx = ssl.create_default_context()
    smtp_timeout = 5 if os.getenv("RENDER") else 15
    try:
        if cfg["ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ctx, timeout=smtp_timeout) as s:
                s.ehlo()
                ok, detail = _dang_nhap_smtp(s, cfg["user"], cfg["password"])
                if not ok:
                    return False, detail
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=smtp_timeout) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
                ok, detail = _dang_nhap_smtp(s, cfg["user"], cfg["password"])
                if not ok:
                    return False, detail
                s.send_message(msg)
        return True, f"Đã gửi email tới {den_clean} từ {cfg['user']}."
    except smtplib.SMTPResponseException as exc:
        return False, _phan_tich_loi_smtp(cfg["user"], exc.smtp_code, exc.smtp_error)
    except Exception as exc:  # noqa: BLE001
        return False, f"Gửi email tới {den_clean} thất bại: {exc}"


def gui_mat_khau_khoi_tao(email: str, ho_ten: str, ten_dang_nhap: str, mat_khau_tam: str) -> Tuple[bool, str]:
    """Soạn và gửi thư bàn giao tài khoản mới kèm mật khẩu khởi tạo tạm thời."""
    noi_dung = (
        f"Kính gửi thầy/cô {ho_ten},\n\n"
        "Ban Quản trị Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ "
        "đã cấp tài khoản làm việc cho thầy/cô với thông tin sau:\n\n"
        f"  - Tên đăng nhập: {ten_dang_nhap}\n"
        f"  - Địa chỉ Gmail: {email}\n"
        f"  - Mật khẩu khởi tạo tạm thời: {mat_khau_tam}\n\n"
        "Ở lần đăng nhập đầu tiên, hệ thống bắt buộc thực hiện 4 bước kích hoạt bên ngoài hệ thống: "
        "quét mã QR ứng dụng Authenticator (chỉ hiển thị duy nhất 1 lần), xác nhận mã OTP 6 số, "
        "đổi mật khẩu cá nhân mới và thiết lập Mã PIN bảo mật 6 chữ số.\n\n"
        "Vui lòng bảo mật tuyệt đối thông tin trong thư này.\n\n"
        "Trân trọng,\nBan Quản trị Hệ thống CNTT - THPT Hoàng Văn Thụ"
    )
    than_html = f"""
      <p>Kính gửi thầy/cô <strong>{html.escape(ho_ten)}</strong>,</p>
      <p>Ban Quản trị đã khởi tạo tài khoản truy cập Hệ thống Quản lý và Phân phối Đề thi cho thầy/cô với thông tin đăng nhập sau:</p>
      <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:10px;padding:14px 18px;margin:14px 0;">
        <div style="margin-bottom:6px;">Tên đăng nhập: <strong style="color:#0f172a;">{html.escape(ten_dang_nhap)}</strong></div>
        <div style="margin-bottom:10px;">Email tài khoản: <strong style="color:#0f172a;">{html.escape(email)}</strong></div>
        <div style="font-size:12px;color:#64748b;text-transform:uppercase;font-weight:700;">Mật khẩu khởi tạo tạm thời</div>
        <div style="margin-top:4px;font-family:Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:0.08em;color:#1d4ed8;">
          {html.escape(mat_khau_tam)}
        </div>
      </div>
      <p>Ở lần đăng nhập đầu tiên, hệ thống yêu cầu hoàn tất kích hoạt bảo mật gồm: quét mã QR Google/Microsoft Authenticator (mã QR chỉ hiển thị duy nhất 1 lần), đổi mật khẩu cá nhân và thiết lập Mã PIN 6 chữ số.</p>
    """
    html_doc = _khung_html_truong(
        "Thông tin cấp tài khoản và mật khẩu khởi tạo",
        "Tài khoản truy cập Cổng Quản lý và Phân phối Đề thi - THPT Hoàng Văn Thụ",
        than_html,
        "Lưu ý bảo mật: Không chuyển tiếp email này hoặc chia sẻ mật khẩu khởi tạo cho bất kỳ ai.",
    )
    return gui_email(email, "[THPT Hoàng Văn Thụ] Thông tin tài khoản và mật khẩu khởi tạo", noi_dung, html_doc)


def gui_thong_bao_dat_lai_2fa(email: str, ho_ten: str, ten_dang_nhap: str, mat_khau_moi: str) -> Tuple[bool, str]:
    """Gửi thông báo đặt lại xác thực 2 bước (2FA) kèm mật khẩu khởi tạo mới."""
    noi_dung = (
        f"Kính gửi thầy/cô {ho_ten},\n\n"
        "Quản trị viên Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ "
        "vừa thực hiện Đặt lại xác thực 2 bước (2FA) và cấp lại mật khẩu khởi tạo mới cho tài khoản của thầy/cô:\n\n"
        f"  - Tên đăng nhập: {ten_dang_nhap}\n"
        f"  - Địa chỉ Gmail: {email}\n"
        f"  - Mật khẩu khởi tạo mới: {mat_khau_moi}\n\n"
        "Toàn bộ khóa 2FA cũ và các phiên đăng nhập trước đó đã bị thu hồi. "
        "Khi đăng nhập lại bằng mật khẩu khởi tạo mới ở trên, thầy/cô sẽ quét mã QR Authenticator mới, "
        "đổi mật khẩu cá nhân và thiết lập lại Mã PIN bảo mật 6 chữ số.\n\n"
        "Trân trọng,\nBan Quản trị Hệ thống CNTT - THPT Hoàng Văn Thụ"
    )
    than_html = f"""
      <p>Kính gửi thầy/cô <strong>{html.escape(ho_ten)}</strong>,</p>
      <p>Quản trị viên vừa thực hiện <strong>Đặt lại xác thực 2 bước (2FA)</strong> và cấp lại mật khẩu khởi tạo mới cho tài khoản của thầy/cô:</p>
      <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:10px;padding:14px 18px;margin:14px 0;">
        <div style="margin-bottom:6px;">Tên đăng nhập: <strong>{html.escape(ten_dang_nhap)}</strong></div>
        <div style="margin-bottom:10px;">Email tài khoản: <strong>{html.escape(email)}</strong></div>
        <div style="font-size:12px;color:#64748b;text-transform:uppercase;font-weight:700;">Mật khẩu khởi tạo mới</div>
        <div style="margin-top:4px;font-family:Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:0.08em;color:#1d4ed8;">
          {html.escape(mat_khau_moi)}
        </div>
      </div>
      <p>Khóa bảo mật 2FA cũ cùng toàn bộ phiên làm việc trước đây đã được thu hồi. Ở lần đăng nhập tiếp theo, thầy/cô sẽ quét mã QR Authenticator mới, đổi mật khẩu cá nhân và đặt lại Mã PIN 6 chữ số.</p>
    """
    html_doc = _khung_html_truong(
        "Đặt lại xác thực 2 bước (2FA) và cấp mật khẩu mới",
        "Thông báo bảo mật tài khoản cán bộ / giáo viên",
        than_html,
        "Nếu thầy/cô không yêu cầu thao tác này, vui lòng liên hệ ngay Quản trị viên CNTT của nhà trường.",
    )
    return gui_email(email, "[THPT Hoàng Văn Thụ] Đặt lại 2FA và cấp mật khẩu khởi tạo mới", noi_dung, html_doc)


def gui_mat_khau_cap_lai(email: str, ho_ten: str, ten_dang_nhap: str, mat_khau_moi: str) -> Tuple[bool, str]:
    """Gửi mật khẩu tạm thời mới khi Quản trị viên mở khóa và cấp lại mật khẩu."""
    noi_dung = (
        f"Kính gửi thầy/cô {ho_ten},\n\n"
        "Tài khoản của thầy/cô trên Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ "
        "đã được Quản trị viên mở khóa và cấp lại mật khẩu tạm thời mới:\n\n"
        f"  - Tên đăng nhập: {ten_dang_nhap}\n"
        f"  - Địa chỉ Gmail: {email}\n"
        f"  - Mật khẩu tạm thời mới: {mat_khau_moi}\n\n"
        "Mật khẩu cũ đã hết hiệu lực và các phiên đăng nhập trước đó đã bị thu hồi.\n\n"
        "Trân trọng,\nBan Quản trị Hệ thống CNTT - THPT Hoàng Văn Thụ"
    )
    than_html = f"""
      <p>Kính gửi thầy/cô <strong>{html.escape(ho_ten)}</strong>,</p>
      <p>Quản trị viên đã mở khóa tài khoản và cấp lại mật khẩu tạm thời mới cho thầy/cô:</p>
      <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:10px;padding:14px 18px;margin:14px 0;">
        <div style="margin-bottom:6px;">Tên đăng nhập: <strong>{html.escape(ten_dang_nhap)}</strong></div>
        <div style="margin-bottom:10px;">Email tài khoản: <strong>{html.escape(email)}</strong></div>
        <div style="font-size:12px;color:#64748b;text-transform:uppercase;font-weight:700;">Mật khẩu tạm thời mới</div>
        <div style="margin-top:4px;font-family:Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:0.08em;color:#1d4ed8;">
          {html.escape(mat_khau_moi)}
        </div>
      </div>
      <p>Mật khẩu cũ đã bị vô hiệu hóa và các phiên đăng nhập đang mở đã được thu hồi để đảm bảo an toàn.</p>
    """
    html_doc = _khung_html_truong(
        "Cấp lại mật khẩu tạm thời",
        "Thông báo khôi phục quyền truy cập tài khoản",
        than_html,
        "Vui lòng không chia sẻ mật khẩu này cho bất kỳ ai.",
    )
    return gui_email(email, "[THPT Hoàng Văn Thụ] Cấp lại mật khẩu tạm thời cho tài khoản", noi_dung, html_doc)


def gui_ma_xac_nhan_quen_pin(email: str, ho_ten: str, ten_dang_nhap: str, ma_xac_nhan: str) -> Tuple[bool, str]:
    """Soạn và gửi mã xác nhận đặt lại mã PIN 6 số (hiệu lực 10 phút) về Gmail của giáo viên."""
    noi_dung = (
        f"Kính gửi thầy/cô {ho_ten},\n\n"
        "Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ "
        "vừa nhận được yêu cầu đặt lại Mã PIN bảo mật (6 chữ số) cho tài khoản:\n\n"
        f"  - Tên đăng nhập: {ten_dang_nhap}\n"
        f"  - Địa chỉ Gmail: {email}\n"
        f"  - Mã xác nhận đặt lại PIN: {ma_xac_nhan}\n\n"
        "Mã xác nhận có hiệu lực trong vòng 10 phút. Vui lòng nhập mã này trên hộp thoại xác nhận "
        "để thiết lập Mã PIN 6 chữ số mới.\n\n"
        "Nếu thầy/cô không thực hiện yêu cầu này, vui lòng bỏ qua email và kiểm tra lại an toàn tài khoản.\n\n"
        "Trân trọng,\nBan Quản trị Hệ thống CNTT - THPT Hoàng Văn Thụ"
    )
    than_html = f"""
      <p>Kính gửi thầy/cô <strong>{html.escape(ho_ten)}</strong>,</p>
      <p>Hệ thống vừa nhận được yêu cầu đặt lại <strong>Mã PIN bảo mật (6 chữ số)</strong> cho tài khoản <strong>{html.escape(ten_dang_nhap)}</strong>.</p>
      <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:16px 18px;margin:16px 0;text-align:center;">
        <div style="font-size:12px;color:#1e40af;text-transform:uppercase;font-weight:700;">Mã xác nhận đặt lại PIN (hiệu lực 10 phút)</div>
        <div style="margin-top:6px;font-family:Consolas,monospace;font-size:28px;font-weight:800;letter-spacing:0.3em;color:#0f2862;">
          {html.escape(ma_xac_nhan)}
        </div>
      </div>
      <p>Vui lòng nhập chính xác dãy 6 chữ số trên vào cửa sổ đặt lại mã PIN để tạo mã PIN bảo mật mới.</p>
    """
    html_doc = _khung_html_truong(
        "Mã xác nhận đặt lại Mã PIN bảo mật (6 số)",
        "Xác thực khôi phục Mã PIN qua Gmail tài khoản",
        than_html,
        "Mã xác nhận chỉ có giá trị trong 10 phút. Nếu thầy/cô không yêu cầu thao tác này, vui lòng bỏ qua email.",
    )
    return gui_email(email, "[THPT Hoàng Văn Thụ] Mã xác nhận đặt lại Mã PIN bảo mật (6 số)", noi_dung, html_doc)


def gui_canh_bao_bay_de_moi(
    ten_tep_bay: str,
    ho_ten_vi_pham: str,
    ma_can_bo: str,
    ten_dang_nhap: str,
    ip_may: str,
    ipv4: str,
    so_lan_kich_hoat: int,
    thoi_diem_vn: str,
) -> Tuple[bool, str]:
    """Gửi cảnh báo an ninh khẩn cấp về hộp thư Gmail quản trị khi tệp bẫy (DE_MOI) bị kích hoạt."""
    cfg = lay_cau_hinh_smtp()
    email_nhan_canh_bao = (os.getenv("SECURITY_ALERT_EMAIL") or cfg["user"] or "").strip()
    if not email_nhan_canh_bao:
        return False, "Chưa cấu hình hộp thư nhận cảnh báo an ninh."

    noi_dung = (
        "BÁO ĐỘNG AN NINH MỨC CAO - KÍCH HOẠT TỆP BẪY ĐỀ MỒI\n\n"
        f"  - Thời điểm phát hiện : {thoi_diem_vn}\n"
        f"  - Tệp bẫy bị truy cập : {ten_tep_bay} (lần kích hoạt thứ {so_lan_kich_hoat})\n"
        f"  - Tài khoản truy cập  : {ho_ten_vi_pham} ({ma_can_bo} - {ten_dang_nhap})\n"
        f"  - Địa chỉ IP thiết bị : {ip_may} (IPv4: {ipv4})\n"
        "  - Biện pháp tự động   : Đã khóa an ninh ngay lập tức tài khoản vi phạm và thu hồi toàn bộ phiên đăng nhập.\n"
    )
    than_html = f"""
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:14px 18px;margin-bottom:16px;color:#991b1b;">
        <strong>Phát hiện truy cập trái phép vào tệp bẫy giám sát (Honeytrap)!</strong><br>
        Hệ thống đã tự động khóa ngay lập tức tài khoản vi phạm và thu hồi toàn bộ phiên làm việc.
      </div>
      <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:10px;padding:14px 18px;">
        <div style="margin-bottom:6px;">Thời điểm phát hiện: <strong>{html.escape(thoi_diem_vn)}</strong></div>
        <div style="margin-bottom:6px;">Tệp bẫy bị kích hoạt: <strong>{html.escape(ten_tep_bay)}</strong> (lần thứ {so_lan_kich_hoat})</div>
        <div style="margin-bottom:6px;">Tài khoản vi phạm: <strong>{html.escape(ho_ten_vi_pham)}</strong> ({html.escape(ma_can_bo)} / {html.escape(ten_dang_nhap)})</div>
        <div>Địa chỉ mạng: <strong>IP {html.escape(ip_may)} - IPv4 {html.escape(ipv4)}</strong></div>
      </div>
    """
    html_doc = _khung_html_truong(
        "Báo động an ninh: Kích hoạt Tệp bẫy Đề mồi",
        "Hệ thống Giám sát Zero-Trust tự động khóa tài khoản xâm nhập",
        than_html,
        "Vui lòng đăng nhập Cổng Quản trị Nhật ký hoạt động để kiểm tra chi tiết chuỗi sự kiện.",
    )
    return gui_email(
        email_nhan_canh_bao,
        f"[BÁO ĐỘNG AN NINH - THPT Hoàng Văn Thụ] Kích hoạt tệp bẫy: {ho_ten_vi_pham} ({ma_can_bo})",
        noi_dung,
        html_doc,
    )


def gui_email_kiem_tra(email_nhan: str, nguoi_thuc_hien: str, thoi_diem_vn: str) -> Tuple[bool, str]:
    """Gửi email kiểm tra kết nối Gmail thực tế từ Bảng điều khiển Quản trị viên."""
    cfg = lay_cau_hinh_smtp()
    noi_dung = (
        "XÁC NHẬN KẾT NỐI DỊCH VỤ GMAIL THÀNH CÔNG\n\n"
        "Hệ thống Quản lý và Phân phối Đề thi - Trường THPT Hoàng Văn Thụ đã kết nối thành công "
        "tới máy chủ Gmail SMTP.\n\n"
        f"  - Hộp thư gửi hệ thống : {cfg['user']} ({cfg['host']}:{cfg['port']})\n"
        f"  - Hộp thư nhận kiểm tra: {email_nhan}\n"
        f"  - Quản trị viên kiểm tra: {nguoi_thuc_hien}\n"
        f"  - Thời điểm gửi        : {thoi_diem_vn}\n\n"
        "Các chức năng gửi mật khẩu khởi tạo, đặt lại 2FA, quên mã PIN 6 số và báo động bẫy đề mồi đã sẵn sàng hoạt động."
    )
    than_html = f"""
      <p>Hệ thống Quản lý và Phân phối Đề thi đã kết nối và gửi thư thành công qua máy chủ <strong>Gmail SMTP</strong>:</p>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 18px;margin:14px 0;color:#14532d;">
        <div style="margin-bottom:6px;">Hộp thư gửi hệ thống: <strong>{html.escape(cfg['user'])}</strong> ({html.escape(cfg['host'])}:{cfg['port']})</div>
        <div style="margin-bottom:6px;">Hộp thư nhận kiểm tra: <strong>{html.escape(email_nhan)}</strong></div>
        <div style="margin-bottom:6px;">Người thực hiện: <strong>{html.escape(nguoi_thuc_hien)}</strong></div>
        <div>Thời điểm gửi: <strong>{html.escape(thoi_diem_vn)}</strong></div>
      </div>
      <p>Toàn bộ luồng gửi mật khẩu khởi tạo, đặt lại 2FA, mã xác nhận quên PIN 6 số và cảnh báo bẫy đề mồi đã hoạt động bình thường.</p>
    """
    html_doc = _khung_html_truong(
        "Xác nhận kết nối dịch vụ Gmail thành công",
        "Thư kiểm tra cấu hình SMTP từ Bảng điều khiển Quản trị viên",
        than_html,
    )
    return gui_email(email_nhan, "[THPT Hoàng Văn Thụ] Xác nhận kết nối Gmail SMTP thành công", noi_dung, html_doc)
