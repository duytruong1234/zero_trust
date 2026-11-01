import os
import re
import io
import sys
import socket
import platform
import base64
import hashlib
import secrets
import random
from typing import Tuple, Optional, Mapping
import bcrypt
import pyotp
import qrcode
from unidecode import unidecode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

# Master Key 32 bytes (256-bit) cho AES-256-GCM
_MASTER_KEY_HEX = os.getenv(
    "OTP_MASTER_KEY_HEX",
    "486f616e6756616e5468755f5a65726f54727573745f4d617374657232303236"
)
MASTER_KEY = bytes.fromhex(_MASTER_KEY_HEX)
SCHOOL_IPV4_PREFIX = os.getenv("SCHOOL_IPV4_PREFIX", "14.232.110.")


# =============================================================================
# 1. MÃ BĂM MẬT KHẨU (BCRYPT) & KIỂM TRA ĐỘ MẠNH MẬT KHẨU
# =============================================================================
def bam_mat_khau(mat_khau_tho: str) -> str:
    """Mã băm mật khẩu bằng thuật toán bcrypt trước khi lưu vào CSDL."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(mat_khau_tho.encode("utf-8"), salt).decode("utf-8")


def kiem_tra_mat_khau(mat_khau_tho: str, mat_khau_bam: str) -> bool:
    """So khớp mật khẩu người dùng nhập với mã băm trong CSDL."""
    try:
        return bcrypt.checkpw(mat_khau_tho.encode("utf-8"), mat_khau_bam.encode("utf-8"))
    except Exception:
        return False


def kiem_tra_do_manh_mat_khau(mat_khau: str) -> Tuple[bool, str]:
    """
    Kiểm tra 4 tiêu chí mật khẩu mới theo giao diện thiết lập an ninh bắt buộc:
    - Tối thiểu 8 ký tự
    - Có chữ HOA (A-Z)
    - Có chữ số (0-9)
    - Có ký tự đặc biệt (@, #...)
    """
    if len(mat_khau) < 8:
        return False, "Mật khẩu mới phải có tối thiểu 8 ký tự."
    if not re.search(r"[A-Z]", mat_khau):
        return False, "Mật khẩu mới phải chứa ít nhất 1 chữ cái IN HOA (A-Z)."
    if not re.search(r"[0-9]", mat_khau):
        return False, "Mật khẩu mới phải chứa ít nhất 1 chữ số (0-9)."
    if not re.search(r"[^A-Za-z0-9]", mat_khau):
        return False, "Mật khẩu mới phải chứa ít nhất 1 ký tự đặc biệt (@, #, $, %, !...)."
    return True, "Hợp lệ"


def kiem_tra_dinh_dang_ma_pin(ma_pin: str) -> Tuple[bool, str]:
    """Kiểm tra mã PIN xác minh bắt buộc gồm đúng 6 chữ số (0-9)."""
    pin = (ma_pin or "").strip()
    if not re.fullmatch(r"\d{6}", pin):
        return False, "Mã PIN bảo mật phải gồm đúng 6 chữ số (0-9)."
    return True, "Hợp lệ"


def bam_ma_pin(ma_pin_tho: str) -> str:
    """Mã băm mã PIN 6 chữ số bằng thuật toán bcrypt trước khi lưu vào CSDL."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(ma_pin_tho.strip().encode("utf-8"), salt).decode("utf-8")


def kiem_tra_ma_pin(ma_pin_tho: str, ma_pin_bam: Optional[str]) -> bool:
    """So khớp mã PIN 6 chữ số người dùng nhập với mã băm trong CSDL."""
    if not ma_pin_tho or not ma_pin_bam:
        return False
    try:
        return bcrypt.checkpw(ma_pin_tho.strip().encode("utf-8"), ma_pin_bam.encode("utf-8"))
    except Exception:
        return False


# =============================================================================
# 2. MÃ HÓA AES-256 + MASTER KEY CHO KHÓA BÍ MẬT TOTP (bi_mat_otp_ma_hoa BYTEA)
# =============================================================================
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def sinh_khoa_bi_mat_totp(do_dai: int = 16) -> str:
    """
    Sinh chuỗi khóa bí mật Base32 chuẩn RFC 6238 bằng bộ sinh ngẫu nhiên mật mã học (secrets).
    Theo Kịch bản 9 (CN_CapTaiKhoanMoi): chuỗi Base32 16 ký tự (ví dụ: MOBI4RYB3FMFWFEQ).
    """
    return "".join(secrets.choice(_BASE32_ALPHABET) for _ in range(do_dai))


def ma_hoa_bi_mat_otp(secret_base32: str) -> bytes:
    """
    Mã hóa khóa bí mật TOTP bằng AES-256-GCM với Master Key của máy chủ.
    Kết quả trả về kiểu bytes (lưu vào cột BYTEA bi_mat_otp_ma_hoa).
    Định dạng: nonce (12 bytes) + ciphertext + tag (16 bytes).
    """
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, secret_base32.encode("utf-8"), None)
    return nonce + ciphertext


def giai_ma_bi_mat_otp(encrypted_bytes: bytes) -> str:
    """Giải mã cột BYTEA bi_mat_otp_ma_hoa để lấy chuỗi Base32 phục vụ tính TOTP."""
    if isinstance(encrypted_bytes, memoryview):
        encrypted_bytes = bytes(encrypted_bytes)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    aesgcm = AESGCM(MASTER_KEY)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# =============================================================================
# 3. XÁC THỰC TOTP RFC 6238 & SINH MÃ QR
# =============================================================================
OTP_VALID_WINDOW = max(1, int(os.getenv("OTP_VALID_WINDOW", "6")))


def lay_totp_uri(
    secret_base32: str,
    email: str,
    ho_ten: str = "",
    ten_dang_nhap: str = "",
) -> str:
    """Tạo chuỗi URI otpauth://totp chuẩn để quét bằng Google/Microsoft Authenticator."""
    secret_clean = re.sub(r"\s+", "", str(secret_base32 or "")).upper()
    totp = pyotp.TOTP(secret_clean, digits=6, interval=30)
    issuer = "THPT Hoang Van Thu"
    email_clean = (email or "").strip()
    return totp.provisioning_uri(name=email_clean, issuer_name=issuer)


def tao_anh_qr_base64(otpauth_uri: str) -> str:
    """Sinh ảnh mã QR định dạng Data URL (data:image/png;base64,...) từ URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def xac_thuc_ma_otp(secret_base32: str, ma_otp: str) -> bool:
    """
    Kiểm tra mã OTP 6 số từ Google Authenticator (TOTP RFC 6238).
    Bù độ lệch đồng hồ thực tế giữa điện thoại cá nhân và máy chủ (mặc định valid_window=6,
    tương ứng biên độ +-3 phút), kết hợp giới hạn chống dò mã tối đa 3 lần sai liên tiếp.
    """
    secret_clean = re.sub(r"\s+", "", str(secret_base32 or "")).upper()
    ma_otp_clean = re.sub(r"\s+|-", "", str(ma_otp or ""))
    if not secret_clean or not re.match(r"^\d{6}$", ma_otp_clean):
        return False
    totp = pyotp.TOTP(secret_clean, digits=6, interval=30)
    return bool(totp.verify(ma_otp_clean, valid_window=OTP_VALID_WINDOW))


def lay_ma_otp_hien_tai(secret_base32: str) -> Tuple[str, int]:
    """Lấy mã OTP 6 số hiện tại và số giây còn lại trong chu kỳ 30s (phục vụ Demo Simulator TOTP)."""
    import time
    totp = pyotp.TOTP(secret_base32, digits=6, interval=30)
    remaining = 30 - (int(time.time()) % 30)
    return totp.now(), remaining


# =============================================================================
# 4. BẢO VỆ SESSION TOKEN (SHA-256) & KIỂM TRA MẠNG TRƯỜNG
# =============================================================================
def sinh_session_token() -> Tuple[str, str]:
    """
    Sinh chuỗi Session Token ngẫu nhiên gửi về Cookie trình duyệt,
    và mã băm SHA-256 (64 ký tự hex) để cất vào cột PhienDangNhap.ma_phien_bam.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = bam_session_token(raw_token)
    return raw_token, token_hash


def bam_session_token(raw_token: str) -> str:
    """Băm SHA-256 chuỗi token từ Cookie để đối chiếu với cột ma_phien_bam."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def la_mang_noi_bo_truong(ipv4: str) -> bool:
    """
    Kiểm tra địa chỉ IPv4 có thuộc dải mạng nội bộ trường THPT Hoàng Văn Thụ
    (14.232.110.x hoặc mạng LAN nội bộ nhà trường 192.168.x.x / 10.x.x.x / 172.16-31.x.x / 127.0.0.1) hay không.
    """
    if not ipv4:
        return False
    ip_str = str(ipv4).strip()
    if ip_str.startswith(SCHOOL_IPV4_PREFIX):
        return True
    if ip_str.startswith(("192.168.", "10.", "127.")):
        return True
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


# =============================================================================
# 5. QUY TẮC SINH MÃ CÁN BỘ & TÊN ĐĂNG NHẬP THEO YÊU CẦU MỤC 1 & MỤC 7
# =============================================================================
# Vai trò phân cấp chính theo tài liệu CN_CapTaiKhoanMoi
VAI_TRO_HOP_LE = {
    "GIAO_VIEN": "Giáo viên",
    "BAN_GIAM_HIEU": "Hiệu trưởng / Phó Hiệu trưởng",
    "QUAN_TRI": "Quản trị viên IT",
}


_TEN_VAI_TRO_CU = {
    "giao vien": "GIAO_VIEN",
    "hieu truong": "BAN_GIAM_HIEU",
    "pho hieu truong": "BAN_GIAM_HIEU",
    "ban giam hieu": "BAN_GIAM_HIEU",
    "quan tri vien": "QUAN_TRI",
    "quan tri vien it": "QUAN_TRI",
    "admin": "QUAN_TRI",
}


def chuan_hoa_vai_tro(vai_tro: str) -> Optional[str]:
    """
    Quy đổi vai trò về 1 trong 3 mã GIAO_VIEN / BAN_GIAM_HIEU / QUAN_TRI.
    Chỉ chấp nhận ĐÚNG mã hoặc ĐÚNG tên vai trò tiếng Việt; mọi giá trị khác trả về None (bị từ chối).
    """
    raw = str(vai_tro or "").strip()
    if raw.upper() in VAI_TRO_HOP_LE:
        return raw.upper()
    return _TEN_VAI_TRO_CU.get(" ".join(unidecode(raw).lower().split()))


def lay_tien_to_vai_tro(vai_tro: str) -> Tuple[str, str]:
    """
    Trả về (Tiền tố Mã cán bộ, Tiền tố Tên đăng nhập) theo vai trò:
    - GIAO_VIEN (Giáo viên) -> ('GV', 'gv')
    - QUAN_TRI (Quản trị viên IT) -> ('AD', 'admin')
    - BAN_GIAM_HIEU (Hiệu trưởng / Phó Hiệu trưởng) -> ('HT', 'ht')
    """
    ma = chuan_hoa_vai_tro(vai_tro)
    if ma == "QUAN_TRI":
        return "AD", "admin"
    if ma == "BAN_GIAM_HIEU":
        return "HT", "ht"
    return "GV", "gv"


def chuan_hoa_ho_ten(ho_ten: str) -> str:
    """
    Chuẩn hóa họ tên tiếng Việt có dấu: cắt khoảng trắng thừa (Trim, gộp khoảng trắng giữa)
    và viết hoa chữ cái đầu mỗi từ. Ví dụ: '  nguyễn   văn MINH ' -> 'Nguyễn Văn Minh'.
    """
    words = str(ho_ten or "").split()
    return " ".join(w[:1].upper() + w[1:].lower() for w in words)


_KY_TU_DAC_BIET = "@#$%&*!?-_+="


def sinh_mat_khau_tam(do_dai: int = 12) -> str:
    """
    Sinh ngẫu nhiên mật khẩu khởi tạo (tối thiểu 10 ký tự) bằng bộ sinh số ngẫu nhiên mật mã học,
    bảo đảm có đủ chữ HOA, chữ thường, chữ số và ký tự đặc biệt.
    """
    do_dai = max(10, do_dai)
    hoa = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    thuong = "abcdefghijkmnopqrstuvwxyz"
    so = "23456789"
    tat_ca = hoa + thuong + so + _KY_TU_DAC_BIET
    ky_tu = [
        secrets.choice(hoa),
        secrets.choice(thuong),
        secrets.choice(so),
        secrets.choice(_KY_TU_DAC_BIET),
    ]
    ky_tu += [secrets.choice(tat_ca) for _ in range(do_dai - len(ky_tu))]
    secrets.SystemRandom().shuffle(ky_tu)
    return "".join(ky_tu)


def kiem_tra_mat_khau_khoi_tao(mat_khau: str) -> Tuple[bool, str]:
    """Mật khẩu khởi tạo: tối thiểu 10 ký tự, gồm chữ hoa, chữ thường, chữ số và ký tự đặc biệt."""
    if len(mat_khau) < 10:
        return False, "Mật khẩu khởi tạo phải có tối thiểu 10 ký tự."
    if not re.search(r"[A-Z]", mat_khau):
        return False, "Mật khẩu khởi tạo phải có ít nhất 1 chữ cái IN HOA."
    if not re.search(r"[a-z]", mat_khau):
        return False, "Mật khẩu khởi tạo phải có ít nhất 1 chữ cái thường."
    if not re.search(r"[0-9]", mat_khau):
        return False, "Mật khẩu khởi tạo phải có ít nhất 1 chữ số."
    if not re.search(r"[^A-Za-z0-9]", mat_khau):
        return False, "Mật khẩu khởi tạo phải có ít nhất 1 ký tự đặc biệt."
    return True, "Hợp lệ"


def sinh_ma_can_bo_ngau_nhien(vai_tro: str) -> str:
    """
    Công thức ghi mã: 'Tên viết tắt vai trò + 7 số ngẫu nhiên'
    Ví dụ: GV1000458, AD1568920, HT2345671
    """
    prefix, _ = lay_tien_to_vai_tro(vai_tro)
    seven_digits = random.randint(1000000, 9999999)
    return f"{prefix}{seven_digits}"


def tao_ten_dang_nhap_tu_ho_ten(ho_ten: str, vai_tro: str) -> str:
    """
    Công thức bắt buộc tạo tên đăng nhập: 'Tên_vai_trò.tên'
    Ví dụ: 'Nguyễn Văn Minh' (Giáo viên) -> 'gv.minh'
           'Trần Văn Phúc' (Quản trị viên) -> 'admin.phuc'
    """
    _, role_prefix = lay_tien_to_vai_tro(vai_tro)
    clean_name = unidecode(str(ho_ten or "")).strip().lower()
    parts = [re.sub(r"[^a-z0-9]", "", p) for p in clean_name.split() if p]
    first_name = parts[-1] if parts else "user"
    return f"{role_prefix}.{first_name}"


EMAIL_TRUONG_SUFFIX = ".thpthoangvanthu@gmail.com"
EMAIL_TRUONG_REGEX = re.compile(
    r"^[a-z0-9]+(\.[a-z0-9]+)*\.(thpthoangvanthu|thtphoangvanthu)@gmail\.com$"
)


def tao_tien_to_email_tu_ho_ten(ho_ten: str) -> str:
    """
    Chuyển họ và tên thành tiền tố email viết thường không dấu nối liền.
    Ví dụ: 'Nguyễn Văn Minh' -> 'nguyenvanminh'
    """
    clean_name = unidecode(str(ho_ten or "")).strip().lower()
    parts = [re.sub(r"[^a-z0-9]", "", p) for p in clean_name.split() if p]
    joined = "".join(parts)
    return joined or "giaovien"


def tao_email_tu_ho_ten(ho_ten: str, so_thu_tu: int = 1) -> str:
    """
    Công thức tạo email giáo viên/cán bộ: '<têngiáoviên>.thpthoangvanthu@gmail.com'
    Ví dụ: 'Nguyễn Văn Minh' -> 'nguyenvanminh.thpthoangvanthu@gmail.com'
    """
    base = tao_tien_to_email_tu_ho_ten(ho_ten)
    suffix_num = "" if so_thu_tu <= 1 else str(so_thu_tu)
    return f"{base}{suffix_num}{EMAIL_TRUONG_SUFFIX}"


def kiem_tra_email_truong_hop_le(email: str) -> bool:
    """Kiểm tra email đúng định dạng <têngiáoviên>.thpthoangvanthu@gmail.com."""
    return bool(EMAIL_TRUONG_REGEX.fullmatch((email or "").strip().lower()))


def _lay_os_that_tren_may_chu() -> str:
    """Đọc trực tiếp phiên bản Hệ điều hành, bản dựng (Build) và tên máy chủ thực tế từ hệ thống."""
    hostname = socket.gethostname()
    try:
        if sys.platform == "win32":
            import winreg
            v = sys.getwindowsversion()
            win_ver = "Windows 11" if v.build >= 22000 else "Windows 10"
            disp_ver = ""
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                )
                disp_ver, _ = winreg.QueryValueEx(key, "DisplayVersion")
            except Exception:
                pass
            ver_detail = f"{disp_ver}, Build {v.build}" if disp_ver else f"Build {v.build}"
            return f"{win_ver} ({ver_detail}) [{hostname}]"
        return f"{platform.system()} {platform.release()} [{hostname}]"
    except Exception:
        return f"{platform.system()} {platform.release()} [{hostname}]"


def _phat_hien_brave_local(chromium_major: str) -> Optional[str]:
    """Kiểm tra phiên bản thực tế của Brave Browser cài trên máy nếu trình duyệt ẩn danh dưới nhân Chromium."""
    brave_app_dir = r"C:\Program Files\BraveSoftware\Brave-Browser\Application"
    if os.path.isdir(brave_app_dir):
        try:
            for entry in os.listdir(brave_app_dir):
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", entry):
                    if not chromium_major or entry.startswith(f"{chromium_major}."):
                        parts = entry.split(".", 1)
                        brave_ver = parts[1] if len(parts) > 1 else entry
                        return f"Brave Browser {brave_ver} (Chromium {parts[0]})"
        except Exception:
            pass
    return None


def _lam_sach_chuoi_header(val: Optional[str], max_len: int = 96) -> str:
    """Làm sạch giá trị header gửi từ trình duyệt, loại bỏ ký tự điều khiển và giới hạn độ dài."""
    if not val:
        return ""
    cleaned = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", str(val)).strip().strip('"').strip()
    return cleaned[:max_len]


def _trich_xuat_phien_ban_brand(sec_ch_src: str, brand_names: tuple[str, ...]) -> str:
    """Trích xuất số phiên bản trình duyệt từ header Client Hints."""
    if not sec_ch_src:
        return ""
    for brand in brand_names:
        pattern = rf'"{re.escape(brand)}"\s*;\s*v="([\d.]+)"'
        m = re.search(pattern, sec_ch_src, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _chon_phien_ban_chi_tiet(sec_ch_full: str, sec_ch_short: str, ua_ver: str, brand_names: tuple[str, ...]) -> str:
    """Ưu tiên phiên bản đầy đủ từ Sec-CH-UA-Full-Version-List, tiếp đến phiên bản đầy đủ trong User-Agent, cuối cùng là Sec-CH-UA."""
    full_ch = _trich_xuat_phien_ban_brand(sec_ch_full, brand_names)
    if full_ch and "." in full_ch:
        return full_ch
    if ua_ver and "." in ua_ver:
        return ua_ver
    short_ch = _trich_xuat_phien_ban_brand(sec_ch_short, brand_names)
    return full_ch or ua_ver or short_ch


def phan_tich_thiet_bi(
    user_agent: str,
    headers: Optional[Mapping[str, str]] = None,
    allow_local_host_probe: bool = False,
) -> str:
    """
    Xác định chính xác Hệ điều hành và Trình duyệt thực tế của máy khách (Client):
    - Ưu tiên thông tin Client Hints độ chính xác cao từ trình duyệt (X-Client-OS, Sec-CH-UA-Platform-Version)
      để phân biệt chính xác Windows 11 (platformVersion >= 13) và Windows 10 (< 13), macOS, Android, iOS, Linux.
    - Tuyệt đối không lấy hệ điều hành của container máy chủ đám mây (Render/Linux AWS) gán cho người truy cập từ xa.
    """
    ua = str(user_agent or "")
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    sec_ch_ua = hdrs.get("sec-ch-ua", "")
    sec_ch_full = hdrs.get("sec-ch-ua-full-version-list", "")
    platform_hint = _lam_sach_chuoi_header(hdrs.get("sec-ch-ua-platform", ""), 40)
    platform_ver_hint = _lam_sach_chuoi_header(hdrs.get("sec-ch-ua-platform-version", ""), 32)
    bitness_hint = _lam_sach_chuoi_header(hdrs.get("sec-ch-ua-bitness", ""), 16)
    arch_hint = _lam_sach_chuoi_header(hdrs.get("sec-ch-ua-arch", ""), 24)
    model_hint = _lam_sach_chuoi_header(hdrs.get("sec-ch-ua-model", ""), 48)
    client_os_hdr = _lam_sach_chuoi_header(hdrs.get("x-client-os", ""), 80)
    real_browser_hdr = _lam_sach_chuoi_header(hdrs.get("x-real-browser", ""), 80)

    if arch_hint.lower() == "arm" and bitness_hint == "64":
        win_arch_suffix = " (ARM64)"
    elif bitness_hint == "64" or any(tok in ua for tok in ("Win64", "x64", "WOW64", "amd64")):
        win_arch_suffix = " (64-bit)"
    elif bitness_hint == "32":
        win_arch_suffix = " (32-bit)"
    else:
        win_arch_suffix = ""

    # 1. Xác định Hệ điều hành thực tế của thiết bị truy cập
    os_name = ""
    if client_os_hdr and "-aws" not in client_os_hdr.lower() and "[srv-" not in client_os_hdr.lower():
        os_name = client_os_hdr

    if not os_name and platform_hint:
        plat_low = platform_hint.lower()
        if plat_low == "windows":
            major_ver = -1
            if platform_ver_hint:
                first_part = platform_ver_hint.split(".")[0].strip()
                if first_part.isdigit():
                    major_ver = int(first_part)
            if major_ver >= 13:
                os_name = f"Windows 11{win_arch_suffix}"
            elif 1 <= major_ver < 13:
                os_name = f"Windows 10{win_arch_suffix}"
            elif allow_local_host_probe and sys.platform == "win32":
                os_name = _lay_os_that_tren_may_chu()
            else:
                os_name = f"Windows 10/11{win_arch_suffix}"
        elif plat_low in ("macos", "mac os x", "mac"):
            if platform_ver_hint and platform_ver_hint != "0.0.0":
                os_name = f"macOS {platform_ver_hint}"
            else:
                os_name = "macOS"
        elif plat_low == "android":
            ver = platform_ver_hint if (platform_ver_hint and platform_ver_hint != "0.0.0") else ""
            if not ver:
                m_and = re.search(r"Android\s+([\d.]+)", ua)
                ver = m_and.group(1) if m_and else ""
            os_name = f"Android {ver}".strip() if ver else "Android"
            if model_hint:
                os_name = f"{os_name} ({model_hint})"
        elif plat_low in ("ios", "ipados"):
            ver = platform_ver_hint if (platform_ver_hint and platform_ver_hint != "0.0.0") else ""
            os_name = f"iOS {ver}".strip() if ver else "iOS (iPhone/iPad)"
        elif plat_low in ("chrome os", "chromium os"):
            os_name = "ChromeOS"
        elif plat_low == "linux" and "Android" not in ua and "Windows" not in ua:
            os_name = "Linux"

    if not os_name:
        if "Android" in ua:
            m_and = re.search(r"Android\s+([\d.]+)", ua)
            os_name = f"Android {m_and.group(1)}" if m_and else "Android"
            m_mod = re.search(r"Android\s+[\d.]+;\s*([^;)]+?)\s+Build/", ua)
            if m_mod:
                mod = _lam_sach_chuoi_header(m_mod.group(1), 36)
                if mod and mod.upper() != "K":
                    os_name = f"{os_name} ({mod})"
        elif "iPhone" in ua or "iPad" in ua:
            dev_lbl = "iPad" if "iPad" in ua else "iPhone"
            m_ios = re.search(r"OS\s+(\d+[_\d]*)", ua)
            if m_ios:
                ios_ver = m_ios.group(1).replace("_", ".")
                os_name = f"iOS {ios_ver} ({dev_lbl})"
            else:
                os_name = f"iOS ({dev_lbl})"
        elif "Windows NT 10.0" in ua:
            if allow_local_host_probe and sys.platform == "win32":
                os_name = _lay_os_that_tren_may_chu()
            else:
                os_name = f"Windows 10/11{win_arch_suffix}"
        elif "Windows NT 6.3" in ua:
            os_name = f"Windows 8.1{win_arch_suffix}"
        elif "Windows NT 6.2" in ua:
            os_name = f"Windows 8{win_arch_suffix}"
        elif "Windows NT 6.1" in ua:
            os_name = f"Windows 7{win_arch_suffix}"
        elif "Windows" in ua:
            os_name = f"Windows{win_arch_suffix}"
        elif ("Mac OS X" in ua or "Macintosh" in ua) and "Windows" not in ua:
            m_mac = re.search(r"Mac OS X\s+(\d+[_\d.]*)", ua)
            if m_mac:
                mac_ver = m_mac.group(1).replace("_", ".")
                os_name = "macOS" if mac_ver.startswith("10.15") else f"macOS {mac_ver}"
            else:
                os_name = "macOS"
        elif "CrOS" in ua:
            os_name = "ChromeOS"
        elif ("Linux" in ua or "X11" in ua) and "Android" not in ua and "Windows" not in ua:
            os_name = "Linux"
        elif allow_local_host_probe:
            os_name = _lay_os_that_tren_may_chu()
        else:
            os_name = "Thiết bị Web"

    # 2. Xác định Trình duyệt thực tế của máy khách
    if real_browser_hdr:
        browser = real_browser_hdr
        if allow_local_host_probe and "Brave" in browser:
            m_chr = re.search(r"Chrome/(\d+)", ua)
            brave_detail = _phat_hien_brave_local(m_chr.group(1) if m_chr else "")
            if brave_detail:
                browser = brave_detail
    elif "Brave" in sec_ch_full or "Brave" in sec_ch_ua or "Brave" in ua:
        m_chr = re.search(r"Chrome/([\d.]+)", ua)
        ch_ver = _chon_phien_ban_chi_tiet(sec_ch_full, sec_ch_ua, "", ("Brave",))
        if allow_local_host_probe:
            brave_local = _phat_hien_brave_local(m_chr.group(1).split(".")[0] if m_chr else "")
        else:
            brave_local = None
        if brave_local:
            browser = brave_local
        elif ch_ver and "." in ch_ver:
            browser = f"Brave Browser {ch_ver}"
        elif m_chr:
            browser = f"Brave Browser (Chromium {m_chr.group(1)})"
        else:
            browser = "Brave Browser"
    elif "CocCoc" in sec_ch_full or "CocCoc" in sec_ch_ua or "coc_coc_browser" in ua:
        m = re.search(r"coc_coc_browser/([\d.]+)", ua)
        ver = _chon_phien_ban_chi_tiet(sec_ch_full, sec_ch_ua, m.group(1) if m else "", ("CocCoc", "Coc Coc"))
        browser = f"Cốc Cốc {ver}".strip() if ver else "Cốc Cốc"
    elif any(tok in ua for tok in ("Edg/", "EdgA/", "EdgiOS/")) or "Microsoft Edge" in sec_ch_ua or "Microsoft Edge" in sec_ch_full:
        m = re.search(r"(?:Edg|EdgA|EdgiOS)/([\d.]+)", ua)
        ver = _chon_phien_ban_chi_tiet(sec_ch_full, sec_ch_ua, m.group(1) if m else "", ("Microsoft Edge",))
        browser = f"Microsoft Edge {ver}".strip() if ver else "Microsoft Edge"
    elif "OPR/" in ua or "Opera" in sec_ch_ua or "Opera" in sec_ch_full:
        m = re.search(r"OPR/([\d.]+)", ua)
        ver = _chon_phien_ban_chi_tiet(sec_ch_full, sec_ch_ua, m.group(1) if m else "", ("Opera",))
        browser = f"Opera {ver}".strip() if ver else "Opera"
    elif "SamsungBrowser/" in ua:
        m = re.search(r"SamsungBrowser/([\d.]+)", ua)
        browser = f"Samsung Internet {m.group(1)}" if m else "Samsung Internet"
    elif "Firefox/" in ua or "FxiOS/" in ua:
        m = re.search(r"(?:Firefox|FxiOS)/([\d.]+)", ua)
        browser = f"Mozilla Firefox {m.group(1)}" if m else "Mozilla Firefox"
    elif "Chrome/" in ua or "CriOS/" in ua:
        m = re.search(r"(?:Chrome|CriOS)/([\d.]+)", ua)
        full_ver = _chon_phien_ban_chi_tiet(sec_ch_full, sec_ch_ua, m.group(1) if m else "", ("Google Chrome", "Chromium"))
        major_ver = full_ver.split(".")[0] if full_ver else ""
        brave_local = _phat_hien_brave_local(major_ver) if allow_local_host_probe else None
        if brave_local and "Google Chrome" not in sec_ch_ua:
            browser = brave_local
        else:
            browser = f"Google Chrome {full_ver}".strip()
    elif "Safari/" in ua:
        m_ver = re.search(r"Version/([\d.]+)", ua)
        browser = f"Apple Safari {m_ver.group(1)}" if m_ver else "Apple Safari"
    else:
        browser = _lam_sach_chuoi_header(ua, 60) or "Trình duyệt Web"

    return f"{os_name} - {browser}"


def _phan_loai_nhom_thiet_bi(thong_tin_thiet_bi: str) -> tuple[str, str]:
    """Trích xuất (nhóm_hệ_điều_hành, nhóm_trình_duyệt) phục vụ đối chiếu tính liên tục của phiên làm việc."""
    s = (thong_tin_thiet_bi or "").strip().lower()
    if not s:
        return ("unknown", "unknown")

    la_chuoi_container_cu = ("-aws" in s) or ("[srv-" in s)
    if la_chuoi_container_cu:
        os_fam = "legacy_cloud"
    elif "windows" in s:
        os_fam = "windows"
    elif "android" in s:
        os_fam = "android"
    elif "ios" in s or "iphone" in s or "ipad" in s:
        os_fam = "ios"
    elif "macos" in s or "mac os" in s:
        os_fam = "macos"
    elif "chromeos" in s:
        os_fam = "chromeos"
    elif "linux" in s:
        os_fam = "linux"
    else:
        os_fam = "unknown"

    if "brave" in s:
        br_fam = "brave"
    elif "cốc cốc" in s or "coccoc" in s:
        br_fam = "coccoc"
    elif "edge" in s:
        br_fam = "edge"
    elif "opera" in s:
        br_fam = "opera"
    elif "samsung" in s:
        br_fam = "samsung"
    elif "firefox" in s:
        br_fam = "firefox"
    elif "chrome" in s:
        br_fam = "chrome"
    elif "safari" in s:
        br_fam = "safari"
    else:
        br_fam = "unknown"

    return (os_fam, br_fam)


def cung_nhom_thiet_bi_phien(thiet_bi_cu: str, thiet_bi_moi: str) -> bool:
    """
    Kiểm tra hai chuỗi thông tin thiết bị có thuộc cùng một trình duyệt và hệ điều hành máy khách hay không
    (hỗ trợ trường hợp mạng Dual-WAN / CGNAT / chuyển vùng IPv4-IPv6 trên cùng trình duyệt đang đăng nhập,
    hoặc nâng cấp chuỗi Client Hints từ Windows 10/11 lên Windows 11).
    """
    os_cu, br_cu = _phan_loai_nhom_thiet_bi(thiet_bi_cu)
    os_moi, br_moi = _phan_loai_nhom_thiet_bi(thiet_bi_moi)
    if br_cu == "unknown" or br_moi == "unknown" or br_cu != br_moi:
        return False
    if os_cu == "legacy_cloud":
        return os_moi != "unknown"
    return os_cu != "unknown" and os_cu == os_moi


# =============================================================================
# 6. MÃ HÓA AES-256-GCM & KIỂM TRA TOÀN VẸN SHA-256 CHO KHO ĐỀ ÔN TẬP & ĐỀ THI
# =============================================================================
def tinh_sha256_bytes(data: bytes) -> str:
    """Tính mã băm SHA-256 (64 ký tự hex) của tệp gốc để kiểm tra tính toàn vẹn."""
    return hashlib.sha256(data).hexdigest()


def ma_hoa_tep_de(data: bytes) -> bytes:
    """Mã hóa nội dung tệp đề ôn tập bằng AES-256-GCM trước khi lưu xuống ổ đĩa."""
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def giai_ma_tep_de(encrypted_bytes: bytes) -> Optional[bytes]:
    """Giải mã tệp đề ôn tập từ ổ đĩa lên RAM. Trả về None nếu tệp bị can thiệp trái phép."""
    try:
        if isinstance(encrypted_bytes, memoryview):
            encrypted_bytes = bytes(encrypted_bytes)
        if len(encrypted_bytes) < 28:
            return None
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        aesgcm = AESGCM(MASTER_KEY)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return None


def ma_hoa_tep_de_thi_envelope(data: bytes, ma_tai_khoan: str):
    """
    Mã hóa bao phong (Envelope Encryption AES-256-GCM) và ký số cho bảng DeThi (CN_TaiLieu):
    - Sinh khóa dữ liệu ngẫu nhiên (DEK 32 bytes) để mã hóa tệp đề -> tách ciphertext và tag (16 bytes).
    - Bọc DEK bằng khóa chủ KEK (MASTER_KEY) -> khoa_ma_hoa_de.
    - Tạo chữ ký số xác thực của người ra đề trên (ma_bam_sha256 | ma_tai_khoan) -> chu_ky_so_nguoi_ra_de.
    """
    sha256_hex = tinh_sha256_bytes(data)
    dek = os.urandom(32)
    nonce = os.urandom(12)
    aes_dek = AESGCM(dek)
    ct_with_tag = aes_dek.encrypt(nonce, data, None)
    ciphertext = ct_with_tag[:-16]
    auth_tag = ct_with_tag[-16:]

    # Bọc DEK bằng MASTER_KEY
    wrap_nonce = os.urandom(12)
    wrapped_dek = wrap_nonce + AESGCM(MASTER_KEY).encrypt(wrap_nonce, dek, None)

    # Ký số HMAC-SHA256 đại diện chữ ký số của người ra đề
    import hmac
    sig_payload = f"{sha256_hex}|{ma_tai_khoan}".encode("utf-8")
    signature = hmac.new(MASTER_KEY, sig_payload, hashlib.sha256).digest()

    return {
        "ciphertext": ciphertext,
        "ma_bam_sha256": sha256_hex,
        "chu_ky_so_nguoi_ra_de": signature,
        "khoa_ma_hoa_de": wrapped_dek,
        "ma_nonce_aes": nonce,
        "the_xac_thuc_aes": auth_tag,
    }


def giai_ma_tep_de_thi_envelope(
    ciphertext: bytes,
    khoa_ma_hoa_de: bytes,
    ma_nonce_aes: bytes,
    the_xac_thuc_aes: bytes,
) -> Optional[bytes]:
    """Giải mã tệp đề thi từ DeThi bằng khóa bao phong và kiểm tra thẻ xác thực AES-GCM."""
    try:
        wrapped = bytes(khoa_ma_hoa_de)
        nonce = bytes(ma_nonce_aes)
        tag = bytes(the_xac_thuc_aes)
        wrap_nonce, wrap_ct = wrapped[:12], wrapped[12:]
        dek = AESGCM(MASTER_KEY).decrypt(wrap_nonce, wrap_ct, None)
        return AESGCM(dek).decrypt(nonce, ciphertext + tag, None)
    except Exception:
        return None

