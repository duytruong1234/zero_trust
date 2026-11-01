import os
import re
import uuid
import socket
import hashlib
import secrets
import ipaddress
import threading
import time
import urllib.request
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from typing import Optional
import psycopg2
from fastapi import FastAPI, Request, Response, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

from db import get_conn, init_db_schema, ghi_nhat_ky
from mailer import (
    cap_nhat_cau_hinh_gmail_env,
    gui_canh_bao_bay_de_moi,
    gui_email_kiem_tra,
    gui_ma_xac_nhan_quen_pin,
    gui_mat_khau_cap_lai,
    gui_mat_khau_khoi_tao,
    gui_thong_bao_dat_lai_2fa,
    kiem_tra_ket_noi_smtp,
    lay_cau_hinh_smtp,
)
from security import (
    bam_mat_khau,
    kiem_tra_mat_khau,
    kiem_tra_do_manh_mat_khau,
    kiem_tra_dinh_dang_ma_pin,
    bam_ma_pin,
    kiem_tra_ma_pin,
    sinh_khoa_bi_mat_totp,
    ma_hoa_bi_mat_otp,
    giai_ma_bi_mat_otp,
    lay_totp_uri,
    tao_anh_qr_base64,
    xac_thuc_ma_otp,
    sinh_session_token,
    bam_session_token,
    la_mang_noi_bo_truong,
    sinh_ma_can_bo_ngau_nhien,
    tao_ten_dang_nhap_tu_ho_ten,
    tao_email_tu_ho_ten,
    kiem_tra_email_truong_hop_le,
    lay_tien_to_vai_tro,
    phan_tich_thiet_bi,
    cung_nhom_thiet_bi_phien,
    chuan_hoa_vai_tro,
    chuan_hoa_ho_ten,
    sinh_mat_khau_tam,
    kiem_tra_mat_khau_khoi_tao,
    tinh_sha256_bytes,
    ma_hoa_tep_de,
    giai_ma_tep_de,
    ma_hoa_tep_de_thi_envelope,
    giai_ma_tep_de_thi_envelope,
    VAI_TRO_HOP_LE,
)

load_dotenv()

SESSION_EXPIRE_MINUTES = int(os.getenv("SESSION_EXPIRE_MINUTES", "120"))
IDLE_TIMEOUT_MINUTES = int(os.getenv("IDLE_TIMEOUT_MINUTES", "5"))
COOKIE_NAME = "hvt_session_token"
THOI_GIAN_KHOA_PHUT = 15
MUI_GIO_VN = timezone(timedelta(hours=7))

app = FastAPI(
    title="THPT Hoàng Văn Thụ - Hệ thống Quản lý và Phân phối Đề thi",
    description="Chức năng Đăng nhập và Bảo mật (CSDL PostgreSQL)",
)

_ACCEPT_CLIENT_HINTS = (
    "Sec-CH-UA, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform, "
    "Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, "
    "Sec-CH-UA-Model, Sec-CH-UA-Mobile"
)
_CRITICAL_CLIENT_HINTS = (
    "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, "
    "Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List"
)


@app.middleware("http")
async def attach_client_hints_header(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Accept-CH", _ACCEPT_CLIENT_HINTS)
    if request.url.path == "/":
        response.headers.setdefault("Critical-CH", _CRITICAL_CLIENT_HINTS)
    return response


def dinh_dang_gio_vn(dt: Optional[datetime]) -> str:
    """Hiển thị mốc thời gian theo giờ Việt Nam: HH:mm:ss DD/MM/YYYY."""
    if not dt:
        return ""
    return dt.astimezone(MUI_GIO_VN).strftime("%H:%M:%S %d/%m/%Y")


def tu_dong_mo_khoa_het_han(cur) -> int:
    """
    CN_CapTaiKhoanMoi: Khi đến hạn khoa_den_thoi_diem, hệ thống tự động mở lại bi_khoa = FALSE
    để người dùng tiếp tục nhập lại. Đồng thời đặt lại bộ đếm sai OTP về 0.
    (Tài khoản bị khóa vĩnh viễn có khoa_den_thoi_diem = NULL nên không bị ảnh hưởng.)
    """
    cur.execute(
        """
        UPDATE TaiKhoan
        SET bi_khoa = FALSE,
            khoa_den_thoi_diem = NULL,
            so_lan_sai_otp = 0
        WHERE khoa_den_thoi_diem IS NOT NULL
          AND khoa_den_thoi_diem <= NOW();
        """
    )
    return cur.rowcount


def _vong_lap_mo_khoa_tu_dong():
    """Tiến trình nền: cứ 30 giây quét bảng TaiKhoan và tự mở khóa các tài khoản đã hết hạn khóa."""
    while True:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    tu_dong_mo_khoa_het_han(cur)
                conn.commit()
        except Exception:
            pass
        time.sleep(30)


@app.on_event("startup")
def on_startup():
    init_db_schema()
    _dong_bo_email_truong_khi_khoi_dong()
    _dong_bo_ipv4_cong_cong_khi_khoi_dong()
    threading.Thread(target=_vong_lap_mo_khoa_tu_dong, daemon=True, name="tu-dong-mo-khoa").start()


# =============================================================================
# MODELS DỮ LIỆU ĐẦU VÀO
# =============================================================================
class LoginRequest(BaseModel):
    identifier: str
    mat_khau: str


class ActivateFirstTimeRequest(BaseModel):
    ma_otp: Optional[str] = None
    mat_khau_tam: Optional[str] = None
    mat_khau_moi: str
    xac_nhan_mat_khau: str
    ma_pin: Optional[str] = None
    xac_nhan_ma_pin: Optional[str] = None


class VerifyOtpRequest(BaseModel):
    ma_otp: str


class PinSetupRequest(BaseModel):
    ma_pin: str
    xac_nhan_ma_pin: str


class PinVerifyRequest(BaseModel):
    ma_pin: str


class PinResetRequest(BaseModel):
    ma_xac_nhan: str
    ma_pin_moi: str
    xac_nhan_ma_pin_moi: str


class PhanQuyenKhoiItem(BaseModel):
    ma_khoi: int
    duoc_truy_cap_de_chung: bool = True
    duoc_truy_cap_de_chinh_thuc: bool = False


class UpdateAccountPermissionsRequest(BaseModel):
    ma_mon_hoc: int
    danh_sach_khoi: Optional[list[PhanQuyenKhoiItem]] = None
    danh_sach_ma_khoi: Optional[list[int]] = None
    duoc_phep_ra_de_thi: Optional[bool] = None
    ma_pin: Optional[str] = None


class CreateAccountRequest(BaseModel):
    ma_can_bo: Optional[str] = None
    ho_ten: str
    ten_dang_nhap: str
    email: str
    vai_tro: str
    # Bỏ trống -> máy chủ tự sinh ngẫu nhiên mật khẩu tạm >= 10 ký tự (hoa, thường, số, ký tự đặc biệt)
    mat_khau_khoi_tao: Optional[str] = None
    # Cấu hình phân công chuyên môn & quyền ra đề thi (bảng PhanQuyenTheoKhoiMon)
    ma_mon_hoc: Optional[int] = None
    danh_sach_khoi: Optional[list[PhanQuyenKhoiItem]] = None
    danh_sach_ma_khoi: Optional[list[int]] = None
    duoc_phep_ra_de_thi: Optional[bool] = None
    ma_pin: Optional[str] = None


def _nhan_vai_tro_tieng_viet(vai_tro: Optional[str]) -> str:
    vt = chuan_hoa_vai_tro(vai_tro or "")
    if vt == "QUAN_TRI":
        return "Quản trị viên"
    if vt == "BAN_GIAM_HIEU":
        return "Ban Giám hiệu"
    return "Giáo viên"


def _mo_ta_can_bo(thong_tin: Optional[dict]) -> str:
    if not thong_tin:
        return "Người dùng không xác định"
    vt = _nhan_vai_tro_tieng_viet(thong_tin.get("vai_tro"))
    ho_ten = (thong_tin.get("ho_ten") or "").strip()
    ma_cb = (thong_tin.get("ma_can_bo") or "").strip()
    if ho_ten and ma_cb:
        return f"{vt} {ho_ten} ({ma_cb})"
    return f"{vt} {ho_ten or ma_cb}".strip()


class AdminPinActionRequest(BaseModel):
    ma_pin: Optional[str] = None


class UnlockAccountRequest(BaseModel):
    cap_lai_mat_khau_tam: bool = False
    ma_pin: Optional[str] = None


class TempLockAccountRequest(BaseModel):
    so_phut: int = 15
    ly_do: Optional[str] = None
    ma_pin: Optional[str] = None


class IpBlockRequest(BaseModel):
    dia_chi_ip: str
    danh_sach_ip: Optional[list[str]] = None
    ly_do: Optional[str] = None
    ma_pin: Optional[str] = None


# =============================================================================
# LẤY ĐỊA CHỈ IP THỰC TẾ CỦA THIẾT BỊ KẾT NỐI VÀ KIỂM TRA PHIÊN TRONG CSDL
# =============================================================================
_PUBLIC_IPV4_ENDPOINTS = (
    "https://checkip.amazonaws.com",
    "https://ipv4.icanhazip.com",
    "https://api4.ipify.org",
)
_DAI_IPV4_NOI_BO = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)
_PUBLIC_IPV4_LOCK = threading.Lock()
_PUBLIC_IPV4_CACHE = {
    "lan_ip": "",
    "public_ipv4": "",
    "expires_at": 0.0,
}


def _phan_tich_ip_hop_le(ip_str: Optional[str]):
    """Chuẩn hóa chuỗi IPv4 hoặc IPv6 hợp lệ (gỡ ngoặc vuông, zone-id, IPv4-mapped IPv6), ngược lại trả về None."""
    raw = (ip_str or "").strip()
    if not raw:
        return None
    if "%" in raw:
        raw = raw.split("%", 1)[0].strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")].strip()
    elif raw.count(":") == 1 and "." in raw:
        host_part, port_part = raw.rsplit(":", 1)
        if port_part.isdigit():
            raw = host_part.strip()
    try:
        addr = ipaddress.ip_address(raw)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr.is_unspecified or addr.is_multicast:
            return None
        return addr
    except ValueError:
        return None


def _phan_tich_ipv4(ip_str: Optional[str]) -> Optional[ipaddress.IPv4Address]:
    """Chuẩn hóa và trả về đối tượng IPv4Address nếu hợp lệ (bao gồm dạng IPv4-mapped IPv6), ngược lại trả về None."""
    addr = _phan_tich_ip_hop_le(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        return addr
    return None


def _la_ipv4_lan_rieng(ip_str: Optional[str]) -> bool:
    """Kiểm tra chuỗi có phải địa chỉ IPv4 mạng LAN riêng tư (10.x, 172.16-31.x, 192.168.x) hay không."""
    ipv4_obj = _phan_tich_ipv4(ip_str)
    if not ipv4_obj or ipv4_obj.is_loopback or ipv4_obj.is_link_local:
        return False
    return any(ipv4_obj in net for net in _DAI_IPV4_NOI_BO[:3])


def _la_ip_cong_cong(addr) -> bool:
    """Kiểm tra đối tượng IPv4Address/IPv6Address có phải IP công cộng định tuyến Internet hay không."""
    if addr is None:
        return False
    return bool(
        addr.is_global
        and not addr.is_loopback
        and not addr.is_private
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_unspecified
    )


def _la_ipv4_ngoai_lan(ip_str: Optional[str]) -> bool:
    """Kiểm tra chuỗi có phải địa chỉ IPv4 nằm ngoài dải mạng LAN nội bộ / loopback hay không."""
    ipv4_obj = _phan_tich_ipv4(ip_str)
    if not ipv4_obj:
        return False
    if ipv4_obj.is_unspecified or ipv4_obj.is_multicast:
        return False
    return not any(ipv4_obj in net for net in _DAI_IPV4_NOI_BO)


def _lay_ip_lan_thuc_te() -> str:
    """Lấy địa chỉ IP máy trạm thực tế của thiết bị trong mạng LAN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def _lay_ipv4_cong_cong_thuc_te(ip_lan_du_phong: Optional[str] = None) -> str:
    """
    Lấy địa chỉ IPv4 công cộng (Public WAN IPv4) thực tế của đường truyền mạng Internet đang sử dụng.
    Kết quả được lưu đệm TTL trong RAM để phản hồi tức thời; nếu ngoại tuyến sẽ dùng IP LAN dự phòng.
    """
    lan_ip = (ip_lan_du_phong or "").strip() or _lay_ip_lan_thuc_te()
    now_mono = time.monotonic()

    cached_lan = _PUBLIC_IPV4_CACHE["lan_ip"]
    cached_pub = _PUBLIC_IPV4_CACHE["public_ipv4"]
    cached_exp = _PUBLIC_IPV4_CACHE["expires_at"]
    if cached_pub and cached_lan == lan_ip and now_mono < cached_exp:
        return cached_pub

    with _PUBLIC_IPV4_LOCK:
        now_mono = time.monotonic()
        if (
            _PUBLIC_IPV4_CACHE["public_ipv4"]
            and _PUBLIC_IPV4_CACHE["lan_ip"] == lan_ip
            and now_mono < _PUBLIC_IPV4_CACHE["expires_at"]
        ):
            return _PUBLIC_IPV4_CACHE["public_ipv4"]

        detected_ipv4 = ""
        for url in _PUBLIC_IPV4_ENDPOINTS:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "THPTHoangVanThu-ZeroTrust/1.0"},
                )
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    candidate = resp.read().decode("utf-8", errors="ignore").strip()
                ipv4_obj = _phan_tich_ipv4(candidate)
                if ipv4_obj and ipv4_obj.is_global:
                    detected_ipv4 = str(ipv4_obj)
                    break
            except Exception:
                continue

        if detected_ipv4:
            _PUBLIC_IPV4_CACHE["lan_ip"] = lan_ip
            _PUBLIC_IPV4_CACHE["public_ipv4"] = detected_ipv4
            _PUBLIC_IPV4_CACHE["expires_at"] = time.monotonic() + 600.0
            return detected_ipv4

        _PUBLIC_IPV4_CACHE["lan_ip"] = lan_ip
        _PUBLIC_IPV4_CACHE["public_ipv4"] = lan_ip
        _PUBLIC_IPV4_CACHE["expires_at"] = time.monotonic() + 30.0
        return lan_ip


def _dong_bo_ipv4_cong_cong_khi_khoi_dong() -> None:
    """
    Chỉ áp dụng cho môi trường máy chủ nội bộ (Local LAN): làm nóng bộ nhớ đệm Public IPv4 khi khởi động.
    Tuyệt đối bỏ qua khi chạy trên đám mây (Render) để không ghi đè IP máy khách bằng IP máy chủ AWS,
    và không bao giờ can thiệp vào bảng bất biến NhatKyLog.
    """
    if os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_URL") or os.getenv("RENDER_SERVICE_ID"):
        return
    ip_lan = _lay_ip_lan_thuc_te()
    ip_cong_cong = _lay_ipv4_cong_cong_thuc_te(ip_lan)
    ipv4_obj = _phan_tich_ipv4(ip_cong_cong)
    if not ipv4_obj or not ipv4_obj.is_global or ip_cong_cong == ip_lan:
        return


def _dong_bo_email_truong_khi_khoi_dong():
    """
    Chuẩn hóa toàn bộ hộp thư cán bộ/giáo viên trong bảng TaiKhoan sang định dạng mới:
    <têngiáoviên>.thpthoangvanthu@gmail.com (ví dụ: nguyenvanminh.thpthoangvanthu@gmail.com)
    và thiết lập lại ràng buộc CHECK chk_taikhoan_email_domain trên PostgreSQL.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE TaiKhoan DROP CONSTRAINT IF EXISTS chk_taikhoan_email_domain;")
            cur.execute(
                """
                SELECT ma_tai_khoan::text AS ma_tai_khoan, ho_ten, email
                FROM TaiKhoan
                ORDER BY thoi_diem_tao ASC, ma_can_bo ASC;
                """
            )
            ds_tk = cur.fetchall()
            da_dung = {
                (r["email"] or "").strip().lower()
                for r in ds_tk
                if kiem_tra_email_truong_hop_le(r["email"] or "")
            }
            for r in ds_tk:
                email_cu = (r["email"] or "").strip().lower()
                if kiem_tra_email_truong_hop_le(email_cu):
                    continue
                stt = 1
                email_moi = tao_email_tu_ho_ten(r["ho_ten"] or "", stt)
                while email_moi in da_dung:
                    stt += 1
                    email_moi = tao_email_tu_ho_ten(r["ho_ten"] or "", stt)
                da_dung.add(email_moi)
                cur.execute(
                    "UPDATE TaiKhoan SET email = %s WHERE ma_tai_khoan = %s;",
                    (email_moi, r["ma_tai_khoan"]),
                )
            cur.execute(
                """
                ALTER TABLE TaiKhoan
                ADD CONSTRAINT chk_taikhoan_email_domain
                CHECK (email ~* '^[a-z0-9]+(\\.[a-z0-9]+)*\\.(thpthoangvanthu|thtphoangvanthu)@gmail\\.com$');
                """
            )
        conn.commit()


def _trich_xuat_ip_tu_proxy_headers(request: Request):
    """
    Trích xuất địa chỉ IP thực (IPv4 hoặc IPv6) của máy khách đứng trước Reverse Proxy / Cloudflare / Render.
    Ưu tiên: CF-Connecting-IP -> True-Client-IP -> hop công cộng đầu tiên trong X-Forwarded-For -> X-Real-IP.
    """
    for hdr_name in ("CF-Connecting-IP", "True-Client-IP"):
        val = (request.headers.get(hdr_name) or "").strip()
        if val:
            addr = _phan_tich_ip_hop_le(val.split(",")[0].strip())
            if addr and not addr.is_loopback:
                return addr

    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        hops = [_phan_tich_ip_hop_le(h.strip()) for h in forwarded.split(",")]
        valid_hops = [h for h in hops if h is not None and not h.is_loopback]
        for h in valid_hops:
            if _la_ip_cong_cong(h):
                return h
        if valid_hops:
            return valid_hops[0]

    real_ip = (request.headers.get("X-Real-IP") or "").strip()
    if real_ip:
        addr = _phan_tich_ip_hop_le(real_ip.split(",")[0].strip())
        if addr and not addr.is_loopback:
            return addr

    return None


def _dang_chay_sau_cloud_proxy(request: Request) -> bool:
    """Kiểm tra ứng dụng có đang chạy trên đám mây (Render) hoặc sau Reverse Proxy công cộng hay không."""
    if os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_URL") or os.getenv("RENDER_SERVICE_ID"):
        return True
    for hdr_name in ("CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For", "X-Real-IP"):
        if (request.headers.get(hdr_name) or "").strip():
            return True
    return False


def lay_ip_client(request: Request):
    """
    Lấy địa chỉ IP thiết bị máy khách (ip_thiet_bi), địa chỉ IPv4 công cộng (ipv4) và thông tin thiết bị (thiet_bi):
    - Khi triển khai công khai trên đám mây (Render / Cloudflare):
      + Không bao giờ lấy IP nội bộ hay IP AWS của máy chủ Render gán cho người truy cập.
      + Hỗ trợ đầy đủ cả người dùng mạng IPv4, Dual-Stack IPv6 (2402:800:...) và CGNAT/Dual-WAN.
      + ip_thiet_bi ghi nhận IP LAN máy khách (nếu trình duyệt cung cấp qua X-Client-LAN-IP) hoặc IPv6/IP máy khách thực tế.
      + ipv4 ghi nhận Public WAN IPv4 thực tế của đường truyền người dùng.
    - Khi chạy trực tiếp trong mạng LAN nội bộ (Localhost / LAN nhà trường):
      + ip_thiet_bi ghi nhận IP LAN máy trạm, ipv4 ghi nhận Public WAN IPv4 của mạng trường.
    """
    co_qua_proxy = _dang_chay_sau_cloud_proxy(request)
    proxy_ip_obj = _trich_xuat_ip_tu_proxy_headers(request)
    client_host = (request.client.host if (request.client and request.client.host) else "").strip()
    client_host_obj = _phan_tich_ip_hop_le(client_host)
    peer_ip_obj = proxy_ip_obj or client_host_obj

    hdr_lan_raw = (request.headers.get("X-Client-LAN-IP") or "").strip()
    client_lan_ipv4 = str(_phan_tich_ipv4(hdr_lan_raw)) if _la_ipv4_lan_rieng(hdr_lan_raw) else ""

    hdr_pub4_raw = (request.headers.get("X-Client-Public-IPv4") or "").strip()
    client_pub_ipv4 = str(_phan_tich_ipv4(hdr_pub4_raw)) if _la_ipv4_ngoai_lan(hdr_pub4_raw) else ""

    if co_qua_proxy:
        if isinstance(peer_ip_obj, ipaddress.IPv4Address) and _la_ip_cong_cong(peer_ip_obj):
            ipv4 = str(peer_ip_obj)
        elif client_pub_ipv4:
            ipv4 = client_pub_ipv4
        elif peer_ip_obj is not None:
            ipv4 = str(peer_ip_obj)
        else:
            ipv4 = "0.0.0.0"

        # Luôn ưu tiên định dạng số IPv4 (IP LAN nếu trình duyệt cung cấp, ngược lại dùng IPv4 thực của máy khách)
        # để không hiển thị chuỗi IPv6 dạng hex dài gây nhầm lẫn với dữ liệu mã hóa.
        if client_lan_ipv4:
            ip_thiet_bi = client_lan_ipv4
        elif _phan_tich_ipv4(ipv4) is not None:
            ip_thiet_bi = ipv4
        elif peer_ip_obj is not None and not peer_ip_obj.is_loopback:
            ip_thiet_bi = str(peer_ip_obj)
        else:
            ip_thiet_bi = ipv4

        allow_local_probe = False
    else:
        is_loopback_peer = (peer_ip_obj is None) or peer_ip_obj.is_loopback
        ip_lan_may_chu = _lay_ip_lan_thuc_te()

        if client_lan_ipv4 and not is_loopback_peer:
            ip_thiet_bi = client_lan_ipv4
        elif peer_ip_obj is not None and not peer_ip_obj.is_loopback:
            ip_thiet_bi = str(peer_ip_obj)
        elif client_lan_ipv4:
            ip_thiet_bi = client_lan_ipv4
        else:
            ip_thiet_bi = ip_lan_may_chu

        if isinstance(peer_ip_obj, ipaddress.IPv4Address) and _la_ip_cong_cong(peer_ip_obj):
            ipv4 = str(peer_ip_obj)
        elif client_pub_ipv4:
            ipv4 = client_pub_ipv4
        else:
            ipv4 = _lay_ipv4_cong_cong_thuc_te(ip_lan_may_chu)

        allow_local_probe = is_loopback_peer

    try:
        request.state.raw_peer_ip = str(peer_ip_obj) if peer_ip_obj is not None else ""
    except Exception:
        pass

    thiet_bi = phan_tich_thiet_bi(
        request.headers.get("User-Agent", ""),
        request.headers,
        allow_local_host_probe=allow_local_probe,
    )
    return ip_thiet_bi, ipv4, thiet_bi


def _kiem_tra_ip_bi_chan(
    cur,
    ip_may: Optional[str],
    ipv4: Optional[str],
    extra_ip: Optional[str] = None,
):
    """Kiểm tra xem địa chỉ IP máy trạm, IPv4 hoặc IP kết nối trực tiếp có đang bị chặn trong ChanDiaChiIP không."""
    ips = [
        ip
        for ip in {
            str(ip_may or "").strip(),
            str(ipv4 or "").strip(),
            str(extra_ip or "").strip(),
        }
        if ip
    ]
    if not ips:
        return None
    cur.execute(
        """
        SELECT ma_chan_ip, host(dia_chi_ip) AS dia_chi_ip, ly_do, thoi_diem_chan
        FROM ChanDiaChiIP
        WHERE dang_chan = TRUE
          AND host(dia_chi_ip) = ANY(%s)
        ORDER BY thoi_diem_chan DESC
        LIMIT 1;
        """,
        (ips,),
    )
    return cur.fetchone()


def kiem_tra_phien_hien_tai(
    request: Request,
    yeu_cau_otp_hoan_tat: bool = True,
    yeu_cau_da_co_pin: bool = True,
):
    """
    Truy vấn trực tiếp bảng PhienDangNhap và TaiKhoan trong PostgreSQL:
    1. Lấy chuỗi Session Token từ Cookie -> băm SHA-256 -> so khớp với cột ma_phien_bam
    2. Kiểm tra da_thu_hoi == FALSE
    3. Kiểm tra NOW() <= thoi_diem_het_han
    4. So sánh IPv4 hiện tại với cột ipv4 của phiên để chống đánh cắp Cookie
    5. Kiểm tra cổng 2FA: da_xac_thuc_otp == TRUE
    """
    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=401, detail={"code": "NO_SESSION", "message": "Vui lòng đăng nhập để tiếp tục."})

    token_hash = bam_session_token(raw_token)
    ip_may, current_ipv4, thiet_bi = lay_ip_client(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    p.ma_phien, p.ma_tai_khoan, p.ma_phien_bam,
                    host(p.ip_thiet_bi) AS phien_ip_thiet_bi,
                    host(p.ipv4) AS phien_ipv4,
                    p.thong_tin_thiet_bi, p.da_xac_thuc_otp, p.da_thu_hoi,
                    p.thoi_diem_het_han, p.thoi_diem_tao,
                    COALESCE(p.thoi_diem_hoat_dong_cuoi, p.thoi_diem_tao) AS thoi_diem_hoat_dong_cuoi,
                    t.ma_can_bo, t.ten_dang_nhap, t.mat_khau, t.ho_ten, t.email, t.vai_tro,
                    t.ma_pin, t.ma_xac_nhan_pin, t.han_xac_nhan_pin,
                    t.bi_mat_otp_ma_hoa, t.da_kich_hoat_otp, t.bi_khoa,
                    t.so_lan_dang_nhap_sai, t.so_lan_sai_otp,
                    host(t.ip_thiet_bi_gan_nhat) AS tk_ip_gan_nhat,
                    host(t.ipv4_gan_nhat) AS tk_ipv4_gan_nhat,
                    t.dang_hoat_dong
                FROM PhienDangNhap p
                JOIN TaiKhoan t ON t.ma_tai_khoan = p.ma_tai_khoan
                WHERE p.ma_phien_bam = %s;
                """,
                (token_hash,),
            )
            phien = cur.fetchone()

            if not phien:
                raise HTTPException(status_code=401, detail={"code": "INVALID_TOKEN", "message": "Phiên đăng nhập không hợp lệ."})

            if phien["da_thu_hoi"]:
                raise HTTPException(status_code=401, detail={"code": "REVOKED_SESSION", "message": "Phiên đăng nhập đã bị thu hồi. Vui lòng đăng nhập lại."})

            if not phien["dang_hoat_dong"]:
                cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                conn.commit()
                raise HTTPException(status_code=401, detail={"code": "ACCOUNT_DISABLED", "message": "Tài khoản đã bị tạm ngưng hoạt động. Phiên làm việc đã bị thu hồi."})

            if phien["bi_khoa"]:
                if tu_dong_mo_khoa_het_han(cur) > 0:
                    conn.commit()
                    cur.execute("SELECT bi_khoa FROM TaiKhoan WHERE ma_tai_khoan = %s;", (phien["ma_tai_khoan"],))
                    row_khoa = cur.fetchone()
                    phien["bi_khoa"] = bool(row_khoa["bi_khoa"]) if row_khoa else True
                if phien["bi_khoa"]:
                    cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                    conn.commit()
                    raise HTTPException(
                        status_code=401,
                        detail={"code": "ACCOUNT_LOCKED", "message": "Tài khoản đang bị tạm khóa an ninh. Phiên làm việc đã bị thu hồi."},
                    )

            raw_peer_ip = getattr(request.state, "raw_peer_ip", "")
            if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
                chan_ip = _kiem_tra_ip_bi_chan(cur, ip_may, current_ipv4, raw_peer_ip)
                if chan_ip:
                    cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                    conn.commit()
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "code": "IP_BLOCKED",
                            "blocked_ip": chan_ip["dia_chi_ip"],
                            "ly_do": chan_ip["ly_do"],
                            "thoi_diem_chan": dinh_dang_gio_vn(chan_ip["thoi_diem_chan"]),
                            "ip_may": ip_may,
                            "dia_chi_ipv4": current_ipv4,
                            "message": f"Thiết bị sử dụng địa chỉ IP ({chan_ip['dia_chi_ip']}) đã bị khóa truy cập toàn hệ thống vì lý do an ninh.",
                        },
                    )

            now_utc = datetime.now(timezone.utc)
            if now_utc > phien["thoi_diem_het_han"]:
                cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                conn.commit()
                raise HTTPException(status_code=401, detail={"code": "EXPIRED_SESSION", "message": "Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại."})

            last_active_dt = phien.get("thoi_diem_hoat_dong_cuoi") or phien["thoi_diem_tao"]
            if (now_utc - last_active_dt) > timedelta(minutes=IDLE_TIMEOUT_MINUTES):
                cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                conn.commit()
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Đăng xuất",
                    ip_thiet_bi=ip_may,
                    ipv4=current_ipv4,
                    ket_qua="Thành công",
                    chi_tiet=f"{_mo_ta_can_bo(phien)} tự động đăng xuất và thu hồi phiên làm việc do không thao tác trên màn hình quá {IDLE_TIMEOUT_MINUTES} phút.",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": "IDLE_SESSION_EXPIRED",
                        "message": f"Phiên làm việc đã tự động đăng xuất do màn hình không có thao tác trong {IDLE_TIMEOUT_MINUTES} phút. Vui lòng đăng nhập lại.",
                    },
                )

            thiet_bi_cu = (phien.get("thong_tin_thiet_bi") or "").strip()
            cung_thiet_bi = cung_nhom_thiet_bi_phien(thiet_bi_cu, thiet_bi)

            if current_ipv4 != phien["phien_ipv4"]:
                if cung_thiet_bi:
                    # Cùng trình duyệt và cùng hệ điều hành máy khách (mạng Dual-WAN / CGNAT / Dual-Stack đổi IP động):
                    # cập nhật lại IP hiện hành của phiên để duy trì phiên làm việc liền mạch.
                    cur.execute(
                        """
                        UPDATE PhienDangNhap
                        SET ip_thiet_bi = %s,
                            ipv4 = %s,
                            thong_tin_thiet_bi = %s
                        WHERE ma_phien = %s;
                        """,
                        (ip_may, current_ipv4, thiet_bi, phien["ma_phien"]),
                    )
                    conn.commit()
                    phien["phien_ip_thiet_bi"] = ip_may
                    phien["phien_ipv4"] = current_ipv4
                    phien["thong_tin_thiet_bi"] = thiet_bi
                else:
                    cur.execute(
                        "UPDATE PhienDangNhap SET da_thu_hoi = TRUE, da_xac_thuc_otp = FALSE WHERE ma_phien = %s;",
                        (phien["ma_phien"],),
                    )
                    conn.commit()
                    ghi_nhat_ky(
                        ma_tai_khoan=phien["ma_tai_khoan"],
                        hanh_dong="Đăng nhập",
                        ip_thiet_bi=ip_may,
                        ipv4=current_ipv4,
                        ket_qua="Cảnh báo",
                        chi_tiet=f"Phát hiện đổi địa chỉ IPv4 từ {phien['phien_ipv4']} sang {current_ipv4} kèm sai khác thiết bị truy cập. Phiên bị chặn ngay lập tức, yêu cầu xác thực lại thiết bị chính chủ.",
                        thong_tin_thiet_bi=thiet_bi,
                    )
                    raise HTTPException(
                        status_code=401,
                        detail={
                            "code": "IPV4_MISMATCH_HIJACK",
                            "message": "Phát hiện địa chỉ mạng và thiết bị thay đổi bất thường. Phiên làm việc đã bị khóa, vui lòng xác thực lại!",
                        },
                    )
            elif cung_thiet_bi and (
                (thiet_bi and thiet_bi != thiet_bi_cu and ("Windows 10/11" in thiet_bi_cu or "-aws" in thiet_bi_cu.lower() or "[srv-" in thiet_bi_cu.lower()))
                or (ip_may and ip_may != phien["phien_ip_thiet_bi"] and ip_may != current_ipv4)
            ):
                thiet_bi_cap_nhat = thiet_bi if ("Windows 10/11" not in thiet_bi) else (thiet_bi_cu or thiet_bi)
                cur.execute(
                    """
                    UPDATE PhienDangNhap
                    SET ip_thiet_bi = %s,
                        thong_tin_thiet_bi = %s
                    WHERE ma_phien = %s;
                    """,
                    (ip_may, thiet_bi_cap_nhat, phien["ma_phien"]),
                )
                conn.commit()
                phien["phien_ip_thiet_bi"] = ip_may
                phien["thong_tin_thiet_bi"] = thiet_bi_cap_nhat

            if yeu_cau_otp_hoan_tat and (not phien["da_xac_thuc_otp"] or not phien["da_kich_hoat_otp"]):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "OTP_REQUIRED",
                        "da_kich_hoat_otp": bool(phien["da_kich_hoat_otp"]),
                        "message": "Bắt buộc hoàn tất xác thực OTP trước khi truy cập hệ thống.",
                    },
                )

            if yeu_cau_otp_hoan_tat and yeu_cau_da_co_pin and not phien.get("ma_pin"):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "PIN_SETUP_REQUIRED",
                        "message": "Bắt buộc thiết lập mã PIN bảo mật 6 chữ số ở bước xác thực bên ngoài trước khi truy cập vào hệ thống.",
                    },
                )

            if request.headers.get("X-Background-Poll") != "1":
                cur.execute(
                    "UPDATE PhienDangNhap SET thoi_diem_hoat_dong_cuoi = CURRENT_TIMESTAMP WHERE ma_phien = %s;",
                    (phien["ma_phien"],),
                )
                conn.commit()

            return phien


# =============================================================================
# 1. API ĐĂNG NHẬP & XÁC THỰC 2FA TOTP (MỤC 1, 4, 5, 6)
# =============================================================================
@app.post("/api/auth/login")
def api_login(req: LoginRequest, request: Request, response: Response):
    identifier = (req.identifier or "").strip()
    mat_khau = req.mat_khau or ""
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    if not identifier or not mat_khau:
        raise HTTPException(status_code=400, detail="Vui lòng nhập đầy đủ Tên đăng nhập / Email và Mật khẩu.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Đến hạn khoa_den_thoi_diem -> tự động mở lại bi_khoa = FALSE trước khi xét đăng nhập
            tu_dong_mo_khoa_het_han(cur)
            conn.commit()

            cur.execute(
                """
                SELECT
                    ma_tai_khoan, ma_can_bo, ten_dang_nhap, mat_khau, ho_ten,
                    email, vai_tro, bi_mat_otp_ma_hoa, da_kich_hoat_otp, ma_pin,
                    bi_khoa, COALESCE(so_lan_dang_nhap_sai, 0) AS so_lan_dang_nhap_sai,
                    COALESCE(so_lan_sai_otp, 0) AS so_lan_sai_otp,
                    host(ip_thiet_bi_gan_nhat) AS ip_gan_nhat,
                    host(ipv4_gan_nhat) AS ipv4_gan_nhat,
                    dang_hoat_dong, khoa_den_thoi_diem
                FROM TaiKhoan
                WHERE LOWER(ten_dang_nhap) = LOWER(%s) OR LOWER(email) = LOWER(%s)
                LIMIT 1;
                """,
                (identifier, identifier),
            )
            acc = cur.fetchone()

            if (not acc) or (chuan_hoa_vai_tro(acc["vai_tro"]) != "QUAN_TRI"):
                chan_ip = _kiem_tra_ip_bi_chan(cur, ip_may, dia_chi_ipv4, getattr(request.state, "raw_peer_ip", ""))
                if chan_ip:
                    ghi_nhat_ky(
                        ma_tai_khoan=acc["ma_tai_khoan"] if acc else None,
                        hanh_dong="Đăng nhập",
                        ip_thiet_bi=ip_may,
                        ipv4=dia_chi_ipv4,
                        ket_qua="Thất bại",
                        chi_tiet=f"Từ chối đăng nhập từ địa chỉ IP đang bị chặn ({chan_ip['dia_chi_ip']})",
                        thong_tin_thiet_bi=thiet_bi,
                    )
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "code": "IP_BLOCKED",
                            "blocked_ip": chan_ip["dia_chi_ip"],
                            "ly_do": chan_ip["ly_do"],
                            "thoi_diem_chan": dinh_dang_gio_vn(chan_ip["thoi_diem_chan"]),
                            "ip_may": ip_may,
                            "dia_chi_ipv4": dia_chi_ipv4,
                            "message": f"Thiết bị sử dụng địa chỉ IP ({chan_ip['dia_chi_ip']}) đang bị khóa truy cập toàn hệ thống. Chỉ tài khoản Quản trị viên IT mới có quyền đăng nhập để gỡ chặn.",
                        },
                    )

            # Kịch bản 1: Tài khoản không tồn tại trên hệ thống
            if not acc:
                ghi_nhat_ky(
                    ma_tai_khoan=None,
                    hanh_dong="Đăng nhập",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet="Phát hiện tài khoản lạ đăng nhập vào hệ thống",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=401,
                    detail="Tài khoản không tồn tại trong hệ thống Trường THPT Hoàng Văn Thụ. Vui lòng kiểm tra lại thông tin.",
                )

            now_utc = datetime.now(timezone.utc)

            # Kịch bản 4: Tài khoản đang bị khóa tạm thời hoặc bị đình chỉ
            # Trường hợp a) Đang trong 15 phút phạt: bi_khoa = TRUE và khoa_den_thoi_diem còn hiệu lực
            if acc["bi_khoa"] and acc["khoa_den_thoi_diem"] and now_utc < acc["khoa_den_thoi_diem"]:
                con_lai_giay = int((acc["khoa_den_thoi_diem"] - now_utc).total_seconds())
                phut = max(1, (con_lai_giay + 59) // 60)
                ghi_nhat_ky(
                    ma_tai_khoan=acc["ma_tai_khoan"],
                    hanh_dong="Đăng nhập",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thất bại",
                    chi_tiet="Từ chối đăng nhập: Tài khoản đang trong thời gian bị khóa hoặc đã bị vô hiệu hóa",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Tài khoản đang bị tạm khóa. Vui lòng thử lại sau {phut} phút. "
                        f"(Tự động mở khóa lúc {dinh_dang_gio_vn(acc['khoa_den_thoi_diem'])})"
                    ),
                )

            # Trường hợp b) Bị vô hiệu hóa (dang_hoat_dong = FALSE) hoặc khóa an ninh vĩnh viễn (bi_khoa = TRUE, không có hạn mở)
            if (not acc["dang_hoat_dong"]) or acc["bi_khoa"]:
                ghi_nhat_ky(
                    ma_tai_khoan=acc["ma_tai_khoan"],
                    hanh_dong="Đăng nhập",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thất bại",
                    chi_tiet="Từ chối đăng nhập: Tài khoản đang trong thời gian bị khóa hoặc đã bị vô hiệu hóa",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản đã bị đình chỉ hoặc khóa an ninh. Vui lòng liên hệ Ban Giám hiệu.",
                )

            so_lan_sai_hien_tai = acc["so_lan_dang_nhap_sai"]

            # Kịch bản 2 & Kịch bản 3 (kèm ngưỡng khóa vĩnh viễn 10 lần của CN_DangNhap.docx):
            if not kiem_tra_mat_khau(mat_khau, acc["mat_khau"]):
                so_lan_sai_moi = so_lan_sai_hien_tai + 1

                # Sai 10 lần khóa luôn tài khoản (bi_khoa = TRUE, không có hạn mở), phải liên hệ Admin cấp lại mật khẩu
                if so_lan_sai_moi >= 10:
                    cur.execute(
                        """
                        UPDATE TaiKhoan
                        SET so_lan_dang_nhap_sai = 10, bi_khoa = TRUE, khoa_den_thoi_diem = NULL
                        WHERE ma_tai_khoan = %s;
                        """,
                        (acc["ma_tai_khoan"],),
                    )
                    conn.commit()
                    ghi_nhat_ky(
                        ma_tai_khoan=acc["ma_tai_khoan"],
                        hanh_dong="Đăng nhập",
                        ip_thiet_bi=ip_may,
                        ipv4=dia_chi_ipv4,
                        ket_qua="Cảnh báo",
                        chi_tiet="Tài khoản đã bị đình chỉ hoặc khóa an ninh do nhập sai mật khẩu 10 lần liên tiếp",
                        thong_tin_thiet_bi=thiet_bi,
                    )
                    raise HTTPException(
                        status_code=403,
                        detail="Tài khoản đã bị đình chỉ hoặc khóa an ninh. Vui lòng liên hệ Ban Giám hiệu.",
                    )

                # Kịch bản 3: Sai mật khẩu lần thứ 5 -> bi_khoa = TRUE, khoa_den_thoi_diem = NOW() + 15 phút
                if so_lan_sai_moi == 5:
                    khoa_den = now_utc + timedelta(minutes=THOI_GIAN_KHOA_PHUT)
                    cur.execute(
                        """
                        UPDATE TaiKhoan
                        SET so_lan_dang_nhap_sai = 5, bi_khoa = TRUE, khoa_den_thoi_diem = %s
                        WHERE ma_tai_khoan = %s;
                        """,
                        (khoa_den, acc["ma_tai_khoan"]),
                    )
                    conn.commit()
                    ghi_nhat_ky(
                        ma_tai_khoan=acc["ma_tai_khoan"],
                        hanh_dong="Đăng nhập",
                        ip_thiet_bi=ip_may,
                        ipv4=dia_chi_ipv4,
                        ket_qua="Cảnh báo",
                        chi_tiet="Tài khoản bị tạm khóa 15 phút do nhập sai mật khẩu 5 lần liên tiếp",
                        thong_tin_thiet_bi=thiet_bi,
                    )
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "Tài khoản đã bị tạm khóa 15 phút do vượt quá số lần đăng nhập sai quy định. Vui lòng thử lại sau. "
                            f"(Tự động mở khóa lúc {dinh_dang_gio_vn(khoa_den)})"
                        ),
                    )

                # Kịch bản 2: Sai mật khẩu xác thực (lần 1..4; hoặc 6..9 sau khi đã hết 15 phút phạt)
                cur.execute(
                    "UPDATE TaiKhoan SET so_lan_dang_nhap_sai = %s WHERE ma_tai_khoan = %s;",
                    (so_lan_sai_moi, acc["ma_tai_khoan"]),
                )
                conn.commit()
                ghi_nhat_ky(
                    ma_tai_khoan=acc["ma_tai_khoan"],
                    hanh_dong="Đăng nhập",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thất bại",
                    chi_tiet=f"Đăng nhập thất bại: Sai mật khẩu lần thứ {so_lan_sai_moi}",
                    thong_tin_thiet_bi=thiet_bi,
                )
                if so_lan_sai_moi < 5:
                    thong_bao = f"Mật khẩu không chính xác. Bạn còn lại {5 - so_lan_sai_moi} lần thử trước khi tài khoản bị tạm khóa 15 phút."
                else:
                    thong_bao = f"Mật khẩu không chính xác. Bạn còn lại {10 - so_lan_sai_moi} lần thử trước khi tài khoản bị khóa an ninh vĩnh viễn."
                raise HTTPException(status_code=401, detail=thong_bao)

            # MẬT KHẨU ĐÚNG -> Phân nhánh Kịch bản 5 (TH1), Kịch bản 6 (TH2), Kịch bản 7 (TH3)
            da_kich_hoat = bool(acc["da_kich_hoat_otp"])
            ip_khop = (acc["ip_gan_nhat"] == ip_may) and (acc["ipv4_gan_nhat"] == dia_chi_ipv4)
            if _dang_chay_sau_cloud_proxy(request):
                thuoc_mang_truong = _la_ipv4_ngoai_lan(dia_chi_ipv4) and la_mang_noi_bo_truong(dia_chi_ipv4)
            else:
                ip_wan_may_chu = _lay_ipv4_cong_cong_thuc_te(_lay_ip_lan_thuc_te())
                thuoc_mang_truong = la_mang_noi_bo_truong(dia_chi_ipv4) or (
                    la_mang_noi_bo_truong(ip_may) and dia_chi_ipv4 == ip_wan_may_chu
                )

            dang_nhap_noi_bo_an_toan = da_kich_hoat and ip_khop and thuoc_mang_truong

            # Thu hồi toàn bộ các phiên "Chờ nhập OTP" (chưa xác thực 2 lớp) còn treo trước đó của tài khoản này
            # để tránh sinh nhiều phiên chờ trùng lặp khi bấm đăng nhập nhiều lần hoặc tải lại trang.
            cur.execute(
                """
                UPDATE PhienDangNhap
                SET da_thu_hoi = TRUE
                WHERE ma_tai_khoan = %s
                  AND da_xac_thuc_otp = FALSE
                  AND da_thu_hoi = FALSE;
                """,
                (acc["ma_tai_khoan"],),
            )

            raw_token, token_hash = sinh_session_token()

            # Kịch bản 5 (TH1): Đăng nhập an toàn từ mạng nội bộ trường
            if dang_nhap_noi_bo_an_toan:
                het_han = now_utc + timedelta(hours=8)
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET so_lan_dang_nhap_sai = 0,
                        so_lan_sai_otp = 0,
                        khoa_den_thoi_diem = NULL,
                        ip_thiet_bi_gan_nhat = %s,
                        ipv4_gan_nhat = %s
                    WHERE ma_tai_khoan = %s;
                    """,
                    (ip_may, dia_chi_ipv4, acc["ma_tai_khoan"]),
                )
                cur.execute(
                    """
                    INSERT INTO PhienDangNhap (
                        ma_tai_khoan, ma_phien_bam, ip_thiet_bi, ipv4,
                        thong_tin_thiet_bi, da_xac_thuc_otp, da_thu_hoi, thoi_diem_het_han, thoi_diem_tao
                    )
                    VALUES (%s, %s, %s, %s, %s, TRUE, FALSE, %s, %s)
                    RETURNING ma_phien;
                    """,
                    (
                        acc["ma_tai_khoan"],
                        token_hash,
                        ip_may,
                        dia_chi_ipv4,
                        thiet_bi,
                        het_han,
                        now_utc,
                    ),
                )
                conn.commit()

                response.set_cookie(
                    key=COOKIE_NAME,
                    value=raw_token,
                    httponly=True,
                    samesite="lax",
                    max_age=8 * 3600,
                )

                ghi_nhat_ky(
                    ma_tai_khoan=acc["ma_tai_khoan"],
                    hanh_dong="Đăng nhập",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thành công",
                    chi_tiet="Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc",
                    thong_tin_thiet_bi=thiet_bi,
                )
                da_co_ma_pin = bool(acc.get("ma_pin"))
                return {
                    "status": "OK",
                    "next_step": "DASHBOARD" if da_co_ma_pin else "SETUP_PIN",
                    "da_co_ma_pin": da_co_ma_pin,
                    "message": (
                        "Đăng nhập thành công!"
                        if da_co_ma_pin
                        else "Đăng nhập thành công! Vui lòng thiết lập mã PIN bảo mật 6 chữ số trước khi truy cập vào hệ thống."
                    ),
                    "user": {
                        "ma_can_bo": acc["ma_can_bo"],
                        "ho_ten": acc["ho_ten"],
                        "ten_dang_nhap": acc["ten_dang_nhap"],
                        "email": acc["email"],
                        "vai_tro": acc["vai_tro"],
                        "da_co_ma_pin": da_co_ma_pin,
                    },
                }

            # Kịch bản 6 (TH2): Tài khoản đăng nhập lần đầu tiên (da_kich_hoat_otp = FALSE)
            if not da_kich_hoat:
                het_han = now_utc + timedelta(minutes=15)
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET so_lan_dang_nhap_sai = 0,
                        so_lan_sai_otp = 0,
                        khoa_den_thoi_diem = NULL
                    WHERE ma_tai_khoan = %s;
                    """,
                    (acc["ma_tai_khoan"],),
                )
                cur.execute(
                    """
                    INSERT INTO PhienDangNhap (
                        ma_tai_khoan, ma_phien_bam, ip_thiet_bi, ipv4,
                        thong_tin_thiet_bi, da_xac_thuc_otp, da_thu_hoi, thoi_diem_het_han, thoi_diem_tao
                    )
                    VALUES (%s, %s, %s, %s, %s, FALSE, FALSE, %s, %s)
                    RETURNING ma_phien;
                    """,
                    (
                        acc["ma_tai_khoan"],
                        token_hash,
                        ip_may,
                        dia_chi_ipv4,
                        thiet_bi,
                        het_han,
                        now_utc,
                    ),
                )
                conn.commit()

                response.set_cookie(
                    key=COOKIE_NAME,
                    value=raw_token,
                    httponly=True,
                    samesite="lax",
                    max_age=8 * 3600,
                )

                ghi_nhat_ky(
                    ma_tai_khoan=acc["ma_tai_khoan"],
                    hanh_dong="Đăng nhập",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thành công",
                    chi_tiet="Xác thực mật khẩu khởi tạo hợp lệ, chuyển sang thiết lập bảo mật 2FA và đặt mã PIN lần đầu.",
                    thong_tin_thiet_bi=thiet_bi,
                )
                return {
                    "status": "OTP_REQUIRED",
                    "next_step": "FIRST_TIME_2FA",
                    "message": "Yêu cầu kích hoạt 2FA",
                    "user": {
                        "ma_can_bo": acc["ma_can_bo"],
                        "ho_ten": acc["ho_ten"],
                        "ten_dang_nhap": acc["ten_dang_nhap"],
                        "email": acc["email"],
                        "vai_tro": acc["vai_tro"],
                        "da_kich_hoat_otp": False,
                        "ip_may": ip_may,
                        "dia_chi_ipv4": dia_chi_ipv4,
                    },
                }

            # Kịch bản 7 (TH3): Đăng nhập từ IP lạ / mạng ngoài trường / thiết bị mới
            het_han = now_utc + timedelta(minutes=5)
            cur.execute(
                """
                UPDATE TaiKhoan
                SET so_lan_dang_nhap_sai = 0,
                    so_lan_sai_otp = 0,
                    khoa_den_thoi_diem = NULL
                WHERE ma_tai_khoan = %s;
                """,
                (acc["ma_tai_khoan"],),
            )
            cur.execute(
                """
                INSERT INTO PhienDangNhap (
                    ma_tai_khoan, ma_phien_bam, ip_thiet_bi, ipv4,
                    thong_tin_thiet_bi, da_xac_thuc_otp, da_thu_hoi, thoi_diem_het_han, thoi_diem_tao
                )
                VALUES (%s, %s, %s, %s, %s, FALSE, FALSE, %s, %s)
                RETURNING ma_phien;
                """,
                (
                    acc["ma_tai_khoan"],
                    token_hash,
                    ip_may,
                    dia_chi_ipv4,
                    thiet_bi,
                    het_han,
                    now_utc,
                ),
            )
            conn.commit()

            response.set_cookie(
                key=COOKIE_NAME,
                value=raw_token,
                httponly=True,
                samesite="lax",
                max_age=8 * 3600,
            )

            ghi_nhat_ky(
                ma_tai_khoan=acc["ma_tai_khoan"],
                hanh_dong="Đăng nhập",
                ip_thiet_bi=ip_may,
                ipv4=dia_chi_ipv4,
                ket_qua="Cảnh báo",
                chi_tiet="Đăng nhập từ thiết bị hoặc địa chỉ mạng mới, yêu cầu xác thực mã OTP 6 số.",
                thong_tin_thiet_bi=thiet_bi,
            )
            return {
                "status": "OTP_REQUIRED",
                "next_step": "VERIFY_OTP",
                "message": "Yêu cầu xác thực bước 2 (OTP)",
                "user": {
                    "ma_can_bo": acc["ma_can_bo"],
                    "ho_ten": acc["ho_ten"],
                    "ten_dang_nhap": acc["ten_dang_nhap"],
                    "email": acc["email"],
                    "vai_tro": acc["vai_tro"],
                    "da_kich_hoat_otp": True,
                    "otp_key_tag": _lay_ma_dinh_danh_khoa_otp(acc.get("bi_mat_otp_ma_hoa")),
                    "ip_may": ip_may,
                    "dia_chi_ipv4": dia_chi_ipv4,
                },
            }


_TEN_MON_NGAN = {
    "TOAN": "Toán",
    "VAN": "Ngữ văn",
    "ANH": "Tiếng Anh",
    "LICH_SU": "Lịch sử",
    "VAT_LY": "Vật lý",
    "HOA_HOC": "Hóa học",
    "SINH_HOC": "Sinh học",
    "DIA_LY": "Địa lý",
}


def _chan_quan_tri_truy_cap_kho_de(request: Request, phien: dict, ten_kho: str) -> None:
    """Phân tách nhiệm vụ Zero-Trust: Quản trị viên IT không được phép truy cập Kho đề ôn tập và Kho đề thi."""
    if chuan_hoa_vai_tro(phien.get("vai_tro") or "") == "QUAN_TRI":
        ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Truy cập trái phép",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Cảnh báo",
            chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} truy cập {ten_kho} theo chính sách phân tách quyền hạn.",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(
            status_code=403,
            detail=f"Tài khoản Quản trị viên không có quyền truy cập {ten_kho}.",
        )


def lay_thong_tin_phan_quyen_mon(cur, ma_tai_khoan, vai_tro: str):
    """
    Truy vấn bảng PhanQuyenTheoKhoiMon kết hợp MonHoc và KhoiLop của tài khoản đang đăng nhập.
    Giáo viên dạy môn nào chỉ được trả về đúng môn học và khối lớp đã phân công.
    Quản trị viên IT chỉ quản trị tài khoản, phân công và nhật ký (không truy cập kho đề).
    """
    if chuan_hoa_vai_tro(vai_tro) == "QUAN_TRI":
        return {
            "ma_mon_hoc": 0,
            "ky_hieu_mon": "",
            "ten_mon_hoc": "",
            "ten_mon_ngan": "",
            "danh_sach_khoi": [],
            "danh_sach_khoi_duoc_phep": [],
            "danh_sach_khoi_chinh_thuc": [],
            "duoc_truy_cap_de_chung": False,
            "duoc_truy_cap_de_chinh_thuc": False,
            "chi_tiet_phan_quyen": [],
        }

    cur.execute(
        """
        SELECT
            pq.ma_phan_quyen,
            pq.ma_khoi,
            kl.ten_khoi,
            pq.ma_mon_hoc,
            mh.ky_hieu_mon,
            mh.ten_mon_hoc,
            pq.duoc_truy_cap_de_chung,
            pq.duoc_truy_cap_de_chinh_thuc
        FROM PhanQuyenTheoKhoiMon pq
        JOIN MonHoc mh ON mh.ma_mon_hoc = pq.ma_mon_hoc
        JOIN KhoiLop kl ON kl.ma_khoi = pq.ma_khoi
        WHERE pq.ma_tai_khoan = %s AND mh.dang_su_dung = TRUE
        ORDER BY pq.ma_mon_hoc ASC, pq.ma_khoi ASC;
        """,
        (ma_tai_khoan,),
    )
    rows = cur.fetchall()
    if rows:
        first = rows[0]
        ky_hieu = first["ky_hieu_mon"]
        ten_ngan = _TEN_MON_NGAN.get(ky_hieu, first["ten_mon_hoc"])
        tat_ca_khoi = sorted({int(r["ma_khoi"]) for r in rows})
        khoi_chung = sorted({int(r["ma_khoi"]) for r in rows if r["duoc_truy_cap_de_chung"]})
        khoi_chinh_thuc = sorted({int(r["ma_khoi"]) for r in rows if r["duoc_truy_cap_de_chinh_thuc"]})
        return {
            "ma_mon_hoc": int(first["ma_mon_hoc"]),
            "ky_hieu_mon": ky_hieu,
            "ten_mon_hoc": first["ten_mon_hoc"],
            "ten_mon_ngan": ten_ngan,
            "danh_sach_khoi": khoi_chung,
            "danh_sach_khoi_duoc_phep": tat_ca_khoi,
            "danh_sach_khoi_chinh_thuc": khoi_chinh_thuc,
            "duoc_truy_cap_de_chung": bool(khoi_chung),
            "duoc_truy_cap_de_chinh_thuc": bool(khoi_chinh_thuc),
            "chi_tiet_phan_quyen": rows,
        }

    cur.execute("SELECT ma_mon_hoc, ky_hieu_mon, ten_mon_hoc FROM MonHoc WHERE ma_mon_hoc = 1 LIMIT 1;")
    mh = cur.fetchone() or {"ma_mon_hoc": 1, "ky_hieu_mon": "TOAN", "ten_mon_hoc": "Toán học"}
    return {
        "ma_mon_hoc": int(mh["ma_mon_hoc"]),
        "ky_hieu_mon": mh["ky_hieu_mon"],
        "ten_mon_hoc": mh["ten_mon_hoc"],
        "ten_mon_ngan": _TEN_MON_NGAN.get(mh["ky_hieu_mon"], mh["ten_mon_hoc"]),
        "danh_sach_khoi": [],
        "danh_sach_khoi_duoc_phep": [],
        "danh_sach_khoi_chinh_thuc": [],
        "duoc_truy_cap_de_chung": False,
        "duoc_truy_cap_de_chinh_thuc": False,
        "chi_tiet_phan_quyen": [],
    }


@app.get("/api/auth/ip-status")
def api_ip_access_status(request: Request):
    """Kiểm tra cổng tường lửa Zero-Trust: Thiết bị / địa chỉ IP hiện tại có đang bị khóa toàn máy trong ChanDiaChiIP hay không."""
    ip_may, current_ipv4, _ = lay_ip_client(request)
    raw_token = request.cookies.get(COOKIE_NAME)
    is_admin_session = False

    with get_conn() as conn:
        with conn.cursor() as cur:
            chan_ip = _kiem_tra_ip_bi_chan(cur, ip_may, current_ipv4, getattr(request.state, "raw_peer_ip", ""))
            if raw_token:
                token_hash = bam_session_token(raw_token)
                cur.execute(
                    """
                    SELECT t.vai_tro, t.dang_hoat_dong, t.bi_khoa, p.da_thu_hoi, p.da_xac_thuc_otp, p.thoi_diem_het_han
                    FROM PhienDangNhap p
                    JOIN TaiKhoan t ON t.ma_tai_khoan = p.ma_tai_khoan
                    WHERE p.ma_phien_bam = %s
                    LIMIT 1;
                    """,
                    (token_hash,),
                )
                row_p = cur.fetchone()
                if (
                    row_p
                    and not row_p["da_thu_hoi"]
                    and row_p["dang_hoat_dong"]
                    and not row_p["bi_khoa"]
                    and row_p["da_xac_thuc_otp"]
                    and row_p["thoi_diem_het_han"] >= datetime.now(timezone.utc)
                    and chuan_hoa_vai_tro(row_p["vai_tro"]) == "QUAN_TRI"
                ):
                    is_admin_session = True

    if not chan_ip:
        return {
            "blocked": False,
            "is_admin_session": is_admin_session,
            "ip_may": ip_may,
            "dia_chi_ipv4": current_ipv4,
        }

    return {
        "blocked": True,
        "is_admin_session": is_admin_session,
        "ip_may": ip_may,
        "dia_chi_ipv4": current_ipv4,
        "blocked_ip": chan_ip["dia_chi_ip"],
        "ly_do": chan_ip["ly_do"],
        "thoi_diem_chan": dinh_dang_gio_vn(chan_ip["thoi_diem_chan"]),
    }


def _lay_ma_dinh_danh_khoa_otp(bi_mat_ma_hoa) -> str:
    if not bi_mat_ma_hoa:
        return ""
    try:
        sec = giai_ma_bi_mat_otp(bi_mat_ma_hoa)
        return (sec or "").strip()[:4].upper()
    except Exception:
        return ""


@app.get("/api/auth/session-status")
def api_session_status(request: Request):
    """Lấy trạng thái phiên hiện tại và phân quyền môn học từ CSDL PostgreSQL."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
    da_co_pin = bool(phien.get("ma_pin"))
    return {
        "authenticated": True,
        "da_xac_thuc_otp": bool(phien["da_xac_thuc_otp"]),
        "da_kich_hoat_otp": bool(phien["da_kich_hoat_otp"]),
        "da_co_ma_pin": da_co_pin,
        "phan_quyen_mon": pq,
        "user": {
            "ma_tai_khoan": str(phien["ma_tai_khoan"]),
            "ma_can_bo": phien["ma_can_bo"],
            "ho_ten": phien["ho_ten"],
            "ten_dang_nhap": phien["ten_dang_nhap"],
            "email": phien["email"],
            "vai_tro": phien["vai_tro"],
            "da_co_ma_pin": da_co_pin,
            "otp_key_tag": _lay_ma_dinh_danh_khoa_otp(phien.get("bi_mat_otp_ma_hoa")),
            "ip_may": phien["phien_ip_thiet_bi"],
            "dia_chi_ipv4": phien["phien_ipv4"],
            "thong_tin_thiet_bi": phien["thong_tin_thiet_bi"],
            "phan_quyen_mon": pq,
        },
    }


@app.get("/api/auth/2fa-setup-info")
def api_get_2fa_setup_info(request: Request):
    """
    Giải mã cột BYTEA bi_mat_otp_ma_hoa từ bảng TaiKhoan để hiển thị mã QR
    trong lần đầu truy cập (khi da_kich_hoat_otp == FALSE).
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False)
    if phien["da_kich_hoat_otp"]:
        raise HTTPException(
            status_code=403,
            detail="Niêm phong khóa: Tài khoản này đã kích hoạt xác thực 2 lớp. Mã QR và chuỗi khóa đã bị ẩn vĩnh viễn.",
        )

    secret_base32 = _lay_hoac_sinh_bi_mat_otp(phien)
    otpauth_uri = lay_totp_uri(
        secret_base32,
        phien["email"],
        phien["ho_ten"],
        phien.get("ten_dang_nhap", ""),
    )
    qr_data_url = tao_anh_qr_base64(otpauth_uri)

    so_lan_sai_otp = int(phien["so_lan_sai_otp"] or 0)
    return {
        "ho_ten": phien["ho_ten"],
        "ma_can_bo": phien["ma_can_bo"],
        "ten_dang_nhap": phien.get("ten_dang_nhap", ""),
        "email": phien["email"],
        "vai_tro": phien["vai_tro"],
        "secret_base32": secret_base32,
        "otp_key_tag": (secret_base32 or "")[:4].upper(),
        "otpauth_uri": otpauth_uri,
        "qr_data_url": qr_data_url,
        "ip_may": phien["phien_ip_thiet_bi"],
        "dia_chi_ipv4": phien["phien_ipv4"],
        "so_lan_sai_otp": so_lan_sai_otp,
        "con_lai_otp": max(0, 3 - so_lan_sai_otp),
        "da_xac_thuc_otp": bool(phien["da_xac_thuc_otp"]),
    }


def _lay_hoac_sinh_bi_mat_otp(phien) -> str:
    """
    CN_CapTaiKhoanMoi - Giai đoạn 2: Lấy dữ liệu mã hóa từ cột bi_mat_otp_ma_hoa lên RAM và giải mã AES-256.
    Nếu cột còn trống (tài khoản cũ / dữ liệu nhập tay), hệ thống tự sinh khóa bí mật TOTP mới,
    mã hóa AES-256 rồi lưu xuống CSDL ngay khi giáo viên bắt đầu bước kích hoạt mã QR lần đầu.
    """
    if phien["bi_mat_otp_ma_hoa"]:
        return giai_ma_bi_mat_otp(phien["bi_mat_otp_ma_hoa"])
    if phien["da_kich_hoat_otp"]:
        raise HTTPException(status_code=409, detail="Tài khoản chưa có khóa bí mật TOTP. Vui lòng liên hệ Quản trị viên để Reset 2FA.")
    secret_base32 = sinh_khoa_bi_mat_totp()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE TaiKhoan SET bi_mat_otp_ma_hoa = %s WHERE ma_tai_khoan = %s AND bi_mat_otp_ma_hoa IS NULL;",
                (psycopg2.Binary(ma_hoa_bi_mat_otp(secret_base32)), phien["ma_tai_khoan"]),
            )
        conn.commit()
    return secret_base32


def _xu_ly_sai_otp(phien, ip_may: str, dia_chi_ipv4: str, thiet_bi: str, response: Response):
    """
    Kịch bản 8: Nhập sai mã OTP (Xác thực bước 2 thất bại)
    - Tăng so_lan_sai_otp += 1 trong bảng TaiKhoan.
    - Lần 1 hoặc 2: giữ nguyên da_thu_hoi = FALSE, thông báo còn {3 - so_lan_sai_otp} lần thử.
    - Lần 3: cập nhật da_thu_hoi = TRUE, khóa an ninh bi_khoa = TRUE đến khoa_den_thoi_diem = NOW() + 15 phút.
    - NhatKyLog: hanh_dong = 'Xác thực OTP', ket_qua = 'Cảnh báo', chi_tiet = 'Nhập sai mã OTP lần {so_lan_sai_otp}'.
    """
    now_utc = datetime.now(timezone.utc)
    so_lan_sai_moi = (phien["so_lan_sai_otp"] or 0) + 1

    with get_conn() as conn:
        with conn.cursor() as cur:
            if so_lan_sai_moi >= 3:
                so_lan_sai_moi = 3
                khoa_den = now_utc + timedelta(minutes=THOI_GIAN_KHOA_PHUT)
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET so_lan_sai_otp = 3, bi_khoa = TRUE, khoa_den_thoi_diem = %s
                    WHERE ma_tai_khoan = %s;
                    """,
                    (khoa_den, phien["ma_tai_khoan"]),
                )
                cur.execute(
                    "UPDATE PhienDangNhap SET da_thu_hoi = TRUE, da_xac_thuc_otp = FALSE WHERE ma_phien = %s;",
                    (phien["ma_phien"],),
                )
                conn.commit()

                response.delete_cookie(COOKIE_NAME)
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Xác thực OTP",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Nhập sai mã OTP lần {so_lan_sai_moi}",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "OTP_BRUTE_FORCE_LOCKED",
                        "message": (
                            "Bạn đã nhập sai mã OTP 3 lần liên tiếp. Phiên làm việc đã bị hủy và tài khoản bị tạm khóa 15 phút vì lý do an ninh. "
                            f"(Tự động mở khóa lúc {dinh_dang_gio_vn(khoa_den)})"
                        ),
                    },
                )
            else:
                cur.execute(
                    "UPDATE TaiKhoan SET so_lan_sai_otp = %s WHERE ma_tai_khoan = %s;",
                    (so_lan_sai_moi, phien["ma_tai_khoan"]),
                )
                conn.commit()
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Xác thực OTP",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Nhập sai mã OTP lần {so_lan_sai_moi}",
                    thong_tin_thiet_bi=thiet_bi,
                )
                con_lai = 3 - so_lan_sai_moi
                raise HTTPException(
                    status_code=400,
                    detail={
                        "code": "OTP_INVALID",
                        "attempts": so_lan_sai_moi,
                        "message": f"Mã xác thực OTP không chính xác hoặc đã hết hạn. Bạn còn lại {con_lai} lần thử trước khi tài khoản bị tạm khóa.",
                    },
                )


@app.post("/api/auth/verify-first-time-otp")
def api_verify_first_time_otp(req: VerifyOtpRequest, request: Request, response: Response):
    """
    Bước 2 của quy trình kích hoạt lần đầu:
    Kiểm tra mã OTP 6 số từ ứng dụng Authenticator trước khi chuyển sang Bước 3 (Đổi mật khẩu khởi tạo).
    - Nếu nhập sai: áp dụng Kịch bản 8 (_xu_ly_sai_otp) tăng so_lan_sai_otp (tối đa 3 lần sẽ khóa 15 phút).
    - Nếu nhập đúng: đặt lại so_lan_sai_otp = 0 và đánh dấu phiên đã qua bước kiểm tra OTP (da_xac_thuc_otp = TRUE),
      nhưng vẫn giữ da_kich_hoat_otp = FALSE cho tới khi hoàn thành đổi mật khẩu ở Bước 3.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    secret_base32 = _lay_hoac_sinh_bi_mat_otp(phien)
    if not xac_thuc_ma_otp(secret_base32, req.ma_otp or ""):
        _xu_ly_sai_otp(phien, ip_may, dia_chi_ipv4, thiet_bi, response)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE TaiKhoan SET so_lan_sai_otp = 0 WHERE ma_tai_khoan = %s;",
                (phien["ma_tai_khoan"],),
            )
            cur.execute(
                "UPDATE PhienDangNhap SET da_xac_thuc_otp = TRUE WHERE ma_phien = %s;",
                (phien["ma_phien"],),
            )
        conn.commit()

    return {
        "status": "OK",
        "message": "Xác nhận mã OTP thành công. Vui lòng đổi mật khẩu khởi tạo để hoàn tất.",
        "con_lai_otp": 3,
    }


@app.post("/api/auth/activate-first-time")
def api_activate_first_time(req: ActivateFirstTimeRequest, request: Request, response: Response):
    """
    Kịch bản 6 (TH2 - Lưu ý sau khi hoàn thành kích hoạt):
    Khi người dùng nhập đúng 6 số OTP và đổi mật khẩu thành công:
    - Cập nhật da_kich_hoat_otp = TRUE trong TaiKhoan
    - Cập nhật da_xac_thuc_otp = TRUE và gia hạn thoi_diem_het_han = thoi_diem_tao + 8 tiếng trong PhienDangNhap.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    secret_base32 = _lay_hoac_sinh_bi_mat_otp(phien)
    # Nếu chưa xác thực OTP ở Bước 2 (hoặc gửi kèm ma_otp trực tiếp) thì kiểm tra mã OTP ngay tại đây
    if not phien["da_xac_thuc_otp"]:
        if not req.ma_otp or not xac_thuc_ma_otp(secret_base32, req.ma_otp):
            _xu_ly_sai_otp(phien, ip_may, dia_chi_ipv4, thiet_bi, response)

    if req.mat_khau_tam is not None:
        if not req.mat_khau_tam.strip():
            raise HTTPException(status_code=400, detail="Vui lòng nhập mật khẩu tạm thời.")
        if not kiem_tra_mat_khau(req.mat_khau_tam, phien["mat_khau"]):
            raise HTTPException(status_code=400, detail="Mật khẩu tạm thời không chính xác.")

    if req.mat_khau_moi != req.xac_nhan_mat_khau:
        raise HTTPException(status_code=400, detail="Mật khẩu xác nhận nhập lại không khớp với mật khẩu mới.")

    if kiem_tra_mat_khau(req.mat_khau_moi, phien["mat_khau"]):
        raise HTTPException(status_code=400, detail="Mật khẩu cá nhân mới không được trùng với mật khẩu tạm thời.")

    hop_le, thong_bao = kiem_tra_do_manh_mat_khau(req.mat_khau_moi)
    if not hop_le:
        raise HTTPException(status_code=400, detail=thong_bao)

    pin_tho = (req.ma_pin or "").strip()
    pin_xn = (req.xac_nhan_ma_pin or "").strip()
    if not pin_tho:
        raise HTTPException(
            status_code=400,
            detail="Vui lòng thiết lập mã PIN xác minh gồm 6 chữ số ở bước tiếp theo sau khi đặt mật khẩu mới.",
        )
    hop_le_pin, thong_bao_pin = kiem_tra_dinh_dang_ma_pin(pin_tho)
    if not hop_le_pin:
        raise HTTPException(status_code=400, detail=thong_bao_pin)
    if pin_tho != pin_xn:
        raise HTTPException(status_code=400, detail="Mã PIN xác nhận nhập lại không khớp với mã PIN đã đặt.")

    mat_khau_bam_moi = bam_mat_khau(req.mat_khau_moi)
    ma_pin_bam_moi = bam_ma_pin(pin_tho)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET mat_khau = %s,
                    ma_pin = %s,
                    ma_xac_nhan_pin = NULL,
                    han_xac_nhan_pin = NULL,
                    da_kich_hoat_otp = TRUE,
                    so_lan_sai_otp = 0,
                    so_lan_dang_nhap_sai = 0,
                    khoa_den_thoi_diem = NULL,
                    ip_thiet_bi_gan_nhat = %s,
                    ipv4_gan_nhat = %s
                WHERE ma_tai_khoan = %s;
                """,
                (mat_khau_bam_moi, ma_pin_bam_moi, ip_may, dia_chi_ipv4, phien["ma_tai_khoan"]),
            )
            cur.execute(
                """
                UPDATE PhienDangNhap
                SET da_xac_thuc_otp = TRUE,
                    ip_thiet_bi = %s,
                    ipv4 = %s,
                    thong_tin_thiet_bi = %s,
                    thoi_diem_het_han = thoi_diem_tao + INTERVAL '8 hours'
                WHERE ma_phien = %s;
                """,
                (ip_may, dia_chi_ipv4, thiet_bi, phien["ma_phien"]),
            )
            cur.execute(
                """
                UPDATE PhienDangNhap
                SET da_thu_hoi = TRUE
                WHERE ma_tai_khoan = %s
                  AND ma_phien <> %s
                  AND da_xac_thuc_otp = FALSE
                  AND da_thu_hoi = FALSE;
                """,
                (phien["ma_tai_khoan"], phien["ma_phien"]),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Xác thực OTP",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet="Hoàn tất kích hoạt đăng nhập lần đầu: xác thực OTP, đổi mật khẩu mới và thiết lập mã PIN 6 số.",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "next_step": "DASHBOARD",
        "da_co_ma_pin": True,
        "message": "Đăng nhập thành công!",
    }


@app.post("/api/auth/verify-otp")
def api_verify_otp(req: VerifyOtpRequest, request: Request, response: Response):
    """
    Kịch bản 7 (TH3 - Lưu ý xử lý sau đó):
    Nếu nhập ĐÚNG 6 số OTP:
    - Cập nhật da_xac_thuc_otp = TRUE và gia hạn thoi_diem_het_han = thoi_diem_tao + 8 tiếng.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    secret_base32 = _lay_hoac_sinh_bi_mat_otp(phien)
    if not xac_thuc_ma_otp(secret_base32, req.ma_otp):
        _xu_ly_sai_otp(phien, ip_may, dia_chi_ipv4, thiet_bi, response)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET so_lan_sai_otp = 0,
                    so_lan_dang_nhap_sai = 0,
                    khoa_den_thoi_diem = NULL,
                    ip_thiet_bi_gan_nhat = %s,
                    ipv4_gan_nhat = %s
                WHERE ma_tai_khoan = %s;
                """,
                (ip_may, dia_chi_ipv4, phien["ma_tai_khoan"]),
            )
            cur.execute(
                """
                UPDATE PhienDangNhap
                SET da_xac_thuc_otp = TRUE,
                    ip_thiet_bi = %s,
                    ipv4 = %s,
                    thong_tin_thiet_bi = %s,
                    thoi_diem_het_han = thoi_diem_tao + INTERVAL '8 hours'
                WHERE ma_phien = %s;
                """,
                (ip_may, dia_chi_ipv4, thiet_bi, phien["ma_phien"]),
            )
            cur.execute(
                """
                UPDATE PhienDangNhap
                SET da_thu_hoi = TRUE
                WHERE ma_tai_khoan = %s
                  AND ma_phien <> %s
                  AND da_xac_thuc_otp = FALSE
                  AND da_thu_hoi = FALSE;
                """,
                (phien["ma_tai_khoan"], phien["ma_phien"]),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Xác thực OTP",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet="Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.",
        thong_tin_thiet_bi=thiet_bi,
    )

    da_co_ma_pin = bool(phien.get("ma_pin"))
    return {
        "status": "OK",
        "next_step": "DASHBOARD" if da_co_ma_pin else "SETUP_PIN",
        "da_co_ma_pin": da_co_ma_pin,
        "message": (
            "Đăng nhập thành công!"
            if da_co_ma_pin
            else "Xác thực OTP thành công! Vui lòng thiết lập mã PIN bảo mật 6 chữ số trước khi truy cập vào hệ thống."
        ),
    }


def _bat_buoc_xac_minh_ma_pin(
    request: Request,
    phien: dict,
    ma_pin_truyen_vao: Optional[str],
    mo_ta_thao_tac: str,
    tai_lieu: str = "",
) -> None:
    """
    Bắt buộc kiểm tra mã PIN 6 chữ số trước khi cho phép cấp tài khoản, phân công chuyên môn,
    hoặc tải lên, cập nhật, tải xuống, niêm phong đề ôn tập / đề thi.
    """
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if not phien.get("ma_pin"):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "PIN_SETUP_REQUIRED",
                "message": "Tài khoản chưa thiết lập mã PIN 6 số. Vui lòng thiết lập mã PIN bảo mật trước khi thực hiện thao tác này.",
            },
        )
    pin = (
        (ma_pin_truyen_vao or "").strip()
        or (request.headers.get("X-Pin-Code") or "").strip()
        or (request.query_params.get("ma_pin") or "").strip()
    )
    if not pin:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "PIN_REQUIRED",
                "message": "Vui lòng nhập mã PIN 6 chữ số để xác minh thao tác.",
            },
        )
    hop_le_fmt, tb_fmt = kiem_tra_dinh_dang_ma_pin(pin)
    if not hop_le_fmt:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "PIN_INVALID_FORMAT",
                "message": tb_fmt,
            },
        )
    if not kiem_tra_ma_pin(pin, phien.get("ma_pin")):
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Xác minh PIN",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Cảnh báo",
            chi_tiet=f"{_mo_ta_can_bo(phien)} nhập sai mã PIN 6 số khi thực hiện thao tác: {mo_ta_thao_tac}.",
            thong_tin_thiet_bi=thiet_bi,
            tai_lieu_thao_tac=tai_lieu,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "PIN_INVALID",
                "message": "Mã PIN xác minh không chính xác. Vui lòng kiểm tra lại hoặc bấm Quên mã PIN để nhận mã đổi PIN qua email.",
            },
        )


@app.post("/api/auth/pin/setup")
def api_setup_initial_pin(req: PinSetupRequest, request: Request):
    """Thiết lập mã PIN 6 số lần đầu ở bước xác thực bên ngoài hệ thống cho tài khoản đã kích hoạt 2FA."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True, yeu_cau_da_co_pin=False)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    if phien.get("ma_pin"):
        raise HTTPException(
            status_code=400,
            detail="Tài khoản đã có mã PIN bảo mật. Nếu quên mã PIN, vui lòng chọn Quên mã PIN để nhận mã xác nhận qua email.",
        )

    pin_tho = (req.ma_pin or "").strip()
    pin_xn = (req.xac_nhan_ma_pin or "").strip()
    hop_le, thong_bao = kiem_tra_dinh_dang_ma_pin(pin_tho)
    if not hop_le:
        raise HTTPException(status_code=400, detail=thong_bao)
    if pin_tho != pin_xn:
        raise HTTPException(status_code=400, detail="Mã PIN xác nhận nhập lại không khớp.")

    pin_bam = bam_ma_pin(pin_tho)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE TaiKhoan SET ma_pin = %s, ma_xac_nhan_pin = NULL, han_xac_nhan_pin = NULL WHERE ma_tai_khoan = %s;",
                (pin_bam, phien["ma_tai_khoan"]),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Đặt mã PIN",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} thiết lập mã PIN bảo mật 6 số lần đầu thành công.",
        thong_tin_thiet_bi=thiet_bi,
    )
    return {"status": "OK", "message": "Thiết lập mã PIN bảo mật 6 số thành công!"}


@app.post("/api/auth/pin/verify")
def api_verify_pin(req: PinVerifyRequest, request: Request):
    """Kiểm tra nhanh mã PIN 6 số của phiên đăng nhập hiện tại."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _bat_buoc_xac_minh_ma_pin(request, phien, req.ma_pin, "Xác minh mã PIN bảo mật")
    return {"status": "OK", "message": "Xác minh mã PIN thành công."}


@app.post("/api/auth/pin/forgot")
def api_forgot_pin(request: Request):
    """Đã tắt chức năng người dùng tự đặt lại mã PIN qua email; bắt buộc liên hệ Quản trị viên."""
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    raise HTTPException(
        status_code=403,
        detail="Vui lòng liên hệ Quản trị viên hệ thống để được đổi hoặc đặt lại mã PIN bảo mật.",
    )


@app.post("/api/auth/pin/reset")
def api_reset_pin(req: PinResetRequest, request: Request):
    """Đã tắt chức năng người dùng tự đặt lại mã PIN qua email; bắt buộc liên hệ Quản trị viên."""
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    raise HTTPException(
        status_code=403,
        detail="Vui lòng liên hệ Quản trị viên hệ thống để được đổi hoặc đặt lại mã PIN bảo mật.",
    )


@app.post("/api/auth/heartbeat")
def api_session_heartbeat(request: Request):
    """Cập nhật thời điểm thao tác màn hình thực tế của người dùng cho bộ đếm tự động đăng xuất 5 phút."""
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False, yeu_cau_da_co_pin=False)
    return {"status": "OK", "idle_timeout_minutes": IDLE_TIMEOUT_MINUTES}


@app.post("/api/auth/logout")
def api_logout(request: Request, response: Response, reason: Optional[str] = None):
    """Đánh dấu PhienDangNhap.da_thu_hoi = TRUE và tự động ghi nhật ký khi đăng xuất."""
    raw_token = request.cookies.get(COOKIE_NAME)
    if raw_token:
        ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
        token_hash = bam_session_token(raw_token)
        phien_row = None
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT p.ma_phien, p.da_thu_hoi, t.ma_tai_khoan, t.ma_can_bo, t.ho_ten, t.vai_tro
                    FROM PhienDangNhap p
                    JOIN TaiKhoan t ON t.ma_tai_khoan = p.ma_tai_khoan
                    WHERE p.ma_phien_bam = %s
                    LIMIT 1;
                    """,
                    (token_hash,),
                )
                phien_row = cur.fetchone()
                cur.execute(
                    "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien_bam = %s;",
                    (token_hash,),
                )
            conn.commit()
        if phien_row and not phien_row["da_thu_hoi"]:
            if (reason or "").strip().lower() == "idle":
                chi_tiet_log = (
                    f"{_mo_ta_can_bo(phien_row)} đã tự động đăng xuất và kết thúc phiên làm việc "
                    f"do màn hình không có thao tác trong {IDLE_TIMEOUT_MINUTES} phút."
                )
            else:
                chi_tiet_log = f"{_mo_ta_can_bo(phien_row)} đã đăng xuất và kết thúc phiên làm việc."
            ghi_nhat_ky(
                ma_tai_khoan=phien_row["ma_tai_khoan"],
                hanh_dong="Đăng xuất",
                ip_thiet_bi=ip_may,
                ipv4=dia_chi_ipv4,
                ket_qua="Thành công",
                chi_tiet=chi_tiet_log,
                thong_tin_thiet_bi=thiet_bi,
            )
    response.delete_cookie(COOKIE_NAME)
    return {"status": "OK", "message": "Đã đăng xuất."}


# =============================================================================
# 2. API QUẢN LÝ TÀI KHOẢN TRONG CSDL (MỤC 1, 2, 7, 8) & CẤP PHÁT TÀI KHOẢN MỚI (CN_CapTaiKhoanMoi)
# =============================================================================
_COT_KIEM_TRA_TRUNG = {"ma_can_bo": "Mã cán bộ", "ten_dang_nhap": "Tên đăng nhập", "email": "Email nội bộ"}


def _da_ton_tai(cur, cot: str, gia_tri: str) -> bool:
    """Kiểm tra giá trị đã tồn tại trong bảng TaiKhoan (không phân biệt hoa/thường)."""
    if cot not in _COT_KIEM_TRA_TRUNG:
        return False
    cur.execute(f"SELECT 1 FROM TaiKhoan WHERE LOWER({cot}) = LOWER(%s) LIMIT 1;", (gia_tri,))
    return cur.fetchone() is not None


@app.get("/api/accounts/preview-formula")
def api_preview_formula(request: Request, ho_ten: str = "", vai_tro: str = "GIAO_VIEN"):
    """
    Gợi ý dữ liệu cấp tài khoản mới:
    - Mã cán bộ: Tiền tố vai trò (GV/AD/HT) + 7 chữ số ngẫu nhiên, bảo đảm KHÔNG trùng trong CSDL.
    - Tên đăng nhập: 'Tên_vai_trò.tên' (viết thường, không dấu); nếu trùng tự thêm số thứ tự (gv.minh2).
    - Email giáo viên/cán bộ: <têngiáoviên>.thpthoangvanthu@gmail.com (ví dụ: nguyenvanminh.thpthoangvanthu@gmail.com).
    - Mật khẩu khởi tạo: sinh ngẫu nhiên >= 10 ký tự (hoa, thường, số, ký tự đặc biệt).
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thực hiện thao tác quản trị tài khoản.")
    ma_vai_tro = chuan_hoa_vai_tro(vai_tro) or "GIAO_VIEN"
    ho_ten_chuan = chuan_hoa_ho_ten(ho_ten)

    with get_conn() as conn:
        with conn.cursor() as cur:
            ma_can_bo = sinh_ma_can_bo_ngau_nhien(ma_vai_tro)
            for _ in range(50):
                if not _da_ton_tai(cur, "ma_can_bo", ma_can_bo):
                    break
                ma_can_bo = sinh_ma_can_bo_ngau_nhien(ma_vai_tro)

            ten_dang_nhap = ""
            email = ""
            if ho_ten_chuan:
                goc = tao_ten_dang_nhap_tu_ho_ten(ho_ten_chuan, ma_vai_tro)
                ten_dang_nhap, stt = goc, 1
                while _da_ton_tai(cur, "ten_dang_nhap", ten_dang_nhap):
                    stt += 1
                    ten_dang_nhap = f"{goc}{stt}"

                stt_email = 1
                email = tao_email_tu_ho_ten(ho_ten_chuan, stt_email)
                while _da_ton_tai(cur, "email", email):
                    stt_email += 1
                    email = tao_email_tu_ho_ten(ho_ten_chuan, stt_email)

    return {
        "ma_can_bo": ma_can_bo,
        "ho_ten": ho_ten_chuan,
        "ten_dang_nhap": ten_dang_nhap,
        "email": email,
        "vai_tro": ma_vai_tro,
        "mat_khau_khoi_tao": sinh_mat_khau_tam(12),
    }


@app.get("/api/accounts/check-unique")
def api_check_unique(request: Request, field: str, value: str):
    """Kiểm tra trực tiếp trên CSDL xem Mã cán bộ / Tên đăng nhập / Email đã bị trùng hay chưa."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thực hiện thao tác quản trị tài khoản.")
    if field not in _COT_KIEM_TRA_TRUNG:
        raise HTTPException(status_code=400, detail="Trường kiểm tra không hợp lệ.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            trung = _da_ton_tai(cur, field, value.strip())
    return {
        "field": field,
        "exists": trung,
        "message": f"{_COT_KIEM_TRA_TRUNG[field]} '{value.strip()}' đã tồn tại trong hệ thống." if trung else "",
    }


def _kiem_tra_va_chuan_hoa_phan_quyen(
    cur,
    ma_mon_hoc: Optional[int],
    danh_sach_khoi: Optional[list[PhanQuyenKhoiItem]],
):
    """Kiểm tra hợp lệ dữ liệu phân quyền khối & môn trước khi ghi vào bảng PhanQuyenTheoKhoiMon."""
    if not ma_mon_hoc:
        return False, "Vui lòng chọn môn học được phép truy cập cho giáo viên!", None, []
    cur.execute(
        "SELECT ma_mon_hoc, ky_hieu_mon, ten_mon_hoc FROM MonHoc WHERE ma_mon_hoc = %s AND dang_su_dung = TRUE;",
        (int(ma_mon_hoc),),
    )
    mon = cur.fetchone()
    if not mon:
        return False, "Môn học được chọn không tồn tại hoặc đang ngừng sử dụng!", None, []

    if not danh_sach_khoi:
        return False, "Vui lòng chọn ít nhất một khối lớp được phép truy cập cho giáo viên!", None, []

    cur.execute("SELECT ma_khoi, ten_khoi FROM KhoiLop ORDER BY ma_khoi ASC;")
    khoi_hop_le = {int(r["ma_khoi"]): r["ten_khoi"] for r in cur.fetchall()}

    by_khoi = {}
    for item in danh_sach_khoi:
        mk = int(item.ma_khoi)
        if mk not in khoi_hop_le:
            return False, f"Khối lớp [{mk}] không hợp lệ trong hệ thống!", None, []
        by_khoi[mk] = {
            "ma_khoi": mk,
            "ten_khoi": khoi_hop_le[mk],
            "duoc_truy_cap_de_chung": bool(item.duoc_truy_cap_de_chung),
            "duoc_truy_cap_de_chinh_thuc": bool(item.duoc_truy_cap_de_chinh_thuc),
        }

    ds_chuan = [by_khoi[k] for k in sorted(by_khoi.keys())]
    return True, "", mon, ds_chuan


@app.get("/api/permissions/catalog")
def api_get_permissions_catalog(request: Request):
    """Lấy danh mục Môn học (MonHoc) và Khối lớp (KhoiLop) phục vụ biểu mẫu Phân quyền theo khối & môn."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập danh mục phân quyền quản trị.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ma_mon_hoc, ky_hieu_mon, ten_mon_hoc FROM MonHoc WHERE dang_su_dung = TRUE ORDER BY ma_mon_hoc ASC;"
            )
            mon_hoc = cur.fetchall()
            cur.execute("SELECT ma_khoi, ten_khoi FROM KhoiLop ORDER BY ma_khoi ASC;")
            khoi_lop = cur.fetchall()
    return {"mon_hoc": mon_hoc, "khoi_lop": khoi_lop}


@app.get("/api/accounts")
def api_list_accounts(request: Request):
    """Truy vấn danh sách tài khoản trực tiếp từ bảng TaiKhoan kết hợp PhanQuyenTheoKhoiMon."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập danh sách tài khoản hệ thống.")
    now_utc = datetime.now(timezone.utc)
    with get_conn() as conn:
        with conn.cursor() as cur:
            tu_dong_mo_khoa_het_han(cur)
            conn.commit()
            cur.execute(
                """
                SELECT
                    ma_tai_khoan::text AS ma_tai_khoan,
                    ma_can_bo,
                    ten_dang_nhap,
                    ho_ten,
                    email,
                    vai_tro,
                    da_kich_hoat_otp,
                    (ma_pin IS NOT NULL) AS da_co_ma_pin,
                    bi_khoa,
                    COALESCE(so_lan_dang_nhap_sai, 0) AS so_lan_dang_nhap_sai,
                    COALESCE(so_lan_sai_otp, 0) AS so_lan_sai_otp,
                    host(ip_thiet_bi_gan_nhat) AS ip_thiet_bi_gan_nhat,
                    host(ipv4_gan_nhat) AS ipv4_gan_nhat,
                    to_char(thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_diem_tao,
                    dang_hoat_dong,
                    khoa_den_thoi_diem,
                    (bi_mat_otp_ma_hoa IS NOT NULL) AS co_bi_mat_otp,
                    '\\x' || encode(substring(bi_mat_otp_ma_hoa from 1 for 14), 'hex') AS bi_mat_otp_hex,
                    EXISTS (
                        SELECT 1
                        FROM ChanDiaChiIP cip
                        WHERE cip.dang_chan = TRUE
                          AND (
                              (ipv4_gan_nhat IS NOT NULL AND cip.dia_chi_ip = ipv4_gan_nhat)
                              OR (ip_thiet_bi_gan_nhat IS NOT NULL AND cip.dia_chi_ip = ip_thiet_bi_gan_nhat)
                          )
                    ) AS ip_dang_bi_chan
                FROM TaiKhoan
                ORDER BY thoi_diem_tao ASC, ma_can_bo ASC;
                """
            )
            rows = cur.fetchall()

            cur.execute(
                """
                SELECT
                    pq.ma_phan_quyen,
                    pq.ma_tai_khoan::text AS ma_tai_khoan,
                    pq.ma_khoi,
                    kl.ten_khoi,
                    pq.ma_mon_hoc,
                    mh.ky_hieu_mon,
                    mh.ten_mon_hoc,
                    pq.duoc_truy_cap_de_chung,
                    pq.duoc_truy_cap_de_chinh_thuc,
                    pq.nguoi_cap_quyen::text AS nguoi_cap_quyen,
                    tk_cap.ho_ten AS ho_ten_nguoi_cap,
                    to_char(pq.thoi_diem_cap_quyen AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_diem_cap_quyen
                FROM PhanQuyenTheoKhoiMon pq
                JOIN MonHoc mh ON mh.ma_mon_hoc = pq.ma_mon_hoc
                JOIN KhoiLop kl ON kl.ma_khoi = pq.ma_khoi
                LEFT JOIN TaiKhoan tk_cap ON tk_cap.ma_tai_khoan = pq.nguoi_cap_quyen
                ORDER BY pq.ma_mon_hoc ASC, pq.ma_khoi ASC;
                """
            )
            pq_map: dict[str, list] = {}
            for pq_row in cur.fetchall():
                pq_map.setdefault(pq_row["ma_tai_khoan"], []).append(pq_row)

            for r in rows:
                khoa_den = r["khoa_den_thoi_diem"]
                r["dang_khoa_tam_15p"] = bool(r["bi_khoa"] and khoa_den and now_utc < khoa_den)
                r["khoa_vinh_vien"] = bool(r["bi_khoa"] and not khoa_den)
                r["khoa_den_hien_thi"] = dinh_dang_gio_vn(khoa_den)
                r["khoa_den_thoi_diem"] = khoa_den.isoformat() if khoa_den else None

                ds_pq = pq_map.get(r["ma_tai_khoan"], [])
                r["phan_quyen_khoi_mon"] = ds_pq
                r["ma_mon_hoc"] = int(ds_pq[0]["ma_mon_hoc"]) if ds_pq else None
                r["ten_mon_hoc"] = ds_pq[0]["ten_mon_hoc"] if ds_pq else ""
                r["danh_sach_khoi_ten"] = ", ".join(x["ten_khoi"] for x in ds_pq)
                r["co_quyen_de_chung"] = any(x["duoc_truy_cap_de_chung"] for x in ds_pq)
                r["co_quyen_de_chinh_thuc"] = any(x["duoc_truy_cap_de_chinh_thuc"] for x in ds_pq)
            return {"accounts": rows, "vai_tro_hop_le": VAI_TRO_HOP_LE}


@app.post("/api/accounts")
def api_create_account(req: CreateAccountRequest, request: Request):
    """
    Chức năng 'Cấp phát tài khoản cho giáo viên mới' (CN_CapTaiKhoanMoi):
    - Điều kiện: Quản trị viên đã đăng nhập phiên hợp lệ (vai_tro = 'QUAN_TRI', da_xac_thuc_otp = TRUE)
      và bắt buộc xác minh mã PIN 6 số.
    - Kiểm tra & chuẩn hóa toàn bộ trường nhập liệu trên giao diện.
    - Ghi NhatKyLog (hanh_dong = 'Tạo tài khoản') tự động cho cả thành công lẫn thất bại.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Truy cập trái phép",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Cảnh báo",
            chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} thực hiện cấp tài khoản mới do không có quyền quản trị.",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền cấp tài khoản mới.")

    ten_dn_tam = (req.ten_dang_nhap or "").strip() or (req.ho_ten or "").strip() or "tài khoản mới"
    _bat_buoc_xac_minh_ma_pin(request, phien, req.ma_pin, f"Cấp tài khoản mới ({ten_dn_tam})")

    def ghi_log_tao_tk(ket_qua: str, chi_tiet: str):
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Tạo tài khoản",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua=ket_qua,
            chi_tiet=chi_tiet,
            thong_tin_thiet_bi=thiet_bi,
        )

    def that_bai(status_code: int, thong_bao_giao_dien: str, chi_tiet_log: str):
        ghi_log_tao_tk("Thất bại", chi_tiet_log)
        raise HTTPException(status_code=status_code, detail=thong_bao_giao_dien)

    ho_ten = chuan_hoa_ho_ten(req.ho_ten)
    ma_vai_tro = chuan_hoa_vai_tro(req.vai_tro)
    ten_dang_nhap = (req.ten_dang_nhap or "").strip()
    email = (req.email or "").strip().lower()
    mat_khau_khoi_tao = (req.mat_khau_khoi_tao or "").strip() or sinh_mat_khau_tam(12)

    if not ma_vai_tro or ma_vai_tro not in ("GIAO_VIEN", "QUAN_TRI"):
        that_bai(
            400,
            "Lỗi: Vai trò hệ thống chỉ được chọn Giáo viên hoặc Quản trị viên IT. Vui lòng kiểm tra lại!",
            f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do chọn vai trò không hợp lệ.",
        )
    if not ho_ten:
        that_bai(
            400,
            "Lỗi: Vui lòng nhập Họ và tên giáo viên!",
            f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do bỏ trống họ và tên cán bộ.",
        )

    prefix_cb, _ = lay_tien_to_vai_tro(ma_vai_tro)
    ma_can_bo = (req.ma_can_bo or "").strip().upper() or sinh_ma_can_bo_ngau_nhien(ma_vai_tro)
    if not re.fullmatch(rf"{prefix_cb}\d{{7}}", ma_can_bo):
        that_bai(
            400,
            f"Lỗi: Mã cán bộ phải theo định dạng '{prefix_cb} + 7 chữ số' (VD: {prefix_cb}1004589). Vui lòng kiểm tra lại!",
            f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do mã cán bộ \"{ma_can_bo}\" không đúng định dạng quy định.",
        )

    if not re.fullmatch(r"[a-z0-9.]+", ten_dang_nhap):
        that_bai(
            400,
            "Lỗi: Tên đăng nhập phải viết thường, không dấu, không khoảng trắng, chỉ gồm chữ cái, số và dấu chấm. Vui lòng kiểm tra lại!",
            f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do tên đăng nhập \"{ten_dang_nhap}\" không đúng định dạng.",
        )

    if not kiem_tra_email_truong_hop_le(email):
        that_bai(
            400,
            "Lỗi: Email phải theo định dạng <têngiáoviên>.thpthoangvanthu@gmail.com (ví dụ: nguyenvanminh.thpthoangvanthu@gmail.com). Vui lòng kiểm tra lại!",
            f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do hộp thư \"{email}\" không đúng định dạng đuôi .thpthoangvanthu@gmail.com.",
        )

    hop_le, thong_bao = kiem_tra_mat_khau_khoi_tao(mat_khau_khoi_tao)
    if not hop_le:
        that_bai(
            400,
            f"Lỗi: {thong_bao}",
            f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do mật khẩu khởi tạo chưa đạt độ mạnh tối thiểu.",
        )

    mon_phan_quyen = None
    ds_khoi_phan_quyen = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            for cot, gia_tri in (("ma_can_bo", ma_can_bo), ("ten_dang_nhap", ten_dang_nhap), ("email", email)):
                if _da_ton_tai(cur, cot, gia_tri):
                    nhan_cot = _COT_KIEM_TRA_TRUNG[cot]
                    that_bai(
                        409,
                        f"Lỗi: {nhan_cot} [{gia_tri}] này đã tồn tại trong hệ thống. Vui lòng kiểm tra lại!",
                        f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do {nhan_cot.lower()} \"{gia_tri}\" đã tồn tại trong hệ thống.",
                    )

            ds_khoi_req = req.danh_sach_khoi
            if ds_khoi_req is None and req.danh_sach_ma_khoi is not None:
                cho_ra_de = bool(req.duoc_phep_ra_de_thi)
                ds_khoi_req = [
                    PhanQuyenKhoiItem(
                        ma_khoi=int(mk),
                        duoc_truy_cap_de_chung=True,
                        duoc_truy_cap_de_chinh_thuc=cho_ra_de,
                    )
                    for mk in req.danh_sach_ma_khoi
                ]

            if ma_vai_tro == "GIAO_VIEN" and (req.ma_mon_hoc is not None or ds_khoi_req is not None):
                ok_pq, loi_pq, mon_phan_quyen, ds_khoi_phan_quyen = _kiem_tra_va_chuan_hoa_phan_quyen(
                    cur, req.ma_mon_hoc, ds_khoi_req
                )
                if not ok_pq:
                    that_bai(
                        400,
                        f"Lỗi: {loi_pq}",
                        f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do thông tin phân công chuyên môn chưa hợp lệ ({loi_pq}).",
                    )

    secret_base32 = sinh_khoa_bi_mat_totp(16)
    encrypted_secret = ma_hoa_bi_mat_otp(secret_base32)
    hashed_pw = bam_mat_khau(mat_khau_khoi_tao)

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO TaiKhoan (
                        ma_can_bo, ten_dang_nhap, mat_khau, ho_ten, email, vai_tro,
                        bi_mat_otp_ma_hoa, da_kich_hoat_otp, bi_khoa,
                        so_lan_dang_nhap_sai, so_lan_sai_otp,
                        ip_thiet_bi_gan_nhat, ipv4_gan_nhat, dang_hoat_dong, khoa_den_thoi_diem
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE, FALSE, 0, 0, NULL, NULL, TRUE, NULL)
                    RETURNING ma_tai_khoan::text AS ma_tai_khoan, ma_can_bo, ten_dang_nhap, email, vai_tro,
                              to_char(thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_diem_tao;
                    """,
                    (
                        ma_can_bo,
                        ten_dang_nhap,
                        hashed_pw,
                        ho_ten,
                        email,
                        ma_vai_tro,
                        psycopg2.Binary(encrypted_secret),
                    ),
                )
                new_acc = cur.fetchone()

                if ma_vai_tro == "GIAO_VIEN" and mon_phan_quyen and ds_khoi_phan_quyen:
                    for item_k in ds_khoi_phan_quyen:
                        cur.execute(
                            """
                            INSERT INTO PhanQuyenTheoKhoiMon (
                                ma_tai_khoan,
                                ma_khoi,
                                ma_mon_hoc,
                                duoc_truy_cap_de_chung,
                                duoc_truy_cap_de_chinh_thuc,
                                nguoi_cap_quyen,
                                thoi_diem_cap_quyen
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                            ON CONFLICT (ma_tai_khoan, ma_khoi, ma_mon_hoc) DO UPDATE
                            SET duoc_truy_cap_de_chung = EXCLUDED.duoc_truy_cap_de_chung,
                                duoc_truy_cap_de_chinh_thuc = EXCLUDED.duoc_truy_cap_de_chinh_thuc,
                                nguoi_cap_quyen = EXCLUDED.nguoi_cap_quyen,
                                thoi_diem_cap_quyen = CURRENT_TIMESTAMP;
                            """,
                            (
                                new_acc["ma_tai_khoan"],
                                item_k["ma_khoi"],
                                int(mon_phan_quyen["ma_mon_hoc"]),
                                item_k["duoc_truy_cap_de_chung"],
                                item_k["duoc_truy_cap_de_chinh_thuc"],
                                phien["ma_tai_khoan"],
                            ),
                        )
                    new_acc["phan_quyen"] = {
                        "ma_mon_hoc": int(mon_phan_quyen["ma_mon_hoc"]),
                        "ten_mon_hoc": mon_phan_quyen["ten_mon_hoc"],
                        "danh_sach_khoi_ten": ", ".join(x["ten_khoi"] for x in ds_khoi_phan_quyen),
                        "co_quyen_de_chung": any(x["duoc_truy_cap_de_chung"] for x in ds_khoi_phan_quyen),
                        "co_quyen_de_chinh_thuc": any(x["duoc_truy_cap_de_chinh_thuc"] for x in ds_khoi_phan_quyen),
                        "chi_tiet": ds_khoi_phan_quyen,
                    }

                conn.commit()
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                that_bai(
                    409,
                    "Lỗi: Mã cán bộ, Tên đăng nhập hoặc Email này đã tồn tại trong hệ thống. Vui lòng kiểm tra lại!",
                    f"{_mo_ta_can_bo(phien)} tạo tài khoản thất bại do trùng mã cán bộ, tên đăng nhập hoặc hộp thư nội bộ.",
                )

    mo_ta_pq_log = ""
    if mon_phan_quyen and ds_khoi_phan_quyen:
        khoi_txt = ", ".join(x["ten_khoi"] for x in ds_khoi_phan_quyen)
        co_ra_de = any(x["duoc_truy_cap_de_chinh_thuc"] for x in ds_khoi_phan_quyen)
        quyen_ra_de_txt = "được phép ra đề thi" if co_ra_de else "chỉ truy cập đề ôn tập"
        mo_ta_pq_log = f", phân công môn {mon_phan_quyen['ten_mon_hoc']} ({khoi_txt} - {quyen_ra_de_txt})"

    nhan_vt = _nhan_vai_tro_tieng_viet(ma_vai_tro)
    ghi_log_tao_tk(
        "Thành công",
        f"{_mo_ta_can_bo(phien)} đã cấp tài khoản {nhan_vt} cho {ho_ten} (mã {ma_can_bo}, tài khoản {ten_dang_nhap}){mo_ta_pq_log}.",
    )

    da_gui_email, thong_tin_email = gui_mat_khau_khoi_tao(email, ho_ten, ten_dang_nhap, mat_khau_khoi_tao)
    if da_gui_email:
        return {
            "status": "OK",
            "email_sent": True,
            "message": "Cấp tài khoản mới thành công! Hệ thống đã gửi mật khẩu khởi tạo tạm thời đến email của cán bộ.",
            "account": new_acc,
        }
    return {
        "status": "OK",
        "email_sent": False,
        "message": (
            "Cấp tài khoản mới thành công! Tuy nhiên CHƯA gửi được email cho cán bộ "
            f"({thong_tin_email}) Vui lòng bàn giao trực tiếp mật khẩu tạm bên dưới."
        ),
        "account": new_acc,
        "mat_khau_khoi_tao": mat_khau_khoi_tao,
    }


@app.put("/api/accounts/{ma_tai_khoan}/permissions")
def api_update_account_permissions(ma_tai_khoan: str, req: UpdateAccountPermissionsRequest, request: Request):
    """Cập nhật cấu hình bảng PhanQuyenTheoKhoiMon cho tài khoản giáo viên (bắt buộc xác minh mã PIN 6 số)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Truy cập trái phép",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Cảnh báo",
            chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} thay đổi phân công chuyên môn do không có quyền quản trị.",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền thay đổi phân công chuyên môn.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ma_tai_khoan::text AS ma_tai_khoan, ma_can_bo, ho_ten, ten_dang_nhap, vai_tro FROM TaiKhoan WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản giáo viên.")
            if chuan_hoa_vai_tro(target["vai_tro"]) != "GIAO_VIEN":
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Phân công chuyên môn",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thất bại",
                    chi_tiet=f"{_mo_ta_can_bo(phien)} phân công chuyên môn thất bại do tài khoản {target['ho_ten']} ({target['ma_can_bo']}) không phải Giáo viên.",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=400,
                    detail="Chỉ áp dụng phân công chuyên môn cho tài khoản có vai trò Giáo viên.",
                )

            _bat_buoc_xac_minh_ma_pin(
                request,
                phien,
                req.ma_pin,
                f"Phân công chuyên môn cho {target['ho_ten']} ({target['ma_can_bo']})",
            )

            ds_khoi_req = req.danh_sach_khoi
            if ds_khoi_req is None and req.danh_sach_ma_khoi is not None:
                cho_ra_de = bool(req.duoc_phep_ra_de_thi)
                ds_khoi_req = [
                    PhanQuyenKhoiItem(
                        ma_khoi=int(mk),
                        duoc_truy_cap_de_chung=True,
                        duoc_truy_cap_de_chinh_thuc=cho_ra_de,
                    )
                    for mk in req.danh_sach_ma_khoi
                ]

            ok_pq, loi_pq, mon_phan_quyen, ds_khoi_phan_quyen = _kiem_tra_va_chuan_hoa_phan_quyen(
                cur, req.ma_mon_hoc, ds_khoi_req
            )
            if not ok_pq:
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Phân công chuyên môn",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thất bại",
                    chi_tiet=f"{_mo_ta_can_bo(phien)} cập nhật phân công cho {target['ho_ten']} ({target['ma_can_bo']}) thất bại: {loi_pq}",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(status_code=400, detail=loi_pq)

            cur.execute("DELETE FROM PhanQuyenTheoKhoiMon WHERE ma_tai_khoan = %s;", (ma_tai_khoan,))
            for item_k in ds_khoi_phan_quyen:
                cur.execute(
                    """
                    INSERT INTO PhanQuyenTheoKhoiMon (
                        ma_tai_khoan,
                        ma_khoi,
                        ma_mon_hoc,
                        duoc_truy_cap_de_chung,
                        duoc_truy_cap_de_chinh_thuc,
                        nguoi_cap_quyen,
                        thoi_diem_cap_quyen
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP);
                    """,
                    (
                        ma_tai_khoan,
                        item_k["ma_khoi"],
                        int(mon_phan_quyen["ma_mon_hoc"]),
                        item_k["duoc_truy_cap_de_chung"],
                        item_k["duoc_truy_cap_de_chinh_thuc"],
                        phien["ma_tai_khoan"],
                    ),
                )
        conn.commit()

    khoi_txt = ", ".join(x["ten_khoi"] for x in ds_khoi_phan_quyen)
    co_ra_de = any(x["duoc_truy_cap_de_chinh_thuc"] for x in ds_khoi_phan_quyen)
    quyen_ra_de_txt = "được phép ra đề thi" if co_ra_de else "chỉ truy cập đề ôn tập"

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Phân công chuyên môn",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"{_mo_ta_can_bo(phien)} đã phân công giáo viên {target['ho_ten']} ({target['ma_can_bo']}) "
            f"phụ trách môn {mon_phan_quyen['ten_mon_hoc']} ({khoi_txt} - {quyen_ra_de_txt})."
        ),
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": f"Đã cập nhật phân công môn {mon_phan_quyen['ten_mon_hoc']} ({khoi_txt}) cho giáo viên {target['ho_ten']}.",
    }


@app.post("/api/accounts/{ma_tai_khoan}/reset-2fa")
def api_reset_2fa(ma_tai_khoan: str, request: Request, req: Optional[AdminPinActionRequest] = None):
    """Đặt lại xác thực 2 lớp (2FA), cấp mật khẩu khởi tạo mới cho tài khoản và thu hồi các phiên làm việc cũ."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền đặt lại 2FA.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ma_can_bo, ho_ten, ten_dang_nhap, email, dang_hoat_dong FROM TaiKhoan WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản trong CSDL.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin if req else None,
        f"Đặt lại 2FA và cấp mật khẩu mới ({target['ten_dang_nhap']})",
    )

    if not target["dang_hoat_dong"]:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Đặt lại 2FA",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thất bại",
            chi_tiet=f"{_mo_ta_can_bo(phien)} đặt lại 2FA thất bại do tài khoản {target['ho_ten']} ({target['ma_can_bo']}) đang ngừng hoạt động.",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(status_code=400, detail="Tài khoản đang ở trạng thái ngừng hoạt động, không thể đặt lại 2FA.")

    new_secret = sinh_khoa_bi_mat_totp(16)
    encrypted_secret = ma_hoa_bi_mat_otp(new_secret)
    mat_khau_moi = sinh_mat_khau_tam(12)
    mat_khau_bam = bam_mat_khau(mat_khau_moi)

    with get_conn() as conn:
        with conn.cursor() as cur:
            if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET bi_mat_otp_ma_hoa = %s,
                        mat_khau = %s,
                        da_kich_hoat_otp = FALSE,
                        so_lan_dang_nhap_sai = 0,
                        so_lan_sai_otp = 0,
                        bi_khoa = FALSE,
                        khoa_den_thoi_diem = NULL
                    WHERE ma_tai_khoan = %s
                    RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                    """,
                    (psycopg2.Binary(encrypted_secret), mat_khau_bam, ma_tai_khoan),
                )
            else:
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET bi_mat_otp_ma_hoa = %s,
                        mat_khau = %s,
                        da_kich_hoat_otp = FALSE,
                        so_lan_dang_nhap_sai = 0,
                        so_lan_sai_otp = 0,
                        bi_khoa = FALSE,
                        khoa_den_thoi_diem = NULL,
                        ma_pin = NULL,
                        ma_xac_nhan_pin = NULL,
                        han_xac_nhan_pin = NULL
                    WHERE ma_tai_khoan = %s
                    RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                    """,
                    (psycopg2.Binary(encrypted_secret), mat_khau_bam, ma_tai_khoan),
                )
            updated = cur.fetchone()

            if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
                cur.execute(
                    "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s AND ma_phien != %s;",
                    (ma_tai_khoan, phien["ma_phien"]),
                )
            else:
                cur.execute(
                    "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s;",
                    (ma_tai_khoan,),
                )
        conn.commit()

    da_gui_email, thong_tin_email = gui_thong_bao_dat_lai_2fa(
        updated["email"], updated["ho_ten"], updated["ten_dang_nhap"], mat_khau_moi
    )

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Đặt lại 2FA",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"{_mo_ta_can_bo(phien)} đã đặt lại xác thực 2 lớp (2FA), cấp mật khẩu khởi tạo mới cho tài khoản "
            f"{updated['ho_ten']} ({updated['ma_can_bo']}) và thu hồi các phiên làm việc cũ."
        ),
        thong_tin_thiet_bi=thiet_bi,
    )

    ghi_chu_email = (
        f" Hệ thống đã gửi mật khẩu khởi tạo mới tới Gmail {updated['email']}."
        if da_gui_email
        else f" Lưu ý chưa gửi được Gmail ({thong_tin_email}), vui lòng bàn giao mật khẩu bên dưới."
    )
    return {
        "status": "OK",
        "email_sent": da_gui_email,
        "email_detail": thong_tin_email,
        "mat_khau_khoi_tao": mat_khau_moi,
        "message": (
            f"Đã đặt lại xác thực 2 bước (2FA) và cấp mật khẩu khởi tạo mới cho tài khoản {updated['ho_ten']} ({updated['ma_can_bo']})! "
            "Khóa bảo mật cũ đã bị hủy, các phiên làm việc đã thu hồi và cán bộ sẽ thiết lập lại mã QR, mật khẩu mới và mã PIN ở lần đăng nhập tiếp theo."
            + ghi_chu_email
        ),
    }


@app.post("/api/accounts/{ma_tai_khoan}/deactivate")
def api_deactivate_account(ma_tai_khoan: str, request: Request, req: Optional[AdminPinActionRequest] = None):
    """Tạm ngưng hoạt động tài khoản và thu hồi toàn bộ phiên đăng nhập."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền ngừng hoạt động tài khoản.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin if req else None,
        "Tạm ngưng hoạt động tài khoản",
    )

    if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Ngừng hoạt động",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thất bại",
            chi_tiet=f"Từ chối thao tác: {_mo_ta_can_bo(phien)} không được tự ngừng hoạt động tài khoản của chính mình.",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(
            status_code=400,
            detail="Lỗi bảo vệ: Hệ thống không cho phép Quản trị viên tự tạm ngưng tài khoản của chính mình!",
        )

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET dang_hoat_dong = FALSE
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                """,
                (ma_tai_khoan,),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
            cur.execute(
                "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Ngừng hoạt động",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã tạm ngưng hoạt động tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}) và thu hồi toàn bộ phiên đăng nhập.",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": (
            f"Đã tạm ngưng hoạt động tài khoản của cán bộ {updated['ho_ten']} ({updated['ma_can_bo']}) thành công! "
            "Toàn bộ phiên làm việc của tài khoản này đã được thu hồi ngay lập tức."
        ),
    }


@app.post("/api/accounts/{ma_tai_khoan}/activate")
def api_activate_account(ma_tai_khoan: str, request: Request, req: Optional[AdminPinActionRequest] = None):
    """Kích hoạt lại tài khoản đã bị vô hiệu hóa."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền kích hoạt tài khoản.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin if req else None,
        "Kích hoạt lại tài khoản",
    )

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET dang_hoat_dong = TRUE
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                """,
                (ma_tai_khoan,),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Kích hoạt tài khoản",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã kích hoạt lại trạng thái hoạt động cho tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}).",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": f"Đã kích hoạt lại tài khoản của cán bộ {updated['ho_ten']} ({updated['ma_can_bo']}) thành công!",
    }


@app.post("/api/accounts/{ma_tai_khoan}/unlock")
def api_unlock_account(ma_tai_khoan: str, req: UnlockAccountRequest, request: Request):
    """Cấp lại mật khẩu tạm thời (khi cap_lai_mat_khau_tam = TRUE) hoặc mở khóa an ninh thủ công."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền mở khóa hoặc cấp lại mật khẩu.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        "Cấp lại mật khẩu tạm thời" if req.cap_lai_mat_khau_tam else "Mở khóa an ninh tài khoản",
    )

    mat_khau_moi = sinh_mat_khau_tam(12) if req.cap_lai_mat_khau_tam else None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ma_can_bo, ho_ten, ten_dang_nhap, email, dang_hoat_dong FROM TaiKhoan WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
            if req.cap_lai_mat_khau_tam and not target["dang_hoat_dong"]:
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Cấp lại mật khẩu",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Thất bại",
                    chi_tiet=f"{_mo_ta_can_bo(phien)} cấp lại mật khẩu thất bại do tài khoản {target['ho_ten']} ({target['ma_can_bo']}) đang ngừng hoạt động.",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=400,
                    detail="Tài khoản đang ở trạng thái ngừng hoạt động, không thể cấp lại mật khẩu tạm thời.",
                )

            if mat_khau_moi:
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET bi_khoa = FALSE,
                        so_lan_dang_nhap_sai = 0,
                        so_lan_sai_otp = 0,
                        khoa_den_thoi_diem = NULL,
                        mat_khau = %s
                    WHERE ma_tai_khoan = %s
                    RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                    """,
                    (bam_mat_khau(mat_khau_moi), ma_tai_khoan),
                )
            else:
                cur.execute(
                    """
                    UPDATE TaiKhoan
                    SET bi_khoa = FALSE,
                        so_lan_dang_nhap_sai = 0,
                        so_lan_sai_otp = 0,
                        khoa_den_thoi_diem = NULL
                    WHERE ma_tai_khoan = %s
                    RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                    """,
                    (ma_tai_khoan,),
                )
            updated = cur.fetchone()
            if mat_khau_moi:
                if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
                    cur.execute(
                        "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s AND ma_phien != %s;",
                        (ma_tai_khoan, phien["ma_phien"]),
                    )
                else:
                    cur.execute(
                        "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s;",
                        (ma_tai_khoan,),
                    )
        conn.commit()

    if mat_khau_moi:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Cấp lại mật khẩu",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thành công",
            chi_tiet=(
                f"{_mo_ta_can_bo(phien)} đã cấp lại mật khẩu tạm thời cho tài khoản "
                f"{updated['ho_ten']} ({updated['ma_can_bo']}) và thu hồi các phiên làm việc cũ."
            ),
            thong_tin_thiet_bi=thiet_bi,
        )
        da_gui_email, thong_tin_email = gui_mat_khau_cap_lai(
            updated["email"], updated["ho_ten"], updated["ten_dang_nhap"], mat_khau_moi
        )
        if da_gui_email:
            thong_bao = (
                f"Cấp lại mật khẩu tạm thời thành công! Mật khẩu khởi tạo mới đã được gửi tới Gmail {updated['email']}."
            )
        else:
            thong_bao = (
                f"Cấp lại mật khẩu tạm thời thành công! Tuy nhiên chưa gửi được Gmail ({thong_tin_email}), "
                "vui lòng sao chép mật khẩu tạm bên dưới để bàn giao trực tiếp."
            )
        return {
            "status": "OK",
            "email_sent": da_gui_email,
            "email_detail": thong_tin_email,
            "message": thong_bao,
            "mat_khau_khoi_tao": mat_khau_moi,
        }

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Mở khóa tài khoản",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã mở khóa an ninh cho tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}).",
        thong_tin_thiet_bi=thiet_bi,
    )
    thong_bao = f"Đã mở khóa tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}) thành công!"
    return {"status": "OK", "message": thong_bao, "mat_khau_khoi_tao": None}


@app.post("/api/accounts/{ma_tai_khoan}/temp-lock")
def api_temp_lock_account(ma_tai_khoan: str, req: TempLockAccountRequest, request: Request):
    """Tạm khóa tài khoản giáo viên trực tiếp từ Modal Chi tiết điều tra Nhật ký hoạt động."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thực hiện thao tác quản trị này.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        "Khóa an ninh tài khoản",
    )

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Khóa tài khoản",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thất bại",
            chi_tiet=f"Từ chối thao tác: {_mo_ta_can_bo(phien)} không được tự khóa tài khoản đang đăng nhập của chính mình.",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(
            status_code=400,
            detail="Hệ thống không cho phép Quản trị viên tự khóa tài khoản đang đăng nhập của chính mình.",
        )

    so_phut = int(req.so_phut or 0)
    khoa_den = datetime.now(timezone.utc) + timedelta(minutes=so_phut) if so_phut > 0 else None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET bi_khoa = TRUE,
                    khoa_den_thoi_diem = %s
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                """,
                (khoa_den, ma_tai_khoan),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản cần tạm khóa.")
            cur.execute(
                "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
        conn.commit()

    mo_ta_thoi_han = f"{so_phut} phút (đến {dinh_dang_gio_vn(khoa_den)})" if khoa_den else "cho đến khi Quản trị viên mở khóa"
    ly_do_str = f" (lý do: {req.ly_do.strip()})" if (req.ly_do and req.ly_do.strip()) else ""
    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Khóa tài khoản",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"{_mo_ta_can_bo(phien)} đã tạm khóa tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}) "
            f"trong {mo_ta_thoi_han} và thu hồi toàn bộ phiên làm việc{ly_do_str}."
        ),
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "bi_khoa": True,
        "khoa_den_hien_thi": dinh_dang_gio_vn(khoa_den) if khoa_den else "",
        "message": (
            f"Đã tạm khóa tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}) {mo_ta_thoi_han}. "
            "Toàn bộ phiên đăng nhập của tài khoản này đã bị thu hồi."
        ),
    }


@app.post("/api/accounts/{ma_tai_khoan}/clear-trusted-ip")
def api_clear_trusted_ip(ma_tai_khoan: str, request: Request, req: Optional[AdminPinActionRequest] = None):
    """Xóa thiết bị và địa chỉ IP tin cậy gần nhất của tài khoản và ghi nhận nhật ký."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền thực hiện thao tác này.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin if req else None,
        "Xóa thiết bị và địa chỉ IP tin cậy",
    )

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET ip_thiet_bi_gan_nhat = NULL,
                    ipv4_gan_nhat = NULL,
                    so_lan_sai_otp = 0
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap;
                """,
                (ma_tai_khoan,),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Quên thiết bị",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã xóa thiết bị và địa chỉ mạng tin cậy của tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}).",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": (
            f"Đã xóa thiết bị tin cậy của tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}). "
            "Lần đăng nhập tiếp theo sẽ bắt buộc xác thực mã OTP 6 số."
        ),
    }


class AdminSetPinRequest(BaseModel):
    ma_pin_moi: str
    xac_nhan_ma_pin_moi: str
    ma_pin: Optional[str] = None


@app.post("/api/accounts/{ma_tai_khoan}/admin-set-pin")
def api_admin_set_teacher_pin(ma_tai_khoan: str, req: AdminSetPinRequest, request: Request):
    """Quản trị viên trực tiếp đổi / đặt mới mã PIN bảo mật 6 số cho giáo viên (hoặc tài khoản cán bộ)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền quản lý mã PIN của giáo viên.")

    pin_moi = (req.ma_pin_moi or "").strip()
    pin_xn = (req.xac_nhan_ma_pin_moi or "").strip()
    hop_le, thong_bao = kiem_tra_dinh_dang_ma_pin(pin_moi)
    if not hop_le:
        raise HTTPException(status_code=400, detail=thong_bao)
    if pin_moi != pin_xn:
        raise HTTPException(status_code=400, detail="Mã PIN mới nhập lại không khớp.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        "Đổi / Cấp mã PIN bảo mật 6 số",
    )

    pin_bam = bam_ma_pin(pin_moi)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET ma_pin = %s,
                    ma_xac_nhan_pin = NULL,
                    han_xac_nhan_pin = NULL
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap, vai_tro;
                """,
                (pin_bam, ma_tai_khoan),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản cần cập nhật mã PIN.")
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Quản lý mã PIN",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã cập nhật mã PIN bảo mật 6 số mới cho tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}).",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "da_co_ma_pin": True,
        "message": f"Đã cập nhật mã PIN bảo mật 6 chữ số mới cho {updated['ho_ten']} ({updated['ma_can_bo']}) thành công!",
    }


@app.post("/api/accounts/{ma_tai_khoan}/admin-reset-pin")
def api_admin_reset_teacher_pin(ma_tai_khoan: str, request: Request, req: Optional[AdminPinActionRequest] = None):
    """
    Quản trị viên xóa mã PIN cũ của giáo viên và thu hồi phiên hiện hành để giáo viên
    tự thiết lập lại mã PIN 6 số mới tại cổng xác thực ngoài hệ thống ở lần đăng nhập kế tiếp.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền đặt lại mã PIN của giáo viên.")

    if str(phien["ma_tai_khoan"]) == str(ma_tai_khoan):
        raise HTTPException(
            status_code=400,
            detail="Không thể xóa trống mã PIN của chính tài khoản Quản trị viên đang đăng nhập. Vui lòng dùng nút 'Đổi / Cấp mã PIN' để đổi trực tiếp sang mã PIN mới.",
        )

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin if req else None,
        "Mở đặt lại mã PIN cho giáo viên",
    )

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET ma_pin = NULL,
                    ma_xac_nhan_pin = NULL,
                    han_xac_nhan_pin = NULL
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap;
                """,
                (ma_tai_khoan,),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản giáo viên.")
            cur.execute(
                "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Quản lý mã PIN",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"{_mo_ta_can_bo(phien)} đã xóa mã PIN cũ và mở quyền thiết lập lại mã PIN ngoài hệ thống "
            f"cho giáo viên {updated['ho_ten']} ({updated['ma_can_bo']}), đồng thời thu hồi các phiên làm việc đang mở."
        ),
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "da_co_ma_pin": False,
        "message": (
            f"Đã xóa mã PIN cũ của {updated['ho_ten']} ({updated['ma_can_bo']}) và thu hồi phiên đang mở. "
            "Khi đăng nhập lại, giáo viên sẽ được chuyển tới màn hình đặt mã PIN 6 số mới bên ngoài hệ thống."
        ),
    }


# =============================================================================
# 3. API NHẬT KÝ LOG TRỰC TIẾP TỪ BẢNG NhatKyLog (MỤC 1, 3, 4)
# =============================================================================
def _truy_van_danh_sach_nhat_ky(cur, ma_nhat_ky: Optional[int] = None):
    """
    Truy vấn bảng NhatKyLog kèm đối chiếu chuỗi băm liên kết (ma_bam_truoc & ma_bam_nhat_ky),
    cờ phát hiện can thiệp trực tiếp trên dòng (bi_can_thiep), thông tin giáo viên,
    bộ môn phân công, khối lớp giảng dạy, trạng thái 2FA và trạng thái chặn IP.
    """
    where_sql = "WHERE c.ma_nhat_ky = %s" if ma_nhat_ky is not None else ""
    params = (ma_nhat_ky,) if ma_nhat_ky is not None else ()
    cur.execute(
        f"""
        WITH chuoi_nhat_ky AS (
            SELECT
                n.ma_nhat_ky,
                n.ma_bam_truoc,
                n.ma_tai_khoan,
                n.hanh_dong,
                n.ip_thiet_bi,
                n.ipv4,
                n.thong_tin_thiet_bi,
                n.tai_lieu_thao_tac,
                n.ket_qua,
                COALESCE(n.ket_qua_goc, n.ket_qua) AS ket_qua_goc,
                COALESCE(n.bi_can_thiep, FALSE) AS bi_can_thiep,
                COALESCE(n.so_lan_can_thiep, 0) AS so_lan_can_thiep,
                n.thoi_diem_can_thiep,
                COALESCE(n.chi_tiet_can_thiep, '') AS chi_tiet_can_thiep,
                n.chi_tiet,
                n.thoi_diem,
                n.ma_bam_nhat_ky,
                LAG(n.ma_bam_nhat_ky, 1, repeat('0', 64)) OVER (ORDER BY n.ma_nhat_ky ASC) AS bam_truoc_ky_vong,
                fn_tinh_bam_nhat_ky_log(
                    n.ma_nhat_ky, n.ma_bam_truoc, n.ma_tai_khoan,
                    n.hanh_dong, n.ip_thiet_bi, n.ipv4, COALESCE(n.ket_qua_goc, n.ket_qua), n.chi_tiet, n.thoi_diem
                ) AS bam_nhat_ky_ky_vong
            FROM NhatKyLog n
        ),
        phan_cong_gv AS (
            SELECT
                pq.ma_tai_khoan,
                STRING_AGG(DISTINCT mh.ten_mon_hoc, ', ' ORDER BY mh.ten_mon_hoc) AS bo_mon_phan_cong,
                STRING_AGG(DISTINCT kl.ten_khoi, ', ' ORDER BY kl.ten_khoi) AS khoi_lop_giang_day
            FROM PhanQuyenTheoKhoiMon pq
            JOIN MonHoc mh ON mh.ma_mon_hoc = pq.ma_mon_hoc
            JOIN KhoiLop kl ON kl.ma_khoi = pq.ma_khoi
            GROUP BY pq.ma_tai_khoan
        )
        SELECT
            c.ma_nhat_ky,
            c.ma_tai_khoan::text AS ma_tai_khoan,
            t.ma_can_bo,
            t.ten_dang_nhap,
            t.ho_ten,
            t.vai_tro,
            t.da_kich_hoat_otp,
            t.bi_khoa,
            t.dang_hoat_dong,
            to_char(t.khoa_den_thoi_diem AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS khoa_den_hien_thi,
            c.hanh_dong,
            host(c.ip_thiet_bi) AS ip_may,
            host(c.ipv4) AS dia_chi_ipv4,
            COALESCE(c.thong_tin_thiet_bi, '') AS thiet_bi_truy_cap,
            COALESCE(c.tai_lieu_thao_tac, '') AS tai_lieu_thao_tac,
            c.ket_qua,
            c.ket_qua_goc,
            c.bi_can_thiep,
            c.so_lan_can_thiep,
            to_char(c.thoi_diem_can_thiep AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_gian_can_thiep,
            c.chi_tiet_can_thiep,
            c.chi_tiet,
            c.ma_bam_truoc,
            c.ma_bam_nhat_ky,
            to_char(c.thoi_diem AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_gian_hien_thi,
            ((NOT c.bi_can_thiep) AND c.ma_bam_truoc = c.bam_truoc_ky_vong AND c.ma_bam_nhat_ky = c.bam_nhat_ky_ky_vong) AS toan_ven_chuoi,
            CASE
                WHEN (NOT c.bi_can_thiep) AND c.ma_bam_truoc = c.bam_truoc_ky_vong AND c.ma_bam_nhat_ky = c.bam_nhat_ky_ky_vong
                THEN 'Toàn vẹn'
                ELSE 'Nhật ký bị can thiệp'
            END AS trang_thai_chuoi,
            COALESCE(
                pc.bo_mon_phan_cong,
                CASE
                    WHEN t.vai_tro = 'QUAN_TRI' THEN 'Quản trị hệ thống'
                    WHEN t.vai_tro = 'BAN_GIAM_HIEU' THEN 'Ban Giám hiệu'
                    WHEN t.ma_tai_khoan IS NOT NULL THEN 'Chưa phân công bộ môn'
                    ELSE 'Không xác định'
                END
            ) AS bo_mon_phan_cong,
            COALESCE(
                pc.khoi_lop_giang_day,
                CASE
                    WHEN t.vai_tro = 'QUAN_TRI' THEN 'Không phân công khối lớp'
                    WHEN t.vai_tro = 'BAN_GIAM_HIEU' THEN 'Khối 10, Khối 11, Khối 12'
                    WHEN t.ma_tai_khoan IS NOT NULL THEN 'Chưa phân công khối lớp'
                    ELSE 'Không xác định'
                END
            ) AS khoi_lop_giang_day,
            EXISTS (
                SELECT 1
                FROM ChanDiaChiIP cip
                WHERE cip.dang_chan = TRUE
                  AND (cip.dia_chi_ip = c.ipv4 OR cip.dia_chi_ip = c.ip_thiet_bi)
            ) AS ip_dang_bi_chan
        FROM chuoi_nhat_ky c
        LEFT JOIN TaiKhoan t ON t.ma_tai_khoan = c.ma_tai_khoan
        LEFT JOIN phan_cong_gv pc ON pc.ma_tai_khoan = c.ma_tai_khoan
        {where_sql}
        ORDER BY c.ma_nhat_ky DESC;
        """,
        params,
    )
    return cur.fetchall()


@app.get("/api/logs")
def api_get_logs(request: Request):
    """Truy vấn trực tiếp bảng NhatKyLog kèm khối thống kê chỉ số tổng quan."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập nhật ký hoạt động hệ thống.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            if tu_dong_mo_khoa_het_han(cur) > 0:
                conn.commit()
            cur.execute(
                """
                SELECT
                    COUNT(ma_nhat_ky) AS tong_su_kien,
                    COUNT(*) FILTER (WHERE ket_qua = 'Thành công') AS thanh_cong,
                    COUNT(*) FILTER (WHERE ket_qua = 'Thất bại') AS that_bai,
                    COUNT(*) FILTER (WHERE ket_qua = 'Cảnh báo') AS canh_bao,
                    COUNT(*) FILTER (WHERE ket_qua = 'Báo động') AS bao_dong,
                    COUNT(*) FILTER (WHERE COALESCE(bi_can_thiep, FALSE) = TRUE) AS so_dong_bi_can_thiep
                FROM NhatKyLog;
                """
            )
            stats = cur.fetchone()
            logs = _truy_van_danh_sach_nhat_ky(cur)
            return {"stats": stats, "logs": logs}


@app.get("/api/logs/verify-chain")
def api_verify_hash_chain(request: Request):
    """Kiểm tra tính toàn vẹn chuỗi băm SHA-256 và cờ can thiệp trực tiếp trong bảng NhatKyLog."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập kiểm định nhật ký hệ thống.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    ma_nhat_ky,
                    ma_bam_truoc,
                    ma_bam_nhat_ky,
                    COALESCE(bi_can_thiep, FALSE) AS bi_can_thiep,
                    fn_tinh_bam_nhat_ky_log(
                        ma_nhat_ky, ma_bam_truoc, ma_tai_khoan,
                        hanh_dong, ip_thiet_bi, ipv4, COALESCE(ket_qua_goc, ket_qua), chi_tiet, thoi_diem
                    ) AS ma_bam_tinh_lai
                FROM NhatKyLog
                ORDER BY ma_nhat_ky ASC;
                """
            )
            rows = cur.fetchall()

    expected_prev = "0" * 64
    broken_at = None
    tampered_ids = []
    for r in rows:
        if r["bi_can_thiep"]:
            tampered_ids.append(r["ma_nhat_ky"])
        if broken_at is None and (r["ma_bam_truoc"] != expected_prev or r["ma_bam_nhat_ky"] != r["ma_bam_tinh_lai"]):
            broken_at = r["ma_nhat_ky"]
        expected_prev = r["ma_bam_nhat_ky"]

    first_alert_id = broken_at if broken_at is not None else (tampered_ids[0] if tampered_ids else None)
    is_valid = (broken_at is None) and (len(tampered_ids) == 0)

    if is_valid:
        msg = f"Chuỗi băm niêm phong SHA-256 toàn vẹn ({len(rows)} bản ghi trong CSDL)."
    elif broken_at is not None:
        msg = f"Báo động: Phát hiện đứt gãy chuỗi băm tại bản ghi #{broken_at}!"
    else:
        ds_id = ", ".join(f"#{i}" for i in tampered_ids[:5])
        msg = f"Báo động: Phát hiện hành vi cố tình can thiệp nhật ký tại bản ghi {ds_id} (dữ liệu gốc đã được bảo vệ nguyên vẹn)!"

    return {
        "valid": is_valid,
        "total_records": len(rows),
        "broken_at_id": first_alert_id,
        "tampered_ids": tampered_ids,
        "latest_seal_hash": expected_prev if rows else ("0" * 64),
        "message": msg,
    }


@app.get("/api/logs/{ma_nhat_ky:int}")
def api_get_log_detail(ma_nhat_ky: int, request: Request):
    """Truy vấn chi tiết điều tra 1 bản ghi nhật ký và kiểm tra trực tiếp bằng chứng liên kết chuỗi."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập nhật ký hoạt động hệ thống.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            if tu_dong_mo_khoa_het_han(cur) > 0:
                conn.commit()
            rows = _truy_van_danh_sach_nhat_ky(cur, ma_nhat_ky=ma_nhat_ky)
            if not rows:
                raise HTTPException(status_code=404, detail="Không tìm thấy bản ghi nhật ký.")
            return {"log": rows[0]}


@app.post("/api/ips/block")
def api_block_ip(req: IpBlockRequest, request: Request):
    """Chặn địa chỉ IP từ Modal Chi tiết điều tra Nhật ký hoạt động và thu hồi các phiên giáo viên từ IP này."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thực hiện thao tác quản trị này.")

    raw_ip = (req.dia_chi_ip or "").strip()
    try:
        ip_hop_le = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        raise HTTPException(status_code=400, detail="Địa chỉ IP không hợp lệ.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        f"Chặn địa chỉ IP ({ip_hop_le})",
    )

    ly_do = (req.ly_do or "").strip() or "Chặn truy cập an ninh từ Nhật ký hoạt động"
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ChanDiaChiIP (dia_chi_ip, ly_do, dang_chan, nguoi_chan, thoi_diem_chan)
                VALUES (%s::inet, %s, TRUE, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (dia_chi_ip) DO UPDATE
                SET dang_chan = TRUE,
                    ly_do = EXCLUDED.ly_do,
                    nguoi_chan = EXCLUDED.nguoi_chan,
                    thoi_diem_chan = CURRENT_TIMESTAMP;
                """,
                (ip_hop_le, ly_do, phien["ma_tai_khoan"]),
            )
            cur.execute(
                """
                UPDATE PhienDangNhap p
                SET da_thu_hoi = TRUE
                FROM TaiKhoan t
                WHERE p.ma_tai_khoan = t.ma_tai_khoan
                  AND p.da_thu_hoi = FALSE
                  AND t.vai_tro != 'QUAN_TRI'
                  AND (p.ipv4 = %s::inet OR p.ip_thiet_bi = %s::inet);
                """,
                (ip_hop_le, ip_hop_le),
            )
            so_phien_thu_hoi = cur.rowcount
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Chặn IP",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã chặn địa chỉ IP {ip_hop_le} ({ly_do}) và thu hồi {so_phien_thu_hoi} phiên hoạt động.",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "dia_chi_ip": ip_hop_le,
        "ip_dang_bi_chan": True,
        "message": f"Đã chặn địa chỉ IP {ip_hop_le} và thu hồi {so_phien_thu_hoi} phiên hoạt động liên quan.",
    }


@app.post("/api/ips/unblock")
def api_unblock_ip(req: IpBlockRequest, request: Request):
    """Gỡ chặn địa chỉ IP trong bảng ChanDiaChiIP."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thực hiện thao tác quản trị này.")

    raw_ip = (req.dia_chi_ip or "").strip()
    try:
        ip_hop_le = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        raise HTTPException(status_code=400, detail="Địa chỉ IP không hợp lệ.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        f"Gỡ chặn địa chỉ IP ({ip_hop_le})",
    )

    ds_ip_go_chan = {ip_hop_le}
    for extra_ip in (req.danh_sach_ip or []):
        s_ip = str(extra_ip or "").strip()
        if not s_ip:
            continue
        try:
            ds_ip_go_chan.add(str(ipaddress.ip_address(s_ip)))
        except ValueError:
            continue

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ChanDiaChiIP
                SET dang_chan = FALSE
                WHERE host(dia_chi_ip) = ANY(%s);
                """,
                (list(ds_ip_go_chan),),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Gỡ chặn IP",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã gỡ chặn địa chỉ IP {ip_hop_le}.",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "dia_chi_ip": ip_hop_le,
        "ip_dang_bi_chan": False,
        "message": f"Đã gỡ chặn địa chỉ IP {ip_hop_le} thành công.",
    }


class GmailTestRequest(BaseModel):
    email_nhan: Optional[str] = None
    ma_pin: Optional[str] = None


class GmailConfigUpdateRequest(BaseModel):
    gmail_user: str
    gmail_app_password: str
    ma_pin: Optional[str] = None


@app.post("/api/admin/gmail-config")
def api_admin_gmail_update_config(req: GmailConfigUpdateRequest, request: Request):
    """Cập nhật GMAIL_USER và GMAIL_APP_PASSWORD vào tệp .env và kiểm tra kết nối ngay (bắt buộc mã PIN Admin)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền cập nhật cấu hình Gmail.")

    g_user = (req.gmail_user or "").strip().lower()
    g_pass_clean = "".join((req.gmail_app_password or "").split())
    if not g_user or not re.match(r"^[^@\s]+@gmail\.com$", g_user):
        raise HTTPException(status_code=400, detail="Vui lòng nhập địa chỉ GMAIL_USER hợp lệ có đuôi @gmail.com.")
    if len(g_pass_clean) != 16:
        raise HTTPException(
            status_code=400,
            detail="Mật khẩu ứng dụng Google (GMAIL_APP_PASSWORD) phải gồm đúng 16 ký tự chữ cái (không tính khoảng trắng).",
        )

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        f"Cập nhật cấu hình Gmail hệ thống ({g_user})",
    )

    cap_nhat_cau_hinh_gmail_env(g_user, req.gmail_app_password.strip())
    ok, status_msg = kiem_tra_ket_noi_smtp()

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Cấu hình Gmail",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công" if ok else "Cảnh báo",
        chi_tiet=f"{_mo_ta_can_bo(phien)} cập nhật hộp thư gửi Gmail hệ thống thành {g_user}. Kết quả kiểm tra: {status_msg}",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "connected": ok,
        "sender_email": g_user,
        "message": status_msg,
    }


@app.get("/api/admin/gmail-status")
def api_admin_gmail_status(request: Request, verify: bool = False):
    """Kiểm tra cấu hình và trạng thái kết nối Gmail SMTP từ tệp .env (dành cho Quản trị viên)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền kiểm tra cấu hình Gmail.")

    cfg = lay_cau_hinh_smtp()
    connected = None
    status_message = (
        f"Đã cấu hình hộp thư gửi {cfg['user']} ({cfg['host']}:{cfg['port']})."
        if cfg["configured"]
        else "Chưa cấu hình GMAIL_USER / GMAIL_APP_PASSWORD trong tệp .env."
    )
    if verify:
        connected, status_message = kiem_tra_ket_noi_smtp()

    return {
        "status": "OK",
        "configured": cfg["configured"],
        "sender_email": cfg["user"],
        "smtp_host": cfg["host"],
        "smtp_port": cfg["port"],
        "smtp_ssl": cfg["ssl"],
        "connected": connected,
        "message": status_message,
    }


@app.post("/api/admin/gmail-test")
def api_admin_gmail_test(req: GmailTestRequest, request: Request):
    """Gửi thư kiểm tra thực tế qua Gmail SMTP (bắt buộc xác minh mã PIN 6 số của Quản trị viên)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
        raise HTTPException(status_code=403, detail="Chỉ Quản trị viên mới có quyền gửi thư kiểm tra Gmail.")

    cfg = lay_cau_hinh_smtp()
    email_dich = (req.email_nhan or cfg["user"] or "").strip()
    if not email_dich or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_dich):
        raise HTTPException(status_code=400, detail="Vui lòng nhập địa chỉ email nhận thư kiểm tra hợp lệ.")

    _bat_buoc_xac_minh_ma_pin(
        request,
        phien,
        req.ma_pin,
        f"Gửi email kiểm tra Gmail tới {email_dich}",
    )

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    thoi_diem_vn = datetime.now(MUI_GIO_VN).strftime("%d/%m/%Y %H:%M:%S")
    da_gui, thong_diep = gui_email_kiem_tra(
        email_dich,
        f"{phien['ho_ten']} ({phien['ma_can_bo']})",
        thoi_diem_vn,
    )

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Kiểm tra Gmail",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công" if da_gui else "Cảnh báo",
        chi_tiet=f"{_mo_ta_can_bo(phien)} gửi thư kiểm tra Gmail tới {email_dich}: {thong_diep}",
        thong_tin_thiet_bi=thiet_bi,
    )

    if not da_gui:
        raise HTTPException(status_code=400, detail=thong_diep)

    return {
        "status": "OK",
        "email_sent": True,
        "sender_email": cfg["user"],
        "recipient_email": email_dich,
        "message": thong_diep,
    }


@app.get("/api/sessions")
def api_list_sessions(request: Request):
    """Truy vấn trực tiếp bảng PhienDangNhap trong PostgreSQL và tự động thu hồi các phiên hết hạn / phiên chờ OTP bị bỏ dở."""
    phien_hien_tai = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien_hien_tai["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập danh sách phiên đăng nhập hệ thống.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE PhienDangNhap p
                SET da_thu_hoi = TRUE
                WHERE p.da_thu_hoi = FALSE
                  AND (
                        p.thoi_diem_het_han <= NOW()
                     OR NOW() - COALESCE(p.thoi_diem_hoat_dong_cuoi, p.thoi_diem_tao) > make_interval(mins => %s)
                     OR (
                          p.da_xac_thuc_otp = FALSE
                          AND EXISTS (
                              SELECT 1
                              FROM PhienDangNhap p2
                              WHERE p2.ma_tai_khoan = p.ma_tai_khoan
                                AND p2.ma_phien <> p.ma_phien
                                AND p2.thoi_diem_tao >= p.thoi_diem_tao
                          )
                        )
                  );
                """,
                (IDLE_TIMEOUT_MINUTES,),
            )
            if cur.rowcount > 0:
                conn.commit()

            cur.execute(
                """
                SELECT
                    p.ma_phien::text AS ma_phien,
                    p.ma_tai_khoan::text AS ma_tai_khoan,
                    t.ma_can_bo,
                    t.ten_dang_nhap,
                    t.ho_ten,
                    p.ma_phien_bam,
                    host(p.ip_thiet_bi) AS ip_thiet_bi,
                    host(p.ipv4) AS ipv4,
                    p.thong_tin_thiet_bi,
                    p.da_xac_thuc_otp,
                    p.da_thu_hoi,
                    to_char(p.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_diem_tao,
                    to_char(p.thoi_diem_het_han AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_diem_het_han,
                    (
                        p.thoi_diem_het_han > NOW()
                        AND NOW() - COALESCE(p.thoi_diem_hoat_dong_cuoi, p.thoi_diem_tao) <= make_interval(mins => %s)
                    ) AS con_han
                FROM PhienDangNhap p
                JOIN TaiKhoan t ON t.ma_tai_khoan = p.ma_tai_khoan
                ORDER BY p.thoi_diem_tao DESC;
                """,
                (IDLE_TIMEOUT_MINUTES,),
            )
            rows = cur.fetchall()
            for r in rows:
                r["la_phien_hien_tai"] = (r["ma_phien"] == str(phien_hien_tai["ma_phien"]))
            return {"sessions": rows}


# =============================================================================
# 4. API KHO ĐỀ ÔN TẬP (CN_DeOnTap.docx) & KHO ĐỀ THI / TỆP BẪY (CN_TaiLieu.docx)
# =============================================================================
_LOAI_DE_ON_TAP_HOP_LE = ("Giữa kỳ I", "Cuối kỳ I", "Giữa kỳ II", "Cuối kỳ II")
_DUOI_TEP_HOP_LE = (".pdf", ".docx", ".xlsx", ".doc", ".xls")
_KICH_THUOC_TOI_DA = 10 * 1024 * 1024  # 10MB


def _kieu_mime_theo_ten_tep(ten_tep: str) -> str:
    ext = os.path.splitext(str(ten_tep or "").lower())[1]
    if ext == ".pdf":
        return "application/pdf"
    if ext == ".docx":
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if ext == ".xlsx":
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return "application/octet-stream"


def _format_nguoi_thao_tac_de(ho_ten: Optional[str], vai_tro: Optional[str], ten_mon_ngan: str) -> str:
    if not ho_ten:
        return "Chưa có chỉnh sửa nào"
    vt = chuan_hoa_vai_tro(vai_tro or "")
    if vt == "QUAN_TRI":
        return f"{ho_ten} (Quản trị viên)"
    if vt == "BAN_GIAM_HIEU":
        return f"{ho_ten} (Ban Giám hiệu)"
    return f"{ho_ten} (GV. {ten_mon_ngan})"


def _kiem_tra_toan_ven_tep_on_tap(duong_dan_tep: str, ma_bam_sha256: str, da_chinh_sua: bool) -> dict:
    """
    Kiểm tra tính toàn vẹn của tệp đề ôn tập đã mã hóa trên ổ đĩa:
    - Giải mã AES-256 trên RAM và tính lại SHA-256 đối chiếu với ma_bam_sha256.
    - Nếu bản ghi chưa chỉnh sửa và SHA-256 khớp => 'Toàn vẹn'.
    - Nếu bản ghi đã chỉnh sửa (da_chinh_sua = TRUE) và SHA-256 khớp bản mới => 'Đã chỉnh sửa'.
    - Nếu tệp mã hóa trên đĩa bị thay đổi trái phép ngoài hệ thống => 'Không toàn vẹn'.
    """
    base_dir = os.path.dirname(__file__)
    abs_path = os.path.join(base_dir, duong_dan_tep.replace("/", os.sep))
    file_nguyen_ven = False
    if os.path.exists(abs_path):
        try:
            with open(abs_path, "rb") as f:
                enc_data = f.read()
            raw_data = giai_ma_tep_de(enc_data)
            if raw_data is not None and tinh_sha256_bytes(raw_data) == (ma_bam_sha256 or "").strip():
                file_nguyen_ven = True
        except Exception:
            file_nguyen_ven = False

    da_sua = bool(da_chinh_sua)
    toan_ven = file_nguyen_ven and (not da_sua)
    if not file_nguyen_ven:
        trang_thai = "Không toàn vẹn"
    elif da_sua:
        trang_thai = "Đã chỉnh sửa"
    else:
        trang_thai = "Toàn vẹn"

    return {
        "file_nguyen_ven": file_nguyen_ven,
        "toan_ven_hop_le": file_nguyen_ven,
        "toan_ven": toan_ven,
        "trang_thai_file": trang_thai,
    }


@app.get("/api/de-on-tap")
def api_list_de_on_tap(
    request: Request,
    search: str = "",
    ma_khoi: Optional[int] = None,
    loai_de: str = "",
):
    """
    Lấy danh sách đề ôn tập theo đúng môn học mà giáo viên đó dạy (PhanQuyenTheoKhoiMon).
    Yêu cầu bắt buộc: Giáo viên dạy môn nào khi truy cập vào hệ thống chỉ hiện đúng môn đó,
    các môn khác không được hiển thị. Quản trị viên không có quyền truy cập Kho đề ôn tập.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề ôn tập")
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            if not pq["duoc_truy_cap_de_chung"]:
                raise HTTPException(status_code=403, detail="Tài khoản của bạn chưa được cấp quyền truy cập Kho đề ôn tập.")

            ma_mon = pq["ma_mon_hoc"]
            ds_khoi = pq["danh_sach_khoi"]

            conditions = ["d.ma_mon_hoc = %s", "d.ma_khoi = ANY(%s)"]
            params = [ma_mon, ds_khoi]

            if ma_khoi and int(ma_khoi) in ds_khoi:
                conditions.append("d.ma_khoi = %s")
                params.append(int(ma_khoi))
            if loai_de and loai_de.strip():
                conditions.append("d.loai_de = %s")
                params.append(loai_de.strip())
            if search and search.strip():
                conditions.append("LOWER(d.ten_de_on_tap) LIKE LOWER(%s)")
                params.append(f"%{search.strip()}%")

            where_sql = " AND ".join(conditions)
            cur.execute(
                f"""
                SELECT
                    d.ma_de_on_tap::text AS ma_de_on_tap,
                    d.ten_de_on_tap,
                    d.ma_mon_hoc,
                    mh.ten_mon_hoc,
                    mh.ky_hieu_mon,
                    d.ma_khoi,
                    kl.ten_khoi,
                    d.loai_de,
                    d.nguoi_tao::text AS nguoi_tao,
                    tk_tao.ho_ten AS ho_ten_nguoi_tao,
                    tk_tao.ma_can_bo AS ma_cb_nguoi_tao,
                    tk_tao.vai_tro AS vai_tro_nguoi_tao,
                    d.nguoi_cap_nhat::text AS nguoi_cap_nhat,
                    tk_sua.ho_ten AS ho_ten_nguoi_cap_nhat,
                    tk_sua.ma_can_bo AS ma_cb_nguoi_cap_nhat,
                    tk_sua.vai_tro AS vai_tro_nguoi_cap_nhat,
                    d.duong_dan_tep,
                    d.ten_tep_goc,
                    d.ma_bam_sha256,
                    COALESCE(d.da_chinh_sua, FALSE) AS da_chinh_sua,
                    to_char(d.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_gian_tai_len,
                    to_char(d.thoi_diem_cap_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS cap_nhat_lan_cuoi
                FROM DeOnTap d
                JOIN MonHoc mh ON mh.ma_mon_hoc = d.ma_mon_hoc
                JOIN KhoiLop kl ON kl.ma_khoi = d.ma_khoi
                JOIN TaiKhoan tk_tao ON tk_tao.ma_tai_khoan = d.nguoi_tao
                LEFT JOIN TaiKhoan tk_sua ON tk_sua.ma_tai_khoan = d.nguoi_cap_nhat
                WHERE {where_sql}
                ORDER BY COALESCE(d.thoi_diem_cap_nhat, d.thoi_diem_tao) DESC, d.thoi_diem_tao DESC;
                """,
                tuple(params),
            )
            rows = cur.fetchall()
            for r in rows:
                ten_ngan = _TEN_MON_NGAN.get(r["ky_hieu_mon"], r["ten_mon_hoc"])
                r["ten_mon_ngan"] = ten_ngan
                r["nguoi_tai_len_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_tao"], r.get("vai_tro_nguoi_tao"), ten_ngan
                )
                if (
                    r["da_chinh_sua"]
                    and r.get("ho_ten_nguoi_cap_nhat")
                    and str(r.get("nguoi_cap_nhat") or "") == str(r["nguoi_tao"])
                ):
                    r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                        r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                    )
                    r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
                else:
                    r["da_chinh_sua"] = False
                    r["nguoi_cap_nhat"] = None
                    r["ho_ten_nguoi_cap_nhat"] = None
                    r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                    r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
                r["la_nguoi_tao"] = str(r["nguoi_tao"]) == str(phien["ma_tai_khoan"])
                r["duoc_phep_chinh_sua"] = r["la_nguoi_tao"]
                tt = _kiem_tra_toan_ven_tep_on_tap(r["duong_dan_tep"], r["ma_bam_sha256"], r["da_chinh_sua"])
                r.update(tt)

            return {
                "phan_quyen_mon": pq,
                "items": rows,
                "total": len(rows),
            }


@app.get("/api/de-on-tap/{ma_de_on_tap}")
def api_get_de_on_tap_detail(ma_de_on_tap: str, request: Request):
    """Xem chi tiết một đề ôn tập (kiểm tra đúng môn học của giáo viên và kiểm tra tính toàn vẹn SHA-256)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề ôn tập")
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                """
                SELECT
                    d.ma_de_on_tap::text AS ma_de_on_tap,
                    d.ten_de_on_tap,
                    d.ma_mon_hoc,
                    mh.ten_mon_hoc,
                    mh.ky_hieu_mon,
                    d.ma_khoi,
                    kl.ten_khoi,
                    d.loai_de,
                    d.nguoi_tao::text AS nguoi_tao,
                    tk_tao.ho_ten AS ho_ten_nguoi_tao,
                    tk_tao.vai_tro AS vai_tro_nguoi_tao,
                    d.nguoi_cap_nhat::text AS nguoi_cap_nhat,
                    tk_sua.ho_ten AS ho_ten_nguoi_cap_nhat,
                    tk_sua.vai_tro AS vai_tro_nguoi_cap_nhat,
                    d.duong_dan_tep,
                    d.ten_tep_goc,
                    d.ma_bam_sha256,
                    COALESCE(d.da_chinh_sua, FALSE) AS da_chinh_sua,
                    to_char(d.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_gian_tai_len,
                    to_char(d.thoi_diem_cap_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS cap_nhat_lan_cuoi
                FROM DeOnTap d
                JOIN MonHoc mh ON mh.ma_mon_hoc = d.ma_mon_hoc
                JOIN KhoiLop kl ON kl.ma_khoi = d.ma_khoi
                JOIN TaiKhoan tk_tao ON tk_tao.ma_tai_khoan = d.nguoi_tao
                LEFT JOIN TaiKhoan tk_sua ON tk_sua.ma_tai_khoan = d.nguoi_cap_nhat
                WHERE d.ma_de_on_tap = %s;
                """,
                (ma_de_on_tap,),
            )
            r = cur.fetchone()
            if not r:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề ôn tập.")
            if not pq["duoc_truy_cap_de_chung"]:
                raise HTTPException(status_code=403, detail="Tài khoản của bạn chưa được cấp quyền truy cập Kho đề ôn tập.")
            if int(r["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép truy cập đề ôn tập thuộc môn học mình giảng dạy.")
            if int(r["ma_khoi"]) not in pq["danh_sach_khoi"]:
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép truy cập đề ôn tập thuộc khối lớp được phân quyền.")

            ten_ngan = _TEN_MON_NGAN.get(r["ky_hieu_mon"], r["ten_mon_hoc"])
            r["ten_mon_ngan"] = ten_ngan
            r["nguoi_tai_len_hien_thi"] = _format_nguoi_thao_tac_de(
                r["ho_ten_nguoi_tao"], r.get("vai_tro_nguoi_tao"), ten_ngan
            )
            if (
                r["da_chinh_sua"]
                and r.get("ho_ten_nguoi_cap_nhat")
                and str(r.get("nguoi_cap_nhat") or "") == str(r["nguoi_tao"])
            ):
                r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                )
                r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
            else:
                r["da_chinh_sua"] = False
                r["nguoi_cap_nhat"] = None
                r["ho_ten_nguoi_cap_nhat"] = None
                r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
            r["la_nguoi_tao"] = str(r["nguoi_tao"]) == str(phien["ma_tai_khoan"])
            r["duoc_phep_chinh_sua"] = r["la_nguoi_tao"]
            r.update(_kiem_tra_toan_ven_tep_on_tap(r["duong_dan_tep"], r["ma_bam_sha256"], r["da_chinh_sua"]))
            return {"item": r}


@app.post("/api/de-on-tap")
async def api_create_de_on_tap(
    request: Request,
    ten_de_on_tap: str = Form(...),
    ma_khoi: int = Form(...),
    loai_de: str = Form(...),
    ma_pin: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    """Thêm đề ôn tập mới với xác minh mã PIN 6 số, kiểm chứng SHA-256 và mã hóa AES-256."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề ôn tập")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    ten_de = (ten_de_on_tap or "").strip()
    loai = (loai_de or "").strip()
    if not ten_de:
        raise HTTPException(status_code=400, detail="Vui lòng nhập tên đề ôn tập.")
    if loai not in _LOAI_DE_ON_TAP_HOP_LE:
        raise HTTPException(status_code=400, detail="Loại đề không hợp lệ (chỉ chọn Giữa kỳ I, Cuối kỳ I, Giữa kỳ II, Cuối kỳ II).")

    ten_tep_goc = os.path.basename(file.filename or "De_On_Tap.pdf")
    ext = os.path.splitext(ten_tep_goc.lower())[1]
    if ext not in _DUOI_TEP_HOP_LE:
        raise HTTPException(status_code=400, detail="Định dạng tệp không hỗ trợ. Vui lòng chọn tệp PDF, DOCX hoặc XLSX.")

    _bat_buoc_xac_minh_ma_pin(request, phien, ma_pin, f"Thêm đề ôn tập \"{ten_de}\"", ten_tep_goc)

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Tệp tải lên đang rỗng.")
    if len(raw_bytes) > _KICH_THUOC_TOI_DA:
        raise HTTPException(status_code=400, detail="Kích thước tệp vượt quá giới hạn 10MB.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            if not pq["duoc_truy_cap_de_chung"] or int(ma_khoi) not in pq["danh_sach_khoi"]:
                raise HTTPException(status_code=403, detail=f"Bạn không có quyền thêm đề ôn tập cho Khối {ma_khoi}.")

            ma_de = str(uuid.uuid4())
            sha256_hex = tinh_sha256_bytes(raw_bytes)
            enc_bytes = ma_hoa_tep_de(raw_bytes)

            base_dir = os.path.dirname(__file__)
            dir_on_tap = os.path.join(base_dir, "storage", "de_on_tap")
            os.makedirs(dir_on_tap, exist_ok=True)
            rel_path = f"storage/de_on_tap/{ma_de}.enc"
            abs_path = os.path.join(dir_on_tap, f"{ma_de}.enc")
            with open(abs_path, "wb") as f:
                f.write(enc_bytes)

            cur.execute(
                """
                INSERT INTO DeOnTap (
                    ma_de_on_tap, ten_de_on_tap, ma_mon_hoc, ma_khoi, loai_de,
                    nguoi_tao, duong_dan_tep, ten_tep_goc, ma_bam_sha256, da_chinh_sua,
                    thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, CURRENT_TIMESTAMP, NULL, NULL)
                RETURNING ma_de_on_tap::text AS ma_de_on_tap;
                """,
                (
                    ma_de,
                    ten_de,
                    pq["ma_mon_hoc"],
                    int(ma_khoi),
                    loai,
                    phien["ma_tai_khoan"],
                    rel_path,
                    ten_tep_goc,
                    sha256_hex,
                ),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Thêm đề ôn tập",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã tải lên đề ôn tập \"{ten_de}\" (Khối {ma_khoi} - {loai}).",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_goc,
    )

    return {
        "status": "OK",
        "message": f"Đã lưu đề ôn tập '{ten_de}' thành công!",
        "ma_de_on_tap": ma_de,
    }


@app.put("/api/de-on-tap/{ma_de_on_tap}")
async def api_update_de_on_tap(
    ma_de_on_tap: str,
    request: Request,
    ten_de_on_tap: str = Form(...),
    ma_khoi: int = Form(...),
    loai_de: str = Form(...),
    ma_pin: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """Cập nhật đề ôn tập do chính giáo viên tạo với xác minh mã PIN 6 số."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề ôn tập")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    ten_de = (ten_de_on_tap or "").strip()
    loai = (loai_de or "").strip()
    if not ten_de:
        raise HTTPException(status_code=400, detail="Vui lòng nhập tên đề ôn tập.")
    if loai not in _LOAI_DE_ON_TAP_HOP_LE:
        raise HTTPException(status_code=400, detail="Loại đề không hợp lệ.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                "SELECT ma_de_on_tap, ten_de_on_tap, ma_mon_hoc, nguoi_tao::text AS nguoi_tao, duong_dan_tep, ten_tep_goc, ma_bam_sha256 FROM DeOnTap WHERE ma_de_on_tap = %s;",
                (ma_de_on_tap,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề ôn tập cần cập nhật.")
            if str(existing["nguoi_tao"]) != str(phien["ma_tai_khoan"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} chỉnh sửa đề ôn tập \"{existing['ten_de_on_tap']}\" do không phải giáo viên tạo đề.",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail="Đề của giáo viên nào tạo thì chỉ chính giáo viên đó mới được phép chỉnh sửa.",
                )
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"] or not pq["duoc_truy_cap_de_chung"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền cập nhật đề ôn tập của môn học khác.")
            if int(ma_khoi) not in pq["danh_sach_khoi"]:
                raise HTTPException(status_code=403, detail=f"Bạn không có quyền cập nhật đề cho Khối {ma_khoi}.")

            _bat_buoc_xac_minh_ma_pin(request, phien, ma_pin, f"Sửa đề ôn tập \"{ten_de}\"", existing["ten_tep_goc"])

            ten_tep_moi = existing["ten_tep_goc"]
            sha256_moi = existing["ma_bam_sha256"]
            rel_path = existing["duong_dan_tep"]

            if file and file.filename:
                raw_bytes = await file.read()
                if not raw_bytes:
                    raise HTTPException(status_code=400, detail="Tệp tải lên mới đang rỗng.")
                if len(raw_bytes) > _KICH_THUOC_TOI_DA:
                    raise HTTPException(status_code=400, detail="Kích thước tệp vượt quá giới hạn 10MB.")
                ten_tep_moi = os.path.basename(file.filename)
                ext = os.path.splitext(ten_tep_moi.lower())[1]
                if ext not in _DUOI_TEP_HOP_LE:
                    raise HTTPException(status_code=400, detail="Định dạng tệp không hỗ trợ (chỉ nhận PDF, DOCX, XLSX).")

                sha256_moi = tinh_sha256_bytes(raw_bytes)
                enc_bytes = ma_hoa_tep_de(raw_bytes)
                base_dir = os.path.dirname(__file__)
                abs_path = os.path.join(base_dir, rel_path.replace("/", os.sep))
                os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                with open(abs_path, "wb") as f:
                    f.write(enc_bytes)

            cur.execute(
                """
                UPDATE DeOnTap
                SET ten_de_on_tap = %s,
                    ma_khoi = %s,
                    loai_de = %s,
                    ten_tep_goc = %s,
                    ma_bam_sha256 = %s,
                    da_chinh_sua = TRUE,
                    nguoi_cap_nhat = %s,
                    thoi_diem_cap_nhat = CURRENT_TIMESTAMP
                WHERE ma_de_on_tap = %s;
                """,
                (
                    ten_de,
                    int(ma_khoi),
                    loai,
                    ten_tep_moi,
                    sha256_moi,
                    phien["ma_tai_khoan"],
                    ma_de_on_tap,
                ),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Sửa đề ôn tập",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã cập nhật đề ôn tập \"{ten_de}\" (Khối {ma_khoi} - {loai}).",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_moi,
    )

    return {
        "status": "OK",
        "message": f"Đã cập nhật đề ôn tập '{ten_de}' thành công! Trạng thái file đã chuyển sang 'Đã chỉnh sửa'.",
    }


@app.delete("/api/de-on-tap/{ma_de_on_tap}")
def api_delete_de_on_tap(ma_de_on_tap: str, request: Request):
    """Xóa đề ôn tập trong phạm vi môn học của giáo viên."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề ôn tập")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                "SELECT ten_de_on_tap, ma_mon_hoc, nguoi_tao::text AS nguoi_tao, duong_dan_tep, ten_tep_goc FROM DeOnTap WHERE ma_de_on_tap = %s;",
                (ma_de_on_tap,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề ôn tập.")
            if str(existing["nguoi_tao"]) != str(phien["ma_tai_khoan"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} xóa đề ôn tập \"{existing['ten_de_on_tap']}\" do không phải giáo viên tạo đề.",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail="Đề của giáo viên nào tạo thì chỉ chính giáo viên đó mới được phép xóa.",
                )
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền xóa đề ôn tập của môn khác.")
            _bat_buoc_xac_minh_ma_pin(
                request,
                phien,
                None,
                f"Xóa đề ôn tập \"{existing['ten_de_on_tap']}\"",
                existing["ten_tep_goc"],
            )
            cur.execute("DELETE FROM DeOnTap WHERE ma_de_on_tap = %s;", (ma_de_on_tap,))
        conn.commit()

    base_dir = os.path.dirname(__file__)
    abs_path = os.path.join(base_dir, existing["duong_dan_tep"].replace("/", os.sep))
    if os.path.exists(abs_path):
        try:
            os.remove(abs_path)
        except Exception:
            pass

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Xóa đề ôn tập",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã xóa đề ôn tập \"{existing['ten_de_on_tap']}\".",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=existing["ten_tep_goc"],
    )
    return {"status": "OK", "message": f"Đã xóa đề ôn tập '{existing['ten_de_on_tap']}'."}


@app.get("/api/de-on-tap/{ma_de_on_tap}/file")
def api_download_de_on_tap_file(ma_de_on_tap: str, request: Request, mode: str = "attachment"):
    """Giải mã AES-256 trên RAM và phục vụ Xem trước (inline) hoặc Tải xuống (attachment) tệp đề ôn tập."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề ôn tập")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                "SELECT ten_de_on_tap, ma_mon_hoc, ma_khoi, duong_dan_tep, ten_tep_goc, ma_bam_sha256 FROM DeOnTap WHERE ma_de_on_tap = %s;",
                (ma_de_on_tap,),
            )
            r = cur.fetchone()
            if not r:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề ôn tập.")
            if not pq["duoc_truy_cap_de_chung"]:
                raise HTTPException(status_code=403, detail="Tài khoản của bạn chưa được cấp quyền truy cập Kho đề ôn tập.")
            if int(r["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn chỉ được xem/tải đề ôn tập của môn mình dạy.")
            if int(r["ma_khoi"]) not in pq["danh_sach_khoi"]:
                raise HTTPException(status_code=403, detail="Bạn chỉ được xem/tải đề ôn tập thuộc khối lớp được phân quyền.")

    if mode != "inline":
        _bat_buoc_xac_minh_ma_pin(
            request,
            phien,
            None,
            f"Tải đề ôn tập \"{r['ten_de_on_tap']}\"",
            r["ten_tep_goc"],
        )

    base_dir = os.path.dirname(__file__)
    abs_path = os.path.join(base_dir, r["duong_dan_tep"].replace("/", os.sep))
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail="Tệp đề mã hóa không tồn tại trên máy chủ.")

    with open(abs_path, "rb") as f:
        enc_bytes = f.read()
    raw_bytes = giai_ma_tep_de(enc_bytes)
    if raw_bytes is None or tinh_sha256_bytes(raw_bytes) != (r["ma_bam_sha256"] or "").strip():
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Can thiệp tệp đề",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Báo động",
            chi_tiet=f"Báo động an ninh: Phát hiện tệp đề ôn tập \"{r['ten_de_on_tap']}\" bị thay đổi trái phép trên máy chủ.",
            thong_tin_thiet_bi=thiet_bi,
            tai_lieu_thao_tac=r["ten_tep_goc"],
        )
        raise HTTPException(status_code=500, detail="Cảnh báo an ninh: Giải mã tệp đề thất bại (tệp có dấu hiệu bị can thiệp).")

    if mode == "inline":
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Xem đề ôn tập",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thành công",
            chi_tiet=f"{_mo_ta_can_bo(phien)} đã xem trực tuyến đề ôn tập \"{r['ten_de_on_tap']}\".",
            thong_tin_thiet_bi=thiet_bi,
            tai_lieu_thao_tac=r["ten_tep_goc"],
        )
    else:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Tải đề ôn tập",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thành công",
            chi_tiet=f"{_mo_ta_can_bo(phien)} đã tải xuống đề ôn tập \"{r['ten_de_on_tap']}\".",
            thong_tin_thiet_bi=thiet_bi,
            tai_lieu_thao_tac=r["ten_tep_goc"],
        )

    disp_type = "inline" if mode == "inline" else "attachment"
    safe_name = quote(r["ten_tep_goc"])
    return Response(
        content=raw_bytes,
        media_type=_kieu_mime_theo_ten_tep(r["ten_tep_goc"]),
        headers={"Content-Disposition": f"{disp_type}; filename*=UTF-8''{safe_name}"},
    )


# -----------------------------------------------------------------------------
# API KHO ĐỀ THI, LỊCH THI & TỆP BẪY MỒI NHỬ (CN_DeThi.docx & CN_TaiLieu.docx)
# -----------------------------------------------------------------------------
def _parse_gio_thi_vn(s: str) -> datetime:
    """Chuyển chuỗi thời gian thi (DD/MM/YYYY HH:MM hoặc YYYY-MM-DDTHH:MM) sang datetime có múi giờ +07:00."""
    val = (s or "").strip()
    tz_vn = timezone(timedelta(hours=7))
    for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(val, fmt)
            return dt.replace(tzinfo=tz_vn)
        except ValueError:
            continue
    raise HTTPException(
        status_code=400,
        detail=f"Định dạng thời gian thi '{val}' không hợp lệ. Vui lòng nhập theo dạng DD/MM/YYYY HH:MM (ví dụ: 15/11/2026 07:30).",
    )


def _kiem_tra_toan_ven_tep_de_thi(
    duong_dan_tep: str,
    ma_bam_sha256: str,
    da_chinh_sua: bool,
    khoa_ma_hoa_de=None,
    ma_nonce_aes=None,
    the_xac_thuc_aes=None,
) -> dict:
    """Kiểm tra tính toàn vẹn SHA-256 của tệp đề thi và trạng thái chỉnh sửa."""
    base_dir = os.path.dirname(__file__)
    abs_path = os.path.join(base_dir, (duong_dan_tep or "").replace("/", os.sep))
    file_nguyen_ven = False
    if os.path.exists(abs_path):
        try:
            with open(abs_path, "rb") as f:
                enc_data = f.read()
            raw_data = None
            if khoa_ma_hoa_de and ma_nonce_aes and the_xac_thuc_aes:
                raw_data = giai_ma_tep_de_thi_envelope(enc_data, khoa_ma_hoa_de, ma_nonce_aes, the_xac_thuc_aes)
            if raw_data is None:
                raw_data = giai_ma_tep_de(enc_data)
            if raw_data is not None and tinh_sha256_bytes(raw_data) == (ma_bam_sha256 or "").strip():
                file_nguyen_ven = True
        except Exception:
            file_nguyen_ven = False

    da_sua = bool(da_chinh_sua)
    toan_ven = file_nguyen_ven and (not da_sua)
    if not file_nguyen_ven:
        trang_thai = "Không toàn vẹn"
    elif da_sua:
        trang_thai = "Đã chỉnh sửa"
    else:
        trang_thai = "Toàn vẹn"

    return {
        "file_nguyen_ven": file_nguyen_ven,
        "toan_ven_hop_le": file_nguyen_ven,
        "toan_ven": toan_ven,
        "trang_thai_file": trang_thai,
    }


def _chuan_hoa_loai_tai_lieu_de_thi(loai: Optional[str]) -> str:
    """Chuẩn hóa cột DeThi.loai: chỉ nhận 1 trong 2 giá trị 'Đề thi' hoặc 'Đáp án'."""
    val = (loai or "Đề thi").strip()
    if val in ("Đáp án", "DAP_AN", "dap_an", "Đáp án đề thi"):
        return "Đáp án"
    if val in ("Đề thi", "DE_THI", "de_thi"):
        return "Đề thi"
    raise HTTPException(
        status_code=400,
        detail="Phân loại tài liệu không hợp lệ. Chỉ chấp nhận 'Đề thi' hoặc 'Đáp án'.",
    )


def _tinh_trang_thai_niem_phong_de_thi(
    da_nem_phong: bool,
    loai: Optional[str],
    gio_bat_dau_dt: Optional[datetime],
    gio_ket_thuc_dt: Optional[datetime],
    now_utc: Optional[datetime] = None,
) -> dict:
    """
    Tính toán trạng thái niêm phong bất khả xâm phạm của bảng DeThi:
    - Tự động khóa trước thời gian bắt đầu thi 24h (NOW >= gio_bat_dau - 24h) HOẶC khi giáo viên bấm nút Niêm phong ngay lập tức (da_nem_phong = TRUE).
    - Tự động mở:
        + 'Đề thi' mở khi đến giờ bắt đầu thi (NOW >= gio_bat_dau).
        + 'Đáp án' mở khi kết thúc giờ thi (NOW >= gio_ket_thuc).
    - Trong thời gian niêm phong (dang_niem_phong = TRUE): kể cả Quản trị viên hay người tạo đề đều không có quyền xem, tải, sửa hoặc xóa.
    """
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)

    loai_chuan = "Đáp án" if str(loai or "").strip() == "Đáp án" else "Đề thi"
    thoi_diem_mo = gio_ket_thuc_dt if loai_chuan == "Đáp án" else gio_bat_dau_dt
    moc_khoa_24h = (gio_bat_dau_dt - timedelta(hours=24)) if gio_bat_dau_dt else None

    tu_dong_khoa_24h = bool(moc_khoa_24h is not None and now_utc >= moc_khoa_24h)
    da_kich_hoat_khoa = bool(da_nem_phong) or tu_dong_khoa_24h
    da_mo = bool(thoi_diem_mo is not None and now_utc >= thoi_diem_mo)

    dang_niem_phong = bool(da_kich_hoat_khoa and not da_mo)
    chua_niem_phong = bool((not da_kich_hoat_khoa) and (not da_mo))

    thoi_diem_mo_txt = (
        thoi_diem_mo.astimezone(MUI_GIO_VN).strftime("%d/%m/%Y %H:%M") if thoi_diem_mo else ""
    )
    moc_khoa_24h_txt = (
        moc_khoa_24h.astimezone(MUI_GIO_VN).strftime("%d/%m/%Y %H:%M") if moc_khoa_24h else ""
    )

    if dang_niem_phong:
        trang_thai = "Đang niêm phong"
        nhan_moc = "kết thúc giờ thi" if loai_chuan == "Đáp án" else "đến giờ bắt đầu thi"
        mo_ta = f"Đang khóa niêm phong — Tự động mở khi {nhan_moc} ({thoi_diem_mo_txt})"
    elif da_mo:
        trang_thai = "Đã mở"
        mo_ta = f"Đã tự động mở từ {thoi_diem_mo_txt}"
    else:
        trang_thai = "Chưa niêm phong"
        mo_ta = f"Chưa niêm phong (tự động khóa từ {moc_khoa_24h_txt})" if moc_khoa_24h_txt else "Chưa niêm phong"

    return {
        "loai": loai_chuan,
        "dang_niem_phong": dang_niem_phong,
        "da_mo": da_mo,
        "chua_niem_phong": chua_niem_phong,
        "tu_dong_khoa_24h": tu_dong_khoa_24h,
        "trang_thai_niem_phong": trang_thai,
        "thoi_diem_mo_hien_thi": thoi_diem_mo_txt,
        "moc_tu_dong_khoa_hien_thi": moc_khoa_24h_txt,
        "mo_ta_niem_phong": mo_ta,
    }


def _co_quyen_ra_de_khoi(pq: dict, ma_khoi: Optional[int]) -> bool:
    """Kiểm tra giáo viên có quyền ra đề thi chính thức đối với khối lớp tương ứng hay không."""
    if not ma_khoi:
        return False
    return bool(pq.get("duoc_truy_cap_de_chinh_thuc")) and (
        int(ma_khoi) in pq.get("danh_sach_khoi_chinh_thuc", [])
    )


def _kich_hoat_bay_de_moi_va_khoa_he_thong(
    cur,
    conn,
    phien: dict,
    ma_de_thi: str,
    ten_de_thi: str,
    ten_tep_goc: Optional[str],
    ip_may: str,
    dia_chi_ipv4: str,
    thiet_bi: str,
) -> None:
    """
    Khi người dùng bấm vào tệp bẫy mồi nhử (loai_de = 'DE_MOI'):
    - Tăng bộ đếm kích hoạt trong bảng TepBay,
    - Lập tức khóa an ninh tài khoản (bi_khoa = TRUE, khoa_den_thoi_diem = NULL),
    - Thu hồi toàn bộ phiên đăng nhập của tài khoản để trục xuất khỏi hệ thống ngay lập tức,
    - Ghi nhận báo động bất biến vào NhatKyLog.
    """
    cur.execute(
        """
        UPDATE TepBay
        SET so_lan_kich_hoat = so_lan_kich_hoat + 1,
            thoi_diem_kich_hoat_gan_nhat = CURRENT_TIMESTAMP
        WHERE ma_de_thi = %s
        RETURNING so_lan_kich_hoat, ten_tep_bay;
        """,
        (ma_de_thi,),
    )
    bay = cur.fetchone()
    so_lan = int(bay["so_lan_kich_hoat"]) if bay else 1

    cur.execute(
        """
        UPDATE TaiKhoan
        SET bi_khoa = TRUE,
            khoa_den_thoi_diem = NULL
        WHERE ma_tai_khoan = %s;
        """,
        (phien["ma_tai_khoan"],),
    )
    cur.execute(
        """
        UPDATE PhienDangNhap
        SET da_thu_hoi = TRUE
        WHERE ma_tai_khoan = %s;
        """,
        (phien["ma_tai_khoan"],),
    )
    conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Bẫy đề mồi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Báo động",
        chi_tiet=(
            f"Báo động an ninh: {_mo_ta_can_bo(phien)} kích hoạt tệp bẫy giám sát \"{ten_de_thi}\" "
            f"(lần kích hoạt thứ {so_lan}). Hệ thống đã lập tức khóa an ninh tài khoản và thu hồi toàn bộ phiên đăng nhập."
        ),
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_goc or "",
    )

    thoi_diem_vn = datetime.now(MUI_GIO_VN).strftime("%d/%m/%Y %H:%M:%S")
    threading.Thread(
        target=gui_canh_bao_bay_de_moi,
        args=(
            ten_de_thi,
            str(phien.get("ho_ten") or ""),
            str(phien.get("ma_can_bo") or ""),
            str(phien.get("ten_dang_nhap") or ""),
            ip_may,
            dia_chi_ipv4,
            so_lan,
            thoi_diem_vn,
        ),
        daemon=True,
    ).start()

    raise HTTPException(
        status_code=403,
        detail={
            "code": "HONEYTRAP_ACCOUNT_LOCKED",
            "so_lan_kich_hoat": so_lan,
            "message": (
                f"BÁO ĐỘNG AN NINH: Bạn vừa truy cập tệp bẫy giám sát bảo mật \"{ten_de_thi}\". "
                "Hệ thống đã lập tức khóa tài khoản, thu hồi phiên làm việc và ghi nhận báo động an ninh!"
            ),
        },
    )


@app.get("/api/de-thi")
def api_list_de_thi(
    request: Request,
    search: str = "",
    ma_khoi: Optional[int] = None,
    loai_ky_thi: str = "",
    loai_de: str = "",
    loai: str = "",
):
    """
    Lấy danh sách đề thi / đáp án và lịch thi trong bảng DeThi kết hợp LichThi và TepBay
    theo đúng môn học mà giáo viên dạy. Quản trị viên không có quyền truy cập Kho đề thi.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    now_utc = datetime.now(timezone.utc)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            ds_khoi_phep = pq.get("danh_sach_khoi_duoc_phep", pq["danh_sach_khoi"])
            conditions = [
                "COALESCE(d.ma_mon_hoc, lt.ma_mon_hoc) = %s",
                "COALESCE(d.ma_khoi, lt.ma_khoi) = ANY(%s)",
            ]
            params = [pq["ma_mon_hoc"], ds_khoi_phep]
            if ma_khoi:
                conditions.append("COALESCE(d.ma_khoi, lt.ma_khoi) = %s")
                params.append(int(ma_khoi))
            if loai_ky_thi and loai_ky_thi.strip():
                conditions.append("COALESCE(lt.loai_ky_thi, 'Giữa kỳ I') = %s")
                params.append(loai_ky_thi.strip())
            if loai_de and loai_de.strip():
                conditions.append("d.loai_de = %s")
                params.append(loai_de.strip())
            if loai and loai.strip():
                conditions.append("COALESCE(d.loai, 'Đề thi') = %s")
                params.append(_chuan_hoa_loai_tai_lieu_de_thi(loai))
            if search and search.strip():
                conditions.append("(LOWER(d.ten_de_thi) LIKE LOWER(%s) OR LOWER(COALESCE(lt.ten_ky_thi, lt.ten_lich_thi, '')) LIKE LOWER(%s))")
                params.extend([f"%{search.strip()}%", f"%{search.strip()}%"])

            where_sql = " AND ".join(conditions)
            cur.execute(
                f"""
                SELECT
                    d.ma_de_thi::text AS ma_de_thi,
                    d.ma_lich_thi,
                    COALESCE(lt.ten_ky_thi, lt.ten_lich_thi, 'Kiểm tra giữa kỳ I') AS ten_ky_thi,
                    COALESCE(lt.ten_lich_thi, lt.ten_ky_thi, 'Kiểm tra giữa kỳ I') AS ten_lich_thi,
                    COALESCE(lt.loai_ky_thi, 'Giữa kỳ I') AS loai_ky_thi,
                    COALESCE(lt.nam_hoc, '2026 - 2027') AS nam_hoc,
                    COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AS raw_gio_bat_dau,
                    COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AS raw_gio_ket_thuc,
                    to_char(COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS gio_bat_dau,
                    to_char(COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS gio_ket_thuc,
                    to_char(COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'YYYY-MM-DD"T"HH24:MI') AS gio_bat_dau_iso,
                    to_char(COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'YYYY-MM-DD"T"HH24:MI') AS gio_ket_thuc_iso,
                    to_char(COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS bat_dau_thi,
                    to_char(COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS ket_thuc_thi,
                    d.ten_de_thi,
                    COALESCE(d.ma_mon_hoc, lt.ma_mon_hoc) AS ma_mon_hoc,
                    mh.ten_mon_hoc,
                    mh.ky_hieu_mon,
                    COALESCE(d.ma_khoi, lt.ma_khoi) AS ma_khoi,
                    kl.ten_khoi,
                    COALESCE(d.loai, 'Đề thi') AS loai,
                    COALESCE(d.loai_de, 'CHINH_THUC') AS loai_de,
                    COALESCE(d.da_nem_phong, FALSE) AS da_nem_phong,
                    to_char(d.thoi_diem_niem_phong AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_diem_niem_phong,
                    d.nguoi_ra_de::text AS nguoi_ra_de,
                    tk_ra.ho_ten AS ho_ten_nguoi_ra_de,
                    tk_ra.ma_can_bo AS ma_cb_nguoi_ra_de,
                    tk_ra.vai_tro AS vai_tro_nguoi_ra_de,
                    d.nguoi_cap_nhat::text AS nguoi_cap_nhat,
                    tk_sua.ho_ten AS ho_ten_nguoi_cap_nhat,
                    tk_sua.ma_can_bo AS ma_cb_nguoi_cap_nhat,
                    tk_sua.vai_tro AS vai_tro_nguoi_cap_nhat,
                    COALESCE(d.duong_dan_tep, d.duong_dan_tep_ma_hoa) AS duong_dan_tep,
                    d.ten_tep_goc,
                    d.ma_bam_sha256,
                    COALESCE(d.da_chinh_sua, FALSE) AS da_chinh_sua,
                    d.bi_can_thiep,
                    d.khoa_ma_hoa_de,
                    d.ma_nonce_aes,
                    d.the_xac_thuc_aes,
                    to_char(d.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_gian_tao,
                    to_char(d.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_diem_tao,
                    to_char(d.thoi_diem_cap_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS cap_nhat_lan_cuoi,
                    to_char(d.thoi_diem_cap_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_diem_cap_nhat,
                    tb.ma_bay,
                    COALESCE(tb.so_lan_kich_hoat, 0) AS so_lan_kich_hoat_bay,
                    to_char(tb.thoi_diem_kich_hoat_gan_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS kich_hoat_bay_gan_nhat
                FROM DeThi d
                LEFT JOIN LichThi lt ON lt.ma_lich_thi = d.ma_lich_thi
                JOIN MonHoc mh ON mh.ma_mon_hoc = COALESCE(d.ma_mon_hoc, lt.ma_mon_hoc)
                JOIN KhoiLop kl ON kl.ma_khoi = COALESCE(d.ma_khoi, lt.ma_khoi)
                JOIN TaiKhoan tk_ra ON tk_ra.ma_tai_khoan = d.nguoi_ra_de
                LEFT JOIN TaiKhoan tk_sua ON tk_sua.ma_tai_khoan = d.nguoi_cap_nhat
                LEFT JOIN TepBay tb ON tb.ma_de_thi = d.ma_de_thi
                WHERE {where_sql}
                ORDER BY COALESCE(d.thoi_diem_cap_nhat, d.thoi_diem_tao) DESC, d.thoi_diem_tao DESC;
                """,
                tuple(params),
            )
            rows = cur.fetchall()
            visible_rows = []
            for r in rows:
                seal = _tinh_trang_thai_niem_phong_de_thi(
                    r["da_nem_phong"],
                    r.get("loai"),
                    r.pop("raw_gio_bat_dau", None),
                    r.pop("raw_gio_ket_thuc", None),
                    now_utc=now_utc,
                )
                if (not _co_quyen_ra_de_khoi(pq, r["ma_khoi"])) and (not seal["da_mo"]):
                    continue
                r.update(seal)
                ten_ngan = _TEN_MON_NGAN.get(r["ky_hieu_mon"], r["ten_mon_hoc"])
                r["ten_mon_ngan"] = ten_ngan
                r["nguoi_ra_de_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_ra_de"], r.get("vai_tro_nguoi_ra_de"), ten_ngan
                )
                if (
                    r["da_chinh_sua"]
                    and r.get("ho_ten_nguoi_cap_nhat")
                    and str(r.get("nguoi_cap_nhat") or "") == str(r["nguoi_ra_de"])
                ):
                    r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                        r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                    )
                    r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
                else:
                    r["da_chinh_sua"] = False
                    r["nguoi_cap_nhat"] = None
                    r["ho_ten_nguoi_cap_nhat"] = None
                    r["thoi_diem_cap_nhat"] = None
                    r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                    r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
                la_nguoi_tao = str(r["nguoi_ra_de"]) == str(phien["ma_tai_khoan"])
                r["la_nguoi_ra_de"] = la_nguoi_tao
                r["duoc_phep_chinh_sua"] = (
                    (not seal["dang_niem_phong"])
                    and bool(pq["duoc_truy_cap_de_chinh_thuc"])
                    and la_nguoi_tao
                )
                r["duoc_phep_xoa"] = r["duoc_phep_chinh_sua"]
                r["duoc_phep_niem_phong"] = (
                    seal["chua_niem_phong"]
                    and bool(pq["duoc_truy_cap_de_chinh_thuc"])
                    and la_nguoi_tao
                )
                r["duoc_phep_truy_cap_tep"] = not seal["dang_niem_phong"]
                tt = _kiem_tra_toan_ven_tep_de_thi(
                    r["duong_dan_tep"],
                    r["ma_bam_sha256"],
                    r["da_chinh_sua"],
                    r.pop("khoa_ma_hoa_de", None),
                    r.pop("ma_nonce_aes", None),
                    r.pop("the_xac_thuc_aes", None),
                )
                r.update(tt)
                visible_rows.append(r)
            return {
                "phan_quyen_mon": pq,
                "items": visible_rows,
                "total": len(visible_rows),
            }


@app.get("/api/de-thi/{ma_de_thi}")
def api_get_de_thi_detail(ma_de_thi: str, request: Request):
    """Xem chi tiết một đề thi / đáp án và lịch thi tương ứng."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    now_utc = datetime.now(timezone.utc)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                """
                SELECT
                    d.ma_de_thi::text AS ma_de_thi,
                    d.ma_lich_thi,
                    COALESCE(lt.ten_ky_thi, lt.ten_lich_thi, 'Kiểm tra giữa kỳ I') AS ten_ky_thi,
                    COALESCE(lt.loai_ky_thi, 'Giữa kỳ I') AS loai_ky_thi,
                    COALESCE(lt.nam_hoc, '2026 - 2027') AS nam_hoc,
                    COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AS raw_gio_bat_dau,
                    COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AS raw_gio_ket_thuc,
                    to_char(COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS gio_bat_dau,
                    to_char(COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS gio_ket_thuc,
                    to_char(COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'YYYY-MM-DD"T"HH24:MI') AS gio_bat_dau_iso,
                    to_char(COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AT TIME ZONE 'Asia/Ho_Chi_Minh', 'YYYY-MM-DD"T"HH24:MI') AS gio_ket_thuc_iso,
                    d.ten_de_thi,
                    COALESCE(d.ma_mon_hoc, lt.ma_mon_hoc) AS ma_mon_hoc,
                    mh.ten_mon_hoc,
                    mh.ky_hieu_mon,
                    COALESCE(d.ma_khoi, lt.ma_khoi) AS ma_khoi,
                    kl.ten_khoi,
                    COALESCE(d.loai, 'Đề thi') AS loai,
                    COALESCE(d.loai_de, 'CHINH_THUC') AS loai_de,
                    COALESCE(d.da_nem_phong, FALSE) AS da_nem_phong,
                    to_char(d.thoi_diem_niem_phong AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_diem_niem_phong,
                    d.nguoi_ra_de::text AS nguoi_ra_de,
                    tk_ra.ho_ten AS ho_ten_nguoi_ra_de,
                    tk_ra.ma_can_bo AS ma_cb_nguoi_ra_de,
                    tk_ra.vai_tro AS vai_tro_nguoi_ra_de,
                    d.nguoi_cap_nhat::text AS nguoi_cap_nhat,
                    tk_sua.ho_ten AS ho_ten_nguoi_cap_nhat,
                    tk_sua.ma_can_bo AS ma_cb_nguoi_cap_nhat,
                    tk_sua.vai_tro AS vai_tro_nguoi_cap_nhat,
                    COALESCE(d.duong_dan_tep, d.duong_dan_tep_ma_hoa) AS duong_dan_tep,
                    d.ten_tep_goc,
                    d.ma_bam_sha256,
                    COALESCE(d.da_chinh_sua, FALSE) AS da_chinh_sua,
                    d.khoa_ma_hoa_de,
                    d.ma_nonce_aes,
                    d.the_xac_thuc_aes,
                    to_char(d.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_gian_tao,
                    to_char(d.thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_diem_tao,
                    to_char(d.thoi_diem_cap_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS cap_nhat_lan_cuoi,
                    to_char(d.thoi_diem_cap_nhat AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI') AS thoi_diem_cap_nhat
                FROM DeThi d
                LEFT JOIN LichThi lt ON lt.ma_lich_thi = d.ma_lich_thi
                JOIN MonHoc mh ON mh.ma_mon_hoc = COALESCE(d.ma_mon_hoc, lt.ma_mon_hoc)
                JOIN KhoiLop kl ON kl.ma_khoi = COALESCE(d.ma_khoi, lt.ma_khoi)
                JOIN TaiKhoan tk_ra ON tk_ra.ma_tai_khoan = d.nguoi_ra_de
                LEFT JOIN TaiKhoan tk_sua ON tk_sua.ma_tai_khoan = d.nguoi_cap_nhat
                WHERE d.ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            r = cur.fetchone()
            if not r:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi.")
            if r.get("loai_de") == "DE_MOI":
                _kich_hoat_bay_de_moi_va_khoa_he_thong(
                    cur,
                    conn,
                    phien,
                    ma_de_thi,
                    r["ten_de_thi"],
                    r.get("ten_tep_goc"),
                    ip_may,
                    dia_chi_ipv4,
                    thiet_bi,
                )
            if int(r["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép truy cập đề thi thuộc môn học mình giảng dạy.")
            if int(r["ma_khoi"]) not in pq.get("danh_sach_khoi_duoc_phep", pq["danh_sach_khoi"]):
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép truy cập đề thi thuộc khối lớp được phân quyền.")

            seal = _tinh_trang_thai_niem_phong_de_thi(
                r["da_nem_phong"],
                r.get("loai"),
                r.pop("raw_gio_bat_dau", None),
                r.pop("raw_gio_ket_thuc", None),
                now_utc=now_utc,
            )
            if (not _co_quyen_ra_de_khoi(pq, r["ma_khoi"])) and (not seal["da_mo"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=(
                        f"Từ chối {_mo_ta_can_bo(phien)} xem chi tiết {seal['loai'].lower()} \"{r['ten_de_thi']}\" "
                        "do tài khoản không có quyền ra đề thi và chưa đến thời điểm mở."
                    ),
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=r.get("ten_tep_goc") or "",
                )
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản không có quyền ra đề thi chỉ được xem những đề thi đã đến giờ thi và các đáp án đã được mở.",
                )
            r.update(seal)
            ten_ngan = _TEN_MON_NGAN.get(r["ky_hieu_mon"], r["ten_mon_hoc"])
            r["ten_mon_ngan"] = ten_ngan
            r["nguoi_ra_de_hien_thi"] = _format_nguoi_thao_tac_de(
                r["ho_ten_nguoi_ra_de"], r.get("vai_tro_nguoi_ra_de"), ten_ngan
            )
            if (
                r["da_chinh_sua"]
                and r.get("ho_ten_nguoi_cap_nhat")
                and str(r.get("nguoi_cap_nhat") or "") == str(r["nguoi_ra_de"])
            ):
                r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                )
                r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
            else:
                r["da_chinh_sua"] = False
                r["nguoi_cap_nhat"] = None
                r["ho_ten_nguoi_cap_nhat"] = None
                r["thoi_diem_cap_nhat"] = None
                r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
            la_nguoi_tao = str(r["nguoi_ra_de"]) == str(phien["ma_tai_khoan"])
            r["la_nguoi_ra_de"] = la_nguoi_tao
            r["duoc_phep_chinh_sua"] = (
                (not seal["dang_niem_phong"])
                and bool(pq["duoc_truy_cap_de_chinh_thuc"])
                and la_nguoi_tao
            )
            r["duoc_phep_xoa"] = r["duoc_phep_chinh_sua"]
            r["duoc_phep_niem_phong"] = (
                seal["chua_niem_phong"]
                and bool(pq["duoc_truy_cap_de_chinh_thuc"])
                and la_nguoi_tao
            )
            r["duoc_phep_truy_cap_tep"] = not seal["dang_niem_phong"]
            r.update(
                _kiem_tra_toan_ven_tep_de_thi(
                    r["duong_dan_tep"],
                    r["ma_bam_sha256"],
                    r["da_chinh_sua"],
                    r.pop("khoa_ma_hoa_de", None),
                    r.pop("ma_nonce_aes", None),
                    r.pop("the_xac_thuc_aes", None),
                )
            )
            return {"item": r}


@app.post("/api/de-thi")
async def api_create_de_thi(
    request: Request,
    ten_de_thi: str = Form(...),
    ten_ky_thi: str = Form("Kiểm tra giữa kỳ I"),
    ten_lich_thi: str = Form(""),
    loai_ky_thi: str = Form("Giữa kỳ I"),
    nam_hoc: str = Form("2026 - 2027"),
    ma_khoi: int = Form(...),
    gio_bat_dau: str = Form("15/11/2026 07:30"),
    gio_ket_thuc: str = Form("15/11/2026 09:00"),
    loai: str = Form("Đề thi"),
    loai_de: str = Form("CHINH_THUC"),
    ma_pin: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    """Tạo Lịch thi và Đề thi / Đáp án mới với xác minh mã PIN 6 số và mã hóa AES-256-GCM."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    ten_ky = (ten_ky_thi or ten_lich_thi or "Kiểm tra giữa kỳ I").strip()
    loai_ky = (loai_ky_thi or "Giữa kỳ I").strip()
    nam = (nam_hoc or "2026 - 2027").strip()
    ten_de = (ten_de_thi or "").strip()
    if not ten_de or not ten_ky:
        raise HTTPException(status_code=400, detail="Vui lòng nhập đầy đủ Tên kỳ thi và Tên đề thi.")

    loai_tai_lieu = _chuan_hoa_loai_tai_lieu_de_thi(loai)

    dt_bat_dau = _parse_gio_thi_vn(gio_bat_dau)
    dt_ket_thuc = _parse_gio_thi_vn(gio_ket_thuc)
    if dt_ket_thuc <= dt_bat_dau:
        raise HTTPException(status_code=400, detail="Thời gian kết thúc phải lớn hơn Thời gian bắt đầu.")

    ma_loai_de = (loai_de or "CHINH_THUC").strip().upper()
    if ma_loai_de not in ("CHINH_THUC", "ON_TAP", "DE_MOI"):
        ma_loai_de = "CHINH_THUC"

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Tệp đề thi đang rỗng.")
    if len(raw_bytes) > _KICH_THUOC_TOI_DA:
        raise HTTPException(status_code=400, detail="Kích thước tệp vượt quá 10MB.")

    ten_tep_goc = os.path.basename(file.filename or "De_Thi.pdf")
    ext = os.path.splitext(ten_tep_goc.lower())[1]
    if ext not in _DUOI_TEP_HOP_LE:
        raise HTTPException(status_code=400, detail="Định dạng tệp không hỗ trợ. Vui lòng chọn tệp PDF, DOCX hoặc XLSX.")

    _bat_buoc_xac_minh_ma_pin(
        request, phien, ma_pin, f"Thêm {loai_tai_lieu.lower()} \"{ten_de}\"", ten_tep_goc
    )

    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            if not pq["duoc_truy_cap_de_chinh_thuc"]:
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản của bạn không có quyền thêm đề thi chính thức.",
                )
            if int(ma_khoi) not in pq["danh_sach_khoi_chinh_thuc"]:
                raise HTTPException(status_code=403, detail=f"Bạn không có quyền tạo lịch thi và đề thi chính thức cho Khối {ma_khoi}.")

            cur.execute(
                """
                INSERT INTO LichThi (
                    ten_ky_thi, loai_ky_thi, ten_lich_thi, nam_hoc,
                    ma_khoi, ma_mon_hoc, gio_bat_dau, gio_ket_thuc,
                    thoi_gian_bat_dau, thoi_gian_ket_thuc, nguoi_tao_lich, thoi_diem_tao
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING ma_lich_thi;
                """,
                (
                    ten_ky,
                    loai_ky,
                    ten_ky,
                    nam,
                    int(ma_khoi),
                    pq["ma_mon_hoc"],
                    dt_bat_dau,
                    dt_ket_thuc,
                    dt_bat_dau,
                    dt_ket_thuc,
                    phien["ma_tai_khoan"],
                ),
            )
            ma_lich = cur.fetchone()["ma_lich_thi"]

            ma_de_thi = str(uuid.uuid4())
            env = ma_hoa_tep_de_thi_envelope(raw_bytes, str(phien["ma_tai_khoan"]))
            base_dir = os.path.dirname(__file__)
            dir_de_thi = os.path.join(base_dir, "storage", "de_thi")
            os.makedirs(dir_de_thi, exist_ok=True)
            rel_path = f"storage/de_thi/{ma_de_thi}.enc"
            abs_path = os.path.join(dir_de_thi, f"{ma_de_thi}.enc")
            with open(abs_path, "wb") as f:
                f.write(env["ciphertext"])

            cur.execute(
                """
                INSERT INTO DeThi (
                    ma_de_thi, ma_lich_thi, ten_de_thi, ma_mon_hoc, ma_khoi, loai, loai_de,
                    da_nem_phong, nguoi_ra_de, duong_dan_tep, duong_dan_tep_ma_hoa, ten_tep_goc,
                    ma_bam_sha256, chu_ky_so_nguoi_ra_de, khoa_ma_hoa_de, ma_nonce_aes, the_xac_thuc_aes,
                    bi_can_thiep, da_chinh_sua, thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, FALSE, CURRENT_TIMESTAMP, NULL, NULL);
                """,
                (
                    ma_de_thi,
                    ma_lich,
                    ten_de,
                    pq["ma_mon_hoc"],
                    int(ma_khoi),
                    loai_tai_lieu,
                    ma_loai_de,
                    phien["ma_tai_khoan"],
                    rel_path,
                    rel_path,
                    ten_tep_goc,
                    env["ma_bam_sha256"],
                    psycopg2.Binary(env["chu_ky_so_nguoi_ra_de"]),
                    psycopg2.Binary(env["khoa_ma_hoa_de"]),
                    psycopg2.Binary(env["ma_nonce_aes"]),
                    psycopg2.Binary(env["the_xac_thuc_aes"]),
                ),
            )
            if ma_loai_de == "DE_MOI":
                cur.execute(
                    """
                    INSERT INTO TepBay (ma_de_thi, ten_tep_bay, duong_dan_kich_hoat, so_lan_kich_hoat, dang_hoat_dong)
                    VALUES (%s, %s, %s, 0, TRUE)
                    ON CONFLICT (duong_dan_kich_hoat) DO NOTHING;
                    """,
                    (ma_de_thi, ten_tep_goc, f"/api/de-thi/{ma_de_thi}/download"),
                )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Thêm đáp án" if loai_tai_lieu == "Đáp án" else "Thêm đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"{_mo_ta_can_bo(phien)} đã tạo lịch thi \"{ten_ky}\" ({loai_ky} - Khối {ma_khoi}) "
            f"và tải lên {loai_tai_lieu.lower()} \"{ten_de}\"."
        ),
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_goc,
    )
    return {
        "status": "OK",
        "message": f"Đã tạo lịch thi '{ten_ky}' và lưu {loai_tai_lieu.lower()} '{ten_de}' thành công!",
        "ma_de_thi": ma_de_thi,
        "ma_lich_thi": ma_lich,
    }


@app.put("/api/de-thi/{ma_de_thi}")
async def api_update_de_thi(
    ma_de_thi: str,
    request: Request,
    ten_de_thi: str = Form(...),
    ten_ky_thi: str = Form("Kiểm tra giữa kỳ I"),
    loai_ky_thi: str = Form("Giữa kỳ I"),
    nam_hoc: str = Form("2026 - 2027"),
    ma_khoi: int = Form(...),
    gio_bat_dau: str = Form("15/11/2026 07:30"),
    gio_ket_thuc: str = Form("15/11/2026 09:00"),
    loai: Optional[str] = Form(None),
    ma_pin: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """Cập nhật Lịch thi và Đề thi / Đáp án (bị chặn tuyệt đối trong thời gian niêm phong, bắt buộc PIN 6 số)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    ten_ky = (ten_ky_thi or "Kiểm tra giữa kỳ I").strip()
    loai_ky = (loai_ky_thi or "Giữa kỳ I").strip()
    nam = (nam_hoc or "2026 - 2027").strip()
    ten_de = (ten_de_thi or "").strip()
    if not ten_de or not ten_ky:
        raise HTTPException(status_code=400, detail="Vui lòng nhập đầy đủ Tên kỳ thi và Tên đề thi.")

    dt_bat_dau = _parse_gio_thi_vn(gio_bat_dau)
    dt_ket_thuc = _parse_gio_thi_vn(gio_ket_thuc)
    if dt_ket_thuc <= dt_bat_dau:
        raise HTTPException(status_code=400, detail="Thời gian kết thúc phải lớn hơn Thời gian bắt đầu.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    d.ma_de_thi, d.ten_de_thi, d.ma_lich_thi, d.ma_mon_hoc,
                    d.nguoi_ra_de::text AS nguoi_ra_de,
                    COALESCE(d.loai, 'Đề thi') AS loai,
                    COALESCE(d.da_nem_phong, FALSE) AS da_nem_phong,
                    COALESCE(d.duong_dan_tep, d.duong_dan_tep_ma_hoa) AS duong_dan_tep,
                    d.ten_tep_goc, d.ma_bam_sha256,
                    COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AS raw_gio_bat_dau,
                    COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AS raw_gio_ket_thuc
                FROM DeThi d
                LEFT JOIN LichThi lt ON lt.ma_lich_thi = d.ma_lich_thi
                WHERE d.ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi cần cập nhật.")

            seal = _tinh_trang_thai_niem_phong_de_thi(
                existing["da_nem_phong"],
                existing["loai"],
                existing["raw_gio_bat_dau"],
                existing["raw_gio_ket_thuc"],
            )
            if seal["dang_niem_phong"]:
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập đề niêm phong",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=(
                        f"Từ chối {_mo_ta_can_bo(phien)} chỉnh sửa {seal['loai'].lower()} đang niêm phong "
                        f"\"{existing['ten_de_thi']}\" (tự động mở lúc {seal['thoi_diem_mo_hien_thi']})."
                    ),
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Tài liệu ({seal['loai']}) đang trong thời gian niêm phong bảo mật. "
                        "Không ai có quyền can thiệp hoặc chỉnh sửa "
                        f"trước thời điểm mở tự động ({seal['thoi_diem_mo_hien_thi']})."
                    ),
                )

            if str(existing["nguoi_ra_de"]) != str(phien["ma_tai_khoan"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} chỉnh sửa {seal['loai'].lower()} \"{existing['ten_de_thi']}\" do không phải giáo viên ra đề.",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail="Đề của giáo viên nào ra thì chỉ chính giáo viên đó mới được phép chỉnh sửa.",
                )

            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            if not pq["duoc_truy_cap_de_chinh_thuc"]:
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản của bạn không có quyền chỉnh sửa đề thi chính thức.",
                )
            if int(ma_khoi) not in pq["danh_sach_khoi_chinh_thuc"]:
                raise HTTPException(
                    status_code=403,
                    detail=f"Bạn không có quyền cập nhật đề thi chính thức cho Khối {ma_khoi}.",
                )
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền cập nhật đề thi của môn học khác.")

            loai_moi = _chuan_hoa_loai_tai_lieu_de_thi(loai) if (loai and loai.strip()) else existing["loai"]
            _bat_buoc_xac_minh_ma_pin(
                request, phien, ma_pin, f"Sửa {loai_moi.lower()} \"{ten_de}\"", existing["ten_tep_goc"]
            )

            if existing["ma_lich_thi"]:
                cur.execute(
                    """
                    UPDATE LichThi
                    SET ten_ky_thi = %s,
                        ten_lich_thi = %s,
                        loai_ky_thi = %s,
                        nam_hoc = %s,
                        ma_khoi = %s,
                        gio_bat_dau = %s,
                        gio_ket_thuc = %s,
                        thoi_gian_bat_dau = %s,
                        thoi_gian_ket_thuc = %s
                    WHERE ma_lich_thi = %s;
                    """,
                    (
                        ten_ky,
                        ten_ky,
                        loai_ky,
                        nam,
                        int(ma_khoi),
                        dt_bat_dau,
                        dt_ket_thuc,
                        dt_bat_dau,
                        dt_ket_thuc,
                        existing["ma_lich_thi"],
                    ),
                )

            ten_tep_moi = existing["ten_tep_goc"]
            sha256_moi = existing["ma_bam_sha256"]
            rel_path = existing["duong_dan_tep"]

            if file and file.filename:
                raw_bytes = await file.read()
                if not raw_bytes:
                    raise HTTPException(status_code=400, detail="Tệp tải lên mới đang rỗng.")
                if len(raw_bytes) > _KICH_THUOC_TOI_DA:
                    raise HTTPException(status_code=400, detail="Kích thước tệp vượt quá 10MB.")
                ten_tep_moi = os.path.basename(file.filename)
                ext = os.path.splitext(ten_tep_moi.lower())[1]
                if ext not in _DUOI_TEP_HOP_LE:
                    raise HTTPException(status_code=400, detail="Định dạng tệp không hỗ trợ (chỉ nhận PDF, DOCX, XLSX).")

                env = ma_hoa_tep_de_thi_envelope(raw_bytes, str(phien["ma_tai_khoan"]))
                sha256_moi = env["ma_bam_sha256"]
                base_dir = os.path.dirname(__file__)
                abs_path = os.path.join(base_dir, rel_path.replace("/", os.sep))
                os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                with open(abs_path, "wb") as f:
                    f.write(env["ciphertext"])

                cur.execute(
                    """
                    UPDATE DeThi
                    SET ten_de_thi = %s,
                        ma_khoi = %s,
                        loai = %s,
                        ten_tep_goc = %s,
                        ma_bam_sha256 = %s,
                        chu_ky_so_nguoi_ra_de = %s,
                        khoa_ma_hoa_de = %s,
                        ma_nonce_aes = %s,
                        the_xac_thuc_aes = %s,
                        da_chinh_sua = TRUE,
                        nguoi_cap_nhat = %s,
                        thoi_diem_cap_nhat = CURRENT_TIMESTAMP
                    WHERE ma_de_thi = %s;
                    """,
                    (
                        ten_de,
                        int(ma_khoi),
                        loai_moi,
                        ten_tep_moi,
                        sha256_moi,
                        psycopg2.Binary(env["chu_ky_so_nguoi_ra_de"]),
                        psycopg2.Binary(env["khoa_ma_hoa_de"]),
                        psycopg2.Binary(env["ma_nonce_aes"]),
                        psycopg2.Binary(env["the_xac_thuc_aes"]),
                        phien["ma_tai_khoan"],
                        ma_de_thi,
                    ),
                )
            else:
                cur.execute(
                    """
                    UPDATE DeThi
                    SET ten_de_thi = %s,
                        ma_khoi = %s,
                        loai = %s,
                        da_chinh_sua = TRUE,
                        nguoi_cap_nhat = %s,
                        thoi_diem_cap_nhat = CURRENT_TIMESTAMP
                    WHERE ma_de_thi = %s;
                    """,
                    (ten_de, int(ma_khoi), loai_moi, phien["ma_tai_khoan"], ma_de_thi),
                )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Sửa đáp án" if loai_moi == "Đáp án" else "Sửa đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã cập nhật lịch thi \"{ten_ky}\" và {loai_moi.lower()} \"{ten_de}\".",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_moi,
    )
    return {
        "status": "OK",
        "message": f"Đã cập nhật lịch thi '{ten_ky}' và {loai_moi.lower()} '{ten_de}' thành công!",
    }


@app.post("/api/de-thi/{ma_de_thi}/seal")
def api_seal_de_thi(
    ma_de_thi: str,
    request: Request,
    req: Optional[PinVerifyRequest] = None,
):
    """Giáo viên bấm nút Niêm phong ngay lập tức đối với Đề thi / Đáp án do mình tạo (bắt buộc PIN 6 số)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                """
                SELECT
                    d.ma_de_thi, d.ten_de_thi, d.ma_mon_hoc, d.ma_khoi,
                    d.nguoi_ra_de::text AS nguoi_ra_de,
                    COALESCE(d.loai, 'Đề thi') AS loai,
                    COALESCE(d.da_nem_phong, FALSE) AS da_nem_phong,
                    d.ten_tep_goc,
                    COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AS raw_gio_bat_dau,
                    COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AS raw_gio_ket_thuc
                FROM DeThi d
                LEFT JOIN LichThi lt ON lt.ma_lich_thi = d.ma_lich_thi
                WHERE d.ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi cần niêm phong.")
            if str(existing["nguoi_ra_de"]) != str(phien["ma_tai_khoan"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} niêm phong {existing['loai'].lower()} \"{existing['ten_de_thi']}\" do không phải giáo viên ra đề.",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail="Đề của giáo viên nào ra thì chỉ chính giáo viên đó mới được phép bấm niêm phong.",
                )
            if not pq["duoc_truy_cap_de_chinh_thuc"] or int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền niêm phong tài liệu này.")

            seal = _tinh_trang_thai_niem_phong_de_thi(
                existing["da_nem_phong"],
                existing["loai"],
                existing["raw_gio_bat_dau"],
                existing["raw_gio_ket_thuc"],
            )
            if seal["dang_niem_phong"]:
                raise HTTPException(status_code=400, detail="Tài liệu này hiện đã ở trạng thái niêm phong bảo mật.")
            if seal["da_mo"]:
                raise HTTPException(
                    status_code=400,
                    detail="Tài liệu này đã qua thời điểm mở tự động theo lịch thi, không thể niêm phong.",
                )

            _bat_buoc_xac_minh_ma_pin(
                request,
                phien,
                req.ma_pin if req else None,
                f"Niêm phong {seal['loai'].lower()} \"{existing['ten_de_thi']}\"",
                existing["ten_tep_goc"],
            )

            cur.execute(
                """
                UPDATE DeThi
                SET da_nem_phong = TRUE,
                    thoi_diem_niem_phong = CURRENT_TIMESTAMP,
                    nguoi_niem_phong = %s
                WHERE ma_de_thi = %s;
                """,
                (phien["ma_tai_khoan"], ma_de_thi),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Niêm phong đề",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"{_mo_ta_can_bo(phien)} đã khóa niêm phong {seal['loai'].lower()} \"{existing['ten_de_thi']}\" "
            f"(tự động mở lúc {seal['thoi_diem_mo_hien_thi']})."
        ),
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=existing["ten_tep_goc"],
    )
    return {
        "status": "OK",
        "message": (
            f"Đã niêm phong {seal['loai'].lower()} '{existing['ten_de_thi']}' thành công! "
            f"Tài liệu sẽ tự động mở lúc {seal['thoi_diem_mo_hien_thi']}."
        ),
    }


@app.delete("/api/de-thi/{ma_de_thi}")
def api_delete_de_thi(ma_de_thi: str, request: Request):
    """Xóa đề thi / đáp án và lịch thi tương ứng (bị chặn tuyệt đối nếu đang trong thời gian niêm phong)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    d.ten_de_thi, d.ma_lich_thi, d.ma_mon_hoc,
                    d.nguoi_ra_de::text AS nguoi_ra_de,
                    COALESCE(d.loai, 'Đề thi') AS loai,
                    COALESCE(d.da_nem_phong, FALSE) AS da_nem_phong,
                    COALESCE(d.duong_dan_tep, d.duong_dan_tep_ma_hoa) AS duong_dan_tep,
                    d.ten_tep_goc,
                    COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AS raw_gio_bat_dau,
                    COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AS raw_gio_ket_thuc
                FROM DeThi d
                LEFT JOIN LichThi lt ON lt.ma_lich_thi = d.ma_lich_thi
                WHERE d.ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi.")

            seal = _tinh_trang_thai_niem_phong_de_thi(
                existing["da_nem_phong"],
                existing["loai"],
                existing["raw_gio_bat_dau"],
                existing["raw_gio_ket_thuc"],
            )
            if seal["dang_niem_phong"]:
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập đề niêm phong",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=(
                        f"Từ chối {_mo_ta_can_bo(phien)} xóa {seal['loai'].lower()} đang niêm phong "
                        f"\"{existing['ten_de_thi']}\" (tự động mở lúc {seal['thoi_diem_mo_hien_thi']})."
                    ),
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Tài liệu ({seal['loai']}) đang trong thời gian niêm phong bảo mật. "
                        "Không ai có quyền xóa hoặc can thiệp "
                        f"trước thời điểm mở tự động ({seal['thoi_diem_mo_hien_thi']})."
                    ),
                )

            if str(existing["nguoi_ra_de"]) != str(phien["ma_tai_khoan"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=f"Từ chối {_mo_ta_can_bo(phien)} xóa {seal['loai'].lower()} \"{existing['ten_de_thi']}\" do không phải giáo viên ra đề.",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=existing["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail="Đề của giáo viên nào ra thì chỉ chính giáo viên đó mới được phép xóa.",
                )

            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            if not pq["duoc_truy_cap_de_chinh_thuc"]:
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản của bạn không có quyền xóa đề thi chính thức.",
                )
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền xóa đề thi của môn học khác.")
            _bat_buoc_xac_minh_ma_pin(
                request,
                phien,
                None,
                f"Xóa {existing['loai'].lower()} \"{existing['ten_de_thi']}\"",
                existing["ten_tep_goc"],
            )
            cur.execute("DELETE FROM DeThi WHERE ma_de_thi = %s;", (ma_de_thi,))
            if existing["ma_lich_thi"]:
                cur.execute("DELETE FROM LichThi WHERE ma_lich_thi = %s;", (existing["ma_lich_thi"],))
        conn.commit()

    base_dir = os.path.dirname(__file__)
    abs_path = os.path.join(base_dir, (existing["duong_dan_tep"] or "").replace("/", os.sep))
    if os.path.exists(abs_path):
        try:
            os.remove(abs_path)
        except Exception:
            pass

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Xóa đáp án" if existing["loai"] == "Đáp án" else "Xóa đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã xóa {existing['loai'].lower()} \"{existing['ten_de_thi']}\".",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=existing["ten_tep_goc"],
    )
    return {"status": "OK", "message": f"Đã xóa {existing['loai'].lower()} '{existing['ten_de_thi']}'."}


@app.get("/api/de-thi/{ma_de_thi}/file")
def api_access_de_thi_file(ma_de_thi: str, request: Request, mode: str = "attachment"):
    """Truy cập / tải tệp từ bảng DeThi với kiểm tra niêm phong, bẫy đề mồi, mã PIN 6 số và toàn vẹn AES-GCM."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    _chan_quan_tri_truy_cap_kho_de(request, phien, "Kho đề thi")
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                """
                SELECT
                    d.ma_de_thi::text AS ma_de_thi, d.ten_de_thi, d.ma_mon_hoc, d.ma_khoi,
                    COALESCE(d.loai, 'Đề thi') AS loai,
                    COALESCE(d.da_nem_phong, FALSE) AS da_nem_phong,
                    d.loai_de, COALESCE(d.duong_dan_tep, d.duong_dan_tep_ma_hoa) AS duong_dan_tep,
                    d.ten_tep_goc, d.ma_bam_sha256,
                    d.khoa_ma_hoa_de, d.ma_nonce_aes, d.the_xac_thuc_aes,
                    COALESCE(lt.gio_bat_dau, lt.thoi_gian_bat_dau) AS raw_gio_bat_dau,
                    COALESCE(lt.gio_ket_thuc, lt.thoi_gian_ket_thuc) AS raw_gio_ket_thuc
                FROM DeThi d
                LEFT JOIN LichThi lt ON lt.ma_lich_thi = d.ma_lich_thi
                WHERE d.ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            d = cur.fetchone()
            if not d:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi.")

            if d["loai_de"] == "DE_MOI":
                _kich_hoat_bay_de_moi_va_khoa_he_thong(
                    cur,
                    conn,
                    phien,
                    ma_de_thi,
                    d["ten_de_thi"],
                    d.get("ten_tep_goc"),
                    ip_may,
                    dia_chi_ipv4,
                    thiet_bi,
                )

            seal = _tinh_trang_thai_niem_phong_de_thi(
                d["da_nem_phong"],
                d["loai"],
                d["raw_gio_bat_dau"],
                d["raw_gio_ket_thuc"],
            )
            if seal["dang_niem_phong"]:
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập đề niêm phong",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=(
                        f"Từ chối {_mo_ta_can_bo(phien)} truy cập tệp {seal['loai'].lower()} đang niêm phong "
                        f"\"{d['ten_de_thi']}\" (tự động mở lúc {seal['thoi_diem_mo_hien_thi']})."
                    ),
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=d["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Tài liệu ({seal['loai']}) đang được khóa niêm phong bảo mật. "
                        "Không ai có quyền xem hoặc tải xuống "
                        f"trước thời điểm mở tự động ({seal['thoi_diem_mo_hien_thi']})."
                    ),
                )

            if int(d["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không được phép truy cập đề thi của môn học khác.")
            if int(d["ma_khoi"]) not in pq.get("danh_sach_khoi_duoc_phep", pq["danh_sach_khoi"]):
                raise HTTPException(status_code=403, detail="Bạn không được phép truy cập đề thi của khối lớp chưa phân quyền.")

            if (not _co_quyen_ra_de_khoi(pq, d["ma_khoi"])) and (not seal["da_mo"]):
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Truy cập trái phép",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Cảnh báo",
                    chi_tiet=(
                        f"Từ chối {_mo_ta_can_bo(phien)} truy cập tệp {seal['loai'].lower()} \"{d['ten_de_thi']}\" "
                        "do tài khoản không có quyền ra đề thi và chưa đến thời điểm mở."
                    ),
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=d.get("ten_tep_goc") or "",
                )
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản không có quyền ra đề thi chỉ được truy cập những đề thi đã đến giờ thi và các đáp án đã được mở.",
                )

            if mode != "inline":
                _bat_buoc_xac_minh_ma_pin(
                    request,
                    phien,
                    None,
                    f"Tải {seal['loai'].lower()} \"{d['ten_de_thi']}\"",
                    d["ten_tep_goc"],
                )

            base_dir = os.path.dirname(__file__)
            abs_path = os.path.join(base_dir, (d["duong_dan_tep"] or "").replace("/", os.sep))
            if not os.path.exists(abs_path):
                raise HTTPException(status_code=404, detail="Tệp đề thi mã hóa không tồn tại.")
            with open(abs_path, "rb") as f:
                ciphertext = f.read()

            raw_bytes = None
            if d["khoa_ma_hoa_de"] and d["ma_nonce_aes"] and d["the_xac_thuc_aes"]:
                raw_bytes = giai_ma_tep_de_thi_envelope(
                    ciphertext, d["khoa_ma_hoa_de"], d["ma_nonce_aes"], d["the_xac_thuc_aes"]
                )
            if raw_bytes is None:
                raw_bytes = giai_ma_tep_de(ciphertext)

            if raw_bytes is None or tinh_sha256_bytes(raw_bytes) != (d["ma_bam_sha256"] or "").strip():
                cur.execute("UPDATE DeThi SET bi_can_thiep = TRUE WHERE ma_de_thi = %s;", (ma_de_thi,))
                conn.commit()
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Can thiệp tệp đề",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Báo động",
                    chi_tiet=f"Báo động an ninh: Phát hiện tệp {seal['loai'].lower()} \"{d['ten_de_thi']}\" bị thay đổi trái phép trên máy chủ.",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=d["ten_tep_goc"],
                )
                raise HTTPException(status_code=500, detail="Cảnh báo: Phát hiện tệp đề thi bị can thiệp trái phép (sai lệch mã kiểm chứng toàn vẹn)!")

    if mode == "inline":
        ten_hd = "Xem đáp án" if seal["loai"] == "Đáp án" else "Xem đề thi"
        mo_ta_hd = "xem trực tuyến"
    else:
        ten_hd = "Tải đáp án" if seal["loai"] == "Đáp án" else "Tải đề thi"
        mo_ta_hd = "tải xuống"

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong=ten_hd,
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"{_mo_ta_can_bo(phien)} đã {mo_ta_hd} {seal['loai'].lower()} \"{d['ten_de_thi']}\".",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=d["ten_tep_goc"],
    )
    disp_type = "inline" if mode == "inline" else "attachment"
    safe_name = quote(d["ten_tep_goc"])
    return Response(
        content=raw_bytes,
        media_type=_kieu_mime_theo_ten_tep(d["ten_tep_goc"]),
        headers={"Content-Disposition": f"{disp_type}; filename*=UTF-8''{safe_name}"},
    )


static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/api/health")
def api_health():
    """Endpoint kiểm tra trạng thái sẵn sàng của dịch vụ cho Render Health Check."""
    return {"status": "OK"}


@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_path = os.path.join(static_dir, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(
            content=f.read(),
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
