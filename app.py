import os
import re
import uuid
import socket
import ipaddress
import threading
import time
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
from mailer import gui_mat_khau_khoi_tao
from security import (
    bam_mat_khau,
    kiem_tra_mat_khau,
    kiem_tra_do_manh_mat_khau,
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
    lay_tien_to_vai_tro,
    phan_tich_thiet_bi,
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
COOKIE_NAME = "hvt_session_token"
THOI_GIAN_KHOA_PHUT = 15
MUI_GIO_VN = timezone(timedelta(hours=7))

app = FastAPI(
    title="THPT Hoàng Văn Thụ - Hệ thống Quản lý và Phân phối Đề thi",
    description="Chức năng Đăng nhập và Bảo mật (CSDL PostgreSQL)",
)


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


class VerifyOtpRequest(BaseModel):
    ma_otp: str


class PhanQuyenKhoiItem(BaseModel):
    ma_khoi: int
    duoc_truy_cap_de_chung: bool = True
    duoc_truy_cap_de_chinh_thuc: bool = False


class UpdateAccountPermissionsRequest(BaseModel):
    ma_mon_hoc: int
    danh_sach_khoi: list[PhanQuyenKhoiItem]


class CreateAccountRequest(BaseModel):
    ma_can_bo: Optional[str] = None
    ho_ten: str
    ten_dang_nhap: str
    email: str
    vai_tro: str
    # Bỏ trống -> máy chủ tự sinh ngẫu nhiên mật khẩu tạm >= 10 ký tự (hoa, thường, số, ký tự đặc biệt)
    mat_khau_khoi_tao: Optional[str] = None
    # Cấu hình phân quyền truy cập theo khối và môn (bảng PhanQuyenTheoKhoiMon)
    ma_mon_hoc: Optional[int] = None
    danh_sach_khoi: Optional[list[PhanQuyenKhoiItem]] = None


class UnlockAccountRequest(BaseModel):
    cap_lai_mat_khau_tam: bool = False


class TempLockAccountRequest(BaseModel):
    so_phut: int = 15
    ly_do: Optional[str] = None


class IpBlockRequest(BaseModel):
    dia_chi_ip: str
    ly_do: Optional[str] = None


# =============================================================================
# LẤY ĐỊA CHỈ IP THỰC TẾ CỦA THIẾT BỊ KẾT NỐI VÀ KIỂM TRA PHIÊN TRONG CSDL
# =============================================================================
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


def lay_ip_client(request: Request):
    """Lấy IP máy trạm (ip_thiet_bi) và IPv4 kết nối thực tế (ipv4) từ Request."""
    ip_thiet_bi = _lay_ip_lan_thuc_te()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ipv4 = forwarded.split(",")[0].strip()
    elif request.client and request.client.host:
        client_host = request.client.host
        ipv4 = ip_thiet_bi if client_host in ("127.0.0.1", "::1", "localhost") else client_host
    else:
        ipv4 = ip_thiet_bi
    thiet_bi = phan_tich_thiet_bi(request.headers.get("User-Agent", ""), request.headers)
    return ip_thiet_bi, ipv4, thiet_bi


def _kiem_tra_ip_bi_chan(cur, ip_may: Optional[str], ipv4: Optional[str]):
    """Kiểm tra xem địa chỉ IP máy trạm hoặc IPv4 kết nối có đang nằm trong danh sách chặn ChanDiaChiIP không."""
    ips = [ip for ip in {str(ip_may or "").strip(), str(ipv4 or "").strip()} if ip]
    if not ips:
        return None
    cur.execute(
        """
        SELECT ma_chan_ip, host(dia_chi_ip) AS dia_chi_ip, ly_do, thoi_diem_chan
        FROM ChanDiaChiIP
        WHERE dang_chan = TRUE
          AND host(dia_chi_ip) = ANY(%s)
        LIMIT 1;
        """,
        (ips,),
    )
    return cur.fetchone()


def kiem_tra_phien_hien_tai(request: Request, yeu_cau_otp_hoan_tat: bool = True):
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
                    t.ma_can_bo, t.ten_dang_nhap, t.mat_khau, t.ho_ten, t.email, t.vai_tro,
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

            if chuan_hoa_vai_tro(phien["vai_tro"]) != "QUAN_TRI":
                chan_ip = _kiem_tra_ip_bi_chan(cur, ip_may, current_ipv4)
                if chan_ip:
                    cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                    conn.commit()
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "code": "IP_BLOCKED",
                            "message": f"Địa chỉ IP ({chan_ip['dia_chi_ip']}) đang bị chặn truy cập hệ thống vì lý do an ninh.",
                        },
                    )

            now_utc = datetime.now(timezone.utc)
            if now_utc > phien["thoi_diem_het_han"]:
                cur.execute("UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien = %s;", (phien["ma_phien"],))
                conn.commit()
                raise HTTPException(status_code=401, detail={"code": "EXPIRED_SESSION", "message": "Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại."})

            if current_ipv4 != phien["phien_ipv4"]:
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
                    chi_tiet=f"Phát hiện đổi địa chỉ IPv4 từ {phien['phien_ipv4']} sang {current_ipv4}. Phiên bị chặn ngay lập tức, yêu cầu xác thực lại thiết bị chính chủ.",
                    thong_tin_thiet_bi=thiet_bi,
                )
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": "IPV4_MISMATCH_HIJACK",
                        "message": "Phát hiện địa chỉ IPv4 thay đổi bất thường. Phiên làm việc đã bị khóa, vui lòng xác thực lại!",
                    },
                )

            if yeu_cau_otp_hoan_tat and (not phien["da_xac_thuc_otp"] or not phien["da_kich_hoat_otp"]):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "OTP_REQUIRED",
                        "da_kich_hoat_otp": bool(phien["da_kich_hoat_otp"]),
                        "message": "Bắt buộc hoàn tất xác thực OTP trước khi truy cập hệ thống.",
                    },
                )

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
                    email, vai_tro, bi_mat_otp_ma_hoa, da_kich_hoat_otp,
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
                chan_ip = _kiem_tra_ip_bi_chan(cur, ip_may, dia_chi_ipv4)
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
                        detail=f"Địa chỉ IP ({chan_ip['dia_chi_ip']}) đang bị chặn truy cập hệ thống vì lý do an ninh. Vui lòng liên hệ Quản trị viên.",
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
            thuoc_mang_truong = la_mang_noi_bo_truong(dia_chi_ipv4)

            dang_nhap_noi_bo_an_toan = da_kich_hoat and ip_khop and thuoc_mang_truong

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
                return {
                    "status": "OK",
                    "next_step": "DASHBOARD",
                    "message": "Đăng nhập thành công!",
                    "user": {
                        "ma_can_bo": acc["ma_can_bo"],
                        "ho_ten": acc["ho_ten"],
                        "ten_dang_nhap": acc["ten_dang_nhap"],
                        "email": acc["email"],
                        "vai_tro": acc["vai_tro"],
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
                    ket_qua="Yêu cầu kích hoạt 2FA",
                    chi_tiet="Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu",
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

            # Kịch bản 7 (TH3): Đăng nhập từ IP lạ / mạng ngoài trường / thiết bị mới (da_kich_hoat_otp = TRUE)
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
                ket_qua="Yêu cầu xác thực bước 2 (OTP)",
                chi_tiet="Đúng mật khẩu từ IP lạ ngoài trường, kích hoạt thử thách mã OTP 6 số",
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


def lay_thong_tin_phan_quyen_mon(cur, ma_tai_khoan, vai_tro: str):
    """
    Truy vấn bảng PhanQuyenTheoKhoiMon kết hợp MonHoc và KhoiLop của tài khoản đang đăng nhập.
    Giáo viên dạy môn nào chỉ được trả về đúng môn học và khối lớp đã phân quyền.
    """
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

    # Trường hợp tài khoản Quản trị / BGH hoặc tài khoản mới tạo chưa gắn dòng PhanQuyenTheoKhoiMon
    cur.execute("SELECT ma_mon_hoc, ky_hieu_mon, ten_mon_hoc FROM MonHoc WHERE ma_mon_hoc = 1 LIMIT 1;")
    mh = cur.fetchone() or {"ma_mon_hoc": 1, "ky_hieu_mon": "TOAN", "ten_mon_hoc": "Toán học"}
    la_quan_tri = chuan_hoa_vai_tro(vai_tro) in ("QUAN_TRI", "BAN_GIAM_HIEU")
    return {
        "ma_mon_hoc": int(mh["ma_mon_hoc"]),
        "ky_hieu_mon": mh["ky_hieu_mon"],
        "ten_mon_hoc": mh["ten_mon_hoc"],
        "ten_mon_ngan": _TEN_MON_NGAN.get(mh["ky_hieu_mon"], mh["ten_mon_hoc"]),
        "danh_sach_khoi": [10, 11, 12] if la_quan_tri else [],
        "danh_sach_khoi_duoc_phep": [10, 11, 12] if la_quan_tri else [],
        "danh_sach_khoi_chinh_thuc": [10, 11, 12] if la_quan_tri else [],
        "duoc_truy_cap_de_chung": la_quan_tri,
        "duoc_truy_cap_de_chinh_thuc": la_quan_tri,
        "chi_tiet_phan_quyen": [],
    }


@app.get("/api/auth/session-status")
def api_session_status(request: Request):
    """Lấy trạng thái phiên hiện tại và phân quyền môn học từ CSDL PostgreSQL."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=False)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
    return {
        "authenticated": True,
        "da_xac_thuc_otp": bool(phien["da_xac_thuc_otp"]),
        "da_kich_hoat_otp": bool(phien["da_kich_hoat_otp"]),
        "phan_quyen_mon": pq,
        "user": {
            "ma_tai_khoan": str(phien["ma_tai_khoan"]),
            "ma_can_bo": phien["ma_can_bo"],
            "ho_ten": phien["ho_ten"],
            "ten_dang_nhap": phien["ten_dang_nhap"],
            "email": phien["email"],
            "vai_tro": phien["vai_tro"],
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
            detail="Niêm phong khóa: Tài khoản này đã kích hoạt 2FA (da_kich_hoat_otp = TRUE). Mã QR và chuỗi khóa đã bị ẩn vĩnh viễn.",
        )

    secret_base32 = _lay_hoac_sinh_bi_mat_otp(phien)
    otpauth_uri = lay_totp_uri(secret_base32, phien["email"], phien["ho_ten"])
    qr_data_url = tao_anh_qr_base64(otpauth_uri)

    so_lan_sai_otp = int(phien["so_lan_sai_otp"] or 0)
    return {
        "ho_ten": phien["ho_ten"],
        "ma_can_bo": phien["ma_can_bo"],
        "email": phien["email"],
        "vai_tro": phien["vai_tro"],
        "secret_base32": secret_base32,
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

    mat_khau_bam_moi = bam_mat_khau(req.mat_khau_moi)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE TaiKhoan
                SET mat_khau = %s,
                    da_kich_hoat_otp = TRUE,
                    so_lan_sai_otp = 0,
                    so_lan_dang_nhap_sai = 0,
                    khoa_den_thoi_diem = NULL,
                    ip_thiet_bi_gan_nhat = %s,
                    ipv4_gan_nhat = %s
                WHERE ma_tai_khoan = %s;
                """,
                (mat_khau_bam_moi, ip_may, dia_chi_ipv4, phien["ma_tai_khoan"]),
            )
            cur.execute(
                """
                UPDATE PhienDangNhap
                SET da_xac_thuc_otp = TRUE,
                    thoi_diem_het_han = thoi_diem_tao + INTERVAL '8 hours'
                WHERE ma_phien = %s;
                """,
                (phien["ma_phien"],),
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

    return {
        "status": "OK",
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
                    thoi_diem_het_han = thoi_diem_tao + INTERVAL '8 hours'
                WHERE ma_phien = %s;
                """,
                (phien["ma_phien"],),
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

    return {
        "status": "OK",
        "message": "Đăng nhập thành công!",
    }


@app.post("/api/auth/logout")
def api_logout(request: Request, response: Response):
    """Đánh dấu PhienDangNhap.da_thu_hoi = TRUE trong CSDL khi đăng xuất."""
    raw_token = request.cookies.get(COOKIE_NAME)
    if raw_token:
        token_hash = bam_session_token(raw_token)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE PhienDangNhap SET da_thu_hoi = TRUE WHERE ma_phien_bam = %s;",
                    (token_hash,),
                )
            conn.commit()
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
    - Email nội bộ: <tên đăng nhập>@thpthoangvanthu.edu.vn
    - Mật khẩu khởi tạo: sinh ngẫu nhiên >= 10 ký tự (hoa, thường, số, ký tự đặc biệt).
    """
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
            if ho_ten_chuan:
                goc = tao_ten_dang_nhap_tu_ho_ten(ho_ten_chuan, ma_vai_tro)
                ten_dang_nhap, stt = goc, 1
                while _da_ton_tai(cur, "ten_dang_nhap", ten_dang_nhap) or _da_ton_tai(
                    cur, "email", f"{ten_dang_nhap}@thpthoangvanthu.edu.vn"
                ):
                    stt += 1
                    ten_dang_nhap = f"{goc}{stt}"

    email = f"{ten_dang_nhap}@thpthoangvanthu.edu.vn" if ten_dang_nhap else ""
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
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
                    bi_khoa,
                    COALESCE(so_lan_dang_nhap_sai, 0) AS so_lan_dang_nhap_sai,
                    COALESCE(so_lan_sai_otp, 0) AS so_lan_sai_otp,
                    host(ip_thiet_bi_gan_nhat) AS ip_thiet_bi_gan_nhat,
                    host(ipv4_gan_nhat) AS ipv4_gan_nhat,
                    to_char(thoi_diem_tao AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_diem_tao,
                    dang_hoat_dong,
                    khoa_den_thoi_diem,
                    (bi_mat_otp_ma_hoa IS NOT NULL) AS co_bi_mat_otp,
                    '\\x' || encode(substring(bi_mat_otp_ma_hoa from 1 for 14), 'hex') AS bi_mat_otp_hex
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


_NHAN_VAI_TRO_LOG = {"GIAO_VIEN": "GiaoVien", "BAN_GIAM_HIEU": "BanGiamHieu", "QUAN_TRI": "QuanTri"}


@app.post("/api/accounts")
def api_create_account(req: CreateAccountRequest, request: Request):
    """
    Chức năng 'Cấp phát tài khoản cho giáo viên mới' (CN_CapTaiKhoanMoi) - Kịch bản 9 & Kịch bản 10:
    - Điều kiện: Quản trị viên đã đăng nhập phiên hợp lệ (vai_tro = 'QUAN_TRI', da_xac_thuc_otp = TRUE).
    - Kiểm tra & chuẩn hóa toàn bộ trường nhập liệu trên giao diện.
    - Các trường hệ thống tự thiết lập ngầm: ma_tai_khoan = gen_random_uuid(), thoi_diem_tao = CURRENT_TIMESTAMP,
      dang_hoat_dong = TRUE, bi_khoa = FALSE, da_kich_hoat_otp = FALSE, so_lan_dang_nhap_sai = 0, so_lan_sai_otp = 0,
      ip_thiet_bi_gan_nhat = NULL, ipv4_gan_nhat = NULL, khoa_den_thoi_diem = NULL.
    - Giai đoạn 1: Sinh chuỗi Base32 16 ký tự, mã hóa AES-256 bằng khóa chủ và cất vào bi_mat_otp_ma_hoa (BYTEA).
    - Ghi NhatKyLog (hanh_dong = 'Tạo tài khoản') cho cả trường hợp thành công lẫn thất bại,
      ma_tai_khoan = mã của Quản trị viên đang thao tác.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

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
        """Kịch bản 10: Không ghi bản ghi TaiKhoan, ghi NhatKyLog ket_qua = 'Thất bại'."""
        ghi_log_tao_tk("Thất bại", chi_tiet_log)
        raise HTTPException(status_code=status_code, detail=thong_bao_giao_dien)

    ho_ten = chuan_hoa_ho_ten(req.ho_ten)
    ma_vai_tro = chuan_hoa_vai_tro(req.vai_tro)
    ten_dang_nhap = (req.ten_dang_nhap or "").strip()
    email = (req.email or "").strip().lower()
    mat_khau_khoi_tao = (req.mat_khau_khoi_tao or "").strip() or sinh_mat_khau_tam(12)

    if not ma_vai_tro:
        that_bai(
            400,
            "Lỗi: Vai trò hệ thống chỉ được chọn 1 trong 3 giá trị GIAO_VIEN, BAN_GIAM_HIEU, QUAN_TRI. Vui lòng kiểm tra lại!",
            f"Tạo tài khoản thất bại: Dữ liệu vai_tro [{req.vai_tro}] không hợp lệ",
        )
    if not ho_ten:
        that_bai(400, "Lỗi: Vui lòng nhập Họ và tên giáo viên!", "Tạo tài khoản thất bại: Dữ liệu ho_ten bị bỏ trống")

    prefix_cb, _ = lay_tien_to_vai_tro(ma_vai_tro)
    ma_can_bo = (req.ma_can_bo or "").strip().upper() or sinh_ma_can_bo_ngau_nhien(ma_vai_tro)
    if not re.fullmatch(rf"{prefix_cb}\d{{7}}", ma_can_bo):
        that_bai(
            400,
            f"Lỗi: Mã cán bộ phải theo định dạng '{prefix_cb} + 7 chữ số' (VD: {prefix_cb}1004589). Vui lòng kiểm tra lại!",
            f"Tạo tài khoản thất bại: Dữ liệu ma_can_bo [{ma_can_bo}] sai định dạng",
        )

    if not re.fullmatch(r"[a-z0-9.]+", ten_dang_nhap):
        that_bai(
            400,
            "Lỗi: Tên đăng nhập phải viết thường, không dấu, không khoảng trắng, chỉ gồm chữ cái, số và dấu chấm. Vui lòng kiểm tra lại!",
            f"Tạo tài khoản thất bại: Dữ liệu ten_dang_nhap [{ten_dang_nhap}] sai định dạng",
        )

    # Kịch bản 10: Email không có đuôi @thpthoangvanthu.edu.vn
    if not re.fullmatch(r"[a-z0-9._%+-]+@thpthoangvanthu\.edu\.vn", email):
        that_bai(
            400,
            "Lỗi: Email phải có đuôi @thpthoangvanthu.edu.vn. Vui lòng kiểm tra lại!",
            f"Tạo tài khoản thất bại: Dữ liệu email [{email}] không có đuôi @thpthoangvanthu.edu.vn",
        )

    hop_le, thong_bao = kiem_tra_mat_khau_khoi_tao(mat_khau_khoi_tao)
    if not hop_le:
        that_bai(400, f"Lỗi: {thong_bao}", "Tạo tài khoản thất bại: Dữ liệu mat_khau không đạt độ mạnh tối thiểu")

    # Kịch bản 10: ma_can_bo / ten_dang_nhap / email đã tồn tại trong bảng TaiKhoan + kiểm tra phân quyền khối môn
    mon_phan_quyen = None
    ds_khoi_phan_quyen = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            for cot, gia_tri in (("ma_can_bo", ma_can_bo), ("ten_dang_nhap", ten_dang_nhap), ("email", email)):
                if _da_ton_tai(cur, cot, gia_tri):
                    that_bai(
                        409,
                        f"Lỗi: {_COT_KIEM_TRA_TRUNG[cot]} [{gia_tri}] này đã tồn tại trong hệ thống. Vui lòng kiểm tra lại!",
                        f"Tạo tài khoản thất bại: Dữ liệu {cot} [{gia_tri}] đã tồn tại",
                    )

            if ma_vai_tro == "GIAO_VIEN" and (req.ma_mon_hoc is not None or req.danh_sach_khoi is not None):
                ok_pq, loi_pq, mon_phan_quyen, ds_khoi_phan_quyen = _kiem_tra_va_chuan_hoa_phan_quyen(
                    cur, req.ma_mon_hoc, req.danh_sach_khoi
                )
                if not ok_pq:
                    that_bai(
                        400,
                        f"Lỗi: {loi_pq}",
                        f"Tạo tài khoản thất bại: Cấu hình phân quyền khối và môn không hợp lệ ({loi_pq})",
                    )

    # Giai đoạn 1: Sinh chuỗi Base32 16 ký tự và mã hóa AES-256 với khóa chủ của hệ thống
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
                    "Tạo tài khoản thất bại: Dữ liệu ma_can_bo/ten_dang_nhap/email đã tồn tại",
                )

    mo_ta_pq_log = ""
    if mon_phan_quyen and ds_khoi_phan_quyen:
        khoi_txt = ", ".join(x["ten_khoi"] for x in ds_khoi_phan_quyen)
        quyen_txt = []
        if any(x["duoc_truy_cap_de_chung"] for x in ds_khoi_phan_quyen):
            quyen_txt.append("Đề chung")
        if any(x["duoc_truy_cap_de_chinh_thuc"] for x in ds_khoi_phan_quyen):
            quyen_txt.append("Đề chính thức")
        mo_ta_pq_log = f", Phân quyền [{mon_phan_quyen['ten_mon_hoc']} - {khoi_txt} ({' + '.join(quyen_txt) or 'Chỉ xem'})]"

    # Kịch bản 9: Ghi NhatKyLog thành công (ma_tai_khoan = Quản trị viên đang thao tác)
    ghi_log_tao_tk(
        "Thành công",
        f"Admin tạo tài khoản mới: Mã CB [{ma_can_bo}], Tên đăng nhập [{ten_dang_nhap}], "
        f"Vai trò [{_NHAN_VAI_TRO_LOG[ma_vai_tro]}], Email [{email}]{mo_ta_pq_log}",
    )

    # Gửi mật khẩu khởi tạo tạm thời đến email giáo viên qua SMTP thật
    da_gui_email, thong_tin_email = gui_mat_khau_khoi_tao(email, ho_ten, ten_dang_nhap, mat_khau_khoi_tao)
    if da_gui_email:
        return {
            "status": "OK",
            "email_sent": True,
            "message": "Cấp tài khoản mới thành công! Hệ thống đã gửi mật khẩu khởi tạo tạm thời đến email của giáo viên.",
            "account": new_acc,
        }
    return {
        "status": "OK",
        "email_sent": False,
        "message": (
            "Cấp tài khoản mới thành công! Tuy nhiên CHƯA gửi được email cho giáo viên "
            f"({thong_tin_email}) Vui lòng bàn giao trực tiếp mật khẩu tạm bên dưới."
        ),
        "account": new_acc,
        # Chỉ trả về mật khẩu tạm khi không gửi được email để Quản trị viên bàn giao; CSDL chỉ lưu mã băm Bcrypt
        "mat_khau_khoi_tao": mat_khau_khoi_tao,
    }


@app.put("/api/accounts/{ma_tai_khoan}/permissions")
def api_update_account_permissions(ma_tai_khoan: str, req: UpdateAccountPermissionsRequest, request: Request):
    """Cập nhật cấu hình bảng PhanQuyenTheoKhoiMon cho tài khoản giáo viên."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thay đổi phân quyền hệ thống.")

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
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
                raise HTTPException(
                    status_code=400,
                    detail="Chỉ áp dụng phân quyền theo khối và môn cho tài khoản có vai trò Giáo viên.",
                )

            ok_pq, loi_pq, mon_phan_quyen, ds_khoi_phan_quyen = _kiem_tra_va_chuan_hoa_phan_quyen(
                cur, req.ma_mon_hoc, req.danh_sach_khoi
            )
            if not ok_pq:
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
    quyen_txt = []
    if any(x["duoc_truy_cap_de_chung"] for x in ds_khoi_phan_quyen):
        quyen_txt.append("Đề chung")
    if any(x["duoc_truy_cap_de_chinh_thuc"] for x in ds_khoi_phan_quyen):
        quyen_txt.append("Đề chính thức")

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Phân quyền khối và môn",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"Quản trị viên {phien['ma_can_bo']} cập nhật phân quyền cho {target['ma_can_bo']} ({target['ho_ten']}): "
            f"{mon_phan_quyen['ten_mon_hoc']} - {khoi_txt} ({' + '.join(quyen_txt) or 'Chỉ xem'})"
        ),
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": f"Đã cập nhật phân quyền môn {mon_phan_quyen['ten_mon_hoc']} ({khoi_txt}) cho giáo viên {target['ho_ten']}.",
    }


@app.post("/api/accounts/{ma_tai_khoan}/reset-2fa")
def api_reset_2fa(ma_tai_khoan: str, request: Request):
    """
    Kịch bản 12: Đặt lại 2FA
    - Sinh ngẫu nhiên chuỗi Base32 mới, mã hóa AES-256 ghi đè vào bi_mat_otp_ma_hoa.
    - Chuyển da_kich_hoat_otp = FALSE, so_lan_sai_otp = 0, bi_khoa = FALSE (giữ nguyên mat_khau cá nhân của giáo viên).
    - Cưỡng chế thu hồi toàn bộ phiên cũ trong PhienDangNhap (da_thu_hoi = TRUE).
    - Ghi NhatKyLog: hanh_dong = 'Đặt lại 2FA và Cấp lại mật khẩu', ket_qua = 'Thành công'.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    new_secret = sinh_khoa_bi_mat_totp(16)
    encrypted_secret = ma_hoa_bi_mat_otp(new_secret)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ma_can_bo, ho_ten, ten_dang_nhap, email, dang_hoat_dong FROM TaiKhoan WHERE ma_tai_khoan = %s;",
                (ma_tai_khoan,),
            )
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản trong CSDL.")
            if not target["dang_hoat_dong"]:
                raise HTTPException(status_code=400, detail="Tài khoản đang ở trạng thái ngừng hoạt động, không thể đặt lại 2FA.")

            cur.execute(
                """
                UPDATE TaiKhoan
                SET bi_mat_otp_ma_hoa = %s,
                    da_kich_hoat_otp = FALSE,
                    so_lan_sai_otp = 0,
                    bi_khoa = FALSE,
                    khoa_den_thoi_diem = NULL
                WHERE ma_tai_khoan = %s
                RETURNING ma_can_bo, ho_ten, ten_dang_nhap, email;
                """,
                (psycopg2.Binary(encrypted_secret), ma_tai_khoan),
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

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Đặt lại 2FA và Cấp lại mật khẩu",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"Admin {phien['ma_can_bo']} thực hiện Đặt lại 2FA và Cấp lại mật khẩu tạm "
            f"cho giáo viên {updated['ma_can_bo']} ({updated['email']}). Đã thu hồi toàn bộ phiên làm việc cũ"
        ),
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": (
            "Đặt lại xác thực 2 bước (2FA) thành công! Khóa bảo mật cũ đã bị hủy và toàn bộ các phiên làm việc "
            "đã được thu hồi. Cán bộ sẽ được yêu cầu quét mã QR mới ở lần đăng nhập tiếp theo."
        ),
    }


@app.post("/api/accounts/{ma_tai_khoan}/deactivate")
def api_deactivate_account(ma_tai_khoan: str, request: Request):
    """
    Kịch bản 12 (Tạm ngưng hoạt động) & Kịch bản 13 (Admin tự thao tác chỉnh tạm ngừng chính tài khoản của mình):
    - Nếu ma_tai_khoan trùng với tài khoản Admin đang thao tác -> Từ chối, ghi NhatKyLog ket_qua = 'Từ chối'.
    - Nếu hợp lệ -> Cập nhật TaiKhoan.dang_hoat_dong = FALSE, thu hồi toàn bộ PhienDangNhap (da_thu_hoi = TRUE),
      ghi NhatKyLog hanh_dong = 'Ngừng hoạt động', ket_qua = 'Thành công'.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    # Kịch bản 13: Admin tự thao tác chỉnh tạm ngừng chính tài khoản của mình
    if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Ngừng hoạt động",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Từ chối",
            chi_tiet=f"Phát hiện hành vi tự tạm ngưng tài khoản quản trị viên {phien['ma_can_bo']}, {phien['ho_ten']}",
            thong_tin_thiet_bi=thiet_bi,
        )
        raise HTTPException(
            status_code=400,
            detail="Lỗi bảo vệ: Hệ thống không cho phép Quản trị viên tự tạm ngưng khoản của chính mình!",
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
        chi_tiet=f"Admin {phien['ma_can_bo']} đã ngừng trạng thái hoạt động của tài khoản {updated['ma_can_bo']} ({updated['email']}) này",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": (
            f"Đã tạm ngưng hoạt động tài khoản của giáo viên {updated['ho_ten']} ({updated['ma_can_bo']}) thành công! "
            "Toàn bộ phiên làm việc của tài khoản này đã được thu hồi ngay lập tức."
        ),
    }


@app.post("/api/accounts/{ma_tai_khoan}/activate")
def api_activate_account(ma_tai_khoan: str, request: Request):
    """Kích hoạt lại tài khoản đã bị vô hiệu hóa: dang_hoat_dong = TRUE."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
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
        chi_tiet=f"Admin {phien['ma_can_bo']} đã kích hoạt lại trạng thái hoạt động của tài khoản {updated['ma_can_bo']} ({updated['email']})",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "message": f"Đã kích hoạt lại tài khoản của cán bộ {updated['ho_ten']} ({updated['ma_can_bo']}) thành công!",
    }


@app.post("/api/accounts/{ma_tai_khoan}/unlock")
def api_unlock_account(ma_tai_khoan: str, req: UnlockAccountRequest, request: Request):
    """
    Kịch bản 11: Cấp lại mật khẩu tạm thời (khi cap_lai_mat_khau_tam = TRUE) hoặc Mở khóa an ninh thủ công:
    - Sinh ngẫu nhiên mật khẩu tạm mới, băm Bcrypt kèm Salt ghi đè vào cột mat_khau.
    - Đặt so_lan_dang_nhap_sai = 0, so_lan_sai_otp = 0, bi_khoa = FALSE, khoa_den_thoi_diem = NULL.
    - Giữ nguyên tuyệt đối bi_mat_otp_ma_hoa và da_kich_hoat_otp.
    - Thu hồi toàn bộ phiên cũ trong PhienDangNhap (da_thu_hoi = TRUE).
    - Ghi NhatKyLog: hanh_dong = 'Cấp lại mật khẩu', ket_qua = 'Thành công'.
    - Gửi email mật khẩu khởi tạo ngẫu nhiên mới đến email nội bộ của cán bộ và trả về mật khẩu tạm để hiển thị modal sao chép.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
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
                f"Admin {phien['ma_can_bo']} cấp lại mật khẩu tạm cho giáo viên "
                f"{updated['ma_can_bo']} ({updated['email']}). Đã thu hồi toàn bộ phiên làm việc cũ"
            ),
            thong_tin_thiet_bi=thiet_bi,
        )
        da_gui_email, _ = gui_mat_khau_khoi_tao(
            updated["email"], updated["ho_ten"], updated["ten_dang_nhap"], mat_khau_moi
        )
        thong_bao = (
            "Cấp lại mật khẩu tạm thời thành công! Mật khẩu khởi tạo ngẫu nhiên mới "
            "đã được gửi đến email nội bộ của cán bộ."
        )
        return {
            "status": "OK",
            "email_sent": da_gui_email,
            "message": thong_bao,
            "mat_khau_khoi_tao": mat_khau_moi,
        }

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Mở khóa tài khoản",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Quản trị viên {phien['ma_can_bo']} đã mở khóa an ninh tài khoản {updated['ma_can_bo']} ({updated['ho_ten']})",
        thong_tin_thiet_bi=thiet_bi,
    )
    thong_bao = f"Đã mở khóa tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}) thành công!"
    return {"status": "OK", "message": thong_bao, "mat_khau_khoi_tao": None}


@app.post("/api/accounts/{ma_tai_khoan}/temp-lock")
def api_temp_lock_account(ma_tai_khoan: str, req: TempLockAccountRequest, request: Request):
    """
    Tạm khóa tài khoản giáo viên trực tiếp từ Modal Chi tiết điều tra Nhật ký hoạt động:
    - Chặn Quản trị viên tự khóa tài khoản của chính mình.
    - Đặt bi_khoa = TRUE, khoa_den_thoi_diem = NOW() + so_phut (hoặc NULL nếu so_phut <= 0: khóa đến khi mở thủ công).
    - Cưỡng chế thu hồi toàn bộ phiên đăng nhập của tài khoản trong PhienDangNhap.
    - Ghi nhận vào NhatKyLog.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    if chuan_hoa_vai_tro(phien["vai_tro"]) == "GIAO_VIEN":
        raise HTTPException(status_code=403, detail="Bạn không có quyền thực hiện thao tác quản trị này.")

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    if str(phien["ma_tai_khoan"]) == ma_tai_khoan:
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Tạm khóa tài khoản",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Từ chối",
            chi_tiet=f"Ngăn chặn hành vi tự khóa tài khoản quản trị viên đang đăng nhập ({phien['ma_can_bo']} - {phien['ho_ten']})",
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
    ly_do_str = f" - Lý do: {req.ly_do.strip()}" if (req.ly_do and req.ly_do.strip()) else ""
    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Tạm khóa tài khoản",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=(
            f"Quản trị viên {phien['ma_can_bo']} đã tạm khóa tài khoản {updated['ma_can_bo']} "
            f"({updated['ho_ten']}) trong {mo_ta_thoi_han} và thu hồi toàn bộ phiên làm việc{ly_do_str}"
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
def api_clear_trusted_ip(ma_tai_khoan: str, request: Request):
    """
    Xóa IP tin cậy (ip_thiet_bi_gan_nhat = NULL, ipv4_gan_nhat = NULL) trong bảng TaiKhoan
    để kiểm thử Kịch bản 7 (TH3: Đăng nhập từ IP lạ / thiết bị mới, yêu cầu nhập 6 số OTP mà không hiện QR).
    """
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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

    return {
        "status": "OK",
        "message": (
            f"Đã xóa IP tin cậy của tài khoản {updated['ho_ten']} ({updated['ma_can_bo']}). "
            "Lần đăng nhập tiếp theo sẽ kích hoạt Kịch bản 7 (TH3): Yêu cầu nhập 6 số OTP (không hiện mã QR)."
        ),
    }


# =============================================================================
# 3. API NHẬT KÝ LOG TRỰC TIẾP TỪ BẢNG NhatKyLog (MỤC 1, 3, 4)
# =============================================================================
def _truy_van_danh_sach_nhat_ky(cur, ma_nhat_ky: Optional[int] = None):
    """
    Truy vấn bảng NhatKyLog kèm đối chiếu chuỗi băm liên kết (ma_bam_truoc & ma_bam_nhat_ky),
    thông tin giáo viên, bộ môn phân công, khối lớp giảng dạy, trạng thái 2FA và trạng thái chặn IP.
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
                n.chi_tiet,
                n.thoi_diem,
                n.ma_bam_nhat_ky,
                LAG(n.ma_bam_nhat_ky, 1, repeat('0', 64)) OVER (ORDER BY n.ma_nhat_ky ASC) AS bam_truoc_ky_vong,
                fn_tinh_bam_nhat_ky_log(
                    n.ma_nhat_ky, n.ma_bam_truoc, n.ma_tai_khoan,
                    n.hanh_dong, n.ip_thiet_bi, n.ipv4, n.ket_qua, n.chi_tiet, n.thoi_diem
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
            c.chi_tiet,
            to_char(c.thoi_diem AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS') AS thoi_gian_hien_thi,
            (c.ma_bam_truoc = c.bam_truoc_ky_vong AND c.ma_bam_nhat_ky = c.bam_nhat_ky_ky_vong) AS toan_ven_chuoi,
            CASE
                WHEN c.ma_bam_truoc = c.bam_truoc_ky_vong AND c.ma_bam_nhat_ky = c.bam_nhat_ky_ky_vong
                THEN 'Toàn vẹn'
                ELSE 'Nhật ký bị can thiệp'
            END AS trang_thai_chuoi,
            COALESCE(
                pc.bo_mon_phan_cong,
                CASE
                    WHEN t.vai_tro = 'QUAN_TRI' THEN 'Quản trị hệ thống (Toàn trường)'
                    WHEN t.vai_tro = 'BAN_GIAM_HIEU' THEN 'Ban Giám hiệu (Toàn trường)'
                    WHEN t.ma_tai_khoan IS NOT NULL THEN 'Chưa phân công bộ môn'
                    ELSE 'Không xác định'
                END
            ) AS bo_mon_phan_cong,
            COALESCE(
                pc.khoi_lop_giang_day,
                CASE
                    WHEN t.vai_tro IN ('QUAN_TRI', 'BAN_GIAM_HIEU') THEN 'Khối 10, Khối 11, Khối 12'
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
                    COUNT(*) FILTER (WHERE ket_qua = 'Báo động') AS bao_dong
                FROM NhatKyLog;
                """
            )
            stats = cur.fetchone()
            logs = _truy_van_danh_sach_nhat_ky(cur)
            return {"stats": stats, "logs": logs}


@app.get("/api/logs/verify-chain")
def api_verify_hash_chain(request: Request):
    """Kiểm tra tính toàn vẹn chuỗi băm SHA-256 trong bảng NhatKyLog."""
    kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    ma_nhat_ky,
                    ma_bam_truoc,
                    ma_bam_nhat_ky,
                    fn_tinh_bam_nhat_ky_log(
                        ma_nhat_ky, ma_bam_truoc, ma_tai_khoan,
                        hanh_dong, ip_thiet_bi, ipv4, ket_qua, chi_tiet, thoi_diem
                    ) AS ma_bam_tinh_lai
                FROM NhatKyLog
                ORDER BY ma_nhat_ky ASC;
                """
            )
            rows = cur.fetchall()

    expected_prev = "0" * 64
    broken_at = None
    for r in rows:
        if r["ma_bam_truoc"] != expected_prev or r["ma_bam_nhat_ky"] != r["ma_bam_tinh_lai"]:
            broken_at = r["ma_nhat_ky"]
            break
        expected_prev = r["ma_bam_nhat_ky"]

    return {
        "valid": broken_at is None,
        "total_records": len(rows),
        "broken_at_id": broken_at,
        "latest_seal_hash": expected_prev if rows else ("0" * 64),
        "message": (
            f"Chuỗi băm niêm phong SHA-256 toàn vẹn ({len(rows)} bản ghi trong CSDL)."
            if broken_at is None
            else f"Phát hiện đứt gãy chuỗi băm tại bản ghi #{broken_at}!"
        ),
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
        hanh_dong="Chặn địa chỉ IP",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Quản trị viên {phien['ma_can_bo']} đã chặn địa chỉ IP {ip_hop_le} ({ly_do}). Đã thu hồi {so_phien_thu_hoi} phiên hoạt động.",
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

    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ChanDiaChiIP
                SET dang_chan = FALSE
                WHERE dia_chi_ip = %s::inet;
                """,
                (ip_hop_le,),
            )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Gỡ chặn địa chỉ IP",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Quản trị viên {phien['ma_can_bo']} đã gỡ chặn địa chỉ IP {ip_hop_le}",
        thong_tin_thiet_bi=thiet_bi,
    )

    return {
        "status": "OK",
        "dia_chi_ip": ip_hop_le,
        "ip_dang_bi_chan": False,
        "message": f"Đã gỡ chặn địa chỉ IP {ip_hop_le} thành công.",
    }


@app.get("/api/sessions")
def api_list_sessions(request: Request):
    """Truy vấn trực tiếp bảng PhienDangNhap trong PostgreSQL."""
    phien_hien_tai = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    with get_conn() as conn:
        with conn.cursor() as cur:
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
                    (p.thoi_diem_het_han > NOW()) AS con_han
                FROM PhienDangNhap p
                JOIN TaiKhoan t ON t.ma_tai_khoan = p.ma_tai_khoan
                ORDER BY p.thoi_diem_tao DESC;
                """
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
    các môn khác không được hiển thị.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
                if r["da_chinh_sua"] and r.get("ho_ten_nguoi_cap_nhat"):
                    r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                        r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                    )
                    r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
                else:
                    r["nguoi_cap_nhat"] = None
                    r["ho_ten_nguoi_cap_nhat"] = None
                    r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                    r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
                r["duoc_phep_chinh_sua"] = str(r["nguoi_tao"]) == str(phien["ma_tai_khoan"])
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
            if r["da_chinh_sua"] and r.get("ho_ten_nguoi_cap_nhat"):
                r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                )
                r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
            else:
                r["nguoi_cap_nhat"] = None
                r["ho_ten_nguoi_cap_nhat"] = None
                r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
            r["duoc_phep_chinh_sua"] = str(r["nguoi_tao"]) == str(phien["ma_tai_khoan"])
            r.update(_kiem_tra_toan_ven_tep_on_tap(r["duong_dan_tep"], r["ma_bam_sha256"], r["da_chinh_sua"]))
            return {"item": r}


@app.post("/api/de-on-tap")
async def api_create_de_on_tap(
    request: Request,
    ten_de_on_tap: str = Form(...),
    ma_khoi: int = Form(...),
    loai_de: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Thêm đề ôn tập mới (CN_DeOnTap.docx):
    - Môn học tự động xác định theo tài khoản của giáo viên (PhanQuyenTheoKhoiMon).
    - Người tạo & Người cập nhật tự lấy từ tài khoản đang đăng nhập.
    - Tính mã băm SHA-256 của tệp gốc, mã hóa AES-256 trước khi lưu xuống duong_dan_tep.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} tải lên đề ôn tập [{ten_de}] (Khối {ma_khoi} - {loai}), SHA-256: {sha256_hex[:16]}...",
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
    file: Optional[UploadFile] = File(None),
):
    """
    Khi giáo viên muốn cập nhật đề (CN_DeOnTap.docx):
    Giáo viên đăng nhập -> Kiểm tra quyền cập nhật -> Tải file mới -> Tính SHA-256 file mới
    -> Cập nhật ma_bam_sha256 -> Lưu thời điểm cập nhật & người cập nhật
    -> Đổi trạng thái 'Toàn vẹn' => 'Đã bị chỉnh sửa' (da_chinh_sua = TRUE).
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
                "SELECT ma_de_on_tap, ma_mon_hoc, nguoi_tao::text AS nguoi_tao, duong_dan_tep, ten_tep_goc, ma_bam_sha256 FROM DeOnTap WHERE ma_de_on_tap = %s;",
                (ma_de_on_tap,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề ôn tập cần cập nhật.")
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"] or not pq["duoc_truy_cap_de_chung"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền cập nhật đề ôn tập của môn học khác.")
            if str(existing["nguoi_tao"]) != str(phien["ma_tai_khoan"]):
                raise HTTPException(
                    status_code=403,
                    detail="Bạn chỉ được phép chỉnh sửa tài liệu đề ôn tập do chính mình tải lên. Tài liệu của giáo viên khác chỉ có quyền xem.",
                )
            if int(ma_khoi) not in pq["danh_sach_khoi"]:
                raise HTTPException(status_code=403, detail=f"Bạn không có quyền cập nhật đề cho Khối {ma_khoi}.")

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
        hanh_dong="Cập nhật đề ôn tập",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} cập nhật đề ôn tập [{ten_de}] (Khối {ma_khoi} - {loai}), SHA-256 mới: {sha256_moi[:16]}...",
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
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền xóa đề ôn tập của môn khác.")
            if str(existing["nguoi_tao"]) != str(phien["ma_tai_khoan"]):
                raise HTTPException(
                    status_code=403,
                    detail="Bạn chỉ được phép xóa tài liệu đề ôn tập do chính mình tải lên.",
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
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} đã xóa đề ôn tập [{existing['ten_de_on_tap']}]",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=existing["ten_tep_goc"],
    )
    return {"status": "OK", "message": f"Đã xóa đề ôn tập '{existing['ten_de_on_tap']}'."}


@app.get("/api/de-on-tap/{ma_de_on_tap}/file")
def api_download_de_on_tap_file(ma_de_on_tap: str, request: Request, mode: str = "attachment"):
    """Giải mã AES-256 trên RAM và phục vụ Xem trước (inline) hoặc Tải xuống (attachment) tệp đề ôn tập."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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

    base_dir = os.path.dirname(__file__)
    abs_path = os.path.join(base_dir, r["duong_dan_tep"].replace("/", os.sep))
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail="Tệp đề mã hóa không tồn tại trên máy chủ.")

    with open(abs_path, "rb") as f:
        enc_bytes = f.read()
    raw_bytes = giai_ma_tep_de(enc_bytes)
    if raw_bytes is None:
        raise HTTPException(status_code=500, detail="Cảnh báo an ninh: Giải mã tệp đề thất bại (tệp có dấu hiệu bị can thiệp).")

    if mode == "attachment":
        ghi_nhat_ky(
            ma_tai_khoan=phien["ma_tai_khoan"],
            hanh_dong="Tải đề ôn tập",
            ip_thiet_bi=ip_may,
            ipv4=dia_chi_ipv4,
            ket_qua="Thành công",
            chi_tiet=f"Giáo viên {phien['ma_can_bo']} tải xuống đề ôn tập [{r['ten_de_on_tap']}]",
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


@app.get("/api/de-thi")
def api_list_de_thi(
    request: Request,
    search: str = "",
    ma_khoi: Optional[int] = None,
    loai_ky_thi: str = "",
    loai_de: str = "",
):
    """
    Lấy danh sách đề thi và lịch thi trong bảng DeThi kết hợp LichThi và TepBay (CN_DeThi.docx & CN_TaiLieu.docx)
    theo đúng môn học mà giáo viên dạy.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
                    COALESCE(d.loai_de, 'CHINH_THUC') AS loai_de,
                    COALESCE(d.da_nem_phong, TRUE) AS da_nem_phong,
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
            for r in rows:
                ten_ngan = _TEN_MON_NGAN.get(r["ky_hieu_mon"], r["ten_mon_hoc"])
                r["ten_mon_ngan"] = ten_ngan
                r["nguoi_ra_de_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_ra_de"], r.get("vai_tro_nguoi_ra_de"), ten_ngan
                )
                if r["da_chinh_sua"] and r.get("ho_ten_nguoi_cap_nhat"):
                    r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                        r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                    )
                    r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
                else:
                    r["nguoi_cap_nhat"] = None
                    r["ho_ten_nguoi_cap_nhat"] = None
                    r["thoi_diem_cap_nhat"] = None
                    r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                    r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
                la_quan_tri = chuan_hoa_vai_tro(phien["vai_tro"]) in ("QUAN_TRI", "BAN_GIAM_HIEU")
                r["duoc_phep_chinh_sua"] = bool(pq["duoc_truy_cap_de_chinh_thuc"]) and (
                    str(r["nguoi_ra_de"]) == str(phien["ma_tai_khoan"]) or la_quan_tri
                )
                tt = _kiem_tra_toan_ven_tep_de_thi(
                    r["duong_dan_tep"],
                    r["ma_bam_sha256"],
                    r["da_chinh_sua"],
                    r.pop("khoa_ma_hoa_de", None),
                    r.pop("ma_nonce_aes", None),
                    r.pop("the_xac_thuc_aes", None),
                )
                r.update(tt)
            return {
                "phan_quyen_mon": pq,
                "items": rows,
                "total": len(rows),
            }


@app.get("/api/de-thi/{ma_de_thi}")
def api_get_de_thi_detail(ma_de_thi: str, request: Request):
    """Xem chi tiết một đề thi và lịch thi tương ứng (CN_DeThi.docx)."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
                    COALESCE(d.loai_de, 'CHINH_THUC') AS loai_de,
                    COALESCE(d.da_nem_phong, TRUE) AS da_nem_phong,
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
            if int(r["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép truy cập đề thi thuộc môn học mình giảng dạy.")
            if int(r["ma_khoi"]) not in pq.get("danh_sach_khoi_duoc_phep", pq["danh_sach_khoi"]):
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép truy cập đề thi thuộc khối lớp được phân quyền.")

            ten_ngan = _TEN_MON_NGAN.get(r["ky_hieu_mon"], r["ten_mon_hoc"])
            r["ten_mon_ngan"] = ten_ngan
            r["nguoi_ra_de_hien_thi"] = _format_nguoi_thao_tac_de(
                r["ho_ten_nguoi_ra_de"], r.get("vai_tro_nguoi_ra_de"), ten_ngan
            )
            if r["da_chinh_sua"] and r.get("ho_ten_nguoi_cap_nhat"):
                r["nguoi_cap_nhat_hien_thi"] = _format_nguoi_thao_tac_de(
                    r["ho_ten_nguoi_cap_nhat"], r.get("vai_tro_nguoi_cap_nhat"), ten_ngan
                )
                r["cap_nhat_lan_cuoi"] = r["cap_nhat_lan_cuoi"] or "Chưa có chỉnh sửa nào"
            else:
                r["nguoi_cap_nhat"] = None
                r["ho_ten_nguoi_cap_nhat"] = None
                r["thoi_diem_cap_nhat"] = None
                r["nguoi_cap_nhat_hien_thi"] = "Chưa có chỉnh sửa nào"
                r["cap_nhat_lan_cuoi"] = "Chưa có chỉnh sửa nào"
            la_quan_tri = chuan_hoa_vai_tro(phien["vai_tro"]) in ("QUAN_TRI", "BAN_GIAM_HIEU")
            r["duoc_phep_chinh_sua"] = bool(pq["duoc_truy_cap_de_chinh_thuc"]) and (
                str(r["nguoi_ra_de"]) == str(phien["ma_tai_khoan"]) or la_quan_tri
            )
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
    loai_de: str = Form("CHINH_THUC"),
    file: UploadFile = File(...),
):
    """
    Tạo Lịch thi và Đề thi mới (CN_DeThi.docx & CN_TaiLieu.docx):
    - Lưu thông tin kỳ thi vào bảng LichThi (ten_ky_thi, loai_ky_thi, nam_hoc, ma_mon_hoc, ma_khoi, gio_bat_dau, gio_ket_thuc, nguoi_tao_lich, thoi_diem_tao).
    - Tính mã băm SHA-256 của tệp đề thi, mã hóa AES-256-GCM và lưu vào bảng DeThi
      (ma_de_thi, ma_lich_thi, ten_de_thi, nguoi_ra_de, duong_dan_tep, ma_bam_sha256, thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat).
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    ten_ky = (ten_ky_thi or ten_lich_thi or "Kiểm tra giữa kỳ I").strip()
    loai_ky = (loai_ky_thi or "Giữa kỳ I").strip()
    nam = (nam_hoc or "2026 - 2027").strip()
    ten_de = (ten_de_thi or "").strip()
    if not ten_de or not ten_ky:
        raise HTTPException(status_code=400, detail="Vui lòng nhập đầy đủ Tên kỳ thi và Tên đề thi.")

    dt_bat_dau = _parse_gio_thi_vn(gio_bat_dau)
    dt_ket_thuc = _parse_gio_thi_vn(gio_ket_thuc)
    if dt_ket_thuc <= dt_bat_dau:
        raise HTTPException(status_code=400, detail="Thời gian kết thúc phải lớn hơn Thời gian bắt đầu.")

    loai = (loai_de or "CHINH_THUC").strip().upper()
    if loai not in ("CHINH_THUC", "ON_TAP", "DE_MOI"):
        loai = "CHINH_THUC"

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Tệp đề thi đang rỗng.")
    if len(raw_bytes) > _KICH_THUOC_TOI_DA:
        raise HTTPException(status_code=400, detail="Kích thước tệp vượt quá 10MB.")

    ten_tep_goc = os.path.basename(file.filename or "De_Thi.pdf")
    ext = os.path.splitext(ten_tep_goc.lower())[1]
    if ext not in _DUOI_TEP_HOP_LE:
        raise HTTPException(status_code=400, detail="Định dạng tệp không hỗ trợ. Vui lòng chọn tệp PDF, DOCX hoặc XLSX.")

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
                    ma_de_thi, ma_lich_thi, ten_de_thi, ma_mon_hoc, ma_khoi, loai_de,
                    da_nem_phong, nguoi_ra_de, duong_dan_tep, duong_dan_tep_ma_hoa, ten_tep_goc,
                    ma_bam_sha256, chu_ky_so_nguoi_ra_de, khoa_ma_hoa_de, ma_nonce_aes, the_xac_thuc_aes,
                    bi_can_thiep, da_chinh_sua, thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat
                )
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, FALSE, CURRENT_TIMESTAMP, NULL, NULL);
                """,
                (
                    ma_de_thi,
                    ma_lich,
                    ten_de,
                    pq["ma_mon_hoc"],
                    int(ma_khoi),
                    loai,
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
            if loai == "DE_MOI":
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
        hanh_dong="Tạo lịch thi và đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} tạo lịch thi [{ten_ky}] ({loai_ky} - Khối {ma_khoi}) và đề thi [{ten_de}], SHA-256: {env['ma_bam_sha256'][:16]}...",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_goc,
    )
    return {
        "status": "OK",
        "message": f"Đã tạo lịch thi '{ten_ky}' và lưu đề thi '{ten_de}' thành công!",
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
    file: Optional[UploadFile] = File(None),
):
    """
    Cập nhật Lịch thi và Đề thi (CN_DeThi.docx):
    - Nếu tải tệp mới: tính lại SHA-256 (ma_bam_sha256), mã hóa lại tệp, cập nhật thoi_diem_cap_nhat & nguoi_cap_nhat,
      đổi trạng thái file sang 'Đã bị chỉnh sửa' (da_chinh_sua = TRUE).
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
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
            cur.execute(
                """
                SELECT ma_de_thi, ma_lich_thi, ma_mon_hoc, nguoi_ra_de::text AS nguoi_ra_de,
                       COALESCE(duong_dan_tep, duong_dan_tep_ma_hoa) AS duong_dan_tep,
                       ten_tep_goc, ma_bam_sha256
                FROM DeThi
                WHERE ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi cần cập nhật.")
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền cập nhật đề thi của môn học khác.")
            la_quan_tri = chuan_hoa_vai_tro(phien["vai_tro"]) in ("QUAN_TRI", "BAN_GIAM_HIEU")
            if str(existing["nguoi_ra_de"]) != str(phien["ma_tai_khoan"]) and not la_quan_tri:
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép chỉnh sửa đề thi do chính mình tạo.")

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
                        da_chinh_sua = TRUE,
                        nguoi_cap_nhat = %s,
                        thoi_diem_cap_nhat = CURRENT_TIMESTAMP
                    WHERE ma_de_thi = %s;
                    """,
                    (ten_de, int(ma_khoi), phien["ma_tai_khoan"], ma_de_thi),
                )
        conn.commit()

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Cập nhật đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} cập nhật lịch thi [{ten_ky}] và đề thi [{ten_de}], SHA-256: {sha256_moi[:16]}...",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=ten_tep_moi,
    )
    return {
        "status": "OK",
        "message": f"Đã cập nhật lịch thi '{ten_ky}' và đề thi '{ten_de}' thành công!",
    }


@app.delete("/api/de-thi/{ma_de_thi}")
def api_delete_de_thi(ma_de_thi: str, request: Request):
    """Xóa đề thi và lịch thi tương ứng trong phạm vi môn học của giáo viên."""
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            if not pq["duoc_truy_cap_de_chinh_thuc"]:
                raise HTTPException(
                    status_code=403,
                    detail="Tài khoản của bạn không có quyền xóa đề thi chính thức.",
                )
            cur.execute(
                """
                SELECT ten_de_thi, ma_lich_thi, ma_mon_hoc, nguoi_ra_de::text AS nguoi_ra_de,
                       COALESCE(duong_dan_tep, duong_dan_tep_ma_hoa) AS duong_dan_tep, ten_tep_goc
                FROM DeThi
                WHERE ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi.")
            if int(existing["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không có quyền xóa đề thi của môn học khác.")
            la_quan_tri = chuan_hoa_vai_tro(phien["vai_tro"]) in ("QUAN_TRI", "BAN_GIAM_HIEU")
            if str(existing["nguoi_ra_de"]) != str(phien["ma_tai_khoan"]) and not la_quan_tri:
                raise HTTPException(status_code=403, detail="Bạn chỉ được phép xóa đề thi do chính mình tạo.")
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
        hanh_dong="Xóa đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} đã xóa đề thi [{existing['ten_de_thi']}]",
        thong_tin_thiet_bi=thiet_bi,
        tai_lieu_thao_tac=existing["ten_tep_goc"],
    )
    return {"status": "OK", "message": f"Đã xóa đề thi '{existing['ten_de_thi']}'."}


@app.get("/api/de-thi/{ma_de_thi}/file")
def api_access_de_thi_file(ma_de_thi: str, request: Request, mode: str = "attachment"):
    """
    Truy cập / tải tệp từ bảng DeThi (CN_DeThi.docx & CN_TaiLieu.docx):
    - Nếu là đề mồi (loai_de = 'DE_MOI' / có trong bảng TepBay): kích hoạt bẫy mồi nhử, tăng so_lan_kich_hoat,
      cập nhật thoi_diem_kich_hoat_gan_nhat và ghi cảnh báo an ninh vào NhatKyLog!
    - Giải mã AES-GCM / AES-256 trên RAM và xác minh ma_bam_sha256.
    """
    phien = kiem_tra_phien_hien_tai(request, yeu_cau_otp_hoan_tat=True)
    ip_may, dia_chi_ipv4, thiet_bi = lay_ip_client(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            pq = lay_thong_tin_phan_quyen_mon(cur, phien["ma_tai_khoan"], phien["vai_tro"])
            cur.execute(
                """
                SELECT
                    d.ma_de_thi::text AS ma_de_thi, d.ten_de_thi, d.ma_mon_hoc, d.ma_khoi,
                    d.loai_de, COALESCE(d.duong_dan_tep, d.duong_dan_tep_ma_hoa) AS duong_dan_tep,
                    d.ten_tep_goc, d.ma_bam_sha256,
                    d.khoa_ma_hoa_de, d.ma_nonce_aes, d.the_xac_thuc_aes
                FROM DeThi d
                WHERE d.ma_de_thi = %s;
                """,
                (ma_de_thi,),
            )
            d = cur.fetchone()
            if not d:
                raise HTTPException(status_code=404, detail="Không tìm thấy đề thi.")
            if int(d["ma_mon_hoc"]) != pq["ma_mon_hoc"]:
                raise HTTPException(status_code=403, detail="Bạn không được phép truy cập đề thi của môn học khác.")
            if int(d["ma_khoi"]) not in pq.get("danh_sach_khoi_duoc_phep", pq["danh_sach_khoi"]):
                raise HTTPException(status_code=403, detail="Bạn không được phép truy cập đề thi của khối lớp chưa phân quyền.")

            # Kiểm tra Bẫy mồi nhử (TepBay)
            if d["loai_de"] == "DE_MOI":
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
                conn.commit()
                so_lan = bay["so_lan_kich_hoat"] if bay else 1
                ghi_nhat_ky(
                    ma_tai_khoan=phien["ma_tai_khoan"],
                    hanh_dong="Cảnh báo bẫy đề mồi",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Báo động",
                    chi_tiet=f"PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [{d['ten_de_thi']}] bởi {phien['ma_can_bo']} ({phien['ten_dang_nhap']}) - Lần kích hoạt thứ {so_lan}!",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=d["ten_tep_goc"],
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"CẢNH BÁO AN NINH: Tệp '{d['ten_tep_goc']}' là đề mồi giám sát bảo mật. Hành vi truy cập đã được ghi nhận vào Nhật ký kiểm toán (Lần kích hoạt: {so_lan})!",
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
                    hanh_dong="Phát hiện can thiệp đề thi",
                    ip_thiet_bi=ip_may,
                    ipv4=dia_chi_ipv4,
                    ket_qua="Báo động",
                    chi_tiet=f"Phát hiện tệp đề thi [{d['ten_de_thi']}] bị can thiệp trái phép (sai lệch mã kiểm chứng toàn vẹn)!",
                    thong_tin_thiet_bi=thiet_bi,
                    tai_lieu_thao_tac=d["ten_tep_goc"],
                )
                raise HTTPException(status_code=500, detail="Cảnh báo: Phát hiện tệp đề thi bị can thiệp trái phép (sai lệch AES-GCM Tag / SHA-256)!")

    ghi_nhat_ky(
        ma_tai_khoan=phien["ma_tai_khoan"],
        hanh_dong="Tải đề thi" if mode == "attachment" else "Xem đề thi",
        ip_thiet_bi=ip_may,
        ipv4=dia_chi_ipv4,
        ket_qua="Thành công",
        chi_tiet=f"Giáo viên {phien['ma_can_bo']} truy cập đề thi [{d['ten_de_thi']}]",
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
