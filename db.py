import os
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from security import (
    tinh_sha256_bytes,
    ma_hoa_tep_de,
    ma_hoa_tep_de_thi_envelope,
)

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:123@localhost:5432/cn_dang_nhap",
)


def get_conn():
    """Tạo kết nối trực tiếp tới CSDL PostgreSQL."""
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def _tao_pdf_mau(tieu_de_ascii: str, mon_ascii: str, khoi: int, loai_ascii: str) -> bytes:
    """Sinh tệp PDF 1.4 hợp lệ phục vụ xem trước và tải xuống đề mẫu."""
    stream_lines = [
        "BT",
        "/F1 16 Tf",
        "50 760 Td",
        "(TRUONG THPT HOANG VAN THU - NGAN HANG DE THI NOI BO) Tj",
        "/F1 13 Tf",
        "0 -32 Td",
        f"(De: {tieu_de_ascii}) Tj",
        "/F1 11 Tf",
        "0 -24 Td",
        f"(Mon hoc: {mon_ascii}   |   Khoi lop: {khoi}   |   Ky: {loai_ascii}) Tj",
        "0 -28 Td",
        "(-------------------------------------------------------------------------) Tj",
        "0 -24 Td",
        "(Cau 1 (2.0 diem): Trinh bay khai niem va ap dung cong thuc co ban.) Tj",
        "0 -20 Td",
        "(Cau 2 (3.0 diem): Giai cac bai toan / cau hoi van dung theo chuong trinh.) Tj",
        "0 -20 Td",
        "(Cau 3 (3.0 diem): Bai tap tong hop nang cao danh cho hoc sinh khoi lop.) Tj",
        "0 -20 Td",
        "(Cau 4 (2.0 diem): Cau hoiphan loai va van dung thuc tiem.) Tj",
        "0 -32 Td",
        "(--- HET ---) Tj",
        "ET",
    ]
    content_bytes = "\n".join(stream_lines).encode("latin-1", errors="ignore")
    objs = []
    objs.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objs.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objs.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    )
    objs.append(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objs.append(
        f"5 0 obj\n<< /Length {len(content_bytes)} >>\nstream\n".encode("ascii")
        + content_bytes
        + b"\nendstream\nendobj\n"
    )
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for o in objs:
        offsets.append(len(out))
        out.extend(o)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def _seed_du_lieu_de_on_tap_va_de_thi(conn):
    """Khởi tạo dữ liệu mẫu thực tế (mã hóa AES-256 trên đĩa) cho DeOnTap, LichThi, DeThi, TepBay nếu bảng đang trống."""
    base_dir = os.path.dirname(__file__)
    dir_on_tap = os.path.join(base_dir, "storage", "de_on_tap")
    dir_de_thi = os.path.join(base_dir, "storage", "de_thi")
    os.makedirs(dir_on_tap, exist_ok=True)
    os.makedirs(dir_de_thi, exist_ok=True)

    with conn.cursor() as cur:
        cur.execute("SELECT ma_can_bo, ma_tai_khoan FROM TaiKhoan;")
        tk_map = {r["ma_can_bo"]: r["ma_tai_khoan"] for r in cur.fetchall()}
        if not tk_map:
            return

        cur.execute("SELECT COUNT(*) AS cnt FROM DeOnTap;")
        if (cur.fetchone() or {}).get("cnt", 0) == 0:
            # Danh sách đề ôn tập mẫu cho 4 môn: Toán (1), Ngữ văn (2), Tiếng Anh (3), Vật lý (5)
            mau_on_tap = [
                # Toán học (ma_mon_hoc = 1) - theo đúng hình mẫu trong CN_DeOnTap.docx
                ("Ôn tập Toán giữa kỳ I", 1, 10, "Giữa kỳ I", "GV1000458", "GV1324570", "De_Toan_10_GiuaKy1.pdf", "On tap Toan giua ky I", "Toan hoc", "2026-10-28 14:30:00+07", "2026-10-28 15:10:00+07", False),
                ("Ôn tập Toán cuối kỳ I", 1, 10, "Cuối kỳ I", "GV1000458", "GV1000458", "De_Toan_10_CuoiKy1.pdf", "On tap Toan cuoi ky I", "Toan hoc", "2026-10-27 16:20:00+07", "2026-10-27 16:45:00+07", False),
                ("Ôn tập Toán giữa kỳ II", 1, 11, "Giữa kỳ II", "GV1324570", "GV1324570", "De_Toan_11_GiuaKy2.pdf", "On tap Toan giua ky II", "Toan hoc", "2026-10-26 09:15:00+07", "2026-10-26 10:05:00+07", False),
                ("Ôn tập Toán cuối kỳ II", 1, 12, "Cuối kỳ II", "GV1780839", "GV1780839", "De_Toan_12_CuoiKy2.pdf", "On tap Toan cuoi ky II", "Toan hoc", "2026-10-25 11:05:00+07", "2026-10-25 11:40:00+07", False),
                ("Đề ôn tập chương Hàm số", 1, 12, "Giữa kỳ II", "GV1000458", "GV1780839", "De_Toan_12_HamSo.pdf", "De on tap chuong Ham so", "Toan hoc", "2026-10-22 13:40:00+07", "2026-10-22 14:10:00+07", False),
                ("Đề ôn tập Hình học không gian", 1, 11, "Cuối kỳ I", "GV1324570", "GV1324570", "De_Toan_11_HinhHoc.pdf", "De on tap Hinh hoc khong gian", "Toan hoc", "2026-10-20 08:30:00+07", "2026-10-20 09:00:00+07", False),

                # Ngữ văn (ma_mon_hoc = 2)
                ("Ôn tập Ngữ văn giữa kỳ I", 2, 10, "Giữa kỳ I", "GV1428003", "GV1428003", "De_Van_10_GiuaKy1.pdf", "On tap Ngu van giua ky I", "Ngu van", "2026-10-28 14:30:00+07", "2026-10-28 15:10:00+07", False),
                ("Ôn tập Ngữ văn cuối kỳ I", 2, 10, "Cuối kỳ I", "GV1456278", "GV1456278", "De_Van_10_CuoiKy1.pdf", "On tap Ngu van cuoi ky I", "Ngu van", "2026-10-27 16:20:00+07", "2026-10-27 16:45:00+07", False),
                ("Ôn tập Ngữ văn giữa kỳ II", 2, 11, "Giữa kỳ II", "GV1428003", "GV1456278", "De_Van_11_GiuaKy2.pdf", "On tap Ngu van giua ky II", "Ngu van", "2026-10-26 09:15:00+07", "2026-10-26 10:05:00+07", False),
                ("Ôn tập Nghị luận văn học lớp 12", 2, 12, "Cuối kỳ II", "GV1456278", "GV1456278", "De_Van_12_CuoiKy2.pdf", "On tap Nghi luan van hoc 12", "Ngu van", "2026-10-25 11:05:00+07", "2026-10-25 11:40:00+07", False),

                # Tiếng Anh (ma_mon_hoc = 3)
                ("Ôn tập Tiếng Anh giữa kỳ I", 3, 10, "Giữa kỳ I", "GV7869077", "GV7869077", "De_Anh_10_GiuaKy1.pdf", "On tap Tieng Anh giua ky I", "Tieng Anh", "2026-10-28 14:30:00+07", "2026-10-28 15:10:00+07", False),
                ("Ôn tập Tiếng Anh cuối kỳ I", 3, 11, "Cuối kỳ I", "GV7802740", "GV7802740", "De_Anh_11_CuoiKy1.pdf", "On tap Tieng Anh cuoi ky I", "Tieng Anh", "2026-10-27 16:20:00+07", "2026-10-27 16:45:00+07", False),
                ("Ôn tập Tiếng Anh giữa kỳ II", 3, 12, "Giữa kỳ II", "GV7802740", "GV7869077", "De_Anh_12_GiuaKy2.pdf", "On tap Tieng Anh giua ky II", "Tieng Anh", "2026-10-26 09:15:00+07", "2026-10-26 10:05:00+07", False),

                # Vật lý (ma_mon_hoc = 5)
                ("Ôn tập Vật lý giữa kỳ I", 5, 10, "Giữa kỳ I", "GV1562839", "GV1562839", "De_Ly_10_GiuaKy1.pdf", "On tap Vat ly giua ky I", "Vat ly", "2026-10-28 14:30:00+07", "2026-10-28 15:10:00+07", False),
                ("Ôn tập Vật lý cuối kỳ I", 5, 11, "Cuối kỳ I", "GV6790839", "GV6790839", "De_Ly_11_CuoiKy1.pdf", "On tap Vat ly cuoi ky I", "Vat ly", "2026-10-27 16:20:00+07", "2026-10-27 16:45:00+07", False),
                ("Ôn tập Dao động cơ & Sóng điện từ", 5, 12, "Cuối kỳ II", "GV6790839", "GV6790839", "De_Ly_12_DaoDong.pdf", "On tap Dao dong co", "Vat ly", "2026-10-25 11:05:00+07", "2026-10-25 11:40:00+07", False),
            ]

            for ten_de, ma_mon, ma_khoi, loai_de, cb_tao, cb_sua, ten_goc, ascii_title, ascii_mon, tg_tao, tg_sua, da_sua in mau_on_tap:
                nguoi_tao = tk_map.get(cb_tao) or next(iter(tk_map.values()))
                nguoi_sua = (tk_map.get(cb_sua) or nguoi_tao) if da_sua else None
                thoi_diem_sua = tg_sua if da_sua else None
                ma_de = str(uuid.uuid4())
                raw_pdf = _tao_pdf_mau(ascii_title, ascii_mon, ma_khoi, loai_de.encode("ascii", "ignore").decode() or "Hoc ky")
                sha256_hex = tinh_sha256_bytes(raw_pdf)
                enc_bytes = ma_hoa_tep_de(raw_pdf)
                rel_path = f"storage/de_on_tap/{ma_de}.enc"
                abs_path = os.path.join(base_dir, "storage", "de_on_tap", f"{ma_de}.enc")
                with open(abs_path, "wb") as f:
                    f.write(enc_bytes)

                cur.execute(
                    """
                    INSERT INTO DeOnTap (
                        ma_de_on_tap, ten_de_on_tap, ma_mon_hoc, ma_khoi, loai_de,
                        nguoi_tao, duong_dan_tep, ten_tep_goc, ma_bam_sha256, da_chinh_sua,
                        thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        ma_de, ten_de, ma_mon, ma_khoi, loai_de,
                        nguoi_tao, rel_path, ten_goc, sha256_hex, da_sua,
                        tg_tao, thoi_diem_sua, nguoi_sua,
                    ),
                )

        # Khởi tạo dữ liệu mẫu cho LichThi, DeThi, TepBay (CN_DeThi.docx & CN_TaiLieu.docx)
        cur.execute("SELECT COUNT(*) AS cnt FROM DeThi;")
        if (cur.fetchone() or {}).get("cnt", 0) == 0:
            admin_id = tk_map.get("AD1568920") or next(iter(tk_map.values()))
            mau_de_thi = [
                (1, 10, "Kiểm tra giữa kỳ I", "Giữa kỳ I", "2026 - 2027", "2026-11-15 07:30:00+07", "2026-11-15 09:00:00+07", "Đề kiểm tra giữa kỳ I - Toán 10", "CHINH_THUC", True, "GV1780839", "de_kiem_tra_giua_ky_1_toan_10.pdf", "De kiem tra giua ky I - Toan 10", "Toan hoc"),
                (1, 12, "Kiểm tra cuối kỳ I", "Cuối kỳ I", "2026 - 2027", "2026-12-20 07:30:00+07", "2026-12-20 09:00:00+07", "Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)", "DE_MOI", True, "GV1780839", "De_ChinhThuc_Toan12_CK1_Mat.pdf", "De thi chinh thuc Toan 12", "Toan hoc"),
                (2, 10, "Kiểm tra giữa kỳ I", "Giữa kỳ I", "2026 - 2027", "2026-11-16 07:30:00+07", "2026-11-16 09:00:00+07", "Đề kiểm tra giữa kỳ I - Ngữ văn 10", "CHINH_THUC", True, "GV1456278", "de_kiem_tra_giua_ky_1_van_10.pdf", "De kiem tra giua ky I - Ngu van 10", "Ngu van"),
                (3, 11, "Kiểm tra giữa kỳ I", "Giữa kỳ I", "2026 - 2027", "2026-11-17 07:30:00+07", "2026-11-17 08:30:00+07", "Đề kiểm tra giữa kỳ I - Tiếng Anh 11", "CHINH_THUC", True, "GV7802740", "de_kiem_tra_giua_ky_1_anh_11.pdf", "De kiem tra giua ky I - Tieng Anh 11", "Tieng Anh"),
                (5, 12, "Kiểm tra giữa kỳ I", "Giữa kỳ I", "2026 - 2027", "2026-11-18 07:30:00+07", "2026-11-18 08:30:00+07", "Đề kiểm tra giữa kỳ I - Vật lý 12", "CHINH_THUC", True, "GV6790839", "de_kiem_tra_giua_ky_1_ly_12.pdf", "De kiem tra giua ky I - Vat ly 12", "Vat ly"),
            ]
            for ma_mon, ma_khoi, ten_ky, loai_ky, nam_hoc, tg_bd, tg_kt, ten_de, loai_de, nem_phong, cb_ra, ten_goc, ascii_title, ascii_mon in mau_de_thi:
                nguoi_ra = tk_map.get(cb_ra) or admin_id
                cur.execute(
                    """
                    INSERT INTO LichThi (
                        ten_ky_thi, loai_ky_thi, ten_lich_thi, nam_hoc,
                        ma_khoi, ma_mon_hoc, gio_bat_dau, gio_ket_thuc,
                        thoi_gian_bat_dau, thoi_gian_ket_thuc, nguoi_tao_lich
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING ma_lich_thi;
                    """,
                    (ten_ky, loai_ky, ten_ky, nam_hoc, ma_khoi, ma_mon, tg_bd, tg_kt, tg_bd, tg_kt, nguoi_ra),
                )
                ma_lich = cur.fetchone()["ma_lich_thi"]
                ma_de_thi = str(uuid.uuid4())
                raw_pdf = _tao_pdf_mau(ascii_title, ascii_mon, ma_khoi, loai_ky)
                env = ma_hoa_tep_de_thi_envelope(raw_pdf, str(nguoi_ra))
                rel_path = f"storage/de_thi/{ma_de_thi}.enc"
                abs_path = os.path.join(base_dir, "storage", "de_thi", f"{ma_de_thi}.enc")
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, FALSE, CURRENT_TIMESTAMP, NULL, NULL);
                    """,
                    (
                        ma_de_thi, ma_lich, ten_de, ma_mon, ma_khoi, loai_de,
                        nem_phong, nguoi_ra, rel_path, rel_path, ten_goc,
                        env["ma_bam_sha256"],
                        psycopg2.Binary(env["chu_ky_so_nguoi_ra_de"]),
                        psycopg2.Binary(env["khoa_ma_hoa_de"]),
                        psycopg2.Binary(env["ma_nonce_aes"]),
                        psycopg2.Binary(env["the_xac_thuc_aes"]),
                    ),
                )
                if loai_de == "DE_MOI":
                    cur.execute(
                        """
                        INSERT INTO TepBay (ma_de_thi, ten_tep_bay, duong_dan_kich_hoat, so_lan_kich_hoat, dang_hoat_dong)
                        VALUES (%s, %s, %s, 0, TRUE)
                        ON CONFLICT (duong_dan_kich_hoat) DO NOTHING;
                        """,
                        (ma_de_thi, ten_goc, f"/api/de-thi/{ma_de_thi}/download"),
                    )

        # Đồng bộ các cột mới của CN_DeThi.docx cho dữ liệu cũ (nếu đã tạo từ trước)
        cur.execute(
            """
            UPDATE LichThi
            SET ten_ky_thi = COALESCE(ten_ky_thi, ten_lich_thi, 'Kiểm tra giữa kỳ I'),
                loai_ky_thi = COALESCE(loai_ky_thi, CASE WHEN ten_lich_thi ILIKE '%cuối%' THEN 'Cuối kỳ I' ELSE 'Giữa kỳ I' END),
                gio_bat_dau = COALESCE(gio_bat_dau, thoi_gian_bat_dau, '2026-11-15 07:30:00+07'::timestamptz),
                gio_ket_thuc = COALESCE(gio_ket_thuc, thoi_gian_ket_thuc, '2026-11-15 09:00:00+07'::timestamptz)
            WHERE ten_ky_thi IS NULL OR gio_bat_dau IS NULL OR gio_ket_thuc IS NULL;
            """
        )
        cur.execute(
            """
            UPDATE DeThi
            SET duong_dan_tep = COALESCE(duong_dan_tep, duong_dan_tep_ma_hoa),
                da_chinh_sua = COALESCE(da_chinh_sua, FALSE)
            WHERE duong_dan_tep IS NULL;
            """
        )
        cur.execute(
            """
            UPDATE DeOnTap
            SET thoi_diem_cap_nhat = NULL,
                nguoi_cap_nhat = NULL
            WHERE COALESCE(da_chinh_sua, FALSE) = FALSE
              AND (thoi_diem_cap_nhat IS NOT NULL OR nguoi_cap_nhat IS NOT NULL);
            """
        )
        cur.execute(
            """
            UPDATE DeThi
            SET thoi_diem_cap_nhat = NULL,
                nguoi_cap_nhat = NULL
            WHERE COALESCE(da_chinh_sua, FALSE) = FALSE
              AND (thoi_diem_cap_nhat IS NOT NULL OR nguoi_cap_nhat IS NOT NULL);
            """
        )


def init_db_schema():
    """Đảm bảo cấu trúc bảng và Trigger trong database/schema.sql đã được khởi tạo trên PostgreSQL."""
    schema_path = os.path.join(os.path.dirname(__file__), "database", "schema.sql")
    if not os.path.exists(schema_path):
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            with open(schema_path, "r", encoding="utf-8") as f:
                cur.execute(f.read())
        _seed_du_lieu_de_on_tap_va_de_thi(conn)
        conn.commit()


def ghi_nhat_ky(
    ma_tai_khoan,
    hanh_dong: str,
    ip_thiet_bi: str,
    ipv4: str,
    ket_qua: str,
    chi_tiet: str,
    thong_tin_thiet_bi: str = "",
    tai_lieu_thao_tac: str = "",
):
    """
    Ghi bản ghi nhật ký thực tế vào bảng NhatKyLog trên PostgreSQL.
    Trigger trg_nhat_ky_log_noi_chuoi trong PostgreSQL tự động tính toán
    ma_bam_truoc và ma_bam_nhat_ky (SHA-256 Hash-Chain).
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO NhatKyLog (
                    ma_tai_khoan, hanh_dong, ip_thiet_bi, ipv4,
                    ket_qua, chi_tiet, thong_tin_thiet_bi, tai_lieu_thao_tac
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING ma_nhat_ky, ma_bam_truoc, ma_bam_nhat_ky, thoi_diem;
                """,
                (
                    ma_tai_khoan,
                    hanh_dong,
                    ip_thiet_bi,
                    ipv4,
                    ket_qua,
                    chi_tiet,
                    thong_tin_thiet_bi,
                    tai_lieu_thao_tac,
                ),
            )
            row = cur.fetchone()
        conn.commit()
    return row
