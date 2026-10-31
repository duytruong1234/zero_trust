import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from dotenv import load_dotenv

load_dotenv()

TABLES_IN_ORDER = [
    "khoilop",
    "monhoc",
    "taikhoan",
    "phanquyentheokhoimon",
    "lichthi",
    "deontap",
    "dethi",
    "niemphongde",
    "tepbay",
    "chandiachiip",
    "nhatkylog",
]


def normalize_dsn(raw_url: str, require_ssl: bool = False) -> str:
    url = (raw_url or "").strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if require_ssl and "sslmode=" not in url and "localhost" not in url and "127.0.0.1" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url


def get_table_columns(cur, table_name: str) -> list[str]:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position ASC;
        """,
        (table_name,),
    )
    return [r["column_name"] for r in cur.fetchall()]


def main():
    target_raw = sys.argv[1] if len(sys.argv) > 1 else os.getenv("RENDER_DATABASE_URL", "")
    if not target_raw.strip():
        print("Cach dung: python sync_to_render_db.py \"<EXTERNAL_DATABASE_URL_CUA_RENDER>\"")
        sys.exit(1)

    source_dsn = normalize_dsn(
        os.getenv("DATABASE_URL", "postgresql://postgres:123@localhost:5432/cn_dang_nhap"),
        require_ssl=False,
    )
    target_dsn = normalize_dsn(target_raw, require_ssl=True)

    if source_dsn == target_dsn:
        print("Loi: Chuoi ket noi nguon va dich trung nhau.")
        sys.exit(1)

    schema_path = os.path.join(os.path.dirname(__file__), "database", "schema.sql")
    if not os.path.exists(schema_path):
        print(f"Khong tim thay tep schema: {schema_path}")
        sys.exit(1)

    print("1. Dang ket noi CSDL cuc bo va CSDL Render...")
    with psycopg2.connect(source_dsn, cursor_factory=RealDictCursor) as src_conn, psycopg2.connect(
        target_dsn, cursor_factory=RealDictCursor, connect_timeout=20
    ) as dst_conn:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with src_conn.cursor() as src_cur, dst_conn.cursor() as dst_cur:
            print("2. Dang khoi tao cau truc bang va Trigger tren Render PostgreSQL...")
            dst_cur.execute(schema_sql)

            # Tam go cac Trigger chan xoa/sua tren bang dich trong qua trinh dong bo nguyen ban
            dst_cur.execute("DROP TRIGGER IF EXISTS trg_nhat_ky_log_noi_chuoi ON NhatKyLog;")
            dst_cur.execute("DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_chinh_sua ON NhatKyLog;")
            dst_cur.execute("DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_xoa ON NhatKyLog;")
            dst_cur.execute("DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_truncate ON NhatKyLog;")
            dst_cur.execute("DROP TRIGGER IF EXISTS trg_dethi_chi_nguoi_ra_de_sua ON DeThi;")

            # Xoa du lieu cu tren bang dich theo thu tu nguoc khoa ngoai
            for tbl in reversed(TABLES_IN_ORDER):
                dst_cur.execute(f"DELETE FROM {tbl};")
            dst_cur.execute("DELETE FROM PhienDangNhap;")

            # Sao chep tung bang giu nguyen UUID, ma bam SHA-256 va moc thoi gian
            for tbl in TABLES_IN_ORDER:
                src_cols = get_table_columns(src_cur, tbl)
                dst_cols_set = set(get_table_columns(dst_cur, tbl))
                cols = [c for c in src_cols if c in dst_cols_set]
                if not cols:
                    continue

                col_sql = ", ".join(cols)
                order_clause = " ORDER BY ma_nhat_ky ASC" if tbl == "nhatkylog" else ""
                src_cur.execute(f"SELECT {col_sql} FROM {tbl}{order_clause};")
                rows = src_cur.fetchall()
                if rows:
                    values = [
                        tuple(
                            psycopg2.Binary(bytes(r[c])) if isinstance(r[c], (bytes, memoryview)) else r[c]
                            for c in cols
                        )
                        for r in rows
                    ]
                    execute_values(
                        dst_cur,
                        f"INSERT INTO {tbl} ({col_sql}) VALUES %s;",
                        values,
                    )
                print(f"   - Da dong bo bang {tbl}: {len(rows)} ban ghi.")

            # Cap nhat bo dem SERIAL / BIGSERIAL tren Render PostgreSQL
            serial_Targets = [
                ("monhoc", "ma_mon_hoc"),
                ("phanquyentheokhoimon", "ma_phan_quyen"),
                ("lichthi", "ma_lich_thi"),
                ("niemphongde", "ma_niem_phong"),
                ("tepbay", "ma_bay"),
                ("chandiachiip", "ma_chan_ip"),
                ("nhatkylog", "ma_nhat_ky"),
            ]
            for tbl, pk in serial_Targets:
                dst_cur.execute(
                    f"""
                    SELECT setval(
                        pg_get_serial_sequence('{tbl}', '{pk}'),
                        COALESCE((SELECT MAX({pk}) FROM {tbl}), 1),
                        (SELECT COUNT(*) > 0 FROM {tbl})
                    );
                    """
                )

            # Khoi phuc toan bo Trigger bao mat Zero-Trust (chay lai schema.sql idempotent)
            dst_cur.execute(schema_sql)

        dst_conn.commit()
    print("3. HOAN TAT! Toan bo du lieu va chuoi bam NhatKyLog da duoc dong bo len Render PostgreSQL.")


if __name__ == "__main__":
    main()
