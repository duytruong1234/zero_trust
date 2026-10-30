-- =============================================================================
-- HỆ THỐNG QUẢN LÝ VÀ PHÂN PHỐI NGÂN HÀNG ĐỀ THI - THPT HOÀNG VĂN THỤ
-- CHỨC NĂNG: ĐĂNG NHẬP VÀ BẢO MẬT (ZERO-TRUST & 2FA TOTP RFC 6238)
-- Chuẩn CSDL: PostgreSQL 17
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -----------------------------------------------------------------------------
-- 1. BẢNG TaiKhoan (Tài khoản người dùng)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS TaiKhoan (
    ma_tai_khoan         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ma_can_bo            VARCHAR(20) UNIQUE NOT NULL,
    ten_dang_nhap        VARCHAR(50) UNIQUE NOT NULL,
    mat_khau             VARCHAR(255) NOT NULL,
    ho_ten               VARCHAR(100) NOT NULL,
    email                VARCHAR(100) UNIQUE NOT NULL,
    vai_tro              VARCHAR(30) NOT NULL,
    bi_mat_otp_ma_hoa    BYTEA NULL,
    da_kich_hoat_otp     BOOLEAN NULL DEFAULT FALSE,
    bi_khoa              BOOLEAN NULL DEFAULT FALSE,
    so_lan_dang_nhap_sai INT NULL DEFAULT 0,
    so_lan_sai_otp       INT NULL DEFAULT 0,
    ip_thiet_bi_gan_nhat INET NULL,
    ipv4_gan_nhat        INET NULL,
    thoi_diem_tao        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dang_hoat_dong       BOOLEAN NULL DEFAULT TRUE,
    -- CN_CapTaiKhoanMoi: Thời điểm hết khóa an ninh = NOW() + INTERVAL '15 minutes'
    -- (khi sai mật khẩu 5 lần hoặc sai OTP 3 lần). Đến hạn hệ thống tự mở lại bi_khoa = FALSE.
    khoa_den_thoi_diem   TIMESTAMPTZ NULL,
    ma_pin               VARCHAR(255) NULL,
    ma_xac_nhan_pin      VARCHAR(255) NULL,
    han_xac_nhan_pin     TIMESTAMPTZ NULL,
    -- Ràng buộc kiểm tra đuôi email nội bộ của trường THPT Hoàng Văn Thụ
    CONSTRAINT chk_taikhoan_email_domain CHECK (email LIKE '%@thpthoangvanthu.edu.vn'),
    -- Ràng buộc kiểm tra công thức mã cán bộ "Tên viết tắt vai trò + 7 số ngẫu nhiên"
    CONSTRAINT chk_taikhoan_ma_can_bo CHECK (
        ma_can_bo ~ '^(GV|AD|HT)[0-9]{7}$'
    )
);

-- -----------------------------------------------------------------------------
-- 1b. NÂNG CẤP CẤU TRÚC BẢNG TaiKhoan THEO TÀI LIỆU CN_CapTaiKhoanMoi
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    -- Đổi tên cột cũ thoi_diem_mo_khoa -> khoa_den_thoi_diem (giữ nguyên dữ liệu đang có)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'taikhoan' AND column_name = 'thoi_diem_mo_khoa'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'taikhoan' AND column_name = 'khoa_den_thoi_diem'
    ) THEN
        ALTER TABLE TaiKhoan RENAME COLUMN thoi_diem_mo_khoa TO khoa_den_thoi_diem;
    END IF;
END $$;

ALTER TABLE TaiKhoan ADD COLUMN IF NOT EXISTS khoa_den_thoi_diem TIMESTAMPTZ NULL;
ALTER TABLE TaiKhoan ADD COLUMN IF NOT EXISTS ma_pin VARCHAR(255) NULL;
ALTER TABLE TaiKhoan ADD COLUMN IF NOT EXISTS ma_xac_nhan_pin VARCHAR(255) NULL;
ALTER TABLE TaiKhoan ADD COLUMN IF NOT EXISTS han_xac_nhan_pin TIMESTAMPTZ NULL;
COMMENT ON COLUMN TaiKhoan.ma_pin IS 'Mã PIN xác minh 6 chữ số đã mã băm (bcrypt) dùng khi tải hoặc niêm phong đề ôn tập, đề thi';

-- Đồng bộ trạng thái khóa cũ: tài khoản đang có mốc khóa còn hiệu lực -> bi_khoa = TRUE
UPDATE TaiKhoan
SET bi_khoa = TRUE
WHERE khoa_den_thoi_diem IS NOT NULL
  AND khoa_den_thoi_diem > NOW()
  AND bi_khoa IS DISTINCT FROM TRUE;

-- Tên đăng nhập: viết thường, không dấu, không khoảng trắng, chỉ chữ cái, số và dấu chấm
ALTER TABLE TaiKhoan DROP CONSTRAINT IF EXISTS chk_taikhoan_ten_dang_nhap;
ALTER TABLE TaiKhoan ADD CONSTRAINT chk_taikhoan_ten_dang_nhap CHECK (ten_dang_nhap ~ '^[a-z0-9.]+$');

-- Vai trò hệ thống: chuẩn hóa về 3 mã phân cấp GIAO_VIEN / BAN_GIAM_HIEU / QUAN_TRI
UPDATE TaiKhoan SET vai_tro = 'GIAO_VIEN'
WHERE vai_tro IN ('Giáo viên', 'Giao vien', 'giáo viên');
UPDATE TaiKhoan SET vai_tro = 'BAN_GIAM_HIEU'
WHERE vai_tro IN ('Hiệu Trưởng', 'Hiệu trưởng', 'Phó Hiệu trưởng', 'Ban Giám hiệu');
UPDATE TaiKhoan SET vai_tro = 'QUAN_TRI'
WHERE vai_tro IN ('Quản trị viên', 'Admin', 'Quan tri vien');
ALTER TABLE TaiKhoan DROP CONSTRAINT IF EXISTS chk_taikhoan_vai_tro;
ALTER TABLE TaiKhoan ADD CONSTRAINT chk_taikhoan_vai_tro CHECK (vai_tro IN ('GIAO_VIEN', 'BAN_GIAM_HIEU', 'QUAN_TRI'));

COMMENT ON COLUMN TaiKhoan.khoa_den_thoi_diem IS 'Thời điểm tự động mở khóa an ninh (NOW() + 15 phút khi sai mật khẩu 5 lần / sai OTP 3 lần)';
COMMENT ON COLUMN TaiKhoan.vai_tro IS 'Vai trò phân cấp: GIAO_VIEN / BAN_GIAM_HIEU / QUAN_TRI';

COMMENT ON TABLE TaiKhoan IS 'Bảng lưu trữ thông tin tài khoản người dùng và cấu hình bảo mật 2FA TOTP';
COMMENT ON COLUMN TaiKhoan.ma_tai_khoan IS 'Mã định danh duy nhất của tài khoản (UUID)';
COMMENT ON COLUMN TaiKhoan.ma_can_bo IS 'Mã quản lý hiển thị: Tên viết tắt vai trò (GV/AD/HT) + 7 số ngẫu nhiên';
COMMENT ON COLUMN TaiKhoan.ten_dang_nhap IS 'Tên đăng nhập viết thường, không dấu, chỉ gồm chữ, số và dấu chấm (^[a-z0-9.]+$)';
COMMENT ON COLUMN TaiKhoan.mat_khau IS 'Mật khẩu đã được mã băm (bcrypt)';
COMMENT ON COLUMN TaiKhoan.email IS 'Địa chỉ email nội bộ trường (@thpthoangvanthu.edu.vn)';
COMMENT ON COLUMN TaiKhoan.bi_mat_otp_ma_hoa IS 'Khóa bí mật TOTP đã mã hóa AES-256 + Master Key';
COMMENT ON COLUMN TaiKhoan.da_kich_hoat_otp IS 'Trạng thái kích hoạt 2FA (FALSE: hiện QR lần đầu; TRUE: khóa QR vĩnh viễn)';

-- -----------------------------------------------------------------------------
-- 2. BẢNG PhienDangNhap (Phiên đăng nhập Zero-Trust)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS PhienDangNhap (
    ma_phien           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ma_tai_khoan       UUID NOT NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE CASCADE,
    ma_phien_bam       CHAR(64) UNIQUE NOT NULL,
    ip_thiet_bi        INET NOT NULL,
    ipv4               INET NOT NULL,
    thong_tin_thiet_bi TEXT NULL,
    da_xac_thuc_otp    BOOLEAN NOT NULL DEFAULT FALSE,
    da_thu_hoi         BOOLEAN NOT NULL DEFAULT FALSE,
    thoi_diem_het_han  TIMESTAMPTZ NOT NULL,
    thoi_diem_tao      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_phiendangnhap_ma_tai_khoan ON PhienDangNhap(ma_tai_khoan);
CREATE INDEX IF NOT EXISTS idx_phiendangnhap_ma_phien_bam ON PhienDangNhap(ma_phien_bam);

COMMENT ON TABLE PhienDangNhap IS 'Bảng quản lý phiên đăng nhập, chống đánh cắp Cookie và kiểm soát cổng 2FA';
COMMENT ON COLUMN PhienDangNhap.ma_phien_bam IS 'Mã băm SHA-256 của Session Token gửi về Cookie trình duyệt';
COMMENT ON COLUMN PhienDangNhap.da_xac_thuc_otp IS 'Kiểm soát cổng 2FA: chỉ cho phép truy cập tài nguyên khi cờ = TRUE';

-- -----------------------------------------------------------------------------
-- 3. BẢNG NhatKyLog (Nhật ký kiểm toán nối chuỗi băm SHA-256 bất biến)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS NhatKyLog (
    ma_nhat_ky          BIGSERIAL PRIMARY KEY,
    ma_bam_truoc        CHAR(64) NOT NULL,
    ma_tai_khoan        UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL,
    hanh_dong           VARCHAR(50) NOT NULL,
    ip_thiet_bi         INET NOT NULL,
    ipv4                INET NOT NULL,
    ket_qua             VARCHAR(30) NOT NULL,
    ket_qua_goc         VARCHAR(30) NULL,
    chi_tiet            TEXT NOT NULL,
    thoi_diem           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ma_bam_nhat_ky      CHAR(64) NOT NULL,
    -- Các trường thông tin bổ trợ hiển thị trên Giao diện Nhật ký Log (Mục 3)
    thong_tin_thiet_bi  TEXT NULL,
    tai_lieu_thao_tac   VARCHAR(255) NULL DEFAULT '',
    -- Các trường khóa cứng dữ liệu gốc & báo động tức thời khi có hành vi cố tình can thiệp
    bi_can_thiep        BOOLEAN NOT NULL DEFAULT FALSE,
    so_lan_can_thiep    INTEGER NOT NULL DEFAULT 0,
    thoi_diem_can_thiep TIMESTAMPTZ NULL,
    chi_tiet_can_thiep  TEXT NULL
);

-- Bỏ giá trị mặc định giả lập cũ: thiết bị truy cập luôn được ghi nhận thực tế từ request
ALTER TABLE NhatKyLog ALTER COLUMN thong_tin_thiet_bi DROP DEFAULT;
ALTER TABLE NhatKyLog ADD COLUMN IF NOT EXISTS ket_qua_goc VARCHAR(30) NULL;
ALTER TABLE NhatKyLog ADD COLUMN IF NOT EXISTS bi_can_thiep BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE NhatKyLog ADD COLUMN IF NOT EXISTS so_lan_can_thiep INTEGER NOT NULL DEFAULT 0;
ALTER TABLE NhatKyLog ADD COLUMN IF NOT EXISTS thoi_diem_can_thiep TIMESTAMPTZ NULL;
ALTER TABLE NhatKyLog ADD COLUMN IF NOT EXISTS chi_tiet_can_thiep TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_nhatkylog_thoi_diem ON NhatKyLog(thoi_diem DESC);
CREATE INDEX IF NOT EXISTS idx_nhatkylog_ma_tai_khoan ON NhatKyLog(ma_tai_khoan);

-- Hàm tính mã băm SHA-256 của bản ghi nhật ký nối chuỗi (Hash-Chain)
CREATE OR REPLACE FUNCTION fn_tinh_bam_nhat_ky_log(
    p_ma_nhat_ky BIGINT,
    p_ma_bam_truoc CHAR(64),
    p_ma_tai_khoan UUID,
    p_hanh_dong VARCHAR,
    p_ip_thiet_bi INET,
    p_ipv4 INET,
    p_ket_qua VARCHAR,
    p_chi_tiet TEXT,
    p_thoi_diem TIMESTAMPTZ
) RETURNS CHAR(64)
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT encode(
        digest(
            concat_ws('|',
                p_ma_nhat_ky::text,
                p_ma_bam_truoc,
                COALESCE(p_ma_tai_khoan::text, 'NULL'),
                p_hanh_dong,
                host(p_ip_thiet_bi),
                host(p_ipv4),
                p_ket_qua,
                p_chi_tiet,
                to_char(p_thoi_diem AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
            ),
            'sha256'
        ),
        'hex'
    )::char(64);
$$;

-- Chuẩn hóa một lần các bản ghi cũ về đúng 4 giá trị ket_qua và hành động ngắn gọn trước khi khóa cứng bảng
DO $$
DECLARE
    rec RECORD;
    v_prev CHAR(64) := repeat('0', 64);
    v_hash CHAR(64);
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_nhat_ky_ket_qua'
    ) THEN
        DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_chinh_sua ON NhatKyLog;
        DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_xoa ON NhatKyLog;

        UPDATE NhatKyLog
        SET ket_qua = CASE
                WHEN ket_qua IN ('Thành công', 'Thất bại', 'Cảnh báo', 'Báo động') THEN ket_qua
                WHEN ket_qua = 'Yêu cầu kích hoạt 2FA' THEN 'Thành công'
                WHEN ket_qua = 'Từ chối' THEN 'Thất bại'
                ELSE 'Cảnh báo'
            END,
            hanh_dong = CASE
                WHEN hanh_dong = 'Đặt lại 2FA và Cấp lại mật khẩu' THEN 'Đặt lại 2FA'
                WHEN hanh_dong = 'Tạo lịch thi và đề thi' THEN 'Thêm đề thi'
                WHEN hanh_dong = 'Xác thực mã OTP' THEN 'Xác thực OTP'
                WHEN hanh_dong = 'Chặn địa chỉ IP' THEN 'Chặn IP'
                WHEN hanh_dong = 'Gỡ chặn địa chỉ IP' THEN 'Gỡ chặn IP'
                WHEN hanh_dong = 'Tạm khóa tài khoản' THEN 'Khóa tài khoản'
                WHEN hanh_dong = 'Cập nhật đề ôn tập' THEN 'Sửa đề ôn tập'
                WHEN hanh_dong = 'Cập nhật đề thi' THEN 'Sửa đề thi'
                WHEN hanh_dong = 'Niêm phong đề thi' THEN 'Niêm phong đề'
                WHEN hanh_dong = 'Cảnh báo bẫy đề mồi' THEN 'Bẫy đề mồi'
                WHEN hanh_dong = 'Phát hiện can thiệp đề thi' THEN 'Can thiệp tệp đề'
                ELSE hanh_dong
            END;

        UPDATE NhatKyLog
        SET ket_qua_goc = COALESCE(ket_qua_goc, ket_qua),
            bi_can_thiep = FALSE,
            so_lan_can_thiep = 0,
            thoi_diem_can_thiep = NULL,
            chi_tiet_can_thiep = NULL;

        FOR rec IN
            SELECT
                ma_nhat_ky, ma_tai_khoan, hanh_dong, ip_thiet_bi, ipv4,
                COALESCE(ket_qua_goc, ket_qua) AS kq_goc, chi_tiet, thoi_diem
            FROM NhatKyLog
            ORDER BY ma_nhat_ky ASC
        LOOP
            v_hash := fn_tinh_bam_nhat_ky_log(
                rec.ma_nhat_ky,
                v_prev,
                rec.ma_tai_khoan,
                rec.hanh_dong,
                rec.ip_thiet_bi,
                rec.ipv4,
                rec.kq_goc,
                rec.chi_tiet,
                rec.thoi_diem
            );
            UPDATE NhatKyLog
            SET ma_bam_truoc = v_prev,
                ma_bam_nhat_ky = v_hash
            WHERE ma_nhat_ky = rec.ma_nhat_ky;
            v_prev := v_hash;
        END LOOP;

        ALTER TABLE NhatKyLog
            ADD CONSTRAINT chk_nhat_ky_ket_qua
            CHECK (ket_qua IN ('Thành công', 'Thất bại', 'Cảnh báo', 'Báo động'));

        ALTER TABLE NhatKyLog
            ADD CONSTRAINT chk_nhat_ky_ket_qua_goc
            CHECK (ket_qua_goc IS NULL OR ket_qua_goc IN ('Thành công', 'Thất bại', 'Cảnh báo', 'Báo động'));
    END IF;
END;
$$;

-- Trigger tự động tính toán ma_bam_truoc và ma_bam_nhat_ky tuần tự khi INSERT
CREATE OR REPLACE FUNCTION fn_nhat_ky_log_noi_chuoi()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_bam_truoc CHAR(64);
BEGIN
    -- Khóa giao dịch tuần tự để đảm bảo thứ tự ma_nhat_ky và chuỗi băm không bị rẽ nhánh
    PERFORM pg_advisory_xact_lock(20261023);

    IF NEW.ket_qua NOT IN ('Thành công', 'Thất bại', 'Cảnh báo', 'Báo động') THEN
        RAISE EXCEPTION 'Giá trị ket_qua không hợp lệ (%): chỉ chấp nhận Thành công, Thất bại, Cảnh báo, Báo động.', NEW.ket_qua;
    END IF;

    IF NEW.ma_nhat_ky IS NULL THEN
        NEW.ma_nhat_ky := nextval(pg_get_serial_sequence('nhatkylog', 'ma_nhat_ky'));
    END IF;

    SELECT n.ma_bam_nhat_ky INTO v_bam_truoc
    FROM NhatKyLog n
    ORDER BY n.ma_nhat_ky DESC
    LIMIT 1;

    IF v_bam_truoc IS NULL THEN
        v_bam_truoc := repeat('0', 64);
    END IF;

    NEW.thoi_diem := COALESCE(NEW.thoi_diem, clock_timestamp());
    NEW.ket_qua_goc := NEW.ket_qua;
    NEW.bi_can_thiep := FALSE;
    NEW.so_lan_can_thiep := 0;
    NEW.thoi_diem_can_thiep := NULL;
    NEW.chi_tiet_can_thiep := NULL;
    NEW.ma_bam_truoc := v_bam_truoc;
    NEW.ma_bam_nhat_ky := fn_tinh_bam_nhat_ky_log(
        NEW.ma_nhat_ky,
        NEW.ma_bam_truoc,
        NEW.ma_tai_khoan,
        NEW.hanh_dong,
        NEW.ip_thiet_bi,
        NEW.ipv4,
        NEW.ket_qua_goc,
        NEW.chi_tiet,
        NEW.thoi_diem
    );

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_nhat_ky_log_noi_chuoi ON NhatKyLog;
CREATE TRIGGER trg_nhat_ky_log_noi_chuoi
BEFORE INSERT ON NhatKyLog
FOR EACH ROW
EXECUTE FUNCTION fn_nhat_ky_log_noi_chuoi();

-- Trigger CHẶN TUYỆT ĐỐI chỉnh sửa dữ liệu gốc bảng NhatKyLog và BÁO ĐỘNG NGAY TẠI DÒNG ĐÓ
CREATE OR REPLACE FUNCTION fn_chan_chinh_sua_nhat_ky_log()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_loai_can_thiep TEXT;
    v_truong_sua TEXT;
    v_thoi_gian_vn TEXT;
BEGIN
    v_loai_can_thiep := COALESCE(current_setting('nhatky.loai_can_thiep', true), '');
    v_thoi_gian_vn := to_char(clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh', 'DD/MM/YYYY HH24:MI:SS');

    IF v_loai_can_thiep = 'XOA' THEN
        PERFORM set_config('nhatky.loai_can_thiep', '', true);
        v_truong_sua := 'lệnh xóa bản ghi';
    ELSE
        v_truong_sua := ARRAY_TO_STRING(ARRAY_REMOVE(ARRAY[
            CASE WHEN NEW.ma_nhat_ky IS DISTINCT FROM OLD.ma_nhat_ky THEN 'mã nhật ký' END,
            CASE WHEN NEW.ma_tai_khoan IS DISTINCT FROM OLD.ma_tai_khoan THEN 'người thực hiện' END,
            CASE WHEN NEW.hanh_dong IS DISTINCT FROM OLD.hanh_dong THEN 'hành động' END,
            CASE WHEN NEW.ip_thiet_bi IS DISTINCT FROM OLD.ip_thiet_bi OR NEW.ipv4 IS DISTINCT FROM OLD.ipv4 THEN 'địa chỉ IP' END,
            CASE WHEN NEW.thong_tin_thiet_bi IS DISTINCT FROM OLD.thong_tin_thiet_bi THEN 'thiết bị' END,
            CASE WHEN NEW.tai_lieu_thao_tac IS DISTINCT FROM OLD.tai_lieu_thao_tac THEN 'tài liệu' END,
            CASE WHEN NEW.ket_qua IS DISTINCT FROM OLD.ket_qua THEN 'kết quả' END,
            CASE WHEN NEW.chi_tiet IS DISTINCT FROM OLD.chi_tiet THEN 'thông tin chi tiết' END,
            CASE WHEN NEW.thoi_diem IS DISTINCT FROM OLD.thoi_diem THEN 'thời gian' END,
            CASE WHEN NEW.ma_bam_truoc IS DISTINCT FROM OLD.ma_bam_truoc OR NEW.ma_bam_nhat_ky IS DISTINCT FROM OLD.ma_bam_nhat_ky THEN 'mã băm niêm phong' END
        ], NULL), ', ');
        IF v_truong_sua IS NULL OR v_truong_sua = '' THEN
            v_truong_sua := 'dữ liệu nhật ký';
        END IF;
    END IF;

    -- Khóa cứng 100% nội dung gốc của bản ghi: mọi dữ liệu người sửa cố ghi đè đều bị hủy bỏ
    NEW.ma_nhat_ky         := OLD.ma_nhat_ky;
    NEW.ma_bam_truoc       := OLD.ma_bam_truoc;
    NEW.ma_tai_khoan       := OLD.ma_tai_khoan;
    NEW.hanh_dong          := OLD.hanh_dong;
    NEW.ip_thiet_bi        := OLD.ip_thiet_bi;
    NEW.ipv4               := OLD.ipv4;
    NEW.thong_tin_thiet_bi := OLD.thong_tin_thiet_bi;
    NEW.tai_lieu_thao_tac  := OLD.tai_lieu_thao_tac;
    NEW.chi_tiet           := OLD.chi_tiet;
    NEW.thoi_diem          := OLD.thoi_diem;
    NEW.ma_bam_nhat_ky     := OLD.ma_bam_nhat_ky;
    NEW.ket_qua_goc        := COALESCE(OLD.ket_qua_goc, OLD.ket_qua);

    -- Kích hoạt Báo động ngay trên dòng bị cố tình can thiệp
    NEW.ket_qua             := 'Báo động';
    NEW.bi_can_thiep        := TRUE;
    NEW.so_lan_can_thiep    := COALESCE(OLD.so_lan_can_thiep, 0) + 1;
    NEW.thoi_diem_can_thiep := clock_timestamp();
    NEW.chi_tiet_can_thiep  := format(
        'Báo động an ninh: Phát hiện hành vi cố tình can thiệp trái phép (%s) tại dòng nhật ký #%s lúc %s. Hệ thống đã chặn chỉnh sửa và giữ nguyên dữ liệu gốc.',
        v_truong_sua,
        OLD.ma_nhat_ky,
        v_thoi_gian_vn
    );

    RAISE WARNING 'BÁO ĐỘNG AN NINH: Bảng NhatKyLog không cho phép chỉnh sửa! Dòng #% đã chuyển sang trạng thái Báo động và giữ nguyên dữ liệu gốc.', OLD.ma_nhat_ky;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_chinh_sua ON NhatKyLog;
CREATE TRIGGER trg_nhat_ky_log_chan_chinh_sua
BEFORE UPDATE ON NhatKyLog
FOR EACH ROW
EXECUTE FUNCTION fn_chan_chinh_sua_nhat_ky_log();

-- Trigger CHẶN TUYỆT ĐỐI xóa bản ghi trong NhatKyLog và BÁO ĐỘNG NGAY TẠI DÒNG ĐÓ
CREATE OR REPLACE FUNCTION fn_chan_xoa_nhat_ky_log()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM set_config('nhatky.loai_can_thiep', 'XOA', true);
    UPDATE NhatKyLog
    SET bi_can_thiep = TRUE
    WHERE ma_nhat_ky = OLD.ma_nhat_ky;

    RAISE WARNING 'BÁO ĐỘNG AN NINH: Bảng NhatKyLog không cho phép xóa! Dòng #% đã chuyển sang trạng thái Báo động và được giữ nguyên.', OLD.ma_nhat_ky;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_xoa ON NhatKyLog;
CREATE TRIGGER trg_nhat_ky_log_chan_xoa
BEFORE DELETE ON NhatKyLog
FOR EACH ROW
EXECUTE FUNCTION fn_chan_xoa_nhat_ky_log();

-- Trigger CHẶN TUYỆT ĐỐI lệnh TRUNCATE trên NhatKyLog
CREATE OR REPLACE FUNCTION fn_chan_truncate_nhat_ky_log()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'BÁO ĐỘNG AN NINH: Nghiêm cấm xóa trắng (TRUNCATE) bảng NhatKyLog!';
END;
$$;

DROP TRIGGER IF EXISTS trg_nhat_ky_log_chan_truncate ON NhatKyLog;
CREATE TRIGGER trg_nhat_ky_log_chan_truncate
BEFORE TRUNCATE ON NhatKyLog
FOR EACH STATEMENT
EXECUTE FUNCTION fn_chan_truncate_nhat_ky_log();

-- -----------------------------------------------------------------------------
-- 4. BẢNG KhoiLop (Danh mục khối lớp - CN_DeOnTap & CN_TaiLieu)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS KhoiLop (
    ma_khoi  SMALLINT PRIMARY KEY,
    ten_khoi VARCHAR(20) NOT NULL
);

INSERT INTO KhoiLop (ma_khoi, ten_khoi) VALUES
    (10, 'Khối 10'),
    (11, 'Khối 11'),
    (12, 'Khối 12')
ON CONFLICT (ma_khoi) DO UPDATE SET ten_khoi = EXCLUDED.ten_khoi;

-- -----------------------------------------------------------------------------
-- 5. BẢNG MonHoc (Danh mục môn học - CN_DeOnTap & CN_TaiLieu)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS MonHoc (
    ma_mon_hoc   SMALLSERIAL PRIMARY KEY,
    ky_hieu_mon  VARCHAR(20) UNIQUE NOT NULL,
    ten_mon_hoc  VARCHAR(50) UNIQUE NOT NULL,
    dang_su_dung BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO MonHoc (ma_mon_hoc, ky_hieu_mon, ten_mon_hoc, dang_su_dung) VALUES
    (1, 'TOAN', 'Toán học', TRUE),
    (2, 'VAN', 'Ngữ văn', TRUE),
    (3, 'ANH', 'Tiếng Anh', TRUE),
    (4, 'LICH_SU', 'Lịch sử', TRUE),
    (5, 'VAT_LY', 'Vật lý', TRUE),
    (6, 'HOA_HOC', 'Hóa học', TRUE),
    (7, 'SINH_HOC', 'Sinh học', TRUE),
    (8, 'DIA_LY', 'Địa lý', TRUE)
ON CONFLICT (ma_mon_hoc) DO UPDATE
SET ky_hieu_mon = EXCLUDED.ky_hieu_mon,
    ten_mon_hoc = EXCLUDED.ten_mon_hoc,
    dang_su_dung = EXCLUDED.dang_su_dung;

SELECT setval(pg_get_serial_sequence('monhoc', 'ma_mon_hoc'), GREATEST((SELECT MAX(ma_mon_hoc) FROM MonHoc), 8));

-- -----------------------------------------------------------------------------
-- 6. BẢNG PhanQuyenTheoKhoiMon (Phân quyền truy cập theo khối và môn)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS PhanQuyenTheoKhoiMon (
    ma_phan_quyen               SERIAL PRIMARY KEY,
    ma_tai_khoan                UUID NOT NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE CASCADE,
    ma_khoi                     SMALLINT NOT NULL REFERENCES KhoiLop(ma_khoi) ON DELETE CASCADE,
    ma_mon_hoc                  BIGINT NOT NULL REFERENCES MonHoc(ma_mon_hoc) ON DELETE CASCADE,
    duoc_truy_cap_de_chung      BOOLEAN NOT NULL DEFAULT TRUE,
    duoc_truy_cap_de_chinh_thuc BOOLEAN NOT NULL DEFAULT FALSE,
    nguoi_cap_quyen             UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL,
    thoi_diem_cap_quyen         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_phan_quyen_tk_khoi_mon UNIQUE (ma_tai_khoan, ma_khoi, ma_mon_hoc)
);

-- Khởi tạo dữ liệu phân quyền theo đúng bảng 5 trong CN_DeOnTap.docx
DO $$
DECLARE
    v_admin UUID;
    r RECORD;
BEGIN
    SELECT ma_tai_khoan INTO v_admin FROM TaiKhoan WHERE ma_can_bo = 'AD1568920' LIMIT 1;

    FOR r IN
        SELECT * FROM (VALUES
            -- Toán học (ma_mon_hoc = 1)
            ('GV1000458', 1, 10, TRUE, FALSE),
            ('GV1000458', 1, 11, TRUE, FALSE),
            ('GV1000458', 1, 12, TRUE, FALSE),
            ('GV1324570', 1, 10, TRUE, FALSE),
            ('GV1324570', 1, 11, TRUE, FALSE),
            ('GV1324570', 1, 12, TRUE, FALSE),
            ('GV1780839', 1, 10, TRUE, TRUE),
            ('GV1780839', 1, 11, TRUE, TRUE),
            ('GV1780839', 1, 12, TRUE, TRUE),
            -- Ngữ văn (ma_mon_hoc = 2)
            ('GV1456278', 2, 10, TRUE, TRUE),
            ('GV1456278', 2, 11, TRUE, TRUE),
            ('GV1456278', 2, 12, TRUE, TRUE),
            ('GV1428003', 2, 10, TRUE, FALSE),
            ('GV1428003', 2, 11, TRUE, FALSE),
            ('GV1428003', 2, 12, TRUE, FALSE),
            -- Tiếng Anh (ma_mon_hoc = 3)
            ('GV7869077', 3, 10, TRUE, FALSE),
            ('GV7869077', 3, 11, TRUE, FALSE),
            ('GV7869077', 3, 12, TRUE, FALSE),
            ('GV7802740', 3, 10, TRUE, TRUE),
            ('GV7802740', 3, 11, TRUE, TRUE),
            ('GV7802740', 3, 12, TRUE, TRUE),
            -- Vật lý (ma_mon_hoc = 5)
            ('GV6790839', 5, 10, TRUE, TRUE),
            ('GV6790839', 5, 11, TRUE, TRUE),
            ('GV6790839', 5, 12, TRUE, TRUE),
            ('GV1562839', 5, 10, TRUE, FALSE),
            ('GV1562839', 5, 11, TRUE, FALSE),
            ('GV1562839', 5, 12, TRUE, FALSE)
        ) AS t(ma_cb, ma_mon, ma_kh, de_chung, de_chinh_thuc)
    LOOP
        INSERT INTO PhanQuyenTheoKhoiMon (
            ma_tai_khoan, ma_khoi, ma_mon_hoc,
            duoc_truy_cap_de_chung, duoc_truy_cap_de_chinh_thuc, nguoi_cap_quyen
        )
        SELECT tk.ma_tai_khoan, r.ma_kh, r.ma_mon, r.de_chung, r.de_chinh_thuc, v_admin
        FROM TaiKhoan tk
        WHERE tk.ma_can_bo = r.ma_cb
        ON CONFLICT (ma_tai_khoan, ma_khoi, ma_mon_hoc) DO UPDATE
        SET duoc_truy_cap_de_chung = EXCLUDED.duoc_truy_cap_de_chung,
            duoc_truy_cap_de_chinh_thuc = EXCLUDED.duoc_truy_cap_de_chinh_thuc,
            nguoi_cap_quyen = EXCLUDED.nguoi_cap_quyen;
    END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- 7. BẢNG DeOnTap (Kho đề ôn tập - CN_DeOnTap)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DeOnTap (
    ma_de_on_tap       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ten_de_on_tap      VARCHAR(200) NOT NULL,
    ma_mon_hoc         SMALLINT NOT NULL REFERENCES MonHoc(ma_mon_hoc) ON DELETE CASCADE,
    ma_khoi            SMALLINT NOT NULL REFERENCES KhoiLop(ma_khoi) ON DELETE CASCADE,
    loai_de            VARCHAR(20) NOT NULL,
    nguoi_tao          UUID NOT NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE CASCADE,
    duong_dan_tep      VARCHAR(500) NOT NULL,
    ten_tep_goc        VARCHAR(255) NOT NULL DEFAULT 'De_On_Tap.pdf',
    ma_bam_sha256      CHAR(64) NOT NULL,
    da_chinh_sua       BOOLEAN NOT NULL DEFAULT FALSE,
    thoi_diem_tao      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    thoi_diem_cap_nhat TIMESTAMPTZ NULL DEFAULT NULL,
    nguoi_cap_nhat     UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL
);

ALTER TABLE DeOnTap ADD COLUMN IF NOT EXISTS ten_tep_goc VARCHAR(255) NOT NULL DEFAULT 'De_On_Tap.pdf';
ALTER TABLE DeOnTap ADD COLUMN IF NOT EXISTS da_chinh_sua BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE DeOnTap ALTER COLUMN thoi_diem_cap_nhat DROP NOT NULL;
ALTER TABLE DeOnTap ALTER COLUMN thoi_diem_cap_nhat DROP DEFAULT;
ALTER TABLE DeOnTap ALTER COLUMN nguoi_cap_nhat DROP NOT NULL;
UPDATE DeOnTap SET thoi_diem_cap_nhat = NULL, nguoi_cap_nhat = NULL WHERE COALESCE(da_chinh_sua, FALSE) = FALSE;
UPDATE DeOnTap
SET da_chinh_sua = FALSE,
    thoi_diem_cap_nhat = NULL,
    nguoi_cap_nhat = NULL
WHERE nguoi_cap_nhat IS NOT NULL
  AND nguoi_cap_nhat IS DISTINCT FROM nguoi_tao;

ALTER TABLE DeOnTap DROP CONSTRAINT IF EXISTS chk_deontap_chi_nguoi_tao_sua;
ALTER TABLE DeOnTap ADD CONSTRAINT chk_deontap_chi_nguoi_tao_sua
    CHECK (nguoi_cap_nhat IS NULL OR nguoi_cap_nhat = nguoi_tao);

CREATE OR REPLACE FUNCTION fn_kiem_tra_chu_so_huu_de_on_tap()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.nguoi_tao IS DISTINCT FROM OLD.nguoi_tao THEN
        RAISE EXCEPTION 'Không được phép thay đổi người tạo gốc của đề ôn tập.';
    END IF;
    IF NEW.nguoi_cap_nhat IS NOT NULL AND NEW.nguoi_cap_nhat IS DISTINCT FROM OLD.nguoi_tao THEN
        RAISE EXCEPTION 'Đề của giáo viên nào tạo thì chỉ chính giáo viên đó mới được phép chỉnh sửa.';
    END IF;
    IF COALESCE(NEW.da_chinh_sua, FALSE) = TRUE AND NEW.nguoi_cap_nhat IS DISTINCT FROM OLD.nguoi_tao THEN
        RAISE EXCEPTION 'Đề của giáo viên nào tạo thì chỉ chính giáo viên đó mới được phép chỉnh sửa.';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_deontap_chi_nguoi_tao_sua ON DeOnTap;
CREATE TRIGGER trg_deontap_chi_nguoi_tao_sua
BEFORE UPDATE ON DeOnTap
FOR EACH ROW
EXECUTE FUNCTION fn_kiem_tra_chu_so_huu_de_on_tap();

CREATE INDEX IF NOT EXISTS idx_deontap_mon_khoi ON DeOnTap(ma_mon_hoc, ma_khoi);

-- -----------------------------------------------------------------------------
-- 8. BẢNG LichThi (Lịch thi - CN_DeThi.docx & CN_TaiLieu.docx)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS LichThi (
    ma_lich_thi        SERIAL PRIMARY KEY,
    ten_ky_thi         VARCHAR(200) NOT NULL,
    loai_ky_thi        VARCHAR(50) NOT NULL DEFAULT 'Giữa kỳ I',
    ten_lich_thi       VARCHAR(200) NOT NULL,
    nam_hoc            VARCHAR(20) NOT NULL,
    ma_mon_hoc         SMALLINT NOT NULL REFERENCES MonHoc(ma_mon_hoc) ON DELETE CASCADE,
    ma_khoi            SMALLINT NOT NULL REFERENCES KhoiLop(ma_khoi) ON DELETE CASCADE,
    gio_bat_dau        TIMESTAMPTZ NOT NULL,
    gio_ket_thuc       TIMESTAMPTZ NOT NULL,
    thoi_gian_bat_dau  TIMESTAMPTZ NOT NULL,
    thoi_gian_ket_thuc TIMESTAMPTZ NOT NULL CHECK (thoi_gian_ket_thuc > thoi_gian_bat_dau),
    nguoi_tao_lich     UUID NOT NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE CASCADE,
    thoi_diem_tao      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE LichThi ADD COLUMN IF NOT EXISTS ten_ky_thi VARCHAR(200);
ALTER TABLE LichThi ADD COLUMN IF NOT EXISTS loai_ky_thi VARCHAR(50) NOT NULL DEFAULT 'Giữa kỳ I';
ALTER TABLE LichThi ADD COLUMN IF NOT EXISTS gio_bat_dau TIMESTAMPTZ;
ALTER TABLE LichThi ADD COLUMN IF NOT EXISTS gio_ket_thuc TIMESTAMPTZ;

-- -----------------------------------------------------------------------------
-- 9. BẢNG DeThi (Kho đề thi - CN_DeThi.docx & CN_TaiLieu.docx)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DeThi (
    ma_de_thi             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ma_lich_thi           INTEGER NOT NULL REFERENCES LichThi(ma_lich_thi) ON DELETE CASCADE,
    ten_de_thi            VARCHAR(200) NOT NULL,
    nguoi_ra_de           UUID NOT NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE CASCADE,
    duong_dan_tep         VARCHAR(500) NOT NULL,
    ma_bam_sha256         CHAR(64) NOT NULL,
    thoi_diem_tao         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    thoi_diem_cap_nhat    TIMESTAMPTZ NULL DEFAULT NULL,
    nguoi_cap_nhat        UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL,
    -- Các trường mở rộng tương thích CN_TaiLieu.docx:
    ma_mon_hoc            BIGINT NOT NULL REFERENCES MonHoc(ma_mon_hoc) ON DELETE CASCADE,
    ma_khoi               SMALLINT NOT NULL REFERENCES KhoiLop(ma_khoi) ON DELETE CASCADE,
    loai                  VARCHAR(20) NOT NULL DEFAULT 'Đề thi' CHECK (loai IN ('Đề thi', 'Đáp án')),
    loai_de               VARCHAR(20) NOT NULL DEFAULT 'CHINH_THUC' CHECK (loai_de IN ('CHINH_THUC', 'ON_TAP', 'DE_MOI')),
    da_nem_phong          BOOLEAN NOT NULL DEFAULT FALSE,
    thoi_diem_niem_phong  TIMESTAMPTZ NULL,
    nguoi_niem_phong      UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL,
    duong_dan_tep_ma_hoa  VARCHAR(500) NOT NULL,
    ten_tep_goc           VARCHAR(255) NOT NULL,
    da_chinh_sua          BOOLEAN NOT NULL DEFAULT FALSE,
    chu_ky_so_nguoi_ra_de BYTEA NULL,
    khoa_ma_hoa_de        BYTEA NULL,
    ma_nonce_aes          BYTEA NULL,
    the_xac_thuc_aes      BYTEA NULL,
    bi_can_thiep          BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS duong_dan_tep VARCHAR(500);
ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS thoi_diem_cap_nhat TIMESTAMPTZ NULL DEFAULT NULL;
ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS nguoi_cap_nhat UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL;
ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS da_chinh_sua BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE DeThi ALTER COLUMN thoi_diem_cap_nhat DROP NOT NULL;
ALTER TABLE DeThi ALTER COLUMN thoi_diem_cap_nhat DROP DEFAULT;
ALTER TABLE DeThi ALTER COLUMN nguoi_cap_nhat DROP NOT NULL;
UPDATE DeThi SET thoi_diem_cap_nhat = NULL, nguoi_cap_nhat = NULL WHERE COALESCE(da_chinh_sua, FALSE) = FALSE;

ALTER TABLE DeThi ALTER COLUMN da_nem_phong SET DEFAULT FALSE;
ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS loai VARCHAR(20) NOT NULL DEFAULT 'Đề thi';
ALTER TABLE DeThi DROP CONSTRAINT IF EXISTS chk_dethi_loai;
ALTER TABLE DeThi ADD CONSTRAINT chk_dethi_loai CHECK (loai IN ('Đề thi', 'Đáp án'));

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'dethi' AND column_name = 'thoi_diem_niem_phong'
    ) THEN
        ALTER TABLE DeThi ADD COLUMN thoi_diem_niem_phong TIMESTAMPTZ NULL;
        ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS nguoi_niem_phong UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL;
        -- Đặt lại cờ niêm phong thủ công về FALSE cho các đề thi mẫu chưa bấm niêm phong (trừ đề mồi)
        UPDATE DeThi SET da_nem_phong = FALSE WHERE loai_de != 'DE_MOI';
    END IF;
END $$;
ALTER TABLE DeThi ADD COLUMN IF NOT EXISTS nguoi_niem_phong UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL;

-- Hủy dấu vết cập nhật chéo cũ từ thời điểm trước khi khóa quyền chủ sở hữu (đề ai ra chỉ người đó được sửa)
UPDATE DeThi
SET da_chinh_sua = FALSE,
    thoi_diem_cap_nhat = NULL,
    nguoi_cap_nhat = NULL
WHERE nguoi_cap_nhat IS NOT NULL
  AND nguoi_cap_nhat IS DISTINCT FROM nguoi_ra_de;

UPDATE DeThi
SET nguoi_niem_phong = nguoi_ra_de
WHERE nguoi_niem_phong IS NOT NULL
  AND nguoi_niem_phong IS DISTINCT FROM nguoi_ra_de;

ALTER TABLE DeThi DROP CONSTRAINT IF EXISTS chk_dethi_chi_nguoi_ra_de_sua;
ALTER TABLE DeThi ADD CONSTRAINT chk_dethi_chi_nguoi_ra_de_sua
    CHECK (
        (nguoi_cap_nhat IS NULL OR nguoi_cap_nhat = nguoi_ra_de)
        AND (nguoi_niem_phong IS NULL OR nguoi_niem_phong = nguoi_ra_de)
    );

CREATE OR REPLACE FUNCTION fn_kiem_tra_chu_so_huu_de_thi()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.nguoi_ra_de IS DISTINCT FROM OLD.nguoi_ra_de THEN
        RAISE EXCEPTION 'Không được phép thay đổi người ra đề gốc của tài liệu thi.';
    END IF;
    IF NEW.nguoi_cap_nhat IS NOT NULL AND NEW.nguoi_cap_nhat IS DISTINCT FROM OLD.nguoi_ra_de THEN
        RAISE EXCEPTION 'Đề của giáo viên nào ra thì chỉ chính giáo viên đó mới được phép chỉnh sửa.';
    END IF;
    IF COALESCE(NEW.da_chinh_sua, FALSE) = TRUE AND NEW.nguoi_cap_nhat IS DISTINCT FROM OLD.nguoi_ra_de THEN
        RAISE EXCEPTION 'Đề của giáo viên nào ra thì chỉ chính giáo viên đó mới được phép chỉnh sửa.';
    END IF;
    IF NEW.nguoi_niem_phong IS NOT NULL AND NEW.nguoi_niem_phong IS DISTINCT FROM OLD.nguoi_ra_de THEN
        RAISE EXCEPTION 'Đề của giáo viên nào ra thì chỉ chính giáo viên đó mới được phép niêm phong.';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_dethi_chi_nguoi_ra_de_sua ON DeThi;
CREATE TRIGGER trg_dethi_chi_nguoi_ra_de_sua
BEFORE UPDATE ON DeThi
FOR EACH ROW
EXECUTE FUNCTION fn_kiem_tra_chu_so_huu_de_thi();

CREATE INDEX IF NOT EXISTS idx_dethi_mon_khoi ON DeThi(ma_mon_hoc, ma_khoi);

-- -----------------------------------------------------------------------------
-- 10. BẢNG TepBay (Bẫy mồi nhử - CN_TaiLieu)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS TepBay (
    ma_bay                       BIGSERIAL PRIMARY KEY,
    ma_de_thi                    UUID NOT NULL REFERENCES DeThi(ma_de_thi) ON DELETE CASCADE,
    ten_tep_bay                  VARCHAR(255) NOT NULL,
    duong_dan_kich_hoat          VARCHAR(255) UNIQUE NOT NULL,
    so_lan_kich_hoat             INT NOT NULL DEFAULT 0 CHECK (so_lan_kich_hoat >= 0),
    thoi_diem_kich_hoat_gan_nhat TIMESTAMPTZ NULL,
    dang_hoat_dong               BOOLEAN NOT NULL DEFAULT TRUE
);

-- -----------------------------------------------------------------------------
-- 11. BẢNG ChanDiaChiIP (Danh sách chặn địa chỉ IP an ninh từ Nhật ký hoạt động)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ChanDiaChiIP (
    ma_chan_ip     SERIAL PRIMARY KEY,
    dia_chi_ip     INET UNIQUE NOT NULL,
    ly_do          TEXT NOT NULL DEFAULT 'Chặn truy cập từ Nhật ký hoạt động',
    dang_chan      BOOLEAN NOT NULL DEFAULT TRUE,
    nguoi_chan     UUID NULL REFERENCES TaiKhoan(ma_tai_khoan) ON DELETE SET NULL,
    thoi_diem_chan TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


