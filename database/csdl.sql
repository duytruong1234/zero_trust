--
-- PostgreSQL database dump
--

\restrict 1U6utf0sZGcKBMLhgxhp5Ox0WjoBG4byULJY9cOcfX7Ce0jcSQNoRTgHeB0115R

-- Dumped from database version 17.9
-- Dumped by pg_dump version 17.9

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: fn_chan_chinh_sua_nhat_ky_log(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_chan_chinh_sua_nhat_ky_log() RETURNS trigger
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


ALTER FUNCTION public.fn_chan_chinh_sua_nhat_ky_log() OWNER TO postgres;

--
-- Name: fn_chan_truncate_nhat_ky_log(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_chan_truncate_nhat_ky_log() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'BÁO ĐỘNG AN NINH: Nghiêm cấm xóa trắng (TRUNCATE) bảng NhatKyLog!';
END;
$$;


ALTER FUNCTION public.fn_chan_truncate_nhat_ky_log() OWNER TO postgres;

--
-- Name: fn_chan_xoa_nhat_ky_log(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_chan_xoa_nhat_ky_log() RETURNS trigger
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


ALTER FUNCTION public.fn_chan_xoa_nhat_ky_log() OWNER TO postgres;

--
-- Name: fn_kiem_tra_chu_so_huu_de_on_tap(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_kiem_tra_chu_so_huu_de_on_tap() RETURNS trigger
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


ALTER FUNCTION public.fn_kiem_tra_chu_so_huu_de_on_tap() OWNER TO postgres;

--
-- Name: fn_kiem_tra_chu_so_huu_de_thi(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_kiem_tra_chu_so_huu_de_thi() RETURNS trigger
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


ALTER FUNCTION public.fn_kiem_tra_chu_so_huu_de_thi() OWNER TO postgres;

--
-- Name: fn_nhat_ky_log_noi_chuoi(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_nhat_ky_log_noi_chuoi() RETURNS trigger
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


ALTER FUNCTION public.fn_nhat_ky_log_noi_chuoi() OWNER TO postgres;

--
-- Name: fn_tinh_bam_nhat_ky_log(bigint, character, uuid, character varying, inet, inet, character varying, text, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_tinh_bam_nhat_ky_log(p_ma_nhat_ky bigint, p_ma_bam_truoc character, p_ma_tai_khoan uuid, p_hanh_dong character varying, p_ip_thiet_bi inet, p_ipv4 inet, p_ket_qua character varying, p_chi_tiet text, p_thoi_diem timestamp with time zone) RETURNS character
    LANGUAGE sql IMMUTABLE
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


ALTER FUNCTION public.fn_tinh_bam_nhat_ky_log(p_ma_nhat_ky bigint, p_ma_bam_truoc character, p_ma_tai_khoan uuid, p_hanh_dong character varying, p_ip_thiet_bi inet, p_ipv4 inet, p_ket_qua character varying, p_chi_tiet text, p_thoi_diem timestamp with time zone) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: chandiachiip; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.chandiachiip (
    ma_chan_ip integer NOT NULL,
    dia_chi_ip inet NOT NULL,
    ly_do text DEFAULT 'Chặn truy cập từ Nhật ký hoạt động'::text NOT NULL,
    dang_chan boolean DEFAULT true NOT NULL,
    nguoi_chan uuid,
    thoi_diem_chan timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.chandiachiip OWNER TO postgres;

--
-- Name: chandiachiip_ma_chan_ip_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.chandiachiip_ma_chan_ip_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.chandiachiip_ma_chan_ip_seq OWNER TO postgres;

--
-- Name: chandiachiip_ma_chan_ip_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.chandiachiip_ma_chan_ip_seq OWNED BY public.chandiachiip.ma_chan_ip;


--
-- Name: deontap; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.deontap (
    ma_de_on_tap uuid DEFAULT gen_random_uuid() NOT NULL,
    ten_de_on_tap character varying(200) NOT NULL,
    ma_mon_hoc smallint NOT NULL,
    ma_khoi smallint NOT NULL,
    loai_de character varying(20) NOT NULL,
    nguoi_tao uuid NOT NULL,
    duong_dan_tep character varying(500) NOT NULL,
    ten_tep_goc character varying(255) DEFAULT 'De_On_Tap.pdf'::character varying NOT NULL,
    ma_bam_sha256 character(64) NOT NULL,
    da_chinh_sua boolean DEFAULT false NOT NULL,
    thoi_diem_tao timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    thoi_diem_cap_nhat timestamp with time zone,
    nguoi_cap_nhat uuid,
    CONSTRAINT chk_deontap_chi_nguoi_tao_sua CHECK (((nguoi_cap_nhat IS NULL) OR (nguoi_cap_nhat = nguoi_tao)))
);


ALTER TABLE public.deontap OWNER TO postgres;

--
-- Name: dethi; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.dethi (
    ma_de_thi uuid DEFAULT gen_random_uuid() NOT NULL,
    ma_lich_thi bigint,
    ten_de_thi character varying(200) NOT NULL,
    ma_mon_hoc bigint NOT NULL,
    ma_khoi smallint NOT NULL,
    loai_de character varying(20) NOT NULL,
    da_nem_phong boolean DEFAULT false NOT NULL,
    nguoi_ra_de uuid NOT NULL,
    duong_dan_tep_ma_hoa character varying(500) NOT NULL,
    ten_tep_goc character varying(255) NOT NULL,
    ma_bam_sha256 character(64) NOT NULL,
    chu_ky_so_nguoi_ra_de bytea NOT NULL,
    khoa_ma_hoa_de bytea NOT NULL,
    ma_nonce_aes bytea NOT NULL,
    the_xac_thuc_aes bytea NOT NULL,
    bi_can_thiep boolean DEFAULT false NOT NULL,
    thoi_diem_tao timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    duong_dan_tep character varying(500),
    thoi_diem_cap_nhat timestamp with time zone,
    nguoi_cap_nhat uuid,
    da_chinh_sua boolean DEFAULT false NOT NULL,
    loai character varying(20) DEFAULT 'Đề thi'::character varying NOT NULL,
    thoi_diem_niem_phong timestamp with time zone,
    nguoi_niem_phong uuid,
    CONSTRAINT chk_dethi_chi_nguoi_ra_de_sua CHECK ((((nguoi_cap_nhat IS NULL) OR (nguoi_cap_nhat = nguoi_ra_de)) AND ((nguoi_niem_phong IS NULL) OR (nguoi_niem_phong = nguoi_ra_de)))),
    CONSTRAINT chk_dethi_loai CHECK (((loai)::text = ANY ((ARRAY['Đề thi'::character varying, 'Đáp án'::character varying])::text[]))),
    CONSTRAINT dethi_loai_de_check CHECK (((loai_de)::text = ANY ((ARRAY['CHINH_THUC'::character varying, 'ON_TAP'::character varying, 'DE_MOI'::character varying])::text[])))
);


ALTER TABLE public.dethi OWNER TO postgres;

--
-- Name: khoilop; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.khoilop (
    ma_khoi smallint NOT NULL,
    ten_khoi character varying(20) NOT NULL
);


ALTER TABLE public.khoilop OWNER TO postgres;

--
-- Name: lichthi; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.lichthi (
    ma_lich_thi integer NOT NULL,
    ten_lich_thi character varying(150) NOT NULL,
    nam_hoc character varying(20) NOT NULL,
    ma_khoi smallint NOT NULL,
    ma_mon_hoc smallint NOT NULL,
    thoi_gian_bat_dau timestamp with time zone NOT NULL,
    thoi_gian_ket_thuc timestamp with time zone NOT NULL,
    nguoi_tao_lich uuid NOT NULL,
    thoi_diem_tao timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ten_ky_thi character varying(200),
    loai_ky_thi character varying(50) DEFAULT 'Giữa kỳ I'::character varying NOT NULL,
    gio_bat_dau timestamp with time zone,
    gio_ket_thuc timestamp with time zone,
    CONSTRAINT lichthi_check CHECK ((thoi_gian_ket_thuc > thoi_gian_bat_dau))
);


ALTER TABLE public.lichthi OWNER TO postgres;

--
-- Name: lichthi_ma_lich_thi_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.lichthi_ma_lich_thi_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.lichthi_ma_lich_thi_seq OWNER TO postgres;

--
-- Name: lichthi_ma_lich_thi_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.lichthi_ma_lich_thi_seq OWNED BY public.lichthi.ma_lich_thi;


--
-- Name: monhoc; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.monhoc (
    ma_mon_hoc smallint NOT NULL,
    ky_hieu_mon character varying(20) NOT NULL,
    ten_mon_hoc character varying(50) NOT NULL,
    dang_su_dung boolean DEFAULT true NOT NULL
);


ALTER TABLE public.monhoc OWNER TO postgres;

--
-- Name: monhoc_ma_mon_hoc_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.monhoc_ma_mon_hoc_seq
    AS smallint
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.monhoc_ma_mon_hoc_seq OWNER TO postgres;

--
-- Name: monhoc_ma_mon_hoc_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.monhoc_ma_mon_hoc_seq OWNED BY public.monhoc.ma_mon_hoc;


--
-- Name: nhatkylog; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.nhatkylog (
    ma_nhat_ky bigint NOT NULL,
    ma_bam_truoc character(64) NOT NULL,
    ma_tai_khoan uuid,
    hanh_dong character varying(50) NOT NULL,
    ip_thiet_bi inet NOT NULL,
    ipv4 inet NOT NULL,
    ket_qua character varying(30) NOT NULL,
    chi_tiet text NOT NULL,
    thoi_diem timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ma_bam_nhat_ky character(64) NOT NULL,
    thong_tin_thiet_bi text,
    tai_lieu_thao_tac character varying(255) DEFAULT ''::character varying,
    ket_qua_goc character varying(30),
    bi_can_thiep boolean DEFAULT false NOT NULL,
    so_lan_can_thiep integer DEFAULT 0 NOT NULL,
    thoi_diem_can_thiep timestamp with time zone,
    chi_tiet_can_thiep text,
    CONSTRAINT chk_nhat_ky_ket_qua CHECK (((ket_qua)::text = ANY ((ARRAY['Thành công'::character varying, 'Thất bại'::character varying, 'Cảnh báo'::character varying, 'Báo động'::character varying])::text[]))),
    CONSTRAINT chk_nhat_ky_ket_qua_goc CHECK (((ket_qua_goc IS NULL) OR ((ket_qua_goc)::text = ANY ((ARRAY['Thành công'::character varying, 'Thất bại'::character varying, 'Cảnh báo'::character varying, 'Báo động'::character varying])::text[]))))
);


ALTER TABLE public.nhatkylog OWNER TO postgres;

--
-- Name: nhatkylog_ma_nhat_ky_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.nhatkylog_ma_nhat_ky_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.nhatkylog_ma_nhat_ky_seq OWNER TO postgres;

--
-- Name: nhatkylog_ma_nhat_ky_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.nhatkylog_ma_nhat_ky_seq OWNED BY public.nhatkylog.ma_nhat_ky;


--
-- Name: phanquyentheokhoimon; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.phanquyentheokhoimon (
    ma_phan_quyen integer NOT NULL,
    ma_tai_khoan uuid NOT NULL,
    ma_khoi smallint NOT NULL,
    ma_mon_hoc bigint NOT NULL,
    duoc_truy_cap_de_chung boolean DEFAULT true NOT NULL,
    duoc_truy_cap_de_chinh_thuc boolean DEFAULT false NOT NULL,
    nguoi_cap_quyen uuid,
    thoi_diem_cap_quyen timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.phanquyentheokhoimon OWNER TO postgres;

--
-- Name: phanquyentheokhoimon_ma_phan_quyen_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.phanquyentheokhoimon_ma_phan_quyen_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.phanquyentheokhoimon_ma_phan_quyen_seq OWNER TO postgres;

--
-- Name: phanquyentheokhoimon_ma_phan_quyen_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.phanquyentheokhoimon_ma_phan_quyen_seq OWNED BY public.phanquyentheokhoimon.ma_phan_quyen;


--
-- Name: phiendangnhap; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.phiendangnhap (
    ma_phien uuid DEFAULT gen_random_uuid() NOT NULL,
    ma_tai_khoan uuid NOT NULL,
    ma_phien_bam character(64) NOT NULL,
    ip_thiet_bi inet NOT NULL,
    ipv4 inet NOT NULL,
    thong_tin_thiet_bi text,
    da_xac_thuc_otp boolean DEFAULT false NOT NULL,
    da_thu_hoi boolean DEFAULT false NOT NULL,
    thoi_diem_het_han timestamp with time zone NOT NULL,
    thoi_diem_tao timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.phiendangnhap OWNER TO postgres;

--
-- Name: TABLE phiendangnhap; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.phiendangnhap IS 'Bảng quản lý phiên đăng nhập, chống đánh cắp Cookie và kiểm soát cổng 2FA';


--
-- Name: COLUMN phiendangnhap.ma_phien_bam; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phiendangnhap.ma_phien_bam IS 'Mã băm SHA-256 của Session Token gửi về Cookie trình duyệt';


--
-- Name: COLUMN phiendangnhap.da_xac_thuc_otp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phiendangnhap.da_xac_thuc_otp IS 'Kiểm soát cổng 2FA: chỉ cho phép truy cập tài nguyên khi cờ = TRUE';


--
-- Name: taikhoan; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.taikhoan (
    ma_tai_khoan uuid DEFAULT gen_random_uuid() NOT NULL,
    ma_can_bo character varying(20) NOT NULL,
    ten_dang_nhap character varying(50) NOT NULL,
    mat_khau character varying(255) NOT NULL,
    ho_ten character varying(100) NOT NULL,
    email character varying(100) NOT NULL,
    vai_tro character varying(30) NOT NULL,
    bi_mat_otp_ma_hoa bytea,
    da_kich_hoat_otp boolean DEFAULT false,
    bi_khoa boolean DEFAULT false,
    so_lan_dang_nhap_sai integer DEFAULT 0,
    so_lan_sai_otp integer DEFAULT 0,
    ip_thiet_bi_gan_nhat inet,
    ipv4_gan_nhat inet,
    thoi_diem_tao timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    dang_hoat_dong boolean DEFAULT true,
    khoa_den_thoi_diem timestamp with time zone,
    ma_pin character varying(255),
    ma_xac_nhan_pin character varying(255),
    han_xac_nhan_pin timestamp with time zone,
    CONSTRAINT chk_taikhoan_email_domain CHECK (((email)::text ~~ '%@thpthoangvanthu.edu.vn'::text)),
    CONSTRAINT chk_taikhoan_ma_can_bo CHECK (((ma_can_bo)::text ~ '^(GV|AD|HT)[0-9]{7}$'::text)),
    CONSTRAINT chk_taikhoan_ten_dang_nhap CHECK (((ten_dang_nhap)::text ~ '^[a-z0-9.]+$'::text)),
    CONSTRAINT chk_taikhoan_vai_tro CHECK (((vai_tro)::text = ANY ((ARRAY['GIAO_VIEN'::character varying, 'BAN_GIAM_HIEU'::character varying, 'QUAN_TRI'::character varying])::text[])))
);


ALTER TABLE public.taikhoan OWNER TO postgres;

--
-- Name: TABLE taikhoan; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.taikhoan IS 'Bảng lưu trữ thông tin tài khoản người dùng và cấu hình bảo mật 2FA TOTP';


--
-- Name: COLUMN taikhoan.ma_tai_khoan; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ma_tai_khoan IS 'Mã định danh duy nhất của tài khoản (UUID)';


--
-- Name: COLUMN taikhoan.ma_can_bo; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ma_can_bo IS 'Mã quản lý hiển thị: Tên viết tắt vai trò (GV/AD/HT) + 7 số ngẫu nhiên';


--
-- Name: COLUMN taikhoan.ten_dang_nhap; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ten_dang_nhap IS 'Tên đăng nhập viết thường, không dấu, chỉ gồm chữ, số và dấu chấm (^[a-z0-9.]+$)';


--
-- Name: COLUMN taikhoan.mat_khau; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.mat_khau IS 'Mật khẩu đã được mã băm (bcrypt)';


--
-- Name: COLUMN taikhoan.email; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.email IS 'Địa chỉ email nội bộ trường (@thpthoangvanthu.edu.vn)';


--
-- Name: COLUMN taikhoan.vai_tro; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.vai_tro IS 'Vai trò phân cấp: GIAO_VIEN / BAN_GIAM_HIEU / QUAN_TRI';


--
-- Name: COLUMN taikhoan.bi_mat_otp_ma_hoa; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.bi_mat_otp_ma_hoa IS 'Khóa bí mật TOTP đã mã hóa AES-256 + Master Key';


--
-- Name: COLUMN taikhoan.da_kich_hoat_otp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.da_kich_hoat_otp IS 'Trạng thái kích hoạt 2FA (FALSE: hiện QR lần đầu; TRUE: khóa QR vĩnh viễn)';


--
-- Name: COLUMN taikhoan.khoa_den_thoi_diem; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.khoa_den_thoi_diem IS 'Thời điểm tự động mở khóa an ninh (NOW() + 15 phút khi sai mật khẩu 5 lần / sai OTP 3 lần)';


--
-- Name: COLUMN taikhoan.ma_pin; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ma_pin IS 'Mã PIN xác minh 6 chữ số đã mã băm (bcrypt) dùng khi tải hoặc niêm phong đề ôn tập, đề thi';


--
-- Name: tepbay; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tepbay (
    ma_bay bigint NOT NULL,
    ma_de_thi uuid NOT NULL,
    ten_tep_bay character varying(255) NOT NULL,
    duong_dan_kich_hoat character varying(255) NOT NULL,
    so_lan_kich_hoat integer DEFAULT 0 NOT NULL,
    thoi_diem_kich_hoat_gan_nhat timestamp with time zone,
    dang_hoat_dong boolean DEFAULT true NOT NULL,
    CONSTRAINT tepbay_so_lan_kich_hoat_check CHECK ((so_lan_kich_hoat >= 0))
);


ALTER TABLE public.tepbay OWNER TO postgres;

--
-- Name: tepbay_ma_bay_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tepbay_ma_bay_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.tepbay_ma_bay_seq OWNER TO postgres;

--
-- Name: tepbay_ma_bay_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tepbay_ma_bay_seq OWNED BY public.tepbay.ma_bay;


--
-- Name: chandiachiip ma_chan_ip; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip ALTER COLUMN ma_chan_ip SET DEFAULT nextval('public.chandiachiip_ma_chan_ip_seq'::regclass);


--
-- Name: lichthi ma_lich_thi; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi ALTER COLUMN ma_lich_thi SET DEFAULT nextval('public.lichthi_ma_lich_thi_seq'::regclass);


--
-- Name: monhoc ma_mon_hoc; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc ALTER COLUMN ma_mon_hoc SET DEFAULT nextval('public.monhoc_ma_mon_hoc_seq'::regclass);


--
-- Name: nhatkylog ma_nhat_ky; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nhatkylog ALTER COLUMN ma_nhat_ky SET DEFAULT nextval('public.nhatkylog_ma_nhat_ky_seq'::regclass);


--
-- Name: phanquyentheokhoimon ma_phan_quyen; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon ALTER COLUMN ma_phan_quyen SET DEFAULT nextval('public.phanquyentheokhoimon_ma_phan_quyen_seq'::regclass);


--
-- Name: tepbay ma_bay; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay ALTER COLUMN ma_bay SET DEFAULT nextval('public.tepbay_ma_bay_seq'::regclass);


--
-- Data for Name: chandiachiip; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.chandiachiip (ma_chan_ip, dia_chi_ip, ly_do, dang_chan, nguoi_chan, thoi_diem_chan) FROM stdin;
3	192.168.1.4	Chặn từ điều tra nhật ký #145	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 13:59:16.30602+07
4	171.250.165.204	Chặn từ bảng Quản lý tài khoản (Nguyễn Văn Minh - GV1000458)	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 20:09:58.764558+07
\.


--
-- Data for Name: deontap; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.deontap (ma_de_on_tap, ten_de_on_tap, ma_mon_hoc, ma_khoi, loai_de, nguoi_tao, duong_dan_tep, ten_tep_goc, ma_bam_sha256, da_chinh_sua, thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat) FROM stdin;
1b47751e-1dbf-41e7-ab3c-54c97e0927e3	Ôn tập Toán giữa kỳ I	1	10	Giữa kỳ I	51c35c7f-0e7c-4880-8925-2f06926f89b0	storage/de_on_tap/1b47751e-1dbf-41e7-ab3c-54c97e0927e3.enc	De_Toan_10_GiuaKy1.pdf	a3f64721879ec9c1830266c9d6e8e44d48cd4a875a0e77cddfb3366ad9e7a07e	f	2026-10-28 14:30:00+07	\N	\N
cafc0f1b-2004-4178-9666-4dccbe57ce14	Ôn tập Toán cuối kỳ I	1	10	Cuối kỳ I	51c35c7f-0e7c-4880-8925-2f06926f89b0	storage/de_on_tap/cafc0f1b-2004-4178-9666-4dccbe57ce14.enc	De_Toan_10_CuoiKy1.pdf	5aaf180aff2386b659140b3167007ce35b793049512cfb985f9493e4dbfe300e	f	2026-10-27 16:20:00+07	\N	\N
86a7819c-797f-4a12-a76f-ec3058874495	Ôn tập Toán giữa kỳ II	1	11	Giữa kỳ II	9ea71a69-8aee-4305-a2aa-65b193245bc1	storage/de_on_tap/86a7819c-797f-4a12-a76f-ec3058874495.enc	De_Toan_11_GiuaKy2.pdf	7cf3feb5e17f1deb1a1f29b4b9660504e2746daca54db248a3f09f2e33b0dcf7	f	2026-10-26 09:15:00+07	\N	\N
10eb8c14-4d56-41e1-b1a3-d27c1bb1dbbe	Ôn tập Toán cuối kỳ II	1	12	Cuối kỳ II	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_on_tap/10eb8c14-4d56-41e1-b1a3-d27c1bb1dbbe.enc	De_Toan_12_CuoiKy2.pdf	47de0aff06a9a54521c5ae8dc6f676bf7c827a484edd1a0cc791bae2f2181a73	f	2026-10-25 11:05:00+07	\N	\N
5d971cf9-0777-4237-bf84-43a96b357d8d	Ôn tập Vật lý giữa kỳ I	5	10	Giữa kỳ I	bc398092-6172-4a0b-8095-dc4f9d33c177	storage/de_on_tap/5d971cf9-0777-4237-bf84-43a96b357d8d.enc	De_Ly_10_GiuaKy1.pdf	bf5beefc7a7777fde9790da9ce5a4809f1e764b9a94eaf31f94ce48827a1511b	f	2026-10-28 14:30:00+07	\N	\N
8874dc39-deca-4fec-bd36-da756e6cc31d	Ôn tập Vật lý cuối kỳ I	5	11	Cuối kỳ I	674289a6-2f98-4142-b90f-436c9e5ab1b4	storage/de_on_tap/8874dc39-deca-4fec-bd36-da756e6cc31d.enc	De_Ly_11_CuoiKy1.pdf	cf8c49f959b0d52cbb76a1f57876b9a7c230e629486b0f0bbd1f35001e43c808	f	2026-10-27 16:20:00+07	\N	\N
7a805370-3e45-4fcb-9286-54af160a12bc	Ôn tập Dao động cơ & Sóng điện từ	5	12	Cuối kỳ II	674289a6-2f98-4142-b90f-436c9e5ab1b4	storage/de_on_tap/7a805370-3e45-4fcb-9286-54af160a12bc.enc	De_Ly_12_DaoDong.pdf	c6f8203f561319e3043bc56b0cc9d52a682b320a39e58a586890a7540810956a	f	2026-10-25 11:05:00+07	\N	\N
777a9dd7-3e2a-4e3a-b1ee-6e69a6ba1632	Đề ôn tập chương Hàm số	1	12	Giữa kỳ II	51c35c7f-0e7c-4880-8925-2f06926f89b0	storage/de_on_tap/777a9dd7-3e2a-4e3a-b1ee-6e69a6ba1632.enc	De_Toan_12_HamSo.pdf	63901f41d6ccf34d4dd46d9cc6ab87b4be2d08da7f6cb7486cedec863b01f1f0	f	2026-10-22 13:40:00+07	\N	\N
16d1268e-8d47-4753-8bd5-94916ae584a2	Đề ôn tập Hình học không gian	1	11	Cuối kỳ I	9ea71a69-8aee-4305-a2aa-65b193245bc1	storage/de_on_tap/16d1268e-8d47-4753-8bd5-94916ae584a2.enc	De_Toan_11_HinhHoc.pdf	bbac801ee60eccb4ce71eaf0fd8b2b51b3b78e857a0733dfd9ac73d5a6c9cda0	f	2026-10-20 08:30:00+07	\N	\N
36fdc16f-fc50-4da4-951a-e4de72e300bd	Ôn tập Ngữ văn giữa kỳ I	2	10	Giữa kỳ I	48f58e38-e84c-44d7-84db-80d4985e7d84	storage/de_on_tap/36fdc16f-fc50-4da4-951a-e4de72e300bd.enc	De_Van_10_GiuaKy1.pdf	05cb95b66e964477fcb057e753ce64f89691fcaeb8d5413765190f22000646a6	f	2026-10-28 14:30:00+07	\N	\N
eba27d99-e943-4e37-836b-0a1c37b26a3c	Ôn tập Ngữ văn cuối kỳ I	2	10	Cuối kỳ I	9bb3575c-1403-4c77-843e-51763a46af39	storage/de_on_tap/eba27d99-e943-4e37-836b-0a1c37b26a3c.enc	De_Van_10_CuoiKy1.pdf	17a899f16013f1ff6e16309b84e5a192908d2bb4b3047f8a13166bc2c7b24193	f	2026-10-27 16:20:00+07	\N	\N
c7e217c6-54a2-45ea-9b8e-5c835b79b542	Ôn tập Tiếng Anh cuối kỳ I	3	11	Cuối kỳ I	7b59f9b7-0c55-44d9-b951-ef82e47a235e	storage/de_on_tap/c7e217c6-54a2-45ea-9b8e-5c835b79b542.enc	De_Anh_11_CuoiKy1.pdf	6aa09c95700a61678ccfcaff4a30b2e00e6e9d8116c2cc179c3af79bc9740c38	f	2026-10-27 16:20:00+07	\N	\N
c2388421-1e7f-4e6f-8c81-3ddfc884fd4c	Ôn tập Tiếng Anh giữa kỳ II	3	12	Giữa kỳ II	7b59f9b7-0c55-44d9-b951-ef82e47a235e	storage/de_on_tap/c2388421-1e7f-4e6f-8c81-3ddfc884fd4c.enc	De_Anh_12_GiuaKy2.pdf	e2a8bf7c63be0b6ff284e9a5e90865dbd41b0c122161ff857a9bfe6bbbb6b01c	f	2026-10-26 09:15:00+07	\N	\N
019c1f71-71e5-432b-840c-a047c3d24334	Ôn tập Ngữ văn giữa kỳ II	2	11	Giữa kỳ II	48f58e38-e84c-44d7-84db-80d4985e7d84	storage/de_on_tap/019c1f71-71e5-432b-840c-a047c3d24334.enc	De_Van_11_GiuaKy2.pdf	2fb21e4993d5043951f8e07f55324aa8469081364d0bf9d5a3737ffa31b07791	f	2026-10-26 09:15:00+07	\N	\N
1964d5ae-7b9b-454f-a55d-e18d449bd729	Ôn tập Nghị luận văn học lớp 12	2	12	Cuối kỳ II	9bb3575c-1403-4c77-843e-51763a46af39	storage/de_on_tap/1964d5ae-7b9b-454f-a55d-e18d449bd729.enc	De_Van_12_CuoiKy2.pdf	d35d027b059141a33290c12ad154fc415866ee2d3eea399737db03a9f620791c	f	2026-10-25 11:05:00+07	\N	\N
cc6d2d99-f491-4739-ad0c-b8a13c99084a	Ôn tập Tiếng Anh giữa kỳ I	3	10	Giữa kỳ I	ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	storage/de_on_tap/cc6d2d99-f491-4739-ad0c-b8a13c99084a.enc	De_Anh_10_GiuaKy1.pdf	551bd26f029ede41af007d66099022de2de3b475b66347bd014e1a298e2b6d58	f	2026-10-28 14:30:00+07	\N	\N
\.


--
-- Data for Name: dethi; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.dethi (ma_de_thi, ma_lich_thi, ten_de_thi, ma_mon_hoc, ma_khoi, loai_de, da_nem_phong, nguoi_ra_de, duong_dan_tep_ma_hoa, ten_tep_goc, ma_bam_sha256, chu_ky_so_nguoi_ra_de, khoa_ma_hoa_de, ma_nonce_aes, the_xac_thuc_aes, bi_can_thiep, thoi_diem_tao, duong_dan_tep, thoi_diem_cap_nhat, nguoi_cap_nhat, da_chinh_sua, loai, thoi_diem_niem_phong, nguoi_niem_phong) FROM stdin;
5cbdf2c8-547e-4043-9ca4-ea8f64047ea0	2	Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)	1	12	DE_MOI	t	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/5cbdf2c8-547e-4043-9ca4-ea8f64047ea0.enc	De_ChinhThuc_Toan12_CK1_Mat.pdf	0c4d85e301cda4f37137aeacb0339230779c00d07a97db973f82e74a3d3b1546	\\xecb0c04fb2d26f1d448a49a7aa69fd28f6a3b21c9b1cd909f88698885ad21997	\\xa93b1f68471279948460d1255141553689af985d9b44455fc89aab2cd69c4e9dbdccef1930f71214f1537bb60693ab3bf38f39699b0f496864075e9c	\\x9d09091ba67e2cb3ae139cbc	\\x18587dcdb5912f541921ab105d871d4b	f	2026-10-28 17:08:17.294522+07	storage/de_thi/5cbdf2c8-547e-4043-9ca4-ea8f64047ea0.enc	\N	\N	f	Đề thi	\N	\N
f38e906b-72da-455e-9b1a-64e06961c1c5	8	Đề kiểm tra giữa kỳ I - Toán 10	1	10	CHINH_THUC	f	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/f38e906b-72da-455e-9b1a-64e06961c1c5.enc	de_kiem_tra_giua_ky_1_toan_10.pdf	ea0cbe4aa662a460040d4064b31a9b5dbeff5ba0c5330f291fc546c25b748145	\\x1ba4748f87ad25b94435549740bb99eb7b0a9960eb4034b64f6390f232323e98	\\xfaad62aa638c9275adb9df9183dcfed153de976adbbbceb2fad534a65792fa0b925d1d128e8a5f25fc06ed66f8089a5f6ad183bceae7d6b57381ca2a	\\x7d287fc3d2ebc657282b1394	\\x164373fb128520330627382c759700f4	f	2026-10-28 20:04:32.804616+07	storage/de_thi/f38e906b-72da-455e-9b1a-64e06961c1c5.enc	\N	\N	f	Đề thi	\N	\N
eae52fe6-956a-4036-8829-5e380c0cf074	3	Đề thi chính thức Giữa kỳ I - Ngữ văn 10	2	10	CHINH_THUC	f	9bb3575c-1403-4c77-843e-51763a46af39	storage/de_thi/eae52fe6-956a-4036-8829-5e380c0cf074.enc	De_ChinhThuc_Van10_GK1.pdf	2ebfd9167fd90632dc52a4462e94e4232b19eeafeecbc1d09d0d38247e6c8a64	\\x743278d8143f4aa32d653e6ae066df07e7c6c06aae3d1e7abc5c27f723042931	\\xee7901e35d2942854a27a3ac9dece0c72751839a791ab0b3191d0f92017f466d6b0c4d9bcf4c856ab502cd85b370f1e468fdf6037c31f357e4c62d89	\\xce2e0455d78d031a5deab986	\\x94a6e420a1e3a628cd8abaca5b2d0ce5	f	2026-10-28 17:08:17.294522+07	storage/de_thi/eae52fe6-956a-4036-8829-5e380c0cf074.enc	\N	\N	f	Đề thi	\N	\N
a12ffd7d-002a-44ee-b516-637f998a47c4	4	Đề thi chính thức Giữa kỳ I - Tiếng Anh 11	3	11	CHINH_THUC	f	7b59f9b7-0c55-44d9-b951-ef82e47a235e	storage/de_thi/a12ffd7d-002a-44ee-b516-637f998a47c4.enc	De_ChinhThuc_Anh11_GK1.pdf	e00a57d2068a88e0b6b72ed0a10c24cc3d93d0e795653121d51f7857e4bfda52	\\x9f67300315f7ae0c10357cd1f56df36f190e029ffad93996a743c72c2da74ee7	\\x2fd11d8a0d2d7c9da06df7410b7ff6aa2626fcd52d7ecc1769d0e2e8ca911d94414e01f31afbed5959448c57dc1ef04b9fa15ed85a4f89ff0b3c0513	\\x0ffd33c2ab286653df4bddf0	\\x379d6c80868306a904d815abaf53884a	f	2026-10-28 17:08:17.294522+07	storage/de_thi/a12ffd7d-002a-44ee-b516-637f998a47c4.enc	\N	\N	f	Đề thi	\N	\N
eb288303-2bfc-4f1f-878c-4dea2a90541d	14	Đề kiểm tra giữa kỳ I - Ngữ văn 10	2	10	CHINH_THUC	f	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	storage/de_thi/eb288303-2bfc-4f1f-878c-4dea2a90541d.enc	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx	03b9092b99e9eb2d18c00f7d6a9ba9230c5db3b713653350829f382cb2b26bd8	\\xcbed9ca6ce174a0bcfb0f5d47b3e25fe75177878bcc04b90f775aba9735dfa1d	\\x7d9d450af37315a93722715ea263738cb0b872ce7e47eab526ea63fcff2b05910316b1da1958e54026a82ac3cbd86ebcc03cf529cf9d822bfd68e482	\\xff4afd65a94031924c5ca94a	\\xecc501042bad05680a93b2dcfe623b01	f	2026-10-30 14:29:39.767165+07	storage/de_thi/eb288303-2bfc-4f1f-878c-4dea2a90541d.enc	2026-10-30 14:30:16.722913+07	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	t	Đề thi	\N	\N
d8dfa534-dad4-4f8a-ba11-790a59d50695	5	Đề thi chính thức Giữa kỳ I - Vật lý 12	5	12	CHINH_THUC	f	674289a6-2f98-4142-b90f-436c9e5ab1b4	storage/de_thi/d8dfa534-dad4-4f8a-ba11-790a59d50695.enc	De_ChinhThuc_Ly12_GK1.pdf	04d17a6c344641512c3fa8b7c0f95d97e639093b594a5346c4e22215aea8fa1f	\\xfe9d055e74c7e71be361b73a9b256a37b7ac2614baffa613669628a8c9501ba0	\\x18ea3cfd414e9dfd12e28829ce65c570a4d50eba1041cca661f53ca7f6e9207882a500eb6617bafcda8083a4d74cf32166062c65f5fdf348d720fc9e	\\x6ee52d98adb0d977ba6a4917	\\xc3177c2c2cf7ab27e0ea1aec54b738cb	f	2026-10-28 17:08:17.294522+07	storage/de_thi/d8dfa534-dad4-4f8a-ba11-790a59d50695.enc	\N	\N	f	Đề thi	\N	\N
8fbb91c5-4a57-44e1-9341-e91e68ed9e50	1	Đề kiểm tra giữa kỳ I - Toán 10	1	10	CHINH_THUC	f	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/8fbb91c5-4a57-44e1-9341-e91e68ed9e50.enc	de_kiem_tra_giua_ky_1_toan_10.pdf	551be77c1ef29b972b3a27692f7c16fcabed691425cdcbe48bb242805a8df59c	\\xb5fe93c1410894c1c99f3331bc112ec4ff5aa6b37a7a3d2084557761a37f0448	\\x4e5003bc66e8bd1bc4fa72a44e13c1645b2c737b6363c5c44f19deb77688a902072d0c3ea641af83063b2447c2a306db96821ac8ea3a5f40cc6e4d93	\\xa5df7ae0d151359783ed701a	\\x1394b8ced0e5464626948b2ed269d20d	f	2026-10-28 17:08:17.294522+07	storage/de_thi/8fbb91c5-4a57-44e1-9341-e91e68ed9e50.enc	\N	\N	f	Đề thi	\N	\N
868c8b4d-dfa0-4ddf-b418-00bcd3355e77	7	Đề kiểm tra giữa kỳ I - Toán 10	1	10	CHINH_THUC	f	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/868c8b4d-dfa0-4ddf-b418-00bcd3355e77.enc	de_kiem_tra_giua_ky_1_toan_10.pdf	ea0cbe4aa662a460040d4064b31a9b5dbeff5ba0c5330f291fc546c25b748145	\\x1ba4748f87ad25b94435549740bb99eb7b0a9960eb4034b64f6390f232323e98	\\xd4ad4de37dd1c659b86ba3269c86572fcf66ad5d29ec7a7eab2b31810e66c46cc5800a42d6381fe7f9a3d4a4d067b225461d85f5e65877cbcc217706	\\xcec1e20b97c39f0e514689b6	\\x9fa5955113f8cf1070dbdd97caa4d9b1	f	2026-10-28 20:02:48.41356+07	storage/de_thi/868c8b4d-dfa0-4ddf-b418-00bcd3355e77.enc	\N	\N	f	Đề thi	\N	\N
\.


--
-- Data for Name: khoilop; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.khoilop (ma_khoi, ten_khoi) FROM stdin;
10	Khối 10
11	Khối 11
12	Khối 12
\.


--
-- Data for Name: lichthi; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.lichthi (ma_lich_thi, ten_lich_thi, nam_hoc, ma_khoi, ma_mon_hoc, thoi_gian_bat_dau, thoi_gian_ket_thuc, nguoi_tao_lich, thoi_diem_tao, ten_ky_thi, loai_ky_thi, gio_bat_dau, gio_ket_thuc) FROM stdin;
2	Kỳ thi Cuối học kỳ I - Toán 12	2026-2027	12	1	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07	Kỳ thi Cuối học kỳ I - Toán 12	Giữa kỳ I	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07
3	Kỳ thi Giữa học kỳ I - Ngữ văn 10	2026-2027	10	2	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07	Kỳ thi Giữa học kỳ I - Ngữ văn 10	Giữa kỳ I	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07
4	Kỳ thi Giữa học kỳ I - Tiếng Anh 11	2026-2027	11	3	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07	Kỳ thi Giữa học kỳ I - Tiếng Anh 11	Giữa kỳ I	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07
5	Kỳ thi Giữa học kỳ I - Vật lý 12	2026-2027	12	5	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07	Kỳ thi Giữa học kỳ I - Vật lý 12	Giữa kỳ I	2026-10-25 07:30:00+07	2026-11-15 17:00:00+07
1	Kiểm tra giữa kỳ I	2026 - 2027	10	1	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07	Kiểm tra giữa kỳ I	Giữa kỳ I	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07
7	Kiểm tra giữa kỳ I	2026 - 2027	10	1	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	2026-10-28 20:02:48.41356+07	Kiểm tra giữa kỳ I	Giữa kỳ I	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07
8	Kiểm tra giữa kỳ I	2026 - 2027	10	1	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	2026-10-28 20:04:32.804616+07	Kiểm tra giữa kỳ I	Giữa kỳ I	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07
14	Kiểm tra giữa kỳ II	2026 - 2027	10	2	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	2026-10-30 14:29:39.767165+07	Kiểm tra giữa kỳ II	Giữa kỳ II	2026-11-15 07:30:00+07	2026-11-15 09:00:00+07
\.


--
-- Data for Name: monhoc; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.monhoc (ma_mon_hoc, ky_hieu_mon, ten_mon_hoc, dang_su_dung) FROM stdin;
1	TOAN	Toán học	t
2	VAN	Ngữ văn	t
3	ANH	Tiếng Anh	t
4	LICH_SU	Lịch sử	t
5	VAT_LY	Vật lý	t
6	HOA_HOC	Hóa học	t
7	SINH_HOC	Sinh học	t
8	DIA_LY	Địa lý	t
\.


--
-- Data for Name: nhatkylog; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.nhatkylog (ma_nhat_ky, ma_bam_truoc, ma_tai_khoan, hanh_dong, ip_thiet_bi, ipv4, ket_qua, chi_tiet, thoi_diem, ma_bam_nhat_ky, thong_tin_thiet_bi, tai_lieu_thao_tac, ket_qua_goc, bi_can_thiep, so_lan_can_thiep, thoi_diem_can_thiep, chi_tiet_can_thiep) FROM stdin;
238	f6d27b25e6412e52a9225c5fce1324686ef27cf56d5e4ede70326ae999ba9226	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 20:09:19.875943+07	eab4fdcd5716f49446a63f3adb2cc795193890f30f823cc6ebef1a435e85fcf0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
239	eab4fdcd5716f49446a63f3adb2cc795193890f30f823cc6ebef1a435e85fcf0	\N	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Phát hiện tài khoản lạ đăng nhập vào hệ thống	2026-10-30 20:09:30.377904+07	6bdea28834b9584b04a51621d43fee541af5407d8d808f61c6431e4bc1619255	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Cảnh báo	f	0	\N	\N
232	33d9e7985eabb1d3ea5d1d127ead7ce4e6755ccfcd029763fa454ea10c29b6fe	48190309-eeb6-4395-a18f-1f902d580c97	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 20:03:47.284316+07	3df34c6f6dde401b6a7df717615148a0f76eb63737d6b129e0ee8a58efc5044f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
240	6bdea28834b9584b04a51621d43fee541af5407d8d808f61c6431e4bc1619255	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 20:09:35.822132+07	2c55bccb746ae9ee8a7604463855728b5003a8e348e4465010c7f5adcc71e9d2	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
233	3df34c6f6dde401b6a7df717615148a0f76eb63737d6b129e0ee8a58efc5044f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 20:03:55.51294+07	7055d4ad7d63ed75d8ffaa46a5aaedf0308e61066f8265bcbfb50459c160de2f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
241	2c55bccb746ae9ee8a7604463855728b5003a8e348e4465010c7f5adcc71e9d2	48190309-eeb6-4395-a18f-1f902d580c97	Chặn IP	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) đã chặn địa chỉ IP 171.250.165.204 (Chặn từ bảng Quản lý tài khoản (Nguyễn Văn Minh - GV1000458)) và thu hồi 0 phiên hoạt động.	2026-10-30 20:09:58.799522+07	6f7dd3e72589be97a90b63198def46fa568f941cfc73eb3f18e9424be78017df	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
234	7055d4ad7d63ed75d8ffaa46a5aaedf0308e61066f8265bcbfb50459c160de2f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã xem trực tuyến đề ôn tập "Ôn tập Toán giữa kỳ I".	2026-10-30 20:04:08.338707+07	f6d27b25e6412e52a9225c5fce1324686ef27cf56d5e4ede70326ae999ba9226	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	De_Toan_10_GiuaKy1.pdf	Thành công	f	0	\N	\N
242	6f7dd3e72589be97a90b63198def46fa568f941cfc73eb3f18e9424be78017df	48190309-eeb6-4395-a18f-1f902d580c97	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 20:10:01.147147+07	41f22994692901fffdc8f798bf573255a43466d0a09543bd7251df5ca0c1b742	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
4	35acf5495e1e2399d358980af47ed41153168e527a7c4daa9cd977a1ae867c71	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Phát hiện đăng nhập từ IP máy lạ hoặc IPv4 không thuộc THPT Hoàng Văn Thụ, yêu cầu nhập mã OTP trên điện thoại.	2026-10-23 14:10:25.579659+07	cda0f6cb88cda26cd06bea35aebef125b95ce6b338226308105cc65e217b2278	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Cảnh báo	f	0	\N	\N
5	cda0f6cb88cda26cd06bea35aebef125b95ce6b338226308105cc65e217b2278	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thất bại	Xác thực mã OTP thất bại: Mã 6 số không chính xác hoặc đã hết thời gian hiệu lực (lần 1)	2026-10-23 14:12:35.21943+07	f625144326160e966e656c6fdb44d852ef75f12fd02e6d5679c5915cbb9ddd43	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
6	f625144326160e966e656c6fdb44d852ef75f12fd02e6d5679c5915cbb9ddd43	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-23 14:13:25.930716+07	2def1459eebc603c32a76b41daf65fdbc904c1abaa4f635bbfa7e759642d5cbf	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
7	2def1459eebc603c32a76b41daf65fdbc904c1abaa4f635bbfa7e759642d5cbf	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:13:43.295484+07	58c8cdba1e5a2e093676acdd691fc5f3752e8fd812bbe1d8eb732d0535b9c349	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
8	58c8cdba1e5a2e093676acdd691fc5f3752e8fd812bbe1d8eb732d0535b9c349	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:27:28.358271+07	3ce0a8473aa5070a138c24af1fbb3ce99151cc7f0210f425e5c6443338ed624c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
243	41f22994692901fffdc8f798bf573255a43466d0a09543bd7251df5ca0c1b742	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 20:10:31.211215+07	bc5711f8ecb299138924e5be0efe956f393c263d7b7d954b128ebe2613ef1322	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
244	bc5711f8ecb299138924e5be0efe956f393c263d7b7d954b128ebe2613ef1322	48190309-eeb6-4395-a18f-1f902d580c97	Gỡ chặn IP	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) đã gỡ chặn địa chỉ IP 171.250.165.204.	2026-10-30 20:10:36.576486+07	160e1b72fafcac06fa45a5c7239faf71f3ecaaa5af83ebe8401196f9ff0b5bf4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
245	160e1b72fafcac06fa45a5c7239faf71f3ecaaa5af83ebe8401196f9ff0b5bf4	48190309-eeb6-4395-a18f-1f902d580c97	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 20:11:18.262314+07	11a2fa71c530defe5b10eb999afba1fa026c0b0349d930297b997aab78400fea	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
246	11a2fa71c530defe5b10eb999afba1fa026c0b0349d930297b997aab78400fea	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 20:11:20.582585+07	4ff456a50ce38fffc04d45fdf6c26d08f0b27492ba9b9f7afc3a07746a2bace6	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
100	1ae147080fa255fe62db8d80934b4c8ded7b456d9feceb2bd0fc98ea9bbc76fe	\N	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Phát hiện tài khoản lạ đăng nhập vào hệ thống	2026-10-28 23:16:31.812315+07	7977d56018f67820dd31ae1495ca945bb45ac9ee3f1278ff994524e25ff98c63	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Cảnh báo	f	0	\N	\N
101	7977d56018f67820dd31ae1495ca945bb45ac9ee3f1278ff994524e25ff98c63	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-28 23:17:14.442213+07	9c1235c03e37b0d1609029ec3a370f2bd5b92bc97637a3a0ca5c0b5e0bafe550	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
102	9c1235c03e37b0d1609029ec3a370f2bd5b92bc97637a3a0ca5c0b5e0bafe550	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-28 23:17:58.401761+07	0d70ae210298dfc0c2fa11e80f2c6da04e2e35d704a3dc4bfcf68c9433b85cd5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
103	0d70ae210298dfc0c2fa11e80f2c6da04e2e35d704a3dc4bfcf68c9433b85cd5	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 3	2026-10-28 23:18:46.68278+07	cf20f61609fd7d700f6139bd91e17aacbdf38c5c50637772999f0af98333335f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
104	cf20f61609fd7d700f6139bd91e17aacbdf38c5c50637772999f0af98333335f	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 23:20:24.255806+07	1d141bbc39095eb454c276a27141e39abb9ab38b579f5d724dd3558b7056d102	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
105	1d141bbc39095eb454c276a27141e39abb9ab38b579f5d724dd3558b7056d102	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 23:23:59.613558+07	f3218f7a084766d74fdaf437cf12b40dc1671bf69e1c3e917417e4f5f7deed29	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
136	95af1244889b0201ce47f3a2dd9c38c71663d6dca03519f68c5b7b19d90ac114	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:31.96925+07	f162d427122ac4d52f788f10867c8dfb3452d0d14c999aa6c4ba073f546b1bca	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
9	3ce0a8473aa5070a138c24af1fbb3ce99151cc7f0210f425e5c6443338ed624c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Phát hiện đăng nhập từ IP máy lạ hoặc IPv4 không thuộc THPT Hoàng Văn Thụ, yêu cầu nhập mã OTP trên điện thoại.	2026-10-23 14:28:45.841084+07	d813f7ef82f37bc4047a872f689e827caf3a3417cbd68769adb20645f6c61b7a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Cảnh báo	f	0	\N	\N
10	d813f7ef82f37bc4047a872f689e827caf3a3417cbd68769adb20645f6c61b7a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thất bại	Xác thực mã OTP thất bại: Mã 6 số không chính xác hoặc đã hết thời gian hiệu lực (lần 1)	2026-10-23 14:29:29.019761+07	94d12c9c42f58d05c389ba96699bceb6d453f1a314a65184d6045e407ac89071	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
11	94d12c9c42f58d05c389ba96699bceb6d453f1a314a65184d6045e407ac89071	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thất bại	Xác thực mã OTP thất bại: Mã 6 số không chính xác hoặc đã hết thời gian hiệu lực (lần 2)	2026-10-23 14:29:44.918592+07	7b5a244a6658b25bf7f553566da7255e9a2e65544fa6422227e39eb995903a63	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
12	7b5a244a6658b25bf7f553566da7255e9a2e65544fa6422227e39eb995903a63	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-23 14:30:11.005355+07	1994658b2b4b0b60f293b4c187c0fd5eb7415b7c1e55d2496d6f89c071e4f606	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
15	1994658b2b4b0b60f293b4c187c0fd5eb7415b7c1e55d2496d6f89c071e4f606	\N	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:19.03302+07	cf039d21d0e5117cb1ff05950fe5e0b1a269258069c984233e1a00567425f251	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
16	cf039d21d0e5117cb1ff05950fe5e0b1a269258069c984233e1a00567425f251	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:27.353517+07	28ce34d07d3d10d99016f44f3b943e3b6eb0be5d07acae56c359efdb64898058	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
17	28ce34d07d3d10d99016f44f3b943e3b6eb0be5d07acae56c359efdb64898058	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:28.055+07	e4cc94991d379c62697dd0c8a170fe2004ba3ef90a03b38d94fbf5d7f2e92e0a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
18	e4cc94991d379c62697dd0c8a170fe2004ba3ef90a03b38d94fbf5d7f2e92e0a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:28.75495+07	4a6db704b94428784a892d43f3375b4787236cff274d0eb7359d0cf0deb19dd0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
19	4a6db704b94428784a892d43f3375b4787236cff274d0eb7359d0cf0deb19dd0	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:36:06.655007+07	92ceb035f68f77377495768858fea30868872148ac1c84eb3f8c00d1fb4f803a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
20	92ceb035f68f77377495768858fea30868872148ac1c84eb3f8c00d1fb4f803a	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Phát hiện đăng nhập từ IP máy lạ hoặc IPv4 không thuộc THPT Hoàng Văn Thụ, yêu cầu nhập mã OTP trên điện thoại.	2026-10-23 14:36:22.127365+07	bf91a259157f19c08ecca68e613e82456dd9707faf711852c42f056e50ac2e10	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Cảnh báo	f	0	\N	\N
21	bf91a259157f19c08ecca68e613e82456dd9707faf711852c42f056e50ac2e10	9ea71a69-8aee-4305-a2aa-65b193245bc1	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-23 14:40:18.176494+07	2b34812d9fde67d6ff089acf355a421e47a86167a6aa6d1f292d42a0bc411491	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
22	2b34812d9fde67d6ff089acf355a421e47a86167a6aa6d1f292d42a0bc411491	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:42:33.283773+07	6110c3b829f0941cf8044a19b5547ffe043eb8a2c72e4e9d8b7265bfacaf2459	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
23	6110c3b829f0941cf8044a19b5547ffe043eb8a2c72e4e9d8b7265bfacaf2459	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:42:39.535198+07	9420466f4123f29e970301c7b10d8eb0f2ba5acf5c3d8294a65076c9c1076f76	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
25	9420466f4123f29e970301c7b10d8eb0f2ba5acf5c3d8294a65076c9c1076f76	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:45:20.808342+07	535e5e9d17eceefb344b2992860634e361c58f0504027e3f1a31d3bc3f1f8d38	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
27	535e5e9d17eceefb344b2992860634e361c58f0504027e3f1a31d3bc3f1f8d38	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-25 21:35:00.047605+07	09d1b3d859627ea0d6269d87eeab784ce107cbcb02d31604f6257c598098c54f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
28	09d1b3d859627ea0d6269d87eeab784ce107cbcb02d31604f6257c598098c54f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-25 21:51:08.063026+07	c2f88ebac134bdc3efb29e6569ea3520ca8f883e188bfdf2ae2d4b8f90fb568f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
61	c2f88ebac134bdc3efb29e6569ea3520ca8f883e188bfdf2ae2d4b8f90fb568f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-26 14:17:25.028957+07	955debae83e3d6e133468f2a97c29dce70e4a25fa65467ede5ebdaaedaffdd79	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
62	955debae83e3d6e133468f2a97c29dce70e4a25fa65467ede5ebdaaedaffdd79	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-26 14:17:36.820066+07	e7950bf14d5b0d61f02e063567bc8dbe83fe654596a47271278204fe532a2569	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
63	e7950bf14d5b0d61f02e063567bc8dbe83fe654596a47271278204fe532a2569	48f58e38-e84c-44d7-84db-80d4985e7d84	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-26 14:19:24.417391+07	2c3976a06e45f25f3b30bfdfc66e1009dd91e7d79d4a3896e3f5ac03954aad0e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
64	2c3976a06e45f25f3b30bfdfc66e1009dd91e7d79d4a3896e3f5ac03954aad0e	48f58e38-e84c-44d7-84db-80d4985e7d84	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-26 14:25:11.86578+07	750c7f71e6d23e9b20d0c9ed61b3004fd5920f14e7a0140a9e6ca34098badf8d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
65	750c7f71e6d23e9b20d0c9ed61b3004fd5920f14e7a0140a9e6ca34098badf8d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Thêm đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 tải lên đề ôn tập [De On Tap Test SHA256] (Khối 10 - Giữa kỳ I), SHA-256: 3480113c63cacba6...	2026-10-28 17:25:53.281929+07	9b5b8d5817bf3598f85d1c9c657dea84b81d149a215319ce1ec409058c15cdbb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test.pdf	Thành công	f	0	\N	\N
66	9b5b8d5817bf3598f85d1c9c657dea84b81d149a215319ce1ec409058c15cdbb	51c35c7f-0e7c-4880-8925-2f06926f89b0	Sửa đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 cập nhật đề ôn tập [De On Tap Test SHA256 v2] (Khối 10 - Giữa kỳ I), SHA-256 mới: 14c5e622333e826e...	2026-10-28 17:25:53.43259+07	894c087679995ea5a8b238ed3aa0b600c141f8313a145a8d28dcc4971dbe9fbe	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test_v2.pdf	Thành công	f	0	\N	\N
67	894c087679995ea5a8b238ed3aa0b600c141f8313a145a8d28dcc4971dbe9fbe	51c35c7f-0e7c-4880-8925-2f06926f89b0	Tải đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 tải xuống đề ôn tập [De On Tap Test SHA256 v2]	2026-10-28 17:25:53.563724+07	d03bc604d6d5b89e849c620a31cc8571041dcd76ad88f6af208afe4023f5a192	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test_v2.pdf	Thành công	f	0	\N	\N
68	d03bc604d6d5b89e849c620a31cc8571041dcd76ad88f6af208afe4023f5a192	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xóa đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 đã xóa đề ôn tập [De On Tap Test SHA256 v2]	2026-10-28 17:25:53.640692+07	f4c6c9159bb8cf339f4410512becd6c7cd52731fe708fbbafced5333789f97cb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test_v2.pdf	Thành công	f	0	\N	\N
69	f4c6c9159bb8cf339f4410512becd6c7cd52731fe708fbbafced5333789f97cb	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 19:01:16.829756+07	e2a612c81007bdf9ef64643d11ade541f1521d51407ca0a19b27e635089e4c6c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
70	e2a612c81007bdf9ef64643d11ade541f1521d51407ca0a19b27e635089e4c6c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 19:01:22.801217+07	12abff1d81fe9465fee36b23b1fa4e184f65ededb40b945f88e40c90cd4f4816	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
71	12abff1d81fe9465fee36b23b1fa4e184f65ededb40b945f88e40c90cd4f4816	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 19:46:15.778019+07	5150c920961518397810b3ccb85d499ac8ea12d9829f211ef628899b7b364dfe	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
72	5150c920961518397810b3ccb85d499ac8ea12d9829f211ef628899b7b364dfe	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Đúng mật khẩu từ IP lạ ngoài trường, kích hoạt thử thách mã OTP 6 số	2026-10-28 20:00:24.105459+07	7eea8716a1d02f0470ae136cc42eead5f7be977d689f59eafcf7dcc4c17c0e7a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Cảnh báo	f	0	\N	\N
73	7eea8716a1d02f0470ae136cc42eead5f7be977d689f59eafcf7dcc4c17c0e7a	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:00:24.239721+07	c16249309964d125c8c4dae19639c4d62d7fc93a8249640490d170df186b4413	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
74	c16249309964d125c8c4dae19639c4d62d7fc93a8249640490d170df186b4413	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:00:52.513874+07	169b7db2eb122725d07fda5fde91ef5118577e487ff8e6ee9b07d42954c6c1e4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
75	169b7db2eb122725d07fda5fde91ef5118577e487ff8e6ee9b07d42954c6c1e4	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:00:52.727757+07	ed3840f83c6ec16c5c594e0813dcb623e3073867846160d845f48c40027494be	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
76	ed3840f83c6ec16c5c594e0813dcb623e3073867846160d845f48c40027494be	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Đúng mật khẩu từ IP lạ ngoài trường, kích hoạt thử thách mã OTP 6 số	2026-10-28 20:00:53.638181+07	d78bbeb45cc0b74ad559ade28c9772c140f8c796623794dfb696b1f63a06d9f4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Cảnh báo	f	0	\N	\N
77	d78bbeb45cc0b74ad559ade28c9772c140f8c796623794dfb696b1f63a06d9f4	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:00:53.755447+07	cc3d19445a9f18d31ffa41948625239641194fd4ee76cee2470873b606b39b07	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
78	cc3d19445a9f18d31ffa41948625239641194fd4ee76cee2470873b606b39b07	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:01:09.308083+07	caae60105ddad71bae85ebdd71771cc162600564c3bbc4a5c93ec16ebaa43b89	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
79	caae60105ddad71bae85ebdd71771cc162600564c3bbc4a5c93ec16ebaa43b89	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:01:09.419694+07	975a522042c1986111958e0e5df9f96594b51e319975198e961ff0dcae8d8609	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
80	975a522042c1986111958e0e5df9f96594b51e319975198e961ff0dcae8d8609	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:01:10.565531+07	bad994433330324890bc8fff7934196392f34de3f592e86feaa8d8242c1da67b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
81	bad994433330324890bc8fff7934196392f34de3f592e86feaa8d8242c1da67b	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:01:10.788874+07	0842f54817f6e115fedb68e94a89bb53aebbf5f149e80d734170939011c59d06	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
82	0842f54817f6e115fedb68e94a89bb53aebbf5f149e80d734170939011c59d06	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:02:46.540558+07	8e4089855c4e313deee2c1fae3724975998a0045bdea8de72c026d06d901b8e1	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
83	8e4089855c4e313deee2c1fae3724975998a0045bdea8de72c026d06d901b8e1	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:02:46.86515+07	3b950820f6412fa0ee1891304fd23e343ff12bd788331edb0776f067057c6d2e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
84	3b950820f6412fa0ee1891304fd23e343ff12bd788331edb0776f067057c6d2e	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:02:47.951871+07	4a72a2fb2593722faaee8243dfd0d35b2cb25c9ce8797acfb6b227ecd4425a60	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
85	4a72a2fb2593722faaee8243dfd0d35b2cb25c9ce8797acfb6b227ecd4425a60	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:02:48.166577+07	a52cd56a001d5812df067eeb8ae840dc794cb103f64d9ec1c9667745c97e8ffe	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
86	a52cd56a001d5812df067eeb8ae840dc794cb103f64d9ec1c9667745c97e8ffe	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Thêm đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1780839 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Bản kiểm thử)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:02:48.454132+07	9a49e1495c919b9d09e45a24c2da9eebab8c97725611d39a0473927b48bb2a7d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf	Thành công	f	0	\N	\N
87	9a49e1495c919b9d09e45a24c2da9eebab8c97725611d39a0473927b48bb2a7d	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:04:30.733783+07	c35a5ed5220739f7f17db61bb4d864261d812dceccaaea7aaefac8a8eebb7129	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
88	c35a5ed5220739f7f17db61bb4d864261d812dceccaaea7aaefac8a8eebb7129	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:04:30.952997+07	7c65127c80dcb036514e4d48c36effccc75e9f80c0902c7cb0fcf63095f1b5da	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
89	7c65127c80dcb036514e4d48c36effccc75e9f80c0902c7cb0fcf63095f1b5da	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:04:32.131671+07	9eb87e54e0647f3e3b889ed64f16bbd19482d8c911e781617b1e3f81011ddf17	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
90	9eb87e54e0647f3e3b889ed64f16bbd19482d8c911e781617b1e3f81011ddf17	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:04:32.456738+07	ef40547cb5b2626343ed675f647b1720af53d3cc15bcdb77e2ce0198f4113bfb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
91	ef40547cb5b2626343ed675f647b1720af53d3cc15bcdb77e2ce0198f4113bfb	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Thêm đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1780839 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Bản kiểm thử)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:04:32.848742+07	20ccea1372909df6e1e3c966f2a796d3ef2f007dbdf32334c04607d0f28ae2c5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf	Thành công	f	0	\N	\N
92	20ccea1372909df6e1e3c966f2a796d3ef2f007dbdf32334c04607d0f28ae2c5	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:09:02.924618+07	966570c460a61882593bf1db579f4b0c86791703f8152bde6f6aa23376b1d545	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
93	966570c460a61882593bf1db579f4b0c86791703f8152bde6f6aa23376b1d545	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:09:03.03664+07	a0e1593abb1a873371b1ff8084cfb95333885aa73a09232d41fb518e85a0b52c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
94	a0e1593abb1a873371b1ff8084cfb95333885aa73a09232d41fb518e85a0b52c	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:09:04.269762+07	438ebf1e2c5cb651467115d8d966f71486068bbc60329b0cd9dfcd407221d3fc	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
95	438ebf1e2c5cb651467115d8d966f71486068bbc60329b0cd9dfcd407221d3fc	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:09:04.492152+07	d7d68390c8bd4b08de7c5672b2c263b7a69065b6e5f62d769633b078db62661d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1		Thành công	f	0	\N	\N
96	d7d68390c8bd4b08de7c5672b2c263b7a69065b6e5f62d769633b078db62661d	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Thêm đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1780839 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Bản kiểm thử)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:09:04.789318+07	06488fdcecad09bf9fbb2178cfa2f5b1f5826587e4620038c6daa4bdc1bd443a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf	Thành công	f	0	\N	\N
97	06488fdcecad09bf9fbb2178cfa2f5b1f5826587e4620038c6daa4bdc1bd443a	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Sửa đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1780839 cập nhật lịch thi [Kiểm tra giữa kỳ I (Đợt 2)] và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Đã cập nhật)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:09:05.009493+07	922550420ed9eb3269bc03f77e702cd788f2a601e7e7cb9bccd8479ac7073842	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf	Thành công	f	0	\N	\N
98	922550420ed9eb3269bc03f77e702cd788f2a601e7e7cb9bccd8479ac7073842	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Tải đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1780839 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Đã cập nhật)]	2026-10-28 20:09:05.63208+07	12fcef6a685d4889cd032f431b59be5c6ebf71b853315ff12ecfef556d68d024	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf	Thành công	f	0	\N	\N
99	12fcef6a685d4889cd032f431b59be5c6ebf71b853315ff12ecfef556d68d024	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xóa đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1780839 đã xóa đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Đã cập nhật)]	2026-10-28 20:09:05.758245+07	1ae147080fa255fe62db8d80934b4c8ded7b456d9feceb2bd0fc98ea9bbc76fe	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf	Thành công	f	0	\N	\N
106	f3218f7a084766d74fdaf437cf12b40dc1671bf69e1c3e917417e4f5f7deed29	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-28 23:43:30.021515+07	24b1163cfd18cce99f91a0c03c5522bc528f298f88470a7414182ecf64cc9466	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
107	24b1163cfd18cce99f91a0c03c5522bc528f298f88470a7414182ecf64cc9466	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 23:45:09.789977+07	399d8550b453238d7dd5a4175b65cc7201f6d43ad332f0ca0fcb22e95ee89745	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thành công	f	0	\N	\N
108	399d8550b453238d7dd5a4175b65cc7201f6d43ad332f0ca0fcb22e95ee89745	51c35c7f-0e7c-4880-8925-2f06926f89b0	Bẫy đề mồi	192.168.1.4	171.250.165.204	Cảnh báo	PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)] bởi GV1000458 (gv.minh) - Lần kích hoạt thứ 1!	2026-10-28 23:45:21.755076+07	3b773a37faeff928dee5163b00a36bfe92a41d5e22427f87a6b9ff8c9a56085e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	De_ChinhThuc_Toan12_CK1_Mat.pdf	Cảnh báo	f	0	\N	\N
109	3b773a37faeff928dee5163b00a36bfe92a41d5e22427f87a6b9ff8c9a56085e	51c35c7f-0e7c-4880-8925-2f06926f89b0	Bẫy đề mồi	192.168.1.4	171.250.165.204	Cảnh báo	PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)] bởi GV1000458 (gv.minh) - Lần kích hoạt thứ 2!	2026-10-28 23:45:25.663067+07	8d39f8a945c32cdfa801bf6bc239458e9207a6a9c28f69e60ca0c5da3754708c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	De_ChinhThuc_Toan12_CK1_Mat.pdf	Cảnh báo	f	0	\N	\N
110	8d39f8a945c32cdfa801bf6bc239458e9207a6a9c28f69e60ca0c5da3754708c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Bẫy đề mồi	192.168.1.4	171.250.165.204	Cảnh báo	PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)] bởi GV1000458 (gv.minh) - Lần kích hoạt thứ 3!	2026-10-28 23:45:38.128565+07	0d96ea195557f304b1a9fc8bfc464714e9ca240c322950e95f3a3ec72c36f4cd	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	De_ChinhThuc_Toan12_CK1_Mat.pdf	Cảnh báo	f	0	\N	\N
111	0d96ea195557f304b1a9fc8bfc464714e9ca240c322950e95f3a3ec72c36f4cd	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-29 14:11:24.298534+07	a8da3206e5854c3f4d10cde062fb3407b39772068b3a632669a4fd6968023b51	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
112	a8da3206e5854c3f4d10cde062fb3407b39772068b3a632669a4fd6968023b51	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-29 14:11:28.851429+07	3b3489e077eef2ad3de5a993bee719027a0aab8980c5f15a1359d8ae74fdfa5b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
113	3b3489e077eef2ad3de5a993bee719027a0aab8980c5f15a1359d8ae74fdfa5b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Thêm đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 tải lên đề ôn tập [Ôn tập Toán giữa kỳ I 29/10/2026] (Khối 10 - Giữa kỳ I), SHA-256: 5ba3b76beae594c7...	2026-10-29 14:15:03.139008+07	726c2915f7ec468a307b93a247297a4e1a794ac09c043d6981dda33853e97f54	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB5_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
114	726c2915f7ec468a307b93a247297a4e1a794ac09c043d6981dda33853e97f54	51c35c7f-0e7c-4880-8925-2f06926f89b0	Tải đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 tải xuống đề ôn tập [Ôn tập Toán giữa kỳ I 29/10/2026]	2026-10-29 14:15:57.387552+07	b19da9c438a7ab382147e453e6b6902e9d80124d895952c4761b830e8c15f312	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB5_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
115	b19da9c438a7ab382147e453e6b6902e9d80124d895952c4761b830e8c15f312	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xóa đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 đã xóa đề ôn tập [Ôn tập Toán giữa kỳ I 29/10/2026]	2026-10-29 14:16:08.30498+07	052632b8f4a6f3beb4aec78c7aa98b08c6f8a5a4c264e76875cfa22d6a9d95fc	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB5_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
116	052632b8f4a6f3beb4aec78c7aa98b08c6f8a5a4c264e76875cfa22d6a9d95fc	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-29 14:17:31.870921+07	3cffa07048160ce9234552388e557d1f53819146e3f0802b4f8a524490e72114	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
117	3cffa07048160ce9234552388e557d1f53819146e3f0802b4f8a524490e72114	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-29 14:17:32.143661+07	ae3a5187fba5e9b12b2585a499c253a38f9e35558ef352d2a93aa82fb4ce6092	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
118	ae3a5187fba5e9b12b2585a499c253a38f9e35558ef352d2a93aa82fb4ce6092	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-29 14:17:35.01809+07	b6d78c4556ad1cfdfda733058e429659640a81b497f629ee3b72c172954b9707	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
119	b6d78c4556ad1cfdfda733058e429659640a81b497f629ee3b72c172954b9707	51c35c7f-0e7c-4880-8925-2f06926f89b0	Sửa đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 cập nhật lịch thi [Kiểm tra giữa kỳ I] và đề thi [Đề kiểm tra giữa kỳ I - Toán 10], SHA-256: ea0cbe4aa662a460...	2026-10-29 14:19:17.423458+07	e96b929ce1c143057bca91b80e400cd0d534d64134d8a4f38f94720618b96779	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
120	e96b929ce1c143057bca91b80e400cd0d534d64134d8a4f38f94720618b96779	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-29 14:20:35.667936+07	efd44a7331a8ec46edefc08472661f82cee62b1e766020da8c0e94ccf7b8a4ea	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
121	efd44a7331a8ec46edefc08472661f82cee62b1e766020da8c0e94ccf7b8a4ea	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-29 14:20:46.989959+07	68ae1dd344b3dbc452ac998919d6104fc5e4684a4b298cf5a4bb8fbd9b32f49e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
125	68ae1dd344b3dbc452ac998919d6104fc5e4684a4b298cf5a4bb8fbd9b32f49e	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 09:11:23.683143+07	0a0a0966aaee8ea84b34ab4aafbd9b5aab895d1d1f01f7f68e1594bf344292ce	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130		Thành công	f	0	\N	\N
132	0a0a0966aaee8ea84b34ab4aafbd9b5aab895d1d1f01f7f68e1594bf344292ce	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 10:07:51.090845+07	eb473d78e39b024438a596b6b3cc6262b19a69adf8f9529d95dd8220947f912b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130		Thành công	f	0	\N	\N
133	eb473d78e39b024438a596b6b3cc6262b19a69adf8f9529d95dd8220947f912b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 10:08:07.744954+07	d5c481a925f2f05ec6a624134fbc77e58f336e7fd4b818baedb39696c94442d3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
134	d5c481a925f2f05ec6a624134fbc77e58f336e7fd4b818baedb39696c94442d3	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:30.168821+07	55f39bd6153f41c9fc7e7552aecc92193ed6bac348d2448d866768984341ee14	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
135	55f39bd6153f41c9fc7e7552aecc92193ed6bac348d2448d866768984341ee14	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:30.52098+07	95af1244889b0201ce47f3a2dd9c38c71663d6dca03519f68c5b7b19d90ac114	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
137	f162d427122ac4d52f788f10867c8dfb3452d0d14c999aa6c4ba073f546b1bca	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:39.48171+07	e8e106fe60454e1f54bc830dca2d42c78101b677a37a90b11168e59b4160356e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
138	e8e106fe60454e1f54bc830dca2d42c78101b677a37a90b11168e59b4160356e	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:39.824351+07	a4bba4e9706b368a58157194973388271ef2ac067d0abcf2f80a6a29e9d444d8	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf	Thành công	f	0	\N	\N
139	a4bba4e9706b368a58157194973388271ef2ac067d0abcf2f80a6a29e9d444d8	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 10:08:56.675545+07	4a73ad333dea9afd8d367bcad0ab90f55434da88724f5c73c430c978a5ce516e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
140	4a73ad333dea9afd8d367bcad0ab90f55434da88724f5c73c430c978a5ce516e	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-30 10:09:14.694098+07	23775ba7844323b1f5fffd6d5e9645a99a841dc705964f2558648e04160f4f3a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
141	23775ba7844323b1f5fffd6d5e9645a99a841dc705964f2558648e04160f4f3a	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 10:11:18.903079+07	710bcb4c185d9d356b9653022fd975dd352325c5980eec4eea2a29f2f4503a78	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
142	710bcb4c185d9d356b9653022fd975dd352325c5980eec4eea2a29f2f4503a78	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:33:14.133771+07	fcb1e28b2d1e552d9e90815075a84da7358dd23162a4ee53bed1621a8b8bcca5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
143	fcb1e28b2d1e552d9e90815075a84da7358dd23162a4ee53bed1621a8b8bcca5	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:33:42.581108+07	2319768391099d43e45c07312da8b425290a347574732e731434c70546834db3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
144	2319768391099d43e45c07312da8b425290a347574732e731434c70546834db3	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:34:59.438832+07	6b0dbf9f935b5dcf397171c0d5260978eabf311cd68af5c8852cd50471631acc	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
145	6b0dbf9f935b5dcf397171c0d5260978eabf311cd68af5c8852cd50471631acc	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:43:04.293318+07	c9974d821f2364db24d49611c896a5c3df156c923306e2fd455c63dac1d5a192	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
146	c9974d821f2364db24d49611c896a5c3df156c923306e2fd455c63dac1d5a192	\N	Đăng nhập	192.168.1.4	171.250.165.204	Cảnh báo	Phát hiện tài khoản lạ đăng nhập vào hệ thống	2026-10-30 13:44:09.536323+07	77c2cbe4ee4f939d9b2fdc11b955ffb137767e78a50d892b5a593f01c57db90d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Cảnh báo	f	0	\N	\N
147	77c2cbe4ee4f939d9b2fdc11b955ffb137767e78a50d892b5a593f01c57db90d	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:44:14.691538+07	78c06e8b9835b6f7e4d9b5f922b684148de050ac2c9cbac49c5759d1e63a7edb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
148	78c06e8b9835b6f7e4d9b5f922b684148de050ac2c9cbac49c5759d1e63a7edb	48190309-eeb6-4395-a18f-1f902d580c97	Khóa tài khoản	192.168.1.4	171.250.165.204	Thành công	Quản trị viên AD1568920 đã tạm khóa tài khoản GV1000458 (Nguyễn Văn Minh) trong 60 phút (đến 14:56:06 30/10/2026) và thu hồi toàn bộ phiên làm việc - Lý do: Khóa điều tra từ nhật ký #110	2026-10-30 13:56:07.017565+07	dcaf16c3fed829ab68b6aff39393855ce7456fe253bddbde0df26de890ca707a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
149	dcaf16c3fed829ab68b6aff39393855ce7456fe253bddbde0df26de890ca707a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Từ chối đăng nhập: Tài khoản đang trong thời gian bị khóa hoặc đã bị vô hiệu hóa	2026-10-30 13:56:27.86625+07	ebc1d426cef3f2a475db4427caff0aca58a52ddf7c52b596964307786d1757d7	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
150	ebc1d426cef3f2a475db4427caff0aca58a52ddf7c52b596964307786d1757d7	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:56:46.120408+07	552e85d86f127c23e835360499c88e1198ed170a1efd8bf5ed0a8b284edb12bc	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
151	552e85d86f127c23e835360499c88e1198ed170a1efd8bf5ed0a8b284edb12bc	48190309-eeb6-4395-a18f-1f902d580c97	Chặn IP	192.168.1.4	171.250.165.204	Thành công	Quản trị viên AD1568920 đã chặn địa chỉ IP 192.168.1.4 (Chặn từ điều tra nhật ký #145). Đã thu hồi 7 phiên hoạt động.	2026-10-30 13:59:16.452442+07	910953d994a716c9c1a88847d39905d4e6f3eab8d316104a12a8c7a0e5f8d6c7	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
152	910953d994a716c9c1a88847d39905d4e6f3eab8d316104a12a8c7a0e5f8d6c7	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Từ chối đăng nhập từ địa chỉ IP đang bị chặn (192.168.1.4)	2026-10-30 13:59:30.928062+07	56aab88343ffaef151b0dd4c9a7c77fad45fdcdd2971f1ede18f051b0f0a6976	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
153	56aab88343ffaef151b0dd4c9a7c77fad45fdcdd2971f1ede18f051b0f0a6976	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:59:48.562666+07	7ebe2c017749578e8ff367a9acb5224bb571112d757c3aa322f4023a51383c19	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
154	7ebe2c017749578e8ff367a9acb5224bb571112d757c3aa322f4023a51383c19	48190309-eeb6-4395-a18f-1f902d580c97	Mở khóa tài khoản	192.168.1.4	171.250.165.204	Thành công	Quản trị viên AD1568920 đã mở khóa an ninh tài khoản GV1000458 (Nguyễn Văn Minh)	2026-10-30 14:03:29.799904+07	c08cd433b68474dbdcffb917465c713aae625c1e7a33c94300514e18cf89fabb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
155	c08cd433b68474dbdcffb917465c713aae625c1e7a33c94300514e18cf89fabb	48190309-eeb6-4395-a18f-1f902d580c97	Đặt lại 2FA	192.168.1.4	171.250.165.204	Thành công	Admin AD1568920 thực hiện Đặt lại 2FA và Cấp lại mật khẩu tạm cho giáo viên GV1000458 (gv.minh@thpthoangvanthu.edu.vn). Đã thu hồi toàn bộ phiên làm việc cũ	2026-10-30 14:03:35.734812+07	3aeb63cc1596df300caf77b350dff4a934d2bcb02a444e53a0187ca605f6e66c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
156	3aeb63cc1596df300caf77b350dff4a934d2bcb02a444e53a0187ca605f6e66c	48190309-eeb6-4395-a18f-1f902d580c97	Cấp lại mật khẩu	192.168.1.4	171.250.165.204	Thành công	Admin AD1568920 cấp lại mật khẩu tạm cho giáo viên GV1000458 (gv.minh@thpthoangvanthu.edu.vn). Đã thu hồi toàn bộ phiên làm việc cũ	2026-10-30 14:03:52.226399+07	ff3191b1cecd48caa70355f16a3db00b91f750244c6f440a13ed8b2f510cadd6	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
157	ff3191b1cecd48caa70355f16a3db00b91f750244c6f440a13ed8b2f510cadd6	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Từ chối đăng nhập từ địa chỉ IP đang bị chặn (192.168.1.4)	2026-10-30 14:04:07.447212+07	8e7d2eda4cad1afbcd23349110427fbd36cd4ca2c22b8ddafe938e60a9e2ed18	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
158	8e7d2eda4cad1afbcd23349110427fbd36cd4ca2c22b8ddafe938e60a9e2ed18	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Từ chối đăng nhập từ địa chỉ IP đang bị chặn (192.168.1.4)	2026-10-30 14:04:11.886834+07	09b0ed0f736da06ef13a32970ee76cc0d1a3c54b6417774fe5fc621dec083cc2	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
159	09b0ed0f736da06ef13a32970ee76cc0d1a3c54b6417774fe5fc621dec083cc2	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:04:32.565248+07	8e7935e1f71c76a200805a3acf8750e2459d404cf4e21460a4cf269163b9d830	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
160	8e7935e1f71c76a200805a3acf8750e2459d404cf4e21460a4cf269163b9d830	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:04:40.606797+07	004cc44c9e2583993b9dde0ea4da2e1e6b50fc8add66c65480dcb8a25f9f2b4a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
161	004cc44c9e2583993b9dde0ea4da2e1e6b50fc8add66c65480dcb8a25f9f2b4a	48190309-eeb6-4395-a18f-1f902d580c97	Gỡ chặn IP	192.168.1.4	171.250.165.204	Thành công	Quản trị viên AD1568920 đã gỡ chặn địa chỉ IP 192.168.1.4	2026-10-30 14:04:53.130556+07	6424748d34e77a17ad34596969e50c9e41c7a34ce34855ca8e60733c6dcd3aa2	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
162	6424748d34e77a17ad34596969e50c9e41c7a34ce34855ca8e60733c6dcd3aa2	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:05:44.046033+07	c030f5d0ad24fd75d33455c04fa8f8b9b19d58a4369e69e242d88e9898e94a28	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
163	c030f5d0ad24fd75d33455c04fa8f8b9b19d58a4369e69e242d88e9898e94a28	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-30 14:05:51.355184+07	4b569709bb5a9cf09610163ac45fb1a72071c339d03f2d0ece035ef94906bff5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
164	4b569709bb5a9cf09610163ac45fb1a72071c339d03f2d0ece035ef94906bff5	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-30 14:05:56.270966+07	69a469fdd86be41dcc8b39b19921ac80d889ba0e3778616e1a4a470bebe419aa	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
165	69a469fdd86be41dcc8b39b19921ac80d889ba0e3778616e1a4a470bebe419aa	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Cảnh báo	Nhập sai mã OTP lần 1	2026-10-30 14:07:24.314326+07	e9042bde484a2459f5d457ffb058970d1f7337d0f2a185c6626f2a344c244d40	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Cảnh báo	f	0	\N	\N
166	e9042bde484a2459f5d457ffb058970d1f7337d0f2a185c6626f2a344c244d40	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Cảnh báo	Nhập sai mã OTP lần 2	2026-10-30 14:07:37.28505+07	ba6adddc77b4adc25177a1c527767e70ec19aae3f71c2c48a4a8c60797681a3e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Cảnh báo	f	0	\N	\N
167	ba6adddc77b4adc25177a1c527767e70ec19aae3f71c2c48a4a8c60797681a3e	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-30 14:09:15.65904+07	811b9a9f8b7d85ebd1f73a06e6a56d07b91c17f189501fca0596e461d90259ee	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
168	811b9a9f8b7d85ebd1f73a06e6a56d07b91c17f189501fca0596e461d90259ee	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:10:00.041984+07	526b45991861b896ad20909e377fc778bf761be43fb31c11aee7d60544d56c20	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
169	526b45991861b896ad20909e377fc778bf761be43fb31c11aee7d60544d56c20	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:10:03.123508+07	6d8312541146c01ec40b396d3ab5f38c0cad3d224576b3d3e7e194fa73d3a0e3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
170	6d8312541146c01ec40b396d3ab5f38c0cad3d224576b3d3e7e194fa73d3a0e3	48190309-eeb6-4395-a18f-1f902d580c97	Đặt lại 2FA	192.168.1.4	171.250.165.204	Thành công	Admin AD1568920 thực hiện Đặt lại 2FA và Cấp lại mật khẩu tạm cho giáo viên GV1000458 (gv.minh@thpthoangvanthu.edu.vn). Đã thu hồi toàn bộ phiên làm việc cũ	2026-10-30 14:14:05.7697+07	f483171c8de7bc76e982531540ee7e9ccca04e073d91a8482cd65c9a14f683d3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
171	f483171c8de7bc76e982531540ee7e9ccca04e073d91a8482cd65c9a14f683d3	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-30 14:14:34.867188+07	a6fbf40cbd5299b1f999e2e43ce50ff25cd461e85ec0619ee8f1b6523273195b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
172	a6fbf40cbd5299b1f999e2e43ce50ff25cd461e85ec0619ee8f1b6523273195b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-30 14:17:47.609629+07	5d392fbe73665bbe257aff4a95eaa7f500a7e6265ba96bd98672e78b0f86cec7	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
173	5d392fbe73665bbe257aff4a95eaa7f500a7e6265ba96bd98672e78b0f86cec7	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:17:59.377184+07	fa595878446b14375630f8f34db0af56805dbc9dfe13dcb3ef77da1be249a83d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
174	fa595878446b14375630f8f34db0af56805dbc9dfe13dcb3ef77da1be249a83d	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:18:02.976726+07	122751cfff0177fcdc0d826f8f01502543ddc99aa3e5f4b6dbb340af7cf32478	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
175	122751cfff0177fcdc0d826f8f01502543ddc99aa3e5f4b6dbb340af7cf32478	48190309-eeb6-4395-a18f-1f902d580c97	Tạo tài khoản	192.168.1.4	171.250.165.204	Thành công	Admin tạo tài khoản mới: Mã CB [GV1269482], Tên đăng nhập [gv.quyen], Vai trò [GiaoVien], Email [gv.quyen@thpthoangvanthu.edu.vn], Phân quyền [Ngữ văn - Khối 10, Khối 11, Khối 12 (Đề chung + Đề chính thức)]	2026-10-30 14:23:45.305411+07	a40a84c80593a96f13887081a0c78a76388b9ce516d15e13c9c440bb591fc108	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
176	a40a84c80593a96f13887081a0c78a76388b9ce516d15e13c9c440bb591fc108	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-30 14:25:15.760526+07	769a015b0572e948ebfa877c189340f52658aa2359bef62a1f5c6069eabc53b1	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
177	769a015b0572e948ebfa877c189340f52658aa2359bef62a1f5c6069eabc53b1	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Xác thực OTP	192.168.1.4	171.250.165.204	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-30 14:28:35.235546+07	89526805c68fddcd142fbb89a67918f572ad6d4580f9b04a5bb1585221c9c160	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
182	7db4f8c7686a8d6daf66696e80d66a0296b8b8a9739bee0fbb98ebe8c70a843d	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:31:00.234009+07	fae2bf760384b7c7cbfd3698adeaa13a97e7dccc6c7399f2576de00cacb294b3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
183	fae2bf760384b7c7cbfd3698adeaa13a97e7dccc6c7399f2576de00cacb294b3	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.7	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:31:04.111999+07	74d27f9abe60e8e65f0b8e4575d4937e9bf7b58bcb6bb6ce8aef0e734f2f0208	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
184	74d27f9abe60e8e65f0b8e4575d4937e9bf7b58bcb6bb6ce8aef0e734f2f0208	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:43:15.892153+07	5e9bb95bf186cf9137550982cc921720c9ae6144dbd916d71f52264ef70ebdb0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
185	5e9bb95bf186cf9137550982cc921720c9ae6144dbd916d71f52264ef70ebdb0	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:43:21.901011+07	2089936ffb46131f273186a53d431288708a945ab9b27f1c2edc412d54462e1d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
201	2089936ffb46131f273186a53d431288708a945ab9b27f1c2edc412d54462e1d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 18:43:52.658276+07	a9aabcca52b0412c3b37470ba8d73ea7b7463b9874d27cf7414d4c1cba1770d7	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
202	a9aabcca52b0412c3b37470ba8d73ea7b7463b9874d27cf7414d4c1cba1770d7	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 18:43:59.522202+07	c547ffb4606edbc127ce89493c8c14415e94bbffd741bcc1b1d6500c3d330f14	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
203	c547ffb4606edbc127ce89493c8c14415e94bbffd741bcc1b1d6500c3d330f14	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 18:44:02.746715+07	1df1ac7ca6c9a79b090c69ce07fc4bc04c4721cdb7011aa18fba5835107d56ce	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
207	1df1ac7ca6c9a79b090c69ce07fc4bc04c4721cdb7011aa18fba5835107d56ce	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 19:03:26.222459+07	bd967412c3e48fa7bf7b697d9d606d1ec422e1bb2c9bc4eafdbf5add486cb834	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
208	bd967412c3e48fa7bf7b697d9d606d1ec422e1bb2c9bc4eafdbf5add486cb834	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 19:05:00.107968+07	5a442fef9ae760c7fc265c8dd1369c4d319972c6007645bc3ba750f963c7d083	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
209	5a442fef9ae760c7fc265c8dd1369c4d319972c6007645bc3ba750f963c7d083	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 19:05:19.808572+07	c73847f71ba0a0b9b5610622eb9dfe3a55b653752a16ad66b239632e90a138be	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
210	c73847f71ba0a0b9b5610622eb9dfe3a55b653752a16ad66b239632e90a138be	48190309-eeb6-4395-a18f-1f902d580c97	Đặt mã PIN	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) thiết lập mã PIN bảo mật 6 số lần đầu thành công.	2026-10-30 19:30:07.097979+07	bc7d62510eaa6f110480b601c878b18014eb3787f1a6a56df147df1ba4ec67ee	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
211	bc7d62510eaa6f110480b601c878b18014eb3787f1a6a56df147df1ba4ec67ee	48190309-eeb6-4395-a18f-1f902d580c97	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Quản trị viên Trần Văn Phúc (AD1568920) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 19:30:33.617141+07	781781264e280a9c190e8852966e9a49e462737e3454bfc8ec53289df8debc7b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
212	781781264e280a9c190e8852966e9a49e462737e3454bfc8ec53289df8debc7b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 19:30:50.357756+07	9cfae322f1a9982d883ce8f3fd5d8bee48b637f691c2b813bc3331e874adeb3a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
213	9cfae322f1a9982d883ce8f3fd5d8bee48b637f691c2b813bc3331e874adeb3a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-30 19:30:53.808699+07	5f90a2460f09e255772fcbd15a4143ea9ba541df5a8167fe7caadb8fd7100830	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thất bại	f	0	\N	\N
214	5f90a2460f09e255772fcbd15a4143ea9ba541df5a8167fe7caadb8fd7100830	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 19:30:55.234051+07	79e604131ac09534ac4cb27c0e6596d595c9965d51f91a817d156bb004d3913c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
215	79e604131ac09534ac4cb27c0e6596d595c9965d51f91a817d156bb004d3913c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đặt mã PIN	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) thiết lập mã PIN bảo mật 6 số lần đầu thành công.	2026-10-30 19:31:43.310975+07	3254f7970362b40ee00880d50da67f29639aeaf64fe3f92f940fa5df439b3901	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
216	3254f7970362b40ee00880d50da67f29639aeaf64fe3f92f940fa5df439b3901	51c35c7f-0e7c-4880-8925-2f06926f89b0	Thêm đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã tải lên đề ôn tập "ryyr" (Khối 11 - Giữa kỳ I).	2026-10-30 19:32:13.187746+07	d64f1352adb629b186a5102265fa70f8b1fe4fadf6f5bb6b6b0abedb8d0c543b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
217	d64f1352adb629b186a5102265fa70f8b1fe4fadf6f5bb6b6b0abedb8d0c543b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xóa đề ôn tập	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã xóa đề ôn tập "ryyr".	2026-10-30 19:32:18.11711+07	84456673b06ae3fc4483acd4ce555c8fc3036001b504fb61b99531d82657f129	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
221	84456673b06ae3fc4483acd4ce555c8fc3036001b504fb61b99531d82657f129	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng xuất	192.168.1.4	171.250.165.204	Thành công	Giáo viên Nguyễn Văn Minh (GV1000458) đã đăng xuất và kết thúc phiên làm việc.	2026-10-30 19:32:48.842027+07	432c43b9fa68f471af6dfa5a74e3c9fb5def0c5756d33da2188432019f6bd9e5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
222	432c43b9fa68f471af6dfa5a74e3c9fb5def0c5756d33da2188432019f6bd9e5	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	171.250.165.204	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 19:33:05.516398+07	33d9e7985eabb1d3ea5d1d127ead7ce4e6755ccfcd029763fa454ea10c29b6fe	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)		Thành công	f	0	\N	\N
1	0000000000000000000000000000000000000000000000000000000000000000	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:09:29.657015+07	280c26d65737aa78494ce278402ab2d40d21792aed18e4f97fc98805fe16ea6d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
2	280c26d65737aa78494ce278402ab2d40d21792aed18e4f97fc98805fe16ea6d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:09:30.340882+07	4a64e9d4f226b72aabfcbf0abb70b66b7e73056164479e10aaab0686d0cd047b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
3	4a64e9d4f226b72aabfcbf0abb70b66b7e73056164479e10aaab0686d0cd047b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	171.250.165.204	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:10:15.379086+07	35acf5495e1e2399d358980af47ed41153168e527a7c4daa9cd977a1ae867c71	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)		Thất bại	f	0	\N	\N
178	89526805c68fddcd142fbb89a67918f572ad6d4580f9b04a5bb1585221c9c160	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1269482 truy cập đề thi [Đề thi chính thức Giữa kỳ I - Ngữ văn 10]	2026-10-30 14:29:11.741341+07	8b4457eaa3cc139ab827ba082c6631f4b635dc6adbbdcb6f2141031b79ba7622	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	De_ChinhThuc_Van10_GK1.pdf	Thành công	f	0	\N	\N
179	8b4457eaa3cc139ab827ba082c6631f4b635dc6adbbdcb6f2141031b79ba7622	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Xem đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1269482 truy cập đề thi [Đề thi chính thức Giữa kỳ I - Ngữ văn 10]	2026-10-30 14:29:12.114822+07	084ed46ce1aeadf96b940cf6fcaa2219eb622cacffc230a26e3e9de69c8897b6	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	De_ChinhThuc_Van10_GK1.pdf	Thành công	f	0	\N	\N
180	084ed46ce1aeadf96b940cf6fcaa2219eb622cacffc230a26e3e9de69c8897b6	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Thêm đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1269482 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Ngữ văn 10], SHA-256: 03b9092b99e9eb2d...	2026-10-30 14:29:39.815306+07	638d9da4cbde28e8ef4df3cb6d0b1f6086290d2c8a705eec56d94fe7be6008db	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
181	638d9da4cbde28e8ef4df3cb6d0b1f6086290d2c8a705eec56d94fe7be6008db	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Sửa đề thi	192.168.1.4	171.250.165.204	Thành công	Giáo viên GV1269482 cập nhật lịch thi [Kiểm tra giữa kỳ II] và đề thi [Đề kiểm tra giữa kỳ I - Ngữ văn 10], SHA-256: 03b9092b99e9eb2d...	2026-10-30 14:30:16.905437+07	7db4f8c7686a8d6daf66696e80d66a0296b8b8a9739bee0fbb98ebe8c70a843d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx	Thành công	f	0	\N	\N
\.


--
-- Data for Name: phanquyentheokhoimon; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.phanquyentheokhoimon (ma_phan_quyen, ma_tai_khoan, ma_khoi, ma_mon_hoc, duoc_truy_cap_de_chung, duoc_truy_cap_de_chinh_thuc, nguoi_cap_quyen, thoi_diem_cap_quyen) FROM stdin;
23	674289a6-2f98-4142-b90f-436c9e5ab1b4	11	5	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
24	674289a6-2f98-4142-b90f-436c9e5ab1b4	12	5	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
25	bc398092-6172-4a0b-8095-dc4f9d33c177	10	5	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
26	bc398092-6172-4a0b-8095-dc4f9d33c177	11	5	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
27	bc398092-6172-4a0b-8095-dc4f9d33c177	12	5	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
1	51c35c7f-0e7c-4880-8925-2f06926f89b0	10	1	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
2	51c35c7f-0e7c-4880-8925-2f06926f89b0	11	1	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
3	51c35c7f-0e7c-4880-8925-2f06926f89b0	12	1	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
4	9ea71a69-8aee-4305-a2aa-65b193245bc1	10	1	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
5	9ea71a69-8aee-4305-a2aa-65b193245bc1	11	1	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
6	9ea71a69-8aee-4305-a2aa-65b193245bc1	12	1	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
7	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	10	1	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
8	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	11	1	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
9	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	12	1	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
10	9bb3575c-1403-4c77-843e-51763a46af39	10	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
11	9bb3575c-1403-4c77-843e-51763a46af39	11	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
12	9bb3575c-1403-4c77-843e-51763a46af39	12	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
13	48f58e38-e84c-44d7-84db-80d4985e7d84	10	2	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
14	48f58e38-e84c-44d7-84db-80d4985e7d84	11	2	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
15	48f58e38-e84c-44d7-84db-80d4985e7d84	12	2	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
16	ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	10	3	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
17	ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	11	3	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
18	ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	12	3	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
19	7b59f9b7-0c55-44d9-b951-ef82e47a235e	10	3	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
28	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	10	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 14:23:45.165762+07
29	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	11	2	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 14:23:45.165762+07
30	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	12	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 14:23:45.165762+07
20	7b59f9b7-0c55-44d9-b951-ef82e47a235e	11	3	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
21	7b59f9b7-0c55-44d9-b951-ef82e47a235e	12	3	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
22	674289a6-2f98-4142-b90f-436c9e5ab1b4	10	5	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
\.


--
-- Data for Name: phiendangnhap; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.phiendangnhap (ma_phien, ma_tai_khoan, ma_phien_bam, ip_thiet_bi, ipv4, thong_tin_thiet_bi, da_xac_thuc_otp, da_thu_hoi, thoi_diem_het_han, thoi_diem_tao) FROM stdin;
03b8ac86-6339-4f4d-8ade-cca1f8cbbbfe	51c35c7f-0e7c-4880-8925-2f06926f89b0	3fe97596704641e8319cf3dbdacc9ff8f17fd573bd7a17b6ad961ef5eedbd2ad	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 04:03:55.275759+07	2026-10-30 20:03:55.275759+07
c8d245aa-367e-47af-8383-09cf0e3735ac	48190309-eeb6-4395-a18f-1f902d580c97	a9ef5f9095148a8681c2bc0f9da7f517e7b112bdad73f51eb78859d6c8f70d68	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:00:23.806228+07	2026-10-28 20:00:23.806228+07
d94493c5-15c3-4d40-a104-6377e85bbac9	48190309-eeb6-4395-a18f-1f902d580c97	697d0d676f5e1d70e483c826e4c7e5307c609ec403a0eb4d89f2de096c5116a2	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:00:52.264917+07	2026-10-28 20:00:52.264917+07
6778742d-0f36-4486-a0c5-f3bcef76a189	48190309-eeb6-4395-a18f-1f902d580c97	d3da0a5be9fb8399f108021e5fe75be34254db80b3e9e20e031f8c18e14cfab8	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:01:09.059867+07	2026-10-28 20:01:09.059867+07
8334aab1-4be9-487a-99d6-50075bf02cc2	48190309-eeb6-4395-a18f-1f902d580c97	943c50ff7218055c668b6e300d33b6ed14b0b070fc6b0f147b60c02d4bff50dd	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:02:46.284757+07	2026-10-28 20:02:46.284757+07
1544afeb-2d38-4ec7-9420-aef087e6ec28	48190309-eeb6-4395-a18f-1f902d580c97	8c09ced05b2512bb080eb6ff4350b14f4908d3adef57ac2c849059deee89f79c	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:04:30.477688+07	2026-10-28 20:04:30.477688+07
1e288975-194b-4d58-a322-5a37f5f92d1e	48190309-eeb6-4395-a18f-1f902d580c97	6b70fc5c3e562447da7bd012a13554d8784b36322bcdbba0fe242c118bf0ff1b	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:09:02.677404+07	2026-10-28 20:09:02.677404+07
6e30eb39-7f7e-44be-a060-9a73751571e9	48190309-eeb6-4395-a18f-1f902d580c97	a991eb1f73b04862eef9bbfa2fdfbbbeb0d41fa2b26e32756c2efb2c602afb87	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 07:20:23.988178+07	2026-10-28 23:20:23.988178+07
acbdaaf6-bb5f-4040-a220-d558ceec0bda	48190309-eeb6-4395-a18f-1f902d580c97	8eb54ae4e01fc074a2c2c609aaaef54f1c11597f178ba80a1f86a0ee31ed0ee3	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	f	2026-10-29 22:20:46.631176+07	2026-10-29 14:20:46.631176+07
f2171382-99b9-452e-9151-d047a7ad7a3d	48190309-eeb6-4395-a18f-1f902d580c97	16bff044054fee4000edb93cf18f2f9f5c12fb2bd54efd6044cbc11eff40f41e	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 03:05:19.55486+07	2026-10-30 19:05:19.55486+07
790428bb-e8cc-41c6-bf07-1c0030b9f254	48f58e38-e84c-44d7-84db-80d4985e7d84	a85a290755bc335ba4f218710cc0e142795096574719fe957fa9beeae10ee962	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 22:19:24.05206+07	2026-10-26 14:19:24.05206+07
3adb8fe8-b95a-4dba-b413-16eb54d30d9f	9ea71a69-8aee-4305-a2aa-65b193245bc1	a8616d01e004cb0b1cf18afec44439854347357f5e1a29abd36219bd4bdcb623	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:36:21.878755+07	2026-10-23 14:36:21.876215+07
50decb38-86e0-4e40-a72f-3a16d2f99ed1	9ea71a69-8aee-4305-a2aa-65b193245bc1	90cb0d2bc0e12c02f43ed9c693f5e96e4c63cf7468fe8bfef7211306ae3d3c81	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:42:39.175715+07	2026-10-23 14:42:39.173501+07
1abb92b3-b58a-43df-ad14-40dce4d0e506	51c35c7f-0e7c-4880-8925-2f06926f89b0	04eb93f260348d3f88dc72e56fa9a94b730c54799bcdb88e918ccb28ba7808bb	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 05:51:07.651561+07	2026-10-25 21:51:07.651561+07
e2d9e6fa-a070-4d7f-aa73-a034710a0b2f	9ea71a69-8aee-4305-a2aa-65b193245bc1	941d444543aa42e71947c77ba697ad5801b8d5884f5a10d8de41356765ad5b0f	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:45:20.551876+07	2026-10-23 14:45:20.549471+07
4b10e45d-a62c-40fc-8711-de72d17fa900	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	b6d84dc71f9bf90757b6f2e63ee511470b767e611387792facdbd5a11aabb28c	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:00:53.390408+07	2026-10-28 20:00:53.390408+07
fd422412-26da-413b-8f05-600c514a3eb1	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	d9dbf72c07312d0aa8caeca0cdcc15f27a335d33bd3f16a97cd399e6c2d459df	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:01:10.320863+07	2026-10-28 20:01:10.320863+07
aad25764-195c-493c-883b-1315f672357f	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	64350a293fbba3dae33c4f8cb3d8ab4700c720f40b97ec77e1834785cecb6ab7	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:02:47.683673+07	2026-10-28 20:02:47.683673+07
e3d71f18-3f9a-4cee-b181-96533a11a931	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	feb68326837138293bf1b0b83996dada4a6c43897ae2c6b8dc8a35788eede9a0	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:04:31.759411+07	2026-10-28 20:04:31.759411+07
4d94965d-4592-48c2-9259-24637096d2a9	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	83ba0a10453b7f6348680914fd43cfe4dd714e9ab6947872cc4325639ac3fcba	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:09:03.881139+07	2026-10-28 20:09:03.881139+07
bf877629-bca0-4608-b71b-5c9482b01f4a	9ea71a69-8aee-4305-a2aa-65b193245bc1	532a3629d665c4fb21e585c2c4c4d73123937146b7f1d3daa924724372f73aef	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 03:46:15.536668+07	2026-10-28 19:46:15.536668+07
28288268-73ea-4ccb-8bb2-8b0d5f818330	48190309-eeb6-4395-a18f-1f902d580c97	d4d4a7599f34bf78e76cf43f9197f8e26c37006a64c50db6b3cdae2bb137728d	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 07:23:59.361159+07	2026-10-28 23:23:59.361159+07
49a8106c-2833-4a56-9b95-99c132eb1eb1	51c35c7f-0e7c-4880-8925-2f06926f89b0	2d28accce2786b3928e5f53dee7588f291c20dfe87518bcb00e74215387aae98	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 03:30:55.000438+07	2026-10-30 19:30:55.000438+07
52f99d55-bc18-45ee-8583-bf380c135f54	48190309-eeb6-4395-a18f-1f902d580c97	f1058d6bb1719a3b3e93d505b4c25a110d63748b9f8f834c76a54496c485cb0c	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:44:14.322147+07	2026-10-30 13:44:14.322147+07
f387a297-e119-43f6-8f8a-d7498b3ee8a0	51c35c7f-0e7c-4880-8925-2f06926f89b0	5db6cf5ec3122e639dbe1a2adf9d0879e917e4b835d8b088d81e1e1f36657d97	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 22:17:36.466216+07	2026-10-26 14:17:36.466216+07
66daead1-31dd-497a-ac25-64de7c2bb828	51c35c7f-0e7c-4880-8925-2f06926f89b0	a5d3ed75a57c7985396e9c17a2d5240394efb79d7c3f60f669151ca86dc2a14a	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 03:01:16.48035+07	2026-10-28 19:01:16.48035+07
891fff23-51c4-408a-a0af-0aa1a9b30ee3	51c35c7f-0e7c-4880-8925-2f06926f89b0	e426eeafcd6bc42fe99b00a910f3cd44a3d881b45d125940b79da51f54db7885	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 03:01:22.455142+07	2026-10-28 19:01:22.455142+07
0339dd15-7c6e-4e51-b538-651e024cb59f	51c35c7f-0e7c-4880-8925-2f06926f89b0	180f315503a423e8caf2a0560276790a73071e96bb473dcd6d71bae2c5cdf588	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:10:25.2833+07	2026-10-23 14:10:25.278996+07
d588dcb0-45a8-4882-8c48-11f136c201c5	51c35c7f-0e7c-4880-8925-2f06926f89b0	be8f9fb5ea99137e27f94168082ab916810ef6901b91f2ba4d751c0d6bd36a5e	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:13:43.052317+07	2026-10-23 14:13:43.049187+07
164266ac-92f7-493e-873c-42bbe58060b8	51c35c7f-0e7c-4880-8925-2f06926f89b0	68c590a6eece937d0db0e502f5acf4189223628689eedd0cb16e382cc876c885	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:27:27.911147+07	2026-10-23 14:27:27.907281+07
99b239b2-3e18-409c-a823-2bdbd4ce64e5	51c35c7f-0e7c-4880-8925-2f06926f89b0	1b97384c126c043ab830a732136a9e945dae6cc0c0d8406fc0350cde55ceb3e4	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:28:45.607132+07	2026-10-23 14:28:45.604959+07
565f71ac-aa0e-4ed8-9b51-54481f5a12bb	51c35c7f-0e7c-4880-8925-2f06926f89b0	5fc4311f163deb6ccafe66750e795ee8200a5a11320d8d155f816b98ff9c8802	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:36:06.375733+07	2026-10-23 14:36:06.373136+07
cf1a65f7-84a8-4a8d-a7fa-acaf00165aaf	51c35c7f-0e7c-4880-8925-2f06926f89b0	6d65f2c674a91a3dec8d9fced47b1870a372dc058300c6e6d9d2e4afab868114	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 05:34:59.802005+07	2026-10-25 21:34:59.802005+07
99944b89-7059-432b-a5fe-b5748c12e959	48190309-eeb6-4395-a18f-1f902d580c97	6b5f3604456122967446db139ee0e402aea2b34a713bb998e3d2540c1c6f3bdb	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 03:33:05.205842+07	2026-10-30 19:33:05.205842+07
1fc403af-3525-4dc5-9eda-3560dcf0a419	51c35c7f-0e7c-4880-8925-2f06926f89b0	56d177bbf81e6e78bc48d8105577628b264e7270bac6103716054de176b7e797	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 07:45:09.533419+07	2026-10-28 23:45:09.533419+07
10c1c7a1-4a33-4af9-aaac-ff418269adf2	51c35c7f-0e7c-4880-8925-2f06926f89b0	eb503bd63f8e4e66bb166513e295399f992efd3732b8ba785c81b56420aae074	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-29 22:11:28.582834+07	2026-10-29 14:11:28.582834+07
ff21ac4a-f418-4929-afbb-0dfdfd1adfb2	51c35c7f-0e7c-4880-8925-2f06926f89b0	25fecb790280907c1e6fdf38b1367e2b49952145d8abe64aa82b5ce9016799ee	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130	t	t	2026-10-30 17:11:23.332267+07	2026-10-30 09:11:23.332267+07
c1870123-4b41-47cb-9ae4-4d5b407fbe69	48190309-eeb6-4395-a18f-1f902d580c97	425f155757259f1651371543d15f51628795dc77626df5935f2cfcb3260e97c5	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 18:11:18.66184+07	2026-10-30 10:11:18.66184+07
05b34a1e-07d0-43d3-b21b-de38d369e66f	9ea71a69-8aee-4305-a2aa-65b193245bc1	774de74cf1a8e43d17e77bcce82ee7428e202e4d53282996da94bf6af77db816	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:33:42.339087+07	2026-10-30 13:33:42.339087+07
b26cd5f9-4e8a-4f40-bcd6-a0229549dd96	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	43f216b9991d4f211d03fe57967845b233a02289481cc08a04ae68a57a5d0235	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:34:59.191699+07	2026-10-30 13:34:59.191699+07
00ec1cdb-07db-4248-8762-e7857d485738	9ea71a69-8aee-4305-a2aa-65b193245bc1	a12cd0265b68d2945a18870d6f58d757ccdb420187d0b4cbdd6033a7ecc5224d	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:43:04.028499+07	2026-10-30 13:43:04.028499+07
9fdbb999-654f-456b-a8bb-aa75995514c7	48190309-eeb6-4395-a18f-1f902d580c97	d428432e0fd9a092a82cb06d8fd9e117a71828790b673849fd24678cd920202d	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:56:45.841106+07	2026-10-30 13:56:45.841106+07
570bfbca-3594-4eed-bcaf-d9cba1942cdd	48190309-eeb6-4395-a18f-1f902d580c97	bc53f5d45ff54c6634d2aac4cf43edd723aee20f470783218fe63d655513f768	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:18:02.695904+07	2026-10-30 14:18:02.695904+07
4b8e49f1-0689-465c-80fd-a65ab22ab21a	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	e077da497e0987a1249a40e8401a5f6aa299701b93c53cf1d86f068323353477	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:25:15.401396+07	2026-10-30 14:25:15.401396+07
954ee27f-665c-46e2-95d0-68c9482ee7cb	48190309-eeb6-4395-a18f-1f902d580c97	9c62ee00a7bfe993bfce6dab7fdf55c616214ea93e3bc228398383dbce360bd0	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:59:48.286302+07	2026-10-30 13:59:48.286302+07
6baa35f6-b011-43ab-80ad-9a2b87284c7e	48190309-eeb6-4395-a18f-1f902d580c97	ba818bdaf8a94c07f389520032eb1548803c00db3ec0c7b0adcb9d167367cdcc	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:04:40.328253+07	2026-10-30 14:04:40.328253+07
565e5822-708e-4af8-9a3a-9d5969761451	48190309-eeb6-4395-a18f-1f902d580c97	097285b59945b11adb148ab4d7d7b9c422a372ace73d29b4e13f351c0449898e	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:31:03.799257+07	2026-10-30 14:31:03.799257+07
de7b45c1-0c82-442c-b448-90c6b8ffbbf8	51c35c7f-0e7c-4880-8925-2f06926f89b0	ab4f9ebb5c14d25f031a038cfa2fd492ba8742716803c8a0b463b82d13030246	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130	t	t	2026-10-30 18:07:50.813619+07	2026-10-30 10:07:50.813619+07
67a1d7b2-9659-411c-ad6a-e8ef8a09eab1	51c35c7f-0e7c-4880-8925-2f06926f89b0	852f7c7db69119f4b9d7b5007205831fc097de41cdbc902e4b2f96bc60389ffd	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 18:08:07.511644+07	2026-10-30 10:08:07.511644+07
e3db6827-3260-434f-a703-5c75987def91	51c35c7f-0e7c-4880-8925-2f06926f89b0	9ce198b95cf3a6af3641c02ca4df746eed94934792928036f75d084e471d78df	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:33:13.876368+07	2026-10-30 13:33:13.876368+07
e2dabfdf-064a-4c1e-a901-947cf1873080	51c35c7f-0e7c-4880-8925-2f06926f89b0	5491a1bd3737a202869b34408167b165d6ac00fe1750e7ae24de7b6c7be3f7f4	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:05:56.009471+07	2026-10-30 14:05:56.009471+07
6d0e80a1-7f46-47d6-9914-6b267e4c4359	48190309-eeb6-4395-a18f-1f902d580c97	554201f4b8bbb44815055d4db77ba84619bafded0b976be444b79c28299ecc48	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:10:02.707197+07	2026-10-30 14:10:02.707197+07
24ab8784-7c7f-47b2-96b1-954eec46fd8d	51c35c7f-0e7c-4880-8925-2f06926f89b0	fef1b7ff451ee8489ab8a6b43aa2b8f9a476cf998ab578f52153623377ef6509	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:14:34.54162+07	2026-10-30 14:14:34.54162+07
28e96b41-9ae6-47b2-9e0c-0e4e36c578c0	51c35c7f-0e7c-4880-8925-2f06926f89b0	f29c1a0bb2a91ade1dcc2b8593857dfb073763a5924c1217f7e2f02f6a3cf8ed	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:43:21.625141+07	2026-10-30 14:43:21.625141+07
bc3ed785-4ce2-402e-8b94-a38ee2f3cb1d	51c35c7f-0e7c-4880-8925-2f06926f89b0	624d87dde95f5db0b86affe9150672927713895d1f58f255311513c742aa9a14	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 02:44:02.411377+07	2026-10-30 18:44:02.411377+07
c4ec5cbf-0991-4b97-90c0-edc09f680d41	48190309-eeb6-4395-a18f-1f902d580c97	8c4303845c3f4abb0b1cacc35d5bc3c56057f3b7e550f51f1845d5d045411784	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 04:09:35.45219+07	2026-10-30 20:09:35.45219+07
2319b741-c4d8-4df1-823c-f05ab35420f1	48190309-eeb6-4395-a18f-1f902d580c97	ada054746b816445dccac7afc75351ad8d86848fea913676f31de5f22ac837fe	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-31 04:10:30.967227+07	2026-10-30 20:10:30.967227+07
0344859f-9d1c-4899-a24d-fcd37d05a862	48190309-eeb6-4395-a18f-1f902d580c97	662a2320636929ea8afcdccd998aa05bfc3e2ed9a59be87c59842fd18f99335b	192.168.1.4	171.250.165.204	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	f	2026-10-31 04:11:20.226093+07	2026-10-30 20:11:20.226093+07
\.


--
-- Data for Name: taikhoan; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.taikhoan (ma_tai_khoan, ma_can_bo, ten_dang_nhap, mat_khau, ho_ten, email, vai_tro, bi_mat_otp_ma_hoa, da_kich_hoat_otp, bi_khoa, so_lan_dang_nhap_sai, so_lan_sai_otp, ip_thiet_bi_gan_nhat, ipv4_gan_nhat, thoi_diem_tao, dang_hoat_dong, khoa_den_thoi_diem, ma_pin, ma_xac_nhan_pin, han_xac_nhan_pin) FROM stdin;
48190309-eeb6-4395-a18f-1f902d580c97	AD1568920	admin.phuc	$2b$12$h.TJSMjvPKK929TGXp.xXujh9umxQqSgqxIvHRllu3yqnsiqY8IZu	Trần Văn Phúc	admin.phuc@thpthoangvanthu.edu.vn	QUAN_TRI	\\xe8a7861e198c727eeb615f20bdd222376f0e5b725674c44998fd076ebc69144770c7395005b044c177ab3ceab8dde9d4e5fcf814648af582d2878375	t	f	0	0	192.168.1.4	171.250.165.204	2026-10-23 14:09:03.698911+07	t	\N	$2b$12$CTyG.pEwj7OiKqAGmEM0TOMH3r9mGRH.hOXG.0LtjwjQux/2j/kjq	\N	\N
9bb3575c-1403-4c77-843e-51763a46af39	GV1456278	gv.nam	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Lê Hoàng Nam	gv.nam@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x665a8b8877ddbb32012fc9f7037b1f79d76b6d4f8792ffbb4ba8cc3742239d8f4da4e10a5a4af228bb8ae4e72b8ec3397b973fc45593a41c2e14c200	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
2cf83bec-ba4b-4648-9c11-4144d9aa6eab	GV1780839	gv.mai	$2b$12$r7ZZ.zQyFkR2rziSjYPvcecxQu3D/koX03e3Tf1f1YOxg7GeLQfke	Nguyễn Thị Mai	gv.mai@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x2b7824ce244ca53e806876f2ef3da6b1ed6f15e7d1dcb67cd58440bfaaae008a3ca8d242cabc1dcfa47fefe739201857b3b824ef0b75bca9530c03e7	t	f	0	0	192.168.1.4	171.250.165.204	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
674289a6-2f98-4142-b90f-436c9e5ab1b4	GV6790839	gv.huy	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Võ Quốc Huy	gv.huy@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xceac45d8fbed28a7997a9847af217aec94200179b8f33848b9311ce74a954a983acc7b8851667256e82950a0c96d84c78384dd2475f6d735c5b64173	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	GV7869077	gv.hoa	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Phạm Thị Hoa	gv.hoa@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xf5c73635dfa9164aba87c7a6cb7407d6a11e78c2df2ae03e1e2cdd73f8a549fca241dc9b7e87af6aa51be4d988567ee28d7ae8d79fbb13fe1a9c0754	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
48f58e38-e84c-44d7-84db-80d4985e7d84	GV1428003	gv.tuan	$2b$12$r7ZZ.zQyFkR2rziSjYPvcecxQu3D/koX03e3Tf1f1YOxg7GeLQfke	Đặng Minh Tuấn	gv.tuan@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x58fe3a86a4faedc624498e4461b5c85c4985b9096b303d6a0cf5fc868423e64ccd1b9fc0fdddc1c78c8fceb62691dbca1f87d6cd944a773bd7dbed47	t	f	0	0	192.168.1.4	171.250.165.204	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
7b59f9b7-0c55-44d9-b951-ef82e47a235e	GV7802740	gv.ngoc	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Bùi Thị Ngọc	gv.ngoc@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x22fc99112217a57258929ee602b99145c28e62b66974217d0c56ee2dbf2ff123b20df1e3510c9252821e1a38727531461f3048310ea34a26d784147c	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
9ea71a69-8aee-4305-a2aa-65b193245bc1	GV1324570	gv.lan	$2b$12$r7ZZ.zQyFkR2rziSjYPvcecxQu3D/koX03e3Tf1f1YOxg7GeLQfke	Trần Thị Lan	gv.lan@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xf5ca4b583f54573a5c43d10e7eefa2e3e6ec9120e56e190229e94e41b70db0915bd236f62c3555fd8bd6d62b27899c11471d9ffd991b74e8d1c20b1b	t	f	0	0	192.168.1.4	171.250.165.204	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
bc398092-6172-4a0b-8095-dc4f9d33c177	GV1562839	gv.anh	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Hoàng Đức Anh	gv.anh@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x03dda1cf20edd6e6c00858ef78e1cd50cb27706f2e7560e206a966c46cd910e8b712172080d5e76491ef1f2ff8e4df36636d0621d5d92d0812063edb	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N	\N	\N	\N
de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	GV1269482	gv.quyen	$2b$12$oElWA6HWwa09fQUiPvzbu.2mOPaXKafjKuR2/ax0u3obD3bcnBpbK	Trần Mỹ Quyên	gv.quyen@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x4dada2c811c490518461f0501cd63785cabf25089166b1be3e5892d56986b42f7028fa7c0f5989f681f8efea	t	f	0	0	192.168.1.4	171.250.165.204	2026-10-30 14:23:45.165762+07	t	\N	\N	\N	\N
51c35c7f-0e7c-4880-8925-2f06926f89b0	GV1000458	gv.minh	$2b$12$cgi1xKKDzBNe0DwxMyotxOag5AFgAaztg.LCa11Y1OlES1SqEfKRq	Nguyễn Văn Minh	gv.minh@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xb891d2f1c30f84db00b255fe0946b5ef7b93a9d7965e61b5b4c591d5ce2a17005f530e09c3f35179cd424ca0	t	f	0	0	192.168.1.4	171.250.165.204	2026-10-23 14:09:03.698911+07	t	\N	$2b$12$CRmbSZ1TKZkerjKd8zpuPeLY55XYwestEr8ehEJP5r/GUDYLNqsPK	\N	\N
\.


--
-- Data for Name: tepbay; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.tepbay (ma_bay, ma_de_thi, ten_tep_bay, duong_dan_kich_hoat, so_lan_kich_hoat, thoi_diem_kich_hoat_gan_nhat, dang_hoat_dong) FROM stdin;
1	5cbdf2c8-547e-4043-9ca4-ea8f64047ea0	De_ChinhThuc_Toan12_CK1_Mat.pdf	/api/de-thi/5cbdf2c8-547e-4043-9ca4-ea8f64047ea0/download	3	2026-10-28 23:45:38.084465+07	t
\.


--
-- Name: chandiachiip_ma_chan_ip_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.chandiachiip_ma_chan_ip_seq', 4, true);


--
-- Name: lichthi_ma_lich_thi_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.lichthi_ma_lich_thi_seq', 18, true);


--
-- Name: monhoc_ma_mon_hoc_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.monhoc_ma_mon_hoc_seq', 8, true);


--
-- Name: nhatkylog_ma_nhat_ky_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.nhatkylog_ma_nhat_ky_seq', 255, true);


--
-- Name: phanquyentheokhoimon_ma_phan_quyen_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.phanquyentheokhoimon_ma_phan_quyen_seq', 271, true);


--
-- Name: tepbay_ma_bay_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.tepbay_ma_bay_seq', 1, true);


--
-- Name: chandiachiip chandiachiip_dia_chi_ip_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip
    ADD CONSTRAINT chandiachiip_dia_chi_ip_key UNIQUE (dia_chi_ip);


--
-- Name: chandiachiip chandiachiip_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip
    ADD CONSTRAINT chandiachiip_pkey PRIMARY KEY (ma_chan_ip);


--
-- Name: deontap deontap_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_pkey PRIMARY KEY (ma_de_on_tap);


--
-- Name: dethi dethi_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_pkey PRIMARY KEY (ma_de_thi);


--
-- Name: khoilop khoilop_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.khoilop
    ADD CONSTRAINT khoilop_pkey PRIMARY KEY (ma_khoi);


--
-- Name: lichthi lichthi_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_pkey PRIMARY KEY (ma_lich_thi);


--
-- Name: monhoc monhoc_ky_hieu_mon_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc
    ADD CONSTRAINT monhoc_ky_hieu_mon_key UNIQUE (ky_hieu_mon);


--
-- Name: monhoc monhoc_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc
    ADD CONSTRAINT monhoc_pkey PRIMARY KEY (ma_mon_hoc);


--
-- Name: monhoc monhoc_ten_mon_hoc_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc
    ADD CONSTRAINT monhoc_ten_mon_hoc_key UNIQUE (ten_mon_hoc);


--
-- Name: nhatkylog nhatkylog_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nhatkylog
    ADD CONSTRAINT nhatkylog_pkey PRIMARY KEY (ma_nhat_ky);


--
-- Name: phanquyentheokhoimon phanquyentheokhoimon_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_pkey PRIMARY KEY (ma_phan_quyen);


--
-- Name: phiendangnhap phiendangnhap_ma_phien_bam_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phiendangnhap
    ADD CONSTRAINT phiendangnhap_ma_phien_bam_key UNIQUE (ma_phien_bam);


--
-- Name: phiendangnhap phiendangnhap_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phiendangnhap
    ADD CONSTRAINT phiendangnhap_pkey PRIMARY KEY (ma_phien);


--
-- Name: taikhoan taikhoan_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_email_key UNIQUE (email);


--
-- Name: taikhoan taikhoan_ma_can_bo_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_ma_can_bo_key UNIQUE (ma_can_bo);


--
-- Name: taikhoan taikhoan_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_pkey PRIMARY KEY (ma_tai_khoan);


--
-- Name: taikhoan taikhoan_ten_dang_nhap_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_ten_dang_nhap_key UNIQUE (ten_dang_nhap);


--
-- Name: tepbay tepbay_duong_dan_kich_hoat_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay
    ADD CONSTRAINT tepbay_duong_dan_kich_hoat_key UNIQUE (duong_dan_kich_hoat);


--
-- Name: tepbay tepbay_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay
    ADD CONSTRAINT tepbay_pkey PRIMARY KEY (ma_bay);


--
-- Name: phanquyentheokhoimon uq_phan_quyen_tk_khoi_mon; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT uq_phan_quyen_tk_khoi_mon UNIQUE (ma_tai_khoan, ma_khoi, ma_mon_hoc);


--
-- Name: idx_deontap_mon_khoi; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_deontap_mon_khoi ON public.deontap USING btree (ma_mon_hoc, ma_khoi);


--
-- Name: idx_dethi_mon_khoi; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_dethi_mon_khoi ON public.dethi USING btree (ma_mon_hoc, ma_khoi);


--
-- Name: idx_nhatkylog_ma_tai_khoan; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_nhatkylog_ma_tai_khoan ON public.nhatkylog USING btree (ma_tai_khoan);


--
-- Name: idx_nhatkylog_thoi_diem; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_nhatkylog_thoi_diem ON public.nhatkylog USING btree (thoi_diem DESC);


--
-- Name: idx_phiendangnhap_ma_phien_bam; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phiendangnhap_ma_phien_bam ON public.phiendangnhap USING btree (ma_phien_bam);


--
-- Name: idx_phiendangnhap_ma_tai_khoan; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phiendangnhap_ma_tai_khoan ON public.phiendangnhap USING btree (ma_tai_khoan);


--
-- Name: deontap trg_deontap_chi_nguoi_tao_sua; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_deontap_chi_nguoi_tao_sua BEFORE UPDATE ON public.deontap FOR EACH ROW EXECUTE FUNCTION public.fn_kiem_tra_chu_so_huu_de_on_tap();


--
-- Name: dethi trg_dethi_chi_nguoi_ra_de_sua; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_dethi_chi_nguoi_ra_de_sua BEFORE UPDATE ON public.dethi FOR EACH ROW EXECUTE FUNCTION public.fn_kiem_tra_chu_so_huu_de_thi();


--
-- Name: nhatkylog trg_nhat_ky_log_chan_chinh_sua; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_nhat_ky_log_chan_chinh_sua BEFORE UPDATE ON public.nhatkylog FOR EACH ROW EXECUTE FUNCTION public.fn_chan_chinh_sua_nhat_ky_log();


--
-- Name: nhatkylog trg_nhat_ky_log_chan_truncate; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_nhat_ky_log_chan_truncate BEFORE TRUNCATE ON public.nhatkylog FOR EACH STATEMENT EXECUTE FUNCTION public.fn_chan_truncate_nhat_ky_log();


--
-- Name: nhatkylog trg_nhat_ky_log_chan_xoa; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_nhat_ky_log_chan_xoa BEFORE DELETE ON public.nhatkylog FOR EACH ROW EXECUTE FUNCTION public.fn_chan_xoa_nhat_ky_log();


--
-- Name: nhatkylog trg_nhat_ky_log_noi_chuoi; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_nhat_ky_log_noi_chuoi BEFORE INSERT ON public.nhatkylog FOR EACH ROW EXECUTE FUNCTION public.fn_nhat_ky_log_noi_chuoi();


--
-- Name: chandiachiip chandiachiip_nguoi_chan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip
    ADD CONSTRAINT chandiachiip_nguoi_chan_fkey FOREIGN KEY (nguoi_chan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- Name: deontap deontap_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- Name: deontap deontap_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- Name: deontap deontap_nguoi_cap_nhat_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_nguoi_cap_nhat_fkey FOREIGN KEY (nguoi_cap_nhat) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: deontap deontap_nguoi_tao_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_nguoi_tao_fkey FOREIGN KEY (nguoi_tao) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: dethi dethi_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- Name: dethi dethi_ma_lich_thi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_ma_lich_thi_fkey FOREIGN KEY (ma_lich_thi) REFERENCES public.lichthi(ma_lich_thi) ON DELETE SET NULL;


--
-- Name: dethi dethi_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- Name: dethi dethi_nguoi_cap_nhat_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_nguoi_cap_nhat_fkey FOREIGN KEY (nguoi_cap_nhat) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: dethi dethi_nguoi_niem_phong_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_nguoi_niem_phong_fkey FOREIGN KEY (nguoi_niem_phong) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- Name: dethi dethi_nguoi_ra_de_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_nguoi_ra_de_fkey FOREIGN KEY (nguoi_ra_de) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: lichthi lichthi_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- Name: lichthi lichthi_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- Name: lichthi lichthi_nguoi_tao_lich_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_nguoi_tao_lich_fkey FOREIGN KEY (nguoi_tao_lich) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: nhatkylog nhatkylog_ma_tai_khoan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nhatkylog
    ADD CONSTRAINT nhatkylog_ma_tai_khoan_fkey FOREIGN KEY (ma_tai_khoan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- Name: phanquyentheokhoimon phanquyentheokhoimon_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- Name: phanquyentheokhoimon phanquyentheokhoimon_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- Name: phanquyentheokhoimon phanquyentheokhoimon_ma_tai_khoan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_ma_tai_khoan_fkey FOREIGN KEY (ma_tai_khoan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: phanquyentheokhoimon phanquyentheokhoimon_nguoi_cap_quyen_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_nguoi_cap_quyen_fkey FOREIGN KEY (nguoi_cap_quyen) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- Name: phiendangnhap phiendangnhap_ma_tai_khoan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phiendangnhap
    ADD CONSTRAINT phiendangnhap_ma_tai_khoan_fkey FOREIGN KEY (ma_tai_khoan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- Name: tepbay tepbay_ma_de_thi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay
    ADD CONSTRAINT tepbay_ma_de_thi_fkey FOREIGN KEY (ma_de_thi) REFERENCES public.dethi(ma_de_thi) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict 1U6utf0sZGcKBMLhgxhp5Ox0WjoBG4byULJY9cOcfX7Ce0jcSQNoRTgHeB0115R

