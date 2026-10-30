--
-- PostgreSQL database dump
--

\restrict YDa6d57zdgVJdspUTaT1glD7dXGKhvZjhNwC306aIFX9TDdIFHh0ta4FIDKP0hw

-- Dumped from database version 17.9
-- Dumped by pg_dump version 17.9

-- Started on 2026-10-30 14:50:54

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
-- TOC entry 2 (class 3079 OID 183692)
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- TOC entry 5106 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- TOC entry 283 (class 1255 OID 183792)
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
    NEW.ma_bam_truoc := v_bam_truoc;
    NEW.ma_bam_nhat_ky := fn_tinh_bam_nhat_ky_log(
        NEW.ma_nhat_ky,
        NEW.ma_bam_truoc,
        NEW.ma_tai_khoan,
        NEW.hanh_dong,
        NEW.ip_thiet_bi,
        NEW.ipv4,
        NEW.ket_qua,
        NEW.chi_tiet,
        NEW.thoi_diem
    );

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.fn_nhat_ky_log_noi_chuoi() OWNER TO postgres;

--
-- TOC entry 282 (class 1255 OID 183791)
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
-- TOC entry 234 (class 1259 OID 241319)
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
-- TOC entry 233 (class 1259 OID 241318)
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
-- TOC entry 5107 (class 0 OID 0)
-- Dependencies: 233
-- Name: chandiachiip_ma_chan_ip_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.chandiachiip_ma_chan_ip_seq OWNED BY public.chandiachiip.ma_chan_ip;


--
-- TOC entry 227 (class 1259 OID 224967)
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
    nguoi_cap_nhat uuid
);


ALTER TABLE public.deontap OWNER TO postgres;

--
-- TOC entry 230 (class 1259 OID 225024)
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
    CONSTRAINT dethi_loai_de_check CHECK (((loai_de)::text = ANY ((ARRAY['CHINH_THUC'::character varying, 'ON_TAP'::character varying, 'DE_MOI'::character varying])::text[])))
);


ALTER TABLE public.dethi OWNER TO postgres;

--
-- TOC entry 222 (class 1259 OID 224918)
-- Name: khoilop; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.khoilop (
    ma_khoi smallint NOT NULL,
    ten_khoi character varying(20) NOT NULL
);


ALTER TABLE public.khoilop OWNER TO postgres;

--
-- TOC entry 229 (class 1259 OID 225001)
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
-- TOC entry 228 (class 1259 OID 225000)
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
-- TOC entry 5108 (class 0 OID 0)
-- Dependencies: 228
-- Name: lichthi_ma_lich_thi_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.lichthi_ma_lich_thi_seq OWNED BY public.lichthi.ma_lich_thi;


--
-- TOC entry 224 (class 1259 OID 224924)
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
-- TOC entry 223 (class 1259 OID 224923)
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
-- TOC entry 5109 (class 0 OID 0)
-- Dependencies: 223
-- Name: monhoc_ma_mon_hoc_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.monhoc_ma_mon_hoc_seq OWNED BY public.monhoc.ma_mon_hoc;


--
-- TOC entry 221 (class 1259 OID 183773)
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
    tai_lieu_thao_tac character varying(255) DEFAULT ''::character varying
);


ALTER TABLE public.nhatkylog OWNER TO postgres;

--
-- TOC entry 220 (class 1259 OID 183772)
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
-- TOC entry 5110 (class 0 OID 0)
-- Dependencies: 220
-- Name: nhatkylog_ma_nhat_ky_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.nhatkylog_ma_nhat_ky_seq OWNED BY public.nhatkylog.ma_nhat_ky;


--
-- TOC entry 226 (class 1259 OID 224936)
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
-- TOC entry 225 (class 1259 OID 224935)
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
-- TOC entry 5111 (class 0 OID 0)
-- Dependencies: 225
-- Name: phanquyentheokhoimon_ma_phan_quyen_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.phanquyentheokhoimon_ma_phan_quyen_seq OWNED BY public.phanquyentheokhoimon.ma_phan_quyen;


--
-- TOC entry 219 (class 1259 OID 183752)
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
-- TOC entry 5112 (class 0 OID 0)
-- Dependencies: 219
-- Name: TABLE phiendangnhap; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.phiendangnhap IS 'Bảng quản lý phiên đăng nhập, chống đánh cắp Cookie và kiểm soát cổng 2FA';


--
-- TOC entry 5113 (class 0 OID 0)
-- Dependencies: 219
-- Name: COLUMN phiendangnhap.ma_phien_bam; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phiendangnhap.ma_phien_bam IS 'Mã băm SHA-256 của Session Token gửi về Cookie trình duyệt';


--
-- TOC entry 5114 (class 0 OID 0)
-- Dependencies: 219
-- Name: COLUMN phiendangnhap.da_xac_thuc_otp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phiendangnhap.da_xac_thuc_otp IS 'Kiểm soát cổng 2FA: chỉ cho phép truy cập tài nguyên khi cờ = TRUE';


--
-- TOC entry 218 (class 1259 OID 183729)
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
    CONSTRAINT chk_taikhoan_email_domain CHECK (((email)::text ~~ '%@thpthoangvanthu.edu.vn'::text)),
    CONSTRAINT chk_taikhoan_ma_can_bo CHECK (((ma_can_bo)::text ~ '^(GV|AD|HT)[0-9]{7}$'::text)),
    CONSTRAINT chk_taikhoan_ten_dang_nhap CHECK (((ten_dang_nhap)::text ~ '^[a-z0-9.]+$'::text)),
    CONSTRAINT chk_taikhoan_vai_tro CHECK (((vai_tro)::text = ANY ((ARRAY['GIAO_VIEN'::character varying, 'BAN_GIAM_HIEU'::character varying, 'QUAN_TRI'::character varying])::text[])))
);


ALTER TABLE public.taikhoan OWNER TO postgres;

--
-- TOC entry 5115 (class 0 OID 0)
-- Dependencies: 218
-- Name: TABLE taikhoan; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.taikhoan IS 'Bảng lưu trữ thông tin tài khoản người dùng và cấu hình bảo mật 2FA TOTP';


--
-- TOC entry 5116 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.ma_tai_khoan; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ma_tai_khoan IS 'Mã định danh duy nhất của tài khoản (UUID)';


--
-- TOC entry 5117 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.ma_can_bo; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ma_can_bo IS 'Mã quản lý hiển thị: Tên viết tắt vai trò (GV/AD/HT) + 7 số ngẫu nhiên';


--
-- TOC entry 5118 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.ten_dang_nhap; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.ten_dang_nhap IS 'Tên đăng nhập viết thường, không dấu, chỉ gồm chữ, số và dấu chấm (^[a-z0-9.]+$)';


--
-- TOC entry 5119 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.mat_khau; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.mat_khau IS 'Mật khẩu đã được mã băm (bcrypt)';


--
-- TOC entry 5120 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.email; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.email IS 'Địa chỉ email nội bộ trường (@thpthoangvanthu.edu.vn)';


--
-- TOC entry 5121 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.vai_tro; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.vai_tro IS 'Vai trò phân cấp: GIAO_VIEN / BAN_GIAM_HIEU / QUAN_TRI';


--
-- TOC entry 5122 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.bi_mat_otp_ma_hoa; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.bi_mat_otp_ma_hoa IS 'Khóa bí mật TOTP đã mã hóa AES-256 + Master Key';


--
-- TOC entry 5123 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.da_kich_hoat_otp; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.da_kich_hoat_otp IS 'Trạng thái kích hoạt 2FA (FALSE: hiện QR lần đầu; TRUE: khóa QR vĩnh viễn)';


--
-- TOC entry 5124 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN taikhoan.khoa_den_thoi_diem; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.taikhoan.khoa_den_thoi_diem IS 'Thời điểm tự động mở khóa an ninh (NOW() + 15 phút khi sai mật khẩu 5 lần / sai OTP 3 lần)';


--
-- TOC entry 232 (class 1259 OID 225058)
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
-- TOC entry 231 (class 1259 OID 225057)
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
-- TOC entry 5125 (class 0 OID 0)
-- Dependencies: 231
-- Name: tepbay_ma_bay_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tepbay_ma_bay_seq OWNED BY public.tepbay.ma_bay;


--
-- TOC entry 4861 (class 2604 OID 241322)
-- Name: chandiachiip ma_chan_ip; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip ALTER COLUMN ma_chan_ip SET DEFAULT nextval('public.chandiachiip_ma_chan_ip_seq'::regclass);


--
-- TOC entry 4850 (class 2604 OID 225004)
-- Name: lichthi ma_lich_thi; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi ALTER COLUMN ma_lich_thi SET DEFAULT nextval('public.lichthi_ma_lich_thi_seq'::regclass);


--
-- TOC entry 4840 (class 2604 OID 224927)
-- Name: monhoc ma_mon_hoc; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc ALTER COLUMN ma_mon_hoc SET DEFAULT nextval('public.monhoc_ma_mon_hoc_seq'::regclass);


--
-- TOC entry 4837 (class 2604 OID 183776)
-- Name: nhatkylog ma_nhat_ky; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nhatkylog ALTER COLUMN ma_nhat_ky SET DEFAULT nextval('public.nhatkylog_ma_nhat_ky_seq'::regclass);


--
-- TOC entry 4842 (class 2604 OID 224939)
-- Name: phanquyentheokhoimon ma_phan_quyen; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon ALTER COLUMN ma_phan_quyen SET DEFAULT nextval('public.phanquyentheokhoimon_ma_phan_quyen_seq'::regclass);


--
-- TOC entry 4858 (class 2604 OID 225061)
-- Name: tepbay ma_bay; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay ALTER COLUMN ma_bay SET DEFAULT nextval('public.tepbay_ma_bay_seq'::regclass);


--
-- TOC entry 5100 (class 0 OID 241319)
-- Dependencies: 234
-- Data for Name: chandiachiip; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.chandiachiip (ma_chan_ip, dia_chi_ip, ly_do, dang_chan, nguoi_chan, thoi_diem_chan) FROM stdin;
3	192.168.1.4	Chặn từ điều tra nhật ký #145	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 13:59:16.30602+07
\.


--
-- TOC entry 5093 (class 0 OID 224967)
-- Dependencies: 227
-- Data for Name: deontap; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.deontap (ma_de_on_tap, ten_de_on_tap, ma_mon_hoc, ma_khoi, loai_de, nguoi_tao, duong_dan_tep, ten_tep_goc, ma_bam_sha256, da_chinh_sua, thoi_diem_tao, thoi_diem_cap_nhat, nguoi_cap_nhat) FROM stdin;
1b47751e-1dbf-41e7-ab3c-54c97e0927e3	Ôn tập Toán giữa kỳ I	1	10	Giữa kỳ I	51c35c7f-0e7c-4880-8925-2f06926f89b0	storage/de_on_tap/1b47751e-1dbf-41e7-ab3c-54c97e0927e3.enc	De_Toan_10_GiuaKy1.pdf	a3f64721879ec9c1830266c9d6e8e44d48cd4a875a0e77cddfb3366ad9e7a07e	f	2026-10-28 14:30:00+07	\N	\N
cafc0f1b-2004-4178-9666-4dccbe57ce14	Ôn tập Toán cuối kỳ I	1	10	Cuối kỳ I	51c35c7f-0e7c-4880-8925-2f06926f89b0	storage/de_on_tap/cafc0f1b-2004-4178-9666-4dccbe57ce14.enc	De_Toan_10_CuoiKy1.pdf	5aaf180aff2386b659140b3167007ce35b793049512cfb985f9493e4dbfe300e	f	2026-10-27 16:20:00+07	\N	\N
86a7819c-797f-4a12-a76f-ec3058874495	Ôn tập Toán giữa kỳ II	1	11	Giữa kỳ II	9ea71a69-8aee-4305-a2aa-65b193245bc1	storage/de_on_tap/86a7819c-797f-4a12-a76f-ec3058874495.enc	De_Toan_11_GiuaKy2.pdf	7cf3feb5e17f1deb1a1f29b4b9660504e2746daca54db248a3f09f2e33b0dcf7	f	2026-10-26 09:15:00+07	\N	\N
10eb8c14-4d56-41e1-b1a3-d27c1bb1dbbe	Ôn tập Toán cuối kỳ II	1	12	Cuối kỳ II	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_on_tap/10eb8c14-4d56-41e1-b1a3-d27c1bb1dbbe.enc	De_Toan_12_CuoiKy2.pdf	47de0aff06a9a54521c5ae8dc6f676bf7c827a484edd1a0cc791bae2f2181a73	f	2026-10-25 11:05:00+07	\N	\N
777a9dd7-3e2a-4e3a-b1ee-6e69a6ba1632	Đề ôn tập chương Hàm số	1	12	Giữa kỳ II	51c35c7f-0e7c-4880-8925-2f06926f89b0	storage/de_on_tap/777a9dd7-3e2a-4e3a-b1ee-6e69a6ba1632.enc	De_Toan_12_HamSo.pdf	63901f41d6ccf34d4dd46d9cc6ab87b4be2d08da7f6cb7486cedec863b01f1f0	f	2026-10-22 13:40:00+07	\N	\N
16d1268e-8d47-4753-8bd5-94916ae584a2	Đề ôn tập Hình học không gian	1	11	Cuối kỳ I	9ea71a69-8aee-4305-a2aa-65b193245bc1	storage/de_on_tap/16d1268e-8d47-4753-8bd5-94916ae584a2.enc	De_Toan_11_HinhHoc.pdf	bbac801ee60eccb4ce71eaf0fd8b2b51b3b78e857a0733dfd9ac73d5a6c9cda0	f	2026-10-20 08:30:00+07	\N	\N
36fdc16f-fc50-4da4-951a-e4de72e300bd	Ôn tập Ngữ văn giữa kỳ I	2	10	Giữa kỳ I	48f58e38-e84c-44d7-84db-80d4985e7d84	storage/de_on_tap/36fdc16f-fc50-4da4-951a-e4de72e300bd.enc	De_Van_10_GiuaKy1.pdf	05cb95b66e964477fcb057e753ce64f89691fcaeb8d5413765190f22000646a6	f	2026-10-28 14:30:00+07	\N	\N
eba27d99-e943-4e37-836b-0a1c37b26a3c	Ôn tập Ngữ văn cuối kỳ I	2	10	Cuối kỳ I	9bb3575c-1403-4c77-843e-51763a46af39	storage/de_on_tap/eba27d99-e943-4e37-836b-0a1c37b26a3c.enc	De_Van_10_CuoiKy1.pdf	17a899f16013f1ff6e16309b84e5a192908d2bb4b3047f8a13166bc2c7b24193	f	2026-10-27 16:20:00+07	\N	\N
019c1f71-71e5-432b-840c-a047c3d24334	Ôn tập Ngữ văn giữa kỳ II	2	11	Giữa kỳ II	48f58e38-e84c-44d7-84db-80d4985e7d84	storage/de_on_tap/019c1f71-71e5-432b-840c-a047c3d24334.enc	De_Van_11_GiuaKy2.pdf	2fb21e4993d5043951f8e07f55324aa8469081364d0bf9d5a3737ffa31b07791	f	2026-10-26 09:15:00+07	\N	\N
1964d5ae-7b9b-454f-a55d-e18d449bd729	Ôn tập Nghị luận văn học lớp 12	2	12	Cuối kỳ II	9bb3575c-1403-4c77-843e-51763a46af39	storage/de_on_tap/1964d5ae-7b9b-454f-a55d-e18d449bd729.enc	De_Van_12_CuoiKy2.pdf	d35d027b059141a33290c12ad154fc415866ee2d3eea399737db03a9f620791c	f	2026-10-25 11:05:00+07	\N	\N
cc6d2d99-f491-4739-ad0c-b8a13c99084a	Ôn tập Tiếng Anh giữa kỳ I	3	10	Giữa kỳ I	ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	storage/de_on_tap/cc6d2d99-f491-4739-ad0c-b8a13c99084a.enc	De_Anh_10_GiuaKy1.pdf	551bd26f029ede41af007d66099022de2de3b475b66347bd014e1a298e2b6d58	f	2026-10-28 14:30:00+07	\N	\N
c7e217c6-54a2-45ea-9b8e-5c835b79b542	Ôn tập Tiếng Anh cuối kỳ I	3	11	Cuối kỳ I	7b59f9b7-0c55-44d9-b951-ef82e47a235e	storage/de_on_tap/c7e217c6-54a2-45ea-9b8e-5c835b79b542.enc	De_Anh_11_CuoiKy1.pdf	6aa09c95700a61678ccfcaff4a30b2e00e6e9d8116c2cc179c3af79bc9740c38	f	2026-10-27 16:20:00+07	\N	\N
c2388421-1e7f-4e6f-8c81-3ddfc884fd4c	Ôn tập Tiếng Anh giữa kỳ II	3	12	Giữa kỳ II	7b59f9b7-0c55-44d9-b951-ef82e47a235e	storage/de_on_tap/c2388421-1e7f-4e6f-8c81-3ddfc884fd4c.enc	De_Anh_12_GiuaKy2.pdf	e2a8bf7c63be0b6ff284e9a5e90865dbd41b0c122161ff857a9bfe6bbbb6b01c	f	2026-10-26 09:15:00+07	\N	\N
5d971cf9-0777-4237-bf84-43a96b357d8d	Ôn tập Vật lý giữa kỳ I	5	10	Giữa kỳ I	bc398092-6172-4a0b-8095-dc4f9d33c177	storage/de_on_tap/5d971cf9-0777-4237-bf84-43a96b357d8d.enc	De_Ly_10_GiuaKy1.pdf	bf5beefc7a7777fde9790da9ce5a4809f1e764b9a94eaf31f94ce48827a1511b	f	2026-10-28 14:30:00+07	\N	\N
8874dc39-deca-4fec-bd36-da756e6cc31d	Ôn tập Vật lý cuối kỳ I	5	11	Cuối kỳ I	674289a6-2f98-4142-b90f-436c9e5ab1b4	storage/de_on_tap/8874dc39-deca-4fec-bd36-da756e6cc31d.enc	De_Ly_11_CuoiKy1.pdf	cf8c49f959b0d52cbb76a1f57876b9a7c230e629486b0f0bbd1f35001e43c808	f	2026-10-27 16:20:00+07	\N	\N
7a805370-3e45-4fcb-9286-54af160a12bc	Ôn tập Dao động cơ & Sóng điện từ	5	12	Cuối kỳ II	674289a6-2f98-4142-b90f-436c9e5ab1b4	storage/de_on_tap/7a805370-3e45-4fcb-9286-54af160a12bc.enc	De_Ly_12_DaoDong.pdf	c6f8203f561319e3043bc56b0cc9d52a682b320a39e58a586890a7540810956a	f	2026-10-25 11:05:00+07	\N	\N
\.


--
-- TOC entry 5096 (class 0 OID 225024)
-- Dependencies: 230
-- Data for Name: dethi; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.dethi (ma_de_thi, ma_lich_thi, ten_de_thi, ma_mon_hoc, ma_khoi, loai_de, da_nem_phong, nguoi_ra_de, duong_dan_tep_ma_hoa, ten_tep_goc, ma_bam_sha256, chu_ky_so_nguoi_ra_de, khoa_ma_hoa_de, ma_nonce_aes, the_xac_thuc_aes, bi_can_thiep, thoi_diem_tao, duong_dan_tep, thoi_diem_cap_nhat, nguoi_cap_nhat, da_chinh_sua) FROM stdin;
f38e906b-72da-455e-9b1a-64e06961c1c5	8	Đề kiểm tra giữa kỳ I - Toán 10	1	10	CHINH_THUC	t	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/f38e906b-72da-455e-9b1a-64e06961c1c5.enc	de_kiem_tra_giua_ky_1_toan_10.pdf	ea0cbe4aa662a460040d4064b31a9b5dbeff5ba0c5330f291fc546c25b748145	\\x1ba4748f87ad25b94435549740bb99eb7b0a9960eb4034b64f6390f232323e98	\\xfaad62aa638c9275adb9df9183dcfed153de976adbbbceb2fad534a65792fa0b925d1d128e8a5f25fc06ed66f8089a5f6ad183bceae7d6b57381ca2a	\\x7d287fc3d2ebc657282b1394	\\x164373fb128520330627382c759700f4	f	2026-10-28 20:04:32.804616+07	storage/de_thi/f38e906b-72da-455e-9b1a-64e06961c1c5.enc	2026-10-29 14:19:17.268843+07	51c35c7f-0e7c-4880-8925-2f06926f89b0	t
5cbdf2c8-547e-4043-9ca4-ea8f64047ea0	2	Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)	1	12	DE_MOI	t	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/5cbdf2c8-547e-4043-9ca4-ea8f64047ea0.enc	De_ChinhThuc_Toan12_CK1_Mat.pdf	0c4d85e301cda4f37137aeacb0339230779c00d07a97db973f82e74a3d3b1546	\\xecb0c04fb2d26f1d448a49a7aa69fd28f6a3b21c9b1cd909f88698885ad21997	\\xa93b1f68471279948460d1255141553689af985d9b44455fc89aab2cd69c4e9dbdccef1930f71214f1537bb60693ab3bf38f39699b0f496864075e9c	\\x9d09091ba67e2cb3ae139cbc	\\x18587dcdb5912f541921ab105d871d4b	f	2026-10-28 17:08:17.294522+07	storage/de_thi/5cbdf2c8-547e-4043-9ca4-ea8f64047ea0.enc	\N	\N	f
eae52fe6-956a-4036-8829-5e380c0cf074	3	Đề thi chính thức Giữa kỳ I - Ngữ văn 10	2	10	CHINH_THUC	t	9bb3575c-1403-4c77-843e-51763a46af39	storage/de_thi/eae52fe6-956a-4036-8829-5e380c0cf074.enc	De_ChinhThuc_Van10_GK1.pdf	2ebfd9167fd90632dc52a4462e94e4232b19eeafeecbc1d09d0d38247e6c8a64	\\x743278d8143f4aa32d653e6ae066df07e7c6c06aae3d1e7abc5c27f723042931	\\xee7901e35d2942854a27a3ac9dece0c72751839a791ab0b3191d0f92017f466d6b0c4d9bcf4c856ab502cd85b370f1e468fdf6037c31f357e4c62d89	\\xce2e0455d78d031a5deab986	\\x94a6e420a1e3a628cd8abaca5b2d0ce5	f	2026-10-28 17:08:17.294522+07	storage/de_thi/eae52fe6-956a-4036-8829-5e380c0cf074.enc	\N	\N	f
a12ffd7d-002a-44ee-b516-637f998a47c4	4	Đề thi chính thức Giữa kỳ I - Tiếng Anh 11	3	11	CHINH_THUC	t	7b59f9b7-0c55-44d9-b951-ef82e47a235e	storage/de_thi/a12ffd7d-002a-44ee-b516-637f998a47c4.enc	De_ChinhThuc_Anh11_GK1.pdf	e00a57d2068a88e0b6b72ed0a10c24cc3d93d0e795653121d51f7857e4bfda52	\\x9f67300315f7ae0c10357cd1f56df36f190e029ffad93996a743c72c2da74ee7	\\x2fd11d8a0d2d7c9da06df7410b7ff6aa2626fcd52d7ecc1769d0e2e8ca911d94414e01f31afbed5959448c57dc1ef04b9fa15ed85a4f89ff0b3c0513	\\x0ffd33c2ab286653df4bddf0	\\x379d6c80868306a904d815abaf53884a	f	2026-10-28 17:08:17.294522+07	storage/de_thi/a12ffd7d-002a-44ee-b516-637f998a47c4.enc	\N	\N	f
d8dfa534-dad4-4f8a-ba11-790a59d50695	5	Đề thi chính thức Giữa kỳ I - Vật lý 12	5	12	CHINH_THUC	t	674289a6-2f98-4142-b90f-436c9e5ab1b4	storage/de_thi/d8dfa534-dad4-4f8a-ba11-790a59d50695.enc	De_ChinhThuc_Ly12_GK1.pdf	04d17a6c344641512c3fa8b7c0f95d97e639093b594a5346c4e22215aea8fa1f	\\xfe9d055e74c7e71be361b73a9b256a37b7ac2614baffa613669628a8c9501ba0	\\x18ea3cfd414e9dfd12e28829ce65c570a4d50eba1041cca661f53ca7f6e9207882a500eb6617bafcda8083a4d74cf32166062c65f5fdf348d720fc9e	\\x6ee52d98adb0d977ba6a4917	\\xc3177c2c2cf7ab27e0ea1aec54b738cb	f	2026-10-28 17:08:17.294522+07	storage/de_thi/d8dfa534-dad4-4f8a-ba11-790a59d50695.enc	\N	\N	f
8fbb91c5-4a57-44e1-9341-e91e68ed9e50	1	Đề kiểm tra giữa kỳ I - Toán 10	1	10	CHINH_THUC	t	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/8fbb91c5-4a57-44e1-9341-e91e68ed9e50.enc	de_kiem_tra_giua_ky_1_toan_10.pdf	551be77c1ef29b972b3a27692f7c16fcabed691425cdcbe48bb242805a8df59c	\\xb5fe93c1410894c1c99f3331bc112ec4ff5aa6b37a7a3d2084557761a37f0448	\\x4e5003bc66e8bd1bc4fa72a44e13c1645b2c737b6363c5c44f19deb77688a902072d0c3ea641af83063b2447c2a306db96821ac8ea3a5f40cc6e4d93	\\xa5df7ae0d151359783ed701a	\\x1394b8ced0e5464626948b2ed269d20d	f	2026-10-28 17:08:17.294522+07	storage/de_thi/8fbb91c5-4a57-44e1-9341-e91e68ed9e50.enc	\N	\N	f
868c8b4d-dfa0-4ddf-b418-00bcd3355e77	7	Đề kiểm tra giữa kỳ I - Toán 10	1	10	CHINH_THUC	t	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	storage/de_thi/868c8b4d-dfa0-4ddf-b418-00bcd3355e77.enc	de_kiem_tra_giua_ky_1_toan_10.pdf	ea0cbe4aa662a460040d4064b31a9b5dbeff5ba0c5330f291fc546c25b748145	\\x1ba4748f87ad25b94435549740bb99eb7b0a9960eb4034b64f6390f232323e98	\\xd4ad4de37dd1c659b86ba3269c86572fcf66ad5d29ec7a7eab2b31810e66c46cc5800a42d6381fe7f9a3d4a4d067b225461d85f5e65877cbcc217706	\\xcec1e20b97c39f0e514689b6	\\x9fa5955113f8cf1070dbdd97caa4d9b1	f	2026-10-28 20:02:48.41356+07	storage/de_thi/868c8b4d-dfa0-4ddf-b418-00bcd3355e77.enc	\N	\N	f
eb288303-2bfc-4f1f-878c-4dea2a90541d	14	Đề kiểm tra giữa kỳ I - Ngữ văn 10	2	10	CHINH_THUC	t	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	storage/de_thi/eb288303-2bfc-4f1f-878c-4dea2a90541d.enc	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx	03b9092b99e9eb2d18c00f7d6a9ba9230c5db3b713653350829f382cb2b26bd8	\\xcbed9ca6ce174a0bcfb0f5d47b3e25fe75177878bcc04b90f775aba9735dfa1d	\\x7d9d450af37315a93722715ea263738cb0b872ce7e47eab526ea63fcff2b05910316b1da1958e54026a82ac3cbd86ebcc03cf529cf9d822bfd68e482	\\xff4afd65a94031924c5ca94a	\\xecc501042bad05680a93b2dcfe623b01	f	2026-10-30 14:29:39.767165+07	storage/de_thi/eb288303-2bfc-4f1f-878c-4dea2a90541d.enc	2026-10-30 14:30:16.722913+07	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	t
\.


--
-- TOC entry 5088 (class 0 OID 224918)
-- Dependencies: 222
-- Data for Name: khoilop; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.khoilop (ma_khoi, ten_khoi) FROM stdin;
10	Khối 10
11	Khối 11
12	Khối 12
\.


--
-- TOC entry 5095 (class 0 OID 225001)
-- Dependencies: 229
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
-- TOC entry 5090 (class 0 OID 224924)
-- Dependencies: 224
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
-- TOC entry 5087 (class 0 OID 183773)
-- Dependencies: 221
-- Data for Name: nhatkylog; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.nhatkylog (ma_nhat_ky, ma_bam_truoc, ma_tai_khoan, hanh_dong, ip_thiet_bi, ipv4, ket_qua, chi_tiet, thoi_diem, ma_bam_nhat_ky, thong_tin_thiet_bi, tai_lieu_thao_tac) FROM stdin;
162	8f02c929f442bebb36f1567f82698cb735389759360bfbbcf190cabefa6d7c0f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:05:44.046033+07	84eaeec281806be5898315df286eca7ab6d1b180dc880aa8d6dac4404cbdd3aa	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
164	4be4be7496df26f710085074df76dbee893807a7e01791919a8652db03c15f29	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu kích hoạt 2FA	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-30 14:05:56.270966+07	53dd7d66113e9bb876ea86e6a4b78daf9aacf088c1bc2ac442b2eb8514b1c134	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
135	9f593e8970c27a41b3e2c1d39899a4de74bed25f64dc43771b65fc3985ab48d8	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:30.52098+07	52b659ac22d1e80a25c6256a40291a6f40f1310e0e676f0d2dbb19709bc4ff2f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
139	707b20ef739785de7753a361a6ef023f53c3a5e27f6c180ffdc39b30969b6fdb	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 10:08:56.675545+07	0394afb98e76bec2032ff8d6457b7e2f394c191f77f4c09bd552b9b363398a98	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
142	75888fc8a6b5767972300f62441d8218ee7e2236428608d61b224ed0e0931d89	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:33:14.133771+07	4f04f2a8b9cea757cde06d90c24ac3958174b5394b5e84a4bc1421f44e201555	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
145	b6b69511304fbaea5ffbbb4a6c0aa124b7e8fe6d9c4db532f5849d0e3c36fcfd	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:43:04.293318+07	db77ce48ded753b45749ede6338a15eb5bcec950ced0359c9585b9d33efe6769	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
148	8fbcae4bb7d06590eb20e3533132df28b8dc74d2cf36f23eebfe5cf9c333da61	48190309-eeb6-4395-a18f-1f902d580c97	Tạm khóa tài khoản	192.168.1.4	192.168.1.4	Thành công	Quản trị viên AD1568920 đã tạm khóa tài khoản GV1000458 (Nguyễn Văn Minh) trong 60 phút (đến 14:56:06 30/10/2026) và thu hồi toàn bộ phiên làm việc - Lý do: Khóa điều tra từ nhật ký #110	2026-10-30 13:56:07.017565+07	e36bfc4f38163844803983a0e29b63d1b68ceb7069bda83a2368a07cbc8e6fc9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
151	e39e49e28beefd286ad6f475bd408ef733a0b5001337b1dc69854916cf3cba0f	48190309-eeb6-4395-a18f-1f902d580c97	Chặn địa chỉ IP	192.168.1.4	192.168.1.4	Thành công	Quản trị viên AD1568920 đã chặn địa chỉ IP 192.168.1.4 (Chặn từ điều tra nhật ký #145). Đã thu hồi 7 phiên hoạt động.	2026-10-30 13:59:16.452442+07	58a3ee88cb0855c809c9e19c6d56ec1f621a030e874fc64724b993668b9ca22d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
154	77a316f23c504e502cd2bef5478a14fdda06e17de95e911a9ea3da4b2fff4c53	48190309-eeb6-4395-a18f-1f902d580c97	Mở khóa tài khoản	192.168.1.4	192.168.1.4	Thành công	Quản trị viên AD1568920 đã mở khóa an ninh tài khoản GV1000458 (Nguyễn Văn Minh)	2026-10-30 14:03:29.799904+07	574d739c8e9100af367a4c04273f948ed33cad87ddaa9dbf722beb87975733e9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
157	c5f0e1363f9baad70b842c5525f7d28258fc41af8965472d906a913ab4bd1165	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Từ chối đăng nhập từ địa chỉ IP đang bị chặn (192.168.1.4)	2026-10-30 14:04:07.447212+07	ae64e7303bc6990dd84a278d02475b2e9f504a80a51c875ae515a0047d16da4d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
160	70732310a1290afe22df8806d4f9fb9f9fd2986b421da0924e4c15d1fd4693a9	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:04:40.606797+07	9083d82a91c991cbbcde8cd8151eb10f9f456de1ecfd106566c0aa91fc5eaaed	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
166	53ae043735196ee66e390faf2824e1c363410bd69f26a8050d050bf2e62e34e4	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	192.168.1.4	Cảnh báo	Nhập sai mã OTP lần 2	2026-10-30 14:07:37.28505+07	eb4611026e69c2ad55c63ff3663bc7e8d3ff7d93e32d465ca4baf0bb0d11f1bc	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
168	38cca892e263bb04d8c861429f9d4b886ed9d0253680806824ace9b16e643aea	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:10:00.041984+07	4f4dc5078c07beff2ea518fa67113a0848a9e3a8cbcc93ca604d0c3990e3ccc1	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
170	c08612c767ca6b216ab245a87a0344a13525c00ba15a5a841e0c114eaf6e6aed	48190309-eeb6-4395-a18f-1f902d580c97	Đặt lại 2FA và Cấp lại mật khẩu	192.168.1.4	192.168.1.4	Thành công	Admin AD1568920 thực hiện Đặt lại 2FA và Cấp lại mật khẩu tạm cho giáo viên GV1000458 (gv.minh@thpthoangvanthu.edu.vn). Đã thu hồi toàn bộ phiên làm việc cũ	2026-10-30 14:14:05.7697+07	dfdd1970ed71cc3bbdca796904fba6e3297f24ff5d55c1c1a6bf5c98568aaba5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
171	dfdd1970ed71cc3bbdca796904fba6e3297f24ff5d55c1c1a6bf5c98568aaba5	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu kích hoạt 2FA	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-30 14:14:34.867188+07	33bd0701a5a2ed54c251158e705c2dd521958650423a7321fd47272bcd0a564a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
172	33bd0701a5a2ed54c251158e705c2dd521958650423a7321fd47272bcd0a564a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-30 14:17:47.609629+07	fc3d4cdcafda594754eb69ebb009da37d37987991762a185e4817b1d08aa3328	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
173	fc3d4cdcafda594754eb69ebb009da37d37987991762a185e4817b1d08aa3328	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:17:59.377184+07	0d8724acef9f03ef9fb8ecefa9936cf9993206cb14a319618363a08b5caa3b9a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
174	0d8724acef9f03ef9fb8ecefa9936cf9993206cb14a319618363a08b5caa3b9a	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:18:02.976726+07	e556e16b08f52d549af554ff9998381158dac037fdb9c09992c197306f2f73a0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
132	828a768faade4d5076581f50921b681658b0e76e4c38d89bbbd29d6b9fd173c3	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 10:07:51.090845+07	07e2db1fe834eb3725df89a2c0e21e7781c24ed44b95d25071c8e113820c87ed	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130	
136	52b659ac22d1e80a25c6256a40291a6f40f1310e0e676f0d2dbb19709bc4ff2f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:31.96925+07	f2ef8894d85db9fe5b186471a9a87f765f2be3ff936196e45200398278317588	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
140	0394afb98e76bec2032ff8d6457b7e2f394c191f77f4c09bd552b9b363398a98	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-30 10:09:14.694098+07	e2c753b4057373b05d727940028ddb33d487230afc3cf02cc0853548bd1fc60e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
143	4f04f2a8b9cea757cde06d90c24ac3958174b5394b5e84a4bc1421f44e201555	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:33:42.581108+07	a12cf1f7186724c17f14c9db2051c5988013664657d0630267d363fb60b5a186	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
146	db77ce48ded753b45749ede6338a15eb5bcec950ced0359c9585b9d33efe6769	\N	Đăng nhập	192.168.1.4	192.168.1.4	Cảnh báo	Phát hiện tài khoản lạ đăng nhập vào hệ thống	2026-10-30 13:44:09.536323+07	a89097cfce6205ea7a5fa4849bae177021380c9168c9a55a365ec15a0015ac00	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
149	e36bfc4f38163844803983a0e29b63d1b68ceb7069bda83a2368a07cbc8e6fc9	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Từ chối đăng nhập: Tài khoản đang trong thời gian bị khóa hoặc đã bị vô hiệu hóa	2026-10-30 13:56:27.86625+07	15200b90f9e4d9b37b67d1d694d0b897d6d3d64aa218fd78eb606cb6ed57718b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
152	58a3ee88cb0855c809c9e19c6d56ec1f621a030e874fc64724b993668b9ca22d	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Từ chối đăng nhập từ địa chỉ IP đang bị chặn (192.168.1.4)	2026-10-30 13:59:30.928062+07	8f549863215153482832d0b801feeedf5689b28ac8424939a94b6fae883c53a0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
155	574d739c8e9100af367a4c04273f948ed33cad87ddaa9dbf722beb87975733e9	48190309-eeb6-4395-a18f-1f902d580c97	Đặt lại 2FA và Cấp lại mật khẩu	192.168.1.4	192.168.1.4	Thành công	Admin AD1568920 thực hiện Đặt lại 2FA và Cấp lại mật khẩu tạm cho giáo viên GV1000458 (gv.minh@thpthoangvanthu.edu.vn). Đã thu hồi toàn bộ phiên làm việc cũ	2026-10-30 14:03:35.734812+07	ca10ff6be5f00de458143439fa49d7e94909d4a878722413d19ae3ae723a4217	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
158	ae64e7303bc6990dd84a278d02475b2e9f504a80a51c875ae515a0047d16da4d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Từ chối đăng nhập từ địa chỉ IP đang bị chặn (192.168.1.4)	2026-10-30 14:04:11.886834+07	81b94789896fde79c4a9adc1e873ff3412bf158fd8990ac585fd67032152d350	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
1	0000000000000000000000000000000000000000000000000000000000000000	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:09:29.657015+07	e28559f59314bb8762f605c9cd302b5575e9507ad7e50d456a36c2f7fe7ef49a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
2	e28559f59314bb8762f605c9cd302b5575e9507ad7e50d456a36c2f7fe7ef49a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:09:30.340882+07	89635f9b28971c2589893eb97305ee9a1146d39cf6263d47439375f5403d06b5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
3	89635f9b28971c2589893eb97305ee9a1146d39cf6263d47439375f5403d06b5	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:10:15.379086+07	79a89d12207503487c7601ab7299741db82eb1837adcc49d5873496b506dc45e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
4	79a89d12207503487c7601ab7299741db82eb1837adcc49d5873496b506dc45e	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu xác thực bước 2 (OTP)	Phát hiện đăng nhập từ IP máy lạ hoặc IPv4 không thuộc THPT Hoàng Văn Thụ, yêu cầu nhập mã OTP trên điện thoại.	2026-10-23 14:10:25.579659+07	aad96e5466c44b880a8850c1f3e0caae4c7197aaba1ad4a17547106e79fb11a3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
5	aad96e5466c44b880a8850c1f3e0caae4c7197aaba1ad4a17547106e79fb11a3	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực mã OTP	192.168.1.4	192.168.1.4	Thất bại	Xác thực mã OTP thất bại: Mã 6 số không chính xác hoặc đã hết thời gian hiệu lực (lần 1)	2026-10-23 14:12:35.21943+07	f468892dd2c0e201bb52df7e3efd6e833ab67d3f8d1981dbe31aec9675b43b52	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
161	9083d82a91c991cbbcde8cd8151eb10f9f456de1ecfd106566c0aa91fc5eaaed	48190309-eeb6-4395-a18f-1f902d580c97	Gỡ chặn địa chỉ IP	192.168.1.4	192.168.1.4	Thành công	Quản trị viên AD1568920 đã gỡ chặn địa chỉ IP 192.168.1.4	2026-10-30 14:04:53.130556+07	8f02c929f442bebb36f1567f82698cb735389759360bfbbcf190cabefa6d7c0f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
163	84eaeec281806be5898315df286eca7ab6d1b180dc880aa8d6dac4404cbdd3aa	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-30 14:05:51.355184+07	4be4be7496df26f710085074df76dbee893807a7e01791919a8652db03c15f29	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
165	53dd7d66113e9bb876ea86e6a4b78daf9aacf088c1bc2ac442b2eb8514b1c134	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	192.168.1.4	Cảnh báo	Nhập sai mã OTP lần 1	2026-10-30 14:07:24.314326+07	53ae043735196ee66e390faf2824e1c363410bd69f26a8050d050bf2e62e34e4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
167	eb4611026e69c2ad55c63ff3663bc7e8d3ff7d93e32d465ca4baf0bb0d11f1bc	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-30 14:09:15.65904+07	38cca892e263bb04d8c861429f9d4b886ed9d0253680806824ace9b16e643aea	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
169	4f4dc5078c07beff2ea518fa67113a0848a9e3a8cbcc93ca604d0c3990e3ccc1	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:10:03.123508+07	c08612c767ca6b216ab245a87a0344a13525c00ba15a5a841e0c114eaf6e6aed	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
133	07e2db1fe834eb3725df89a2c0e21e7781c24ed44b95d25071c8e113820c87ed	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 10:08:07.744954+07	538145f86fb7def8872284ecaf1ee8b3ba21c7ba27bc6780bfc8a29b3256cd8f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
137	f2ef8894d85db9fe5b186471a9a87f765f2be3ff936196e45200398278317588	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:39.48171+07	466d64b77183f155409d8dddc2cfb194c2e3e63db5abca9eb9911708dd5c7b0b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
141	e2c753b4057373b05d727940028ddb33d487230afc3cf02cc0853548bd1fc60e	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 10:11:18.903079+07	75888fc8a6b5767972300f62441d8218ee7e2236428608d61b224ed0e0931d89	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
6	f468892dd2c0e201bb52df7e3efd6e833ab67d3f8d1981dbe31aec9675b43b52	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực mã OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-23 14:13:25.930716+07	57803d0d2d30669076ba429dc9e63c726f275220989ad2cad3c04d792f08bc0c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
7	57803d0d2d30669076ba429dc9e63c726f275220989ad2cad3c04d792f08bc0c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:13:43.295484+07	81f66c8b0817b267a481a0be5164f5e52e17827cbafc6f49d975a65899f32a0f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
8	81f66c8b0817b267a481a0be5164f5e52e17827cbafc6f49d975a65899f32a0f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:27:28.358271+07	7537a564e109276c0d96b590d8e9e53dc1a893016e5b5167b934e0fc4d1c4339	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
9	7537a564e109276c0d96b590d8e9e53dc1a893016e5b5167b934e0fc4d1c4339	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu xác thực bước 2 (OTP)	Phát hiện đăng nhập từ IP máy lạ hoặc IPv4 không thuộc THPT Hoàng Văn Thụ, yêu cầu nhập mã OTP trên điện thoại.	2026-10-23 14:28:45.841084+07	e48e0b3d0e827860d741913a180173ef649a71929552fdff963accd2235bb48d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
10	e48e0b3d0e827860d741913a180173ef649a71929552fdff963accd2235bb48d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực mã OTP	192.168.1.4	192.168.1.4	Thất bại	Xác thực mã OTP thất bại: Mã 6 số không chính xác hoặc đã hết thời gian hiệu lực (lần 1)	2026-10-23 14:29:29.019761+07	e7e2c5f41b8158b6f3f7e35a6aefe82de7fabe825c0cbdc13e5ce6ddfa6e8e4c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
11	e7e2c5f41b8158b6f3f7e35a6aefe82de7fabe825c0cbdc13e5ce6ddfa6e8e4c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực mã OTP	192.168.1.4	192.168.1.4	Thất bại	Xác thực mã OTP thất bại: Mã 6 số không chính xác hoặc đã hết thời gian hiệu lực (lần 2)	2026-10-23 14:29:44.918592+07	07ba2566a06fc9000851592a931e6e9424183ead87c8cab6e6d0c7a1c6ab5daa	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
12	07ba2566a06fc9000851592a931e6e9424183ead87c8cab6e6d0c7a1c6ab5daa	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xác thực mã OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-23 14:30:11.005355+07	000487e77d943812673190428d5e942243cd8413f1a44ed68714e037fe8d85b4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
15	000487e77d943812673190428d5e942243cd8413f1a44ed68714e037fe8d85b4	\N	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:19.03302+07	323df8119c5b864f4bb21a8ba8e3a1934a2b219710f4d06a10b01028b00b0f6f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
16	323df8119c5b864f4bb21a8ba8e3a1934a2b219710f4d06a10b01028b00b0f6f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:27.353517+07	912e9fbe6f0ef7c27eec51ba5eea2abebcb0f4f19f1067c39d869b553792cbd1	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
17	912e9fbe6f0ef7c27eec51ba5eea2abebcb0f4f19f1067c39d869b553792cbd1	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:28.055+07	9cd575e0089def5058c09ddd4dd4f7f3f0350819331a5954eaf4e00efdea891d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
18	9cd575e0089def5058c09ddd4dd4f7f3f0350819331a5954eaf4e00efdea891d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:35:28.75495+07	bb8a52947dde1a87612f0073ed7b159e3805b0565c3c996037261c0aa93109cd	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
144	a12cf1f7186724c17f14c9db2051c5988013664657d0630267d363fb60b5a186	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:34:59.438832+07	b6b69511304fbaea5ffbbb4a6c0aa124b7e8fe6d9c4db532f5849d0e3c36fcfd	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
147	a89097cfce6205ea7a5fa4849bae177021380c9168c9a55a365ec15a0015ac00	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:44:14.691538+07	8fbcae4bb7d06590eb20e3533132df28b8dc74d2cf36f23eebfe5cf9c333da61	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
150	15200b90f9e4d9b37b67d1d694d0b897d6d3d64aa218fd78eb606cb6ed57718b	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:56:46.120408+07	e39e49e28beefd286ad6f475bd408ef733a0b5001337b1dc69854916cf3cba0f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
153	8f549863215153482832d0b801feeedf5689b28ac8424939a94b6fae883c53a0	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 13:59:48.562666+07	77a316f23c504e502cd2bef5478a14fdda06e17de95e911a9ea3da4b2fff4c53	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
156	ca10ff6be5f00de458143439fa49d7e94909d4a878722413d19ae3ae723a4217	48190309-eeb6-4395-a18f-1f902d580c97	Cấp lại mật khẩu	192.168.1.4	192.168.1.4	Thành công	Admin AD1568920 cấp lại mật khẩu tạm cho giáo viên GV1000458 (gv.minh@thpthoangvanthu.edu.vn). Đã thu hồi toàn bộ phiên làm việc cũ	2026-10-30 14:03:52.226399+07	c5f0e1363f9baad70b842c5525f7d28258fc41af8965472d906a913ab4bd1165	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
19	bb8a52947dde1a87612f0073ed7b159e3805b0565c3c996037261c0aa93109cd	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:36:06.655007+07	89389ffef5712ac451ee6b4c2a52bee2b7a682712754bf0fc2a960332ceb7486	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
20	89389ffef5712ac451ee6b4c2a52bee2b7a682712754bf0fc2a960332ceb7486	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu xác thực bước 2 (OTP)	Phát hiện đăng nhập từ IP máy lạ hoặc IPv4 không thuộc THPT Hoàng Văn Thụ, yêu cầu nhập mã OTP trên điện thoại.	2026-10-23 14:36:22.127365+07	d3e0271a6d406365d40799c473da62b480f4ca581e598469f9a5946411700e1d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
21	d3e0271a6d406365d40799c473da62b480f4ca581e598469f9a5946411700e1d	9ea71a69-8aee-4305-a2aa-65b193245bc1	Xác thực mã OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-23 14:40:18.176494+07	c4aa7b7d3feb7fea01f3f2066da56f9c69c72b1f82fc4e6fbf099dc2248f6979	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
22	c4aa7b7d3feb7fea01f3f2066da56f9c69c72b1f82fc4e6fbf099dc2248f6979	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại do sai mật khẩu	2026-10-23 14:42:33.283773+07	7ddee2c65a6fab249647d002840c05640b7a162481fe51f31c6393730ee1005a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
23	7ddee2c65a6fab249647d002840c05640b7a162481fe51f31c6393730ee1005a	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:42:39.535198+07	bbc214e5ed49bddc14c6be0b804f71e1965081e17f0f1092586920277d5c16b2	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
25	bbc214e5ed49bddc14c6be0b804f71e1965081e17f0f1092586920277d5c16b2	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường THPT Hoàng Văn Thụ	2026-10-23 14:45:20.808342+07	6f3da4505b93ec1993dfd69ddac5697f686ec52858b374af30dcbc07a3ca153d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
27	6f3da4505b93ec1993dfd69ddac5697f686ec52858b374af30dcbc07a3ca153d	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-25 21:35:00.047605+07	819f094db4e10fef0adf5f4aebd6228beae088fbe211fb9a0a3b459975080e0a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
28	819f094db4e10fef0adf5f4aebd6228beae088fbe211fb9a0a3b459975080e0a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-25 21:51:08.063026+07	dd695568645199754bfb6e965d477016daaed10356b67176f7dcb9f057f54fb5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
61	dd695568645199754bfb6e965d477016daaed10356b67176f7dcb9f057f54fb5	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-26 14:17:25.028957+07	bb77aa3ce07635aadc150a04b3b25d7e50c15ac051f58597daf6ae58a36bfcb9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
62	bb77aa3ce07635aadc150a04b3b25d7e50c15ac051f58597daf6ae58a36bfcb9	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-26 14:17:36.820066+07	1acec67aa4b2c6063011d689236cb515267a5d03588cba0b146c069b6d7ad5b9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
63	1acec67aa4b2c6063011d689236cb515267a5d03588cba0b146c069b6d7ad5b9	48f58e38-e84c-44d7-84db-80d4985e7d84	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu kích hoạt 2FA	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-26 14:19:24.417391+07	61f1248b23af83af87ad8c8edcc31e9f117cbac16ce837290bd870e35624bfb3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
64	61f1248b23af83af87ad8c8edcc31e9f117cbac16ce837290bd870e35624bfb3	48f58e38-e84c-44d7-84db-80d4985e7d84	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-26 14:25:11.86578+07	9f63d4d997abda410ca5a75815e53c4eec06952224500176ac6a7d823bcf6277	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
65	9f63d4d997abda410ca5a75815e53c4eec06952224500176ac6a7d823bcf6277	51c35c7f-0e7c-4880-8925-2f06926f89b0	Thêm đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 tải lên đề ôn tập [De On Tap Test SHA256] (Khối 10 - Giữa kỳ I), SHA-256: 3480113c63cacba6...	2026-10-28 17:25:53.281929+07	d22f3e78925531c23b68654ac31d5e8b7a3b3ecaac99486c569598d905cfbc25	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test.pdf
66	d22f3e78925531c23b68654ac31d5e8b7a3b3ecaac99486c569598d905cfbc25	51c35c7f-0e7c-4880-8925-2f06926f89b0	Cập nhật đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 cập nhật đề ôn tập [De On Tap Test SHA256 v2] (Khối 10 - Giữa kỳ I), SHA-256 mới: 14c5e622333e826e...	2026-10-28 17:25:53.43259+07	c427b1396d0f133aae07adbacfd418eca7db6c8ecc3ffb707dfd641ad5279c94	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test_v2.pdf
67	c427b1396d0f133aae07adbacfd418eca7db6c8ecc3ffb707dfd641ad5279c94	51c35c7f-0e7c-4880-8925-2f06926f89b0	Tải đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 tải xuống đề ôn tập [De On Tap Test SHA256 v2]	2026-10-28 17:25:53.563724+07	a1545ee415709d7f41a458a95f9399842e90d0b451894a8649034f9e6096196c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test_v2.pdf
68	a1545ee415709d7f41a458a95f9399842e90d0b451894a8649034f9e6096196c	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xóa đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 đã xóa đề ôn tập [De On Tap Test SHA256 v2]	2026-10-28 17:25:53.640692+07	655edb76abd0af6f3d5b49b72867ced23f91aaf15f4e81ca0aab2ba01377e53a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	De_On_Tap_Toan_Test_v2.pdf
69	655edb76abd0af6f3d5b49b72867ced23f91aaf15f4e81ca0aab2ba01377e53a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 19:01:16.829756+07	0d858e18d029d26c2ac4631e983fbfda4282e2d8191b2ccab9280cacc58840ee	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
70	0d858e18d029d26c2ac4631e983fbfda4282e2d8191b2ccab9280cacc58840ee	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 19:01:22.801217+07	7a29d64f924f4de229a3ae2af45bc8ae7c85237ba9c541d926e1d749c212174c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
159	81b94789896fde79c4a9adc1e873ff3412bf158fd8990ac585fd67032152d350	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:04:32.565248+07	70732310a1290afe22df8806d4f9fb9f9fd2986b421da0924e4c15d1fd4693a9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
71	7a29d64f924f4de229a3ae2af45bc8ae7c85237ba9c541d926e1d749c212174c	9ea71a69-8aee-4305-a2aa-65b193245bc1	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 19:46:15.778019+07	6e525d9d74371696d9dd2d15408a8c8a7c10b0b6c340553854612a1c156c2ea2	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
72	6e525d9d74371696d9dd2d15408a8c8a7c10b0b6c340553854612a1c156c2ea2	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu xác thực bước 2 (OTP)	Đúng mật khẩu từ IP lạ ngoài trường, kích hoạt thử thách mã OTP 6 số	2026-10-28 20:00:24.105459+07	2ae15be2f2c0460624ce90be9cbffbf6e100ab044123966a0c1fbcab1d515d16	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
73	2ae15be2f2c0460624ce90be9cbffbf6e100ab044123966a0c1fbcab1d515d16	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:00:24.239721+07	7646a128e903288689c4ef2aacf8314835acdc5e1c849c21841c3db261da66e9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
74	7646a128e903288689c4ef2aacf8314835acdc5e1c849c21841c3db261da66e9	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:00:52.513874+07	8f204285f6fd96b6250f69b9f3b470ef47f4efc425054b574d5781c928c3c410	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
75	8f204285f6fd96b6250f69b9f3b470ef47f4efc425054b574d5781c928c3c410	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:00:52.727757+07	c212508ac39c251c1a9b8116714420089cd0ae2678118f6bb31c106dd839410e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
76	c212508ac39c251c1a9b8116714420089cd0ae2678118f6bb31c106dd839410e	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu xác thực bước 2 (OTP)	Đúng mật khẩu từ IP lạ ngoài trường, kích hoạt thử thách mã OTP 6 số	2026-10-28 20:00:53.638181+07	47ddb2bc414ae3df34fc134657371f268995ce994c653e878381a03b80d9711d	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
77	47ddb2bc414ae3df34fc134657371f268995ce994c653e878381a03b80d9711d	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:00:53.755447+07	ee562a563fb02d952e899d9bd40cf41840523df3411ae728ea2da883b5fd6ae7	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
78	ee562a563fb02d952e899d9bd40cf41840523df3411ae728ea2da883b5fd6ae7	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:01:09.308083+07	60b189afedb9bef252c42775ab59a41103543bb42eaf90b6f6512b84c9e9d2a8	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
79	60b189afedb9bef252c42775ab59a41103543bb42eaf90b6f6512b84c9e9d2a8	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:01:09.419694+07	b4c2adec194c0a4c30f4675ff4181cb094da2c81006540a873f5897724c9b406	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
80	b4c2adec194c0a4c30f4675ff4181cb094da2c81006540a873f5897724c9b406	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:01:10.565531+07	5214fb78df8cf055019a1f24380fc3caabf0eb53ec78fed7a530e9b380eac8fb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
81	5214fb78df8cf055019a1f24380fc3caabf0eb53ec78fed7a530e9b380eac8fb	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:01:10.788874+07	cbde180827df8e0c933373d909f36eac95cbedd536df8b3e69077d4ba54a00e0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
82	cbde180827df8e0c933373d909f36eac95cbedd536df8b3e69077d4ba54a00e0	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:02:46.540558+07	c8bb80c9b712f23782451fa755905191bdcfb529a3339d3768ad24dcdda925ad	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
83	c8bb80c9b712f23782451fa755905191bdcfb529a3339d3768ad24dcdda925ad	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:02:46.86515+07	30c80dbb1197e98d051a67a883f0b1ae7be1e8573f9fb3e3e9bfc2e4df8c68de	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
84	30c80dbb1197e98d051a67a883f0b1ae7be1e8573f9fb3e3e9bfc2e4df8c68de	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:02:47.951871+07	1078725566bd11e9f1ee02d3c2896f5cc82b1d2efc50bb367d7a2c0a27c7dee3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
85	1078725566bd11e9f1ee02d3c2896f5cc82b1d2efc50bb367d7a2c0a27c7dee3	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:02:48.166577+07	3b2294485cdfc37a3bc799126f0c9937014c168b501daaa71a3618b7a86e3d38	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
86	3b2294485cdfc37a3bc799126f0c9937014c168b501daaa71a3618b7a86e3d38	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Tạo lịch thi và đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1780839 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Bản kiểm thử)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:02:48.454132+07	ce60357c2a35e35c0c66f598e621fc5c1633ad22c8e602d653ec41e2b700afe5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf
87	ce60357c2a35e35c0c66f598e621fc5c1633ad22c8e602d653ec41e2b700afe5	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:04:30.733783+07	ea781d645926d6f0a40818e27e73d078eae0cbff85f3c5eeb3283d672d98e0bb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
88	ea781d645926d6f0a40818e27e73d078eae0cbff85f3c5eeb3283d672d98e0bb	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:04:30.952997+07	a4fecd57c3daa56905359ed8666e241e341c47a854ceec4f80f6255bf42daf8f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
89	a4fecd57c3daa56905359ed8666e241e341c47a854ceec4f80f6255bf42daf8f	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:04:32.131671+07	b29b7729a103f30893404e6981dd26911fe85c9eca696f89978baf1614b04fe8	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
90	b29b7729a103f30893404e6981dd26911fe85c9eca696f89978baf1614b04fe8	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:04:32.456738+07	728a6276acd06101abbcda544677c9abbfed46e0d26a7785a2a7e6266044e86b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
91	728a6276acd06101abbcda544677c9abbfed46e0d26a7785a2a7e6266044e86b	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Tạo lịch thi và đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1780839 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Bản kiểm thử)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:04:32.848742+07	083b725bda94902c281ccff1a2e3c79466a128d9ffddf5c808a65ba18fc15450	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf
92	083b725bda94902c281ccff1a2e3c79466a128d9ffddf5c808a65ba18fc15450	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:09:02.924618+07	b44fda85e58e021790ab3b34e7e478aeae34cadcf6f233d47d7dc26af08cb61b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
93	b44fda85e58e021790ab3b34e7e478aeae34cadcf6f233d47d7dc26af08cb61b	48190309-eeb6-4395-a18f-1f902d580c97	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:09:03.03664+07	14443a16bb0f24dd0ddc494b285961b52ae64f9cbe534f1eb828fa608caac1b0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
94	14443a16bb0f24dd0ddc494b285961b52ae64f9cbe534f1eb828fa608caac1b0	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 20:09:04.269762+07	9012da85e2ee7a2bad93ff1c3deba2d1d57f3203427fb8a893d4e655f8635841	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
95	9012da85e2ee7a2bad93ff1c3deba2d1d57f3203427fb8a893d4e655f8635841	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-28 20:09:04.492152+07	deff74d119ad901be10b17cc661913863e46a8650823368619013949e5131555	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
96	deff74d119ad901be10b17cc661913863e46a8650823368619013949e5131555	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Tạo lịch thi và đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1780839 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Bản kiểm thử)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:09:04.789318+07	9c92756ca2b217f0d4b9904a50fb0c61c175800ead4b628c4cba7267a3b33f11	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf
97	9c92756ca2b217f0d4b9904a50fb0c61c175800ead4b628c4cba7267a3b33f11	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Cập nhật đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1780839 cập nhật lịch thi [Kiểm tra giữa kỳ I (Đợt 2)] và đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Đã cập nhật)], SHA-256: ea0cbe4aa662a460...	2026-10-28 20:09:05.009493+07	51420159f8a643a69259707ef44ee3fdbcf5c542c82ed67aa593b6e5fd4947d1	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf
98	51420159f8a643a69259707ef44ee3fdbcf5c542c82ed67aa593b6e5fd4947d1	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Tải đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1780839 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Đã cập nhật)]	2026-10-28 20:09:05.63208+07	a999852fb9c9b5ee982f56e1bb2b70268bb0e8ab4bd38fda6aa75084a5060113	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf
99	a999852fb9c9b5ee982f56e1bb2b70268bb0e8ab4bd38fda6aa75084a5060113	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	Xóa đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1780839 đã xóa đề thi [Đề kiểm tra giữa kỳ I - Toán 10 (Đã cập nhật)]	2026-10-28 20:09:05.758245+07	2df4c2b36bd03e9cd60e529b32c16e50826ec41ed9dae2c9c5d53a8e91a9be7e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	de_kiem_tra_giua_ky_1_toan_10_test.pdf
100	2df4c2b36bd03e9cd60e529b32c16e50826ec41ed9dae2c9c5d53a8e91a9be7e	\N	Đăng nhập	192.168.1.4	192.168.1.4	Cảnh báo	Phát hiện tài khoản lạ đăng nhập vào hệ thống	2026-10-28 23:16:31.812315+07	2986d86b0eff492711d8b4d3e999db315642cce0b1b3ed3762dcc58f4919c5a0	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
101	2986d86b0eff492711d8b4d3e999db315642cce0b1b3ed3762dcc58f4919c5a0	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-28 23:17:14.442213+07	d8cc7e068de43d9228269b79a58f99148fb2e5c9eb43e82bc830b5f66413fc8c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
102	d8cc7e068de43d9228269b79a58f99148fb2e5c9eb43e82bc830b5f66413fc8c	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 2	2026-10-28 23:17:58.401761+07	08c5162d79e362d79b3cf684b5b1ad5607c5f87056058cb3522342c090e00bf3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
103	08c5162d79e362d79b3cf684b5b1ad5607c5f87056058cb3522342c090e00bf3	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 3	2026-10-28 23:18:46.68278+07	320f7650f2d69848d810280bd00d51eee93c1e3d34d1029ec31d7f2947a89c03	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
104	320f7650f2d69848d810280bd00d51eee93c1e3d34d1029ec31d7f2947a89c03	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 23:20:24.255806+07	90fb80c558213502761081c8e65576abbab5565d08da5eabe09f3a4e126c6486	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	
105	90fb80c558213502761081c8e65576abbab5565d08da5eabe09f3a4e126c6486	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 23:23:59.613558+07	e42d56d800898a4aa3bfc72cd9b10f3287b8a1a5287edd9f684b16a22c696645	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
106	e42d56d800898a4aa3bfc72cd9b10f3287b8a1a5287edd9f684b16a22c696645	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-28 23:43:30.021515+07	00e3acf1ef5efe3de7cb44d6a6a60e61b62a87593163158c2f06fd26ca23b7ae	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
107	00e3acf1ef5efe3de7cb44d6a6a60e61b62a87593163158c2f06fd26ca23b7ae	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-28 23:45:09.789977+07	34252f770a3462d352e391ab28a2cab1bcc73c58ff65a1d4f44ba9f398cf7875	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	
108	34252f770a3462d352e391ab28a2cab1bcc73c58ff65a1d4f44ba9f398cf7875	51c35c7f-0e7c-4880-8925-2f06926f89b0	Cảnh báo bẫy đề mồi	192.168.1.4	192.168.1.4	Cảnh báo	PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)] bởi GV1000458 (gv.minh) - Lần kích hoạt thứ 1!	2026-10-28 23:45:21.755076+07	3e8c86604b04ddf8791c515b6320c467f12d7f1d170dd8d1c450a0d649d16312	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	De_ChinhThuc_Toan12_CK1_Mat.pdf
109	3e8c86604b04ddf8791c515b6320c467f12d7f1d170dd8d1c450a0d649d16312	51c35c7f-0e7c-4880-8925-2f06926f89b0	Cảnh báo bẫy đề mồi	192.168.1.4	192.168.1.4	Cảnh báo	PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)] bởi GV1000458 (gv.minh) - Lần kích hoạt thứ 2!	2026-10-28 23:45:25.663067+07	f4e662b3e49a756bc4bd8cca58a0d417dc5f76a0713b15b8f45ceeaafe8c8018	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	De_ChinhThuc_Toan12_CK1_Mat.pdf
110	f4e662b3e49a756bc4bd8cca58a0d417dc5f76a0713b15b8f45ceeaafe8c8018	51c35c7f-0e7c-4880-8925-2f06926f89b0	Cảnh báo bẫy đề mồi	192.168.1.4	192.168.1.4	Cảnh báo	PHÁT HIỆN TRUY CẬP TỆP BẪY MỒI NHỬ [Đề thi chính thức Cuối kỳ I - Toán 12 (Đề mồi bảo vệ)] bởi GV1000458 (gv.minh) - Lần kích hoạt thứ 3!	2026-10-28 23:45:38.128565+07	f3b3ad8827d6265066543c0276e0c9af4ec96f9875501fd2ae2d279981b59009	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	De_ChinhThuc_Toan12_CK1_Mat.pdf
111	f3b3ad8827d6265066543c0276e0c9af4ec96f9875501fd2ae2d279981b59009	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-29 14:11:24.298534+07	98a52a14678626cb0b0740e61322a0421cf2ace5596c0a0ae56c69ce52ce8a01	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
112	98a52a14678626cb0b0740e61322a0421cf2ace5596c0a0ae56c69ce52ce8a01	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-29 14:11:28.851429+07	8838711500b750e3a8d0ca45f7c46d5c9d5a43594dbdd16f74c365444eb785d8	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
113	8838711500b750e3a8d0ca45f7c46d5c9d5a43594dbdd16f74c365444eb785d8	51c35c7f-0e7c-4880-8925-2f06926f89b0	Thêm đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 tải lên đề ôn tập [Ôn tập Toán giữa kỳ I 29/10/2026] (Khối 10 - Giữa kỳ I), SHA-256: 5ba3b76beae594c7...	2026-10-29 14:15:03.139008+07	01abae6397eebe1bc5ebfd06c872384ba60489db0a474ec2fbd47a760b8f4452	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB5_1150070048-NguyenDuyTruong.docx
114	01abae6397eebe1bc5ebfd06c872384ba60489db0a474ec2fbd47a760b8f4452	51c35c7f-0e7c-4880-8925-2f06926f89b0	Tải đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 tải xuống đề ôn tập [Ôn tập Toán giữa kỳ I 29/10/2026]	2026-10-29 14:15:57.387552+07	136e20276ad83ecdadc6d39c69842b05e26c04b34af917808263a402eb2ea478	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB5_1150070048-NguyenDuyTruong.docx
115	136e20276ad83ecdadc6d39c69842b05e26c04b34af917808263a402eb2ea478	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xóa đề ôn tập	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 đã xóa đề ôn tập [Ôn tập Toán giữa kỳ I 29/10/2026]	2026-10-29 14:16:08.30498+07	9ca8a045b3e07a9e9c56c3a53f92f879d46bc3f4ce9c900ca1aad1628847a562	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB5_1150070048-NguyenDuyTruong.docx
116	9ca8a045b3e07a9e9c56c3a53f92f879d46bc3f4ce9c900ca1aad1628847a562	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-29 14:17:31.870921+07	61a5f1f1e95b9a23c98cd3d4ea61a991c43d8256923000c01004b5c5916a4c68	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
117	61a5f1f1e95b9a23c98cd3d4ea61a991c43d8256923000c01004b5c5916a4c68	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-29 14:17:32.143661+07	0b8382b9e6f23ff40c2e3685b12fa355258a727d185c4cf6b1ffcce587c63e98	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
118	0b8382b9e6f23ff40c2e3685b12fa355258a727d185c4cf6b1ffcce587c63e98	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-29 14:17:35.01809+07	bb88a7096da90b7781b05939b9f4dfceb0015a56f805d3abc4d0346cb3819551	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
119	bb88a7096da90b7781b05939b9f4dfceb0015a56f805d3abc4d0346cb3819551	51c35c7f-0e7c-4880-8925-2f06926f89b0	Cập nhật đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 cập nhật lịch thi [Kiểm tra giữa kỳ I] và đề thi [Đề kiểm tra giữa kỳ I - Toán 10], SHA-256: ea0cbe4aa662a460...	2026-10-29 14:19:17.423458+07	aeac6f7c756604f953b11fe965c2b78847d6414cd535e2488dd767c168c52ae5	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
120	aeac6f7c756604f953b11fe965c2b78847d6414cd535e2488dd767c168c52ae5	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-29 14:20:35.667936+07	8c6af7cd69c7ada2ef84248f67356d50f34e031779aeaecd0d31ad6596d364a3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
121	8c6af7cd69c7ada2ef84248f67356d50f34e031779aeaecd0d31ad6596d364a3	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-29 14:20:46.989959+07	bd67ea9791f10b5d8c86bc5ca70ca72d0a0f27a5bcd5d81dd9dee38eef241a7e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
125	bd67ea9791f10b5d8c86bc5ca70ca72d0a0f27a5bcd5d81dd9dee38eef241a7e	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 09:11:23.683143+07	828a768faade4d5076581f50921b681658b0e76e4c38d89bbbd29d6b9fd173c3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130	
134	538145f86fb7def8872284ecaf1ee8b3ba21c7ba27bc6780bfc8a29b3256cd8f	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:30.168821+07	9f593e8970c27a41b3e2c1d39899a4de74bed25f64dc43771b65fc3985ab48d8	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
138	466d64b77183f155409d8dddc2cfb194c2e3e63db5abca9eb9911708dd5c7b0b	51c35c7f-0e7c-4880-8925-2f06926f89b0	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1000458 truy cập đề thi [Đề kiểm tra giữa kỳ I - Toán 10]	2026-10-30 10:08:39.824351+07	707b20ef739785de7753a361a6ef023f53c3a5e27f6c180ffdc39b30969b6fdb	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	de_kiem_tra_giua_ky_1_toan_10.pdf
175	e556e16b08f52d549af554ff9998381158dac037fdb9c09992c197306f2f73a0	48190309-eeb6-4395-a18f-1f902d580c97	Tạo tài khoản	192.168.1.4	192.168.1.4	Thành công	Admin tạo tài khoản mới: Mã CB [GV1269482], Tên đăng nhập [gv.quyen], Vai trò [GiaoVien], Email [gv.quyen@thpthoangvanthu.edu.vn], Phân quyền [Ngữ văn - Khối 10, Khối 11, Khối 12 (Đề chung + Đề chính thức)]	2026-10-30 14:23:45.305411+07	139b932554eade5c884a02d90d65e3163557b9dfcaaaa893056060f9813efa08	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
176	139b932554eade5c884a02d90d65e3163557b9dfcaaaa893056060f9813efa08	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Đăng nhập	192.168.1.4	192.168.1.4	Yêu cầu kích hoạt 2FA	Đăng nhập lần đầu: Chuyển hướng yêu cầu quét mã QR Authenticator và đổi mật khẩu	2026-10-30 14:25:15.760526+07	a3a6d211c278f8cb4b2883da002035ee0b94dd60ec722448df556fe7c7bc89d7	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
177	a3a6d211c278f8cb4b2883da002035ee0b94dd60ec722448df556fe7c7bc89d7	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Xác thực OTP	192.168.1.4	192.168.1.4	Thành công	Xác thực mã OTP 6 số thành công, cấp quyền truy cập phiên làm việc mới.	2026-10-30 14:28:35.235546+07	6dc07af3a6776a55abebcbe6db2b4b45aff59aa43aa3fe4fe9df53b7eb15a23f	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
178	6dc07af3a6776a55abebcbe6db2b4b45aff59aa43aa3fe4fe9df53b7eb15a23f	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1269482 truy cập đề thi [Đề thi chính thức Giữa kỳ I - Ngữ văn 10]	2026-10-30 14:29:11.741341+07	d9a58db280d395a785f9c08f52dc05c7d7c5eefa87ef05404b00007ace96062e	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	De_ChinhThuc_Van10_GK1.pdf
179	d9a58db280d395a785f9c08f52dc05c7d7c5eefa87ef05404b00007ace96062e	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Xem đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1269482 truy cập đề thi [Đề thi chính thức Giữa kỳ I - Ngữ văn 10]	2026-10-30 14:29:12.114822+07	bbadc01af690914ee59e3a9c60c0f13380eecb74caac601b38da9ab316364507	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	De_ChinhThuc_Van10_GK1.pdf
180	bbadc01af690914ee59e3a9c60c0f13380eecb74caac601b38da9ab316364507	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Tạo lịch thi và đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1269482 tạo lịch thi [Kiểm tra giữa kỳ I] (Giữa kỳ I - Khối 10) và đề thi [Đề kiểm tra giữa kỳ I - Ngữ văn 10], SHA-256: 03b9092b99e9eb2d...	2026-10-30 14:29:39.815306+07	7e811b03acf710a38fbfc6935daeb1286beb72e3a0fc575b63cef66b6c42ca80	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx
181	7e811b03acf710a38fbfc6935daeb1286beb72e3a0fc575b63cef66b6c42ca80	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	Cập nhật đề thi	192.168.1.4	192.168.1.4	Thành công	Giáo viên GV1269482 cập nhật lịch thi [Kiểm tra giữa kỳ II] và đề thi [Đề kiểm tra giữa kỳ I - Ngữ văn 10], SHA-256: 03b9092b99e9eb2d...	2026-10-30 14:30:16.905437+07	563ee14f05f06dc1fc8af0785478af515abeae263ff48383b04276655899ca9c	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	11_TMĐT-LAB8_1150070048-NguyenDuyTruong.docx
182	563ee14f05f06dc1fc8af0785478af515abeae263ff48383b04276655899ca9c	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:31:00.234009+07	4557cd0766113a20e84ff9c4f893b7802f19010dd01b2b02802891ba459d1f4b	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
183	4557cd0766113a20e84ff9c4f893b7802f19010dd01b2b02802891ba459d1f4b	48190309-eeb6-4395-a18f-1f902d580c97	Đăng nhập	192.168.1.7	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:31:04.111999+07	b067f014a671526b12ea7a252d6c098d701a3ea3a19ff6834ec0f4ed5f98af2a	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
184	b067f014a671526b12ea7a252d6c098d701a3ea3a19ff6834ec0f4ed5f98af2a	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thất bại	Đăng nhập thất bại: Sai mật khẩu lần thứ 1	2026-10-30 14:43:15.892153+07	48ee09525fd4dde86cc6190c073a80ddc7d89ba8ed22ff5baf161743574562d3	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
185	48ee09525fd4dde86cc6190c073a80ddc7d89ba8ed22ff5baf161743574562d3	51c35c7f-0e7c-4880-8925-2f06926f89b0	Đăng nhập	192.168.1.4	192.168.1.4	Thành công	Đăng nhập thành công từ mạng nội bộ trường (IP tin cậy), cấp phiên làm việc	2026-10-30 14:43:21.901011+07	0edbe230f686520a2102d4a3aab5694f04933741f5440a95681d32bd7822daf9	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	
\.


--
-- TOC entry 5092 (class 0 OID 224936)
-- Dependencies: 226
-- Data for Name: phanquyentheokhoimon; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.phanquyentheokhoimon (ma_phan_quyen, ma_tai_khoan, ma_khoi, ma_mon_hoc, duoc_truy_cap_de_chung, duoc_truy_cap_de_chinh_thuc, nguoi_cap_quyen, thoi_diem_cap_quyen) FROM stdin;
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
20	7b59f9b7-0c55-44d9-b951-ef82e47a235e	11	3	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
21	7b59f9b7-0c55-44d9-b951-ef82e47a235e	12	3	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
22	674289a6-2f98-4142-b90f-436c9e5ab1b4	10	5	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
23	674289a6-2f98-4142-b90f-436c9e5ab1b4	11	5	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
24	674289a6-2f98-4142-b90f-436c9e5ab1b4	12	5	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
25	bc398092-6172-4a0b-8095-dc4f9d33c177	10	5	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-28 17:08:17.294522+07
28	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	10	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 14:23:45.165762+07
29	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	11	2	t	f	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 14:23:45.165762+07
30	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	12	2	t	t	48190309-eeb6-4395-a18f-1f902d580c97	2026-10-30 14:23:45.165762+07
\.


--
-- TOC entry 5085 (class 0 OID 183752)
-- Dependencies: 219
-- Data for Name: phiendangnhap; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.phiendangnhap (ma_phien, ma_tai_khoan, ma_phien_bam, ip_thiet_bi, ipv4, thong_tin_thiet_bi, da_xac_thuc_otp, da_thu_hoi, thoi_diem_het_han, thoi_diem_tao) FROM stdin;
790428bb-e8cc-41c6-bf07-1c0030b9f254	48f58e38-e84c-44d7-84db-80d4985e7d84	a85a290755bc335ba4f218710cc0e142795096574719fe957fa9beeae10ee962	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 22:19:24.05206+07	2026-10-26 14:19:24.05206+07
3adb8fe8-b95a-4dba-b413-16eb54d30d9f	9ea71a69-8aee-4305-a2aa-65b193245bc1	a8616d01e004cb0b1cf18afec44439854347357f5e1a29abd36219bd4bdcb623	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:36:21.878755+07	2026-10-23 14:36:21.876215+07
50decb38-86e0-4e40-a72f-3a16d2f99ed1	9ea71a69-8aee-4305-a2aa-65b193245bc1	90cb0d2bc0e12c02f43ed9c693f5e96e4c63cf7468fe8bfef7211306ae3d3c81	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:42:39.175715+07	2026-10-23 14:42:39.173501+07
1abb92b3-b58a-43df-ad14-40dce4d0e506	51c35c7f-0e7c-4880-8925-2f06926f89b0	04eb93f260348d3f88dc72e56fa9a94b730c54799bcdb88e918ccb28ba7808bb	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 05:51:07.651561+07	2026-10-25 21:51:07.651561+07
e2d9e6fa-a070-4d7f-aa73-a034710a0b2f	9ea71a69-8aee-4305-a2aa-65b193245bc1	941d444543aa42e71947c77ba697ad5801b8d5884f5a10d8de41356765ad5b0f	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:45:20.551876+07	2026-10-23 14:45:20.549471+07
4b10e45d-a62c-40fc-8711-de72d17fa900	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	b6d84dc71f9bf90757b6f2e63ee511470b767e611387792facdbd5a11aabb28c	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:00:53.390408+07	2026-10-28 20:00:53.390408+07
fd422412-26da-413b-8f05-600c514a3eb1	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	d9dbf72c07312d0aa8caeca0cdcc15f27a335d33bd3f16a97cd399e6c2d459df	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:01:10.320863+07	2026-10-28 20:01:10.320863+07
aad25764-195c-493c-883b-1315f672357f	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	64350a293fbba3dae33c4f8cb3d8ab4700c720f40b97ec77e1834785cecb6ab7	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:02:47.683673+07	2026-10-28 20:02:47.683673+07
e3d71f18-3f9a-4cee-b181-96533a11a931	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	feb68326837138293bf1b0b83996dada4a6c43897ae2c6b8dc8a35788eede9a0	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:04:31.759411+07	2026-10-28 20:04:31.759411+07
4d94965d-4592-48c2-9259-24637096d2a9	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	83ba0a10453b7f6348680914fd43cfe4dd714e9ab6947872cc4325639ac3fcba	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	t	2026-10-29 04:09:03.881139+07	2026-10-28 20:09:03.881139+07
c8d245aa-367e-47af-8383-09cf0e3735ac	48190309-eeb6-4395-a18f-1f902d580c97	a9ef5f9095148a8681c2bc0f9da7f517e7b112bdad73f51eb78859d6c8f70d68	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:00:23.806228+07	2026-10-28 20:00:23.806228+07
d94493c5-15c3-4d40-a104-6377e85bbac9	48190309-eeb6-4395-a18f-1f902d580c97	697d0d676f5e1d70e483c826e4c7e5307c609ec403a0eb4d89f2de096c5116a2	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:00:52.264917+07	2026-10-28 20:00:52.264917+07
6778742d-0f36-4486-a0c5-f3bcef76a189	48190309-eeb6-4395-a18f-1f902d580c97	d3da0a5be9fb8399f108021e5fe75be34254db80b3e9e20e031f8c18e14cfab8	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:01:09.059867+07	2026-10-28 20:01:09.059867+07
8334aab1-4be9-487a-99d6-50075bf02cc2	48190309-eeb6-4395-a18f-1f902d580c97	943c50ff7218055c668b6e300d33b6ed14b0b070fc6b0f147b60c02d4bff50dd	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:02:46.284757+07	2026-10-28 20:02:46.284757+07
1544afeb-2d38-4ec7-9420-aef087e6ec28	48190309-eeb6-4395-a18f-1f902d580c97	8c09ced05b2512bb080eb6ff4350b14f4908d3adef57ac2c849059deee89f79c	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:04:30.477688+07	2026-10-28 20:04:30.477688+07
1e288975-194b-4d58-a322-5a37f5f92d1e	48190309-eeb6-4395-a18f-1f902d580c97	6b70fc5c3e562447da7bd012a13554d8784b36322bcdbba0fe242c118bf0ff1b	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 04:09:02.677404+07	2026-10-28 20:09:02.677404+07
bf877629-bca0-4608-b71b-5c9482b01f4a	9ea71a69-8aee-4305-a2aa-65b193245bc1	532a3629d665c4fb21e585c2c4c4d73123937146b7f1d3daa924724372f73aef	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 03:46:15.536668+07	2026-10-28 19:46:15.536668+07
6e30eb39-7f7e-44be-a060-9a73751571e9	48190309-eeb6-4395-a18f-1f902d580c97	a991eb1f73b04862eef9bbfa2fdfbbbeb0d41fa2b26e32756c2efb2c602afb87	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - python-httpx/0.28.1	t	f	2026-10-29 07:20:23.988178+07	2026-10-28 23:20:23.988178+07
28288268-73ea-4ccb-8bb2-8b0d5f818330	48190309-eeb6-4395-a18f-1f902d580c97	d4d4a7599f34bf78e76cf43f9197f8e26c37006a64c50db6b3cdae2bb137728d	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 07:23:59.361159+07	2026-10-28 23:23:59.361159+07
acbdaaf6-bb5f-4040-a220-d558ceec0bda	48190309-eeb6-4395-a18f-1f902d580c97	8eb54ae4e01fc074a2c2c609aaaef54f1c11597f178ba80a1f86a0ee31ed0ee3	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	f	2026-10-29 22:20:46.631176+07	2026-10-29 14:20:46.631176+07
52f99d55-bc18-45ee-8583-bf380c135f54	48190309-eeb6-4395-a18f-1f902d580c97	f1058d6bb1719a3b3e93d505b4c25a110d63748b9f8f834c76a54496c485cb0c	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:44:14.322147+07	2026-10-30 13:44:14.322147+07
f387a297-e119-43f6-8f8a-d7498b3ee8a0	51c35c7f-0e7c-4880-8925-2f06926f89b0	5db6cf5ec3122e639dbe1a2adf9d0879e917e4b835d8b088d81e1e1f36657d97	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 22:17:36.466216+07	2026-10-26 14:17:36.466216+07
66daead1-31dd-497a-ac25-64de7c2bb828	51c35c7f-0e7c-4880-8925-2f06926f89b0	a5d3ed75a57c7985396e9c17a2d5240394efb79d7c3f60f669151ca86dc2a14a	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 03:01:16.48035+07	2026-10-28 19:01:16.48035+07
891fff23-51c4-408a-a0af-0aa1a9b30ee3	51c35c7f-0e7c-4880-8925-2f06926f89b0	e426eeafcd6bc42fe99b00a910f3cd44a3d881b45d125940b79da51f54db7885	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 03:01:22.455142+07	2026-10-28 19:01:22.455142+07
0339dd15-7c6e-4e51-b538-651e024cb59f	51c35c7f-0e7c-4880-8925-2f06926f89b0	180f315503a423e8caf2a0560276790a73071e96bb473dcd6d71bae2c5cdf588	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:10:25.2833+07	2026-10-23 14:10:25.278996+07
d588dcb0-45a8-4882-8c48-11f136c201c5	51c35c7f-0e7c-4880-8925-2f06926f89b0	be8f9fb5ea99137e27f94168082ab916810ef6901b91f2ba4d751c0d6bd36a5e	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:13:43.052317+07	2026-10-23 14:13:43.049187+07
164266ac-92f7-493e-873c-42bbe58060b8	51c35c7f-0e7c-4880-8925-2f06926f89b0	68c590a6eece937d0db0e502f5acf4189223628689eedd0cb16e382cc876c885	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:27:27.911147+07	2026-10-23 14:27:27.907281+07
99b239b2-3e18-409c-a823-2bdbd4ce64e5	51c35c7f-0e7c-4880-8925-2f06926f89b0	1b97384c126c043ab830a732136a9e945dae6cc0c0d8406fc0350cde55ceb3e4	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:28:45.607132+07	2026-10-23 14:28:45.604959+07
565f71ac-aa0e-4ed8-9b51-54481f5a12bb	51c35c7f-0e7c-4880-8925-2f06926f89b0	5fc4311f163deb6ccafe66750e795ee8200a5a11320d8d155f816b98ff9c8802	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-23 16:36:06.375733+07	2026-10-23 14:36:06.373136+07
cf1a65f7-84a8-4a8d-a7fa-acaf00165aaf	51c35c7f-0e7c-4880-8925-2f06926f89b0	6d65f2c674a91a3dec8d9fced47b1870a372dc058300c6e6d9d2e4afab868114	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-26 05:34:59.802005+07	2026-10-25 21:34:59.802005+07
1fc403af-3525-4dc5-9eda-3560dcf0a419	51c35c7f-0e7c-4880-8925-2f06926f89b0	56d177bbf81e6e78bc48d8105577628b264e7270bac6103716054de176b7e797	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.60 (Chromium 156)	t	t	2026-10-29 07:45:09.533419+07	2026-10-28 23:45:09.533419+07
10c1c7a1-4a33-4af9-aaac-ff418269adf2	51c35c7f-0e7c-4880-8925-2f06926f89b0	eb503bd63f8e4e66bb166513e295399f992efd3732b8ba785c81b56420aae074	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-29 22:11:28.582834+07	2026-10-29 14:11:28.582834+07
ff21ac4a-f418-4929-afbb-0dfdfd1adfb2	51c35c7f-0e7c-4880-8925-2f06926f89b0	25fecb790280907c1e6fdf38b1367e2b49952145d8abe64aa82b5ce9016799ee	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130	t	t	2026-10-30 17:11:23.332267+07	2026-10-30 09:11:23.332267+07
c1870123-4b41-47cb-9ae4-4d5b407fbe69	48190309-eeb6-4395-a18f-1f902d580c97	425f155757259f1651371543d15f51628795dc77626df5935f2cfcb3260e97c5	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 18:11:18.66184+07	2026-10-30 10:11:18.66184+07
05b34a1e-07d0-43d3-b21b-de38d369e66f	9ea71a69-8aee-4305-a2aa-65b193245bc1	774de74cf1a8e43d17e77bcce82ee7428e202e4d53282996da94bf6af77db816	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:33:42.339087+07	2026-10-30 13:33:42.339087+07
b26cd5f9-4e8a-4f40-bcd6-a0229549dd96	2cf83bec-ba4b-4648-9c11-4144d9aa6eab	43f216b9991d4f211d03fe57967845b233a02289481cc08a04ae68a57a5d0235	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:34:59.191699+07	2026-10-30 13:34:59.191699+07
00ec1cdb-07db-4248-8762-e7857d485738	9ea71a69-8aee-4305-a2aa-65b193245bc1	a12cd0265b68d2945a18870d6f58d757ccdb420187d0b4cbdd6033a7ecc5224d	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:43:04.028499+07	2026-10-30 13:43:04.028499+07
9fdbb999-654f-456b-a8bb-aa75995514c7	48190309-eeb6-4395-a18f-1f902d580c97	d428432e0fd9a092a82cb06d8fd9e117a71828790b673849fd24678cd920202d	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:56:45.841106+07	2026-10-30 13:56:45.841106+07
570bfbca-3594-4eed-bcaf-d9cba1942cdd	48190309-eeb6-4395-a18f-1f902d580c97	bc53f5d45ff54c6634d2aac4cf43edd723aee20f470783218fe63d655513f768	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:18:02.695904+07	2026-10-30 14:18:02.695904+07
4b8e49f1-0689-465c-80fd-a65ab22ab21a	de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	e077da497e0987a1249a40e8401a5f6aa299701b93c53cf1d86f068323353477	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:25:15.401396+07	2026-10-30 14:25:15.401396+07
954ee27f-665c-46e2-95d0-68c9482ee7cb	48190309-eeb6-4395-a18f-1f902d580c97	9c62ee00a7bfe993bfce6dab7fdf55c616214ea93e3bc228398383dbce360bd0	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:59:48.286302+07	2026-10-30 13:59:48.286302+07
6baa35f6-b011-43ab-80ad-9a2b87284c7e	48190309-eeb6-4395-a18f-1f902d580c97	ba818bdaf8a94c07f389520032eb1548803c00db3ec0c7b0adcb9d167367cdcc	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:04:40.328253+07	2026-10-30 14:04:40.328253+07
565e5822-708e-4af8-9a3a-9d5969761451	48190309-eeb6-4395-a18f-1f902d580c97	097285b59945b11adb148ab4d7d7b9c422a372ace73d29b4e13f351c0449898e	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:31:03.799257+07	2026-10-30 14:31:03.799257+07
28e96b41-9ae6-47b2-9e0c-0e4e36c578c0	51c35c7f-0e7c-4880-8925-2f06926f89b0	f29c1a0bb2a91ade1dcc2b8593857dfb073763a5924c1217f7e2f02f6a3cf8ed	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	f	2026-10-30 22:43:21.625141+07	2026-10-30 14:43:21.625141+07
de7b45c1-0c82-442c-b448-90c6b8ffbbf8	51c35c7f-0e7c-4880-8925-2f06926f89b0	ab4f9ebb5c14d25f031a038cfa2fd492ba8742716803c8a0b463b82d13030246	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Google Chrome 152.0.7977.130	t	t	2026-10-30 18:07:50.813619+07	2026-10-30 10:07:50.813619+07
67a1d7b2-9659-411c-ad6a-e8ef8a09eab1	51c35c7f-0e7c-4880-8925-2f06926f89b0	852f7c7db69119f4b9d7b5007205831fc097de41cdbc902e4b2f96bc60389ffd	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 18:08:07.511644+07	2026-10-30 10:08:07.511644+07
e3db6827-3260-434f-a703-5c75987def91	51c35c7f-0e7c-4880-8925-2f06926f89b0	9ce198b95cf3a6af3641c02ca4df746eed94934792928036f75d084e471d78df	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 21:33:13.876368+07	2026-10-30 13:33:13.876368+07
e2dabfdf-064a-4c1e-a901-947cf1873080	51c35c7f-0e7c-4880-8925-2f06926f89b0	5491a1bd3737a202869b34408167b165d6ac00fe1750e7ae24de7b6c7be3f7f4	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:05:56.009471+07	2026-10-30 14:05:56.009471+07
6d0e80a1-7f46-47d6-9914-6b267e4c4359	48190309-eeb6-4395-a18f-1f902d580c97	554201f4b8bbb44815055d4db77ba84619bafded0b976be444b79c28299ecc48	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:10:02.707197+07	2026-10-30 14:10:02.707197+07
24ab8784-7c7f-47b2-96b1-954eec46fd8d	51c35c7f-0e7c-4880-8925-2f06926f89b0	fef1b7ff451ee8489ab8a6b43aa2b8f9a476cf998ab578f52153623377ef6509	192.168.1.4	192.168.1.4	Windows 11 (26H2, Build 26300) [DESKTOP-7476BNE] - Brave Browser 1.98.62 (Chromium 156)	t	t	2026-10-30 22:14:34.54162+07	2026-10-30 14:14:34.54162+07
\.


--
-- TOC entry 5084 (class 0 OID 183729)
-- Dependencies: 218
-- Data for Name: taikhoan; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.taikhoan (ma_tai_khoan, ma_can_bo, ten_dang_nhap, mat_khau, ho_ten, email, vai_tro, bi_mat_otp_ma_hoa, da_kich_hoat_otp, bi_khoa, so_lan_dang_nhap_sai, so_lan_sai_otp, ip_thiet_bi_gan_nhat, ipv4_gan_nhat, thoi_diem_tao, dang_hoat_dong, khoa_den_thoi_diem) FROM stdin;
2cf83bec-ba4b-4648-9c11-4144d9aa6eab	GV1780839	gv.mai	$2b$12$r7ZZ.zQyFkR2rziSjYPvcecxQu3D/koX03e3Tf1f1YOxg7GeLQfke	Nguyễn Thị Mai	gv.mai@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x2b7824ce244ca53e806876f2ef3da6b1ed6f15e7d1dcb67cd58440bfaaae008a3ca8d242cabc1dcfa47fefe739201857b3b824ef0b75bca9530c03e7	t	f	0	0	192.168.1.4	192.168.1.4	2026-10-23 14:09:03.698911+07	t	\N
48190309-eeb6-4395-a18f-1f902d580c97	AD1568920	admin.phuc	$2b$12$h.TJSMjvPKK929TGXp.xXujh9umxQqSgqxIvHRllu3yqnsiqY8IZu	Trần Văn Phúc	admin.phuc@thpthoangvanthu.edu.vn	QUAN_TRI	\\xe8a7861e198c727eeb615f20bdd222376f0e5b725674c44998fd076ebc69144770c7395005b044c177ab3ceab8dde9d4e5fcf814648af582d2878375	t	f	0	0	192.168.1.4	192.168.1.4	2026-10-23 14:09:03.698911+07	t	\N
9bb3575c-1403-4c77-843e-51763a46af39	GV1456278	gv.nam	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Lê Hoàng Nam	gv.nam@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x665a8b8877ddbb32012fc9f7037b1f79d76b6d4f8792ffbb4ba8cc3742239d8f4da4e10a5a4af228bb8ae4e72b8ec3397b973fc45593a41c2e14c200	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N
674289a6-2f98-4142-b90f-436c9e5ab1b4	GV6790839	gv.huy	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Võ Quốc Huy	gv.huy@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xceac45d8fbed28a7997a9847af217aec94200179b8f33848b9311ce74a954a983acc7b8851667256e82950a0c96d84c78384dd2475f6d735c5b64173	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N
ffc74f6b-2064-4b2a-8b6a-0f5c3eb0b571	GV7869077	gv.hoa	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Phạm Thị Hoa	gv.hoa@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xf5c73635dfa9164aba87c7a6cb7407d6a11e78c2df2ae03e1e2cdd73f8a549fca241dc9b7e87af6aa51be4d988567ee28d7ae8d79fbb13fe1a9c0754	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N
48f58e38-e84c-44d7-84db-80d4985e7d84	GV1428003	gv.tuan	$2b$12$r7ZZ.zQyFkR2rziSjYPvcecxQu3D/koX03e3Tf1f1YOxg7GeLQfke	Đặng Minh Tuấn	gv.tuan@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x58fe3a86a4faedc624498e4461b5c85c4985b9096b303d6a0cf5fc868423e64ccd1b9fc0fdddc1c78c8fceb62691dbca1f87d6cd944a773bd7dbed47	t	f	0	0	192.168.1.4	192.168.1.4	2026-10-23 14:09:03.698911+07	t	\N
7b59f9b7-0c55-44d9-b951-ef82e47a235e	GV7802740	gv.ngoc	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Bùi Thị Ngọc	gv.ngoc@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x22fc99112217a57258929ee602b99145c28e62b66974217d0c56ee2dbf2ff123b20df1e3510c9252821e1a38727531461f3048310ea34a26d784147c	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N
bc398092-6172-4a0b-8095-dc4f9d33c177	GV1562839	gv.anh	$2b$12$VgCnDKmCYTemsMHL3i5ZlOp4arB.BY9K4XrpEgyuFYxNJpkG4LOOm	Hoàng Đức Anh	gv.anh@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x03dda1cf20edd6e6c00858ef78e1cd50cb27706f2e7560e206a966c46cd910e8b712172080d5e76491ef1f2ff8e4df36636d0621d5d92d0812063edb	f	f	0	0	\N	\N	2026-10-23 14:09:03.698911+07	t	\N
9ea71a69-8aee-4305-a2aa-65b193245bc1	GV1324570	gv.lan	$2b$12$r7ZZ.zQyFkR2rziSjYPvcecxQu3D/koX03e3Tf1f1YOxg7GeLQfke	Trần Thị Lan	gv.lan@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xf5ca4b583f54573a5c43d10e7eefa2e3e6ec9120e56e190229e94e41b70db0915bd236f62c3555fd8bd6d62b27899c11471d9ffd991b74e8d1c20b1b	t	f	0	0	192.168.1.4	192.168.1.4	2026-10-23 14:09:03.698911+07	t	\N
de4bc6a5-f511-4680-b8b6-f3cbc578b3e3	GV1269482	gv.quyen	$2b$12$oElWA6HWwa09fQUiPvzbu.2mOPaXKafjKuR2/ax0u3obD3bcnBpbK	Trần Mỹ Quyên	gv.quyen@thpthoangvanthu.edu.vn	GIAO_VIEN	\\x4dada2c811c490518461f0501cd63785cabf25089166b1be3e5892d56986b42f7028fa7c0f5989f681f8efea	t	f	0	0	192.168.1.4	192.168.1.4	2026-10-30 14:23:45.165762+07	t	\N
51c35c7f-0e7c-4880-8925-2f06926f89b0	GV1000458	gv.minh	$2b$12$cgi1xKKDzBNe0DwxMyotxOag5AFgAaztg.LCa11Y1OlES1SqEfKRq	Nguyễn Văn Minh	gv.minh@thpthoangvanthu.edu.vn	GIAO_VIEN	\\xb891d2f1c30f84db00b255fe0946b5ef7b93a9d7965e61b5b4c591d5ce2a17005f530e09c3f35179cd424ca0	t	f	0	0	192.168.1.4	192.168.1.4	2026-10-23 14:09:03.698911+07	t	\N
\.


--
-- TOC entry 5098 (class 0 OID 225058)
-- Dependencies: 232
-- Data for Name: tepbay; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.tepbay (ma_bay, ma_de_thi, ten_tep_bay, duong_dan_kich_hoat, so_lan_kich_hoat, thoi_diem_kich_hoat_gan_nhat, dang_hoat_dong) FROM stdin;
1	5cbdf2c8-547e-4043-9ca4-ea8f64047ea0	De_ChinhThuc_Toan12_CK1_Mat.pdf	/api/de-thi/5cbdf2c8-547e-4043-9ca4-ea8f64047ea0/download	3	2026-10-28 23:45:38.084465+07	t
\.


--
-- TOC entry 5126 (class 0 OID 0)
-- Dependencies: 233
-- Name: chandiachiip_ma_chan_ip_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.chandiachiip_ma_chan_ip_seq', 3, true);


--
-- TOC entry 5127 (class 0 OID 0)
-- Dependencies: 228
-- Name: lichthi_ma_lich_thi_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.lichthi_ma_lich_thi_seq', 14, true);


--
-- TOC entry 5128 (class 0 OID 0)
-- Dependencies: 223
-- Name: monhoc_ma_mon_hoc_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.monhoc_ma_mon_hoc_seq', 8, true);


--
-- TOC entry 5129 (class 0 OID 0)
-- Dependencies: 220
-- Name: nhatkylog_ma_nhat_ky_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.nhatkylog_ma_nhat_ky_seq', 185, true);


--
-- TOC entry 5130 (class 0 OID 0)
-- Dependencies: 225
-- Name: phanquyentheokhoimon_ma_phan_quyen_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.phanquyentheokhoimon_ma_phan_quyen_seq', 30, true);


--
-- TOC entry 5131 (class 0 OID 0)
-- Dependencies: 231
-- Name: tepbay_ma_bay_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.tepbay_ma_bay_seq', 1, true);


--
-- TOC entry 4915 (class 2606 OID 241331)
-- Name: chandiachiip chandiachiip_dia_chi_ip_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip
    ADD CONSTRAINT chandiachiip_dia_chi_ip_key UNIQUE (dia_chi_ip);


--
-- TOC entry 4917 (class 2606 OID 241329)
-- Name: chandiachiip chandiachiip_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip
    ADD CONSTRAINT chandiachiip_pkey PRIMARY KEY (ma_chan_ip);


--
-- TOC entry 4903 (class 2606 OID 224978)
-- Name: deontap deontap_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_pkey PRIMARY KEY (ma_de_on_tap);


--
-- TOC entry 4908 (class 2606 OID 225035)
-- Name: dethi dethi_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_pkey PRIMARY KEY (ma_de_thi);


--
-- TOC entry 4891 (class 2606 OID 224922)
-- Name: khoilop khoilop_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.khoilop
    ADD CONSTRAINT khoilop_pkey PRIMARY KEY (ma_khoi);


--
-- TOC entry 4906 (class 2606 OID 225008)
-- Name: lichthi lichthi_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_pkey PRIMARY KEY (ma_lich_thi);


--
-- TOC entry 4893 (class 2606 OID 224932)
-- Name: monhoc monhoc_ky_hieu_mon_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc
    ADD CONSTRAINT monhoc_ky_hieu_mon_key UNIQUE (ky_hieu_mon);


--
-- TOC entry 4895 (class 2606 OID 224930)
-- Name: monhoc monhoc_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc
    ADD CONSTRAINT monhoc_pkey PRIMARY KEY (ma_mon_hoc);


--
-- TOC entry 4897 (class 2606 OID 224934)
-- Name: monhoc monhoc_ten_mon_hoc_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.monhoc
    ADD CONSTRAINT monhoc_ten_mon_hoc_key UNIQUE (ten_mon_hoc);


--
-- TOC entry 4889 (class 2606 OID 183783)
-- Name: nhatkylog nhatkylog_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nhatkylog
    ADD CONSTRAINT nhatkylog_pkey PRIMARY KEY (ma_nhat_ky);


--
-- TOC entry 4899 (class 2606 OID 224944)
-- Name: phanquyentheokhoimon phanquyentheokhoimon_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_pkey PRIMARY KEY (ma_phan_quyen);


--
-- TOC entry 4883 (class 2606 OID 183764)
-- Name: phiendangnhap phiendangnhap_ma_phien_bam_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phiendangnhap
    ADD CONSTRAINT phiendangnhap_ma_phien_bam_key UNIQUE (ma_phien_bam);


--
-- TOC entry 4885 (class 2606 OID 183762)
-- Name: phiendangnhap phiendangnhap_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phiendangnhap
    ADD CONSTRAINT phiendangnhap_pkey PRIMARY KEY (ma_phien);


--
-- TOC entry 4873 (class 2606 OID 183751)
-- Name: taikhoan taikhoan_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_email_key UNIQUE (email);


--
-- TOC entry 4875 (class 2606 OID 183747)
-- Name: taikhoan taikhoan_ma_can_bo_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_ma_can_bo_key UNIQUE (ma_can_bo);


--
-- TOC entry 4877 (class 2606 OID 183745)
-- Name: taikhoan taikhoan_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_pkey PRIMARY KEY (ma_tai_khoan);


--
-- TOC entry 4879 (class 2606 OID 183749)
-- Name: taikhoan taikhoan_ten_dang_nhap_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.taikhoan
    ADD CONSTRAINT taikhoan_ten_dang_nhap_key UNIQUE (ten_dang_nhap);


--
-- TOC entry 4911 (class 2606 OID 225070)
-- Name: tepbay tepbay_duong_dan_kich_hoat_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay
    ADD CONSTRAINT tepbay_duong_dan_kich_hoat_key UNIQUE (duong_dan_kich_hoat);


--
-- TOC entry 4913 (class 2606 OID 225068)
-- Name: tepbay tepbay_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay
    ADD CONSTRAINT tepbay_pkey PRIMARY KEY (ma_bay);


--
-- TOC entry 4901 (class 2606 OID 224946)
-- Name: phanquyentheokhoimon uq_phan_quyen_tk_khoi_mon; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT uq_phan_quyen_tk_khoi_mon UNIQUE (ma_tai_khoan, ma_khoi, ma_mon_hoc);


--
-- TOC entry 4904 (class 1259 OID 224999)
-- Name: idx_deontap_mon_khoi; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_deontap_mon_khoi ON public.deontap USING btree (ma_mon_hoc, ma_khoi);


--
-- TOC entry 4909 (class 1259 OID 225056)
-- Name: idx_dethi_mon_khoi; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_dethi_mon_khoi ON public.dethi USING btree (ma_mon_hoc, ma_khoi);


--
-- TOC entry 4886 (class 1259 OID 183790)
-- Name: idx_nhatkylog_ma_tai_khoan; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_nhatkylog_ma_tai_khoan ON public.nhatkylog USING btree (ma_tai_khoan);


--
-- TOC entry 4887 (class 1259 OID 183789)
-- Name: idx_nhatkylog_thoi_diem; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_nhatkylog_thoi_diem ON public.nhatkylog USING btree (thoi_diem DESC);


--
-- TOC entry 4880 (class 1259 OID 183771)
-- Name: idx_phiendangnhap_ma_phien_bam; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phiendangnhap_ma_phien_bam ON public.phiendangnhap USING btree (ma_phien_bam);


--
-- TOC entry 4881 (class 1259 OID 183770)
-- Name: idx_phiendangnhap_ma_tai_khoan; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phiendangnhap_ma_tai_khoan ON public.phiendangnhap USING btree (ma_tai_khoan);


--
-- TOC entry 4938 (class 2620 OID 241341)
-- Name: nhatkylog trg_nhat_ky_log_noi_chuoi; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_nhat_ky_log_noi_chuoi BEFORE INSERT ON public.nhatkylog FOR EACH ROW EXECUTE FUNCTION public.fn_nhat_ky_log_noi_chuoi();


--
-- TOC entry 4937 (class 2606 OID 241332)
-- Name: chandiachiip chandiachiip_nguoi_chan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chandiachiip
    ADD CONSTRAINT chandiachiip_nguoi_chan_fkey FOREIGN KEY (nguoi_chan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- TOC entry 4924 (class 2606 OID 224984)
-- Name: deontap deontap_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- TOC entry 4925 (class 2606 OID 224979)
-- Name: deontap deontap_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- TOC entry 4926 (class 2606 OID 224994)
-- Name: deontap deontap_nguoi_cap_nhat_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_nguoi_cap_nhat_fkey FOREIGN KEY (nguoi_cap_nhat) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4927 (class 2606 OID 224989)
-- Name: deontap deontap_nguoi_tao_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.deontap
    ADD CONSTRAINT deontap_nguoi_tao_fkey FOREIGN KEY (nguoi_tao) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4931 (class 2606 OID 225046)
-- Name: dethi dethi_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- TOC entry 4932 (class 2606 OID 225036)
-- Name: dethi dethi_ma_lich_thi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_ma_lich_thi_fkey FOREIGN KEY (ma_lich_thi) REFERENCES public.lichthi(ma_lich_thi) ON DELETE SET NULL;


--
-- TOC entry 4933 (class 2606 OID 225041)
-- Name: dethi dethi_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- TOC entry 4934 (class 2606 OID 225084)
-- Name: dethi dethi_nguoi_cap_nhat_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_nguoi_cap_nhat_fkey FOREIGN KEY (nguoi_cap_nhat) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4935 (class 2606 OID 225051)
-- Name: dethi dethi_nguoi_ra_de_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dethi
    ADD CONSTRAINT dethi_nguoi_ra_de_fkey FOREIGN KEY (nguoi_ra_de) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4928 (class 2606 OID 225009)
-- Name: lichthi lichthi_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- TOC entry 4929 (class 2606 OID 225014)
-- Name: lichthi lichthi_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- TOC entry 4930 (class 2606 OID 225019)
-- Name: lichthi lichthi_nguoi_tao_lich_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.lichthi
    ADD CONSTRAINT lichthi_nguoi_tao_lich_fkey FOREIGN KEY (nguoi_tao_lich) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4919 (class 2606 OID 183784)
-- Name: nhatkylog nhatkylog_ma_tai_khoan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nhatkylog
    ADD CONSTRAINT nhatkylog_ma_tai_khoan_fkey FOREIGN KEY (ma_tai_khoan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- TOC entry 4920 (class 2606 OID 224952)
-- Name: phanquyentheokhoimon phanquyentheokhoimon_ma_khoi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_ma_khoi_fkey FOREIGN KEY (ma_khoi) REFERENCES public.khoilop(ma_khoi) ON DELETE CASCADE;


--
-- TOC entry 4921 (class 2606 OID 224957)
-- Name: phanquyentheokhoimon phanquyentheokhoimon_ma_mon_hoc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_ma_mon_hoc_fkey FOREIGN KEY (ma_mon_hoc) REFERENCES public.monhoc(ma_mon_hoc) ON DELETE CASCADE;


--
-- TOC entry 4922 (class 2606 OID 224947)
-- Name: phanquyentheokhoimon phanquyentheokhoimon_ma_tai_khoan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_ma_tai_khoan_fkey FOREIGN KEY (ma_tai_khoan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4923 (class 2606 OID 224962)
-- Name: phanquyentheokhoimon phanquyentheokhoimon_nguoi_cap_quyen_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phanquyentheokhoimon
    ADD CONSTRAINT phanquyentheokhoimon_nguoi_cap_quyen_fkey FOREIGN KEY (nguoi_cap_quyen) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE SET NULL;


--
-- TOC entry 4918 (class 2606 OID 183765)
-- Name: phiendangnhap phiendangnhap_ma_tai_khoan_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phiendangnhap
    ADD CONSTRAINT phiendangnhap_ma_tai_khoan_fkey FOREIGN KEY (ma_tai_khoan) REFERENCES public.taikhoan(ma_tai_khoan) ON DELETE CASCADE;


--
-- TOC entry 4936 (class 2606 OID 225071)
-- Name: tepbay tepbay_ma_de_thi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tepbay
    ADD CONSTRAINT tepbay_ma_de_thi_fkey FOREIGN KEY (ma_de_thi) REFERENCES public.dethi(ma_de_thi) ON DELETE CASCADE;


-- Completed on 2026-10-30 14:50:54

--
-- PostgreSQL database dump complete
--

\unrestrict YDa6d57zdgVJdspUTaT1glD7dXGKhvZjhNwC306aIFX9TDdIFHh0ta4FIDKP0hw

