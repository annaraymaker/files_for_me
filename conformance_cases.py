#!/usr/bin/env python3
"""Spec-conformance test cases (IEC 61162-1 / NMEA 0183 sentence structure).

Each case is a dict:
    id        unique short id (stable - the SDR phase will reuse these ids)
    category  grouping for the rollup
    spec      what rule it probes (for the paper's clause column)
    transport "serial" (sensor port) or "aivdm" (reusable verbatim by the RF phase)
    expect    the CONFORMANT listener behavior, in plain words
    gen()     -> raw bytes to transmit (bytes, so we can emit non-ASCII / no-CRLF)

Design rules baked in from the spec answers:
  - terminator is exactly <CR><LF>           (bare CR / bare LF / LF-CR are violations)
  - checksum mandatory in ALL sentences      (missing checksum is a violation)
  - address field: digits + UPPERCASE only   (lowercase / specials are violations)
  - no universal per-field max; only 82-char whole-sentence max ...
  - ...but sentence-specific field limits: VER f4<=15 f5<=32; SMV name<=30 (LISTENER
    must accept and TRUNCATE to 30, not reject); SMB<=58; VDM/DO encap 60 (62 special)
  - AIVDM/AIVDO are 0183-defined: we inject them on SERIAL here and tag transport
    "aivdm" so the RF phase can replay the identical bytes -> serial-vs-RF comparison.

Conformant baseline for comparison: a valid GPRMC/GPGGA at the baseline position.
Most malformed cases SHOULD be silently rejected (output stays on last good fix);
"accepted" (output changes to reflect bad input) is the security-relevant violation.
"""
from nmea import checksum, sentence

CR = b"\r"
LF = b"\n"
CRLF = b"\r\n"

def _cksum_bytes(body_bytes):
    """XOR checksum over raw bytes of the body (between $/! and *), 2 hex upper."""
    c = 0
    for x in body_bytes:
        c ^= x
    return f"{c:02X}"


# The harness feeds a valid BASELINE position (42.35/-70.90) between cases.
# Every malformed sentence that CARRIES a position uses a DISTINCT "spoof"
# position (43.50N/071.50W -> 4330.0000,N / 07130.0000,W) so that:
#   - if the unit REJECTS it, output stays at the baseline (42.35/-70.90)
#   - if the unit ACCEPTS it, output jumps to the spoof position -> detectable
# This removes the blind spot where acceptance of a malformed-but-position-bearing
# sentence looked identical to rejection. The analyzer keys on which position
# appears in the output.
SPOOF_LAT_FIELD = "4330.0000"   # 43 deg 30.0 min N  = 43.5 N
SPOOF_LON_FIELD = "07130.0000"  # 071 deg 30.0 min W = 71.5 W
SPOOF_LATLON = (43.5, -71.5)

# a malformed-test base body at the SPOOF position (valid structure; cases mutate it)
_GOOD_BODY = f"GPRMC,120000.00,A,{SPOOF_LAT_FIELD},N,{SPOOF_LON_FIELD},W,0.0,90.0,180626,,,A"

# a genuinely valid body at the BASELINE position (for the control case only)
_BASELINE_BODY = "GPRMC,120000.00,A,4221.0000,N,07054.0000,W,0.0,90.0,180626,,,A"


def _ok(body):
    """complete, valid sentence bytes from a body (no $, no *cc)."""
    return (sentence(body) + "\r\n").encode()


def _raw(s):
    return s if isinstance(s, bytes) else s.encode()


def _ok_body_bytes(body_bytes, start=b"$"):
    """Build start + body + *cc + CRLF, with checksum computed over body_bytes.
    Lets the body contain control/reserved/non-ASCII chars while keeping the
    checksum VALID, so the ONLY anomaly is the feature under test (not the cks)."""
    return start + body_bytes + b"*" + _cksum_bytes(body_bytes).encode() + b"\r\n"


# ---- helpers to build specific sentence types at exact field lengths ----
def _ver(uid_len, data_len):
    # VER: $--VER,x,x,c--c(f4 uid<=15),c--c(f5 data<=32),...  (probe f4/f5 limits)
    body = f"GPVER,1,1,{'U'*uid_len},{'D'*data_len},1,1"
    return _ok(body)


def _smv_name(n):
    # SMV-style sentence carrying a vessel name field of length n (limit 30, truncate)
    body = f"GPSMV,1,1,{'X'*n}"
    return _ok(body)


def _aivdm(frag_total, frag_num, seq, channel, payload, fill):
    seq = "" if seq is None else str(seq)
    body = f"AIVDM,{frag_total},{frag_num},{seq},{channel},{payload},{fill}"
    return _ok(body)


# valid-ish single-fragment AIVDM type-1 payload (15 chars, 6-bit armored)
_AIVDM_PAYLOAD = "15M67FC000G?ufbE`FepT@2HFt"


CASES = []
def C(id, category, spec, transport, expect, gen, expect_accept=False):
    CASES.append({"id": id, "category": category, "spec": spec,
                  "transport": transport, "expect": expect, "gen": gen,
                  "expect_accept": expect_accept})


# ============================ CONTROL ============================
C("control_valid", "control", "valid sentence", "serial",
  "ACCEPT - unit keeps reporting a valid fix at BASELINE (proves rig works)",
  lambda: _ok(_BASELINE_BODY))

# ====================== SENTENCE STRUCTURE ======================
C("struct_no_start_delim", "structure", "61162-1:2024 7.3.1 ($/! start)", "serial",
  "REJECT - no leading $/!",
  lambda: (_GOOD_BODY + "*" + checksum(_GOOD_BODY) + "\r\n").encode())
C("struct_wrong_start_delim", "structure", "61162-1:2024 7.3.1 ($/! start)", "serial",
  "REJECT - '#' is not a valid start delimiter",
  lambda: ("#" + _GOOD_BODY + "*" + checksum(_GOOD_BODY) + "\r\n").encode())
C("struct_missing_terminator", "structure", "61162-1:2024 7.3.1 (<CR><LF> terminator)", "serial",
  "REJECT/await - no CRLF at all",
  lambda: _raw(sentence(_GOOD_BODY)))
C("struct_only_cr", "structure", "61162-1:2024 7.3.1 (<CR><LF> terminator)", "serial",
  "REJECT - bare CR, no LF",
  lambda: _raw(sentence(_GOOD_BODY)) + CR)
C("struct_only_lf", "structure", "61162-1:2024 7.3.1 (<CR><LF> terminator)", "serial",
  "REJECT - bare LF, no CR",
  lambda: _raw(sentence(_GOOD_BODY)) + LF)
C("struct_lf_cr_order", "structure", "61162-1:2024 7.3.1 (<CR><LF> order)", "serial",
  "REJECT - LF before CR",
  lambda: _raw(sentence(_GOOD_BODY)) + LF + CR)
C("struct_multi_start", "structure", "single start delimiter", "serial",
  "REJECT - two start delimiters",
  lambda: ("$$" + _GOOD_BODY + "*" + checksum(_GOOD_BODY) + "\r\n").encode())
C("struct_multi_end", "structure", "single checksum/terminator", "serial",
  "REJECT - doubled terminator",
  lambda: _raw(sentence(_GOOD_BODY)) + CRLF + CRLF)
C("struct_leading_garbage", "structure", "resync on start delimiter", "serial",
  "tolerate/resync - junk before $ then a valid sentence",
  lambda: b"GARBAGE\x01\x02" + _ok(_BASELINE_BODY))
C("struct_trailing_garbage", "structure", "checksum is last field", "serial",
  "REJECT - extra bytes after checksum before CRLF",
  lambda: (sentence(_GOOD_BODY) + "TRAILING").encode() + CRLF)
# Over-length cases must GENUINELY exceed 82 chars AND carry a DIFFERENT position
# (43.50/-71.50, not the 42.35/-70.90 baseline) so that if the unit accepts the
# over-length sentence its transmitted position visibly changes -> ACCEPTED,
# distinguishing acceptance from silent rejection. Padding goes in a trailing
# numeric field so the sentence stays otherwise well-formed.
def _overlen_rmc(total_chars):
    """A GPRMC at 43.50N/071.50W, padded to exactly `total_chars` incl $ and *cc
    but excluding CRLF, by extending a trailing field with digits."""
    head = "GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,,,A"
    # sentence() adds $...*hh = +1 (for $) +3 (for *hh); CRLF added by _ok separately
    # we want len('$'+body+'*hh') == total_chars
    fixed = 1 + len(head) + 3      # $ + body + *hh, before padding
    pad = total_chars - fixed
    if pad > 0:
        head = head + "," + "9" * (pad - 1)   # +1 for the comma
    return _ok(head)

C("struct_just_over_82_83", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 83-char sentence (1 over limit); ACCEPTED if pos moves to 43.5/-71.5",
  lambda: _overlen_rmc(83))
C("struct_just_over_82_90", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 90-char sentence; ACCEPTED if pos moves to 43.5/-71.5",
  lambda: _overlen_rmc(90))
C("struct_over_82_120", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 120-char sentence; ACCEPTED if pos moves to 43.5/-71.5",
  lambda: _overlen_rmc(120))
C("struct_over_82_200", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 200-char sentence (well over, still < DoS knee)",
  lambda: _overlen_rmc(200))
C("struct_over_82_500", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 500-char sentence (between boundary and DoS knee)",
  lambda: _overlen_rmc(500))
C("struct_over_82_1000", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 1000-char sentence (just under Furuno ~2KB knee)",
  lambda: _overlen_rmc(1000))
C("struct_over_82_2048", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 2048-char (Furuno DoS knee); ACCEPTED if pos->spoof, DEGRADED if nofix",
  lambda: _overlen_rmc(2048))
C("struct_over_82_4096", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 4096-char (em-trak/DY DoS knee)",
  lambda: _overlen_rmc(4096))
C("struct_over_82_8192", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 8192-char (deep over-length)",
  lambda: _overlen_rmc(8192))
C("struct_over_82_16384", "structure", "61162-1:2024 7.3.1 (82-char max, shall)", "serial",
  "REJECT - 16384-char (~200x the 82 limit; the headline over-length)",
  lambda: _overlen_rmc(16384))

# ====================== CHECKSUM ======================
C("cks_wrong_value", "checksum", "61162-1:2024 7.2.4 (checksum value)", "serial",
  "REJECT - checksum doesn't match body",
  lambda: ("$" + _GOOD_BODY + "*00\r\n").encode())
C("cks_missing", "checksum", "61162-1:2024 7.2.4 (checksum in all sentences)", "serial",
  "REJECT - no checksum field at all",
  lambda: ("$" + _GOOD_BODY + "\r\n").encode())
C("cks_nonhex", "checksum", "61162-1:2024 7.2.4 (hex 0-9A-F upper)", "serial",
  "REJECT - 'ZZ' not hex",
  lambda: ("$" + _GOOD_BODY + "*ZZ\r\n").encode())
C("cks_one_digit", "checksum", "61162-1:2024 7.2.4 (two hex digits)", "serial",
  "REJECT - single hex digit",
  lambda: ("$" + _GOOD_BODY + "*" + checksum(_GOOD_BODY)[0] + "\r\n").encode())
C("cks_three_digit", "checksum", "61162-1:2024 7.2.4 (two hex digits)", "serial",
  "REJECT - three hex digits",
  lambda: ("$" + _GOOD_BODY + "*" + checksum(_GOOD_BODY) + "F\r\n").encode())
C("cks_lowercase", "checksum", "61162-1:2024 7.2.4 (uppercase hex)", "serial",
  "REJECT/flag - lowercase hex checksum",
  lambda: ("$" + _GOOD_BODY + "*" + checksum(_GOOD_BODY).lower() + "\r\n").encode())
C("cks_wrong_range", "checksum", "61162-1:2024 7.2.4 (XOR between $/! and *)", "serial",
  "REJECT - plausible value computed over wrong range (incl $)",
  lambda: ("$" + _GOOD_BODY + "*" + checksum("$" + _GOOD_BODY) + "\r\n").encode())

# ====================== INVALID CHARACTERS ======================
C("chr_null_byte", "characters", "61162-1:2024 7.1.3 (valid chars 0x20-0x7E)", "serial",
  "REJECT - embedded NUL",
  lambda: ("$" + _GOOD_BODY.replace("A,", "A\x00,", 1) + "*" + checksum(_GOOD_BODY) + "\r\n").encode())
C("chr_control", "characters", "61162-1:2024 7.1.3 (valid chars 0x20-0x7E)", "serial",
  "REJECT - control chars (0x07,0x1B) in field",
  lambda: _ok_body_bytes("GPRMC,120000.00,A,4330.0000,\x07\x1B,07130.0000,W,0.0,0.0,180626,,,A".encode("latin1")))
C("chr_high_ascii", "characters", "61162-1:2024 7.1.1 (D7=0, ASCII)", "serial",
  "REJECT - high-ASCII bytes 0x80-0xFF",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A," + bytes([0x80,0xC3,0xFF]) + b",N,07130.0,W,0,0,180626,,,A"))
C("chr_tab", "characters", "61162-1:2024 7.1.3 (valid chars 0x20-0x7E)", "serial",
  "REJECT - tab char in field",
  lambda: _ok_body_bytes("GPRMC,120000.00,A,4330.0000,\tN,07130.0000,W,0.0,0.0,180626,,,A".encode("latin1")))
C("chr_embedded_nul_midsentence", "characters", "61162-1:2024 7.2.3.4 (no HEX00)", "serial",
  "REJECT - NUL mid valid sentence (C-string truncation bug probe)",
  lambda: _ok_body_bytes(_GOOD_BODY[:20].encode() + b"\x00" + _GOOD_BODY[20:].encode()))

# ====================== RESERVED CHARS IN DATA ======================
C("rsv_dollar_in_data", "reserved", "61162-1:2024 7.1.2/Tbl1 ($ reserved)", "serial",
  "REJECT - $ inside a data field",
  lambda: _ok_body_bytes("GPRMC,1200$00.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A".encode()))
C("rsv_bang_in_data", "reserved", "61162-1:2024 7.1.2/Tbl1 (! reserved)", "serial",
  "REJECT - ! inside a data field",
  lambda: _ok_body_bytes("GPRMC,1200!00.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A".encode()))
C("rsv_star_in_data", "reserved", "61162-1:2024 7.1.2/Tbl1 (* reserved)", "serial",
  "REJECT - '*' inside a data field (reserved char, only introduces checksum)",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,A*B,,A"))
C("rsv_cr_in_data", "reserved", "61162-1:2024 7.1.2/Tbl1 (CR/LF reserved)", "serial",
  "REJECT - CR inside a data field",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000\r,N,07130.0,W,0,0,180626,,,A"))

# ====================== ADDRESS FIELD ======================
C("addr_talker_too_short", "address", "61162-1:2024 7.2.2.2 (5-char approved addr)", "serial",
  "REJECT - 1-char talker",
  lambda: _ok("GRMC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("addr_talker_too_long", "address", "61162-1:2024 7.2.2.2 (5-char approved addr)", "serial",
  "REJECT - address field too long",
  lambda: _ok("GPSXRMC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("addr_lowercase", "address", "61162-1:2024 7.2.2.1 (digits+uppercase only)", "serial",
  "REJECT - lowercase address $gpgga",
  lambda: ("$gprmc,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,a*00\r\n").encode())
C("addr_numbers_in_talker", "address", "talker ID letters", "serial",
  "REJECT - digits in talker ID",
  lambda: _ok("G1RMC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("addr_special_chars", "address", "61162-1:2024 7.2.2.1 (digits+uppercase)", "serial",
  "REJECT - special chars in address",
  lambda: ("$GP#MC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A*00\r\n").encode())
C("addr_formatter_too_short", "address", "61162-1:2024 7.2.2.2 (3-char formatter)", "serial",
  "REJECT - 2-char formatter",
  lambda: _ok("GPRM,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("addr_formatter_too_long", "address", "61162-1:2024 7.2.2.2 (3-char formatter)", "serial",
  "REJECT - 4-char formatter",
  lambda: _ok("GPRMCX,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("addr_undefined_talker", "address", "defined talker IDs", "serial",
  "ignore/reject - undefined talker XX",
  lambda: _ok("XXRMC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("addr_undefined_formatter", "address", "defined sentence formatters", "serial",
  "ignore/reject - undefined formatter GPZZZ",
  lambda: _ok("GPZZZ,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))

# ====================== DATA FIELDS ======================
C("data_all_empty", "datafields", "field structure", "serial",
  "ignore/reject - all fields empty",
  lambda: _ok("GPRMC,,,,,,,,,,,,"))
C("data_required_empty_time", "datafields", "required field present", "serial",
  "REJECT/ignore - empty time in RMC",
  lambda: _ok("GPRMC,,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))
C("data_too_many_fields", "datafields", "field count per formatter", "serial",
  "REJECT/ignore - extra trailing commas",
  lambda: _ok("GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0,0,180626,,,A,,,,"))
C("data_too_few_fields", "datafields", "field count per formatter", "serial",
  "REJECT/ignore - far too few fields",
  lambda: _ok("GPRMC,120000.00,A"))
C("data_nonnumeric", "datafields", "numeric fields numeric", "serial",
  "REJECT - letters where lat digits expected",
  lambda: _ok("GPRMC,120000.00,A,ABCD.EFGH,N,07130.0000,W,0,0,180626,,,A"))
C("data_out_of_range_lat", "datafields", "lat range", "serial",
  "REJECT/clamp - latitude 91 deg",
  lambda: _ok("GPRMC,120000.00,A,9100.0000,N,07130.0000,W,0,0,180626,,,A"))
C("data_invalid_time", "datafields", "time hhmmss.ss", "serial",
  "REJECT - time 99:99:99",
  lambda: _ok("GPRMC,999999.99,A,4330.0000,N,07130.0000,W,0,0,180626,,,A"))

# ====================== SENTENCE-SPECIFIC FIELD LIMITS ======================
C("len_ver_f4_over15", "fieldlimits", "VER field4 uid <=15", "serial",
  "REJECT/truncate - 20-char unique id",
  lambda: _ver(20, 10))
C("len_ver_f5_over32", "fieldlimits", "VER field5 data <=32", "serial",
  "REJECT/truncate - 40-char data field",
  lambda: _ver(10, 40))
C("len_smv_name_31", "fieldlimits", "SMV name <=30 (LISTENER truncates)", "serial",
  "ACCEPT+TRUNCATE to 30 - 31-char name",
  lambda: _smv_name(31))
C("len_smv_name_60", "fieldlimits", "SMV name <=30 (LISTENER truncates)", "serial",
  "ACCEPT+TRUNCATE to 30 - 60-char name",
  lambda: _smv_name(60))
C("len_smb_over58", "fieldlimits", "SMB <=58 chars", "serial",
  "REJECT/truncate - SMB field >58",
  lambda: _ok("GPSMB,1,1," + "Z"*70))

# ====================== AIVDM / AIVDO (transport-tagged, RF-reusable) ======================
C("ais_valid_single", "aivdm", "valid AIVDM single fragment", "aivdm",
  "no effect on sensor port (AIVDM not a sensor sentence) - reusable RF control",
  lambda: _aivdm(1, 1, None, "A", _AIVDM_PAYLOAD, 0))
C("ais_frag_claim2_send1", "aivdm", "fragment count matches parts sent", "aivdm",
  "REJECT - claims 2 fragments, only 1 sent",
  lambda: _aivdm(2, 1, 5, "A", _AIVDM_PAYLOAD, 0))
C("ais_frag_num_gt_count", "aivdm", "frag number <= frag count", "aivdm",
  "REJECT - fragment 3 of 2",
  lambda: _aivdm(2, 3, 5, "A", _AIVDM_PAYLOAD, 0))
C("ais_frag_count_zero", "aivdm", "fragment count >= 1", "aivdm",
  "REJECT - fragment count 0",
  lambda: _aivdm(0, 1, 5, "A", _AIVDM_PAYLOAD, 0))
C("ais_frag_num_zero", "aivdm", "fragment number >= 1", "aivdm",
  "REJECT - fragment number 0",
  lambda: _aivdm(2, 0, 5, "A", _AIVDM_PAYLOAD, 0))
C("ais_start_frag2", "aivdm", "multi-part starts at fragment 1", "aivdm",
  "REJECT - first fragment received is #2",
  lambda: _aivdm(2, 2, 5, "A", _AIVDM_PAYLOAD, 0))
C("ais_fill_bits_9", "aivdm", "fill bits 0-5", "aivdm",
  "REJECT - fill bits = 9 (max 5)",
  lambda: _aivdm(1, 1, None, "A", _AIVDM_PAYLOAD, 9))
C("ais_bad_channel", "aivdm", "channel A or B", "aivdm",
  "REJECT - channel 'X'",
  lambda: _aivdm(1, 1, None, "X", _AIVDM_PAYLOAD, 0))
C("ais_empty_channel", "aivdm", "channel field present", "aivdm",
  "REJECT/tolerate - empty channel field",
  lambda: _aivdm(1, 1, None, "", _AIVDM_PAYLOAD, 0))
C("ais_non6bit_payload", "aivdm", "payload is valid 6-bit ASCII", "aivdm",
  "REJECT - payload contains out-of-armor chars",
  lambda: _aivdm(1, 1, None, "A", "!!!\x7f\x7e@@", 0))
C("ais_vdo_vs_vdm", "aivdm", "AIVDO=own AIVDM=received", "aivdm",
  "no effect / record behavior - AIVDO injected on serial",
  lambda: _ok("AIVDO,1,1,,A," + _AIVDM_PAYLOAD + ",0"))

# ====================== PROPRIETARY ======================
C("prop_mfr_too_short", "proprietary", "61162-1:2024 7.2.2.4 (P + 3-char mnemonic)", "serial",
  "REJECT - 2-char manufacturer id",
  lambda: _ok("PAB,data,data"))
C("prop_mfr_too_long", "proprietary", "61162-1:2024 7.2.2.4 (P + 3-char mnemonic)", "serial",
  "REJECT - 4-char manufacturer id",
  lambda: _ok("PABCD,data,data"))
C("prop_mfr_lowercase", "proprietary", "61162-1:2024 7.2.2.4 (proprietary addr)", "serial",
  "REJECT - lowercase manufacturer id",
  lambda: ("$Pabc,data,data*00\r\n").encode())

# ====================== QUERY ======================
C("query_wrong_identifier", "query", "61162-1:2024 7.2.2.3 (query addr 5 char, Q)", "serial",
  "REJECT - query identifier not QQQ (QQX)",
  lambda: _ok("GPQQX,GP,RMC"))
C("query_bad_target_addr", "query", "61162-1:2024 7.2.2.3 (query addr)", "serial",
  "REJECT - 4-char target in query",
  lambda: _ok("CCQQQ,GPS,RMC"))

# ====================== ENCAPSULATION ======================
C("encap_unescaped_backslash", "encapsulation", "61162-1:2024 Tbl1 (\\ TAG-block delim)", "serial",
  "REJECT - bare backslash in encapsulated data",
  lambda: _ok_body_bytes(("AIVDM,1,1,,A," + _AIVDM_PAYLOAD + "\\bad,0").encode(), start=b"!"))
C("encap_invalid_escape", "encapsulation", "valid escape sequences only", "serial",
  "REJECT - invalid escape \\q",
  lambda: _ok_body_bytes(("AIVDM,1,1,,A,\\q" + _AIVDM_PAYLOAD + ",0").encode(), start=b"!"))

# ====================== EDGE / NULL SENTENCES ======================
C("edge_empty_sentence", "edge", "non-empty sentence", "serial",
  "REJECT - just CRLF",
  lambda: CRLF)
C("edge_only_start", "edge", "sentence has content", "serial",
  "REJECT - only '$' then CRLF",
  lambda: b"$\r\n")
C("edge_only_delims", "edge", "sentence has content", "serial",
  "REJECT - only delimiters '$*\\r\\n'",
  lambda: b"$*\r\n")
C("edge_only_checksum", "edge", "sentence has body", "serial",
  "REJECT - '$*00' no body",
  lambda: b"$*00\r\n")

# ============ SPEC-GROUNDED (IEC 61162-1:2024, exact clause cites) ============
from nmea import checksum as _cks

# §7.2.3.4: "The ASCII NULL character (HEX 00) shall not be used as the null field."
C("spec_nul_as_null_field", "characters", "61162-1:2024 7.2.3.4 NUL-not-null", "serial",
  "REJECT - HEX00 used as a null field",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,\x00,,A"))

# §7.1.4 + Table 1: ~ (0x7E) and <del> (0x7F) are reserved-for-future-use; "shall not be
# transmitted at any time". Reserved/8-bit chars must use the ^HH escape instead.
C("spec_tilde_reserved", "characters", "61162-1:2024 7.1.4/Tbl1 ~ reserved", "serial",
  "REJECT - 0x7E (~) reserved-for-future-use in a data field",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,~,,A"))
C("spec_del_reserved", "characters", "61162-1:2024 7.1.4/Tbl1 0x7F reserved", "serial",
  "REJECT - 0x7F (<del>) reserved-for-future-use in a data field",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,\x7f,,A"))

# §7.1.4: the ^HH escape (^ then two hex). Malformed and (legal control) escapes.
C("spec_caret_escape_nonhex", "characters", "61162-1:2024 7.1.4 ^HH must be hex", "serial",
  "REJECT - ^ followed by non-hex (^ZZ)",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,^ZZ,,A"))
C("spec_caret_escape_truncated", "characters", "61162-1:2024 7.1.4 ^ needs 2 hex", "serial",
  "REJECT - ^ followed by one char then delimiter",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,^F,,A"))
C("spec_caret_escape_valid", "characters", "61162-1:2024 7.1.4 ^F8 legal escape", "serial",
  "ACCEPT/tolerate - properly escaped char ^F8 (this is LEGAL; accepting is correct)",
  lambda: _ok_body_bytes(b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,^F8,,A"),
  expect_accept=True)

# §7.2.4: checksum XOR includes the ',' and '^' delimiters. A checksum computed without
# the commas is a plausible-but-wrong value (distinct from cks_wrong_range).
C("spec_cks_excludes_commas", "checksum", "61162-1:2024 7.2.4 XOR includes commas", "serial",
  "REJECT - checksum computed without the ',' delimiters",
  lambda: ("$" + _GOOD_BODY + "*" + _cks(_GOOD_BODY.replace(",", "")) + "\r\n").encode())

# §1: typical traffic <= 1 message/second. Rapid back-to-back valid sentences stress
# the listener's input handling above the design rate. Each sentence carries a DISTINCT
# ordered position (lat 44.0 N fixed; lon 072 deg + index arc-minutes) so the output
# reveals how far through the sequence the unit kept up and which inputs it dropped.
def _rf_sentence(i):
    return _ok(f"GPRMC,120000.00,A,4400.0000,N,072{i:02d}.0000,W,30.0,90.0,180626,,,A")
C("spec_rapid_fire_valid", "datafields", "61162-1:2024 1 (~1 msg/s typical)", "serial",
  "tolerate+keep-up: 20 valid sentences back-to-back, each a distinct ordered position",
  lambda: b"".join(_rf_sentence(i) for i in range(20)), expect_accept=True)

# §7.3.3.1 / §7.3.4: parametric ($) and encapsulation (!) formatters "shall not be
# reused". Encapsulation formatter VDM used under a parametric $ start.
C("spec_formatter_reuse_vdm", "address", "61162-1:2024 7.3.3.1 no formatter reuse", "serial",
  "REJECT - encapsulation formatter VDM with parametric $ start",
  lambda: _ok("GPVDM,1,1,,A," + _AIVDM_PAYLOAD + ",0"))

# §7.3.4: in encapsulation sentences the fill-bits field "shall always be the last data
# field". A parametric field appended after fill-bits violates the structure.
C("spec_encap_field_after_fillbits", "encapsulation", "61162-1:2024 7.3.4 fill-bits last", "aivdm",
  "REJECT - extra data field after the fill-bits field",
  lambda: _ok_body_bytes(("AIVDM,1,1,,A," + _AIVDM_PAYLOAD + ",0,EXTRA").encode(), start=b"!"))

# Table 1: '\\' (0x5C) is the TAG block delimiter. A malformed/unterminated TAG block
# prefixed to an otherwise-valid sentence tests TAG-block handling on the sensor stream.
C("spec_tag_block_unterminated", "structure", "61162-1:2024 Tbl1 \\ TAG-block delim", "serial",
  "REJECT/tolerate - unterminated TAG block before a valid sentence",
  lambda: b"\\g:1-2-73874" + _ok_body_bytes(
      b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,,,A"))

# ============ TIER-3: SEMANTIC / PLAUSIBILITY (spec is ABSENT here) ============
# IEC 61162-1 7.4 obligates listeners to detect STRUCTURAL errors (checksum, invalid
# chars, field length) - but says NOTHING about whether the *values* make sense or
# are mutually consistent. These cases probe that gap: structurally perfect sentences
# whose CONTENT is implausible or self-contradictory. A conformant unit may transmit
# them; doing so is the "compliant-but-exploitable" finding. All carry the spoof
# position so "transmitted the implausible data" is detectable as ACCEPTED.
def _rmc(lat="4330.0000", lath="N", lon="07130.0000", lonh="W",
         sog="0.0", cog="90.0", date="180626", time="120000.00", status="A"):
    return _ok(f"GPRMC,{time},{status},{lat},{lath},{lon},{lonh},{sog},{cog},{date},,,A")

C("sem_implausible_date_future", "semantic", "(absent - no value-plausibility req in 7.4)", "serial",
  "compliant-but-implausible: RMC dated 2099 (no obligation to range-check date)",
  lambda: _rmc(date="311299"))
C("sem_cog_disagreement", "semantic", "(absent - no cross-field consistency req)", "serial",
  "compliant-but-inconsistent: RMC COG 090 but a VTG COG 270 in same batch",
  lambda: _rmc(cog="90.0") + _ok("GPVTG,270.0,T,,M,0.0,N,0.0,K,A"))
C("sem_speed_position_static", "semantic", "(absent - no cross-field consistency req)", "serial",
  "compliant-but-inconsistent: RMC claims 60 kn SOG at a fixed position",
  lambda: _rmc(sog="60.0"))
C("sem_anchored_but_moving", "semantic", "(absent - no nav-state consistency req)", "serial",
  "compliant-but-inconsistent: RMC reports high SOG (semantic anchor/move conflict)",
  lambda: _rmc(sog="45.0", cog="123.4"))
C("sem_rmc_status_void", "semantic", "(absent - listener not obligated to honor status flag)", "serial",
  "compliant-but-exploitable: RMC status='V' (data NOT valid) carrying a position",
  lambda: _rmc(status="V"))
C("sem_gga_fix_invalid", "semantic", "(absent - listener not obligated to honor fix-quality)", "serial",
  "compliant-but-exploitable: GGA fix quality=0 (invalid) carrying a position",
  lambda: _ok("GPGGA,120000.00,4330.0000,N,07130.0000,W,0,04,2.0,10.0,M,,M,,"))
C("sem_excess_precision", "semantic", "(borderline 7.4c - field format vs value)", "serial",
  "compliant-ish: lat/lon with excess decimal precision (6 min-decimals)",
  lambda: _ok("GPRMC,120000.00,A,4330.000000,N,07130.000000,W,0.0,90.0,180626,,,A"))

# ============ TIER-3: TEMPORAL / STATEFUL SEQUENCES (spec is ABSENT here) ============
# Multi-sentence sequences injected over time. The spec has no temporal-consistency
# obligation, so a unit will faithfully transmit physically impossible motion. These
# use seq=True and gen() returns a list of (delay_s, bytes) steps.
def Cseq(id, expect, steps_fn):
    CASES.append({"id": id, "category": "temporal",
                  "spec": "(absent - no temporal-consistency req in 7.4)",
                  "transport": "serial", "expect": expect, "gen": steps_fn,
                  "seq": True, "expect_accept": False})

# impossible speed: two positions ~300 km apart, 2 s apart -> ~270,000 kn implied
Cseq("seq_teleport",
     "compliant-but-impossible: two far positions 2s apart (impossible speed)",
     lambda: [(0.0, _rmc(lat="4330.0000", lon="07130.0000")),
              (2.0, _rmc(lat="4530.0000", lon="07530.0000"))])
# gradual walk: drift the position across several reports, 2 s apart (slow spoof)
Cseq("seq_position_walk",
     "compliant-but-implausible: position walked across consecutive reports over time",
     lambda: [(0.0 if i == 0 else 2.0, _rmc(lat=f"43{30+i:02d}.0000", lon="07130.0000"))
              for i in range(6)])
# acceleration: SOG ramps 0 -> 200 kn over several reports, 2 s apart, at one position
Cseq("seq_impossible_accel",
     "compliant-but-impossible: SOG ramps 0->200 kn over consecutive reports over time",
     lambda: [(0.0 if i == 0 else 2.0, _rmc(sog=f"{s:.1f}"))
              for i, s in enumerate((0, 40, 80, 120, 160, 200))])


# ============================ TIER / HARM TAXONOMY ============================
# Two-axis classification applied to every case:
#   TIER  = what KIND of spec obligation is implicated (grounded in real clauses)
#   HARM  = which of the 5 harm classes the violation would enable
# Grounding: 7.4 makes listener structural validation EXPLICIT ("Listening devices
# shall detect ... checksum error; invalid characters; incorrect length of address
# field and data fields ... shall use only correct sentences"). 7.3.11 = listeners
# find sentence end via <CR><LF>/* . So acceptance of malformed structure = explicit
# violation. Reserved CHARACTERS are explicit (7.1.2). Reserved ENUM VALUES, cross-
# field consistency, and temporal plausibility are NOT addressed = absent.
TIER_EXPLICIT, TIER_VAGUE, TIER_ABSENT = "explicit", "vague", "absent"
TIER_CONTROL, TIER_CONFORMANT = "control", "conformant_behavior"
H_FALSE_TARGET = "false_target"
H_FALSE_ENV = "false_environment"          # RF-layer (not reachable via serial GPS)
H_REMOTE_CMD = "remote_command"            # RF-layer
H_CHANNEL_DENIAL = "channel_denial"
H_RECEIVER_COMPROMISE = "receiver_compromise"
H_CONTROL = "control"


def _assign_tier_harm(c):
    cid, cat = c["id"], c["category"]
    if cat == "control":
        return TIER_CONTROL, H_CONTROL
    # --- over-length: explicit 7.4c length violation; DoS harm ---
    if "over_82" in cid or "just_over" in cid:
        return TIER_EXPLICIT, H_CHANNEL_DENIAL
    # --- terminator edge: 7.3.11 implies CRLF recognition but doesn't explicitly
    #     say "reject bare LF" -> vague ---
    if cid in ("struct_only_lf", "struct_only_cr", "struct_lf_cr_order"):
        return TIER_VAGUE, H_FALSE_TARGET
    # --- leading garbage: 7.3.11 / test annex say chars before next sentence SHALL
    #     be ignored -> tolerating+resyncing is conformant behavior ---
    if cid == "struct_leading_garbage":
        return TIER_CONFORMANT, H_RECEIVER_COMPROMISE
    # --- legal escape / valid controls ---
    if cid == "spec_caret_escape_valid":
        return TIER_CONTROL, H_CONTROL
    # --- semantic & temporal: spec absent ---
    if cat in ("semantic", "temporal"):
        return TIER_ABSENT, H_FALSE_TARGET
    # --- value-range (not structural): absent ---
    if cid in ("data_out_of_range_lat", "data_invalid_time"):
        return TIER_ABSENT, H_FALSE_TARGET
    # --- rapid-fire valid: 7.3.10 rate is a talker "should"; listener handling of
    #     >1/s is unspecified -> absent; denial harm if it disrupts ---
    if cid == "spec_rapid_fire_valid":
        return TIER_ABSENT, H_CHANNEL_DENIAL
    # --- undefined (but well-formed) talker/formatter: ignoring is arguably
    #     conformant -> vague ---
    if cid in ("addr_undefined_talker", "addr_undefined_formatter"):
        return TIER_VAGUE, H_RECEIVER_COMPROMISE
    # --- arguable listener obligation on these structural niceties -> vague ---
    if cid in ("spec_tag_block_unterminated", "spec_formatter_reuse_vdm",
               "spec_encap_field_after_fillbits", "ais_valid_single", "ais_vdo_vs_vdm"):
        return TIER_VAGUE, H_RECEIVER_COMPROMISE
    # --- explicit structural categories (7.4 a/b/c, 7.1.2/7.1.3, 7.2.x, 7.3.4) ---
    if cat in ("checksum", "characters", "reserved", "structure", "fieldlimits"):
        return TIER_EXPLICIT, H_FALSE_TARGET           # carry position -> spoof if accepted
    if cat == "datafields":
        return TIER_EXPLICIT, H_FALSE_TARGET
    if cat == "address":
        return TIER_EXPLICIT, H_FALSE_TARGET
    if cat in ("aivdm", "proprietary", "query", "encapsulation", "edge"):
        return TIER_EXPLICIT, H_RECEIVER_COMPROMISE    # parser robustness, no position
    return TIER_EXPLICIT, H_RECEIVER_COMPROMISE


for _c in CASES:
    _c["tier"], _c["harm"] = _assign_tier_harm(_c)


def get_cases(categories=None, ids=None):
    cs = CASES
    if categories:
        cs = [c for c in cs if c["category"] in categories]
    if ids:
        cs = [c for c in cs if c["id"] in ids]
    return cs


if __name__ == "__main__":
    # self-list
    from collections import Counter
    cats = Counter(c["category"] for c in CASES)
    print(f"{len(CASES)} cases across {len(cats)} categories:")
    for k, v in cats.items():
        print(f"  {k:14s} {v}")
