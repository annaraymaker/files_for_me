#!/usr/bin/env python3
"""NMEA 0183 sentence construction and deliberate malformation.

Used by the GPS injector (valid sentences) and the malformed-NMEA experiment
(broken sentences). Keeping both here means there is one definition of a
"correct" sentence to deviate from.
"""
from datetime import datetime, timezone


def checksum(body):
    """XOR of every char between $ and * (exclusive)."""
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def sentence(body):
    """Wrap a body (no $, no *cc) into a complete sentence with checksum."""
    return f"${body}*{checksum(body)}"


def _lat(deg):
    h = 'N' if deg >= 0 else 'S'
    deg = abs(deg); d = int(deg); m = (deg - d) * 60
    return f"{d:02d}{m:07.4f}", h


def _lon(deg):
    h = 'E' if deg >= 0 else 'W'
    deg = abs(deg); d = int(deg); m = (deg - d) * 60
    return f"{d:03d}{m:07.4f}", h


# ---------- valid sentence builders ----------
def gga(lat, lon, alt=10.0, t=None):
    now = t or datetime.now(timezone.utc)
    ts = now.strftime("%H%M%S.00")
    la, lah = _lat(lat); lo, loh = _lon(lon)
    return sentence(f"GPGGA,{ts},{la},{lah},{lo},{loh},1,08,0.9,{alt:.1f},M,0.0,M,,")


def rmc(lat, lon, sog=0.0, cog=0.0, t=None):
    now = t or datetime.now(timezone.utc)
    ts = now.strftime("%H%M%S.00"); ds = now.strftime("%d%m%y")
    la, lah = _lat(lat); lo, loh = _lon(lon)
    return sentence(f"GPRMC,{ts},A,{la},{lah},{lo},{loh},{sog:.1f},{cog:.1f},{ds},,,A")


def vtg(sog=0.0, cog=0.0):
    return sentence(f"GPVTG,{cog:.1f},T,,M,{sog:.1f},N,{sog*1.852:.1f},K,A")


def zda(t=None):
    now = t or datetime.now(timezone.utc)
    ts = now.strftime("%H%M%S.00")
    return sentence(f"GPZDA,{ts},{now:%d},{now:%m},{now:%Y},00,00")


def dtm():
    return sentence("GPDTM,W84,,0.0,N,0.0,E,0.0,W84")


def full_batch(lat, lon, sog=0.0, cog=0.0, alt=10.0, with_dtm=False, with_zda=False):
    """The proven-working batch: GGA/RMC/VTG only - identical field layout to the
    original gps_sim that works on all three transponders. DTM/ZDA are optional
    extras (off by default); the FA-170 issue was a missing MMSI, not DTM, so the
    plain GGA/RMC/VTG set is what we send."""
    out = []
    if with_dtm:
        out.append(dtm())
    out += [gga(lat, lon, alt), rmc(lat, lon, sog, cog), vtg(sog, cog)]
    if with_zda:
        out.append(zda())
    return out


# ---------- raw-field builders (structurally valid, impossible VALUES) ----------
# Let the caller pass pre-formatted lat/lon field strings so we can emit things
# the decimal->ddmm conversion can't, e.g. minutes >= 60 or over-long fields.
def gga_raw(lat_field, lat_h, lon_field, lon_h, alt=10.0, t=None):
    now = t or datetime.now(timezone.utc)
    ts = now.strftime("%H%M%S.00")
    return sentence(f"GPGGA,{ts},{lat_field},{lat_h},{lon_field},{lon_h},"
                    f"1,08,0.9,{alt:.1f},M,0.0,M,,")


def rmc_raw(lat_field, lat_h, lon_field, lon_h, sog=0.0, cog=0.0, t=None):
    now = t or datetime.now(timezone.utc)
    ts = now.strftime("%H%M%S.00"); ds = now.strftime("%d%m%y")
    return sentence(f"GPRMC,{ts},A,{lat_field},{lat_h},{lon_field},{lon_h},"
                    f"{sog:.1f},{cog:.1f},{ds},,,A")


def full_batch_raw(lat_field, lat_h, lon_field, lon_h, sog=0.0, cog=0.0, alt=10.0):
    return [gga_raw(lat_field, lat_h, lon_field, lon_h, alt),
            rmc_raw(lat_field, lat_h, lon_field, lon_h, sog, cog),
            vtg(sog, cog)]


# ---------- deliberate malformations (for the malformed-NMEA experiment) ----------
# Each returns (label, raw_bytes). Raw bytes so we can emit non-ASCII / truncated junk.
def mal_bad_checksum(lat=42.35, lon=-70.90):
    s = rmc(lat, lon)
    bad = s[:-2] + ("00" if s[-2:] != "00" else "01")  # flip checksum
    return ("bad_checksum", bad.encode())


def mal_no_checksum(lat=42.35, lon=-70.90):
    s = rmc(lat, lon).split('*')[0]
    return ("no_checksum", s.encode())


def mal_truncated(lat=42.35, lon=-70.90):
    s = rmc(lat, lon)
    return ("truncated_midfield", s[:len(s)//2].encode())


def mal_oversized_field():
    body = "GPRMC,120000.00,A," + "9" * 200 + ",N,07054.0000,W,0.0,0.0,150626,,,A"
    return ("oversized_field", sentence(body).encode())


def mal_out_of_range():
    # lat 91 deg, lon 181 deg, impossible sog
    body = "GPRMC,120000.00,A,9100.0000,N,18100.0000,E,9999.9,9999.9,150626,,,A"
    return ("out_of_range_values", sentence(body).encode())


def mal_wrong_field_count():
    return ("too_few_fields", sentence("GPRMC,120000.00,A,4221.0000,N").encode())


def mal_extra_fields():
    body = "GPRMC,120000.00,A,4221.0000,N,07054.0000,W,0.0,0.0,150626,,,A,X,Y,Z,EXTRA"
    return ("extra_fields", sentence(body).encode())


def mal_null_fields():
    return ("all_null_fields", sentence("GPRMC,,,,,,,,,,,").encode())


def mal_garbage():
    return ("binary_garbage", bytes([0x00, 0xFF, 0xAA, 0x55] * 8))


def mal_huge_line():
    # buffer-stress: very long line with no terminator logic
    return ("huge_line_8k", (b"$GPRMC," + b"A" * 8000 + b"*00"))


def mal_status_void(lat=42.35, lon=-70.90):
    # structurally valid but status V (invalid) - should be ignored, not crash
    la, lah = _lat(lat); lo, loh = _lon(lon)
    return ("status_void", sentence(
        f"GPRMC,120000.00,V,{la},{lah},{lo},{loh},0.0,0.0,150626,,,N").encode())


def mal_wrong_talker():
    return ("unknown_talker_XXZZZ", sentence("XXZZZ,120000.00,A,4221.0,N").encode())


MALFORMATIONS = [
    mal_bad_checksum, mal_no_checksum, mal_truncated, mal_oversized_field,
    mal_out_of_range, mal_wrong_field_count, mal_extra_fields, mal_null_fields,
    mal_garbage, mal_huge_line, mal_status_void, mal_wrong_talker,
]
