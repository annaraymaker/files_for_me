#!/usr/bin/env python3
r"""
serial_parser_suite.py -- parser-robustness / injection probes for the NMEA presentation interface.

These are the "web-style" parser vulnerabilities applied to NMEA 0183:
  1. ESCAPE-EXPANSION  the IEC 61162-1 "^HH" code-delimiter escape is an entity-expansion feature
                        (^2A->'*', ^24->'$', ^0D^0A->CRLF). If the unit un-escapes it inside a
                        field, an attacker materialises a checksum delimiter, sentence start, or
                        line terminator from bytes that look benign on the wire.
  2. MEMORY / LEAK      the unit already emitted a stray DEL byte in its own $AINAK error output.
                        These probes carry distinctive markers (and a long->short sequence) to see
                        whether the error path echoes the input or leaks prior-sentence memory.
  3. CRASH / OVERFLOW   huge field counts, single over-long fields, unterminated input, numeric
                        edge values, multi-sentence reassembly abuse, and malformed tag blocks --
                        aimed at buffer / state-machine faults (hang / reboot).
  4. CONFIG (LAST)      proprietary / query / set sentences that may change persistent state. This
                        is the only class that can brick the unit, so it runs LAST -- every other
                        result is captured first -- and only if --i-accept-config-risk is given.

Model: the same continuous-baseline harness as serial_cve_suite -- a valid position is fed
continuously; each probe injects a crafted sentence (leak probes repeat briefly), then the
baseline is held for recovery. Detection is offline (analyze_parser.py) from the unit's OUTPUT
capture + this manifest: silence = crash/hang, silence+reset = reboot, marker/foreign bytes in
output = leak, smuggled position in output = escape expansion. If --out-port is given, the runner
also does a LIVE liveness check after each probe and halts if the unit dies during the config
category.

SAFETY: categories 1-3 are recoverable (worst case a hang or reboot). Category 4 can change
persistent settings -- run only on an expendable unit, with a factory-reset plan.
"""
import argparse, json, os, sys, time
try:
    import serial
except Exception:
    serial = None

# reuse the tested harness from the CVE suite
from serial_cve_suite import (cksum, sent, gga, rmc, baseline_batch, hold_baseline,
                              BASE, SPOOF, SPOOF_LAT_F, SPOOF_LON_F)

SPOOF_BODY   = f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A"
SMUGGLE      = (44.5, -72.5)
SMUGGLE_BODY = "GPRMC,120000.00,A,4430.0000,N,07230.0000,W,0.0,90.0,180626,,,A"
MARKER       = "ZQJXKVWZ"        # rare-letter marker, easy to spot if echoed/leaked


def good(body):
    """well-formed sentence: $body*cc<CR><LF> with a VALID checksum over the literal body."""
    return sent(body).encode()

def badcks(body):
    """structurally valid but deliberately WRONG checksum -> the unit should reject it (-> $AINAK)."""
    return ("$" + body + "*00\r\n").encode()

def _xorck(body):
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"

def aivdm(body, good_ck=True):
    """An encapsulated '!'-sentence (AIVDM/AIVDO family) with a correct or deliberately wrong
    checksum. body is the text between '!' and '*'."""
    cs = _xorck(body) if good_ck else "00"
    return f"!{body}*{cs}\r\n".encode()

def spoof_field(payload):
    """a spoof-position RMC with `payload` spliced into the (otherwise empty) time field."""
    return f"GPRMC,1200{payload}00.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A"


def build_probes(accept_config):
    P = []
    def add(cat, risk, pid, gen, note="", marker=None, smuggle=None, expect="process"):
        P.append(dict(cat=cat, risk=risk, id=pid, gen=gen, note=note,
                      marker=marker, smuggle=smuggle, expect=expect))

    # ---------- 1. ESCAPE-EXPANSION (^HH entity analog) ----------
    for tag, seq, meansto in [("star", "^2A", "*"), ("dollar", "^24", "$"),
                              ("bang", "^21", "!"), ("caret", "^5E", "^")]:
        add("escape", "low", f"esc_{tag}", (lambda s=seq: good(spoof_field(s))),
            note=f"{seq} un-escapes to '{meansto}' if the parser expands it", marker=seq)
    # ^0D^0A -> CRLF, with a trailing sentence: if expanded, the CRLF ends the field early and the
    # trailing sentence is exposed (entity-driven hidden-sentence injection).
    esc_crlf_body = f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A^0D^0A${SMUGGLE_BODY}"
    add("escape", "low", "esc_crlf_smuggle", (lambda b=esc_crlf_body: good(b)),
        note="^0D^0A may expand to CRLF and expose the trailing $GPRMC (smuggle 44.5/-72.5)",
        smuggle=SMUGGLE)
    for tag, seq in [("bare", "^"), ("onehex", "^Z"), ("onedigit", "^0"),
                     ("nonhex", "^GG"), ("chained", "^5E2A")]:
        add("escape", "low", f"esc_malformed_{tag}", (lambda s=seq: good(spoof_field(s))),
            note=f"malformed escape '{seq}' (un-escaper edge)")
    add("escape", "low", "esc_flood",
        (lambda: good("GPRMC,120000.00,A," + "^0D" * 120 + f"{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A")),
        note="120x ^0D -> expansion-buffer growth")

    # ---------- 2. MEMORY / LEAK (chase the DEL-in-$AINAK lead) ----------
    add("leak", "low", "leak_marker_reject",
        (lambda: badcks("GPRMC,120000.00,A," + MARKER * 3 + f",{SPOOF_LAT_F},N,{SPOOF_LON_F},W,0.0,90.0,180626,,,A")),
        note="rejected sentence carrying a distinctive marker; does the $AINAK echo it?",
        marker=MARKER, expect="reject")
    add("leak", "low", "leak_del_reject",
        (lambda: ("$GPRMC,1200\x7f00.00,A," + SPOOF_LAT_F + ",N," + SPOOF_LON_F + ",W,0.0,90.0,180626,,,A*00\r\n").encode()),
        note="DEL (0x7f) in a REJECTED sentence; does the error path echo the DEL?",
        marker="\x7f", expect="reject")
    add("leak", "low", "leak_long_marker_reject",
        (lambda: badcks("GPRMC,120000.00,A," + MARKER * 20 + ",X")),
        note="LONG rejected sentence with marker; run just before leak_short to test stale buffer",
        marker=MARKER, expect="reject")
    add("leak", "low", "leak_short_after_long",
        (lambda: badcks("GPRMC,1,A")),
        note="SHORT rejected sentence right after the long one; a leak echoes the long one's bytes",
        marker=MARKER, expect="reject")

    # ---------- 3. CRASH / OVERFLOW / NUMERIC / REASSEMBLY / TAG ----------
    add("overflow", "med", "of_many_fields",
        (lambda: good("GPRMC" + "," * 300 + "A")), note="~300 empty fields -> field-array overflow")
    for n in (500, 2000, 8000):
        add("overflow", "med", f"of_long_field_{n}",
            (lambda n=n: good("GPRMC,120000.00,A," + "9" * n)), note=f"single {n}-char field")
    add("overflow", "med", "of_unterminated_8000",
        (lambda: ("$GPRMC,120000.00,A," + "9" * 8000).encode()),
        note="8000-char field, NO checksum/terminator (keeps filling the line buffer)")
    for tag, val in [("huge_int", "9" * 30), ("scientific", "1e999"), ("nan", "NaN"),
                     ("inf", "Inf"), ("neg", "-1e-999"), ("hexlike", "0x1F")]:
        add("numeric", "med", f"num_{tag}",
            (lambda v=val: good(f"GPRMC,120000.00,A,{SPOOF_LAT_F},N,{SPOOF_LON_F},W,{v},90.0,180626,,,A")),
            note=f"numeric edge value '{val}' in the SOG field")
    add("reassembly", "med", "frag_incomplete",
        (lambda: b"!AIVDM,3,1,7,A,14eG;o@034o8sd<L9i:a?wv00SsO,0*5B\r\n"),
        note="part 1 of a 3-part AIVDM; parts 2-3 never sent (reassembly buffer left open)")
    add("reassembly", "med", "frag_part_gt_total",
        (lambda: b"!AIVDM,2,3,7,A,14eG;o@034o8sd<L9i:a?wv00SsO,0*4E\r\n"),
        note="part 3 of a 2-part message (index > total)")
    add("reassembly", "med", "frag_huge_total",
        (lambda: b"!AIVDM,99,1,7,A,14eG;o@034o8sd<L9i:a?wv00SsO,0*33\r\n"),
        note="claims 99 fragments")
    add("reassembly", "med", "frag_dup_seq",
        (lambda: b"!AIVDM,2,1,7,A,14eG;o@034o8sd<L9i:a?wv00SsO,0*4C\r\n!AIVDM,2,1,7,A,14eG;o@034o8sd<L9i:a?wv00SsO,0*4C\r\n"),
        note="two copies of part 1 (duplicate sequence)")
    add("tagblock", "med", "tag_unterminated",
        (lambda: (b"\\s:foo,c:1," + good(SPOOF_BODY)).replace(b"\\s", b"\\s")),
        note="unterminated tag block (no closing backslash) before the sentence")
    add("tagblock", "med", "tag_huge",
        (lambda: (b"\\" + b"A" * 4000 + b"\\" + good(SPOOF_BODY))),
        note="4000-char tag block")
    add("tagblock", "med", "tag_reserved",
        (lambda: (b"\\s:$$**!!,c:1*00\\" + good(SPOOF_BODY))),
        note="tag block containing reserved chars")

    # ---------- CONFORMANCE (targeted IEC 61162-1 receiver checks; run with --conform-only) ----------
    # A 2-part encapsulated message. p1 is well formed; the second fragment is either broken or
    # interrupted, which under IEC 61162-1 7.3.9 obliges the listener to DISCARD THE WHOLE message.
    _p1 = "AIVDM,2,1,3,A,55P5TL01VIaAL@7WKO@mBplU@Tpl00000000000L0000000000000,0"
    _p2 = "AIVDM,2,2,3,A,00000000000000000000000000000000000,0"
    add("conform", "low", "conf_frag_badcks",
        (lambda: aivdm(_p1, True) + aivdm(_p2, False)),
        note="2-part message, part 2 has a BAD checksum -> whole message must be discarded (7.3.9)",
        expect="reject")
    add("conform", "low", "conf_frag_interrupt",
        (lambda: aivdm(_p1, True) + good(SPOOF_BODY) + aivdm(_p2, True)),
        note="2-part message interrupted by an unrelated sentence (non-contiguous) -> discard whole (7.3.9)",
        smuggle=SPOOF, expect="reject")
    add("conform", "low", "conf_frag_index_bad",
        (lambda: aivdm("AIVDM,2,2,4,A,55P5TL01VIaAL@7WKO@mBplU@Tpl0000000,0", True)),
        note="fragment 2 of a 2-part message with no part 1 (orphan fragment) -> must not be acted on",
        expect="reject")
    # Config-command semantics (7.3.7): a command must be flagged unambiguously; a null command
    # field means no change. NOTE: the sentence formatter below is a PLACEHOLDER -- replace it with
    # the unit's real config formatter per vendor before trusting a negative result.
    add("conform", "low", "conf_cfg_no_c_flag",
        (lambda: good("PAISCFG,RATE,5,R")),
        note="PLACEHOLDER config sentence without the 'C' command flag (status R) -> must not change config",
        expect="reject")
    add("conform", "low", "conf_cfg_null_field",
        (lambda: good("PAISCFG,RATE,,C")),
        note="PLACEHOLDER config command with a NULL command field -> must be treated as no change",
        expect="reject")

    # ---------- 4. CONFIG / PROPRIETARY (LAST, brick risk; opt-in) ----------
    if accept_config:
        add("config", "high", "prop_query_emt",
            (lambda: good("PEMT,Q")), note="em-trak proprietary query probe (guessed prefix)",
            expect="unknown")
        add("config", "high", "prop_generic_query",
            (lambda: good("PGRMC")), note="generic proprietary query", expect="unknown")
        add("config", "high", "std_query_txcfg",
            (lambda: good("AIQ,VSD")), note="standard AIS query for voyage/static data", expect="unknown")
        add("config", "high", "prop_unknown_set",
            (lambda: good("PEMT,SET,TEST,1")), note="proprietary SET-shaped sentence (may write state)",
            expect="unknown")

    return P


# ---------------- optional live liveness on the unit's OUTPUT port ----------------
def unit_alive(out_port, out_baud, seconds):
    """Read the unit's output for `seconds`; return the count of its own transmissions (AIVDO)."""
    if not out_port or serial is None:
        return None
    try:
        s = serial.Serial(out_port, out_baud, timeout=0.5)
    except Exception as e:
        sys.stderr.write(f"  (liveness: cannot open {out_port}: {e})\n"); return None
    end = time.time() + seconds; n = 0
    try:
        while time.time() < end:
            line = s.readline().decode("ascii", "replace")
            if line.startswith("!AIVDO") or line.startswith("!AIVDM"):
                n += 1
    finally:
        s.close()
    return n


def main():
    ap = argparse.ArgumentParser(description="NMEA parser-robustness / injection suite.")
    ap.add_argument("--gps-port"); ap.add_argument("--gps-baud", type=int, default=4800)
    ap.add_argument("--out-port", help="unit's OUTPUT serial port for live liveness checks (optional)")
    ap.add_argument("--out-baud", type=int, default=38400)
    ap.add_argument("--gap", type=float, default=10.0, help="baseline recovery after each probe")
    ap.add_argument("--settle", type=float, default=60.0)
    ap.add_argument("--leak-repeat", type=int, default=6, help="times to repeat each leak probe")
    ap.add_argument("--liveness-secs", type=float, default=4.0)
    ap.add_argument("--only", nargs="+"); ap.add_argument("--skip-config", action="store_true")
    ap.add_argument("--conform-only", action="store_true",
                    help="run ONLY the targeted IEC 61162-1 conformance probes (multi-sentence "
                         "reassembly + config-command semantics), skipping all other categories")
    ap.add_argument("--i-accept-config-risk", action="store_true",
                    help="include category 4 (config/proprietary) -- can change persistent state")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    probes = build_probes(args.i_accept_config_risk and not args.skip_config)
    if args.conform_only:
        probes = [p for p in probes if p["cat"] == "conform"]
    if args.only:
        probes = [p for p in probes if p["id"] in args.only]
    # stable order: escape, leak, overflow/numeric/reassembly/tag, conform, config LAST
    catrank = {"escape": 0, "leak": 1, "overflow": 2, "numeric": 2, "reassembly": 2,
               "tagblock": 2, "conform": 3, "config": 9}
    probes.sort(key=lambda p: catrank.get(p["cat"], 5))

    if args.dry_run:
        for p in probes:
            raw = p["gen"]()
            s = raw[:96].decode("latin-1").replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0").replace("\x7f", "\\x7f")
            print(f"[{p['cat']:10} {p['risk']:4}] {p['id']:22} {s}")
        cats = {}
        for p in probes: cats[p["cat"]] = cats.get(p["cat"], 0) + 1
        print(f"\n{len(probes)} probes: {cats}")
        print(f"config category {'INCLUDED' if any(p['cat']=='config' for p in probes) else 'excluded'}")
        return

    if serial is None:
        print("needs pyserial: pip install pyserial --break-system-packages"); sys.exit(1)
    if not args.gps_port:
        print("need --gps-port"); sys.exit(1)
    if not args.i_confirm_cage_sealed:
        if input("Type EXACTLY 'cage is sealed' to run: ").strip() != "cage is sealed":
            print("Aborted."); sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    manifest = os.path.join(args.logdir, f"parser_{stamp}.jsonl")
    mf = open(manifest, "a", buffering=1)
    def rec(**kw): mf.write(json.dumps({"t": time.time(),
                    "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **kw}) + "\n")

    ser = serial.Serial(args.gps_port, args.gps_baud, timeout=1)
    rec(event="session_start", base_lat=BASE[0], base_lon=BASE[1], spoof_lat=SPOOF[0],
        spoof_lon=SPOOF[1], smuggle_lat=SMUGGLE[0], smuggle_lon=SMUGGLE[1],
        marker=MARKER, gps_baud=args.gps_baud, n=len(probes))
    print(f"settling {args.settle}s ..."); hold_baseline(ser, args.settle)
    rec(event="baseline", name="baseline_settle"); hold_baseline(ser, 3)
    base_alive = unit_alive(args.out_port, args.out_baud, args.liveness_secs)
    if base_alive is not None:
        rec(event="liveness", when="baseline", aivdo=base_alive); print(f"  baseline liveness: {base_alive} own-tx")

    try:
        last_cat = None
        for i, p in enumerate(probes):
            if p["cat"] == "config" and last_cat != "config":
                print("\n!! entering CONFIG category (brick risk). Verifying unit is alive first ...")
                a = unit_alive(args.out_port, args.out_baud, args.liveness_secs)
                rec(event="liveness", when="pre_config", aivdo=a)
                if a == 0:
                    print("   unit is NOT transmitting before config probes -- stopping."); break
            last_cat = p["cat"]
            raw = p["gen"]()
            rec(event="probe_start", id=p["id"], cat=p["cat"], risk=p["risk"], note=p["note"],
                marker=p["marker"], smuggle_lat=(p["smuggle"] or (None, None))[0],
                smuggle_lon=(p["smuggle"] or (None, None))[1], expect=p["expect"],
                sent_len=len(raw), sample=raw[:120].decode("latin-1").replace("\x00", "\\0"))
            print(f"[{i+1}/{len(probes)}] {p['cat']}/{p['id']} ({p['risk']})")
            reps = args.leak_repeat if p["cat"] == "leak" else 1
            t0 = time.time()
            for _ in range(reps):
                ser.write(raw); ser.flush()
                if reps > 1: time.sleep(1.0)
            rec(event="probe_end", id=p["id"], write_s=round(time.time() - t0, 3), reps=reps)
            hold_baseline(ser, args.gap)
            alive = unit_alive(args.out_port, args.out_baud, args.liveness_secs)
            if alive is not None:
                rec(event="liveness", when="after", id=p["id"], aivdo=alive)
                if alive == 0:
                    print(f"   !! unit SILENT after {p['id']} -- waiting 20s for possible reboot ...")
                    hold_baseline(ser, 20)
                    alive2 = unit_alive(args.out_port, args.out_baud, args.liveness_secs)
                    rec(event="liveness", when="after_wait", id=p["id"], aivdo=alive2)
                    if alive2 == 0:
                        print(f"   !! still silent -- likely crash/hang/brick at {p['id']}. Stopping.")
                        rec(event="halt_dead_unit", id=p["id"]); break
    except KeyboardInterrupt:
        print("\ninterrupted."); rec(event="interrupted")
    finally:
        hold_baseline(ser, 3); ser.close(); rec(event="session_end"); mf.close()
    print(f"\ndone. manifest: {manifest}\nfeed it + the unit's serial output to analyze_parser.py")


if __name__ == "__main__":
    main()
