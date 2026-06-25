#!/usr/bin/env python3
"""Standalone follow-up experiment - drop into the testbed dir and run. Does NOT
modify or depend on the rest of the repo (only needs pyserial + pyais, already used).

Answers two questions about a vendor's flaky / inconsistent malformed-input handling:

  ARM 1  "is the flaky acceptance a timing race?"
    Cases that have sometimes been ACCEPTED (took the spoof position) and sometimes
    not, injected MANY times at controlled PHASE OFFSETS relative to the unit's own
    output tick. Reports acceptance fraction per (case, phase). A clean phase
    dependence => characterized timing race; flat-and-high => reliable vuln;
    flat-and-low => intermittent, cause not output-cycle timing. Negative-control
    cases (always-rejected) confirm the fractions are real, not measurement noise.

  ARM 2  "why do different reserved characters get different outcomes, and does the
          FIELD matter?"
    2-D sweep: each reserved/special character x each field position. The char is
    inserted into one field of an otherwise-valid spoof-position RMC (valid checksum
    over the malformed body, so the char+field is the only variable). Records the full
    outcome (ACCEPTED / DEGRADED / REJECTED) per (char, field), repeated N times.

OUTCOME DEFINITIONS (black-box, from the AIS output stream):
  ACCEPTED  = a non-baseline position appeared  -> unit acted on malformed input (spoof)
  DEGRADED  = unit went to no-fix (91/181)      -> malformed input denied normal operation
  REJECTED  = output stayed at baseline only     -> correct behavior
Baseline GPS (42.35 N / 70.90 W) flows continuously; the malformed sentence carries a
distinct spoof position (43.5 N / 71.5 W), so "accepted" is unambiguous.

USAGE
  run:      python3 run_repeatability.py --gps /dev/ttyUSB0 --ais /dev/ttyUSB1 --vendor Emtrak
  options:  --trials 20 --phases 0,250,500,750 --arm both|1|2
            --baseline-s 8 --observe-s 6 --recovery-s 8 --dry-run
  reanalyze: python3 run_repeatability.py --analyze results/repeatability_Emtrak__<stamp>

Runtime is large by design (statistical). ~ (Arm1 cases*phases + Arm2 chars*fields)
* trials * (baseline+observe+recovery). Run under tmux.
"""
import argparse
import json
import os
import random
import sys
import threading
import time
from datetime import datetime, timezone

try:
    import serial
    HAVE_SERIAL = True
except Exception:
    HAVE_SERIAL = False
try:
    from pyais import decode as ais_decode
    HAVE_PYAIS = True
except Exception:
    HAVE_PYAIS = False

# ---- geometry (matches the conformance suite) ----
BASE_LAT, BASE_LON = 42.35, -70.90
SPOOF_LAT, SPOOF_LON = 43.5, -71.5
GPS_BAUD, AIS_BAUD = 4800, 38400

# ---- NMEA helpers (inline so the script is self-contained) ----
def cksum(body: bytes) -> bytes:
    c = 0
    for x in body:
        c ^= x
    return f"{c:02X}".encode()


def sentence(body: bytes, start=b"$") -> bytes:
    return start + body + b"*" + cksum(body) + b"\r\n"


def gps_batch(lat, lon, sog=12.0, cog=90.0):
    """Valid GGA/RMC/VTG batch at a position (the proven-accepted set)."""
    latd = int(abs(lat)); latm = (abs(lat) - latd) * 60
    lond = int(abs(lon)); lonm = (abs(lon) - lond) * 60
    la = f"{latd:02d}{latm:07.4f}"; lah = "N" if lat >= 0 else "S"
    lo = f"{lond:03d}{lonm:07.4f}"; loh = "E" if lon >= 0 else "W"
    out = b""
    out += sentence(f"GPGGA,120000.00,{la},{lah},{lo},{loh},1,08,1.0,10.0,M,,M,,".encode())
    out += sentence(f"GPRMC,120000.00,A,{la},{lah},{lo},{loh},{sog:.1f},{cog:.1f},180626,,,A".encode())
    out += sentence(f"GPVTG,{cog:.1f},T,,M,{sog:.1f},N,{sog*1.852:.1f},K,A".encode())
    return out


# spoof-position RMC body used as the base for Arm-2 char insertion
SPOOF_RMC_BODY = b"GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,,,A"
# field name -> comma-split index in SPOOF_RMC_BODY
FIELD_INDEX = {"time": 1, "lat": 3, "lon": 5, "sog": 7, "cog": 8, "date": 9}
# reserved / special characters to sweep
SPECIAL_CHARS = {
    "dollar": b"$", "bang": b"!", "star": b"*", "tilde": b"~",
    "del7F": b"\x7f", "cr": b"\r", "lf": b"\n", "nul": b"\x00",
}


def insert_char_in_field(body: bytes, field_idx: int, ch: bytes) -> bytes:
    """Insert `ch` into the middle of field `field_idx` (comma-split), keep the rest."""
    parts = body.split(b",")
    if field_idx >= len(parts):
        return body
    f = parts[field_idx]
    mid = len(f) // 2
    parts[field_idx] = f[:mid] + ch + f[mid:]
    return b",".join(parts)


def arm2_payload(char_name, pos_name):
    """Insert a special char at a named position. pos_name is either a field name
    (comma-split field) or a special structural position."""
    ch = SPECIAL_CHARS[char_name]
    if pos_name in FIELD_INDEX:
        body = insert_char_in_field(SPOOF_RMC_BODY, FIELD_INDEX[pos_name], ch)
        return sentence(body)
    if pos_name == "in_address":
        # inside the formatter: GPRMC -> GPR<ch>MC
        body = SPOOF_RMC_BODY[:4] + ch + SPOOF_RMC_BODY[4:]
        return sentence(body)
    if pos_name == "in_checksum":
        # inside the checksum hex field (makes it 3 chars) - tests checksum-field validation
        c = cksum(SPOOF_RMC_BODY)
        return b"$" + SPOOF_RMC_BODY + b"*" + c[:1] + ch + c[1:] + b"\r\n"
    return sentence(SPOOF_RMC_BODY)


# Arm-2 insertion positions: the 6 fields + 2 structural positions
ARM2_POSITIONS = list(FIELD_INDEX) + ["in_address", "in_checksum"]


# ---- Arm 3: strictness gradation sweeps (no timing hypothesis -> no phase loop) ----
def arm3_cases():
    """Cases that probe HOW STRICT validation is, by grading the malformation from
    near-miss to far-miss. All carry the spoof position so accept/degrade is visible."""
    cases = {}
    body = SPOOF_RMC_BODY
    good = cksum(body)                       # correct 2-hex checksum, e.g. b"7C"
    gi = int(good, 16)
    # --- checksum gradation: near-miss -> far-miss ---
    cases["cksOK_control"] = b"$" + body + b"*" + good + b"\r\n"           # VALID (positive control)
    cases["cks_off1bit"] = b"$" + body + b"*" + f"{gi ^ 0x01:02X}".encode() + b"\r\n"
    cases["cks_off1char"] = b"$" + body + b"*" + (bytes([good[0]]) +
                            (b"0" if good[1:2] != b"0" else b"1")) + b"\r\n"
    cases["cks_swapped"] = b"$" + body + b"*" + good[::-1] + b"\r\n"        # digit-swap
    cases["cks_far00"] = b"$" + body + b"*00\r\n"
    cases["cks_garbageZZ"] = b"$" + body + b"*ZZ\r\n"
    # --- field-length gradation: single oversized field vs oversized whole sentence ---
    # one DATA field (cog) padded with digits (numeric but over-long) - tests per-field
    # length enforcement (7.4c "data fields") distinctly from whole-sentence length
    def cog_padded(n):
        parts = body.split(b",")
        parts[FIELD_INDEX["cog"]] = b"90.0" + b"0" * n
        b = b",".join(parts)
        return b"$" + b + b"*" + cksum(b) + b"\r\n"
    cases["fieldlen_data_50"] = cog_padded(50)
    cases["fieldlen_data_200"] = cog_padded(200)
    cases["fieldlen_data_500"] = cog_padded(500)
    # oversized ADDRESS field (formatter blown out) - different clause path
    addr_body = b"GPRMC" + b"X" * 60 + body[5:]
    cases["fieldlen_addr_long"] = b"$" + addr_body + b"*" + cksum(addr_body) + b"\r\n"
    # whole-sentence oversized (reference point vs the single-field cases above)
    whole = body + b"," + b"9" * 120
    cases["fieldlen_whole_200"] = b"$" + whole + b"*" + cksum(whole) + b"\r\n"
    return cases


# ---- Arm-1 flaky cases (rebuilt inline; spoof position so acceptance is detectable) ----
def arm1_cases():
    cases = {}
    # embedded $ in a data field (consistent acceptor - positive control)
    cases["rsv_dollar_in_data"] = sentence(b"GPRMC,1200$00.00,A,4330.0000,N,07130.0000,W,0,0,180626,A,,A")
    # bare-LF terminator (accepted in an earlier run)
    cases["struct_only_lf"] = b"$" + SPOOF_RMC_BODY + b"*" + cksum(SPOOF_RMC_BODY) + b"\n"
    # two start delimiters / doubled end - structural ambiguity
    cases["struct_multi_end"] = b"$" + SPOOF_RMC_BODY + b"*" + cksum(SPOOF_RMC_BODY) + b"\r\n\r\n"
    # checksum computed without the commas (plausible-but-wrong)
    nocommas = SPOOF_RMC_BODY.replace(b",", b"")
    cases["spec_cks_excludes_commas"] = b"$" + SPOOF_RMC_BODY + b"*" + cksum(nocommas) + b"\r\n"
    # ---- negative controls: should ALWAYS be rejected ----
    cases["NEG_no_start_delim"] = SPOOF_RMC_BODY + b"*" + cksum(SPOOF_RMC_BODY) + b"\r\n"
    cases["NEG_cks_wrong_value"] = b"$" + SPOOF_RMC_BODY + b"*00\r\n"
    cases["NEG_edge_only_start"] = b"$*00\r\n"
    return cases


# ---- live AIS reader ----
class Reader(threading.Thread):
    def __init__(self, port, baud, cap_path, dry):
        super().__init__(daemon=True)
        self.dry = dry
        self.cap_path = cap_path
        self.port = port
        self.ser = None
        self.open_error = None
        if not (dry or not HAVE_SERIAL):
            try:
                self.ser = serial.Serial(port, baud, timeout=0.2)
            except Exception as e:
                self.open_error = e          # surfaced by the caller, not swallowed
        self.buf = []           # (t, raw) recent lines
        self.total_lines = 0    # everything seen on the wire (for liveness checks)
        self.read_errors = 0
        self.lock = threading.Lock()
        self.stop_flag = False
        self.fh = open(cap_path, "w")

    def run(self):
        if self.dry or self.ser is None:
            return
        while not self.stop_flag:
            try:
                line = self.ser.readline().decode("ascii", "replace").strip()
            except Exception:
                self.read_errors += 1
                line = ""
                time.sleep(0.05)
            if line:
                rec = (time.time(), line)
                with self.lock:
                    self.buf.append(rec)
                    self.total_lines += 1
                self.fh.write(json.dumps({"t": rec[0], "raw": rec[1]}) + "\n")
                self.fh.flush()

    def recent(self, since):
        with self.lock:
            return [(t, r) for (t, r) in self.buf if t >= since]

    def stop(self):
        self.stop_flag = True
        time.sleep(0.3)
        try:
            self.fh.close()
        except Exception:
            pass
        if self.ser:
            self.ser.close()


def decode_pos(raw):
    """Return (lat, lon) for an AIS position report, else None."""
    if not HAVE_PYAIS or not (raw.startswith("!AIV")):
        return None
    try:
        d = ais_decode(raw).asdict()
        if d.get("msg_type") in (1, 2, 3) and d.get("lat") is not None:
            return (d["lat"], d["lon"])
    except Exception:
        return None
    return None


def classify_positions(positions):
    """positions: list of (lat,lon). Return ACCEPTED / DEGRADED / REJECTED."""
    def is_nofix(p):
        return abs(p[0] - 91.0) < 0.1 and abs(p[1] - 181.0) < 0.1

    def near(p, lat, lon, tol=0.05):
        return abs(p[0] - lat) < tol and abs(p[1] - lon) < tol
    dev = [p for p in positions if not near(p, BASE_LAT, BASE_LON) and not is_nofix(p)]
    if dev:
        return "ACCEPTED"
    if any(is_nofix(p) for p in positions):
        return "DEGRADED"
    return "REJECTED"


def gps_writer(ser, dry, payload):
    if dry or ser is None:
        return
    ser.write(payload)
    ser.flush()


def near_baseline_pos(p, tol=0.05):
    return abs(p[0] - BASE_LAT) < tol and abs(p[1] - BASE_LON) < tol


def at_fix_now(reader, dry, lookback=12.0):
    """True if the unit emitted ANY baseline-fix position in the lookback window.
    No-fix sentences mixed in are ignored: some units (DY) interleave no-fix reports
    continuously even while healthy and holding a fix, so the presence of a single
    baseline fix in the window is what counts, not the absence of no-fix. Lookback is
    generous (12s) so a transient run of no-fix chatter can't cause a false negative."""
    if dry:
        return True
    for (t, raw) in reader.recent(time.time() - lookback):
        p = decode_pos(raw)
        if p and near_baseline_pos(p):
            return True
    return False


def ensure_baseline_fix(gps, reader, dry, max_wait):
    """Inject valid baseline GPS until the unit reports a baseline fix, up to
    max_wait seconds. Returns True iff a fix was established. This is the guard that
    prevents a too-short baseline from masquerading as a DEGRADED finding: if the unit
    cannot reach a fix, the trial is INVALID, not a result."""
    if dry:
        return True
    t0 = time.time()
    while time.time() - t0 < max_wait:
        gps_writer(gps, dry, gps_batch(BASE_LAT, BASE_LON))
        time.sleep(1.0)
        if at_fix_now(reader, dry):
            return True
    return False


def run_trial(gps, reader, dry, malformed, phase_ms, max_baseline_s, observe_s):
    """One independent trial. Each trial VERIFIES the unit is at a baseline fix before
    injecting; if it cannot establish one within max_baseline_s, the trial is INVALID
    (never scored as DEGRADED). Adaptive: a unit already at fix proceeds immediately;
    only a unit recovering from a prior degrade pays the reacquisition wait."""
    # 1) establish (or confirm) baseline fix - the precondition for a valid trial
    t_base0 = time.time()
    ok = ensure_baseline_fix(gps, reader, dry, max_baseline_s)
    base_wait = time.time() - t_base0
    if not ok:
        return "INVALID", {"phase_ms": phase_ms, "reason": "no baseline fix",
                           "base_wait_s": round(base_wait, 1)}
    # 2) phase-lock: wait for a fresh output tick, then phase_ms, then inject ONCE
    if not dry:
        tick = None
        wait_start = time.time()
        while time.time() - wait_start < 3.0:
            for (t, raw) in reader.recent(wait_start):
                if decode_pos(raw) is not None:
                    tick = t
                    break
            if tick:
                break
            time.sleep(0.05)
        time.sleep(phase_ms / 1000.0)
    inject_t = time.time()
    gps_writer(gps, dry, malformed)
    # 3) observe (no GPS injected) - see the unit's response to the malformed input
    if not dry:
        time.sleep(observe_s)
    obs = [decode_pos(raw) for (t, raw) in (reader.recent(inject_t) if not dry else [])]
    obs = [p for p in obs if p is not None]
    outcome = classify_positions(obs) if obs else ("REJECTED" if not dry else "DRY")
    return outcome, {"phase_ms": phase_ms, "n_obs": len(obs),
                     "base_wait_s": round(base_wait, 1), "inject_t": inject_t}


# ===================== analysis =====================
def analyze(rundir):
    meta = json.load(open(os.path.join(rundir, "metadata.json")))
    rows = [json.loads(l) for l in open(os.path.join(rundir, "trials.jsonl")) if l.strip()]
    vendor = meta.get("vendor", "?")
    print(f"\n=== repeatability / reserved-char sweep: {vendor} ===")
    print(f"trials/cell={meta.get('trials')}  phases={meta.get('phases')}\n")

    # ARM 1: acceptance fraction per (case, phase)
    arm1 = [r for r in rows if r["arm"] == 1]
    n_invalid = sum(1 for r in rows if r["outcome"] == "INVALID")
    if n_invalid:
        print(f"!! {n_invalid}/{len(rows)} trials were INVALID (unit not at a baseline fix "
              f"before injection) - excluded from fractions. If this is large, the run's\n"
              f"   timing was too short for this unit; results are unreliable.\n")
    if arm1:
        print("ARM 1 - flaky acceptance vs output-tick phase (fraction ACCEPTED, "
              "INVALID excluded):")
        cases = sorted({r["case"] for r in arm1})
        phases = sorted({r["phase_ms"] for r in arm1})
        hdr = "  " + f"{'case':28s}" + "".join(f"{('p'+str(p)):>9s}" for p in phases) + f"{'overall':>10s}"
        print(hdr)
        for c in cases:
            cell = []
            allk = alln = 0
            for p in phases:
                t = [r for r in arm1 if r["case"] == c and r["phase_ms"] == p
                     and r["outcome"] != "INVALID"]
                k = sum(1 for r in t if r["outcome"] == "ACCEPTED")
                cell.append(f"{k}/{len(t)}".rjust(9) if t else f"{'-':>9s}")
                allk += k; alln += len(t)
            frac = (allk / alln) if alln else 0.0
            tag = ""
            fracs = []
            for p in phases:
                t = [r for r in arm1 if r["case"] == c and r["phase_ms"] == p
                     and r["outcome"] != "INVALID"]
                if t:
                    fracs.append(sum(1 for r in t if r["outcome"] == "ACCEPTED") / len(t))
            if alln == 0:
                tag = "  <- ALL INVALID (no usable trials)"
            elif fracs and (max(fracs) - min(fracs)) >= 0.4:
                tag = "  <- PHASE-DEPENDENT (timing race)"
            elif frac >= 0.8:
                tag = "  <- reliable"
            elif 0.05 < frac < 0.8:
                tag = "  <- intermittent"
            elif frac == 0 and not c.startswith("NEG_"):
                tag = "  <- not reproduced this run"
            print("  " + f"{c:28s}" + "".join(cell) + f"{allk}/{alln}".rjust(10) + tag)
        print()

    # ARM 2: outcome distribution per (char, field)
    arm2 = [r for r in rows if r["arm"] == 2]
    if arm2:
        print("ARM 2 - reserved char x field -> outcome (A=accepted D=degraded R=rejected):")
        chars = sorted({r["char"] for r in arm2})
        fields = sorted({r["field"] for r in arm2})
        print("  " + f"{'char':10s}" + "".join(f"{f:>14s}" for f in fields))
        for ch in chars:
            cells = []
            for f in fields:
                t = [r for r in arm2 if r["char"] == ch and r["field"] == f
                     and r["outcome"] != "INVALID"]
                a = sum(1 for r in t if r["outcome"] == "ACCEPTED")
                d = sum(1 for r in t if r["outcome"] == "DEGRADED")
                rj = sum(1 for r in t if r["outcome"] == "REJECTED")
                if not t:
                    cells.append(f"{'(inv)':>14s}")
                else:
                    cells.append(f"A{a}/D{d}/R{rj}".rjust(14))
            print("  " + f"{ch:10s}" + "".join(cells))
        print("\n  (read across a row: does the SAME char behave differently by field?")
        print("   read down a column: do DIFFERENT chars behave differently in the same field?)")
        print()

    # ARM 3: strictness gradation
    arm3 = [r for r in rows if r["arm"] == 3]
    if arm3:
        print("ARM 3 - strictness gradation (A=accepted D=degraded R=rejected per N trials):")
        cases = sorted({r["case"] for r in arm3})
        for c in cases:
            t = [r for r in arm3 if r["case"] == c and r["outcome"] != "INVALID"]
            a = sum(1 for r in t if r["outcome"] == "ACCEPTED")
            d = sum(1 for r in t if r["outcome"] == "DEGRADED")
            rj = sum(1 for r in t if r["outcome"] == "REJECTED")
            tag = ""
            if c == "cksOK_control":
                tag = "  <- VALID; should ACCEPT (confirms rig)" if a > 0 else "  <- rejected a VALID sentence?!"
            elif c.startswith("cks_") and a > 0:
                tag = "  <- ACCEPTS a wrong checksum (NOT validating)"
            elif c.startswith("fieldlen_") and a > 0:
                tag = "  <- ACCEPTS oversized field (spoof)"
            elif c.startswith("fieldlen_") and d > 0:
                tag = "  <- oversized field -> DoS"
            print(f"  {c:22s} A{a}/D{d}/R{rj}{tag}")
        print("\n  (checksum row: near-miss accepted but far-miss rejected => format-check, not"
              " true validation. field-length: single oversized field vs whole-sentence.)")

    json.dump({"vendor": vendor, "n_trials": len(rows)},
              open(os.path.join(rundir, "summary_repeatability.json"), "w"))


# ===================== run =====================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gps", default="/dev/ttyUSB0")
    ap.add_argument("--ais", default="/dev/ttyUSB1")
    ap.add_argument("--vendor", default="unknown")
    ap.add_argument("--trials", type=int, default=12)
    ap.add_argument("--phases", default="0,250,500,750", help="phase offsets (ms) after a tick")
    ap.add_argument("--arm", default="both", choices=["both", "1", "2", "3"])
    ap.add_argument("--max-baseline-s", type=float, default=60.0,
                    help="max time to (re)establish a baseline fix before a trial; "
                         "must exceed the unit's reacquisition time (~30s) or trials go INVALID")
    ap.add_argument("--observe-s", type=float, default=12.0)
    ap.add_argument("--settle-s", type=float, default=120.0,
                    help="initial settle before any trials")
    ap.add_argument("--outdir", default="results")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--analyze", default=None, help="results dir to (re)analyze, no run")
    args = ap.parse_args()

    if args.analyze:
        analyze(args.analyze)
        return

    phases = [int(p) for p in args.phases.split(",")]
    a1 = arm1_cases()
    # Arm-2 grid: chars x positions (fields + structural positions)
    a2 = [(cn, pos) for cn in SPECIAL_CHARS for pos in ARM2_POSITIONS]
    a3 = arm3_cases()

    want = lambda n: args.arm in ("both", n)
    n1 = len(a1) * len(phases) * args.trials if want("1") else 0
    n2 = len(a2) * args.trials if want("2") else 0
    n3 = len(a3) * args.trials if want("3") else 0
    ntot = n1 + n2 + n3
    # adaptive timing: a trial costs ~ (small baseline confirm + observe) when the unit
    # stays at fix, or up to (max_baseline_s + observe) when it must reacquire after a
    # degrade. Estimate a midpoint so the number isn't wildly off either way.
    fast = 3 + args.observe_s            # unit already at fix
    slow = args.max_baseline_s + args.observe_s
    lo = ntot * fast / 3600.0
    hi = ntot * slow / 3600.0
    print(f"repeatability + reserved-char + strictness sweep: vendor={args.vendor}")
    print("  [run_repeatability v3: 12s fix-lookback, INVALID guard, adaptive timing]")
    print(f"ARM1 (phase) cases={list(a1)}")
    print(f"ARM2 (char x pos) chars={list(SPECIAL_CHARS)} positions={ARM2_POSITIONS}")
    print(f"ARM3 (strictness) cases={list(a3)}")
    print(f"=> {ntot} trials. Adaptive runtime ~{lo:.1f}-{hi:.1f} h "
          f"(fast when the unit stays at fix; slow when a degrade forces ~{args.max_baseline_s:.0f}s "
          f"reacquisition). tmux! (use --arm / --trials to subset)")
    if args.dry_run:
        print("(dry-run: no serial I/O; logic/structure check only)")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rundir = os.path.join(args.outdir, f"repeatability_{args.vendor}__{stamp}")
    os.makedirs(rundir, exist_ok=True)
    json.dump({"experiment": "repeatability", "vendor": args.vendor, "trials": args.trials,
               "phases": phases, "arm": args.arm, "max_baseline_s": args.max_baseline_s,
               "observe_s": args.observe_s, "start_utc": stamp},
              open(os.path.join(rundir, "metadata.json"), "w"), indent=2)

    reader = Reader(args.ais, AIS_BAUD, os.path.join(rundir, "capture.jsonl"), args.dry_run)
    if not args.dry_run:
        if reader.open_error is not None:
            print(f"!! ABORT: could not open AIS port {args.ais}: {reader.open_error}\n"
                  f"   Is another process holding it? (ps aux | grep run_)  Is the port name right?",
                  flush=True)
            return
        reader.start()
        # LIVENESS CHECK: confirm AIS lines are actually arriving before the 120s settle,
        # so a silent/busy/wrong port fails in ~10s instead of after minutes.
        print(f"checking AIS port {args.ais} is live...", flush=True)
        time.sleep(10)
        if reader.total_lines == 0:
            print(f"!! ABORT: no data on AIS port {args.ais} after 10s "
                  f"(read_errors={reader.read_errors}).\n"
                  f"   The reader is connected but the unit is silent on this port. Check:\n"
                  f"   (1) a previous run still holding the port (ps aux | grep run_; kill it),\n"
                  f"   (2) correct port name and baud ({AIS_BAUD}),\n"
                  f"   (3) the unit is powered and emitting (cat {args.ais} should show !AIV lines).",
                  flush=True)
            reader.stop()
            return
        print(f"  AIS port live: {reader.total_lines} lines in 10s.", flush=True)
    gps = None if args.dry_run or not HAVE_SERIAL else serial.Serial(args.gps, GPS_BAUD, timeout=1)
    trials_fh = open(os.path.join(rundir, "trials.jsonl"), "w")

    def log(rec):
        trials_fh.write(json.dumps(rec) + "\n"); trials_fh.flush()

    MB, OB = args.max_baseline_s, args.observe_s
    try:
        if not args.dry_run:
            # initial settle, then a STARTUP SELF-CHECK: the unit must reach a baseline
            # fix, or we abort now rather than waste the whole run producing INVALID
            # trials (this is the guard that catches a wrong port / too-short timing).
            print(f"settling {args.settle_s:.0f}s...", flush=True)
            t0 = time.time()
            while time.time() - t0 < args.settle_s:
                gps_writer(gps, args.dry_run, gps_batch(BASE_LAT, BASE_LON)); time.sleep(1.0)
            print("startup self-check: confirming the unit reaches a baseline fix...", flush=True)
            if not ensure_baseline_fix(gps, reader, args.dry_run, MB):
                recent = reader.recent(time.time() - 30)
                seen = {}
                for (t, raw) in recent:
                    p = decode_pos(raw)
                    if p:
                        key = ("fix" if near_baseline_pos(p) else
                               "nofix" if abs(p[0] - 91.0) < 0.1 else "other")
                        seen[key] = seen.get(key, 0) + 1
                print("!! ABORT: self-check did not see a baseline fix.", flush=True)
                print(f"   In the last 30s the unit emitted: {seen or 'NOTHING'}", flush=True)
                if seen.get("fix", 0) > 0:
                    print("   NOTE: baseline fixes WERE present - this is a code/version bug,\n"
                          "   not the unit. Confirm you are running run_repeatability v3.", flush=True)
                else:
                    print("   Check serial ports, GPS injection wiring, and that\n"
                          "   --max-baseline-s exceeds the unit's reacquisition time.", flush=True)
                return
            print("self-check OK: unit holds a fix. Starting trials.", flush=True)
        # ARM 1
        if want("1"):
            for case, payload in a1.items():
                for ph in phases:
                    for tr in range(args.trials):
                        oc, diag = run_trial(gps, reader, args.dry_run, payload, ph, MB, OB)
                        log({"arm": 1, "case": case, "phase_ms": ph, "trial": tr,
                             "outcome": oc, **diag})
                    print(f"  arm1 {case} phase={ph} done", flush=True)
        # ARM 2
        if want("2"):
            for (cn, pos) in a2:
                payload = arm2_payload(cn, pos)
                for tr in range(args.trials):
                    oc, diag = run_trial(gps, reader, args.dry_run, payload, 0, MB, OB)
                    log({"arm": 2, "char": cn, "field": pos, "trial": tr,
                         "outcome": oc, **diag})
                print(f"  arm2 {cn} x {pos} done", flush=True)
        # ARM 3 (strictness gradation - single phase, no timing hypothesis)
        if want("3"):
            for case, payload in a3.items():
                for tr in range(args.trials):
                    oc, diag = run_trial(gps, reader, args.dry_run, payload, 0, MB, OB)
                    log({"arm": 3, "case": case, "trial": tr, "outcome": oc, **diag})
                print(f"  arm3 {case} done", flush=True)
    finally:
        trials_fh.close()
        if not args.dry_run:
            reader.stop()
        if gps:
            gps.close()
    print(f"\nwrote {rundir}")
    if not args.dry_run:
        analyze(rundir)
    else:
        print("analyze: python3 run_repeatability.py --analyze " + rundir)


if __name__ == "__main__":
    main()
