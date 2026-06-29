#!/usr/bin/env python3
r"""
run_furuno_final.py  -  the LAST Furuno serial run.

Why this exists, in one breath: the generic deep-dive (run_repeatability.py) injects
the spoof as a BARE $GPRMC. em-trak and DY adopt a position from RMC alone, so their
deep-dives are valid. Furuno does NOT; it needs a full GGA+RMC+VTG batch to update its
fix. So in the Furuno deep-dive the spoof position NEVER appeared (the valid control
included), making every outcome uninformative. This script fixes that root cause: every
injected case is delivered as a FULL spoof-bearing batch (GGA+RMC+VTG), with the
malformation under test applied to the chosen sentence, so Furuno actually adopts the
position and acceptance becomes detectable. The accompanying GGA/VTG carry the SAME
spoof coordinates as the (possibly malformed) RMC, so a spoof sighting means the unit
adopted the batch that contained the malformed sentence, not a separate clean fix.

It covers exactly the things still genuinely open for Furuno, and nothing already
settled by its (full-batch, clean-7%-chatter) conformance run:

  PART A - sequence / plausibility, re-scored CORRECTLY (per-injected-step detection):
     seq_teleport            : pos jumps 43.5/-71.5 -> 45.5/-75.5  (does it follow the JUMP?)
     seq_position_walk       : pos advances, sog=0                 (does it emit the walk points?)
     seq_impossible_accel    : pos fixed, sog ramps 0..200         (does it emit the high SOG?)
     sem_speed_position_static: pos fixed, sog=60                  (does it emit + carry 60kn?)
   Scored by: for EACH injected step, did that exact position (teleport/walk) or that
   SOG (accel/static) appear in the unit's output within the step window? Not the
   single-spoof heuristic that mis-scored these before.

  PART B - reserved character x field (one rejection != all reject):
     chars: $ ! * ~ 0x7F   x  fields: lat lon sog (content) + address checksum (struct)
   Confirms whether Furuno is strict for ALL reserved chars in ALL fields, or (like
   em-trak/DY) only strict in structural fields while leaking some in content fields.

  PART C - checksum gradation (does it reject ALL bad checksums, or just some?):
     cksOK_control / off-by-1-char / swapped / far00 / garbageZZ
   Confirms the conformance \cE checksum cell reflects real validation, not one tolerance.

Run:
  python3 run_furuno_final.py --gps /dev/serial/by-id/... --ais /dev/serial/by-id/...
Analyze (same invocation, points at the run dir):
  python3 run_furuno_final.py --analyze results/furuno_final__<stamp>
"""
import argparse, json, os, sys, time

# Reuse the PROVEN machinery (Reader, guards, decode, timing) from the deep-dive.
import run_repeatability as rr
from run_repeatability import (
    Reader, decode_pos, at_fix_now, ensure_baseline_fix, gps_writer,
    cksum, sentence, _utc_fields, BASE_LAT, BASE_LON, SPOOF_LAT, SPOOF_LON,
    GPS_BAUD, AIS_BAUD, HAVE_PYAIS, PYAIS_ERR, HAVE_SERIAL,
)
if HAVE_SERIAL:
    import serial


# ---------------------------------------------------------------------------
# Full spoof-bearing batch builders. GGA + RMC + VTG all at the spoof position,
# so Furuno will adopt it. `rmc_body_override` lets a case supply a malformed RMC
# body; the GGA/VTG stay well-formed but carry the SAME coordinates, so adoption of
# the spoof means the batch (incl. the malformed RMC) was accepted.
# ---------------------------------------------------------------------------
def _coord_fields(lat, lon):
    latd = int(abs(lat)); latm = (abs(lat) - latd) * 60
    lond = int(abs(lon)); lonm = (abs(lon) - lond) * 60
    la = f"{latd:02d}{latm:07.4f}"; lah = "N" if lat >= 0 else "S"
    lo = f"{lond:03d}{lonm:07.4f}"; loh = "E" if lon >= 0 else "W"
    return la, lah, lo, loh


def full_batch(lat, lon, sog=0.0, cog=90.0, rmc_override=None):
    """GGA+RMC+VTG at (lat,lon). If rmc_override (bytes, full sentence incl $..*cc\\r\\n)
    is given, that exact RMC is used in place of the clean one (for malformed cases)."""
    la, lah, lo, loh = _coord_fields(lat, lon)
    tm, dt = _utc_fields()
    out = b""
    out += sentence(f"GPGGA,{tm},{la},{lah},{lo},{loh},1,08,0.9,10.0,M,0.0,M,,".encode())
    if rmc_override is not None:
        out += rmc_override
    else:
        out += sentence(f"GPRMC,{tm},A,{la},{lah},{lo},{loh},{sog:.1f},{cog:.1f},{dt},,,A".encode())
    out += sentence(f"GPVTG,{cog:.1f},T,,M,{sog:.1f},N,{sog*1.852:.1f},K,A".encode())
    return out


def clean_rmc(lat, lon, sog=0.0, cog=90.0):
    la, lah, lo, loh = _coord_fields(lat, lon)
    tm, dt = _utc_fields()
    return sentence(f"GPRMC,{tm},A,{la},{lah},{lo},{loh},{sog:.1f},{cog:.1f},{dt},,,A".encode())


# ---------------------------------------------------------------------------
# PART A: sequence / plausibility steps. Each step is (full_batch_bytes, expect),
# where expect describes what to look for in the output to call that step "adopted":
#   {"pos": (lat,lon)}  -> that position must appear
#   {"sog": value}      -> a position report carrying ~that SOG must appear
# ---------------------------------------------------------------------------
def seq_cases():
    S_LAT, S_LON = SPOOF_LAT, SPOOF_LON
    cases = {}

    # teleport: first point, then a far jump. The JUMP is the test.
    cases["seq_teleport"] = [
        (full_batch(S_LAT, S_LON, sog=0.0), {"pos": (S_LAT, S_LON)}),
        (full_batch(45.5, -75.5, sog=0.0), {"pos": (45.5, -75.5)}),
    ]
    # position walk: advance latitude in 1' steps with sog=0. Each advanced point is a step.
    walk = []
    for i in range(6):
        lat = S_LAT + i * (1.0 / 60.0)  # +1 arcmin per step
        walk.append((full_batch(lat, S_LON, sog=0.0), {"pos": (round(lat, 4), S_LON)}))
    cases["seq_position_walk"] = walk
    # impossible accel: fixed position, sog ramps. Each high SOG is a step.
    accel = []
    for sog in (0.0, 40.0, 80.0, 120.0, 160.0, 200.0):
        accel.append((full_batch(S_LAT, S_LON, sog=sog), {"sog": sog}))
    cases["seq_impossible_accel"] = accel
    # speed/position static: single batch, fixed pos, sog=60. Look for pos + 60kn SOG.
    cases["sem_speed_position_static"] = [
        (full_batch(S_LAT, S_LON, sog=60.0), {"pos": (S_LAT, S_LON), "sog": 60.0}),
    ]
    return cases


# ---------------------------------------------------------------------------
# PART B: reserved char x field. Build a malformed RMC (char inserted into a field),
# wrapped in a spoof-bearing batch so Furuno can still fix; acceptance = spoof appears.
# ---------------------------------------------------------------------------
RESERVED = {"dollar": b"$", "bang": b"!", "star": b"*", "tilde": b"~", "del7F": b"\x7f"}
FIELD_IDX = {"lat": 3, "lon": 5, "sog": 7}  # content fields
STRUCT = ("in_address", "in_checksum")


def reserved_field_payload(char_name, field_name):
    """Build a batch where the reserved char corrupts the SAME position field in BOTH
    GGA and RMC (for content fields), so the unit can only emit the spoof position if it
    parses PAST the reserved character. This avoids the confound where a clean GGA would
    fix the unit regardless of the malformed RMC. For structural fields (address/checksum)
    the corruption is RMC-only (those fields have no GGA analogue); acceptance there means
    the RMC was parsed despite the structural defect, with the GGA carrying the same
    coords (documented: structural-field result is RMC-tolerance given a valid GGA)."""
    ch = RESERVED[char_name]
    la, lah, lo, loh = _coord_fields(SPOOF_LAT, SPOOF_LON)
    tm, dt = _utc_fields()

    if field_name in FIELD_IDX:
        # corrupt the corresponding field in BOTH GGA and RMC
        def corrupt_rmc():
            body = f"GPRMC,{tm},A,{la},{lah},{lo},{loh},0.0,90.0,{dt},,,A".encode()
            parts = body.split(b","); idx = FIELD_IDX[field_name]
            parts[idx] = parts[idx][:2] + ch + parts[idx][2:]
            return sentence(b",".join(parts))
        def corrupt_gga():
            # GGA fields: 0 GPGGA,1 time,2 lat,3 N,4 lon,5 W,6 fix,7 sats,...
            gga_idx = {"lat": 2, "lon": 4, "sog": None}[field_name]
            body = f"GPGGA,{tm},{la},{lah},{lo},{loh},1,08,0.9,10.0,M,0.0,M,,".encode()
            if gga_idx is None:
                return sentence(body)  # sog has no GGA field; leave GGA clean
            parts = body.split(b",")
            parts[gga_idx] = parts[gga_idx][:2] + ch + parts[gga_idx][2:]
            return sentence(b",".join(parts))
        out = corrupt_gga() + corrupt_rmc()
        out += sentence(f"GPVTG,90.0,T,,M,0.0,N,0.0,K,A".encode())
        return out

    # structural fields: corrupt RMC only; GGA carries clean spoof coords
    body = f"GPRMC,{tm},A,{la},{lah},{lo},{loh},0.0,90.0,{dt},,,A".encode()
    if field_name == "in_address":
        body = body[:4] + ch + body[4:]
        rmc = sentence(body)
    elif field_name == "in_checksum":
        c = cksum(body)
        rmc = b"$" + body + b"*" + c[:1] + ch + c[1:] + b"\r\n"
    else:
        rmc = sentence(body)
    return full_batch(SPOOF_LAT, SPOOF_LON, rmc_override=rmc)


# ---------------------------------------------------------------------------
# PART C: checksum gradation. Malformed-checksum RMC in a spoof-bearing batch.
# NOTE: GGA/VTG are clean here, so if the unit adopts the spoof it could be via GGA.
# To make THIS test about the RMC checksum specifically, the batch is RMC-ONLY for
# Part C (no GGA/VTG); Furuno may then need the RMC alone to be valid. Since the
# cksOK_control is RMC-only too, the control tells us if RMC-only adoption works at all
# for Furuno; if the control fails, Part C is inconclusive (documented in analysis).
# ---------------------------------------------------------------------------
def checksum_cases():
    la, lah, lo, loh = _coord_fields(SPOOF_LAT, SPOOF_LON)
    tm, dt = _utc_fields()
    body = f"GPRMC,{tm},A,{la},{lah},{lo},{loh},0.0,90.0,{dt},,,A".encode()
    good = cksum(body)
    cases = {}
    cases["cksOK_control"] = b"$" + body + b"*" + good + b"\r\n"            # valid
    # off by one hex char in the checksum
    cases["cks_off1char"] = b"$" + body + b"*" + good[:1] + (b"F" if good[1:2] != b"F" else b"0") + b"\r\n"
    cases["cks_swapped"] = b"$" + body + b"*" + good[1:2] + good[:1] + b"\r\n"
    cases["cks_far00"] = b"$" + body + b"*00\r\n"
    cases["cks_garbageZZ"] = b"$" + body + b"*ZZ\r\n"
    # also a batch-wrapped control so we know full-batch adoption works for the run
    cases["cksOK_control_batch"] = full_batch(SPOOF_LAT, SPOOF_LON)
    return cases


# ---------------------------------------------------------------------------
# Injection + per-step observation
# ---------------------------------------------------------------------------
def observe_after(reader, dry, t_inject, window_s):
    """Return list of (lat,lon,sog) decoded from output in [t_inject, t_inject+window]."""
    if dry:
        return []
    out = []
    deadline = t_inject + window_s
    while time.time() < deadline:
        time.sleep(0.2)
    for (t, raw) in reader.recent(t_inject - 0.5):
        if t > deadline:
            continue
        if not raw.startswith("!AIV"):
            continue
        try:
            d = rr.ais_decode(raw).asdict()
            if d.get("msg_type") in (1, 2, 3) and d.get("lat") is not None:
                out.append((d["lat"], d["lon"], d.get("speed")))
        except Exception:
            pass
    return out


def pos_matches(obs, lat, lon, tol=0.03):
    return any(abs(o[0] - lat) < tol and abs(o[1] - lon) < tol for o in obs)


def sog_matches(obs, sog, tol=3.0):
    return any(o[2] is not None and abs(o[2] - sog) < tol for o in obs)


def run_seq_trial(gps, reader, dry, steps, step_window, settle_first, MB):
    """Inject a sequence; for each step record whether its expected pos/sog appeared."""
    if not ensure_baseline_fix(gps, reader, dry, MB):
        return {"valid": False, "reason": "no_baseline_fix"}
    results = []
    for (batch, expect) in steps:
        t0 = time.time()
        gps_writer(gps, dry, batch)
        obs = observe_after(reader, dry, t0, step_window)
        got = {}
        if "pos" in expect:
            got["pos_appeared"] = pos_matches(obs, expect["pos"][0], expect["pos"][1])
        if "sog" in expect:
            got["sog_appeared"] = sog_matches(obs, expect["sog"])
        got["expect"] = expect
        got["n_obs"] = len(obs)
        results.append(got)
    return {"valid": True, "steps": results}


def run_single_trial(gps, reader, dry, payload, window, MB):
    """Inject one payload; return whether the spoof position appeared (acceptance)."""
    if not ensure_baseline_fix(gps, reader, dry, MB):
        return {"valid": False, "reason": "no_baseline_fix"}
    t0 = time.time()
    gps_writer(gps, dry, payload)
    obs = observe_after(reader, dry, t0, window)
    return {"valid": True,
            "spoof_appeared": pos_matches(obs, SPOOF_LAT, SPOOF_LON),
            "n_obs": len(obs)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gps"); ap.add_argument("--ais")
    ap.add_argument("--analyze")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--trials", type=int, default=8, help="trials per case (B,C)")
    ap.add_argument("--seq-trials", type=int, default=6, help="repeats per sequence case")
    ap.add_argument("--step-window", type=float, default=10.0,
                    help="seconds to watch after each injected step (>= unit update period)")
    ap.add_argument("--single-window", type=float, default=12.0)
    ap.add_argument("--max-baseline-s", type=float, default=60.0)
    ap.add_argument("--settle-s", type=float, default=120.0)
    args = ap.parse_args()

    if args.analyze:
        return analyze(args.analyze)

    print("Furuno FINAL serial run (full-batch injection; seq + reserved-field + checksum)")
    print("  [fixes RMC-only adoption bug; sequence-aware scoring]")
    if not args.dry_run and not HAVE_PYAIS:
        print(f"!! ABORT: pyais not importable in {sys.executable}: {PYAIS_ERR}\n"
              f"   {sys.executable} -m pip install pyais --break-system-packages", flush=True)
        return
    if not args.dry_run and (not args.gps or not args.ais):
        print("!! need --gps and --ais (use /dev/serial/by-id/ paths)"); return
    if not args.dry_run and args.gps == args.ais:
        print("!! --gps and --ais are the same port"); return

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    rundir = os.path.join("results", f"furuno_final__{stamp}")
    os.makedirs(rundir, exist_ok=True)
    json.dump({"experiment": "furuno_final", "vendor": "Furuno", "start_utc": stamp,
               "step_window": args.step_window}, open(os.path.join(rundir, "metadata.json"), "w"))

    reader = Reader(args.ais, AIS_BAUD, os.path.join(rundir, "capture.jsonl"), args.dry_run)
    if not args.dry_run:
        if reader.open_error is not None:
            print(f"!! ABORT: cannot open AIS {args.ais}: {reader.open_error}"); return
        reader.start()
        time.sleep(10)
        if reader.total_lines == 0:
            print(f"!! ABORT: no AIS data in 10s on {args.ais}"); reader.stop(); return
        print(f"  AIS live: {reader.total_lines} lines/10s")
    gps = None
    if not args.dry_run:
        try:
            gps = serial.Serial(args.gps, GPS_BAUD, timeout=1)
        except Exception as e:
            print(f"!! ABORT: cannot open GPS {args.gps}: {e}"); reader.stop(); return

    out = open(os.path.join(rundir, "results.jsonl"), "w")
    MB = args.max_baseline_s

    if not args.dry_run:
        print(f"settling {args.settle_s:.0f}s...", flush=True)
        t = time.time()
        while time.time() - t < args.settle_s:
            gps_writer(gps, args.dry_run, full_batch(BASE_LAT, BASE_LON)); time.sleep(1.0)
        if not ensure_baseline_fix(gps, reader, args.dry_run, MB):
            print("!! ABORT: no baseline fix at start"); reader.stop(); return
        print("self-check OK: holds a fix. starting.", flush=True)

    # PART A: sequences
    print("PART A: sequence / plausibility (full-batch, per-step scoring)", flush=True)
    seqs = seq_cases()
    for cname, steps in seqs.items():
        for trial in range(args.seq_trials):
            r = run_seq_trial(gps, reader, args.dry_run, steps, args.step_window,
                              args.settle_s, MB)
            rec = {"part": "A", "case": cname, "trial": trial, **r}
            out.write(json.dumps(rec) + "\n"); out.flush()
            print(f"  A {cname} t{trial}: {'valid' if r.get('valid') else r.get('reason')}",
                  flush=True)

    # PART B: reserved char x field
    print("PART B: reserved char x field", flush=True)
    for cn in RESERVED:
        for fld in list(FIELD_IDX) + list(STRUCT):
            for trial in range(args.trials):
                payload = reserved_field_payload(cn, fld)
                r = run_single_trial(gps, reader, args.dry_run, payload, args.single_window, MB)
                rec = {"part": "B", "char": cn, "field": fld, "trial": trial, **r}
                out.write(json.dumps(rec) + "\n"); out.flush()
        print(f"  B {cn} done", flush=True)

    # PART C: checksum gradation
    print("PART C: checksum gradation", flush=True)
    cks = checksum_cases()
    for cname, payload in cks.items():
        for trial in range(args.trials):
            r = run_single_trial(gps, reader, args.dry_run, payload, args.single_window, MB)
            rec = {"part": "C", "case": cname, "trial": trial, **r}
            out.write(json.dumps(rec) + "\n"); out.flush()
        print(f"  C {cname} done", flush=True)

    out.close()
    if not args.dry_run:
        reader.stop()
    print(f"\nDONE. results in {rundir}\n  analyze: python3 run_furuno_final.py --analyze {rundir}")


def analyze(rundir):
    rows = [json.loads(l) for l in open(os.path.join(rundir, "results.jsonl")) if l.strip()]
    from collections import defaultdict

    # PART A: per sequence case, per step, fraction of trials where it appeared
    print("=== PART A: sequence / plausibility (per-step adoption) ===")
    A = [r for r in rows if r["part"] == "A"]
    bycase = defaultdict(list)
    for r in A:
        if r.get("valid"):
            bycase[r["case"]].append(r["steps"])
    for case, trials in bycase.items():
        nsteps = len(trials[0])
        print(f"\n{case}  ({len(trials)} valid trials):")
        for si in range(nsteps):
            exp = trials[0][si]["expect"]
            if "pos" in exp:
                hits = sum(1 for t in trials if t[si].get("pos_appeared"))
                print(f"  step{si} pos {exp['pos']}: appeared {hits}/{len(trials)}")
            if "sog" in exp:
                hits = sum(1 for t in trials if t[si].get("sog_appeared"))
                print(f"  step{si} sog {exp['sog']}kn: appeared {hits}/{len(trials)}")
        invalid = sum(1 for r in A if r["case"] == case and not r.get("valid"))
        if invalid:
            print(f"  ({invalid} invalid trials excluded)")

    # PART B: reserved char x field acceptance
    print("\n=== PART B: reserved char x field (spoof appeared = accepted) ===")
    B = [r for r in rows if r["part"] == "B" and r.get("valid")]
    agg = defaultdict(lambda: [0, 0])
    for r in B:
        agg[(r["char"], r["field"])][1] += 1
        if r.get("spoof_appeared"):
            agg[(r["char"], r["field"])][0] += 1
    chars = sorted(set(k[0] for k in agg))
    fields = ["lat", "lon", "sog", "in_address", "in_checksum"]
    hdr = f"  {'char':8s} " + " ".join(f"{f:>11s}" for f in fields)
    print(hdr)
    for ch in chars:
        cells = []
        for f in fields:
            a, n = agg[(ch, f)]
            cells.append(f"{a}/{n}")
        print(f"  {ch:8s} " + " ".join(f"{c:>11s}" for c in cells))
    print("  (content fields: lat/lon/sog ; structural: in_address/in_checksum)")

    # PART C: checksum gradation
    print("\n=== PART C: checksum gradation (spoof appeared = accepted bad checksum) ===")
    C = [r for r in rows if r["part"] == "C" and r.get("valid")]
    ck = defaultdict(lambda: [0, 0])
    for r in C:
        ck[r["case"]][1] += 1
        if r.get("spoof_appeared"):
            ck[r["case"]][0] += 1
    for case in ["cksOK_control", "cksOK_control_batch", "cks_off1char",
                 "cks_swapped", "cks_far00", "cks_garbageZZ"]:
        if case in ck:
            a, n = ck[case]
            print(f"  {case:22s}: accepted {a}/{n}")
    print("  read: if cksOK_control (RMC-only) is 0/n but cksOK_control_batch is n/n,")
    print("        Furuno needs the full batch to adopt and Part C (RMC-only) is")
    print("        inconclusive; rely on conformance for the checksum cell.")


if __name__ == "__main__":
    main()
