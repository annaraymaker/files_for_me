#!/usr/bin/env python3
"""Run the full spec-conformance suite against one transponder.

Model (different from the DoS runner): a CONTINUOUS valid GPS baseline is held on
the sensor port. Each test case is injected as a single perturbation against that
running-good state, with a long quiet gap (>= reacquisition latency) before and
after, so the analyzer can tell whether the unit:
  - REJECTED it  (output stayed on the valid baseline fix)   <- usually conformant
  - ACCEPTED it  (transmitted position/identity changed)     <- the real violation
  - DEGRADED     (went no-fix / dropped out)                 <- robustness problem
  - ALERTED      ($AIALC/ALR/PFEC)
A known-good control is injected every CONTROL_EVERY cases; if a control later
fails, you know exactly when the unit wedged.

Crash-safe / resumable:
  - capture.jsonl streams continuously to disk
  - events.jsonl gets a case_start/case_end per case as it happens
  - progress.json lists completed case ids; rerun with --resume to skip them

Usage:
  python3 run_conformance.py --gps /dev/ttyUSB0 --ais /dev/ttyUSB1 \
      --vendor furuno --gap 50
  python3 run_conformance.py ... --categories checksum,address   # subset
  python3 run_conformance.py ... --resume                        # continue a run
  python3 run_conformance.py ... --dry-run                       # no hardware
"""
import argparse, json, os, time, sys
from datetime import datetime, timezone

import serial
from capture import CaptureThread
import conformance_cases as cc
import nmea

CONTROL_EVERY = 5
BASELINE = (42.3500, -70.9000)


def log_event(path, d):
    with open(path, "a", buffering=1) as f:
        f.write(json.dumps({"t": time.time(), **d}) + "\n")


def emit(ser, dry, data, tag=""):
    if dry:
        print(f"    TX[{tag}] {data[:64]!r}")
        return
    ser.write(data)
    ser.flush()


def gps_baseline_burst(ser, dry):
    """One batch of valid GPS at the baseline position (SOG>0 -> fast reporting)."""
    for s in nmea.full_batch(BASELINE[0], BASELINE[1], sog=12.0, cog=90.0):
        emit(ser, dry, (s + "\r\n").encode(), "gps")


def hold_baseline(ser, dry, seconds, rate=1.0):
    end = time.time() + seconds
    while time.time() < end:
        gps_baseline_burst(ser, dry)
        if dry:
            return
        time.sleep(rate)


def run(gps_port, ais_port, gps_baud, ais_baud, vendor, gap, settle,
        categories, only_ids, resume, dry):
    cases = cc.get_cases(categories, only_ids)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = os.path.dirname(__file__)
    rundir = os.path.join(base, "results", f"conformance_{vendor}__{stamp}")
    # resume: find latest matching dir
    if resume:
        prior = sorted(d for d in os.listdir(os.path.join(base, "results"))
                       if d.startswith(f"conformance_{vendor}__"))
        if prior:
            rundir = os.path.join(base, "results", prior[-1])
            print(f"[resume] continuing {rundir}")
    os.makedirs(rundir, exist_ok=True)
    cap_path = os.path.join(rundir, "capture.jsonl")
    ev_path = os.path.join(rundir, "events.jsonl")
    prog_path = os.path.join(rundir, "progress.json")

    done = set()
    if resume and os.path.exists(prog_path):
        done = set(json.load(open(prog_path)).get("completed", []))
        print(f"[resume] {len(done)} cases already done, skipping them")

    meta = {
        "experiment": "spec_conformance", "vendor": vendor,
        "gps_port": gps_port, "ais_port": ais_port,
        "gps_baud": gps_baud, "ais_baud": ais_baud,
        "gap_s": gap, "settle_s": settle, "control_every": CONTROL_EVERY,
        "baseline": BASELINE, "n_cases": len(cases),
        "start_utc": datetime.now(timezone.utc).isoformat(),
        "start_t": time.time(), "dry_run": dry,
    }
    with open(os.path.join(rundir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)

    cap = CaptureThread(ais_port, ais_baud, cap_path, node=vendor)
    if not dry:
        cap.start(); time.sleep(1.0)

    gps = None if dry else serial.Serial(gps_port, gps_baud, timeout=1)

    # pre-flight: establish baseline and verify it's flowing
    print(f"[{vendor}] settling baseline {settle}s before first case...")
    log_event(ev_path, {"event": "preflight_settle", "seconds": settle})
    hold_baseline(gps, dry, settle)

    control = next(c for c in cc.CASES if c["id"] == "control_valid")
    completed = list(done)
    try:
        for i, case in enumerate(cases):
            if case["id"] in done:
                continue
            # periodic control injection
            if i > 0 and i % CONTROL_EVERY == 0:
                log_event(ev_path, {"event": "control_start", "seq": i})
                emit(gps, dry, control["gen"](), "control")
                log_event(ev_path, {"event": "control_end", "seq": i})
                hold_baseline(gps, dry, gap)

            # the case itself
            log_event(ev_path, {"event": "case_start", "id": case["id"],
                                "category": case["category"], "spec": case["spec"],
                                "transport": case["transport"], "expect": case["expect"]})
            print(f"  [{i+1}/{len(cases)}] {case['id']:28s} ({case['category']})")
            try:
                payload = case["gen"]()
                if case.get("seq") or (isinstance(payload, list)):
                    # sequence case: list of (delay_s, bytes) steps injected over time
                    for step in payload:
                        delay, data = step
                        if not dry:
                            time.sleep(delay)
                        emit(gps, dry, data, case["id"])
                else:
                    emit(gps, dry, payload, case["id"])
            except Exception as e:
                log_event(ev_path, {"event": "case_error", "id": case["id"], "error": str(e)})
            log_event(ev_path, {"event": "case_end", "id": case["id"]})

            # quiet recovery window: pure valid GPS so the unit can re-acquire and
            # so we can see whether output returns to the baseline fix
            log_event(ev_path, {"event": "recover_start", "id": case["id"], "seconds": gap})
            hold_baseline(gps, dry, gap)

            completed.append(case["id"])
            with open(prog_path, "w") as f:
                json.dump({"completed": completed}, f)
            if dry and i >= 3:
                print("  (dry-run: stopping after a few cases)")
                break
    finally:
        if gps:
            gps.close()
        meta["end_utc"] = datetime.now(timezone.utc).isoformat()
        meta["end_t"] = time.time()
        if not dry:
            time.sleep(1.0); cap.stop(); cap.join(timeout=3)
            meta["captured_lines"] = cap.lines
        with open(os.path.join(rundir, "metadata.json"), "w") as f:
            json.dump(meta, f, indent=2)
    print(f"\n[{vendor}] done. {len(completed)}/{len(cases)} cases. "
          f"{meta.get('captured_lines','(dry)')} lines captured.")
    print(f"  analyze: python3 analyze_conformance.py {rundir}")
    return rundir


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--gps", default="/dev/ttyUSB0")
    p.add_argument("--ais", default="/dev/ttyUSB1")
    p.add_argument("--gps-baud", type=int, default=4800)
    p.add_argument("--ais-baud", type=int, default=38400)
    p.add_argument("--vendor", required=True, help="label, e.g. furuno / emtrak / dy")
    p.add_argument("--gap", type=float, default=50.0, help="quiet seconds around each case (>= reacquisition)")
    p.add_argument("--settle", type=float, default=120.0, help="initial baseline settle")
    p.add_argument("--categories", default="", help="comma list to run a subset")
    p.add_argument("--ids", default="", help="comma list of specific case ids")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    cats = [c.strip() for c in a.categories.split(",") if c.strip()] or None
    ids = [c.strip() for c in a.ids.split(",") if c.strip()] or None
    run(a.gps, a.ais, a.gps_baud, a.ais_baud, a.vendor, a.gap, a.settle,
        cats, ids, a.resume, a.dry_run)


if __name__ == "__main__":
    main()
