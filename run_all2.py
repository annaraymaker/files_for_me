#!/usr/bin/env python3
"""Overnight battery v2 for one vendor: run the 101-case conformance suite (then its
analyzer), then the repeatability + reserved-char + strictness deep-dive (which
self-analyzes). Skips the side-channel probe, which came back below its detection
floor and is not worth repeating per-vendor.

RESILIENT: a failure in one stage does not abort the other - conformance results
survive a deep-dive error and vice versa. Output STREAMS live to console and to a
timestamped master log (child processes are forced unbuffered, so per-case progress
appears in real time). Ctrl-C stops the current stage and still prints the summary.

USAGE
  tmux new -s ais
  python3 run_all2.py --gps /dev/ttyUSB0 --ais /dev/ttyUSB1 --vendor Furuno
  # detach: Ctrl-b d   reattach: tmux attach -t ais

OPTIONS
  --skip-conformance / --skip-deepdive    run only one stage
  --gap / --settle                        conformance timing
  --dd-trials / --dd-arm / --dd-phases    deep-dive config (see run_repeatability.py)
  --dd-baseline-s / --dd-observe-s / --dd-recovery-s
  --dry-run                               structure check, no serial I/O

Total ~= conformance (~90 min) + deep-dive (~13 h at 20 trials; tune --dd-trials).
"""
import argparse
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def ts():
    return datetime.now().strftime("%H:%M:%S")


def banner(msg, logf):
    line = "=" * 70
    for s in (line, f"  {msg}", line):
        print(s, flush=True)
        logf.write(s + "\n"); logf.flush()


def stream(cmd, logf):
    """Run cmd, streaming stdout+stderr live to console and log. Child forced
    UNBUFFERED so per-case progress appears in real time (Python block-buffers a
    pipe otherwise). Returns (returncode, captured_lines)."""
    logf.write(f"\n$ {' '.join(cmd)}\n"); logf.flush()
    print(f"\n$ {' '.join(cmd)}", flush=True)
    env = dict(os.environ); env["PYTHONUNBUFFERED"] = "1"
    lines = []
    proc = subprocess.Popen(cmd, cwd=HERE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    try:
        for line in proc.stdout:
            sys.stdout.write(line); sys.stdout.flush()
            logf.write(line); logf.flush()
            lines.append(line.rstrip("\n"))
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        raise
    return proc.returncode, lines


def find_rundir(lines):
    """Extract result dir from an 'analyze: ... <dir>' or 'wrote <dir>' line."""
    for line in reversed(lines):
        if "analyze:" in line and ".py" in line:
            return line.split(".py", 1)[1].strip().split()[0].replace("--analyze", "").strip()
    for line in reversed(lines):
        if line.strip().startswith("wrote "):
            return line.strip().split("wrote ", 1)[1].strip()
    return None


def run_stage(name, run_cmd, analyze_script, logf, results):
    """Run one stage. If analyze_script is None, the run self-analyzes (deep-dive).
    Never raises except KeyboardInterrupt."""
    banner(f"[{ts()}] START {name}", logf)
    t0 = time.time()
    try:
        rc, lines = stream(run_cmd, logf)
    except KeyboardInterrupt:
        results.append((name, "INTERRUPTED", None)); raise
    except Exception as e:
        banner(f"[{ts()}] {name} run ERRORED: {e}", logf)
        results.append((name, f"RUN-ERROR: {e}", None)); return
    if rc != 0:
        banner(f"[{ts()}] {name} run exited rc={rc} (continuing)", logf)
    rundir = find_rundir(lines)
    status = "OK" if rc == 0 else f"run_rc={rc}"
    if analyze_script and rundir:
        try:
            arc, _ = stream([sys.executable, "-u", analyze_script, rundir], logf)
            status = "OK" if (rc == 0 and arc == 0) else f"run_rc={rc},analyze_rc={arc}"
        except KeyboardInterrupt:
            results.append((name, "INTERRUPTED", rundir)); raise
        except Exception as e:
            status = f"ANALYZE-ERROR: {e}"
    elif analyze_script and not rundir:
        banner(f"[{ts()}] {name}: could not locate result dir to analyze", logf)
        status += " (no-result-dir)"
    dt = (time.time() - t0) / 60.0
    banner(f"[{ts()}] DONE {name} in {dt:.0f} min  ({status})", logf)
    results.append((name, status, rundir))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gps", default="/dev/ttyUSB0")
    ap.add_argument("--ais", default="/dev/ttyUSB1")
    ap.add_argument("--vendor", required=True)
    ap.add_argument("--skip-conformance", action="store_true")
    ap.add_argument("--skip-deepdive", action="store_true")
    # conformance
    ap.add_argument("--gap", type=float, default=50.0)
    ap.add_argument("--settle", type=float, default=120.0)
    # deep-dive (repeatability)
    ap.add_argument("--dd-trials", type=int, default=20)
    ap.add_argument("--dd-arm", default="both", choices=["both", "1", "2", "3"])
    ap.add_argument("--dd-phases", default="0,250,500,750")
    ap.add_argument("--dd-max-baseline-s", type=float, default=60.0)
    ap.add_argument("--dd-observe-s", type=float, default=12.0)
    ap.add_argument("--dd-settle-s", type=float, default=120.0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logpath = os.path.join(HERE, f"run_all2_{args.vendor}__{stamp}.log")
    logf = open(logpath, "w")

    banner(f"OVERNIGHT BATTERY v2  vendor={args.vendor}  start {ts()}", logf)
    print(f"master log: {logpath}", flush=True)
    print("stages: conformance (101 cases) -> deep-dive (repeatability+char+strictness)",
          flush=True)
    if args.dry_run:
        print("(DRY-RUN: no serial I/O)", flush=True)

    results = []
    py = sys.executable
    try:
        if not args.skip_conformance:
            cmd = [py, "-u", "run_conformance.py", "--gps", args.gps, "--ais", args.ais,
                   "--vendor", args.vendor, "--gap", str(args.gap),
                   "--settle", str(args.settle)]
            if args.dry_run:
                cmd.append("--dry-run")
            run_stage("CONFORMANCE", cmd, "analyze_conformance.py", logf, results)
        else:
            banner("skipping conformance", logf)

        if not args.skip_deepdive:
            cmd = [py, "-u", "run_repeatability.py", "--gps", args.gps, "--ais", args.ais,
                   "--vendor", args.vendor, "--trials", str(args.dd_trials),
                   "--arm", args.dd_arm, "--phases", args.dd_phases,
                   "--max-baseline-s", str(args.dd_max_baseline_s),
                   "--observe-s", str(args.dd_observe_s),
                   "--settle-s", str(args.dd_settle_s)]
            if args.dry_run:
                cmd.append("--dry-run")
            # deep-dive self-analyzes -> no separate analyzer script
            run_stage("DEEP-DIVE", cmd, None, logf, results)
        else:
            banner("skipping deep-dive", logf)
    except KeyboardInterrupt:
        banner(f"[{ts()}] INTERRUPTED by user", logf)

    banner(f"SUMMARY  vendor={args.vendor}  end {ts()}", logf)
    for name, status, rundir in results:
        line = f"  {name:12s} {status}"
        if rundir:
            line += f"\n               results: {rundir}"
        print(line, flush=True); logf.write(line + "\n")
    print(f"\nmaster log saved: {logpath}", flush=True)
    logf.write(f"\nmaster log saved: {logpath}\n"); logf.close()


if __name__ == "__main__":
    main()
