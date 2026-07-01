#!/usr/bin/env python3
r"""
rf_run_all.py -- fire every (or a selected) attack once, in succession, with a gap
between each, and write a timing manifest so the listener's decode can be matched back
to which attack produced it. This is the pre-transponder verification sweep: transmit
each SDR-injectable message and confirm the witness receiver decodes it as intended.

Requires ais-simulator.py already running (cage sealed) and websocket-client installed.

Usage (cage sealed):
    python3 rf_run_all.py                       # all attacks, 6s apart
    python3 rf_run_all.py --gap 8               # more spacing
    python3 rf_run_all.py --only ghost_ship interrogation reserved_values
    python3 rf_run_all.py --skip truncated_msg oversized_msg

After it finishes, stop the listener and send me:
    - the listener NMEA file (~/ais/ais_*.nmea)
    - this run's manifest (printed path at the end, ~/ais_tx/runall_*.jsonl)
so the two can be aligned by timestamp.
"""
import argparse, json, os, sys, time

try:
    import websocket
except Exception:
    websocket = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_attack as A


def main():
    ap = argparse.ArgumentParser(description="Fire all attacks in succession (verification sweep).")
    ap.add_argument("--url", default="ws://127.0.0.1:52002/ws")
    ap.add_argument("--gap", type=float, default=6.0,
                    help="seconds between attacks (>= the receiver's report window; "
                         "wide enough that each decode is unambiguously attributable)")
    ap.add_argument("--msg-gap", type=float, default=1.0,
                    help="seconds between multiple messages within one attack")
    ap.add_argument("--only", nargs="+", help="run only these attacks")
    ap.add_argument("--skip", nargs="+", default=[], help="skip these attacks")
    ap.add_argument("--n", type=int, default=6, help="fleet size for rapid_ghost_fleet")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    if websocket is None:
        print("!! needs websocket-client: pip install websocket-client --break-system-packages")
        sys.exit(1)

    # choose attack set, preserving definition order
    names = list(A.ATTACKS.keys())
    if args.only:
        names = [n for n in names if n in args.only]
    names = [n for n in names if n not in args.skip]
    if not names:
        print("no attacks selected."); sys.exit(2)

    print(f"verification sweep: {len(names)} attacks, {args.gap}s apart")
    print("  " + ", ".join(names))
    print(f"  target: {args.url}")
    print()
    print("  ais-simulator.py must be running (cage sealed). Each attack's messages")
    print("  transmit on the channel you launched the backend with.")
    print()

    if not args.i_confirm_cage_sealed:
        ans = input("Type EXACTLY 'cage is sealed' to transmit: ")
        if ans.strip() != "cage is sealed":
            print("Aborted."); sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    manifest = os.path.join(args.logdir, f"runall_{stamp}.jsonl")
    mf = open(manifest, "a", buffering=1)

    def rec(**kw):
        mf.write(json.dumps({"t": time.time(),
                             "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             **kw}) + "\n")

    rec(event="sweep_start", attacks=names, gap=args.gap)

    ws = websocket.create_connection(args.url, timeout=10)
    print(f"connected to {args.url}\n")
    try:
        for i, name in enumerate(names):
            fn = A.ATTACKS[name]
            payloads, desc = (fn(args.n) if name == "rapid_ghost_fleet" else fn())
            t_attack = time.time()
            rec(event="attack_begin", name=name, index=i, desc=desc,
                n_msgs=len(payloads))
            print(f"[{i+1}/{len(names)}] {name}  ({len(payloads)} msg) @ "
                  f"{time.strftime('%H:%M:%S')}")
            for j, (bits, meta) in enumerate(payloads):
                if any(c not in "01" for c in bits):
                    rec(event="skip_bad_payload", name=name, meta=meta); continue
                ws.send(bits)
                rec(event="sent", name=name, msg_index=j, meta=meta,
                    bits_len=len(bits))
                print(f"      -> {meta} ({len(bits)} bits)")
                if j < len(payloads) - 1:
                    time.sleep(args.msg_gap)
            rec(event="attack_end", name=name)
            if i < len(names) - 1:
                time.sleep(args.gap)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        rec(event="interrupted")
    finally:
        ws.close()
        rec(event="sweep_end")
        mf.close()

    print(f"\ndone. manifest: {manifest}")
    print("Now stop the listener and send me BOTH:")
    print(f"  - the listener NMEA (~/ais/ais_*.nmea)")
    print(f"  - this manifest ({manifest})")
    print("so decodes can be matched to attacks by timestamp.")


if __name__ == "__main__":
    main()
