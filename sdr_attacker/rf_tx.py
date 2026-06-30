#!/usr/bin/env python3
r"""
rf_tx.py -- transmit an AIS IQ file via the HackRF. CAGE-GATED.

** SAFETY **
Transmitting AIS (161.975 / 162.025 MHz) outside a sealed Faraday cage is illegal
(protected maritime safety band) and a navigation hazard: any real receiver in range
treats an injected frame as a real vessel. No transmit power is low enough to make
open-air transmission safe. This tool will NOT key the radio until you explicitly
confirm the cage is sealed (or pass --i-confirm-cage-sealed for unattended runs).
Every transmit is logged with a timestamp so the witness receiver's recording can be
matched against exactly what was sent.

It wraps `hackrf_transfer -t`. Input is interleaved int8 IQ (.cs8), the format
ais_encode.write_iq_file(..., fmt="cs8") produces and hackrf_transfer expects.

Typical loopback validation:
  # on the attacker Pi, cage sealed:
  python3 rf_tx.py --iq known.cs8 --channel B --once
  # on the listener Pi: record_ais.sh is running; check its NMEA for the message.

Flags of note (from hackrf_transfer):
  -t file   transmit from file        -f Hz   center frequency
  -s Hz     sample rate (>=2e6)       -x dB   TX VGA gain 0-47 (1 dB steps)
  -a 1/0    RF amp enable             -d sn   select HackRF by serial
"""
import argparse, os, subprocess, sys, time, json

# AIS channel center frequencies (Hz)
AIS_CHAN = {"A": 161_975_000, "B": 162_025_000}
DEFAULT_SAMPLE_RATE = 2_000_000     # HackRF minimum; must match the IQ file's rate
DEFAULT_TX_GAIN = 0                 # start at MINIMUM; cage coupling needs very little


def human_check_cage(skip):
    """Refuse to transmit until the operator confirms the cage is sealed.
    The whole safety model rests on this gate; do not weaken it."""
    if skip:
        return True
    print("=" * 68)
    print(" TRANSMIT SAFETY CHECK")
    print(" Transmitting AIS outside a sealed Faraday cage is illegal and a")
    print(" navigation-safety hazard. There is no safe open-air power level.")
    print("=" * 68)
    ans = input(" Type EXACTLY 'cage is sealed' to transmit (anything else aborts): ")
    if ans.strip() != "cage is sealed":
        print(" Aborted. Nothing transmitted.")
        return False
    return True


def preflight(iq_path, serial):
    """Fail fast on the obvious problems before keying anything."""
    if not os.path.exists(iq_path):
        print(f"!! IQ file not found: {iq_path}")
        return False
    size = os.path.getsize(iq_path)
    if size == 0:
        print(f"!! IQ file is empty: {iq_path}")
        return False
    if size % 2 != 0:
        print(f"!! IQ file size {size} is odd; cs8 must be interleaved I,Q (even).")
        return False
    # confirm hackrf_transfer exists and a device is present
    try:
        info = subprocess.run(["hackrf_info"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        print("!! hackrf_transfer/hackrf_info not found in PATH. Install hackrf tools.")
        return False
    if "No HackRF boards found" in (info.stdout + info.stderr) or info.returncode != 0:
        print("!! No HackRF detected (hackrf_info). Check USB/power.")
        print(info.stdout or info.stderr)
        return False
    if serial and serial not in info.stdout:
        print(f"!! HackRF serial {serial} not found among connected devices.")
        return False
    return True


def build_cmd(iq_path, freq_hz, sample_rate, tx_gain, amp, serial, repeat):
    cmd = ["hackrf_transfer", "-t", iq_path,
           "-f", str(freq_hz),
           "-s", str(sample_rate),
           "-x", str(tx_gain),
           "-a", "1" if amp else "0"]
    if serial:
        cmd += ["-d", serial]
    if repeat:
        cmd += ["-R"]   # repeat: loop the file (hackrf_transfer -R)
    return cmd


def main():
    ap = argparse.ArgumentParser(description="Transmit an AIS IQ file via HackRF (cage-gated).")
    ap.add_argument("--iq", required=True, help="interleaved int8 IQ file (.cs8)")
    ap.add_argument("--channel", choices=["A", "B"], default="B",
                    help="AIS channel: A=161.975 MHz, B=162.025 MHz (default B)")
    ap.add_argument("--freq", type=int, help="override center frequency in Hz")
    ap.add_argument("--sample-rate", type=int, default=DEFAULT_SAMPLE_RATE,
                    help="MUST match the rate the IQ file was generated at (default 2e6)")
    ap.add_argument("--tx-gain", type=int, default=DEFAULT_TX_GAIN,
                    help="TX VGA gain 0-47 dB. START LOW (0); cage coupling needs little. "
                         "Raise only if the receiver doesn't decode.")
    ap.add_argument("--amp", action="store_true",
                    help="enable the RF power amp. Leave OFF for cage loopback; "
                         "the extra power is unnecessary and risks overloading the receiver.")
    ap.add_argument("--serial", default="", help="HackRF serial (stable device selection)")
    ap.add_argument("--repeat", action="store_true",
                    help="loop the IQ file continuously (for disappearance/duration tests). "
                         "Ctrl-C to stop.")
    ap.add_argument("--once", action="store_true",
                    help="transmit the file exactly once (default if neither --repeat nor "
                         "--count given)")
    ap.add_argument("--count", type=int, default=1,
                    help="transmit the file N times with --gap seconds between (default 1)")
    ap.add_argument("--gap", type=float, default=2.0,
                    help="seconds between repeated single transmits (with --count)")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"),
                    help="where to write the transmit log")
    ap.add_argument("--label", default="", help="free-text label recorded in the log")
    ap.add_argument("--i-confirm-cage-sealed", action="store_true",
                    help="skip the interactive prompt (for scripted/unattended cage runs). "
                         "Use ONLY when the cage is verified sealed.")
    args = ap.parse_args()

    if args.tx_gain < 0 or args.tx_gain > 47:
        print("!! --tx-gain must be 0-47 dB"); sys.exit(2)
    if args.sample_rate < 2_000_000:
        print("!! HackRF minimum sample rate is 2 MHz; the IQ file must be generated "
              "at >= 2e6 too."); sys.exit(2)

    freq = args.freq if args.freq else AIS_CHAN[args.channel]

    if not preflight(args.iq, args.serial):
        sys.exit(1)

    print(f"about to transmit:")
    print(f"  file       : {args.iq} ({os.path.getsize(args.iq)} bytes)")
    print(f"  channel    : {args.channel}  ({freq/1e6:.3f} MHz)")
    print(f"  sample rate: {args.sample_rate} (MUST equal the file's generation rate)")
    print(f"  tx gain    : {args.tx_gain} dB    amp: {'ON' if args.amp else 'off'}")
    print(f"  mode       : {'repeat (loop)' if args.repeat else f'{args.count}x'}")
    print()

    if not human_check_cage(args.i_confirm_cage_sealed):
        sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    logpath = os.path.join(args.logdir, f"tx_{stamp}.jsonl")
    logf = open(logpath, "a", buffering=1)

    def log(event, **kw):
        rec = {"t": time.time(), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "event": event, **kw}
        logf.write(json.dumps(rec) + "\n")

    log("tx_session_start", iq=args.iq, channel=args.channel, freq_hz=freq,
        sample_rate=args.sample_rate, tx_gain=args.tx_gain, amp=bool(args.amp),
        label=args.label, repeat=bool(args.repeat), count=args.count)
    print(f"logging to {logpath}")

    cmd = build_cmd(args.iq, freq, args.sample_rate, args.tx_gain, args.amp,
                    args.serial, args.repeat)
    print("  $", " ".join(cmd))

    try:
        if args.repeat:
            log("tx_begin", mode="repeat")
            print("transmitting in a loop; Ctrl-C to stop.")
            subprocess.run(cmd)   # runs until Ctrl-C
            log("tx_end", mode="repeat")
        else:
            for i in range(args.count):
                log("tx_begin", mode="single", index=i)
                t0 = time.time()
                rc = subprocess.run(cmd).returncode
                log("tx_end", mode="single", index=i, rc=rc,
                    duration_s=round(time.time() - t0, 3))
                print(f"  sent {i+1}/{args.count} (rc={rc})")
                if i < args.count - 1:
                    time.sleep(args.gap)
    except KeyboardInterrupt:
        log("tx_interrupted")
        print("\ninterrupted; stopped transmitting.")
    finally:
        log("tx_session_end")
        logf.close()
        print(f"done. transmit log: {logpath}")
        print("Match this log's timestamps against the listener's NMEA recording.")


if __name__ == "__main__":
    main()
