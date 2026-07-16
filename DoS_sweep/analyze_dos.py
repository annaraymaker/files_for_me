#!/usr/bin/env python3
r"""
analyze_dos.py -- extract the DoS signal from a serial_dos_sweep.py run and decide whether the
over-length finding is a WEAPON (amplification / persistence) or merely a CONFORMANCE cell
(the unit ignores the mandated 82-char bound, but the outage is just line occupancy).

For each injected length it measures, from the unit's OWN serial output (!AIVDO position reports):
  OUTAGE  = longest stretch inside the probe window with no valid own position (vessel off the map)
  REACQ   = time from the end of the malformed write to the FIRST valid report afterward
            (the recovery penalty AFTER the bus is already free)
and compares both to the transmission time  tx = actual_len / (baud/10).

Verdicts the tool prints, because they are what a reviewer will ask for:
  * BOUNDED          outage ~ 0  -> the unit enforced the length bound (secure; Furuno-like).
  * OCCUPANCY        outage ~ tx, reacq ~ 0 -> pure line monopoly. NOT unique given serial control;
                     report as a conformance failure (IEC 61162-1 7.3.1 "shall" not enforced), not a DoS.
  * AMPLIFIED        outage > tx by a clear margin, or reacq large -> one write buys disproportionate
                     silence; the attacker no longer needs to HOLD the bus. This is the finding worth a figure.
The KNEE is the smallest length that stops being BOUNDED -- the point the parser gives up.

Sustained mode (if present) reports total dark time across the back-to-back stream and the recovery
after it stops: the "held dark for as long as the attacker types" panel.

Usage: python3 analyze_dos.py <manifest.jsonl> <unit_serial_out.nmea> [vhf.nmea] [--csv out.csv]
"""
import sys, json, math, argparse, statistics
from collections import defaultdict, Counter
try:
    from pyais import decode
except Exception:
    print("needs pyais: pip install pyais --break-system-packages"); sys.exit(1)

POS = {1, 2, 3}
FIX_CADENCE = 2.0   # the fast AIS report interval; a "gap" only counts as outage beyond this


def parse_ts(s):
    from datetime import datetime
    try: return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()
    except Exception: return None


def load(path):
    out = []
    for l in open(path, errors='replace'):
        if '\t' not in l: continue
        ts, raw = l.split('\t', 1); raw = raw.rstrip('\r\n'); ep = parse_ts(ts)
        if ep is None: continue
        r = dict(ep=ep, own=raw.startswith('!AIVDO'), mmsi=None, type=None, lat=None)
        if raw.startswith('!AIVDO') or raw.startswith('!AIVDM'):
            try:
                d = decode(raw).asdict()
                r.update(mmsi=d.get('mmsi'), type=d.get('msg_type'), lat=d.get('lat'))
            except Exception:
                pass
        out.append(r)
    return out


def is_nofix(lat): return lat is None or abs(lat) > 90


def valid_fix_times(cap, isown, t0, t1):
    return sorted(m['ep'] for m in cap
                  if t0 <= m['ep'] <= t1 and isown(m) and m['type'] in POS and not is_nofix(m['lat']))


def max_gap(times, t0, t1):
    pts = [t0] + [t for t in times if t0 <= t <= t1] + [t1]
    return max((b - a for a, b in zip(pts, pts[1:])), default=t1 - t0)


def reacq_after(times, tw, t1):
    nxt = next((t for t in times if t >= tw), None)
    return (nxt - tw) if nxt is not None else (t1 - tw)


def summarize(vals):
    vals = list(vals)
    if not vals: return (None, None, None)
    return (statistics.median(vals), min(vals), max(vals))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest"); ap.add_argument("serial_out"); ap.add_argument("vhf", nargs="?")
    ap.add_argument("--csv")
    ap.add_argument("--amp-abs", type=float, default=4.0,
                    help="seconds of silence BEYOND (write time + one report quantum) to call it "
                         "AMPLIFIED -- real penalty, not cadence noise (default 4 s)")
    ap.add_argument("--bound-thresh", type=float, default=2.0,
                    help="outage at/below (one quantum + this) = the unit BOUNDED the input (secure)")
    args = ap.parse_args()

    man = [json.loads(l) for l in open(args.manifest) if l.strip()]
    ser = load(args.serial_out); vhf = load(args.vhf) if args.vhf else []
    own = [m['mmsi'] for m in ser if m['own'] and m['mmsi'] is not None]
    if not own: print("ERROR: no !AIVDO own-tx in serial capture."); sys.exit(1)
    dut = Counter(own).most_common(1)[0][0]
    is_ser = lambda m: m['own']; is_rf = lambda m: m['mmsi'] == dut
    have_rf = bool(vhf)
    ss = next((m for m in man if m.get('event') == 'session_start'), {})
    baud = ss.get('gps_baud', 4800); cps = baud / 10.0

    starts = [m for m in man if m.get('event') == 'probe_start']
    ends = {m['id']: m for m in man if m.get('event') == 'probe_end'}

    # per-probe measurement, keyed by (nominal length, kind) so unterminated is separate
    per_len = defaultdict(lambda: dict(tx=0, alen=0, out=[], reacq=[], rout=[], wedge=0, n=0))
    wedge_from = None
    for i, b in enumerate(starts):
        t0 = b['t']
        t1 = starts[i + 1]['t'] if i + 1 < len(starts) else t0 + b.get('predicted_s', 0) + 60
        tw = ends.get(b['id'], {}).get('t', t0 + b.get('predicted_s', 0))
        alen = b.get('length', b.get('nominal')); nominal = b.get('nominal', alen)
        kind = b.get('kind', 'sweep')
        st = valid_fix_times(ser, is_ser, t0, t1)
        outage = max_gap(st, t0, t1); reacq = reacq_after(st, tw, t1)
        # WEDGED: no valid fix anywhere after the write finished, across a window long enough to
        # have expected several -> a hang / reset the unit did not self-recover from in this window.
        post = [t for t in st if t >= tw]
        wedged = (len(post) == 0 and (t1 - tw) > 4 * FIX_CADENCE)
        if wedged and wedge_from is None:
            wedge_from = (nominal, kind)
        d = per_len[(nominal, kind)]; d['tx'] = alen / cps; d['alen'] = alen; d['n'] += 1
        d['out'].append(outage); d['reacq'].append(max(0.0, reacq)); d['wedge'] += int(wedged)
        if have_rf:
            rt = valid_fix_times(vhf, is_rf, t0, t1)
            d['rout'].append(max_gap(rt, t0, t1))

    keys = sorted(per_len, key=lambda k: (k[1] != 'sweep', k[0]))  # sweep first, then unterm, by len
    print(f"DUT MMSI {dut}   baud {baud} ({cps:.0f} cps)   RF witness: {'yes' if have_rf else 'NONE'}")
    print("=" * 100)
    print(f"{'len':>7}{'kind':>8}{'tx_s':>8}{'outage_med':>12}{'[min,max]':>14}{'reacq_med':>11}"
          f"{'out/tx':>8}{'verdict':>11}")
    print("-" * 100)

    rows = []
    knee = None
    for k in keys:
        nominal, kind = k; d = per_len[k]
        om, olo, ohi = summarize(d['out']); rm, rlo, rhi = summarize(d['reacq'])
        rout_m = summarize(d['rout'])[0] if d['rout'] else None
        ratio = (om / d['tx']) if (om is not None and d['tx'] > 0.5) else None
        # excess = silence BEYOND what pure line-occupancy explains (write time + one report
        # quantum you can always straddle). Only excess this large is real amplification; it
        # keeps the 2 s report cadence from inflating the ratio at small lengths.
        excess = (om - d['tx'] - FIX_CADENCE) if om is not None else None
        if d['wedge'] and d['wedge'] >= max(1, d['n'] // 2):
            v = "WEDGED"                                     # unit never came back after the write
        elif om is not None and om <= FIX_CADENCE + args.bound_thresh and (excess is None or excess < args.amp_abs):
            v = "BOUNDED"                                    # unit ignored the over-length input
        elif (excess is not None and excess >= args.amp_abs) or (rm is not None and rm > 3 * FIX_CADENCE):
            v = "AMPLIFIED"                                  # penalty beyond line time (or slow recovery)
        else:
            v = "OCCUPANCY"                                  # outage tracks the write time, nothing more
        if knee is None and kind == 'sweep' and v not in ("BOUNDED",):
            knee = nominal
        print(f"{d['alen']:>7}{kind:>8}{d['tx']:>8.1f}{(f'{om:.1f}s' if om is not None else '-'):>12}"
              f"{(f'[{olo:.0f},{ohi:.0f}]' if om is not None else '-'):>14}"
              f"{(f'{rm:.1f}s' if rm is not None else '-'):>11}"
              f"{(f'{ratio:.2f}' if ratio is not None else '-'):>8}{v:>11}")
        rows.append(dict(nominal=nominal, kind=kind, alen=d['alen'], tx=d['tx'], n=d['n'],
                         out_med=om, out_min=olo, out_max=ohi,
                         reacq_med=rm, reacq_min=rlo, reacq_max=rhi,
                         rf_out_med=rout_m, ratio=ratio, verdict=v, wedge=d['wedge']))

    # ---- sustained ----
    sstart = next((m for m in man if m.get('event') == 'sustained_start'), None)
    send = next((m for m in man if m.get('event') == 'sustained_end'), None)
    sustained = None
    if sstart:
        t0 = sstart['t']; t1 = (send['t'] if send else t0 + sstart.get('target_s', 0))
        recov_end = t1 + sstart.get('predicted_s', 0) + 60
        st_all = valid_fix_times(ser, is_ser, t0, recov_end)
        dark = max_gap(valid_fix_times(ser, is_ser, t0, t1), t0, t1)
        recov = reacq_after(st_all, t1, recov_end)
        sustained = dict(target=sstart.get('target_s'), writes=(send or {}).get('writes'),
                         dark=dark, recov=max(0.0, recov), alen=sstart.get('length'))

    # ---- headline verdict ----
    print("\n" + "=" * 92)
    amp = [r for r in rows if r['verdict'] == "AMPLIFIED"]
    occ = [r for r in rows if r['verdict'] == "OCCUPANCY"]
    bnd = [r for r in rows if r['verdict'] == "BOUNDED"]
    print("HEADLINE READ-OUT")
    if wedge_from is not None:
        wn, wk = wedge_from
        print(f"  -> WEDGED at {wn} chars ({wk}): the unit stopped reporting and did not self-recover "
              f"in-window -> likely a hang/reset needing a power-cycle. This is the STRONGEST persistence")
        print(f"     result (withholding GPS never does this) -- BUT probes after it may be invalid; "
              f"confirm the unit was reset before trusting later rows.")
    if bnd and not occ and not amp:
        print("  -> unit BOUNDED every length. It enforces the 82-char limit: SECURE (Furuno-like).")
    else:
        if knee: print(f"  -> KNEE at ~{knee} chars: below this the unit bounds the input, at/above it the outage sets in.")
        if amp:
            worst = max(amp, key=lambda r: (r['ratio'] or 0))
            print(f"  -> AMPLIFIED: e.g. {worst['alen']} chars -> {worst['out_med']:.0f}s outage vs "
                  f"{worst['tx']:.0f}s on the wire (x{worst['ratio']:.1f}); one write buys disproportionate "
                  f"silence -> the attacker need NOT hold the bus. THIS is the figure-worthy finding.")
        # persistence only counts from sweep rows that did NOT wedge (a wedge's reacq is a fallback)
        maxreacq = max((r['reacq_med'] or 0) for r in rows if r['verdict'] != "WEDGED")
        if maxreacq > 3 * FIX_CADENCE:
            print(f"  -> PERSISTENCE: recovery takes up to {maxreacq:.0f}s AFTER the line is free "
                  f"(vs ~{FIX_CADENCE:.0f}s normal) -> a penalty withholding GPS cannot cause.")
        if occ and not amp and wedge_from is None and maxreacq <= 3 * FIX_CADENCE:
            print("  -> OCCUPANCY only: outage ~ line time, instant recovery. Given serial control this is")
            print("     NOT a unique DoS -- report it as a CONFORMANCE failure (IEC 61162-1 7.3.1 'shall'")
            print("     unenforced), not a weapon. The unique remote denial is the RF M16 rate command.")
    if sustained and sustained['dark'] is not None:
        print(f"  -> SUSTAINED: {sustained['writes']} back-to-back writes held the vessel dark "
              f"{sustained['dark']:.0f}s (target {sustained['target']:.0f}s); recovered {sustained['recov']:.0f}s "
              f"after the stream stopped. -> silence lasts as long as the attacker keeps the bus.")

    # ---- CSV ----
    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["nominal_len", "kind", "actual_len", "tx_pred_s", "n_reps",
                        "outage_med_s", "outage_min_s", "outage_max_s",
                        "reacq_med_s", "reacq_min_s", "reacq_max_s",
                        "rf_outage_med_s", "outage_over_tx", "wedged_reps", "verdict"])
            for r in rows:
                w.writerow([r['nominal'], r['kind'], r['alen'], round(r['tx'], 3), r['n'],
                            _r(r['out_med']), _r(r['out_min']), _r(r['out_max']),
                            _r(r['reacq_med']), _r(r['reacq_min']), _r(r['reacq_max']),
                            _r(r['rf_out_med']), _r(r['ratio']), r['wedge'], r['verdict']])
        # sustained appended as a comment-less second file for the timeline plot
        if sustained:
            with open(args.csv.replace(".csv", "_sustained.csv"), "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["target_s", "writes", "dark_s", "recovery_s", "actual_len"])
                w.writerow([_r(sustained['target']), sustained['writes'],
                            _r(sustained['dark']), _r(sustained['recov']), sustained['alen']])
        print(f"\nwrote {args.csv}" + (" (+ _sustained.csv)" if sustained else "")
              + "  -> feed to plot_dos.py")


def _r(x): return "" if x is None else round(x, 3)


if __name__ == "__main__":
    main()
