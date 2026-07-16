#!/usr/bin/env python3
"""
analyze_m22.py -- obvious per-variant readout of the base-retest M22 channel-management tests.

For each M22 test window (single-channel txA/txB, single-AIS1, off-band retune, power-low; fired
both addressed and regional) it prints a plain verdict. Crucially, every verdict is GATED on a
coverage check: the listener must have actually been recording that window, proven by the
attacker's own injections appearing in it. If the injections are absent (recorder stalled), the
window is marked NO-COVERAGE instead of being misread as "the unit went silent / retuned". This is
the exact trap the first Digital Yacht run fell into -- the RF recorder stopped ~3 min before the
session ended, which looked like an M22 retune but was a dead capture.

Observables come from the AIS-catcher level JSON (the RF truth: per-message channel + signal
level), with the VHF NMEA as a backup channel source:
  txA_only / txB_only / single_ais1 -> DUT transmit-channel balance collapses toward one channel
  offband                            -> DUT disappears from the AIS pair while injections continue,
                                        and REAPPEARS in the following recovery window (reversible)
  power_low                          -> DUT received signal level drops (~11 dB for 12.5W -> 1W)

Usage: analyze_m22.py <manifest.jsonl> <vhf.nmea> <serial.nmea> <level.json>
Needs AIS-catcher run with per-message JSON incl. channel (and -M D for signal level on power-low).
"""
import sys, json, statistics
import analyze_effects as A


def load_lv(path):
    """level.json rows kept REGARDLESS of whether 'level' is populated (we need channel + mmsi for
    the channel/coverage tests even when the signal-level field is absent)."""
    out = []
    for l in open(path, errors='replace'):
        l = l.strip()
        if not l or l[0] != '{':
            continue
        try:
            d = json.loads(l)
        except Exception:
            continue
        ep = None
        for k in ('rxuxtime', 'rxtime', 'timestamp', 'time'):
            if k in d:
                ep = A.parse_rxtime(d[k])
                if ep is not None:
                    break
        if ep is None:
            continue
        lvl = d.get('level', d.get('signalpower'))
        try:
            lvl = float(lvl) if lvl is not None else None
        except (TypeError, ValueError):
            lvl = None
        ch = d.get('channel')
        ch = {'1': 'A', '2': 'B'}.get(ch, ch)
        out.append(dict(ep=ep, mmsi=d.get('mmsi'), channel=ch, level=lvl, type=d.get('type')))
    return out


def main():
    if len(sys.argv) < 5:
        print("usage: analyze_m22.py <manifest.jsonl> <vhf.nmea> <serial.nmea> <level.json>")
        sys.exit(1)
    man = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    vhf = A.load_nmea(sys.argv[2])
    serial = A.load_nmea(sys.argv[3])
    lv = load_lv(sys.argv[4])

    dy = A.pick_dy(serial)
    shift_inject, _ = A.calibrate_clocks(man, vhf, serial, dy)
    sh = shift_inject or 0

    # windows from the manifest (attacker frame -> listener frame via +sh), carrying the tags
    begins = [(m['t'] + sh, m.get('name', ''), m.get('command'), m.get('variant'), m.get('form'))
              for m in man if m.get('event') == 'attack_begin' and m.get('t')]
    wins = []
    for i, (t, n, cmd, var, form) in enumerate(begins):
        end = begins[i + 1][0] if i + 1 < len(begins) else t + 90
        wins.append(dict(name=n, cmd=cmd, var=var, form=form, t0=t, t1=end))

    def stats(t0, t1):
        dut = [x for x in lv if t0 <= x['ep'] < t1 and x['mmsi'] == dy]
        inj = [x for x in lv if t0 <= x['ep'] < t1 and x['mmsi'] is not None and x['mmsi'] != dy]
        a = sum(1 for x in dut if x['channel'] == 'A')
        b = sum(1 for x in dut if x['channel'] == 'B')
        lvls = [x['level'] for x in dut if x['level'] is not None]
        dur = max(t1 - t0, 1e-6)
        return dict(dut=len(dut), inj=len(inj), a=a, b=b, dur=dur,
                    fracA=(a / (a + b) if (a + b) else None),
                    rate=len(dut) / dur,
                    lvl=(statistics.median(lvls) if lvls else None))

    # baseline from control + recover windows (rate-matched, no command in force)
    def is_base(n):
        return 'control' in n or 'recover' in n
    ba = bb = 0
    blvls = []
    brates = []
    for w in wins:
        if is_base(w['name']):
            s = stats(w['t0'], w['t1'])
            ba += s['a']; bb += s['b']
            if s['lvl'] is not None:
                blvls.append(s['lvl'])
            if s['dut'] > 0:
                brates.append(s['rate'])
    base_fracA = ba / (ba + bb) if (ba + bb) else None
    base_lvl = statistics.median(blvls) if blvls else None
    base_rate = statistics.median(brates) if brates else None

    print("=" * 100)
    print(f"M22 CHANNEL-MANAGEMENT READOUT   DUT MMSI {dy}")
    print("=" * 100)
    print(f"baseline (control+recover): channel frac A={base_fracA if base_fracA is None else round(base_fracA,2)}, "
          f"DUT RF rate={base_rate if base_rate is None else round(base_rate,2)}/s, "
          f"recv level={base_lvl if base_lvl is None else round(base_lvl,1)} dB")
    if base_rate is None:
        print("  !! no baseline DUT RF messages -> cannot judge; is the level JSON from this run?")
    print()

    # recovery lookup: the window right after a test (for offband reappear check)
    def next_recover(idx):
        for j in range(idx + 1, len(wins)):
            if 'recover' in wins[j]['name']:
                return wins[j]
            break
        return None

    hdr = f"{'variant':13}{'form':10}{'cov?':6}{'DUTrf':>6}{'A/B':>9}{'fracA':>7}{'lvl dB':>8}   verdict"
    print(hdr); print("-" * 100)
    summary = {}
    for idx, w in enumerate(wins):
        if not w['name'].startswith('br_M22_'):
            continue
        s = stats(w['t0'], w['t1'])
        var = w['var'] or '?'
        form = w['form'] or '?'
        cov = s['inj'] > 0                       # recorder-alive guard: our injections present?
        if not cov:
            verdict = "NO-COVERAGE: no injections in window -> recorder not capturing; rerun"
        elif var in ('txA_only', 'txB_only', 'single_ais1'):
            if (s['a'] + s['b']) < 8:
                verdict = f"DUT nearly silent on AIS ({s['a']}/{s['b']}) while recorder live -> possible retune/silence"
            else:
                fa = s['fracA']
                if var == 'txB_only':
                    ok = fa is not None and fa <= 0.15
                else:                             # txA_only and single_ais1 both -> channel A (AIS1)
                    ok = fa is not None and fa >= 0.85
                verdict = f"balance A={fa:.2f} (base {base_fracA:.2f}) -> {'OBEYED (single-channel)' if ok else 'no shift'}"
        elif var == 'offband':
            expect = (base_rate or 0) * s['dur']
            vanished = s['dut'] <= max(2, 0.2 * expect)
            rec_note = ""
            r = next_recover(idx)
            if r is not None:
                rs = stats(r['t0'], r['t1'])
                if vanished and rs['dut'] >= max(3, 0.5 * (base_rate or 0) * rs['dur']):
                    rec_note = " + RETURNED after recovery (reversible)"
                elif vanished:
                    rec_note = " (did NOT return in recovery window -- check it recovered)"
            verdict = (f"DUT RF={s['dut']} (base~{expect:.0f}), inj={s['inj']} -> "
                       f"{'OBEYED: vanished from AIS while recorder live' + rec_note if vanished else 'still on AIS (ignored)'}")
        elif var == 'power_low':
            if s['lvl'] is None or base_lvl is None:
                verdict = "no signal-level data -> run AIS-catcher with -M D (level output) to test power-low"
            else:
                drop = s['lvl'] - base_lvl
                verdict = f"level {s['lvl']:.1f} (base {base_lvl:.1f}), delta {drop:+.1f} dB -> {'OBEYED: power dropped' if drop <= -3 else 'no drop'}"
        else:
            verdict = "unknown variant"
        fa_s = f"{s['fracA']:.2f}" if s['fracA'] is not None else "-"
        lvl_s = f"{s['lvl']:.1f}" if s['lvl'] is not None else "-"
        ab_s = f"{s['a']}/{s['b']}"
        cov_s = 'yes' if cov else 'NO'
        print(f"{var:13}{form:10}{cov_s:6}{s['dut']:>6}{ab_s:>9}{fa_s:>7}{lvl_s:>8}   {verdict}")
        summary.setdefault(var, {})[form] = ('OBEYED' in verdict, cov, verdict)

    print("-" * 100)
    print("cov?=were the attacker's own injections present in the window (recorder alive). A NO here")
    print("means the capture is dead for that window -- ignore the row and rerun, do NOT read it as")
    print("a retune. addressed vs regional: a unit may honour one form and not the other (per spec).")

    # addressed-vs-regional contrast per variant
    print("\nADDRESSED vs REGIONAL")
    print("-" * 100)
    for var, forms in summary.items():
        a = forms.get('addressed'); r = forms.get('regional')
        def tag(x):
            if x is None: return "n/a"
            obeyed, cov, _ = x
            return ("no-coverage" if not cov else ("OBEYED" if obeyed else "ignored"))
        print(f"  {var:13} addressed={tag(a):12} regional={tag(r):12}")
    print("\nKEY: OBEYED from a forged, unauthenticated base (MMSI + M4 both spoofable) is the")
    print("     security finding. 'ignored' with full coverage is a real conformance result; a")
    print("     NO-COVERAGE row proves nothing either way -- rerun with the recorder kept alive.")


if __name__ == "__main__":
    main()
