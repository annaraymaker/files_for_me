#!/usr/bin/env python3
r"""
analyze_serial_cve.py -- disclosure-ready, per-finding CVE report for a serial_cve_suite.py run
(continuous-baseline / single-injection model), judged on BOTH interfaces.

Model: a valid baseline (42.35/-70.90) flows continuously; each probe is one injection carrying
the fixed SPOOF position 43.5/-71.5. So per probe, per interface (SERIAL = the unit's AIVDO
output; RF = its VHF transmissions):
  ACCEPTED      the SPOOF position appeared in the unit's output  -> it acted on bad input
  SMUGGLED      a smuggled 2nd sentence's position (44.5/-72.5) appeared -> parser differential
  DIFFERENTIAL  some other non-baseline position appeared (field-shift mis-parse)
  DEGRADED      the unit dropped to no-fix (91/181) above its background rate / went silent
  REJECTED      the unit held the baseline position (good)
For over-length probes it measures SUPPRESSION: the longest stretch with no valid baseline fix,
compared to predicted_s = N*10/baud (the transmit time). Suppression tracking predicted_s, and
growing with N, is the attacker-controlled DoS.

Usage: python3 analyze_serial_cve.py <manifest.jsonl> <serial_out.nmea> [vhf.nmea]
"""
import sys, json, math
from collections import Counter
try:
    from pyais import decode
except Exception:
    print("needs pyais: pip install pyais --break-system-packages"); sys.exit(1)

POS = {1, 2, 3}; TOL = 0.10


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
        r = dict(ep=ep, linelen=len(raw), own=raw.startswith('!AIVDO'), mmsi=None, type=None, lat=None, lon=None)
        if raw.startswith('!AIVDO') or raw.startswith('!AIVDM'):
            try:
                d = decode(raw).asdict(); r.update(mmsi=d.get('mmsi'), type=d.get('msg_type'),
                                                   lat=d.get('lat'), lon=d.get('lon'))
            except Exception: pass
        out.append(r)
    return out


def near(pos, ref):
    if pos is None or ref is None or ref[0] is None: return False
    dlat = pos[0] - ref[0]; dlon = (pos[1] - ref[1]) * math.cos(math.radians((pos[0] + ref[0]) / 2))
    return math.hypot(dlat, dlon) < TOL


def is_nofix(lat): return lat is not None and abs(lat) > 90


def max_gap(times, t0, t1):
    pts = [t0] + sorted(t for t in times if t0 <= t <= t1) + [t1]
    return max((b - a for a, b in zip(pts, pts[1:])), default=t1 - t0)


def iface_window(cap, isown, t0, t1, base, spoof, smuggle, bg_nofix_rate):
    """Classify one interface over a probe window. Returns verdict + suppression + counts."""
    msgs = [m for m in cap if t0 <= m['ep'] < t1 and isown(m) and m['type'] in POS and m['lat'] is not None]
    fixes = [(m['ep'], (m['lat'], m['lon'])) for m in msgs if not is_nofix(m['lat'])]
    nofix_t = [m['ep'] for m in msgs if is_nofix(m['lat'])]
    spoof_n = sum(1 for _, p in fixes if near(p, spoof))
    smug_n = sum(1 for _, p in fixes if smuggle and near(p, smuggle))
    base_n = sum(1 for _, p in fixes if near(p, base))
    other = [p for _, p in fixes if not near(p, base) and not near(p, spoof) and not (smuggle and near(p, smuggle))]
    dur = max(t1 - t0, 1e-6); exp_nofix = bg_nofix_rate * dur
    # DEGRADED = no-fix rose clearly above the unit's background chatter (recovery afterward,
    # which is expected, no longer suppresses the verdict).
    degraded = (len(nofix_t) - exp_nofix >= 3 and len(nofix_t) > 1.5 * max(exp_nofix, 1e-9))
    # suppression: longest stretch with no VALID BASELINE fix (DoS duration)
    supp = max_gap([t for t, p in fixes if near(p, base)], t0, t1)
    if spoof_n:          v = "ACCEPTED"
    elif smug_n:         v = "SMUGGLED"
    elif len(other) >= 2:v = "DIFFERENTIAL"           # >=2 to ignore a single stray/boundary msg
    elif degraded:       v = "DEGRADED"
    elif base_n:         v = "REJECTED"
    else:                v = "no-tx"
    return dict(v=v, supp=supp, spoof=spoof_n, base=base_n, nofix=len(nofix_t),
                other=(round(other[0][0], 2), round(other[0][1], 2)) if other else None)


def main():
    if len(sys.argv) < 3:
        print("usage: analyze_serial_cve.py <manifest.jsonl> <serial_out.nmea> [vhf.nmea]"); sys.exit(1)
    man = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    ser = load(sys.argv[2]); vhf = load(sys.argv[3]) if len(sys.argv) > 3 else []
    own = [m['mmsi'] for m in ser if m['own'] and m['mmsi'] is not None]
    if not own: print("ERROR: no !AIVDO own-tx in serial capture."); sys.exit(1)
    dut = Counter(own).most_common(1)[0][0]
    is_ser = lambda m: m['own']; is_rf = lambda m: m['mmsi'] == dut; have_rf = bool(vhf)

    ss = next((m for m in man if m.get('event') == 'session_start'), {})
    base = (ss.get('base_lat', 42.35), ss.get('base_lon', -70.90))
    begins = [m for m in man if m.get('event') == 'probe_start']
    # background no-fix rate from the clean settle (before the first probe)
    base_t = next((m['t'] for m in man if m.get('event') == 'baseline'), ss.get('t', 0))
    first = begins[0]['t'] if begins else base_t + 60
    span = max(first - base_t, 1e-6)
    bg_ser = sum(1 for m in ser if base_t <= m['ep'] < first and m['own'] and m['type'] in POS and is_nofix(m['lat'])) / span
    bg_rf = (sum(1 for m in vhf if base_t <= m['ep'] < first and is_rf(m) and m['type'] in POS and is_nofix(m['lat'])) / span) if have_rf else 0

    print(f"DUT MMSI {dut}   RF witness: {'yes' if have_rf else 'NONE'}   baseline {base}")
    print(f"background no-fix rate: serial {bg_ser:.3f}/s  RF {bg_rf:.3f}/s")

    rows = []
    for i, b in enumerate(begins):
        t0 = b['t']; t1 = begins[i + 1]['t'] if i + 1 < len(begins) else t0 + 120
        spoof = (b.get('spoof_lat'), b.get('spoof_lon'))
        sm = (b.get('smuggle_lat'), b.get('smuggle_lon')); sm = sm if sm[0] is not None else None
        s = iface_window(ser, is_ser, t0, t1, base, spoof, sm, bg_ser)
        r = iface_window(vhf, is_rf, t0, t1, base, spoof, sm, bg_rf) if have_rf else None
        overs = [m['linelen'] for m in ser if t0 <= m['ep'] <= t1 and m['linelen'] > 82]
        rows.append(dict(id=b['id'], finding=b.get('finding', ''), cve=b.get('cve', ''),
                         pred=b.get('predicted_s') or 0, sent_len=b.get('sent_len'),
                         s=s, r=r, emit=max(overs) if overs else None))

    def sc(x): return f"{x:.0f}s" if x is not None else "-"
    print("=" * 122)
    print(f"{'probe':22}{'finding':20}{'str':5}{'SERIAL':>13}{'supp':>6}   {'RF':>13}{'supp':>6}  {'emit':>5}")
    print("-" * 122)
    for r in rows:
        rf = r['r']
        rr = f"{rf['v']:>13}{sc(rf['supp']):>6}" if rf else f"{'-':>13}{'-':>6}"
        print(f"{r['id'][:21]:22}{r['finding'][:19]:20}{r['cve'][:4]:5}"
              f"{r['s']['v']:>13}{sc(r['s']['supp']):>6}   {rr}  {(str(r['emit']) if r['emit'] else '-'):>5}")

    # overlength DoS sweep: suppression vs predicted transmit time, both interfaces
    sweep = sorted([r for r in rows if r['finding'].startswith('1 ') and r['sent_len']], key=lambda r: r['sent_len'])
    if sweep:
        print("\n" + "=" * 84)
        print("OVERLENGTH DoS SWEEP -- suppression of legitimate reporting vs. input length")
        print(f"{'len':>7} {'pred_tx':>8} {'ser supp':>10} {'RF supp':>9} {'serial':>13} {'RF':>13}")
        print("-" * 84)
        for r in sweep:
            rf = r['r']
            print(f"{r['sent_len']:>7} {r['pred']:>7.1f}s {sc(r['s']['supp']):>10} "
                  f"{(sc(rf['supp']) if rf else '-'):>9} {r['s']['v']:>13} {(rf['v'] if rf else '-'):>13}")
        print("suppression ~ pred_tx and GROWING with length = attacker-controlled DoS (core CVE).")

    print("\n" + "=" * 122)
    print("CVE READ-OUT:")
    strong, parser, degrade, semantic, safe = [], [], [], [], []
    for r in rows:
        s, rf = r['s'], r['r']
        air = (rf and rf['v'] == "ACCEPTED")
        tag = "and BROADCAST over RF" if air else "(serial only; RF not confirmed)"
        if s['v'] == "ACCEPTED":
            if "checksum" in r['finding']:
                strong.append(f"{r['id']}: acts on data FAILING the checksum {tag}")
            elif r['cve'] == "SEMANTIC":
                semantic.append(f"{r['id']}: impossible/again-out-of-spec value propagated {tag}")
            else:
                strong.append(f"{r['id']}: malformed input accepted -> false position {tag}")
        if s['v'] in ("SMUGGLED", "DIFFERENTIAL"):
            parser.append(f"{r['id']}: {s['v'].lower()} confirmed on serial")
        if r['emit']:
            parser.append(f"{r['id']}: emits over-length output ({r['emit']} chars)")
        # DoS: over-length suppression tracking predicted transmit time
        if r['pred'] >= 2 and (s['supp'] >= 0.6 * r['pred'] or (rf and rf['supp'] >= 0.6 * r['pred'])):
            where = []
            if rf and rf['supp'] >= 0.6 * r['pred']: where.append(f"RF {sc(rf['supp'])}")
            if s['supp'] >= 0.6 * r['pred']: where.append(f"serial {sc(s['supp'])}")
            strong.append(f"{r['id']}: DoS -- reporting suppressed {', '.join(where)} (predicted {r['pred']:.0f}s)")
        elif s['v'] == "DEGRADED" or (rf and rf['v'] == "DEGRADED"):
            degrade.append(f"{r['id']}: unit dropped to no-fix (fix loss / robustness)")
        if s['v'] == "REJECTED" and (not rf or rf['v'] in ("REJECTED", "no-tx")):
            safe.append(r['id'])

    def blk(t, items):
        print(f"\n  {t}")
        for it in sorted(set(items)): print(f"    - {it}")
        if not items: print("    (none observed)")
    blk("STRONG CVE candidates (demonstrated):", strong)
    blk("Parser weaknesses with a demonstrated effect:", parser)
    blk("Robustness (fix-loss / degradation):", degrade)
    blk("Missing semantic validation:", semantic)
    if safe: print(f"\n  Rejected / not vulnerable: {', '.join(sorted(set(safe)))}")
    if not have_rf: print("\n  !! No VHF capture: RF effects UNCONFIRMED (pass the witness file as arg 3).")


if __name__ == "__main__":
    main()
