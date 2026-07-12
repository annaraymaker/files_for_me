#!/usr/bin/env python3
r"""
analyze_serial_cve.py -- turn a serial_cve_suite.py run into a DISCLOSURE-READY, per-finding
CVE report, measuring the effect on BOTH interfaces the transponder exposes:
  SERIAL  the unit's own AIS output port (its AIVDO position reports)
  RF      the unit's actual VHF transmissions, seen by the witness SDR (AIVDM, mmsi = unit)

For each test, on each interface, it reports:
  acceptance : did the unit's broadcast position move to the SPOOF position (it acted on the
               malformed input), to a field-SHIFT / SMUGGLED position (parser differential),
               or hold BASELINE (rejected)?
  outage     : longest interval the unit stopped transmitting during the test (DoS duration).
  recovery   : how long after the input was restored until the unit resumed (reboot / stall).
Plus, on serial, whether the unit EMITTED an over-length (>82 char) sentence.

Why both interfaces: the serial output tells you what the unit parsed; the RF tells you the
real-world effect (a false position that reaches other ships, or transmissions that actually
stop). For the overlength DoS it prints a SWEEP table of outage vs. input length on both.

Usage: python3 analyze_serial_cve.py <manifest.jsonl> <serial_out.nmea> [vhf.nmea]
"""
import sys, json, statistics, math
from collections import Counter
try:
    from pyais import decode
except Exception:
    print("needs pyais: pip install pyais --break-system-packages"); sys.exit(1)

POS_TYPES = {1, 2, 3}
MATCH_DEG = 0.02


def parse_ts(s):
    from datetime import datetime
    try: return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()
    except Exception: return None


def load(path):
    out = []
    for l in open(path, errors='replace'):
        if '\t' not in l: continue
        ts, raw = l.split('\t', 1); raw = raw.rstrip('\r\n')
        ep = parse_ts(ts)
        if ep is None: continue
        r = dict(ep=ep, linelen=len(raw), own=raw.startswith('!AIVDO'),
                 mmsi=None, type=None, lat=None, lon=None)
        if raw.startswith('!AIVDO') or raw.startswith('!AIVDM'):
            try:
                d = decode(raw).asdict()
                r.update(mmsi=d.get('mmsi'), type=d.get('msg_type'), lat=d.get('lat'), lon=d.get('lon'))
            except Exception:
                pass
        out.append(r)
    return out


def dist(a, b):
    if not a or not b or a[0] is None or b[0] is None: return 9e9
    dlat = a[0] - b[0]; dlon = (a[1] - b[1]) * math.cos(math.radians((a[0] + b[0]) / 2))
    return math.hypot(dlat, dlon)


def max_gap(times, t0, t1):
    pts = [t0] + sorted(t for t in times if t0 <= t <= t1) + [t1]
    return max((b - a for a, b in zip(pts, pts[1:])), default=t1 - t0)


def iface(cap, isown, t0, t1, tnext):
    """Metrics for one interface over the test window, plus recovery after it."""
    times = [m['ep'] for m in cap if t0 <= m['ep'] <= t1 and isown(m)]
    pos = [m for m in cap if t0 <= m['ep'] <= t1 and isown(m) and m['type'] in POS_TYPES
           and m['lat'] is not None and abs(m['lat']) <= 90]
    settled = None
    if pos:
        pos.sort(key=lambda m: m['ep']); tail = pos[len(pos) * 2 // 3:]
        settled = (statistics.median([m['lat'] for m in tail]),
                   statistics.median([m['lon'] for m in tail]))
    after = sorted(m['ep'] for m in cap if t1 < m['ep'] <= tnext and isown(m))
    recovery = (after[0] - t1) if after else None      # None = did not resume in window
    return dict(outage=max_gap(times, t0, t1), settled=settled, n=len(times), recovery=recovery)


def classify(settled, sp, sh, sm, base):
    if settled is None: return "no-tx"
    if dist(settled, sp) < MATCH_DEG: return "ACCEPTED"
    if sh[0] is not None and dist(settled, sh) < MATCH_DEG: return "DIFFERENTIAL"
    if sm[0] is not None and dist(settled, sm) < MATCH_DEG: return "SMUGGLED"
    if base[0] is not None and dist(settled, base) < MATCH_DEG: return "REJECTED"
    return f"OTHER"


def main():
    if len(sys.argv) < 3:
        print("usage: analyze_serial_cve.py <manifest.jsonl> <serial_out.nmea> [vhf.nmea]"); sys.exit(1)
    man = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    ser = load(sys.argv[2])
    vhf = load(sys.argv[3]) if len(sys.argv) > 3 else []

    own = [m['mmsi'] for m in ser if m['own'] and m['mmsi'] is not None]
    if not own:
        print("ERROR: no own-transmissions (!AIVDO) in serial output capture."); sys.exit(1)
    dut = Counter(own).most_common(1)[0][0]
    is_ser = lambda m: m['own']
    is_rf = lambda m: m['mmsi'] == dut
    have_rf = bool(vhf)

    # baseline (serial)
    base_t = next((m['t'] for m in man if m.get('event') in ('baseline', 'session_start')), 0)
    begins = [m for m in man if m.get('event') == 'test_begin']
    ends = {m['name']: m['t'] for m in man if m.get('event') == 'test_end'}
    base_end = begins[0]['t'] if begins else base_t + 60
    bpos = [m for m in ser if base_t <= m['ep'] <= base_end and m['own'] and m['type'] in POS_TYPES
            and m['lat'] is not None]
    base = (statistics.median([m['lat'] for m in bpos]), statistics.median([m['lon'] for m in bpos])) \
        if bpos else (None, None)
    btimes = sorted(m['ep'] for m in ser if base_t <= m['ep'] <= base_end and m['own'])
    base_iv = statistics.median([b - a for a, b in zip(btimes, btimes[1:])]) if len(btimes) > 2 else None

    print(f"Device under test MMSI: {dut}    RF witness: {'yes' if have_rf else 'NONE (serial only)'}")
    if base[0] is not None:
        print(f"baseline position {base[0]:.4f},{base[1]:.4f}   serial tx interval "
              f"{('%.1fs' % base_iv) if base_iv else 'n/a'}")
    thr = max(6 * base_iv, 5) if base_iv else 8

    rows = []
    for i, b in enumerate(begins):
        name = b['name']; t0 = b['t']
        t1 = ends.get(name, begins[i + 1]['t'] if i + 1 < len(begins) else t0 + 40)
        tnext = begins[i + 1]['t'] if i + 1 < len(begins) else t1 + 45
        sp = (b.get('spoof_lat'), b.get('spoof_lon'))
        sh = (b.get('shift_lat'), b.get('shift_lon'))
        sm = (b.get('smuggle_lat'), b.get('smuggle_lon'))
        sm_ = iface(ser, is_ser, t0, t1, tnext)
        rf_ = iface(vhf, is_rf, t0, t1, tnext) if have_rf else None
        overs = [m['linelen'] for m in ser if t0 <= m['ep'] <= t1 and m['linelen'] > 82]
        rows.append(dict(name=name, finding=b.get('finding', ''), cve=b.get('cve', ''),
                         sent_len=b.get('sent_len'), sp=sp, sh=sh, sm=sm,
                         s_verdict=classify(sm_['settled'], sp, sh, sm, base), s=sm_,
                         r_verdict=classify(rf_['settled'], sp, sh, sm, base) if rf_ else "-",
                         r=rf_, emit=max(overs) if overs else None))

    # ---- per-test dual-interface table ----
    def secs(x): return f"{x:.0f}s" if x is not None else "n/a"
    print("=" * 128)
    print(f"{'test':24}{'finding':17}{'str':5}"
          f"{'SERIAL':>10} {'out':>5} {'rec':>5}   {'RF':>10} {'out':>5} {'rec':>5}  {'emit':>5}")
    print("-" * 128)
    for r in rows:
        s, rf = r['s'], r['r']
        rline = f"{r['r_verdict']:>10} {secs(rf['outage']):>5} {secs(rf['recovery']):>5}" if rf \
            else f"{'-':>10} {'-':>5} {'-':>5}"
        print(f"{r['name']:24}{r['finding'][:16]:17}{r['cve'][:4]:5}"
              f"{r['s_verdict']:>10} {secs(s['outage']):>5} {secs(s['recovery']):>5}   "
              f"{rline}  {(str(r['emit']) if r['emit'] else '-'):>5}")

    # ---- overlength DoS sweep (outage vs input length, both interfaces) ----
    sweep = sorted([r for r in rows if r['finding'].startswith('1 ') and r['sent_len']],
                   key=lambda r: r['sent_len'])
    if sweep:
        print("\n" + "=" * 70)
        print("OVERLENGTH DoS SWEEP -- outage & recovery vs. input length")
        print(f"{'input len':>10} {'serial out':>12} {'serial rec':>12} "
              f"{'RF out':>10} {'RF rec':>10}")
        print("-" * 70)
        for r in sweep:
            rf = r['r']
            print(f"{r['sent_len']:>10} {secs(r['s']['outage']):>12} {secs(r['s']['recovery']):>12} "
                  f"{(secs(rf['outage']) if rf else '-'):>10} {(secs(rf['recovery']) if rf else '-'):>10}")
        print("If outage grows with input length, the DoS duration is attacker-controlled "
              "(the core CVE claim).")

    # ---- CVE read-out ----
    print("\n" + "=" * 128)
    print("CVE READ-OUT (observed behavior, dual-interface):")
    strong, parser, semantic, safe = [], [], [], []
    for r in rows:
        s, rf = r['s'], r['r']
        rf_out = rf['outage'] if rf else 0
        # DoS: strongest if the RF transmissions actually stopped
        if s['outage'] > thr or rf_out > thr:
            where = []
            if rf and rf_out > thr: where.append(f"RF {secs(rf_out)}")
            if s['outage'] > thr: where.append(f"serial {secs(s['outage'])}")
            rec = f", recovery {secs(s['recovery'])}" if s['recovery'] else ", did NOT recover in window"
            strong.append(f"{r['name']}: DoS confirmed ({', '.join(where)}{rec})")
        # false-position acceptance; note whether it reached the air
        if r['s_verdict'] == "ACCEPTED":
            reached = (rf and r['r_verdict'] == "ACCEPTED")
            air = "and BROADCAST over RF to other ships" if reached else "(serial output only; RF not confirmed)"
            if "invalid checksum" in r['finding']:
                strong.append(f"{r['name']}: acts on data failing the checksum {air}")
            elif r['cve'] == "SEMANTIC":
                semantic.append(f"{r['name']}: impossible state propagated {air}")
            else:
                strong.append(f"{r['name']}: false position accepted {air}")
        if r['emit']:
            parser.append(f"{r['name']}: emits over-length output ({r['emit']} chars) -> replay into a real listener")
        if r['s_verdict'] in ("DIFFERENTIAL", "SMUGGLED") or (rf and r['r_verdict'] in ("DIFFERENTIAL", "SMUGGLED")):
            parser.append(f"{r['name']}: parser differential / sentence smuggling confirmed")
        if r['s_verdict'] == "REJECTED" and (not rf or r['r_verdict'] in ("REJECTED", "no-tx")):
            safe.append(r['name'])

    def blk(title, items):
        print(f"\n  {title}")
        for it in sorted(set(items)) or []:
            print(f"    - {it}")
        if not items: print("    (none observed)")
    blk("STRONG CVE candidates (demonstrated):", strong)
    blk("Parser weaknesses with a demonstrated effect:", parser)
    blk("Missing semantic validation (paper findings):", semantic)
    if safe:
        print(f"\n  Rejected / not vulnerable: {', '.join(sorted(set(safe)))}")
    if not have_rf:
        print("\n  !! No VHF capture supplied: RF effects (real DoS, over-the-air propagation)")
        print("     are UNCONFIRMED. Re-run the analysis with the witness capture as arg 3.")


if __name__ == "__main__":
    main()
