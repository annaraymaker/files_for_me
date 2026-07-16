#!/usr/bin/env python3
"""
analyze_m20.py -- focused read of the M20 slot-reservation density suite (rf_session --m20 / --m20-only).

The single 10-slot reservation in the full session was too small to separate its effect from
ordinary SOTDMA slot churn. This suite sweeps the RESERVATION DENSITY (fraction of the frame
reserved, via the M20 increment field). The question this tool answers:

  does the victim's slot churn / transmit rate SCALE with reservation density?
     rises with density  -> the unit HONORS M20 (it must vacate more of the frame)
     flat across density  -> the unit IGNORES M20

We read the victim's own SOTDMA communication state from AIS-catcher's level JSON. The key,
interpretation-free signal is slot_timeout==0, which is the frame in which a Class A announces a
NEW slot offset -- i.e. a slot reselection. More reselections = more slot churn = more disruption.
received_stations is printed as a traffic control: in an --m20-only run there is no injected ghost
traffic, so it should stay roughly constant, meaning any change in churn is the reservation, not load.

Usage: analyze_m20.py <manifest.jsonl> <vhf.nmea> <serial.nmea> <level.json>
"""
import sys, json, statistics
import analyze_effects as A


def load_commstate(path, dy):
    """Victim (own-MMSI) SOTDMA comm-state per received message, from AIS-catcher JSON."""
    out = []
    for l in open(path, errors='replace'):
        l = l.strip()
        if not l or l[0] != '{':
            continue
        try:
            d = json.loads(l)
        except Exception:
            continue
        if d.get('mmsi') != dy or 'rxuxtime' not in d:
            continue
        out.append(dict(ep=float(d['rxuxtime']), timeout=d.get('slot_timeout'),
                        offset=d.get('slot_offset'), recv=d.get('received_stations'),
                        mtype=d.get('type')))
    return out


# legacy fixed labels (old m20 suite) plus the new percent labels p50..p100 from the base-retest.
_LEGACY_PCT = {"small": 0.4, "half": 50, "dense": 67, "verydense": 75}

def dens_pct(label):
    """Reservation density (percent of frame) for an m20_base_<label> window, or None if the
    label is a control/unknown. Handles legacy labels and the new p<NN> percent labels."""
    if label in _LEGACY_PCT:
        return _LEGACY_PCT[label]
    if label.startswith("p") and label[1:].isdigit():
        return float(label[1:])
    return None


def main():
    if len(sys.argv) < 5:
        print("usage: analyze_m20.py <manifest.jsonl> <vhf.nmea> <serial.nmea> <level.json>"); sys.exit(1)
    man = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    vhf = A.load_nmea(sys.argv[2]); serial = A.load_nmea(sys.argv[3])
    dy = A.pick_dy(serial)
    shift_inject, _ = A.calibrate_clocks(man, vhf, serial, dy)
    for m in man:
        if m.get('t') is not None:
            m['t'] += (shift_inject or 0)

    begins = [(m['t'], m['name']) for m in man if m.get('event') == 'attack_begin' and m.get('t')]
    wins = []
    for i, (t, n) in enumerate(begins):
        end = begins[i + 1][0] if i + 1 < len(begins) else t + 35
        wins.append((n, t, end))
    cs = load_commstate(sys.argv[4], dy)

    def metrics(t0, t1):
        xs = [c for c in cs if t0 <= c['ep'] < t1]
        if not xs:
            return None
        dur = max(t1 - t0, 1e-6)
        resel = sum(1 for c in xs if c['timeout'] == 0)
        recv = [c['recv'] for c in xs if c['recv'] is not None]
        return dict(n=len(xs), rate=len(xs) / dur, reselpct=100 * resel / len(xs),
                    recv=(statistics.median(recv) if recv else None))

    print(f"DUT MMSI {dy}   M20 slot-reservation density sweep")
    if not cs:
        print("  !! no victim comm-state found in the level JSON (need AIS-catcher -M D -o 5). "
              "Cannot judge M20 from this capture."); return
    print(f"  {len(cs)} victim comm-state messages in the level JSON\n")

    rel = [(n, t0, t1) for (n, t0, t1) in wins
           if any(k in n.lower() for k in ('m20', 'control', 'recover'))]
    print(f"{'window':32}{'n':>4}{'tx/s':>7}{'reselect%':>11}{'recv_sta':>9}")
    print("-" * 63)
    rows = {}
    for n, t0, t1 in rel:
        m = metrics(t0, t1)
        if not m:
            print(f"{n[:31]:32}{'--- no victim tx in window ---':>40}"); continue
        rows[n] = m
        print(f"{n[:31]:32}{m['n']:>4}{m['rate']:>7.2f}{m['reselpct']:>10.0f}%"
              f"{(str(int(m['recv'])) if m['recv'] is not None else '-'):>9}")

    # controls = baseline + recover windows
    ctrl = [m['reselpct'] for n, m in rows.items() if 'control' in n or 'recover' in n]
    ctrl_hi = max(ctrl) if ctrl else None
    ctrl_med = statistics.median(ctrl) if ctrl else None

    # density sweep from the base (exclude the control windows; order by actual percent)
    sweep = sorted([(dens_pct(n.split('_')[-1]), n, rows[n])
                    for n in rows if n.startswith('m20_base_')
                    and 'control' not in n and dens_pct(n.split('_')[-1]) is not None],
                   key=lambda x: x[0])

    print("\nVERDICT")
    print("-" * 63)
    if ctrl_hi is not None:
        print(f"control (no-reservation) reselect%: median {ctrl_med:.0f}%, max {ctrl_hi:.0f}%")
    if len(sweep) >= 2:
        lo = sweep[0][2]['reselpct']; hi = sweep[-1][2]['reselpct']
        seq = ", ".join(f"{n.split('_')[-1]}={m['reselpct']:.0f}%" for _, n, m in sweep)
        print(f"base density sweep reselect%: {seq}")
        rising = hi - lo
        exceeds = (ctrl_hi is not None and hi > ctrl_hi + 10)
        if rising >= 15 and exceeds:
            print("=> slot churn RISES with reservation density and exceeds the control band")
            print("   -> em-trak HONORS M20 (it vacates more of the frame as more is reserved).")
        elif rising >= 15:
            print("=> churn rises with density but stays near the control band -> LIKELY honors,"
                  " weak; widen the densities or lengthen dwell to confirm.")
        else:
            print("=> slot churn is FLAT across densities (small vs very-dense within noise)")
            print("   -> em-trak IGNORES M20 (no reaction to how much of the frame is reserved).")
        # tx-rate corroboration
        r_lo = sweep[0][2]['rate']; r_hi = sweep[-1][2]['rate']
        if r_hi < 0.7 * r_lo:
            print(f"   corroboration: transmit rate FELL {r_lo:.2f}->{r_hi:.2f}/s as density rose "
                  "(being squeezed off slots).")
    else:
        print("base density sweep not found (expected windows m20_base_small..verydense). "
              "Is this an --m20 run?")

    # source authority at the dense level
    if 'm20_base_dense' in rows and 'm20_regular_dense' in rows:
        b = rows['m20_base_dense']['reselpct']; r = rows['m20_regular_dense']['reselpct']
        print(f"\nsource authority (dense): base={b:.0f}%  regular-ship={r:.0f}%")
        if ctrl_hi is not None and r > ctrl_hi + 10:
            print("=> acts on a REGULAR ship's M20 as well -> NO source-authority check.")
        elif ctrl_hi is not None:
            print("=> regular-ship M20 stays in the control band -> ignores non-base M20 "
                  "(or honors base only).")


if __name__ == "__main__":
    main()
