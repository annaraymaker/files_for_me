#!/usr/bin/env python3
"""
analyze_effects.py -- comprehensive per-attack effect detector for AIS transponder
security testing. Correlates the session manifest, listener VHF capture, and the
transponder serial capture to determine, for each attack, whether it took effect.

Detectable effects (from serial + VHF):
  RECEIVED   : the transponder reported the injected message on serial (ingestion).
               Per the operator's chartplotter validation, serial receipt == the
               injected content reached the transponder's target picture.
  REPLIED    : the transponder emitted Type-3 interrogation replies (answered M15).
  ACKED      : the transponder emitted Type-7 acknowledgements (acted on addressed msg).
  CHANNEL    : the channel distribution of the transponder's OWN transmissions shifted
               away from its balanced A/B baseline (possible M22 retune obeyed).
  SILENCED   : the transponder's own transmission rate dropped sharply or stopped
               (possible quiet/retune-to-unhearable-channel).
  RATE       : the transponder's inter-transmission interval changed (possible M16
               reporting-rate change).

Baseline for the transponder's normal behavior is computed from quiet windows (the
'recover' windows and the pre-attack settle), so each attack is judged against how the
unit behaves when it is NOT under a command.

Usage:
  python3 analyze_effects.py <manifest.jsonl> <vhf.nmea> <serial.nmea>
"""
import sys, json, statistics
from collections import Counter, defaultdict
from datetime import datetime
try:
    from pyais import decode
except Exception:
    print("needs pyais: pip install pyais --break-system-packages"); sys.exit(1)

def parse_ts(s):
    try: return datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
    except Exception: return None

def load_nmea(path, want_channel=False):
    """Return list of dicts: {ep, mmsi, type, own, channel}."""
    out=[]
    for l in open(path, errors='replace'):
        if '\t' not in l: continue
        ts_s, raw = l.split('\t',1); raw=raw.strip()
        if not (raw.startswith('!AIVDO') or raw.startswith('!AIVDM')): continue
        ep=parse_ts(ts_s)
        if ep is None: continue
        try: d=decode(raw).asdict()
        except: continue
        ch = raw.split(',')[4] if len(raw.split(','))>4 else ''
        # Normalize the AIVDM channel field: decoders emit either A/B or 1/2 for the two
        # AIS channels. Without this, a decoder that reports 1/2 yields zero A and zero B,
        # silently disabling all CHANNEL-SHIFT / M22-retune detection.
        ch = {'1':'A','2':'B'}.get(ch, ch)
        out.append(dict(ep=ep, mmsi=d.get('mmsi'), type=d.get('msg_type'),
                        own=raw.startswith('!AIVDO'), channel=ch,
                        lat=d.get('lat'), lon=d.get('lon')))
    return out

def _peak_shift(src, ref, max_skew=20.0, bin_w=0.5):
    """Estimate the time shift between two event streams that record the SAME events on
    different clocks. src/ref are lists of (time, identity). We only pair events sharing
    an identity, collect all (src_time - ref_time) deltas within +/-max_skew, and take the
    peak of their histogram (true matches pile up at the real offset+lag; accidental pairs
    smear out). Robust to unknown offset and to dropped frames on either side.

    Returns (shift, n_matched, p10, p90) where shift = median delta at the peak and
    p10/p90 bound its spread (the jitter), or None if too few matches."""
    import bisect, statistics
    from collections import Counter, defaultdict
    ref_by = defaultdict(list)
    for t, i in ref:
        ref_by[i].append(t)
    for i in ref_by:
        ref_by[i].sort()
    deltas = []
    for t, i in src:
        rs = ref_by.get(i)
        if not rs:
            continue
        lo = bisect.bisect_left(rs, t - max_skew)
        hi = bisect.bisect_right(rs, t + max_skew)
        for r in rs[lo:hi]:
            deltas.append(t - r)
    if len(deltas) < 3:
        return None
    center = Counter(round(d / bin_w) for d in deltas).most_common(1)[0][0] * bin_w
    near = sorted(d for d in deltas if abs(d - center) <= 1.5 * bin_w)
    if len(near) < 3:
        return None
    p10 = near[int(0.10 * (len(near) - 1))]
    p90 = near[int(0.90 * (len(near) - 1))]
    return statistics.median(near), len(near), p10, p90


def calibrate_clocks(manifest, vhf, serial, DY, warn_thresh=2.0):
    """Measure the residual clock offsets between the three capture hosts from events they
    share, so alignment does not depend on NTP quality:

      attacker<->listener : each injected message is logged in the manifest (attacker clock,
                            'sent' events, tagged with src_mmsi+mtype) AND heard on VHF
                            (listener clock). Matching them gives shift_inject.
      transponder<->listener: each of DY's own transmissions appears on serial (transponder
                            clock, AIVDO) AND on VHF (listener clock, AIVDM mmsi==DY).
                            Matching them gives shift_serial -- which also IS the serial
                            presentation-lag distribution when the hosts are clock-synced.

    Returns (shift_inject, shift_serial) in seconds (either may be None if uncalibratable).
    The caller normalizes everything into the listener frame: manifest t += shift_inject,
    serial ep -= shift_serial, VHF left as the reference."""
    # attacker <-> listener, matched by (source MMSI, message type)
    sent = [(m['t'], (m.get('src_mmsi'), m.get('mtype')))
            for m in manifest
            if m.get('event') == 'sent' and m.get('t') and m.get('src_mmsi') is not None]
    vhf_inj = [(m['ep'], (m['mmsi'], m['type']))
               for m in vhf if not m['own'] and m['mmsi'] is not None and m['mmsi'] != DY]
    r_inj = _peak_shift(vhf_inj, sent)          # median(vhf - sent)
    # transponder <-> listener, DY's own transmissions
    ser_own = [(m['ep'], 'DY') for m in serial if m['own'] and m['mmsi'] == DY]
    vhf_own = [(m['ep'], 'DY') for m in vhf if m['mmsi'] == DY]
    r_ser = _peak_shift(ser_own, vhf_own)       # median(serial - vhf)

    print("CLOCK CALIBRATION (from shared events; listener VHF is the reference frame):")
    if r_inj:
        s, n, lo, hi = r_inj
        print(f"  attacker<->listener : {s:+.3f}s  (n={n} injected msgs matched, "
              f"jitter p10..p90 {lo:+.3f}..{hi:+.3f}s)")
        if abs(s) > warn_thresh:
            print(f"    !! offset > {warn_thresh}s -- hosts are poorly synced. Alignment "
                  f"corrects it, but run chrony on the LAN to shrink boundary risk.")
        shift_inject = s
    else:
        print("  attacker<->listener : uncalibratable (no matched injections on VHF); "
              "assuming 0. Check the listener heard the injected channel.")
        shift_inject = None
    if r_ser:
        s, n, lo, hi = r_ser
        print(f"  transponder<->listener: {s:+.3f}s (n={n} own-tx matched)")
        print(f"    serial presentation lag ~ median {s:+.3f}s, jitter p10..p90 "
              f"{lo:+.3f}..{hi:+.3f}s (report this in measurement-validity)")
        if abs(s) > warn_thresh:
            print(f"    !! offset > {warn_thresh}s -- large serial/host skew; see chrony note.")
        shift_serial = s
    else:
        print("  transponder<->listener: uncalibratable (no DY own-tx matched on VHF); "
              "assuming 0. Expected if VHF frame loss was total during the run.")
        shift_serial = None
    print("-" * 118)
    return shift_inject, shift_serial


def pick_dy(serial):
    """Identify the device-under-test MMSI as the most frequent own-transmission (AIVDO)
    sender on the serial capture. Fail loudly if the serial capture has no own-tx, rather
    than crashing on an empty Counter."""
    own=[m['mmsi'] for m in serial if m['own'] and m['mmsi'] is not None]
    if not own:
        print("ERROR: no own-transmissions (!AIVDO) with an MMSI found in the serial "
              "capture; cannot identify the device under test. Check that the serial "
              "recorder captured the transponder's own output and that lines are "
              "'<iso-ts>\\t<sentence>'."); sys.exit(1)
    return Counter(own).most_common(1)[0][0]

def main():
    if len(sys.argv)<4:
        print("usage: analyze_effects.py <manifest.jsonl> <vhf.nmea> <serial.nmea>"); sys.exit(1)
    manifest=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    vhf=load_nmea(sys.argv[2])
    serial=load_nmea(sys.argv[3])

    DY=pick_dy(serial)

    # --- self-calibrate the three host clocks from shared events, then normalize every
    # stream into the listener (VHF) frame so window attribution does not depend on NTP.
    shift_inject, shift_serial = calibrate_clocks(manifest, vhf, serial, DY)
    if shift_inject:
        for m in manifest:
            if m.get('t') is not None: m['t'] += shift_inject   # attacker -> listener frame
    if shift_serial:
        for m in serial:
            m['ep'] -= shift_serial                              # transponder -> listener frame

    # attack windows from manifest
    begins=[(m['t'],m['name']) for m in manifest if m.get('event')=='attack_begin' and m.get('t')]
    windows=[]
    for i,(t,n) in enumerate(begins):
        end=begins[i+1][0] if i+1<len(begins) else t+30
        windows.append((n,t,end))

    # --- BASELINE: DY's normal behavior ---
    # For RATE and SILENCE we use DY's OWN transmissions on SERIAL (AIVDO): the serial
    # link records every transmission the unit makes, so it is immune to the listener
    # frame loss that makes VHF-based rate measurement unreliable during heavy injection.
    # For CHANNEL distribution we must use VHF (serial AIVDO does not carry the channel),
    # and we flag channel results as lower-confidence for that reason.
    def dy_tx_serial(t0,t1):
        return sorted([m for m in serial if t0<=m['ep']<=t1 and m['own']], key=lambda m:m['ep'])
    def dy_tx_vhf(t0,t1):
        return [m for m in vhf if t0<=m['ep']<=t1 and m['mmsi']==DY]
    # collect baseline from quiet windows: phase-2/3 'recover' windows AND the injection-
    # free 'baseline_settle' window rf_session opens during the pre-attack settle. The
    # latter means a phase-1-only run still has a baseline (previously it did not).
    def is_baseline(name): return ('recover' in name) or ('baseline' in name)
    base_channels=Counter(); base_intervals=[]; base_rate_samples=[]
    for name,t0,t1 in windows:
        if is_baseline(name):
            tx=dy_tx_serial(t0,t1)                      # rate from serial (reliable)
            base_rate_samples.append(len(tx)/(t1-t0) if t1>t0 else 0)
            for a,b in zip(tx, tx[1:]):
                dt=b['ep']-a['ep']
                if 0<dt<60: base_intervals.append(dt)
            for m in dy_tx_vhf(t0,t1):                  # channel from VHF
                base_channels[m['channel']]+=1
    base_a=base_channels.get('A',0); base_b=base_channels.get('B',0)
    base_bal = base_a/(base_a+base_b) if (base_a+base_b) else 0.5
    base_interval = statistics.median(base_intervals) if base_intervals else None
    base_rate = statistics.median(base_rate_samples) if base_rate_samples else None

    print(f"Transponder MMSI: {DY}")
    if base_rate:
        print(f"BASELINE (recover+settle windows, serial rate + VHF channel): tx-rate={base_rate:.2f}/s; "
              f"median inter-tx={base_interval:.1f}s; VHF channel frac A={base_bal:.2f}")
    else:
        print("baseline: insufficient")
    print("="*118)
    hdr=f"{'attack':26} {'rcvd':>4} {'rep3':>4} {'ack7':>4} {'DYtx_s':>6} {'rate/s':>6} {'A/B_vhf':>8}  EFFECTS"
    print(hdr); print("-"*118)

    for name,t0,t1 in windows:
        dur=t1-t0
        rcvd=sum(1 for m in serial if t0<=m['ep']<=t1 and not m['own'] and m['mmsi']!=DY)
        rep3=sum(1 for m in serial if t0<=m['ep']<=t1 and m['own'] and m['type']==3)
        ack7=sum(1 for m in serial if t0<=m['ep']<=t1 and m['own'] and m['type']==7)
        tx=dy_tx_serial(t0,t1)                          # reliable rate source
        dytx=len(tx)
        rate = dytx/dur if dur>0 else 0
        ivs=[y['ep']-x['ep'] for x,y in zip(tx,tx[1:]) if 0<y['ep']-x['ep']<60]
        med_iv=statistics.median(ivs) if ivs else None
        vtx=dy_tx_vhf(t0,t1)                            # channel distribution
        a=sum(1 for m in vtx if m['channel']=='A'); b=sum(1 for m in vtx if m['channel']=='B')

        effects=[]
        if rcvd>0: effects.append(f"RECEIVED({rcvd})")
        if rep3>0: effects.append(f"REPLIED({rep3})")
        if ack7>0: effects.append(f"ACKED({ack7})")
        # SILENCE/RATE from serial (reliable): flag only if the unit's actual tx-rate moved
        if base_rate and rate < 0.6*base_rate and not is_baseline(name):
            effects.append(f"TX-DROP({rate:.2f} vs base {base_rate:.2f})")
        if base_interval and med_iv and abs(med_iv-base_interval)/base_interval>0.4:
            effects.append(f"RATE-CHANGE({med_iv:.1f}s vs {base_interval:.1f}s)")
        # CHANNEL shift from VHF (lower confidence, needs >=10 caught to trust)
        if a+b>=10:
            fa=a/(a+b)
            if abs(fa-base_bal)>0.35:
                effects.append(f"CHANNEL-SHIFT?(A={fa:.2f} vs {base_bal:.2f}, VHF)")

        print(f"{name:26} {rcvd:>4} {rep3:>4} {ack7:>4} {dytx:>6} {rate:>6.2f} {a}/{b:<6}  {' '.join(effects)}")

    print("="*118)
    print("EFFECTS: RECEIVED=ingested on serial (==reached target picture, per plotter"); 
    print("  validation). REPLIED=Type-3 interrogation reply. ACKED=Type-7 ack. CHANNEL-SHIFT=")
    print("  DY's tx channel balance moved from baseline (possible M22 retune). TX-DROP=DY's")
    print("  transmit rate fell below 60% of baseline (possible quiet/retune-to-unhearable).")
    print("  RATE-CHANGE=DY's inter-tx interval shifted (possible M16 rate change).")
    print("  Note: power-mode changes are NOT reliably detectable from this capture.")

    # if the session included the own-MMSI echo test, report whether RF traffic leaked
    # into the own-ship channel
    analyze_own_mmsi_echo(manifest, vhf, serial, DY)

    # if the session included phase-3 source-authority cells, print the 2xN table
    analyze_phase3(manifest, vhf, serial, DY)


def _pos_dist_deg(a_lat, a_lon, b_lat, b_lon):
    """Rough great-circle-ish distance in degrees (flat-earth, fine for a coarse 'is this
    the real position or the spoofed one' test)."""
    import math
    dlat = a_lat - b_lat
    dlon = (a_lon - b_lon) * math.cos(math.radians((a_lat + b_lat) / 2.0))
    return math.hypot(dlat, dlon)


def analyze_own_mmsi_echo(manifest, vhf, serial, DY, far_deg=0.05):
    """Did transmitting a frame with the victim's OWN MMSI (at a distinct position) leak
    into the own-ship channel?

    DY continuously reports its real (fed) position as AIVDO. The injected frame carries
    DY's MMSI but a position ~30 km away, so any DY-MMSI sentence on serial whose position
    is FAR from DY's own baseline position must have come from the injected RF frame, not
    from the unit's sensor bus. We classify by the serial tag:
      AIVDO far-position -> CONTAMINATION: unit filed received own-MMSI RF as its OWN data
      AIVDM far-position -> unit labeled it 'other' but a duplicate-MMSI target is now in
                            the picture (milder, still notable)
      none far           -> not echoed to serial (rejected / absorbed / conflict-alarmed)"""
    begins=[(m['t'],m['name']) for m in manifest
            if m.get('event')=='attack_begin' and m.get('t') and m['name']=='own_mmsi_echo']
    if not begins:
        return
    t0=begins[0][0]
    all_beg=sorted([m['t'] for m in manifest if m.get('event')=='attack_begin' and m.get('t')])
    later=[t for t in all_beg if t>t0]
    t1=min(later) if later else t0+30

    # DY's own baseline position: median of its AIVDO positions across the whole capture
    dy_pos=[(m['lat'],m['lon']) for m in serial
            if m['own'] and m['mmsi']==DY and m['lat'] is not None and m['lon'] is not None]
    print("\n"+"="*100)
    print("OWN-MMSI ECHO -- does received own-MMSI RF traffic leak into the own-ship channel?")
    print("="*100)
    if not dy_pos:
        print("  no positioned AIVDO from DY -> cannot establish the unit's own position; "
              "inconclusive."); return
    base_lat=statistics.median([p[0] for p in dy_pos])
    base_lon=statistics.median([p[1] for p in dy_pos])
    print(f"  DY own (baseline) position ~ {base_lat:.4f},{base_lon:.4f}; "
          f"flagging DY-MMSI serial sentences > {far_deg} deg away as injected.")

    contam=[]; other=[]
    for m in serial:
        if not (t0<=m['ep']<=t1): continue
        if m['mmsi']!=DY or m['lat'] is None or m['lon'] is None: continue
        if _pos_dist_deg(m['lat'],m['lon'],base_lat,base_lon) > far_deg:
            (contam if m['own'] else other).append(m)
    if contam:
        ex=contam[0]
        print(f"  ** CONTAMINATION: {len(contam)} AIVDO (own-tagged) sentence(s) at the "
              f"INJECTED position (e.g. {ex['lat']:.4f},{ex['lon']:.4f}). The unit filed "
              f"received own-MMSI RF traffic as its OWN data. This is a real finding.")
    elif other:
        ex=other[0]
        print(f"  DUPLICATE-MMSI: {len(other)} AIVDM (other-tagged) sentence(s) at the "
              f"injected position ({ex['lat']:.4f},{ex['lon']:.4f}). Correctly classified "
              f"as 'other', but a target sharing DY's MMSI is now in the picture.")
    else:
        print("  no DY-MMSI sentence at the injected position appeared on serial during the "
              "window -> the frame was rejected/absorbed (or a conflict alarm was raised, "
              "which this NMEA capture cannot see). Check the unit's alarm log to confirm.")


def analyze_phase3(manifest, vhf, serial, DY):
    """Build the base-vs-regular source-authority table from phase-3 cells.

    Each phase-3 test cell is tagged in the manifest with command= and source=. For each
    command we compare what the transponder did when the command came from a base station
    versus a regular ship, using the per-command observable:
      M15  -> Type-3 replies (does it answer the interrogation)
      M6   -> Type-7 acks    (does it acknowledge the addressed message)
      M16  -> tx inter-interval change over the dwell (does it change reporting rate)
      M22  -> channel shift / serial-continues-but-VHF-vanishes (does it retune)
    Well-observed: M15, M6, M16, M22 channel. Poorly observed (reported but flagged):
    M20 slot reservation, M22 power.
    """
    import statistics
    begins=[(m['t'],m['name'],m.get('command'),m.get('source'))
            for m in manifest if m.get('event')=='attack_begin' and m.get('t')
            and m['name'].startswith('p3_') and not m['name'].startswith('p3_recover')]
    if not begins:
        return
    # window end = next attack_begin overall
    all_beg=sorted([m['t'] for m in manifest if m.get('event')=='attack_begin' and m.get('t')])
    def wend(t0):
        later=[t for t in all_beg if t>t0]
        return min(later) if later else t0+90

    # baseline tx interval from quiet windows (recover cells + the settle baseline), serial
    rec_iv=[]
    rb=[(m['t'],m['name']) for m in manifest if m.get('event')=='attack_begin'
        and m.get('t') and ('recover' in m['name'] or 'baseline' in m['name'])]
    for t0,_ in rb:
        t1=wend(t0)
        tx=sorted([m['ep'] for m in serial if t0<=m['ep']<=t1 and m['own']])
        rec_iv+=[b-a for a,b in zip(tx,tx[1:]) if 0<b-a<60]
    base_iv=statistics.median(rec_iv) if rec_iv else None

    # collect per (command, source)
    results={}
    for t0,name,cmd,src in begins:
        t1=wend(t0)
        rep3=sum(1 for m in serial if t0<=m['ep']<=t1 and m['own'] and m['type']==3)
        ack7=sum(1 for m in serial if t0<=m['ep']<=t1 and m['own'] and m['type']==7)
        rcvd=sum(1 for m in serial if t0<=m['ep']<=t1 and not m['own'] and m['mmsi']!=DY)
        tx=sorted([m['ep'] for m in serial if t0<=m['ep']<=t1 and m['own']])
        ivs=[b-a for a,b in zip(tx,tx[1:]) if 0<b-a<60]
        med_iv=statistics.median(ivs) if ivs else None
        vtx=[m for m in vhf if t0<=m['ep']<=t1 and m['mmsi']==DY]
        va=sum(1 for m in vtx if m['channel']=='A'); vb=sum(1 for m in vtx if m['channel']=='B')
        serial_tx=len(tx); vhf_tx=len(vtx)
        results[(cmd,src)]=dict(rep3=rep3, ack7=ack7, rcvd=rcvd, med_iv=med_iv,
                                serial_tx=serial_tx, vhf_tx=vhf_tx, va=va, vb=vb)

    # print the 2xN table
    print("\n" + "="*100)
    print("PHASE 3 -- SOURCE AUTHORITY: does the unit act on the command from BASE vs REGULAR?")
    print("="*100)
    print(f"baseline tx interval (recover windows): "
          f"{base_iv:.2f}s" if base_iv else "baseline interval: n/a")
    cmds=[]
    for (cmd,src) in results:
        if cmd not in cmds: cmds.append(cmd)
    print(f"\n{'command':22} {'source':8} {'observable -> verdict'}")
    print("-"*100)
    for cmd in cmds:
        for src in ('base','regular'):
            r=results.get((cmd,src))
            if not r: continue
            # pick the observable + verdict per command family
            if cmd.startswith('M15'):
                v=f"Type3 replies={r['rep3']:>3}  -> {'ACTED' if r['rep3']>0 else 'no reply'}"
            elif cmd.startswith('M6'):
                v=f"Type7 acks={r['ack7']:>3}     -> {'ACTED' if r['ack7']>0 else 'no ack'}"
            elif cmd.startswith('M16'):
                if base_iv and r['med_iv']:
                    changed=abs(r['med_iv']-base_iv)/base_iv>0.4
                    v=f"tx-interval={r['med_iv']:.2f}s(base {base_iv:.2f}) -> {'RATE CHANGED' if changed else 'no change'}"
                else:
                    v=f"tx-interval=n/a -> inconclusive"
            elif cmd.startswith('M22_channel'):
                # retune signature: serial continues but VHF vanishes, OR channel balance flips
                div = r['serial_tx']>0 and r['vhf_tx']==0
                v=(f"serial_tx={r['serial_tx']} vhf_tx={r['vhf_tx']} A/B={r['va']}/{r['vb']} -> "
                   f"{'RETUNED (serial cont, VHF gone)' if div else 'still on AIS channels'}")
            elif cmd.startswith('M22_power'):
                v=f"(power not reliably observable) serial_tx={r['serial_tx']}"
            elif cmd.startswith('M20'):
                v=f"(slot effect weakly observable) serial_tx={r['serial_tx']} rcvd={r['rcvd']}"
            else:
                v=f"rcvd={r['rcvd']}"
            print(f"{cmd:22} {src:8} {v}")
        # per-command base-vs-regular contrast note
        rb_=results.get((cmd,'base')); rr_=results.get((cmd,'regular'))
        if rb_ and rr_:
            if cmd.startswith('M15'):
                note=_contrast("interrogation reply", rb_['rep3'], rr_['rep3'])
            elif cmd.startswith('M6'):
                note=_contrast("acknowledgement", rb_['ack7'], rr_['ack7'])
            else:
                note=""
            if note: print(f"{'':22} {'':8} => {note}")
        print()
    print("KEY QUESTION answered per command: if the REGULAR-source row shows the unit ACTED,")
    print("the unit does NOT enforce base-station authority for that command (the worse finding).")
    print("If only the BASE row acts, the unit is spec-compliant but the command is still abusable")
    print("by anyone able to forge a base-station MMSI (which is unauthenticated).")


def _contrast(label, base_n, reg_n):
    if base_n>0 and reg_n>0:
        return f"acts on {label} from BOTH base and regular (NO source-authority check)"
    if base_n>0 and reg_n==0:
        return f"acts on {label} from base only (enforces source authority)"
    if base_n==0 and reg_n>0:
        return f"acts on {label} from regular but NOT base (unexpected -- investigate)"
    return f"no {label} from either source"


if __name__=='__main__':
    main()
