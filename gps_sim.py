#!/usr/bin/env python3
"""NMEA 0183 GPS simulator: static, dead-reckoning, or waypoint replay."""
import argparse, csv, math, time, sys, signal
import serial, pynmea2
from datetime import datetime, timezone

# ---------- helpers ----------
def to_nmea(deg, is_lat):
    hemi = ('N' if deg >= 0 else 'S') if is_lat else ('E' if deg >= 0 else 'W')
    deg = abs(deg); d = int(deg); m = (deg - d) * 60
    return (f"{d:02d}{m:07.4f}" if is_lat else f"{d:03d}{m:07.4f}"), hemi

def build_sentences(lat, lon, alt, speed_kts, course_deg):
    now = datetime.now(timezone.utc)
    t = now.strftime("%H%M%S.00"); d = now.strftime("%d%m%y")
    lat_s, lat_h = to_nmea(lat, True)
    lon_s, lon_h = to_nmea(lon, False)
    gga = pynmea2.GGA('GP','GGA',(t, lat_s, lat_h, lon_s, lon_h,
          '1','08','0.9', f"{alt:.1f}",'M','0.0','M','',''))
    rmc = pynmea2.RMC('GP','RMC',(t,'A', lat_s, lat_h, lon_s, lon_h,
          f"{speed_kts:.1f}", f"{course_deg:.1f}", d,'','','A'))
    vtg = pynmea2.VTG('GP','VTG',(f"{course_deg:.1f}",'T','','M',
          f"{speed_kts:.1f}",'N', f"{speed_kts*1.852:.1f}",'K','A'))
    return (gga, rmc, vtg)

def advance(lat, lon, speed_kts, course_deg, dt=1.0):
    """Flat-earth dead reckoning. Fine for <100km moves."""
    dist = speed_kts * 0.5144 * dt
    c = math.radians(course_deg)
    new_lat = lat + (dist * math.cos(c)) / 111320.0
    new_lon = lon + (dist * math.sin(c)) / (111320.0 * math.cos(math.radians(lat)))
    return new_lat, new_lon

def bearing_distance(lat1, lon1, lat2, lon2):
    """Great-circle bearing (deg) and distance (m)."""
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    x = math.sin(dl) * math.cos(p2)
    y = math.cos(p1)*math.sin(p2) - math.sin(p1)*math.cos(p2)*math.cos(dl)
    brg = (math.degrees(math.atan2(x, y)) + 360) % 360
    a = math.sin((p2-p1)/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    dist = 2*R*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return brg, dist

# ---------- mode generators (yield: lat, lon, alt, speed, course) ----------
def gen_static(args):
    while True:
        yield args.lat, args.lon, args.alt, args.speed, args.course

def gen_move(args):
    lat, lon = args.lat, args.lon
    while True:
        yield lat, lon, args.alt, args.speed, args.course
        lat, lon = advance(lat, lon, args.speed, args.course, args.rate)

def gen_waypoints(args):
    with open(args.csv) as f:
        wps = [(float(r['lat']), float(r['lon']), float(r.get('hold', 1)))
               for r in csv.DictReader(f)]
    if args.smooth and len(wps) > 1:
        for i in range(len(wps) - 1):
            lat1, lon1, hold = wps[i]
            lat2, lon2, _   = wps[i+1]
            brg, dist = bearing_distance(lat1, lon1, lat2, lon2)
            steps = max(1, int(hold / args.rate))
            spd_kts = (dist / (hold)) / 0.5144 if hold > 0 else 0.0
            lat, lon = lat1, lon1
            for _ in range(steps):
                yield lat, lon, args.alt, spd_kts, brg
                lat, lon = advance(lat, lon, spd_kts, brg, args.rate)
        lat, lon, hold = wps[-1]
        for _ in range(max(1, int(hold / args.rate))):
            yield lat, lon, args.alt, 0.0, 0.0
    else:
        for lat, lon, hold in wps:
            for _ in range(max(1, int(hold / args.rate))):
                yield lat, lon, args.alt, 0.0, 0.0

# ---------- main ----------
def main():
    p = argparse.ArgumentParser(description="NMEA 0183 GPS simulator")
    p.add_argument("--port", default="/dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=4800)
    p.add_argument("--rate", type=float, default=1.0, help="seconds between sentence batches")
    p.add_argument("--quiet", action="store_true")
    sub = p.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("static", help="hold one position forever")
    s.add_argument("lat", type=float); s.add_argument("lon", type=float)
    s.add_argument("--alt", type=float, default=10.0)
    s.add_argument("--speed",  type=float, default=0.0)
    s.add_argument("--course", type=float, default=0.0)
    s.set_defaults(gen=gen_static)

    m = sub.add_parser("move", help="dead-reckon from start point")
    m.add_argument("lat", type=float); m.add_argument("lon", type=float)
    m.add_argument("--speed",  type=float, required=True, help="knots")
    m.add_argument("--course", type=float, required=True, help="degrees true")
    m.add_argument("--alt", type=float, default=10.0)
    m.set_defaults(gen=gen_move)

    w = sub.add_parser("waypoints", help="replay CSV: columns lat,lon,hold")
    w.add_argument("csv")
    w.add_argument("--smooth", action="store_true",
                   help="interpolate between points (else jump)")
    w.add_argument("--loop", action="store_true", help="repeat after last point")
    w.add_argument("--alt", type=float, default=10.0)
    w.set_defaults(gen=gen_waypoints)

    args = p.parse_args()
    ser = serial.Serial(args.port, args.baud, timeout=1)
    print(f"[{args.mode}] -> {args.port} @ {args.baud}, rate {args.rate}s. Ctrl-C to stop.")

    def stop(*_):
        ser.close(); print("\nstopped."); sys.exit(0)
    signal.signal(signal.SIGINT, stop)

    try:
        while True:
            for lat, lon, alt, spd, crs in args.gen(args):
                for sent in build_sentences(lat, lon, alt, spd, crs):
                    ser.write((str(sent) + '\r\n').encode())
                if not args.quiet:
                    print(f"  {lat:.6f},{lon:.6f}  spd={spd:.1f}kt  brg={crs:.1f}°")
                time.sleep(args.rate)
            if args.mode != "waypoints" or not args.loop:
                break
            print("--- looping ---")
    finally:
        ser.close()

if __name__ == "__main__":
    main()
