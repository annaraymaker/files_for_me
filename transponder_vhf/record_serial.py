#!/usr/bin/env python3
"""
record_serial.py -- record a transponder's serial AIS (NMEA) output, timestamped.

Simple: opens the serial port, writes every line as "<utc>\t<line>" to one file.
Stop with Ctrl-C.

Usage:
  python3 record_serial.py --port /dev/serial/by-id/usb-XXimeXX --baud 38400
  python3 record_serial.py --port /dev/ttyUSB0            # baud defaults to 38400

Tip: use the /dev/serial/by-id/ path (stable across reboots) if you can;
list them with:  ls /dev/serial/by-id/
"""
import argparse, sys, time, datetime
import serial   # pip install pyserial

ap = argparse.ArgumentParser()
ap.add_argument("--port", required=True, help="serial device, e.g. /dev/ttyUSB0")
ap.add_argument("--baud", type=int, default=38400, help="baud rate (AIS is usually 38400)")
ap.add_argument("--out", help="output file (default: ais_serial_<utc>.nmea)")
args = ap.parse_args()

outpath = args.out or f"ais_serial_{datetime.datetime.utcnow():%Y%m%dT%H%M%SZ}.nmea"

try:
    ser = serial.Serial(args.port, args.baud, timeout=1)
except Exception as e:
    print(f"cannot open {args.port} @ {args.baud}: {e}")
    sys.exit(1)

print(f"recording {args.port} @ {args.baud} -> {outpath}")
print("Ctrl-C to stop.")

n = 0
with open(outpath, "a", buffering=1) as out:
    try:
        while True:
            line = ser.readline().decode("ascii", "replace").strip()
            if line:
                ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                out.write(f"{ts}\t{line}\n")
                n += 1
                print(f"{ts}  {line}")
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()
        print(f"\nstopped. {n} lines saved to {outpath}")
