#!/usr/bin/env bash
# record_ais.sh -- start the RTL-SDR listening for AIS and record timestamped NMEA.
# Run this AFTER the one-time setup. Stop with Ctrl-C; each run writes one dated file.
set -euo pipefail

# ---- config: edit these ----
SERIAL=""            # dongle serial (e.g. 88874440) for stable selection; blank = first device
PPM=0                 # frequency correction from your `rtl_test -p` calibration
GAIN=auto            # tuner gain: "auto" or a fixed number like 38.6
OUTDIR="$HOME/ais"   # where recordings are written
WEBPORT=8100         # live map at http://<pi-ip>:WEBPORT
UDPPORT=10110        # internal only: AIS-catcher -> logger
STATS=30             # print receiver stats every N seconds
# ----------------------------

# Fail early if the pieces aren't in place.
command -v AIS-catcher >/dev/null 2>&1 || {
  echo "AIS-catcher not found in PATH. Run the one-time setup first." >&2; exit 1; }
if ! lsusb | grep -qi 'RTL28'; then
  echo "No RTL-SDR dongle detected on USB (lsusb). Check it's plugged in." >&2; exit 1
fi

mkdir -p "$OUTDIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTFILE="$OUTDIR/ais_${TS}.nmea"

# Tiny UDP logger: writes "<utc-iso>\t<nmea>" per message, line-buffered to disk
# so nothing is lost even on an abrupt stop. NMEA goes here; stats stay on screen.
read -r -d '' LOGGER <<'PY' || true
import socket, sys, datetime
out = open(sys.argv[1], "a", buffering=1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[2])))
try:
    while True:
        data, _ = s.recvfrom(4096)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for line in data.decode("ascii", "replace").splitlines():
            line = line.strip()
            if line:
                out.write(f"{ts}\t{line}\n")
except KeyboardInterrupt:
    pass
finally:
    out.close()
PY

python3 -u -c "$LOGGER" "$OUTFILE" "$UDPPORT" &
LOGGER_PID=$!

_cleaned=0
cleanup() {
  [ "$_cleaned" = 1 ] && return; _cleaned=1
  kill "$LOGGER_PID" 2>/dev/null || true
  wait "$LOGGER_PID" 2>/dev/null || true
  lines="$(wc -l < "$OUTFILE" 2>/dev/null || echo 0)"
  echo
  echo "Stopped. Recorded ${lines} NMEA lines to ${OUTFILE}"
}
trap cleanup EXIT

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "Recording to: $OUTFILE"
echo "Live map:     http://${IP:-<pi-ip>}:${WEBPORT}"
echo "Press Ctrl-C to stop."
echo

# Device selection: AIS-catcher reads "-d <number>" as a SERIAL, not an index.
# Use the serial if given (stable across reboots); otherwise "-d:0" = first device by index.
if [ -n "$SERIAL" ]; then DEV_ARG=(-d "$SERIAL"); else DEV_ARG=(-d:0); fi

# Give the logger a moment to bind, then start the receiver in the foreground.
# -u feeds the logger; -N serves the map; -o 0 keeps screen NMEA off (UDP is separate).
sleep 1
AIS-catcher \
  "${DEV_ARG[@]}" \
  -p "$PPM" \
  -gr TUNER "$GAIN" RTLAGC on \
  -N "$WEBPORT" \
  -u 127.0.0.1 "$UDPPORT" \
  -o 0 \
  -v "$STATS"
