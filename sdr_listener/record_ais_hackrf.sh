#!/usr/bin/env bash
# record_ais.sh -- HackRF AIS receiver + timestamped NMEA logger.
# Receive-only (legal with an antenna). Run after the one-time setup.
# Stop with Ctrl-C; each run writes a dated .nmea (data), .log (diagnostics),
# and .meta (the config that was active) so runs are reproducible and debuggable.
set -euo pipefail

# ---- config: edit these ----
SERIAL=""            # HackRF serial for stable selection; blank = first device.
                     # Find it with:  AIS-catcher -L    (or: hackrf_info)
LNA_GAIN=16          # HackRF LNA (IF) gain: 0-40 in steps of 8. Keep LOW for the
                     # close-range cage to avoid front-end overload.
VGA_GAIN=20          # HackRF VGA (baseband) gain: 0-62 in steps of 2. Keep LOW.
PREAMP="off"         # HackRF preamplifier (extra gain). OFF at close range; you have
                     # plenty of signal and the preamp will overload the receiver.
CHANNELS="AB"        # AIS channel pair: AB = 161.975/162.025 MHz (standard).
OUTDIR="$HOME/ais"   # where recordings are written
WEBPORT=8100         # live map at http://<pi-ip>:WEBPORT
UDPPORT=10110        # internal only: AIS-catcher -> logger
STATS=30             # receiver prints stats every N seconds
LIVENESS=60          # logger writes a heartbeat line every N seconds
RESTART_WAIT=2       # seconds to wait before restarting a crashed receiver
# ----------------------------

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

# ---- fail-fast preflight (catch problems before a long run, not after) ----
command -v AIS-catcher >/dev/null 2>&1 || {
  log "FATAL: AIS-catcher not in PATH. Run the one-time setup first."; exit 1; }
command -v python3 >/dev/null 2>&1 || { log "FATAL: python3 not found."; exit 1; }
# HackRF USB id is 1d50:6089; also match the name in case ids differ.
if ! lsusb | grep -qiE 'HackRF|1d50:6089'; then
  log "FATAL: no HackRF on USB (lsusb shows no HackRF). Check the cable."; exit 1
fi
mkdir -p "$OUTDIR"
if ! touch "$OUTDIR/.write_test" 2>/dev/null; then
  log "FATAL: cannot write to $OUTDIR"; exit 1
fi
rm -f "$OUTDIR/.write_test"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTFILE="$OUTDIR/ais_${TS}.nmea"
LOGFILE="$OUTDIR/ais_${TS}.log"
METAFILE="$OUTDIR/ais_${TS}.meta"

# ---- record the active config so runs are comparable later ----
{
  echo "start_utc=$TS"
  echo "device=HackRF"
  echo "serial=${SERIAL:-<first-device>}"
  echo "lna_gain=$LNA_GAIN"
  echo "vga_gain=$VGA_GAIN"
  echo "preamp=$PREAMP"
  echo "channels=$CHANNELS"
  echo "webport=$WEBPORT"
  echo "udpport=$UDPPORT"
  echo "aiscatcher_version=$(AIS-catcher -h 2>&1 | head -1 || echo unknown)"
  echo "host=$(hostname)"
} > "$METAFILE"

# ---- UDP logger: writes "<utc-iso>\t<nmea>" per message, line-buffered so an
# abrupt stop loses nothing. Also writes a periodic heartbeat with the running
# message count, so a quiet channel is distinguishable from a dead receiver. ----
read -r -d '' LOGGER <<'PY' || true
import socket, sys, datetime, threading
outpath, port, liveness = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
out = open(outpath, "a", buffering=1)
count = {"n": 0}
lock = threading.Lock()

def heartbeat():
    while True:
        threading.Event().wait(liveness)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with lock:
            n = count["n"]
        # heartbeat goes to stderr (-> .log), NOT the .nmea data file
        sys.stderr.write(f"{ts}\tHEARTBEAT\tmessages_logged={n}\n")
        sys.stderr.flush()

threading.Thread(target=heartbeat, daemon=True).start()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port))
except OSError as e:
    sys.stderr.write(f"FATAL: logger could not bind UDP {port}: {e}\n")
    sys.exit(1)
sys.stderr.write(f"logger bound on 127.0.0.1:{port}, writing {outpath}\n")
sys.stderr.flush()
try:
    while True:
        data, _ = s.recvfrom(4096)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for line in data.decode("ascii", "replace").splitlines():
            line = line.strip()
            if line:
                out.write(f"{ts}\t{line}\n")
                sys.stdout.write(f"{ts}\t{line}\n")   # echo NMEA to screen (live debug)
                with lock:
                    count["n"] += 1
except KeyboardInterrupt:
    pass
finally:
    out.close()
PY

# start logger; its stderr (bind confirmation + heartbeats) goes to the .log
python3 -u -c "$LOGGER" "$OUTFILE" "$UDPPORT" "$LIVENESS" 2>>"$LOGFILE" &
LOGGER_PID=$!

# verify the logger actually came up and bound (don't run blind if it died)
sleep 1
if ! kill -0 "$LOGGER_PID" 2>/dev/null; then
  log "FATAL: UDP logger failed to start (see $LOGFILE). Is port $UDPPORT in use?"; exit 1
fi
if ! grep -q "logger bound" "$LOGFILE" 2>/dev/null; then
  log "WARNING: logger bind not confirmed yet; check $LOGFILE if no data appears."
fi

_cleaned=0
cleanup() {
  [ "$_cleaned" = 1 ] && return; _cleaned=1
  kill "$LOGGER_PID" 2>/dev/null || true
  wait "$LOGGER_PID" 2>/dev/null || true
  lines="$(wc -l < "$OUTFILE" 2>/dev/null || echo 0)"
  log "Stopped. Recorded ${lines} NMEA lines to ${OUTFILE}"
  log "Diagnostics: ${LOGFILE}   Config: ${METAFILE}"
}
trap cleanup EXIT

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
log "Recording NMEA -> $OUTFILE"
log "Diagnostics    -> $LOGFILE"
log "Live map       -> http://${IP:-<pi-ip>}:${WEBPORT}"
log "HackRF LNA=$LNA_GAIN VGA=$VGA_GAIN PREAMP=$PREAMP  channels=$CHANNELS  Heartbeat every ${LIVENESS}s in the .log"
log "Press Ctrl-C to stop."

# HackRF device selection: by serial if given, else first device.
if [ -n "$SERIAL" ]; then DEV_ARG=(-d "$SERIAL"); else DEV_ARG=(-d:0); fi

# ---- restart loop: a USB hiccup or transient receiver error should NOT silently
# end the capture. Each (re)start is timestamped in the .log so a crash is a
# visible event, not a dead run. Ctrl-C breaks the loop via the trap. ----
RUN=1
while [ "$_cleaned" = 0 ]; do
  log "starting AIS-catcher (attempt $RUN)" | tee -a "$LOGFILE"
  set +e
  AIS-catcher \
    "${DEV_ARG[@]}" \
    -c "$CHANNELS" \
    -gf lna "$LNA_GAIN" vga "$VGA_GAIN" preamp "$PREAMP" \
    -N "$WEBPORT" \
    -u 127.0.0.1 "$UDPPORT" \
    -o 0 \
    -X off \
    -v "$STATS" \
    2>>"$LOGFILE"
  rc=$?
  set -e
  [ "$_cleaned" = 1 ] && break
  log "AIS-catcher exited (rc=$rc); restarting in ${RESTART_WAIT}s" | tee -a "$LOGFILE"
  RUN=$((RUN+1))
  sleep "$RESTART_WAIT"
done
