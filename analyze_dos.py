#!/usr/bin/env python3
"""Timeline analyzer for the DoS / alert experiments.

Unlike analyze.py (pass/fail checks), these experiments need a time-series view:
classify the transponder's OUTPUT over time as valid-fix / no-fix / alert, then
correlate it with the attack windows in events.jsonl to measure how long
legitimate reporting was suppressed and which inputs raised alarms.

Handles:
  parser_length_sweep / unterminated_hold / flood_dos  -> suppression analysis
  alert_trigger                                         -> per-probe alert counts

Usage: python3 analyze_dos.py results/<rundir>
"""
import json, os, sys

try:
    from pyais import decode as ais_decode
    HAVE = True
except Exception:
    HAVE = False

NOFIX_LAT, NOFIX_LON = 91.0, 181.0


def is_nofix(lat, lon):
    return abs(lat - NOFIX_LAT) < 0.01 and abs(lon - NOFIX_LON) < 0.01


def load(p):
    rows = []
    if os.path.exists(p):
        for line in open(p):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def is_alert(raw):
    if not raw.startswith("$"):
        return False
    head = raw[:8].upper()
    return ("ALR" in head) or ("ALC" in head) or raw.upper().startswith("$PFEC")


def classify(cap, spoof=None, baseline=None):
    """-> list of (t, kind, lat, lon); kind in fix/spoof/nofix/alert/undecodable.
    If spoof=(lat,lon) given, positions near it are tagged 'spoof' (the unit accepted
    the over-length sentence); positions near baseline are 'fix'; others are 'fix' too
    (any non-spoof, non-nofix position counts as the unit still reporting normally)."""
    def near(lat, lon, ref):
        return ref is not None and abs(lat - ref[0]) < 0.05 and abs(lon - ref[1]) < 0.05
    out = []
    for c in cap:
        raw = c.get("raw", ""); t = c.get("t")
        if raw.startswith("!AIVD"):
            if not HAVE:
                continue
            try:
                d = ais_decode(raw).asdict()
                if d.get("msg_type") in (1, 2, 3) and d.get("lat") is not None:
                    lat, lon = d["lat"], d["lon"]
                    if is_nofix(lat, lon):
                        kind = "nofix"
                    elif near(lat, lon, spoof):
                        kind = "spoof"
                    else:
                        kind = "fix"
                    out.append((t, kind, lat, lon))
            except Exception:
                out.append((t, "undecodable", None, None))
        elif is_alert(raw):
            out.append((t, "alert", None, None))
    return out


def first_after(series, kind, t):
    for (tt, k, *_ ) in series:
        if k == kind and tt >= t:
            return tt
    return None


def analyze_suppression(meta, events, series, t0):
    """For each attack_start/attack_end pair, measure DoS suppression."""
    starts = [e for e in events if e.get("event") == "attack_start"]
    ends = {e.get("length", e.get("kind")): e for e in events
            if e.get("event") == "attack_end"}
    # next attack_start time, to bound each attack's observation window
    start_ts = sorted(s["t"] for s in starts)
    rows = []
    for s in starts:
        a_start = s["t"]
        key = s.get("length", s.get("kind"))
        e = ends.get(key, {})
        a_end = e.get("t", a_start)
        write_s = e.get("write_s")
        pred_s = e.get("predicted_s")
        # window for THIS attack: from its start until the next attack starts
        nexts = [t for t in start_ts if t > a_start]
        win_end = nexts[0] if nexts else (a_start + 600)
        nofix_in = [t for (t, k, *_ ) in series
                    if k == "nofix" and a_start <= t < win_end]
        went_nofix = len(nofix_in) > 0
        # did the unit transmit the SPOOF position from the over-length sentence?
        spoof_in = [t for (t, k, *_ ) in series
                    if k == "spoof" and a_start <= t < win_end]
        accepted = len(spoof_in) > 0
        # was the unit's FIRST post-injection output a no-fix (denial) rather than a
        # held baseline? compare the time of the first nofix vs the first baseline fix
        # after the attack; recovery fixes later in the window don't negate a denial.
        first_nofix = min(nofix_in) if nofix_in else None
        first_basefix = None
        for (tt, k, *_ ) in series:
            if k == "fix" and a_start <= tt < win_end:
                first_basefix = tt; break
        degraded = (first_nofix is not None and
                    (first_basefix is None or first_nofix < first_basefix))
        if accepted:
            outcome = "ACCEPTED"
        elif degraded:
            outcome = "DEGRADED"
        else:
            outcome = "IGNORED"   # ingested (timing shows) but kept reporting baseline
        # recovery: first valid fix at/after attack end, before the next attack
        recov = None
        for (tt, k, *_ ) in series:
            if k == "fix" and a_end <= tt < win_end:
                recov = tt; break
        suppression = (recov - a_start) if recov else None
        rows.append({
            "attack": s.get("kind"),
            "length": s.get("length"),
            "rel_start_s": round(a_start - t0, 1),
            "write_s": write_s,
            "predicted_s": pred_s,
            "excess_s": (round(write_s - pred_s, 3)
                         if (write_s is not None and pred_s is not None) else None),
            "outcome": outcome,
            "accepted_spoof": accepted,
            "spoof_count": len(spoof_in),
            "went_nofix": went_nofix,
            "nofix_count": len(nofix_in),
            "suppression_s": round(suppression, 1) if suppression else None,
            "recovered": recov is not None,
        })
    return rows


def analyze_alerts(events, series):
    """Per-probe alert counts during the probe_start..probe_end window."""
    probes = []
    cur = None
    for e in events:
        if e.get("event") == "probe_start":
            cur = {"probe": e["probe"], "start": e["t"]}
        elif e.get("event") == "probe_end" and cur:
            cur["end"] = e["t"]
            n = sum(1 for (t, k, *_ ) in series
                    if k == "alert" and cur["start"] <= t <= cur["end"])
            nofix = sum(1 for (t, k, *_ ) in series
                        if k == "nofix" and cur["start"] <= t <= cur["end"])
            cur["alert_sentences"] = n
            cur["nofix_during"] = nofix
            probes.append(cur); cur = None
    return probes


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 analyze_dos.py results/<rundir>")
    rundir = sys.argv[1]
    meta = json.load(open(os.path.join(rundir, "metadata.json")))
    events = load(os.path.join(rundir, "events.jsonl"))
    cap = load(os.path.join(rundir, "capture.jsonl"))
    # recover the spoof and baseline positions from the run's events (if present)
    spoof = baseline = None
    for e in events:
        if e.get("spoof") and spoof is None:
            spoof = tuple(e["spoof"])
        if e.get("baseline") and baseline is None:
            baseline = tuple(e["baseline"])
    series = classify(cap, spoof=spoof, baseline=baseline)
    t0 = meta.get("start_t", events[0]["t"] if events else 0)

    fixes = sum(1 for (_, k, *_ ) in series if k == "fix")
    nofix = sum(1 for (_, k, *_ ) in series if k == "nofix")
    alerts = sum(1 for (_, k, *_ ) in series if k == "alert")
    exp = meta["experiment"]
    print(f"\n=== {exp} ===")
    print(f"output classified: {fixes} valid-fix, {nofix} no-fix, {alerts} alert "
          f"sentences  (decode {'on' if HAVE else 'OFF - pip install pyais'})")

    summary = {"experiment": exp, "totals": {"fix": fixes, "nofix": nofix, "alert": alerts}}

    if exp == "alert_trigger":
        probes = analyze_alerts(events, series)
        summary["probes"] = probes
        print("\nper-probe alert output:")
        print(f"  {'probe':24s} {'alerts':>7s} {'nofix':>6s}")
        for p in probes:
            flag = "  <-- triggers alerts" if p["alert_sentences"] > 0 else ""
            print(f"  {p['probe']:24s} {p['alert_sentences']:7d} "
                  f"{p['nofix_during']:6d}{flag}")
    else:
        rows = analyze_suppression(meta, events, series, t0)
        summary["attacks"] = rows
        summary["spoof"] = list(spoof) if spoof else None
        print(f"\nspoof position: {spoof}  (ACCEPTED = unit transmitted this)")
        print("suppression per attack:")
        hdr = f"  {'len/kind':>10s} {'outcome':>9s} {'pred_s':>7s} {'excess':>7s} " \
              f"{'suppress_s':>10s} {'recov':>6s}"
        print(hdr)
        for r in rows:
            lk = r["length"] if r["length"] is not None else r["attack"]
            print(f"  {str(lk):>10s} {str(r['outcome']):>9s} "
                  f"{str(r['predicted_s']):>7s} {str(r['excess_s']):>7s} "
                  f"{str(r['suppression_s']):>10s} "
                  f"{str(r['recovered']):>6s}")
        print("\nread: ACCEPTED = unit transmitted the spoof position (parsed the "
              "over-length sentence); DEGRADED = went to no-fix (denial); IGNORED = "
              "ingested but kept reporting baseline. suppression_s ~= predicted_s -> "
              "transmit-time-bound (no length enforcement).")

    with open(os.path.join(rundir, "summary_dos.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nwrote {os.path.join(rundir, 'summary_dos.json')}")


if __name__ == "__main__":
    main()
