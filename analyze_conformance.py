#!/usr/bin/env python3
"""Analyze a spec-conformance run: classify each case's outcome and roll up.

For each case window (case_start .. recover_start of that case) we look at the
transponder OUTPUT and classify against the running baseline fix:

  REJECTED   output stayed on the valid baseline position (no deviation)
             -> usually conformant. NOTE: on the sensor port this is
                indistinguishable from "ignored as irrelevant" for sentences the
                unit never consumes (talker/formatter/AIVDM cases) - flagged.
  ACCEPTED   transmitted position/identity CHANGED to reflect the injected input
             -> the security-relevant violation (it took bad data)
  DEGRADED   output went no-fix (91/181) or stopped -> robustness problem
  ALERTED    $AIALC/ALR/PFEC emitted during the window
  ANOMALOUS  undecodable/garbage output or other oddity

Controls are checked separately: a control that doesn't show a valid fix means
the unit had wedged by that point (tells you the run lost validity there).

Usage: python3 analyze_conformance.py results/<rundir>
"""
import json, os, sys
from collections import Counter, defaultdict

try:
    from pyais import decode as ais_decode
    HAVE = True
except Exception:
    HAVE = False

BASE_LAT, BASE_LON = 42.3500, -70.9000
SPOOF_LAT, SPOOF_LON = 43.5, -71.5      # distinct position malformed cases carry


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


def is_nofix(lat, lon):
    return abs(lat - 91.0) < 0.01 and abs(lon - 181.0) < 0.01


def near_baseline(lat, lon, tol=0.05):
    return abs(lat - BASE_LAT) < tol and abs(lon - BASE_LON) < tol


def near_spoof(lat, lon, tol=0.05):
    return abs(lat - SPOOF_LAT) < tol and abs(lon - SPOOF_LON) < tol


def rapidfire_index(lat, lon):
    """Rapid-fire sentences sit at lat 44.0 N, lon 072 deg + index arc-minutes.
    Return the integer index if this looks like a rapid-fire output, else None."""
    if abs(lat - 44.0) < 0.05 and 72.0 <= abs(lon) <= 72.40:
        return int(round((abs(lon) - 72.0) * 60))
    return None


def is_nak(raw):
    """The spec's defined listener rejection sentence (8.3.70). Detecting it splits
    'rejected silently' from 'rejected with a signaled NAK'."""
    return "NAK" in raw[:12].upper()


def is_alert(raw):
    h = raw[:8].upper()
    return raw.startswith("$") and ("ALR" in h or "ALC" in h or raw.upper().startswith("$PFEC"))


def classify_output(cap):
    """-> list of (t, kind, lat, lon, mmsi). kind: fix/nofix/alert/undecodable.

    Multi-fragment AIVDM/AIVDO (e.g. routine Type 5 static msgs) are reassembled
    by (channel, seq) so they are not mis-flagged undecodable. Only position
    reports (1/2/3) drive fix/nofix; other decoded types are ignored (not anomalies).
    """
    out = []
    frag = {}
    for c in cap:
        raw = c.get("raw", ""); t = c.get("t")
        if raw.startswith("!AIVD"):
            if not HAVE:
                continue
            try:
                parts = raw.split(",")
                ftot = int(parts[1]); fnum = int(parts[2]); seq = parts[3]; chan = parts[4]
            except Exception:
                out.append((t, "undecodable", None, None, None)); continue
            try:
                if ftot == 1:
                    d = ais_decode(raw).asdict()
                else:
                    key = (chan, seq)
                    frag.setdefault(key, {})[fnum] = raw
                    if len(frag[key]) < ftot:
                        continue                      # wait for the rest
                    ordered = [frag[key][i] for i in range(1, ftot + 1)]
                    frag.pop(key, None)
                    d = ais_decode(*ordered).asdict()
                if d.get("msg_type") in (1, 2, 3) and d.get("lat") is not None:
                    lat, lon = d["lat"], d["lon"]
                    kind = "nofix" if is_nofix(lat, lon) else "fix"
                    out.append((t, kind, lat, lon, d.get("mmsi"), d.get("speed")))
                # other message types (5, etc.) are routine - not anomalies
            except Exception:
                out.append((t, "undecodable", None, None, None, None))
        elif is_alert(raw):
            out.append((t, "alert", None, None, None, None))
    return out


def windows(events):
    """Pair case_start with the following recover_start (end of observation)."""
    cases = []
    cur = None
    for e in events:
        ev = e.get("event")
        if ev == "case_start":
            cur = dict(id=e["id"], category=e["category"], spec=e["spec"],
                       transport=e["transport"], expect=e["expect"],
                       start=e["t"])
        elif ev == "recover_start" and cur and e.get("id") == cur["id"]:
            cur["end"] = e["t"] + 0  # observation = case_start..recover_start point;
            cases.append(cur); cur = None
    return cases


def classify_case(case, series, base_alert_rate=0.0, base_nofix_rate=0.0):
    """Five-way classification of one case window.

    base_alert_rate = steady-state alert sentences/sec during the clean preflight settle.
    base_nofix_rate = steady-state no-fix sentences/sec during that same settle. Some
    units (DY) interleave no-fix reports continuously even while healthy and holding a
    fix, so a case only counts as DEGRADED if its no-fix rate rises clearly above this
    background AND the unit is not still emitting the baseline fix."""
    s = case["start"]
    # observe from case start until ~gap later; use next case start as hard bound
    e = case.get("win_end", s + 600)
    win = [(t, k, lat, lon, mmsi, spd) for (t, k, lat, lon, mmsi, spd) in series if s <= t < e]
    raw_alerts = sum(1 for (_, k, *_ ) in win if k == "alert")
    dur = max(e - s, 1e-6)
    expected_bg = base_alert_rate * dur
    # excess alerts above background chatter (>=3 and >50% over expected)
    excess = raw_alerts - expected_bg
    alerts = int(round(excess)) if (excess >= 3 and raw_alerts > 1.5 * expected_bg) else 0
    positions = [(t, lat, lon, mmsi, spd) for (t, k, lat, lon, mmsi, spd) in win if k == "fix"]
    nofix = [(t,) for (t, k, *_ ) in win if k == "nofix"]
    undec = [(t,) for (t, k, *_ ) in win if k == "undecodable"]
    # NAK: the spec's defined rejection signal, counted from the raw capture window
    naks = case.get("_naks", 0)
    # baseline-fix outputs still present in this window (unit holding the real fix)
    base_fix = [p for p in positions if near_baseline(p[1], p[2])]
    # no-fix measured as EXCESS over the unit's steady-state no-fix chatter: a case
    # only degraded the unit if no-fix rose clearly above background AND the baseline
    # fix output essentially stopped. Otherwise the no-fix is just normal interleaved
    # chatter (DY does this constantly) and the case did NOT deny the unit.
    expected_nofix = base_nofix_rate * dur
    nofix_excess = len(nofix) - expected_nofix
    degraded_real = (len(nofix) > 0 and nofix_excess >= 3
                     and len(nofix) > 1.5 * expected_nofix
                     and len(base_fix) <= max(2, 0.25 * len(nofix)))
    def _nofix_detail():
        return {"nofix_count": len(nofix), "nofix_excess": round(max(0.0, nofix_excess), 1),
                "base_fix_in_window": len(base_fix)}

    outcome = None
    detail = {}

    # ===== RAPID-FIRE: measure how far through the ordered sequence the unit kept up =====
    # Each input carried a distinct index (lon arc-minutes). The output index is the
    # high-water mark of what the unit ingested. This turns "did it drop input?" from a
    # guess into a measurement: max index reached / 20, and whether it advanced.
    if case["id"] == "spec_rapid_fire_valid":
        idxs = sorted({rapidfire_index(lat, lon) for (t, lat, lon, mmsi, spd) in positions
                       if rapidfire_index(lat, lon) is not None})
        if degraded_real and not idxs:
            outcome = "DEGRADED"; detail.update(_nofix_detail())
            detail["rapidfire"] = "burst drove unit to no-fix"
        elif not idxs:
            # never showed any rapid-fire position -> either rejected all or stayed baseline
            outcome = "REJECTED_VALID"
            detail["rapidfire"] = "no rapid-fire position output (dropped/ignored all 20 valid inputs)"
        else:
            hi = max(idxs)
            detail["rapidfire_max_index"] = f"{hi}/19"
            detail["rapidfire_distinct_seen"] = len(idxs)
            if hi >= 15:
                outcome = "TOLERATED"
                detail["rapidfire"] = f"kept up: reached index {hi}/19 (handled rapid valid input)"
            else:
                outcome = "DEGRADED"
                detail["rapidfire"] = (f"fell behind: high-water index only {hi}/19 "
                                       f"(dropped input under load)")
        if naks:
            detail["nak_count"] = naks
        return outcome, detail

    # ACCEPTED: the unit transmitted the SPOOF position the malformed sentence
    # carried -> it parsed and acted on out-of-spec input. This is unambiguous
    # because valid baseline GPS (42.35/-70.90) is flowing the whole time, so the
    # only way the spoof position (43.5/-71.5) appears is if the unit took it.
    spoofed = [(lat, lon) for (t, lat, lon, mmsi, spd) in positions if near_spoof(lat, lon)]
    # any other non-baseline, non-spoof, non-nofix position is also a deviation
    other_dev = [(lat, lon) for (t, lat, lon, mmsi, spd) in positions
                 if not near_baseline(lat, lon) and not near_spoof(lat, lon)
                 and not is_nofix(lat, lon)]
    if spoofed:
        outcome = "ACCEPTED"
        detail["accepted_spoof_position"] = True
        detail["positions"] = sorted({(round(a, 3), round(b, 3)) for a, b in spoofed})[:3]
    elif other_dev:
        outcome = "ACCEPTED"
        detail["accepted_unexpected_position"] = True
        detail["positions"] = sorted({(round(a, 3), round(b, 3)) for a, b in other_dev})[:3]
    elif degraded_real:
        outcome = "DEGRADED"
        detail.update(_nofix_detail())
    elif nofix and len(base_fix) > 0:
        # no-fix present but baseline fix still flowing and no-fix not above background
        # -> the unit ignored the bad input and kept reporting; that is REJECTED, the
        # no-fix is just this unit's normal interleaved chatter, not denial.
        outcome = "REJECTED"
        detail["nofix_chatter"] = len(nofix)
        detail["base_fix_in_window"] = len(base_fix)
    elif undec:
        outcome = "ANOMALOUS"
        detail["undecodable"] = len(undec)
    else:
        outcome = "REJECTED"
        # SILENCE CHECK: baseline GPS flows continuously, so during a normal window we
        # expect repeated baseline output. If the unit produced NO output at all for a
        # sustained stretch (and we didn't already see spoof/nofix), it went quiet ->
        # that is denial/anomaly, not a healthy rejection. Without this check a case
        # that silences the unit would look identical to a clean reject.
        # Bound the observation to a fixed window after case start (the inter-case gap
        # is ~50s); do NOT measure a tail gap to an arbitrary win_end (the last case's
        # win_end defaults far in the future, and the settle period legitimately has the
        # unit transmitting baseline). We only flag gaps BETWEEN outputs and an initial
        # gap from case start to first output.
        obs_end = min(e, s + 60)
        all_out_ts = sorted(t for (t, k, *_ ) in win if k in ("fix", "nofix", "alert")
                            and t < obs_end)
        observe_dur = obs_end - s
        if observe_dur >= 25:
            if not all_out_ts:
                outcome = "ANOMALOUS"
                detail["silent"] = "no output at all during the observation window"
            else:
                # gaps: case-start -> first output, and between consecutive outputs
                # (NOT last-output -> obs_end, which is just the quiet settle tail)
                edges = [s] + all_out_ts
                longest = max(edges[i + 1] - edges[i] for i in range(len(edges) - 1)) \
                    if len(edges) >= 2 else 0.0
                if longest >= 20 and "over_82" not in case["id"] and "just_over" not in case["id"]:
                    outcome = "ANOMALOUS"
                    detail["output_blackout_s"] = round(longest, 1)
                    detail["note_silence"] = ("unit went silent mid-window "
                                              "(possible transient denial / wedge)")
    # alerts are an overlay (can co-occur)
    if alerts:
        detail["alerts"] = alerts
    if naks:
        detail["nak_count"] = naks

    # ===== EXPECT-ACCEPT cases (legal input; accepting is CORRECT) =====
    # For these the healthy outcome is acceptance, not rejection. Invert the reading:
    # took the position -> TOLERATED (correct); stayed baseline/ignored -> REJECTED_VALID
    # (over-strict: rejected a legal sentence); nofix/anomalous stays a failure.
    if case.get("expect_accept"):
        if outcome == "ACCEPTED":
            outcome = "TOLERATED"
            detail["note_legal"] = "legal input correctly accepted"
        elif outcome == "REJECTED":
            outcome = "REJECTED_VALID"
            detail["note_legal"] = "rejected a LEGAL sentence (over-strict)"
        # DEGRADED / ANOMALOUS remain failures

    # ===== INDETERMINATE: rejection is not observable for these categories =====
    # AIVDM / encapsulation / proprietary / query sentences carry no GPS position, so
    # if the unit ignores them as irrelevant the output is unchanged - indistinguishable
    # from validating-and-rejecting. We can only call it a confirmed REJECT if the unit
    # emitted a NAK (the spec's defined rejection signal). Otherwise it's INDETERMINATE,
    # NOT a verified pass - so we never credit a pass we couldn't actually see.
    if outcome == "REJECTED" and case["category"] in (
            "aivdm", "proprietary", "query", "encapsulation"):
        if naks:
            detail["note"] = "confirmed reject: unit emitted NAK"
        else:
            outcome = "INDETERMINATE"
            detail["note"] = ("ignored-as-irrelevant vs validated-and-rejected "
                              "indistinguishable on this interface (no NAK, no position payload)")

    # speed reporting for speed/accel semantic cases: verify the unit actually
    # transmitted the (implausible) speed, not just the position
    if case["id"] in ("sem_speed_position_static", "sem_anchored_but_moving",
                       "seq_impossible_accel"):
        spds = [spd for (t, lat, lon, mmsi, spd) in positions if spd is not None]
        if spds:
            detail["max_transmitted_sog_kn"] = round(max(spds), 1)
            if max(spds) >= 40:
                detail["transmitted_implausible_speed"] = True

    # --- ingestion-gap measurement (esp. for over-length cases) ---
    # The longest silence between consecutive OUTPUT lines during the case window
    # tells us whether the unit READ the whole oversized line. If that gap ~= the
    # line's transmit time, the unit ingested all of it (length NOT enforced) even
    # if it didn't act on the content. A short gap with no nofix => likely rejected
    # at/near the boundary (the only truly conformant behavior for over-length).
    if case.get("predicted_s") is not None:
        out_ts = sorted(t for (t, k, *_ ) in win if k in ("fix", "nofix", "alert"))
        max_gap = 0.0
        if len(out_ts) >= 2:
            max_gap = max(out_ts[i] - out_ts[i-1] for i in range(1, len(out_ts)))
        pred = case["predicted_s"]
        detail["predicted_transmit_s"] = round(pred, 2)
        detail["max_output_gap_s"] = round(max_gap, 1)
        # did the gap track the transmit time? (read the whole line)
        ingested_whole = max_gap >= 0.6 * pred and pred >= 2.0
        detail["ingested_whole_line"] = bool(ingested_whole)
        # interpretation for over-length cases
        if "over_82" in case["id"] or "just_over" in case["id"]:
            if outcome == "REJECTED" and ingested_whole:
                detail["overlength_verdict"] = ("LENGTH NOT ENFORCED - read entire "
                    "over-length line then held baseline (absorbed, no spoof, no DoS)")
            elif outcome == "REJECTED" and not ingested_whole and pred >= 2.0:
                detail["overlength_verdict"] = ("possibly bounded - no long output gap; "
                    "may have rejected near the 82-char limit (conformant)")
            elif outcome == "DEGRADED":
                detail["overlength_verdict"] = ("LENGTH NOT ENFORCED - ingested line, "
                    "starved position to no-fix (DoS)")
            elif outcome == "ACCEPTED":
                detail["overlength_verdict"] = ("LENGTH NOT ENFORCED - parsed and ACTED "
                    "on over-length content (spoof accepted)")

    return outcome, detail


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 analyze_conformance.py results/<rundir>")
    rundir = sys.argv[1]
    meta = json.load(open(os.path.join(rundir, "metadata.json")))
    events = load(os.path.join(rundir, "events.jsonl"))
    cap = load(os.path.join(rundir, "capture.jsonl"))
    series = classify_output(cap)

    cases = windows(events)
    # attach predicted transmit time per case (from the case library) so the
    # ingestion-gap measurement can compare output silence to line transmit time
    gps_baud = meta.get("gps_baud", 4800)
    try:
        import conformance_cases as _cc
        bylen = {c["id"]: (len(c["gen"]()) if not c.get("seq") else None) for c in _cc.CASES}
        bytax = {c["id"]: (c.get("tier", "?"), c.get("harm", "?")) for c in _cc.CASES}
        byaccept = {c["id"]: c.get("expect_accept", False) for c in _cc.CASES}
    except Exception:
        bylen = {}; bytax = {}; byaccept = {}
    for c in cases:
        nbytes = bylen.get(c["id"])
        c["predicted_s"] = (nbytes * 10.0 / gps_baud) if nbytes else None
        c["expect_accept"] = byaccept.get(c["id"], False)
    # set each case's window end to the next case/control start (hard bound)
    starts = sorted([e["t"] for e in events
                     if e.get("event") in ("case_start", "control_start")])
    for c in cases:
        nxt = [t for t in starts if t > c["start"]]
        c["win_end"] = nxt[0] if nxt else (c["start"] + 600)
    # per-window NAK count from the raw capture (the spec's defined rejection signal),
    # measured as EXCESS over the steady-state background NAK rate - some units (em-trak)
    # emit NAKs continuously, so a raw count is meaningless; only a clear rise over
    # baseline indicates this case provoked rejection.
    # (base_nak_rate is computed below from the preflight settle; defer excess calc)
    for c in cases:
        raw_naks = sum(1 for cc_ in cap
                       if c["start"] <= cc_.get("t", 0) < c["win_end"]
                       and is_nak(cc_.get("raw", "")))
        c["_raw_naks"] = raw_naks
        c["_win_dur"] = max(c["win_end"] - c["start"], 1e-6)

    # steady-state alert chatter: rate during the clean preflight settle
    # (everything before the first case_start)
    first_case_t = min([c["start"] for c in cases], default=None)
    preflight_start = meta.get("start_t")
    base_alert_rate = 0.0
    base_nak_rate = 0.0
    base_nofix_rate = 0.0
    if first_case_t and preflight_start and first_case_t > preflight_start:
        span = first_case_t - preflight_start
        bg = sum(1 for (t, k, *_ ) in series
                 if k == "alert" and preflight_start <= t < first_case_t)
        base_alert_rate = bg / span
        bgn = sum(1 for cc_ in cap
                  if preflight_start <= cc_.get("t", 0) < first_case_t
                  and is_nak(cc_.get("raw", "")))
        base_nak_rate = bgn / span
        # steady-state no-fix chatter during the clean settle (DY interleaves no-fix
        # even while healthy; without this, every case looks DEGRADED)
        bgnf = sum(1 for (t, k, *_ ) in series
                   if k == "nofix" and preflight_start <= t < first_case_t)
        base_nofix_rate = bgnf / span

    # now resolve per-case NAK EXCESS over background (>=3 and >50% over expected)
    for c in cases:
        expected = base_nak_rate * c.get("_win_dur", 1.0)
        excess = c.get("_raw_naks", 0) - expected
        c["_naks"] = int(round(excess)) if (excess >= 3 and
                          c.get("_raw_naks", 0) > 1.5 * expected) else 0

    results = []
    for c in cases:
        outcome, detail = classify_case(c, series, base_alert_rate, base_nofix_rate)
        tier, harm = bytax.get(c["id"], ("?", "?"))
        results.append({"id": c["id"], "category": c["category"], "spec": c["spec"],
                        "transport": c["transport"], "expect": c["expect"],
                        "tier": tier, "harm": harm,
                        "outcome": outcome, "detail": detail})

    # control health
    ctrl_windows = []
    cw = None
    for e in events:
        if e.get("event") == "control_start":
            cw = {"seq": e.get("seq"), "start": e["t"]}
        elif e.get("event") == "control_end" and cw:
            cw["end"] = e["t"]; ctrl_windows.append(cw); cw = None
    ctrl_ok = 0
    for w in ctrl_windows:
        nxt = [t for t in starts if t > w["start"]]
        we = nxt[0] if nxt else w["start"] + 600
        if any(k == "fix" and near_baseline(lat, lon)
               for (t, k, lat, lon, mmsi, spd) in series if w["start"] <= t < we):
            ctrl_ok += 1

    vendor = meta.get("vendor", "?")
    print(f"\n=== spec_conformance: {vendor} ===")
    print(f"cases analyzed: {len(results)}   "
          f"controls healthy: {ctrl_ok}/{len(ctrl_windows)}   "
          f"decode {'on' if HAVE else 'OFF (pip install pyais)'}")

    by_outcome = Counter(r["outcome"] for r in results)
    print("\noutcome totals:", dict(by_outcome))

    # the headline: anything ACCEPTED / DEGRADED is interesting
    interesting = [r for r in results if r["outcome"] in
                   ("ACCEPTED", "DEGRADED", "ANOMALOUS", "REJECTED_VALID", "INDETERMINATE")]
    if interesting:
        print("\n*** non-REJECTED outcomes (look here first) ***")
        for r in interesting:
            print(f"  {r['outcome']:9s} {r['id']:28s} {r['category']:12s} "
                  f"{r['detail']}")
    else:
        print("\nAll cases REJECTED/ignored (no accept/degrade/anomaly).")

    # per-category rollup
    print("\nper-category outcomes:")
    cat = defaultdict(Counter)
    for r in results:
        cat[r["category"]][r["outcome"]] += 1
    for k in sorted(cat):
        print(f"  {k:14s} {dict(cat[k])}")

    # ===== TWO-AXIS TABLE: obligation tier x harm class =====
    def failed(r):
        return r["outcome"] in ("ACCEPTED", "DEGRADED", "ANOMALOUS")
    tiers = ["explicit", "vague", "absent", "conformant_behavior"]
    harms = ["false_target", "false_environment", "remote_command",
             "channel_denial", "receiver_compromise"]
    hlabel = {"false_target": "false_tgt", "false_environment": "false_env",
              "remote_command": "remote_cmd", "channel_denial": "chan_deny",
              "receiver_compromise": "recv_comp"}
    print(f"\n===== TWO-AXIS: failures by obligation tier x harm class ({vendor}) =====")
    print("  cell = (failed / total) cases in that tier+harm; '-' = none")
    print("  " + f"{'tier':>20s} " + " ".join(f"{hlabel[h]:>10s}" for h in harms))
    for t in tiers:
        row = []
        for h in harms:
            cell = [r for r in results if r["tier"] == t and r["harm"] == h]
            row.append((f"{sum(1 for r in cell if failed(r))}/{len(cell)}"
                        if cell else "-").rjust(10))
        print(f"  {t:>20s} " + " ".join(row))

    # per-tier rollup - the headline counts
    print("\nper-tier summary:")
    for t in ["explicit", "vague", "absent"]:
        tc = [r for r in results if r["tier"] == t]
        if not tc:
            continue
        f = [r for r in tc if failed(r)]
        label = {"explicit": "explicit spec requirements VIOLATED (clear conformance failures)",
                 "vague": "vague/ambiguous-clause cases mishandled",
                 "absent": "absent-obligation cases exploitable (COMPLIANT-but-exploitable)"}[t]
        print(f"  {t:8s}: {len(f)}/{len(tc)} {label}")
        for r in f:
            print(f"            - {r['outcome']:9s} {r['id']} ({r['harm']})")

    # over-length length-enforcement table (the §7.3.1 finding, with ingestion timing)
    ol = [r for r in results if ("over_82" in r["id"] or "just_over" in r["id"])]
    if ol:
        def _len(r):
            import re
            m = re.search(r"(\d+)$", r["id"]); return int(m.group(1)) if m else 0
        ol.sort(key=_len)
        print("\nover-length (\u00a77.3.1, 82-char max) - did the unit enforce the bound?")
        print(f"  {'chars':>6} {'outcome':>9} {'pred_s':>7} {'out_gap_s':>9} {'read_all':>8}  verdict")
        for r in ol:
            d = r["detail"]
            print(f"  {_len(r):>6} {r['outcome']:>9} "
                  f"{str(d.get('predicted_transmit_s','-')):>7} "
                  f"{str(d.get('max_output_gap_s','-')):>9} "
                  f"{str(d.get('ingested_whole_line','-')):>8}  "
                  f"{d.get('overlength_verdict','')}")

    # alerts overlay
    alerted = [r for r in results if "alerts" in r["detail"]]
    if alerted:
        print(f"\ncases that produced alert output ({len(alerted)}):")
        for r in alerted:
            print(f"  {r['id']:28s} alerts={r['detail']['alerts']}")

    out = {"vendor": vendor, "controls_ok": ctrl_ok, "controls_total": len(ctrl_windows),
           "outcome_totals": dict(by_outcome), "cases": results}
    with open(os.path.join(rundir, "summary_conformance.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {os.path.join(rundir, 'summary_conformance.json')}")
    print("note: REJECTED for address/aivdm/proprietary/query/encap may be 'ignored "
          "as irrelevant' rather than 'validated+rejected' - see per-case detail.")


if __name__ == "__main__":
    main()
