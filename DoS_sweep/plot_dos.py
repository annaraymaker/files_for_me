#!/usr/bin/env python3
r"""
plot_dos.py -- paper-ready figures from analyze_dos.py CSVs.

Panels:
  (1) OUTAGE vs input length, log-x, per vendor, with the transmission-time reference line
      tx = len/(baud/10). The gap ABOVE the line is the amplification -- the whole argument in
      one picture: on the line = pure occupancy, above it = the parser hurting itself. Knee marked.
  (2) REACQUISITION vs input length, per vendor (the recovery penalty after the bus is free).
  (3) SUSTAINED hold (if *_sustained.csv given): dark time per vendor -- "held dark as long as
      the attacker streams."

Usage:
  python3 plot_dos.py --baud 4800 --out dos \
      emtrak=emtrak_dos.csv DY=dy_dos.csv Furuno=furuno_dos.csv
Each arg is LABEL=path/to.csv. A sibling LABEL_sustained.csv (or path with _sustained) is auto-used.
"""
import sys, csv, argparse, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COLORS = ["#c1272d", "#0000a7", "#008176", "#eecc16", "#b3b3b3"]  # colsafe-ish


def load_csv(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            def fl(k):
                v = r.get(k, "")
                return float(v) if v not in ("", None) else None
            rows.append(dict(alen=int(float(r["actual_len"])), tx=fl("tx_pred_s"),
                             out=fl("outage_med_s"), omin=fl("outage_min_s"), omax=fl("outage_max_s"),
                             reacq=fl("reacq_med_s"), verdict=r.get("verdict", "")))
    rows.sort(key=lambda x: x["alen"])
    return rows


def load_sustained(path):
    if not os.path.exists(path): return None
    with open(path) as f:
        r = next(csv.DictReader(f), None)
    if not r: return None
    def fl(k):
        v = r.get(k, ""); return float(v) if v not in ("", None) else None
    return dict(dark=fl("dark_s"), recov=fl("recovery_s"), writes=r.get("writes"), alen=r.get("actual_len"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("series", nargs="+", help="LABEL=path.csv")
    ap.add_argument("--baud", type=int, default=4800)
    ap.add_argument("--out", default="dos")
    args = ap.parse_args()
    cps = args.baud / 10.0

    data = {}
    for s in args.series:
        label, path = s.split("=", 1)
        data[label] = dict(rows=load_csv(path),
                            sust=load_sustained(path.replace(".csv", "_sustained.csv")))

    # ---------- Panel 1: outage vs length + tx reference ----------
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    all_len = sorted({r["alen"] for d in data.values() for r in d["rows"]})
    ax.plot(all_len, [n / cps for n in all_len], "k--", lw=1.4, zorder=1,
            label=f"transmission time (len/{cps:.0f})")
    for i, (label, d) in enumerate(data.items()):
        rows = d["rows"]; c = COLORS[i % len(COLORS)]
        x = [r["alen"] for r in rows]; y = [r["out"] for r in rows]
        lo = [(r["out"] - r["omin"]) if r["out"] is not None and r["omin"] is not None else 0 for r in rows]
        hi = [(r["omax"] - r["out"]) if r["out"] is not None and r["omax"] is not None else 0 for r in rows]
        ax.errorbar(x, y, yerr=[lo, hi], fmt="o-", color=c, lw=1.6, ms=4, capsize=2, label=label, zorder=3)
        knee = next((r for r in rows if r["verdict"] != "BOUNDED" and r["out"]), None)
        if knee:
            ax.annotate(f"knee\n~{knee['alen']} ch", xy=(knee["alen"], knee["out"]),
                        xytext=(knee["alen"] * 1.1, (knee["out"] or 1) + 8), fontsize=8, color=c,
                        arrowprops=dict(arrowstyle="->", color=c, lw=1))
    ax.set_xscale("log"); ax.set_xlabel("injected sentence length (chars)")
    ax.set_ylabel("position-report outage (s)")
    ax.set_title("Serial over-length DoS: outage vs. input length")
    ax.grid(True, which="both", ls=":", alpha=0.5); ax.legend(fontsize=8, loc="upper left")
    fig.tight_layout(); fig.savefig(f"{args.out}_outage.png", dpi=160); fig.savefig(f"{args.out}_outage.pdf")

    # ---------- Panel 2: reacquisition ----------
    fig2, ax2 = plt.subplots(figsize=(6.4, 4.0))
    for i, (label, d) in enumerate(data.items()):
        rows = d["rows"]; c = COLORS[i % len(COLORS)]
        x = [r["alen"] for r in rows]; y = [r["reacq"] for r in rows]
        ax2.plot(x, y, "s-", color=c, lw=1.6, ms=4, label=label)
    ax2.axhline(2.0, color="k", ls=":", lw=1, label="normal report interval (~2s)")
    ax2.set_xscale("log"); ax2.set_xlabel("injected sentence length (chars)")
    ax2.set_ylabel("reacquisition after line clears (s)")
    ax2.set_title("Recovery penalty (persistence beyond line time)")
    ax2.grid(True, which="both", ls=":", alpha=0.5); ax2.legend(fontsize=8)
    fig2.tight_layout(); fig2.savefig(f"{args.out}_reacq.png", dpi=160); fig2.savefig(f"{args.out}_reacq.pdf")

    # ---------- Panel 3: sustained hold ----------
    susts = {k: d["sust"] for k, d in data.items() if d["sust"]}
    if susts:
        fig3, ax3 = plt.subplots(figsize=(6.0, 3.6))
        labels = list(susts); dark = [susts[k]["dark"] or 0 for k in labels]
        recov = [susts[k]["recov"] or 0 for k in labels]
        y = range(len(labels))
        ax3.barh(y, dark, color="#c1272d", label="dark (no position)")
        ax3.barh(y, recov, left=dark, color="#eecc16", label="recovery")
        ax3.set_yticks(list(y)); ax3.set_yticklabels(labels)
        ax3.set_xlabel("seconds"); ax3.set_title("Sustained injection: vessel held off the traffic picture")
        ax3.legend(fontsize=8, loc="lower right"); ax3.grid(True, axis="x", ls=":", alpha=0.5)
        fig3.tight_layout(); fig3.savefig(f"{args.out}_sustained.png", dpi=160); fig3.savefig(f"{args.out}_sustained.pdf")

    made = [f"{args.out}_outage", f"{args.out}_reacq"] + ([f"{args.out}_sustained"] if susts else [])
    print("wrote: " + ", ".join(f"{m}.png/.pdf" for m in made))


if __name__ == "__main__":
    main()
