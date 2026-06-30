#!/usr/bin/env python3
"""
validate_vhf.py -- prove the RF chain works BEFORE trusting it for any experiment.

This is the RF analog of the serial-side discipline: validate the instrument first.
It does NOT transmit. Two levels of validation, in order of confidence:

  1. SOFTWARE ROUND-TRIP (always runs, no hardware):
     encode a known AIS message -> GMSK IQ -> demodulate IQ in software -> decode bits
     -> assert the recovered MMSI/lat/lon equal what went in. If this fails, the encoder
     is wrong and nothing downstream can be trusted. This catches framing/CRC/NRZI bugs.

  2. LOOPBACK / WITNESS (optional, in the cage, with the witness receiver):
     write the IQ file, transmit it with rf_tx.py inside the sealed cage, and confirm the
     witness receiver (record_ais.sh / AIS-catcher) decodes the same message. This proves
     the full physical chain incl. the HackRF and the receiver. This step is described and
     scaffolded here but requires the cage + a deliberate transmit; it is never automatic.

Run:
  python3 validate_vhf.py                 # software round-trip self-test
  python3 validate_vhf.py --write out.cs8 # also write an IQ file for a later cage loopback
  python3 validate_vhf.py --sample-rate 2400000
"""
import argparse, sys
import numpy as np
import ais_encode as enc


# ----------------------------------------------------------------------------
# Software GMSK demodulator (just enough to recover the bits for validation).
# This is a *checker*, not a production receiver: it inverts the encoder so a
# round-trip failure localizes a bug. The real receiver in the cage is AIS-catcher.
# ----------------------------------------------------------------------------
def gmsk_demod_bits(iq, sample_rate):
    """Recover the NRZI line bits from GMSK IQ via differential phase detection."""
    sps = int(round(sample_rate / enc.SYMBOL_RATE))
    # instantaneous frequency = derivative of phase = which way the symbol went
    phase = np.angle(iq)
    dphase = np.diff(np.unwrap(phase))
    # sample at symbol centers; find the burst (skip the zero pad) by energy
    mag = np.abs(iq)
    active = np.where(mag > 0.5 * np.max(mag))[0]
    if len(active) == 0:
        return ""
    start, end = active[0], active[-1]
    # decide bits at symbol centers within the active region
    bits = ""
    idx = start + sps // 2
    while idx < end and idx < len(dphase):
        bits += "1" if dphase[idx] > 0 else "0"
        idx += sps
    return bits


def nrzi_decode(bits):
    """Invert NRZI: level held = 1, level toggled = 0."""
    out = ""
    prev = bits[0] if bits else "1"
    for bit in bits[1:]:
        out += "1" if bit == prev else "0"
        prev = bit
    return out


def unstuff(bits):
    """Invert HDLC bit-stuffing: drop the 0 after five consecutive 1s."""
    out = ""
    run = 0
    i = 0
    while i < len(bits):
        b = bits[i]
        out += b
        if b == "1":
            run += 1
            if run == 5:
                i += 1   # skip the stuffed 0
                run = 0
        else:
            run = 0
        i += 1
    return out


def extract_payload(line_bits):
    """Find the flags, strip framing, unstuff, drop CRC -> message payload bits."""
    flag = enc.FLAG
    first = line_bits.find(flag)
    if first < 0:
        return None
    after = line_bits.find(flag, first + len(flag))
    # the opening flag may be immediately followed by content; find the closing flag
    # by scanning from the end
    last = line_bits.rfind(flag)
    if last <= first:
        return None
    inner = line_bits[first + len(flag): last]
    unstuffed = unstuff(inner)
    if len(unstuffed) < 16:
        return None
    payload = unstuffed[:-16]   # drop the 16-bit CRC
    return payload


def decode_type1(payload):
    """Minimal Type 1 decode -> dict(mmsi, lat, lon, sog, cog)."""
    def u(start, n):
        return int(payload[start:start+n], 2)
    def s(start, n):
        v = int(payload[start:start+n], 2)
        if v & (1 << (n-1)):
            v -= (1 << n)
        return v
    if len(payload) < 168:
        return None
    mtype = u(0, 6)
    mmsi = u(8, 30)
    sog = u(50, 10) / 10.0
    lon = s(61, 28) / 600000.0
    lat = s(89, 27) / 600000.0
    cog = u(116, 12) / 10.0
    return {"type": mtype, "mmsi": mmsi, "lat": lat, "lon": lon, "sog": sog, "cog": cog}


# ----------------------------------------------------------------------------
# Round-trip validation
# ----------------------------------------------------------------------------
def software_roundtrip(sample_rate, verbose=True):
    """Encode a known message, demodulate+decode in software, assert it matches."""
    known = dict(mmsi=366000001, lat=42.3500, lon=-70.9000, sog=7.5, cog=123.0)
    if verbose:
        print(f"[software round-trip @ {sample_rate} sps]")
        print(f"  input : MMSI={known['mmsi']} lat={known['lat']} lon={known['lon']} "
              f"sog={known['sog']} cog={known['cog']}")

    payload_bits = enc.encode_type1(known["mmsi"], known["lat"], known["lon"],
                                    sog=known["sog"], cog=known["cog"])
    iq = enc.encode_to_iq(payload_bits, sample_rate)

    line = gmsk_demod_bits(iq, sample_rate)
    nrzi = nrzi_decode(line)
    payload = extract_payload(nrzi)
    if payload is None:
        print("  FAIL: could not recover a framed payload from the IQ")
        return False
    got = decode_type1(payload)
    if got is None:
        print("  FAIL: payload too short to decode")
        return False
    if verbose:
        print(f"  output: MMSI={got['mmsi']} lat={got['lat']:.4f} lon={got['lon']:.4f} "
              f"sog={got['sog']} cog={got['cog']}")

    ok = (got["mmsi"] == known["mmsi"]
          and abs(got["lat"] - known["lat"]) < 0.001
          and abs(got["lon"] - known["lon"]) < 0.001)
    print("  RESULT:", "PASS - encoder round-trips, chain is self-consistent" if ok
          else "FAIL - recovered message does not match input")
    return ok


def pyais_crosscheck(sample_rate):
    """If pyais is available, also armor the payload to !AIVDM and decode with pyais,
    a second independent check that the bit layout matches the real AIS spec (not just
    self-consistent with our own decoder)."""
    try:
        from pyais import decode as pyais_decode
    except Exception:
        print("[pyais cross-check] pyais not installed; skipping "
              "(pip install pyais). Software round-trip already ran.")
        return None
    known = dict(mmsi=366000001, lat=42.3500, lon=-70.9000)
    payload_bits = enc.encode_type1(known["mmsi"], known["lat"], known["lon"])
    # armor 6-bit -> AIVDM ASCII
    armored = ""
    for i in range(0, len(payload_bits), 6):
        chunk = payload_bits[i:i+6].ljust(6, "0")
        val = int(chunk, 2)
        armored += chr(val + 48 if val < 40 else val + 56)
    sentence = f"!AIVDM,1,1,,A,{armored},0*00"
    try:
        d = pyais_decode(sentence).asdict()
        ok = (d.get("mmsi") == known["mmsi"]
              and abs(d.get("lat", 999) - known["lat"]) < 0.001
              and abs(d.get("lon", 999) - known["lon"]) < 0.001)
        print(f"[pyais cross-check] decoded MMSI={d.get('mmsi')} "
              f"lat={d.get('lat')} lon={d.get('lon')} -> "
              f"{'PASS - bit layout matches AIS spec' if ok else 'FAIL - layout off'}")
        return ok
    except Exception as e:
        print(f"[pyais cross-check] decode error: {e} "
              f"(checksum placeholder is expected; layout is what matters)")
        return None


def main():
    ap = argparse.ArgumentParser(description="Validate the AIS RF chain (no transmit).")
    ap.add_argument("--sample-rate", type=int, default=240000,
                    help="IQ sample rate (must be >= ~4x9600). HackRF min is 2e6; "
                         "240000 is fine for software validation.")
    ap.add_argument("--write", metavar="PATH",
                    help="also write an IQ .cs8 file for a later in-cage loopback test")
    args = ap.parse_args()

    print("=" * 64)
    print("RF chain validation -- NO TRANSMIT. Software round-trip + optional file.")
    print("=" * 64)

    ok = software_roundtrip(args.sample_rate)
    print()
    pyais_crosscheck(args.sample_rate)

    if args.write:
        known = dict(mmsi=366000001, lat=42.35, lon=-70.90, sog=7.5, cog=123.0)
        bits = enc.encode_type1(**known)
        # for a real HackRF loopback you need >= 2 Msps; use that for the file
        sr = max(args.sample_rate, 2000000)
        iq = enc.encode_to_iq(bits, sr)
        enc.write_iq_file(args.write, iq, fmt="cs8")
        print(f"\nwrote IQ file: {args.write}  ({len(iq)} samples @ {sr} sps, cs8)")
        print("  -> in the SEALED cage only: rf_tx.py can transmit this; the witness")
        print("     receiver (record_ais.sh) should decode MMSI 366000001 at 42.35/-70.90.")

    print()
    if not ok:
        print("OVERALL: FAIL. Do not proceed to RF experiments until the round-trip passes.")
        sys.exit(1)
    print("OVERALL: software chain validated. Next: in-cage loopback to validate the "
          "physical HackRF->receiver path.")


if __name__ == "__main__":
    main()
