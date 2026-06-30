#!/usr/bin/env python3
"""
ais_encode.py -- build AIS message payloads and modulate them to baseband IQ.

This is the foundation for every RF test: it turns an AIS message (e.g. a Type 1
position report with a chosen MMSI / lat / lon) into the GMSK baseband IQ samples that
a HackRF would transmit. It writes IQ to a FILE; it never touches the radio. Transmit
is a separate, cage-gated step (rf_tx.py).

Pipeline (per ITU-R M.1371 / the AIS link layer):
  message fields  -> 6-bit ASCII payload (the !AIVDM body)
                  -> bit payload + 16-bit CRC-CCITT
                  -> HDLC: flag, bit-stuffing, NRZI
                  -> GMSK modulation (BT=0.4, 9600 bps)
                  -> complex baseband IQ (int8 I/Q interleaved, HackRF format)

VALIDATION DISCIPLINE: do not trust this encoder until a known message round-trips.
The companion `validate_vhf.py` writes an IQ file here, decodes it back with a software
AIS decoder, and asserts the decoded MMSI/lat/lon equal what was put in. Only after a
clean round-trip is the encoder trustworthy as an instrument.

References used: ITU-R M.1371-5 (message formats), the AIVDM/AIVDO 6-bit armoring,
and standard HDLC framing (training sequence + flags + bit stuffing + NRZI).
"""
import numpy as np

# ----------------------------------------------------------------------------
# AIS link-layer constants
# ----------------------------------------------------------------------------
SYMBOL_RATE = 9600                # AIS GMSK bit rate, bits/s
BT = 0.4                          # Gaussian filter bandwidth-time product for AIS
TRAINING = "010101010101010101010101"   # 24-bit preamble (alternating)
FLAG = "01111110"                 # HDLC flag (0x7E)
RAMP_BITS = 0                     # power ramp handled by tx, not here


# ----------------------------------------------------------------------------
# 6-bit ASCII payload assembly (the !AIVDM data field)
# ----------------------------------------------------------------------------
def _bits(value, nbits):
    """Unsigned integer -> MSB-first bit string of width nbits."""
    if value < 0:
        value += (1 << nbits)     # two's complement for signed fields
    return format(value & ((1 << nbits) - 1), f"0{nbits}b")


def encode_type1(mmsi, lat, lon, sog=0.0, cog=0.0, heading=511,
                 nav_status=0, rot=128, timestamp=60):
    """Build the 168-bit Type 1 (Position Report Class A) bit payload.

    lat/lon in decimal degrees. AIS stores them as 1/10000 minute, signed.
    Defaults (heading 511, rot 128, timestamp 60) are the 'not available' sentinels.
    """
    lat_units = int(round(lat * 600000.0))    # degrees -> 1/10000 min
    lon_units = int(round(lon * 600000.0))
    sog_u = int(round(sog * 10.0))            # knots -> 1/10 kn
    cog_u = int(round(cog * 10.0))            # deg -> 1/10 deg
    b = ""
    b += _bits(1, 6)              # message type 1
    b += _bits(0, 2)             # repeat indicator
    b += _bits(mmsi, 30)        # MMSI
    b += _bits(nav_status, 4)   # navigation status
    b += _bits(rot, 8)          # rate of turn
    b += _bits(sog_u, 10)       # speed over ground
    b += _bits(1, 1)            # position accuracy
    b += _bits(lon_units, 28)   # longitude (signed)
    b += _bits(lat_units, 27)   # latitude (signed)
    b += _bits(cog_u, 12)       # course over ground
    b += _bits(heading, 9)      # true heading
    b += _bits(timestamp, 6)    # UTC second
    b += _bits(0, 2)            # maneuver indicator
    b += _bits(0, 3)            # spare
    b += _bits(0, 1)            # RAIM
    b += _bits(0, 19)           # radio status
    assert len(b) == 168, f"Type 1 must be 168 bits, got {len(b)}"
    return b


def encode_type5_static(mmsi, callsign="", shipname="", shiptype=0):
    """Minimal Type 5 (static/voyage). Provided for identity tests; many fields zeroed.
    Strings are 6-bit ASCII, space-padded. Returns the 424-bit payload."""
    def sixbit_str(s, nchars):
        s = (s.upper() + "@" * nchars)[:nchars]
        table = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"
        out = ""
        for ch in s:
            idx = table.find(ch)
            out += _bits(idx if idx >= 0 else 0, 6)
        return out
    b = ""
    b += _bits(5, 6); b += _bits(0, 2); b += _bits(mmsi, 30)
    b += _bits(0, 2)                       # AIS version
    b += _bits(0, 30)                      # IMO
    b += sixbit_str(callsign, 7)           # call sign (7 chars)
    b += sixbit_str(shipname, 20)          # vessel name (20 chars)
    b += _bits(shiptype, 8)
    b += _bits(0, 30)                      # dimensions
    b += _bits(0, 4)                       # EPFD
    b += _bits(0, 20)                      # ETA
    b += _bits(0, 8)                       # draught
    b += sixbit_str("", 20)                # destination
    b += _bits(0, 1) + _bits(0, 1)         # DTE + spare
    # pad/truncate to 424
    b = (b + "0" * 424)[:424]
    return b


# ----------------------------------------------------------------------------
# HDLC framing: CRC, bit-stuffing, NRZI, training + flags
# ----------------------------------------------------------------------------
def _crc16_ccitt(bits):
    """CRC-16-CCITT (X.25/HDLC) over the bit string, returned LSB-first per AIS."""
    data = bytearray()
    # pack bits MSB-first into bytes (pad to byte boundary at the end)
    padded = bits + "0" * ((8 - len(bits) % 8) % 8)
    for i in range(0, len(padded), 8):
        data.append(int(padded[i:i+8], 2))
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc ^= 0xFFFF
    # AIS transmits the FCS LSB-first
    return format(crc, "016b")[::-1]


def _bit_stuff(bits):
    """HDLC bit stuffing: insert a 0 after any run of five consecutive 1s."""
    out = ""
    run = 0
    for bit in bits:
        out += bit
        if bit == "1":
            run += 1
            if run == 5:
                out += "0"
                run = 0
        else:
            run = 0
    return out


def _nrzi_encode(bits):
    """NRZI: a 0 toggles the level, a 1 keeps it. AIS uses NRZI on the line."""
    out = ""
    level = "1"
    for bit in bits:
        if bit == "0":
            level = "0" if level == "1" else "1"
        out += level
    return out


def build_frame_bits(payload_bits):
    """payload_bits (the message) -> full on-air NRZI bit stream:
    training + flag + (payload + CRC, bit-stuffed) + flag, then NRZI."""
    crc = _crc16_ccitt(payload_bits)
    body = payload_bits + crc
    stuffed = _bit_stuff(body)
    framed = TRAINING + FLAG + stuffed + FLAG
    return _nrzi_encode(framed)


# ----------------------------------------------------------------------------
# GMSK modulation -> baseband IQ
# ----------------------------------------------------------------------------
def _gaussian_taps(sps, bt=BT, span=4):
    """Gaussian pulse-shaping filter taps for GMSK."""
    t = np.arange(-span * sps, span * sps + 1) / sps
    alpha = np.sqrt(np.log(2) / 2) / bt
    h = (np.sqrt(np.pi) / alpha) * np.exp(-(np.pi ** 2) * (t ** 2) / (alpha ** 2))
    return h / np.sum(h)


def gmsk_modulate(nrzi_bits, sample_rate, bt=BT):
    """NRZI bit string -> complex baseband IQ at sample_rate (GMSK).

    This matches GNU Radio's digital.gmsk_mod (the implementation the standard AIS-TX
    tools use), which is what real AIS receivers are validated against:
      1. map bits to NRZ +/-1 and REPEAT each symbol sps times (not an impulse train),
      2. low-pass with a Gaussian filter (BT product, ~4*sps taps, normalized),
      3. FM-modulate with sensitivity (pi*h)/sps, h=0.5 (MSK), i.e. integrate the
         filtered signal to phase.
    The earlier version filtered an impulse train instead of repeated symbols, which
    produced the wrong pulse shape: a real FM discriminator could not recover the bits
    even though deviation magnitude looked right. Repeating the symbols is the fix.
    """
    sps = int(round(sample_rate / SYMBOL_RATE))
    if sps < 4:
        raise ValueError(f"sample_rate {sample_rate} too low for {SYMBOL_RATE} bps "
                         f"(need >= ~4 samples/symbol)")
    h = 0.5                                   # MSK modulation index
    sensitivity = (np.pi * h) / sps           # GNU Radio FM sensitivity
    # NRZ symbols, each repeated across its symbol period
    nrz = np.array([1.0 if b == "1" else -1.0 for b in nrzi_bits])
    upsampled = np.repeat(nrz, sps)
    # Gaussian pulse-shaping filter
    taps = _gaussian_taps(sps, bt)
    filtered = np.convolve(upsampled, taps, mode="same")
    # FM-modulate: integrate the filtered signal to phase
    phase = np.cumsum(filtered * sensitivity)
    return np.exp(1j * phase).astype(np.complex64)


def iq_to_hackrf_int8(iq):
    """complex64 IQ in [-1,1] -> interleaved int8 I,Q (HackRF .cs8 format)."""
    i = np.clip(np.real(iq) * 127, -127, 127).astype(np.int8)
    q = np.clip(np.imag(iq) * 127, -127, 127).astype(np.int8)
    out = np.empty(i.size * 2, dtype=np.int8)
    out[0::2] = i
    out[1::2] = q
    return out


def encode_to_iq(payload_bits, sample_rate, pad_ms=2.0):
    """Full chain: message bits -> framed NRZI -> GMSK IQ (complex64), with a short
    zero pad front/back so the burst isn't clipped. Returns complex64 array."""
    nrzi = build_frame_bits(payload_bits)
    iq = gmsk_modulate(nrzi, sample_rate)
    pad = int(sample_rate * pad_ms / 1000.0)
    return np.concatenate([np.zeros(pad, np.complex64), iq, np.zeros(pad, np.complex64)])


def write_iq_file(path, iq, fmt="cs8"):
    """Write IQ to disk. cs8 = interleaved int8 (HackRF -t default expects this with
    appropriate flags); cf32 = interleaved float32 (for inspection/round-trip)."""
    if fmt == "cs8":
        iq_to_hackrf_int8(iq).tofile(path)
    elif fmt == "cf32":
        out = np.empty(iq.size * 2, dtype=np.float32)
        out[0::2] = np.real(iq); out[1::2] = np.imag(iq)
        out.tofile(path)
    else:
        raise ValueError(f"unknown fmt {fmt}")


if __name__ == "__main__":
    # quick self-check: build a Type 1 and report sizes (no file, no radio)
    bits = encode_type1(mmsi=366000001, lat=42.35, lon=-70.90, sog=0.0, cog=90.0)
    print(f"Type 1 payload bits: {len(bits)}")
    frame = build_frame_bits(bits)
    print(f"framed NRZI bits: {len(frame)}")
    for sr in (240000, 2400000):
        iq = encode_to_iq(bits, sr)
        print(f"  sample_rate {sr}: {len(iq)} IQ samples "
              f"({len(iq)/sr*1000:.1f} ms burst incl pad)")
