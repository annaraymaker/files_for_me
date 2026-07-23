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


def _sixbit_str(s, nchars):
    """6-bit ASCII, space/'@'-padded to nchars -- shared by Type 5 and Type 24 string fields."""
    s = (s.upper() + "@" * nchars)[:nchars]
    table = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"
    out = ""
    for ch in s:
        idx = table.find(ch)
        out += _bits(idx if idx >= 0 else 0, 6)
    return out


def encode_type24_a(mmsi, shipname=""):
    """Type 24 Part A (static data report): 168 bits, ONE slot. Carries just the ship name.
    Use this + encode_type24_b as a drop-in identity-forgery substitute for Type 5: Type 5 is
    424 bits (2 slots) and this testbed's SDR injector only reliably transmits single-slot
    bursts, so Type 5 never actually reaches the air intact (confirmed: 0/0/0/0/0 Type-5
    sentences across every run and vendor, including the independent listener SDR). Type 24
    carries the same identity fields split across two single-slot messages by design, so it
    exercises the same "does the unit accept an unverified identity claim" question without
    depending on multi-slot support."""
    b = ""
    b += _bits(24, 6); b += _bits(0, 2); b += _bits(mmsi, 30)
    b += _bits(0, 2)                       # part number = 0 (Part A)
    b += _sixbit_str(shipname, 20)         # vessel name (20 chars, 120 bits)
    b += _bits(0, 8)                       # spare
    assert len(b) == 168, f"Type24A must be 168 bits, got {len(b)}"
    return b


def encode_type24_b(mmsi, callsign="", shiptype=0):
    """Type 24 Part B (static data report): 168 bits, ONE slot. Carries call sign + ship type
    (+ zeroed vendor/model/serial/dimensions). See encode_type24_a for why this replaces Type 5."""
    b = ""
    b += _bits(24, 6); b += _bits(0, 2); b += _bits(mmsi, 30)
    b += _bits(1, 2)                       # part number = 1 (Part B)
    b += _bits(shiptype, 8)
    b += _sixbit_str("", 3)                # vendor ID (3 chars, 18 bits) -- zeroed
    b += _bits(0, 4)                       # unit model code
    b += _bits(0, 20)                      # serial number
    b += _sixbit_str(callsign, 7)          # call sign (7 chars, 42 bits)
    b += _bits(0, 9) + _bits(0, 9) + _bits(0, 6) + _bits(0, 6)   # dimensions to bow/stern/port/stbd
    b += _bits(0, 6)                       # spare
    assert len(b) == 168, f"Type24B must be 168 bits, got {len(b)}"
    return b


# ----------------------------------------------------------------------------
# Command / addressed / binary message builders (ITU-R M.1371).
# These enable the SDR-injection attack matrix: interrogation, assignment,
# channel management, slot reservation, addressed/broadcast binary.
# Each returns the message payload bit string (framing/CRC added by the tx backend).
# ----------------------------------------------------------------------------
def encode_type6(src_mmsi, dest_mmsi, dac=0, fid=0, app_data_bits="", seqno=0):
    """Type 6: addressed binary message (for auto-ack tests: send to a transponder).
    app_data_bits is a bit string of application data (<= 920 bits)."""
    b = ""
    b += _bits(6, 6)                # msg type
    b += _bits(0, 2)                # repeat
    b += _bits(src_mmsi, 30)
    b += _bits(seqno, 2)            # sequence number
    b += _bits(dest_mmsi, 30)
    b += _bits(0, 1)                # retransmit flag
    b += _bits(0, 1)                # spare
    b += _bits(dac, 10)             # designated area code
    b += _bits(fid, 6)              # functional ID
    b += app_data_bits
    return b


def encode_type8(src_mmsi, dac=0, fid=0, app_data_bits=""):
    """Type 8: binary broadcast (for fake area notice / met-hydro / provenance tests).
    Set dac=1,fid=22 for area notice; dac=1,fid=11 for meteorological/hydrological."""
    b = ""
    b += _bits(8, 6)
    b += _bits(0, 2)
    b += _bits(src_mmsi, 30)
    b += _bits(0, 2)                # spare
    b += _bits(dac, 10)
    b += _bits(fid, 6)
    b += app_data_bits
    return b


def encode_type15(src_mmsi, dest1_mmsi, msg1_1=5, dest2_mmsi=None, msg2_1=0):
    """Type 15: interrogation (ask a transponder to reply, e.g. with its Type 5/Type 3).
    msg1_1 is the requested message type from dest1 (e.g. 3 or 5). 88 bits for single
    interrogation, longer for two."""
    b = ""
    b += _bits(15, 6)
    b += _bits(0, 2)
    b += _bits(src_mmsi, 30)
    b += _bits(0, 2)                # spare
    b += _bits(dest1_mmsi, 30)
    b += _bits(msg1_1, 6)           # requested message type
    b += _bits(0, 12)              # slot offset
    if dest2_mmsi is None:
        b = b[:88]                  # single interrogation is 88 bits
    else:
        b += _bits(0, 2)
        b += _bits(dest2_mmsi, 30)
        b += _bits(msg2_1, 6)
        b += _bits(0, 12)
        b += _bits(0, 2)
    return b


def encode_type16(src_mmsi, dest_a, offset_a, increment_a,
                  dest_b=None, offset_b=0, increment_b=0):
    """Type 16: assignment mode command (rate/slot assignment -> near-silence tests).
    Assigns a reporting rate/slot to dest_a (and optionally dest_b). 96 or 144 bits."""
    b = ""
    b += _bits(16, 6)
    b += _bits(0, 2)
    b += _bits(src_mmsi, 30)
    b += _bits(0, 2)                # spare
    b += _bits(dest_a, 30)
    b += _bits(offset_a, 12)
    b += _bits(increment_a, 10)
    if dest_b is None:
        b += _bits(0, 4)            # spare -> 96 bits
    else:
        b += _bits(dest_b, 30)
        b += _bits(offset_b, 12)
        b += _bits(increment_b, 10)
    return b


def encode_type20(src_mmsi, offset1=0, slots1=1, timeout1=7, increment1=0):
    """Type 20: data-link management (reserve FATDMA slots -> slot hogging via SDR).
    Reserves slots so other stations avoid them. 72 bits (one reservation block)."""
    b = ""
    b += _bits(20, 6)
    b += _bits(0, 2)
    b += _bits(src_mmsi, 30)
    b += _bits(0, 2)                # spare
    b += _bits(offset1, 12)         # slot offset
    b += _bits(slots1, 4)           # number of slots
    b += _bits(timeout1, 3)         # timeout (minutes)
    b += _bits(increment1, 11)      # increment
    b = (b + "0" * 72)[:72]
    return b


def encode_type22(src_mmsi, channel_a=2087, channel_b=2088, tx_rx=0, power=0,
                 ne_lon=0, ne_lat=0, sw_lon=0, sw_lat=0, addressed=0,
                 dest1=None, dest2=None, zonesize=0):
    """Type 22: channel management (force channel/power change -> channel-mgmt tests).
    Broadcast (regional) by default; set addressed=1 with dest1/dest2 to target a unit.
    168 bits.

    NOTE (bug fix): the addressed flag lives at bit 139 in BOTH forms. The geographic
    (broadcast) form fills bits 69-138 with the NE/SW bounding box (18+17+18+17=70).
    The addressed form fills the SAME 70-bit region with dest1(30)+spare(5)+dest2(30)+
    spare(5). The previous version packed the two MMSIs back-to-back (60 bits) with no
    interleaving spares, which pushed the addressed flag to bit 129; a conforming
    decoder then read addressed=0 and treated the command as a broadcast regional
    message (dest1=None). Verified against pyais in __main__."""
    b = ""
    b += _bits(22, 6)
    b += _bits(0, 2)
    b += _bits(src_mmsi, 30)
    b += _bits(0, 2)                # spare
    b += _bits(channel_a, 12)       # channel A number
    b += _bits(channel_b, 12)       # channel B number
    b += _bits(tx_rx, 4)            # tx/rx mode
    b += _bits(power, 1)            # power (0=high,1=low)   -> now at bit 69
    if addressed and dest1 is not None:
        # addressed form: dest1(30) + spare(5) + dest2(30) + spare(5) = 70 bits
        b += _bits(dest1, 30)                     # bits 69-98  : destination MMSI 1
        b += _bits(0, 5)                          # bits 99-103 : spare
        b += _bits(dest2 if dest2 else 0, 30)     # bits 104-133: destination MMSI 2
        b += _bits(0, 5)                          # bits 134-138: spare
    else:
        b += _bits(ne_lon, 18)      # bits 69-86  : NE corner lon (1/10 min)
        b += _bits(ne_lat, 17)      # bits 87-103 : NE corner lat
        b += _bits(sw_lon, 18)      # bits 104-121: SW corner lon
        b += _bits(sw_lat, 17)      # bits 122-138: SW corner lat
    b += _bits(addressed, 1)        # bit 139: addressed flag (both forms land here)
    b += _bits(0, 1)                # bit 140: Band A in use
    b += _bits(0, 1)                # bit 141: Band B in use
    b += _bits(zonesize, 3)         # bits 142-144: transition zone size (NM); 1-8 valid
    b = (b + "0" * 168)[:168]
    assert len(b) == 168, f"Type 22 must be 168 bits, got {len(b)}"
    return b


# ----------------------------------------------------------------------------
# Malformed / edge-case builders (protocol-fuzzing attacks). These deliberately
# violate the spec to probe parser robustness. Payload-level malformations only;
# framing-level ones (bad CRC, truncated frame) are noted where they need the raw
# modulator path instead of the framing backend.
# ----------------------------------------------------------------------------
def encode_type4(mmsi, lat, lon, year=2026, month=1, day=1, hour=0,
                 minute=0, second=0, epfd=7):
    """Type 4 base-station report (168 bits, single slot). Carries the base's claimed
    UTC and position -- receivers may use it for time sync and to establish a base cell.
    Set a ship-format MMSI + false time/position to test whether a unit trusts an
    unauthenticated base announcement (INV-B-AUTH-02)."""
    b = ""
    b += _bits(4, 6); b += _bits(0, 2); b += _bits(mmsi, 30)
    b += _bits(year, 14); b += _bits(month, 4); b += _bits(day, 5)
    b += _bits(hour, 5); b += _bits(minute, 6); b += _bits(second, 6)
    b += _bits(1, 1)                                # fix quality
    b += _bits(int(round(lon * 600000.0)), 28)      # longitude (signed)
    b += _bits(int(round(lat * 600000.0)), 27)      # latitude  (signed)
    b += _bits(epfd, 4); b += _bits(0, 10)          # EPFD + spare
    b += _bits(0, 1); b += _bits(0, 19)             # RAIM + radio status
    assert len(b) == 168, f"Type 4 must be 168 bits, got {len(b)}"
    return b


def encode_type9(mmsi, lat, lon, sog=0.0, cog=0.0, altitude=1000, timestamp=60):
    """Type 9 SAR-aircraft position report (168 bits, single slot). The standard reserves
    Message 9 for SAR aircraft; sending it from an ordinary ship MMSI tests station-class
    enforcement (INV-B-AUTH-03)."""
    b = ""
    b += _bits(9, 6); b += _bits(0, 2); b += _bits(mmsi, 30)
    b += _bits(min(int(altitude), 4095), 12)        # altitude (m)
    b += _bits(min(int(round(sog)), 1022), 10)      # SOG (integer kn for SAR)
    b += _bits(1, 1)                                # position accuracy
    b += _bits(int(round(lon * 600000.0)), 28)      # longitude (signed)
    b += _bits(int(round(lat * 600000.0)), 27)      # latitude  (signed)
    b += _bits(int(round(cog * 10.0)), 12)          # COG
    b += _bits(timestamp, 6)                        # UTC second
    b += _bits(0, 8)                                # reserved / regional
    b += _bits(0, 1); b += _bits(0, 3)             # DTE + spare
    b += _bits(0, 1); b += _bits(0, 1)             # assigned + RAIM
    b += _bits(0, 20)                              # radio status
    assert len(b) == 168, f"Type 9 must be 168 bits, got {len(b)}"
    return b


def encode_type17(mmsi, lat, lon, data_bits=None):
    """Type 17 DGNSS broadcast (single slot). Header carries the reference position in
    1/10-minute units; the payload carries differential corrections. Sending it from an
    ordinary MMSI with bogus corrections tests whether a unit consumes unauthenticated
    DGNSS data and lets an attacker shift computed fixes (INV-B-AUTH-02)."""
    if data_bits is None:
        data_bits = "1" * 40                        # bogus correction payload
    lon_u = int(round(lon * 600.0))                 # deg -> 1/10 minute
    lat_u = int(round(lat * 600.0))
    b = ""
    b += _bits(17, 6); b += _bits(0, 2); b += _bits(mmsi, 30); b += _bits(0, 2)
    b += _bits(lon_u, 18)                            # longitude (signed, 1/10 min)
    b += _bits(lat_u, 17)                            # latitude  (signed, 1/10 min)
    b += _bits(0, 5)                                 # spare
    b += data_bits
    return b                                         # <= 168 bits, single slot


def encode_type1_raw(mmsi, lat, lon, sog_u=None, cog_u=None, heading=511,
                     nav_status=0, rot=128, timestamp=60, spare=0):
    """Type 1 with RAW field values (no unit conversion) so you can inject illegal
    sentinels/reserved values directly: e.g. sog_u=1023, nav_status=13, cog_u=4000,
    heading=511, or lat/lon out of range. Fields left None use sensible defaults."""
    lat_units = int(round(lat * 600000.0))
    lon_units = int(round(lon * 600000.0))
    if sog_u is None:
        sog_u = 0
    if cog_u is None:
        cog_u = 0
    b = ""
    b += _bits(1, 6)
    b += _bits(0, 2)
    b += _bits(mmsi, 30)
    b += _bits(nav_status, 4)       # nav=13 is reserved/undefined
    b += _bits(rot, 8)
    b += _bits(sog_u, 10)           # 1023 = not available sentinel; other values raw
    b += _bits(1, 1)
    b += _bits(lon_units, 28)       # can be forced out of range (lon=181 -> huge)
    b += _bits(lat_units, 27)       # lat=91 -> out of range
    b += _bits(cog_u, 12)           # 4000 = 400.0 deg, illegal (>360)
    b += _bits(heading, 9)          # 511 = not available; >359 illegal
    b += _bits(timestamp, 6)
    b += _bits(0, 2)
    b += _bits(spare, 3)            # spare bits: spec says 0; set nonzero to test
    b += _bits(0, 1)
    b += _bits(0, 19)
    return b[:168]


def encode_undefined_type(msg_type, mmsi, nbits=168):
    """A message with an undefined/reserved type (0, or 28+). Body is zero-padded."""
    b = _bits(msg_type, 6) + _bits(0, 2) + _bits(mmsi, 30)
    b = (b + "0" * nbits)[:nbits]
    return b


def make_truncated(payload_bits, keep_bits):
    """Return only the first keep_bits of a payload (truncated message)."""
    return payload_bits[:keep_bits]


def make_oversized(payload_bits, extra_bits):
    """Append extra_bits of padding beyond the spec length (oversized message)."""
    return payload_bits + "1" * extra_bits


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

    # optional: verify the (fixed) addressed Type 22 decodes correctly via pyais.
    # This guards the addressed-flag position regression. Skipped if pyais absent.
    try:
        from pyais import decode

        def _wrap(bstr):
            payload = ""
            padded = bstr + "0" * ((6 - len(bstr) % 6) % 6)
            for i in range(0, len(padded), 6):
                v = int(padded[i:i+6], 2)
                payload += chr(v + 48 if v < 40 else v + 56)
            fill = (6 - len(bstr) % 6) % 6
            body = f"AIVDM,1,1,,A,{payload},{fill}"
            cs = 0
            for c in body:
                cs ^= ord(c)
            return f"!{body}*{cs:02X}"

        t22 = encode_type22(3669999, channel_a=2088, channel_b=2087,
                            addressed=1, dest1=677777777)
        d = decode(_wrap(t22)).asdict()
        ok = (d.get("msg_type") == 22 and d.get("addressed") in (True, 1)
              and d.get("dest1") == 677777777)
        print(f"  Type 22 addressed round-trip: "
              f"{'OK' if ok else 'FAIL'} (addressed={d.get('addressed')}, "
              f"dest1={d.get('dest1')})")
        assert ok, "addressed Type 22 did not round-trip; check bit layout"
    except ImportError:
        print("  (pyais not installed; skipping Type 22 round-trip check)")
