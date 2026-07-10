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


def m16_assignment(src_mmsi, dest_mmsi, offset=0, increment=10):
    """M16: assigned-mode command setting dest_mmsi's reporting slot offset/increment.
    A large increment (slow rate) tests whether the unit will quiet itself on command."""
    return _encode({'msg_type': 16, 'mmsi': src_mmsi, 'mmsi1': dest_mmsi,
                    'offset1': offset, 'increment1': increment})


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
        ("M15", m15_interrogation(BASE, V, req_type=5),
         {'msg_type': 15, 'mmsi': BASE, 'mmsi1': V, 'type1_1': 5}),
        ("M16", m16_assignment(BASE, V, offset=0, increment=1000),
         {'msg_type': 16, 'mmsi': BASE, 'mmsi1': V, 'offset1': 0, 'increment1': 1000}),
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
    print("\nALL PASS" if all_ok else "\nSOME FAILED")
