"""SNMP wire-format tests.

snmp.py had no test coverage at all (17% of lines, none of them the codec),
which is how the BER long-form length bug survived: sysDescr strings longer
than 127 bytes were decoded with a garbage leading character and truncated at
129 bytes. Cisco IOS descriptors run past 200 characters, so this is the
common case on any network with enterprise switching, and the truncation
also broke the vendor-matching regexes that engine._scan_snmp runs over the
result.
"""

from hvac_scanner.snmp import SNMPScanner


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def _make_response(descr: bytes, val_tag: int = 0x04) -> bytes:
    """Build a well-formed SNMPv1 GetResponse carrying sysDescr = descr."""
    oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = oid + bytes([val_tag]) + _ber_len(len(descr)) + descr
    vb_seq = bytes([0x30]) + _ber_len(len(varbind)) + varbind
    vb_list = bytes([0x30]) + _ber_len(len(vb_seq)) + vb_seq
    pdu_content = (bytes([0x02, 0x01, 0x01])
                   + bytes([0x02, 0x01, 0x00])
                   + bytes([0x02, 0x01, 0x00])
                   + vb_list)
    pdu = bytes([0xA2]) + _ber_len(len(pdu_content)) + pdu_content
    msg = bytes([0x02, 0x01, 0x00]) + bytes([0x04, 0x06]) + b'public' + pdu
    return bytes([0x30]) + _ber_len(len(msg)) + msg


# -- length codec ----------------------------------------------------------

def test_ber_len_short_form():
    assert SNMPScanner._ber_len(0) == b'\x00'
    assert SNMPScanner._ber_len(6) == b'\x06'
    assert SNMPScanner._ber_len(127) == b'\x7f'


def test_ber_len_long_form():
    assert SNMPScanner._ber_len(128) == b'\x81\x80'
    assert SNMPScanner._ber_len(255) == b'\x81\xff'
    assert SNMPScanner._ber_len(256) == b'\x82\x01\x00'
    assert SNMPScanner._ber_len(65535) == b'\x82\xff\xff'


def test_read_ber_len_roundtrip():
    for n in (0, 1, 127, 128, 200, 255, 256, 4096, 65535):
        encoded = SNMPScanner._ber_len(n)
        assert SNMPScanner._read_ber_len(encoded, 0) == (n, len(encoded))


# -- request building ------------------------------------------------------

def test_build_get_is_well_formed_for_default_community():
    pkt = SNMPScanner._build_snmp_get(b'public')
    assert pkt[0] == 0x30
    length, idx = SNMPScanner._read_ber_len(pkt, 1)
    assert idx + length == len(pkt)


def test_build_get_stays_well_formed_with_a_long_community():
    """A >127-byte community pushed the outer SEQUENCE into long-form length.

    The old builder emitted a bare length byte, producing a packet that no
    agent would answer.
    """
    pkt = SNMPScanner._build_snmp_get(b'c' * 200)
    assert pkt[0] == 0x30
    length, idx = SNMPScanner._read_ber_len(pkt, 1)
    assert idx + length == len(pkt)
    assert b'c' * 200 in pkt


# -- response parsing ------------------------------------------------------

def test_parse_short_sysdescr():
    assert SNMPScanner._parse_snmp_response(_make_response(b'Trane Tracer SC+')) \
        == 'Trane Tracer SC+'


def test_parse_sysdescr_at_the_short_form_boundary():
    for n in (126, 127, 128, 129):
        descr = b'A' * n
        assert SNMPScanner._parse_snmp_response(_make_response(descr)) == descr.decode()


def test_parse_long_sysdescr_is_not_truncated_or_corrupted():
    """The regression case: a realistic Cisco IOS descriptor."""
    descr = (b"Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
             b"Version 15.0(2)SE11, RELEASE SOFTWARE (fc3) Technical Support: "
             b"http://www.cisco.com/techsupport")
    assert len(descr) > 127
    got = SNMPScanner._parse_snmp_response(_make_response(descr))
    assert got == descr.decode()
    assert '\ufffd' not in got


def test_parse_very_long_sysdescr_two_byte_length():
    descr = b'X' * 300
    assert SNMPScanner._parse_snmp_response(_make_response(descr)) == descr.decode()


def test_parse_integer_valued_response():
    assert SNMPScanner._parse_snmp_response(_make_response(b'\x01\x2c', val_tag=0x02)) == '300'


def test_parse_rejects_packet_without_the_oid():
    assert SNMPScanner._parse_snmp_response(b'\x30\x05not-snmp') is None


def test_parse_rejects_truncated_value():
    """A length field claiming more bytes than the datagram actually holds."""
    pkt = _make_response(b'A' * 200)
    assert SNMPScanner._parse_snmp_response(pkt[:-50]) is None
