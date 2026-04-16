"""Modbus scanner tests."""

from hvac_scanner.modbus import ModbusScanner


def test_parse_device_id_response():
    # Synthetic MEI 14 response: vendor='Acme', product='Gateway', version='1.0'
    # Layout: MBAP(7) + fc(1) + mei_type(1) + readDeviceIDCode(1)
    #         + conformityLevel(1) + moreFollows(1) + nextObjectId(1) + numObjects(1)
    # That's 14 bytes, so num_objects lives at resp[13] — the parser's starting index.
    resp = bytearray()
    resp += b"\x00\x01\x00\x00\x00\x20\x01"           # MBAP: txid, proto, len, uid
    resp += bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00])  # fc,mei,readcode,conformity,more,next
    resp += bytes([0x03])                              # num_objects at idx 13
    # obj 0: vendor = "Acme"
    resp += bytes([0x00, 4]) + b"Acme"
    # obj 1: product = "Gateway"
    resp += bytes([0x01, 7]) + b"Gateway"
    # obj 2: version = "1.0"
    resp += bytes([0x02, 3]) + b"1.0"

    info = ModbusScanner._parse_device_id_response(bytes(resp))
    assert info['vendor'] == 'Acme'
    assert info['product'] == 'Gateway'
    assert info['version'] == '1.0'


def test_parse_device_id_empty():
    info = ModbusScanner._parse_device_id_response(b"")
    assert info['vendor'] == 'Unknown'


def test_common_unit_ids_includes_255():
    """Regression: v1 missed 255 which is the default for TCP-only gateways."""
    assert 255 in ModbusScanner.COMMON_UNIT_IDS
    assert 1 in ModbusScanner.COMMON_UNIT_IDS
    assert 247 in ModbusScanner.COMMON_UNIT_IDS
