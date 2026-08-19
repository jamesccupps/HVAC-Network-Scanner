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


# ---------------------------------------------------------------------------
# Framing: every probe used one recv() and treated the result as a complete
# response. TCP makes no such promise — a segmented reply was parsed short and
# a register list larger than the first segment was silently truncated.
# ---------------------------------------------------------------------------

import socket
import struct
import threading

from hvac_scanner.modbus import ModbusScanner


class _SegmentedSocket:
    """Socket stub that hands back a frame in caller-controlled fragments."""

    def __init__(self, payload: bytes, chunk: int = 3):
        self.payload = payload
        self.chunk = chunk
        self.pos = 0

    def recv(self, n: int) -> bytes:
        take = min(n, self.chunk, len(self.payload) - self.pos)
        out = self.payload[self.pos:self.pos + take]
        self.pos += take
        return out


def _read_registers_frame(values, unit=1, fc=3):
    body = b''.join(struct.pack('!H', v) for v in values)
    pdu = bytes([fc, len(body)]) + body
    return struct.pack('!HHH', 1, 0, len(pdu) + 1) + bytes([unit]) + pdu


def test_recv_frame_reassembles_a_segmented_response():
    frame = _read_registers_frame(list(range(50)))
    sock = _SegmentedSocket(frame, chunk=7)
    assert ModbusScanner._recv_frame(sock) == frame


def test_recv_frame_handles_one_byte_at_a_time():
    frame = _read_registers_frame([1, 2, 3])
    assert ModbusScanner._recv_frame(_SegmentedSocket(frame, chunk=1)) == frame


def test_recv_frame_stops_at_the_declared_length():
    """Trailing bytes from a pipelined reply must not be absorbed."""
    frame = _read_registers_frame([9, 9])
    sock = _SegmentedSocket(frame + b'\xde\xad\xbe\xef', chunk=5)
    assert ModbusScanner._recv_frame(sock) == frame


def test_recv_frame_survives_a_truncated_header():
    assert ModbusScanner._recv_frame(_SegmentedSocket(b'\x00\x01\x00', chunk=2)) \
        == b'\x00\x01\x00'


def test_recv_frame_rejects_an_absurd_declared_length():
    bogus = struct.pack('!HHH', 1, 0, 60000) + b'\x01\x03'
    out = ModbusScanner._recv_frame(_SegmentedSocket(bogus, chunk=64))
    assert len(out) == 7


def test_exception_response_to_fc43_is_not_labelled_device_id():
    """FC 43 / MEI 14 is optional; a rejection is not a successful ID read."""
    scanner = ModbusScanner(timeout=0.2)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        for fc in (0xAB, 0x03):          # reject FC43, then answer FC3
            conn, _ = srv.accept()
            conn.recv(256)
            if fc == 0xAB:
                pdu = bytes([0xAB, 0x01])          # illegal function
            else:
                pdu = bytes([0x03, 0x02, 0x00, 0x2A])
            conn.sendall(struct.pack('!HHH', 1, 0, len(pdu) + 1)
                         + bytes([1]) + pdu)
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        results = scanner.scan_host('127.0.0.1', port, unit_ids=[1])
    finally:
        t.join(timeout=2)
        srv.close()

    assert len(results) == 1
    assert results[0]['detected_via'] == 'holding_register_read'


def test_device_id_request_encodes_at_all():
    """Regression: '!HHHBBBB' was seven format chars for eight values, so
    struct.pack raised on every call. struct.error is not an OSError, so it
    escaped _try_device_id's handler, propagated out of scan_host and
    scan_network, and aborted the entire Modbus pass at the engine's
    catch-all — any host with 502 open killed Modbus scanning."""
    scanner = ModbusScanner(timeout=0.05)
    # No listener on this port: the call must fail by timing out, not by
    # raising struct.error before a packet is even built.
    assert scanner._try_device_id('127.0.0.1', 1, 1) is None


def test_device_id_request_is_a_well_formed_mei_frame():
    req = struct.pack('!HHHBBBBB', 0x0001, 0x0000, 0x0005, 1, 0x2B, 0x0E, 0x01, 0x00)
    assert len(req) == 11
    assert struct.unpack('!H', req[4:6])[0] == len(req) - 6   # MBAP length field
    assert req[6] == 1        # unit id
    assert req[7] == 0x2B     # FC 43
    assert req[8] == 0x0E     # MEI type 14


def test_modbus_pass_survives_a_host_that_answers_on_502():
    """End-to-end: the failure mode was the whole pass dying, not one host."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(2)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.recv(256)
                pdu = bytes([0x03, 0x02, 0x00, 0x2A])
                conn.sendall(struct.pack('!HHH', 1, 0, len(pdu) + 1)
                             + bytes([1]) + pdu)
            finally:
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        results = ModbusScanner(timeout=0.3).scan_host('127.0.0.1', port, unit_ids=[1])
    finally:
        srv.close()
    assert len(results) == 1
    assert results[0]['unit_id'] == 1
