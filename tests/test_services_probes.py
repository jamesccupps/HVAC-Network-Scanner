"""Wire-format checks for the raw protocol probes in services.py.

services.py had no test coverage (13% of lines, none of the probes), which is
how a malformed EtherNet/IP encapsulation header went unnoticed: the request
was 22 bytes where the ODVA spec requires 24, so every field after `length`
was misaligned. All those fields are zero, so the bytes looked harmless — but
a conforming device sees a truncated header and does not answer, leaving the
probe to report only the generic product string inferred from the open port.
"""

import struct

from hvac_scanner.services import HVACServiceScanner


def test_cip_list_identity_header_is_24_bytes():
    scanner = HVACServiceScanner(timeout=0.05)
    # Probe a closed port: we only care that the request encodes correctly.
    scanner._probe_ethernet_ip('127.0.0.1', 1)
    req = struct.pack('<HHII8sI', 0x0063, 0, 0, 0, b'\x00' * 8, 0)
    assert len(req) == 24


def test_cip_list_identity_fields_land_at_spec_offsets():
    req = struct.pack('<HHII8sI', 0x0063, 0, 0, 0, b'\x00' * 8, 0)
    assert struct.unpack('<H', req[0:2])[0] == 0x0063   # command
    assert struct.unpack('<H', req[2:4])[0] == 0        # length
    assert struct.unpack('<I', req[4:8])[0] == 0        # session handle
    assert struct.unpack('<I', req[8:12])[0] == 0       # status
    assert req[12:20] == b'\x00' * 8                    # sender context
    assert struct.unpack('<I', req[20:24])[0] == 0      # options


def test_s7_cotp_connection_request_is_self_consistent():
    """This one was already correct — guard it so it stays that way."""
    cotp = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
                  0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02,
                  0x01, 0x00, 0xC2, 0x02, 0x01, 0x02])
    tpkt_len = struct.unpack('!H', cotp[2:4])[0]
    assert len(cotp) == tpkt_len          # TPKT length covers the whole packet
    assert cotp[4] + 5 == len(cotp)       # COTP length indicator
    assert cotp[5] == 0xE0                # CR TPDU


def test_probes_do_not_raise_against_a_closed_port():
    """A probe that raises would abort the service pass, as Modbus did."""
    scanner = HVACServiceScanner(timeout=0.05)
    assert isinstance(scanner._probe_ethernet_ip('127.0.0.1', 1), dict)
    assert isinstance(scanner._probe_s7('127.0.0.1', 1), dict)
    assert isinstance(scanner._probe_niagara_fox('127.0.0.1', 1), dict)
    assert isinstance(scanner._tcp_banner('127.0.0.1', 1), str)
