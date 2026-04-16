"""End-to-end tests for BACnetClient invoke_id filtering.

These tests verify the v2.0.2 fix for cross-request contamination on the shared
BACnet socket. The socket is bound to port 47808 where I-Am broadcasts, COV
notifications, and stale replies from prior requests arrive constantly. Before
the fix, the first packet received after sendto() was parsed as the reply —
meaning a stale packet from device A could be interpreted as the reply to a
request sent to device B, producing column-swapped values in the Points tab.
"""

import struct
from unittest.mock import MagicMock

import pytest

from hvac_scanner import bacnet, codec


def _make_rp_ack(invoke_id: int, value_float: float) -> bytes:
    """Build a ReadProperty-ACK carrying the given invoke_id and a real value."""
    return codec.build_bvlc(0x0A, b'\x01\x00' + bytes([
        0x30, invoke_id, 0x0C,
        0x0C, 0x00, 0x00, 0x00, 0x08,  # object id
        0x19, 0x55,                     # prop id 85
        0x3E, 0x44, *struct.pack('!f', value_float),
        0x3F,
    ]))


def _make_iam(instance: int) -> bytes:
    """Build an I-Am broadcast (no invoke_id — should be filtered)."""
    return codec.build_bvlc(0x0B, b'\x01\x20\xff\xff\x00\xff' + bytes([
        0x10, 0x00, 0xC4,
        (instance >> 24) & 0x03 | 0x02, (instance >> 16) & 0xFF,
        (instance >> 8) & 0xFF, instance & 0xFF,
        0x22, 0x01, 0xE0, 0x91, 0x00, 0x21, 0x02,
    ]))


def _mock_client(packet_queue):
    """BACnetClient with a mocked socket that returns queued packets."""
    client = bacnet.BACnetClient(timeout=0.5)
    client._sock = MagicMock()
    client._sock.gettimeout.return_value = 0.5
    client._sock.recvfrom = MagicMock(side_effect=packet_queue)
    return client


def test_discards_iam_broadcast_received_during_request():
    """An I-Am broadcast arriving mid-request must not be parsed as the reply."""
    client = _mock_client([
        (_make_iam(99), ('10.0.0.99', 47808)),       # broadcast from random device
        (_make_rp_ack(1, 72.5), ('10.0.0.21', 47808)),  # the real reply
    ])
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result == 72.5
    assert client._sock.recvfrom.call_count == 2


def test_discards_stale_reply_from_prior_request():
    """A late reply with the wrong invoke_id must be filtered out."""
    client = _mock_client([
        (_make_rp_ack(42, 99.9), ('10.0.0.21', 47808)),  # stale from prior request
        (_make_rp_ack(1, 72.5),  ('10.0.0.21', 47808)),  # actual reply
    ])
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result == 72.5  # NOT the stale 99.9
    assert client._sock.recvfrom.call_count == 2


def test_discards_reply_from_different_device():
    """A reply from the wrong source IP must be filtered out even if invoke_id matches."""
    client = _mock_client([
        (_make_rp_ack(1, 99.9), ('10.0.0.50', 47808)),   # wrong IP, right invoke
        (_make_rp_ack(1, 72.5), ('10.0.0.21', 47808)),   # right IP, right invoke
    ])
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result == 72.5


def test_returns_none_on_only_unrelated_traffic():
    """If only unrelated packets arrive and then timeout, return None."""
    import socket as _socket

    # 3 unrelated packets then timeout
    queue = [
        (_make_iam(99), ('10.0.0.99', 47808)),
        (_make_iam(100), ('10.0.0.100', 47808)),
        (_make_rp_ack(200, 0.0), ('10.0.0.99', 47808)),
        _socket.timeout(),
    ]
    client = _mock_client(queue)
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result is None


def test_accepts_first_matching_reply():
    """Best case: the matching reply is the first packet received."""
    client = _mock_client([
        (_make_rp_ack(1, 72.5), ('10.0.0.21', 47808)),
    ])
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result == 72.5
    assert client._sock.recvfrom.call_count == 1
