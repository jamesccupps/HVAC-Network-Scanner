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


# ---------------------------------------------------------------------------
# Regression: unsolicited traffic from the TARGET device itself.
#
# The tests above all send stray packets from a different source IP, which the
# `addr[0] != ip` check already caught. The uncovered case was a packet with no
# invoke-id arriving from the very device being polled — an I-Am, unconfirmed
# COV, or unconfirmed event notification, all of which a live controller emits
# on its own schedule while we are bound to 47808. `_extract_invoke_id` returns
# None for those, and the old condition (`got_id is not None and ...`) let them
# fall through to the parser, which returned None and aborted the read with
# most of the timeout still unspent. On a segment with active COV subscriptions
# this silently dropped points.
# ---------------------------------------------------------------------------

def _make_unconfirmed_cov(instance: int) -> bytes:
    """Unconfirmed COV notification (PDU type 1 — carries no invoke-id)."""
    return codec.build_bvlc(0x0B, b'\x01\x00' + bytes([
        0x10, 0x02,              # Unconfirmed-Request, service 2 = unconfirmedCOVNotification
        0x09, 0x0C,              # ctx0 subscriber process id
        0x1C, 0x02, 0x00, 0x00, 0x05,  # ctx1 initiating device
        0x2C, 0x00, 0x00, 0x00, instance & 0xFF,  # ctx2 monitored object
        0x39, 0x00,              # ctx3 time remaining
    ]))


def test_iam_from_target_device_does_not_abort_read():
    """An I-Am from the polled device itself must be skipped, not end the wait."""
    client = _mock_client([
        (_make_iam(29), ('10.0.0.21', 47808)),          # SAME IP as the target
        (_make_rp_ack(1, 72.5), ('10.0.0.21', 47808)),  # the real reply
    ])
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result == 72.5
    assert client._sock.recvfrom.call_count == 2


def test_unconfirmed_cov_from_target_device_does_not_abort_read():
    """Unconfirmed COV notifications are constant on a live BAS segment."""
    client = _mock_client([
        (_make_unconfirmed_cov(29), ('10.0.0.21', 47808)),
        (_make_unconfirmed_cov(30), ('10.0.0.21', 47808)),
        (_make_rp_ack(1, 68.25), ('10.0.0.21', 47808)),
    ])
    result = client.read_property('10.0.0.21', 'Analog Input', 29, 'presentValue')
    assert result == 68.25
    assert client._sock.recvfrom.call_count == 3


def test_rpm_survives_unsolicited_traffic_from_target():
    """Same protection must hold on the ReadPropertyMultiple path."""
    rpm_ack = codec.build_bvlc(0x0A, b'\x01\x00' + bytes([
        0x30, 0x01, 0x0E,
        0x0C, 0x00, 0x00, 0x00, 0x08,
        0x1E,
        0x29, 0x55, 0x4E, 0x44, *struct.pack('!f', 55.5), 0x4F,
        0x1F,
    ]))
    client = _mock_client([
        (_make_iam(29), ('10.0.0.21', 47808)),
        (rpm_ack, ('10.0.0.21', 47808)),
    ])
    result = client.read_property_multiple('10.0.0.21', 'Analog Input', 29, [85])
    assert result == {85: 55.5}


# ---------------------------------------------------------------------------
# Partial ReadPropertyMultiple results.
#
# A partial RPM result has two causes: the device genuinely lacks the property,
# or its RPM implementation is incomplete while single-property reads work.
# The old code took any non-empty RPM result as final, so the second case left
# permanently blank Name/Units columns. Filling blindly is not the answer
# either — that is a round trip per missing property per object, thousands of
# wasted exchanges on a supervisory controller whose answer never changes. The
# client fills gaps individually but gives up per (device, property) after
# _PARTIAL_FILL_GIVE_UP consecutive failures.
# ---------------------------------------------------------------------------

from hvac_scanner.bacnet import _PARTIAL_FILL_GIVE_UP


class _ScriptedClient(bacnet.BACnetClient):
    """Client whose RPM and ReadProperty results are supplied by the test."""

    def __init__(self, rpm_result, single_results):
        super().__init__(timeout=0.1)
        self._rpm_result = rpm_result
        self._single_results = single_results      # {prop_name: value or None}
        self.single_reads: list[tuple[str, str]] = []

    def read_property_multiple(self, ip, obj_type, obj_instance, prop_ids,
                               dnet=None, dadr=None):
        return dict(self._rpm_result)

    def read_property(self, ip, obj_type, obj_instance, prop_id,
                      array_index=None, dnet=None, dadr=None):
        self.single_reads.append((ip, prop_id))
        return self._single_results.get(prop_id)


def test_partial_rpm_gaps_are_filled_individually():
    """The recoverable case: RPM omits objectName but ReadProperty has it."""
    client = _ScriptedClient(
        rpm_result={85: 72.5},                      # presentValue only
        single_results={'objectName': 'AHU-1 SAT', 'units': 64,
                        'description': 'supply air temp'},
    )
    out = client.read_point_properties('10.0.0.21', 'Analog Input', 1)
    assert out['presentValue'] == 72.5
    assert out['objectName'] == 'AHU-1 SAT'
    assert out['units'] == 64
    assert out['description'] == 'supply air temp'


def test_partial_fill_does_not_re_read_what_rpm_already_returned():
    client = _ScriptedClient(
        rpm_result={85: 72.5, 77: 'AHU-1 SAT'},
        single_results={'units': 64, 'description': 'd'},
    )
    client.read_point_properties('10.0.0.21', 'Analog Input', 1)
    asked = {prop for _ip, prop in client.single_reads}
    assert 'presentValue' not in asked
    assert 'objectName' not in asked


def test_partial_fill_gives_up_after_repeated_refusals():
    """A device that simply lacks the property costs a bounded number of reads."""
    client = _ScriptedClient(rpm_result={85: 72.5}, single_results={})  # all refuse
    for instance in range(25):
        client.read_point_properties('10.0.0.21', 'Analog Input', instance)
    per_prop = {}
    for _ip, prop in client.single_reads:
        per_prop[prop] = per_prop.get(prop, 0) + 1
    for prop, count in per_prop.items():
        assert count == _PARTIAL_FILL_GIVE_UP, f"{prop} retried {count} times"


def test_give_up_is_tracked_per_device_not_globally():
    """One uncooperative controller must not suppress fills on another."""
    client = _ScriptedClient(rpm_result={85: 1.0}, single_results={})
    for i in range(10):
        client.read_point_properties('10.0.0.21', 'Analog Input', i)
    before = len(client.single_reads)
    client._single_results = {'objectName': 'VAV-3 DAT'}
    out = client.read_point_properties('10.0.0.99', 'Analog Input', 0)
    assert len(client.single_reads) > before
    assert out['objectName'] == 'VAV-3 DAT'


def test_a_success_resets_the_failure_counter():
    """Intermittent failures must not permanently disable a property."""
    client = _ScriptedClient(rpm_result={85: 1.0}, single_results={})
    client.read_point_properties('10.0.0.21', 'Analog Input', 0)
    assert client._partial_fill_failures[('10.0.0.21', 'objectName')] == 1
    client._single_results = {'objectName': 'recovered'}
    out = client.read_point_properties('10.0.0.21', 'Analog Input', 1)
    assert out['objectName'] == 'recovered'
    assert ('10.0.0.21', 'objectName') not in client._partial_fill_failures


def test_empty_rpm_still_retries_every_property():
    """Unchanged behavior for devices that reject RPM outright."""
    client = _ScriptedClient(
        rpm_result={},
        single_results={'presentValue': 68.0, 'objectName': 'RM-101 TEMP',
                        'units': 64, 'description': 'room temp'},
    )
    out = client.read_point_properties('10.0.0.21', 'Analog Input', 1)
    assert out['presentValue'] == 68.0
    assert out['objectName'] == 'RM-101 TEMP'
