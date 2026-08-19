"""Batched objectList enumeration via ReadPropertyMultiple array indices.

Enumerating a device used to cost one ReadProperty per array index — 5,476
round trips on a large supervisory controller, strictly serialized, before a
single point value had been read. BACnetPropertyReference carries an optional
propertyArrayIndex, so one RPM request can ask for objectList[1..N] and the
whole enumeration collapses to one exchange per batch.

These tests run against a real UDP mock device (tests/mock_device.py) rather
than a stubbed client, because the thing being asserted is wire behaviour and
exchange count. The mock can emulate the three RPM behaviours seen in the
field: full support, RPM without propertyArrayIndex, and outright rejection.
"""

import socket

import pytest

import hvac_scanner.bacnet as bacnet
from hvac_scanner import codec

from .mock_device import MockBACnetDevice


@pytest.fixture
def ephemeral_client(monkeypatch):
    """A client bound to an ephemeral port so it does not fight the mock for 47808."""
    def _open(self):
        if self._sock is not None:
            return self._bound_port or 0
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(self.timeout)
        s.bind(("", 0))
        self._sock, self._bound_port = s, s.getsockname()[1]
        return self._bound_port
    monkeypatch.setattr(bacnet.BACnetClient, "open", _open)

    made = []

    def _make(timeout=1.0, **kw):
        c = bacnet.BACnetClient(timeout=timeout, **kw)
        c.open()
        made.append(c)
        return c
    yield _make
    for c in made:
        c.close()


# -- codec ------------------------------------------------------------------

class TestArrayIndexEncoding:

    def test_property_reference_carries_an_array_index(self):
        pkt = codec.build_read_property_multiple('Device', 1, [('objectList', 7)])
        # ctx0 propertyIdentifier 76, then ctx1 propertyArrayIndex 7
        assert bytes([0x09, 76, 0x19, 0x07]) in pkt

    def test_plain_property_reference_has_no_array_index(self):
        pkt = codec.build_read_property_multiple('Device', 1, ['objectList'])
        assert bytes([0x09, 76]) in pkt
        assert bytes([0x09, 76, 0x19]) not in pkt

    def test_two_byte_array_index(self):
        pkt = codec.build_read_property_multiple('Device', 1, [('objectList', 300)])
        assert bytes([0x09, 76, 0x1A, 0x01, 0x2C]) in pkt

    def test_mixed_plain_and_indexed_references(self):
        pkt = codec.build_read_property_multiple(
            'Device', 1, ['objectName', ('objectList', 3)])
        assert bytes([0x09, 77]) in pkt
        assert bytes([0x09, 76, 0x19, 0x03]) in pkt


class TestFullAckParsing:

    @staticmethod
    def _ack(entries):
        """entries: [(prop_id, array_index, value_bytes)]"""
        body = bytearray(bytes([0x0C]) + codec.encode_object_id('Device', 1) + bytes([0x1E]))
        for prop, ai, val in entries:
            body += codec.encode_context_unsigned(2, prop)
            if ai is not None:
                body += codec.encode_context_unsigned(3, ai)
            body += bytes([0x4E]) + val + bytes([0x4F])
        body += bytes([0x1F])
        return codec.build_bvlc(0x0A, b'\x01\x00' + bytes([0x30, 1, 0x0E]) + bytes(body))

    def test_array_index_is_preserved(self):
        pkt = self._ack([
            (76, 1, bytes([0xC4]) + codec.encode_object_id('Analog Input', 0)),
            (76, 2, bytes([0xC4]) + codec.encode_object_id('Binary Input', 5)),
        ])
        out = codec.parse_read_property_multiple_ack_full(pkt)
        assert [(e.prop_id, e.array_index, e.value) for e in out] == [
            (76, 1, ('Analog Input', 0)),
            (76, 2, ('Binary Input', 5)),
        ]

    def test_dict_wrapper_still_returns_the_old_shape(self):
        pkt = self._ack([(85, None, bytes([0x44]) + b'\x42\x91\x00\x00')])
        assert codec.parse_read_property_multiple_ack(pkt, [85]) == {85: 72.5}

    def test_dict_wrapper_cannot_represent_a_batch(self):
        """Documents why the full parser exists: 130 objectList entries all
        arrive as property 76 and a dict keyed on property id collapses them."""
        pkt = self._ack([
            (76, 1, bytes([0xC4]) + codec.encode_object_id('Analog Input', 0)),
            (76, 2, bytes([0xC4]) + codec.encode_object_id('Binary Input', 5)),
        ])
        assert len(codec.parse_read_property_multiple_ack(pkt, [76])) == 1
        assert len(codec.parse_read_property_multiple_ack_full(pkt)) == 2

    def test_object_identity_is_reported(self):
        pkt = self._ack([(85, None, bytes([0x44]) + b'\x42\x91\x00\x00')])
        e = codec.parse_read_property_multiple_ack_full(pkt)[0]
        assert (e.obj_type, e.obj_instance) == (8, 1)

    def test_access_errors_are_still_skipped(self):
        body = bytearray(bytes([0x0C]) + codec.encode_object_id('Device', 1) + bytes([0x1E]))
        body += codec.encode_context_unsigned(2, 76)
        body += codec.encode_context_unsigned(3, 1)
        body += bytes([0x5E, 0x91, 0x02, 0x91, 0x20, 0x5F])
        body += bytes([0x1F])
        pkt = codec.build_bvlc(0x0A, b'\x01\x00' + bytes([0x30, 1, 0x0E]) + bytes(body))
        assert codec.parse_read_property_multiple_ack_full(pkt) == []


# -- batch sizing -----------------------------------------------------------

class TestBatchSizing:

    def test_scales_with_the_device_apdu(self):
        size = bacnet.BACnetClient._object_list_batch_size
        assert size(128) < size(480) < size(1476)

    def test_never_returns_less_than_one(self):
        size = bacnet.BACnetClient._object_list_batch_size
        for apdu in (0, 1, 50, None):
            assert size(apdu) >= 1

    def test_unknown_apdu_is_conservative(self):
        """An unknown device gets the small-controller assumption, not the large one."""
        size = bacnet.BACnetClient._object_list_batch_size
        assert size(None) == size(480)

    def test_capped_so_one_bad_batch_stays_cheap(self):
        assert bacnet.BACnetClient._object_list_batch_size(1476) <= bacnet._RPM_MAX_BATCH


# -- end to end against the mock -------------------------------------------

class TestEnumerationAgainstMock:

    N = 300

    def _enumerate(self, client, dev):
        return client.read_object_list_entries_indexed(
            '127.0.0.1', 1234, list(range(1, self.N + 1)), max_apdu=dev.max_apdu)

    def test_batched_enumeration_is_complete_and_ordered(self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            got = self._enumerate(ephemeral_client(), dev)
        assert [i for i, _ in got] == list(range(1, self.N + 1))

    def test_batched_enumeration_costs_orders_of_magnitude_fewer_exchanges(
            self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            self._enumerate(ephemeral_client(), dev)
            batched = dev.exchanges
        with MockBACnetDevice(n_objects=self.N, rpm_mode='reject') as dev2:
            self._enumerate(ephemeral_client(), dev2)
            serial = dev2.exchanges
        assert batched < serial / 10, f"batched={batched} serial={serial}"
        assert dev.rpm_batches > 0

    def test_entries_match_between_batched_and_serial_paths(self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            fast = self._enumerate(ephemeral_client(), dev)
        with MockBACnetDevice(n_objects=self.N, rpm_mode='reject') as dev2:
            slow = self._enumerate(ephemeral_client(), dev2)
        assert fast == slow

    def test_device_rejecting_rpm_outright_still_enumerates_fully(self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='reject') as dev:
            got = self._enumerate(ephemeral_client(), dev)
        assert [i for i, _ in got] == list(range(1, self.N + 1))

    def test_device_without_array_index_support_still_enumerates_fully(
            self, ephemeral_client):
        """RPM works but propertyArrayIndex does not — a real stack variant."""
        with MockBACnetDevice(n_objects=self.N, rpm_mode='no_arrays') as dev:
            got = self._enumerate(ephemeral_client(), dev)
        assert [i for i, _ in got] == list(range(1, self.N + 1))
        assert dev.rpm_batches == 0

    def test_fallback_gives_up_on_batching_quickly(self, ephemeral_client):
        """A device that refuses batches must not be re-probed for every batch."""
        with MockBACnetDevice(n_objects=self.N, rpm_mode='reject') as dev:
            self._enumerate(ephemeral_client(), dev)
        wasted = dev.exchanges - self.N
        assert wasted <= bacnet._RPM_BATCH_GIVE_UP, f"{wasted} wasted probes"

    def test_prefer_multiple_false_uses_the_serial_path(self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            got = ephemeral_client().read_object_list_entries_indexed(
                '127.0.0.1', 1234, list(range(1, self.N + 1)),
                max_apdu=dev.max_apdu, prefer_multiple=False)
        assert len(got) == self.N
        assert dev.rpm_batches == 0

    def test_small_apdu_device_batches_within_its_limit(self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full', max_apdu=206) as dev:
            got = self._enumerate(ephemeral_client(), dev)
        assert [i for i, _ in got] == list(range(1, self.N + 1))
        assert dev.exchanges < self.N

    def test_single_index_does_not_use_a_batch(self, ephemeral_client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            got = ephemeral_client().read_object_list_entries_indexed(
                '127.0.0.1', 1234, [5], max_apdu=dev.max_apdu)
        assert len(got) == 1 and got[0][0] == 5
        assert dev.rpm_batches == 0
