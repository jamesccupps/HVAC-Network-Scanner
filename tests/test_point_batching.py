"""Batched per-point property reads across multiple objects.

ReadPropertyMultiple takes a LIST of ReadAccessSpecifications, so one exchange
can read four properties from a dozen objects. The scanner previously issued
one RPM per object, so a 1000-point controller cost 1000 exchanges for the
property phase alone.

Response size cannot be predicted from the request here — object names and
descriptions are free-form — so the batch size is adaptive rather than
computed, and every path must produce identical data.
"""

import socket

import pytest

import hvac_scanner.bacnet as bacnet
from hvac_scanner import codec
from hvac_scanner.constants import PROP_IDS

from .mock_device import MockBACnetDevice



POINT_PROPS = ['objectName', 'presentValue', 'units', 'description']


@pytest.fixture
def client(monkeypatch):
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

    def _make(**kw):
        c = bacnet.BACnetClient(timeout=1.0, **kw)
        c.open()
        made.append(c)
        return c
    yield _make
    for c in made:
        c.close()


def _objects(dev, n):
    return [(t, i, POINT_PROPS) for t, i in dev.objects[:n]]


# -- builder ----------------------------------------------------------------

class TestMultiObjectRequest:

    def test_encodes_one_access_specification_per_object(self):
        pkt = codec.build_read_property_multiple_objects([
            ('Analog Input', 0, ['presentValue']),
            ('Analog Input', 1, ['presentValue']),
            ('Binary Input', 4, ['presentValue']),
        ])
        assert pkt.count(bytes([0x0C])) == 3      # context tag 0, object id
        assert pkt.count(bytes([0x1E])) == 3      # opening tag 1
        assert pkt.count(bytes([0x1F])) == 3      # closing tag 1

    def test_each_object_carries_its_own_property_list(self):
        """A binary point must not be asked for units in a shared batch."""
        pkt = codec.build_read_property_multiple_objects([
            ('Analog Input', 0, ['presentValue', 'units']),
            ('Binary Input', 0, ['presentValue']),
        ])
        assert pkt.count(bytes([0x09, PROP_IDS['units']])) == 1
        assert pkt.count(bytes([0x09, PROP_IDS['presentValue']])) == 2

    def test_empty_spec_list_is_still_a_valid_packet(self):
        pkt = codec.build_read_property_multiple_objects([])
        assert pkt[0] == 0x81 and len(pkt) >= 10


# -- correctness ------------------------------------------------------------

class TestBatchedPointReads:

    N = 40

    def test_batched_matches_per_object_reads_exactly(self, client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            objs = _objects(dev, self.N)
            fast = client().read_points_batched('127.0.0.1', 1234, objs)
            slow = client().read_points_batched('127.0.0.1', 1234, objs,
                                                prefer_multiple=False)
        assert fast == slow

    def test_property_names_are_the_ones_that_were_requested(self, client):
        """Regression: PROP_IDS carries hyphenated aliases alongside camelCase
        names, so inverting it returned 'object-name' instead of 'objectName'
        and the engine silently dropped every name and value."""
        with MockBACnetDevice(n_objects=4, rpm_mode='full') as dev:
            out = client().read_points_batched('127.0.0.1', 1234, _objects(dev, 4))
        for _t, _i, props in out:
            assert props, "no properties came back at all"
            assert set(props).issubset(set(POINT_PROPS)), (
                f"unexpected key names: {sorted(props)}"
            )
            assert 'objectName' in props
            assert 'object-name' not in props

    def test_every_object_in_the_batch_comes_back(self, client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            objs = _objects(dev, self.N)
            out = client().read_points_batched('127.0.0.1', 1234, objs)
        assert len(out) == self.N
        assert [(t, i) for t, i, _ in out] == [(t, i) for t, i, _ in objs]
        assert all(props.get('objectName') for _t, _i, props in out)

    def test_results_are_attributed_to_the_right_object(self, client):
        """The mock names each point after its own type and instance."""
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            out = client().read_points_batched('127.0.0.1', 1234, _objects(dev, self.N))
        for t, i, props in out:
            assert props['objectName'] == f"{t}-{i}"

    def test_binary_points_are_not_given_units(self, client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            objs = [(t, i, ['objectName', 'presentValue']
                     if t.startswith('Binary') else POINT_PROPS)
                    for t, i in dev.objects[:self.N]]
            out = client().read_points_batched('127.0.0.1', 1234, objs)
        for t, _i, props in out:
            if t.startswith('Binary'):
                assert 'units' not in props


# -- cost and resilience ----------------------------------------------------

class TestBatchingBehaviour:

    N = 120

    def test_batching_cuts_the_exchange_count(self, client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            client().read_points_batched('127.0.0.1', 1234, _objects(dev, self.N))
            batched = dev.exchanges
            assert dev.multi_object_batches > 0
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev2:
            client().read_points_batched('127.0.0.1', 1234, _objects(dev2, self.N),
                                         prefer_multiple=False)
            per_object = dev2.exchanges
        assert batched < per_object / 4, f"batched={batched} per_object={per_object}"

    def test_device_rejecting_rpm_still_returns_complete_data(self, client):
        with MockBACnetDevice(n_objects=self.N, rpm_mode='reject') as dev:
            out = client().read_points_batched('127.0.0.1', 1234, _objects(dev, self.N))
        assert len(out) == self.N
        assert all(props.get('objectName') for _t, _i, props in out)

    def test_batch_window_shrinks_when_a_device_refuses(self, client):
        c = client()
        with MockBACnetDevice(n_objects=self.N, rpm_mode='reject') as dev:
            c.read_points_batched('127.0.0.1', 1234, _objects(dev, self.N))
        assert c._point_batch[('127.0.0.1', 1234)] == bacnet._POINT_BATCH_MIN

    def test_batch_window_grows_on_a_cooperative_device(self, client):
        c = client()
        with MockBACnetDevice(n_objects=self.N, rpm_mode='full') as dev:
            c.read_points_batched('127.0.0.1', 1234, _objects(dev, self.N))
        assert c._point_batch[('127.0.0.1', 1234)] > bacnet._POINT_BATCH_INITIAL

    def test_window_never_exceeds_the_cap(self, client):
        c = client()
        with MockBACnetDevice(n_objects=400, rpm_mode='full') as dev:
            c.read_points_batched('127.0.0.1', 1234, _objects(dev, 400))
        assert c._point_batch[('127.0.0.1', 1234)] <= bacnet._POINT_BATCH_MAX

    def test_window_is_tracked_per_device(self, client):
        c = client()
        with MockBACnetDevice(n_objects=20, rpm_mode='reject') as dev:
            c.read_points_batched('127.0.0.1', 1234, _objects(dev, 20))
        assert ('127.0.0.1', 1234) in c._point_batch
        assert ('127.0.0.1', 9999) not in c._point_batch

    def test_empty_object_list_is_harmless(self, client):
        with MockBACnetDevice(n_objects=4, rpm_mode='full'):
            assert client().read_points_batched('127.0.0.1', 1234, []) == []

    def test_stop_fn_aborts_mid_batch(self, client):
        calls = {'n': 0}

        def stop():
            calls['n'] += 1
            return calls['n'] > 2
        with MockBACnetDevice(n_objects=200, rpm_mode='full') as dev:
            out = client().read_points_batched('127.0.0.1', 1234,
                                               _objects(dev, 200), stop_fn=stop)
        assert len(out) == 200            # shape preserved
        assert any(not props for _t, _i, props in out)   # but not all were read
