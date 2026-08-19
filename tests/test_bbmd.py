"""Foreign Device registration with a BBMD.

A Who-Is is a broadcast and broadcasts do not cross a router, so discovery was
confined to the scanner's own subnet — one run per building. Registering as a
Foreign Device with a BBMD puts the scanner in that BBMD's Foreign Device
Table; Distribute-Broadcast-To-Network then reaches the BBMD's subnet and its
peers, and I-Am replies come back as ordinary unicast.

Tested against a mock BBMD that relays to mock devices as Forwarded-NPDU,
because the failure mode being guarded against is subtle: a Forwarded-NPDU
carries the originating device's address ahead of the NPDU, so an I-Am parser
that does not skip it drops every reply and registration looks like it did
nothing.
"""

import socket
import struct

import pytest

import hvac_scanner.bacnet as bacnet
from hvac_scanner import codec

from .mock_bbmd import MockBBMD
from .mock_device import MockBACnetDevice


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

    def _make(timeout=0.6):
        c = bacnet.BACnetClient(timeout=timeout)
        c.open()
        made.append(c)
        return c
    yield _make
    for c in made:
        c.close()


# -- wire format ------------------------------------------------------------

class TestWireFormat:

    def test_register_foreign_device_frame(self):
        pkt = codec.build_register_foreign_device(120)
        assert len(pkt) == 6
        bvlc_type, fn, length, ttl = struct.unpack('!BBHH', pkt)
        assert bvlc_type == 0x81
        assert fn == codec.BVLC_REGISTER_FOREIGN_DEVICE
        assert length == 6
        assert ttl == 120

    def test_ttl_is_clamped_to_the_wire_range(self):
        assert struct.unpack('!H', codec.build_register_foreign_device(0)[4:6])[0] == 1
        assert struct.unpack('!H', codec.build_register_foreign_device(10**9)[4:6])[0] \
            == 0xFFFF

    def test_distributed_whois_uses_the_right_bvlc_function(self):
        pkt = codec.build_whois_distribute()
        assert pkt[1] == codec.BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK

    def test_distributed_whois_carries_the_same_apdu_as_a_normal_one(self):
        plain = codec.build_whois()
        dist = codec.build_whois_distribute()
        assert plain[4:] == dist[4:]      # identical NPDU + APDU

    def test_distributed_whois_honours_an_instance_range(self):
        pkt = codec.build_whois_distribute(low=0, high=999)
        assert bytes([0x10, 0x08]) in pkt
        assert pkt[-1] == 0xE7           # 999 low byte of the high limit

    def test_bvlc_result_parsing(self):
        ok = struct.pack('!BBHH', 0x81, codec.BVLC_RESULT, 6, 0x0000)
        nak = struct.pack('!BBHH', 0x81, codec.BVLC_RESULT, 6, 0x0030)
        assert codec.parse_bvlc_result(ok) == codec.BVLC_RESULT_SUCCESS
        assert codec.parse_bvlc_result(nak) == \
            codec.BVLC_RESULT_REGISTER_FOREIGN_DEVICE_NAK
        assert codec.parse_bvlc_result(codec.build_whois()) is None

    def test_result_codes_have_readable_names(self):
        assert 'Register-Foreign-Device' in \
            codec.bvlc_result_name(codec.BVLC_RESULT_REGISTER_FOREIGN_DEVICE_NAK)
        assert 'unknown' in codec.bvlc_result_name(0xABCD)


# -- forwarded NPDU ---------------------------------------------------------

class TestForwardedNpdu:

    def _iam(self, instance=42):
        oid = struct.pack('!I', (8 << 22) | instance)
        return (bytes([0x10, 0x00, 0xC4]) + oid
                + bytes([0x22, 0x05, 0xC4, 0x91, 0x03, 0x21, 0x02]))

    def test_iam_inside_a_forwarded_npdu_is_parsed(self):
        """Without skipping the 6-byte originating address, every I-Am that
        arrives through a BBMD is dropped and registration looks inert."""
        npdu = bytes([0x01, 0x00]) + self._iam(42)
        origin = socket.inet_aton('10.9.9.9') + struct.pack('!H', 47808)
        pkt = struct.pack('!BBH', 0x81, codec.BVLC_FORWARDED_NPDU,
                          4 + 6 + len(npdu)) + origin + npdu
        dev = codec.parse_iam(pkt, ('10.0.0.5', 47808))
        assert dev is not None
        assert dev.instance == 42

    def test_ordinary_broadcast_iam_still_parses(self):
        npdu = bytes([0x01, 0x00]) + self._iam(7)
        pkt = codec.build_bvlc(codec.BVLC_ORIGINAL_BROADCAST_NPDU, npdu)
        dev = codec.parse_iam(pkt, ('10.0.0.5', 47808))
        assert dev is not None and dev.instance == 7


# -- registration against a mock BBMD ---------------------------------------

class TestRegistration:

    def test_successful_registration(self, client):
        with MockBBMD(mode='accept') as bbmd:
            c = client()
            assert c.register_foreign_device('127.0.0.1', ttl=90) is True
            assert c._bbmd == ('127.0.0.1', 90)
        assert bbmd.registrations and bbmd.registrations[0][1] == 90

    def test_refused_registration_reports_failure(self, client):
        with MockBBMD(mode='refuse'):
            assert client().register_foreign_device('127.0.0.1') is False

    def test_silent_bbmd_reports_failure(self, client):
        """A BBMD that says nothing must not look like success — otherwise the
        scan reports an empty network and passes for a clean result."""
        with MockBBMD(mode='silent'):
            assert client(timeout=0.3).register_foreign_device('127.0.0.1') is False

    def test_failed_registration_leaves_no_stale_state(self, client):
        with MockBBMD(mode='refuse'):
            c = client()
            c.register_foreign_device('127.0.0.1')
            assert c._bbmd is None

    def test_discovery_requires_registration_first(self, client):
        with MockBBMD(mode='accept'):
            with pytest.raises(RuntimeError):
                client().discover_who_is_via_bbmd()


# -- discovery through the BBMD ---------------------------------------------

class TestDiscoveryViaBbmd:

    def test_devices_behind_the_bbmd_are_discovered(self, client):
        with MockBBMD(mode='accept') as bbmd:
            with MockBACnetDevice(instance=5001, n_objects=4, patch_port=False) as d1, \
                 MockBACnetDevice(instance=5002, n_objects=4, patch_port=False) as d2:
                bbmd.add_device(d1)
                bbmd.add_device(d2)
                c = client()
                assert c.register_foreign_device('127.0.0.1') is True
                found = c.discover_who_is_via_bbmd()
        instances = sorted(d['instance'] for d in found)
        assert instances == [5001, 5002]

    def test_the_bbmd_actually_saw_a_distributed_broadcast(self, client):
        with MockBBMD(mode='accept') as bbmd:
            with MockBACnetDevice(instance=5001, patch_port=False) as d1:
                bbmd.add_device(d1)
                c = client()
                c.register_foreign_device('127.0.0.1')
                c.discover_who_is_via_bbmd()
        assert bbmd.distributed == 1

    def test_instance_range_is_passed_through(self, client):
        with MockBBMD(mode='accept') as bbmd:
            with MockBACnetDevice(instance=5001, patch_port=False) as d1:
                bbmd.add_device(d1)
                c = client()
                c.register_foreign_device('127.0.0.1')
                found = c.discover_who_is_via_bbmd(low=0, high=9999)
        assert found and found[0]['instance'] == 5001


# -- TTL renewal ------------------------------------------------------------

class TestTtlRenewal:

    def test_registration_is_renewed_before_the_lease_lapses(self, client):
        """A site that takes longer to scan than the TTL would otherwise stop
        finding devices partway through, with nothing to say why."""
        with MockBBMD(mode='accept') as bbmd:
            with MockBACnetDevice(instance=5001, patch_port=False) as d1:
                bbmd.add_device(d1)
                c = client()
                c.register_foreign_device('127.0.0.1', ttl=60)
                assert len(bbmd.registrations) == 1
                # Pretend most of the lease has elapsed.
                c._bbmd_registered_at -= 50
                c.discover_who_is_via_bbmd()
        assert len(bbmd.registrations) == 2

    def test_a_fresh_registration_is_not_renewed(self, client):
        with MockBBMD(mode='accept') as bbmd:
            with MockBACnetDevice(instance=5001, patch_port=False) as d1:
                bbmd.add_device(d1)
                c = client()
                c.register_foreign_device('127.0.0.1', ttl=600)
                c.discover_who_is_via_bbmd()
        assert len(bbmd.registrations) == 1


# -- engine and CLI ---------------------------------------------------------

class TestIntegration:

    def test_engine_discovers_through_a_bbmd(self, client, monkeypatch):
        from hvac_scanner.engine import ScanEngine, ScanOptions

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

        with MockBBMD(mode='accept') as bbmd:
            with MockBACnetDevice(instance=5001, n_objects=4, patch_port=False) as d1:
                bbmd.add_device(d1)
                opts = ScanOptions(networks=["127.0.0.1"], timeout=0.6,
                                   bbmd="127.0.0.1", deep_scan=False,
                                   scan_modbus=False, scan_services=False,
                                   scan_snmp=False, scan_mstp=False)
                result = ScanEngine(opts, callback=lambda m: None).run()
        assert [d['instance'] for d in result.devices] == [5001]

    def test_engine_aborts_bacnet_when_registration_fails(self, monkeypatch):
        """Falling back to a local broadcast would report an empty network and
        look like a clean result, when the truth is the BBMD is unreachable."""
        from hvac_scanner.engine import ScanEngine, ScanOptions

        def _open(self):
            if self._sock is not None:
                return self._bound_port or 0
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.bind(("", 0))
            self._sock, self._bound_port = s, s.getsockname()[1]
            return self._bound_port
        monkeypatch.setattr(bacnet.BACnetClient, "open", _open)

        logs = []
        with MockBBMD(mode='refuse'):
            opts = ScanOptions(networks=["127.0.0.1"], timeout=0.4,
                               bbmd="127.0.0.1", scan_modbus=False,
                               scan_services=False, scan_snmp=False,
                               scan_mstp=False)
            result = ScanEngine(opts, callback=logs.append).run()
        assert result.devices == []
        assert any('Could not register with BBMD' in line for line in logs)

    def test_cli_flags(self):
        from hvac_scanner.cli import _build_parser
        a = _build_parser().parse_args(['10.0.0.0/24', '--bbmd', '10.1.1.5',
                                        '--bbmd-ttl', '300'])
        assert a.bbmd == '10.1.1.5'
        assert a.bbmd_ttl == 300

    def test_bbmd_defaults_to_off(self):
        from hvac_scanner.cli import _build_parser
        a = _build_parser().parse_args(['10.0.0.0/24'])
        assert a.bbmd is None
        assert a.bbmd_ttl == 60

    def test_scan_options_default_has_no_bbmd(self):
        from hvac_scanner.engine import ScanOptions
        assert ScanOptions().bbmd is None
