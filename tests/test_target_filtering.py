"""v2.1.2: verify I-Am responses from IPs outside the user's target
range are dropped before deep-scan, and that results only contain
in-range devices.

Regression guard for the OCC test where user typed 10.0.0.2-10.0.0.21
and the scanner deep-read 15 devices across the whole /24 because the
Who-Is broadcast reached every device on the physical subnet.
"""
from __future__ import annotations

import pytest

from hvac_scanner.engine import ScanEngine, ScanOptions


class TestAllowedIpsSet:
    """`_allowed_ips_for_targets` should enumerate every IP the user asked for."""

    def test_single_host(self):
        engine = ScanEngine(ScanOptions(networks=["10.0.0.5"]),
                            callback=lambda _m: None)
        allowed = engine._allowed_ips_for_targets()
        assert allowed == {"10.0.0.5"}

    def test_small_range(self):
        engine = ScanEngine(ScanOptions(networks=["10.0.0.2-10.0.0.21"]),
                            callback=lambda _m: None)
        allowed = engine._allowed_ips_for_targets()
        expected = {f"10.0.0.{i}" for i in range(2, 22)}
        assert allowed == expected

    def test_short_range(self):
        engine = ScanEngine(ScanOptions(networks=["10.0.0.2-10"]),
                            callback=lambda _m: None)
        allowed = engine._allowed_ips_for_targets()
        expected = {f"10.0.0.{i}" for i in range(2, 11)}
        assert allowed == expected

    def test_cidr(self):
        engine = ScanEngine(ScanOptions(networks=["10.0.0.0/28"]),
                            callback=lambda _m: None)
        allowed = engine._allowed_ips_for_targets()
        expected = {f"10.0.0.{i}" for i in range(1, 15)}  # hosts(): .1-.14
        assert allowed == expected

    def test_list(self):
        engine = ScanEngine(
            ScanOptions(networks=["10.0.0.19, 10.0.0.21, 10.0.0.192"]),
            callback=lambda _m: None,
        )
        allowed = engine._allowed_ips_for_targets()
        assert allowed == {"10.0.0.19", "10.0.0.21", "10.0.0.192"}

    def test_multiple_networks(self):
        """networks= with multiple entries — union of all of them."""
        engine = ScanEngine(
            ScanOptions(networks=["10.0.0.5", "10.0.0.10-12"]),
            callback=lambda _m: None,
        )
        allowed = engine._allowed_ips_for_targets()
        assert allowed == {"10.0.0.5", "10.0.0.10", "10.0.0.11", "10.0.0.12"}


class TestOCCScenario:
    """The specific scenario that sent up the flag: user typed
    10.0.0.2-10.0.0.21 and got 15 out-of-range deep-reads because of
    the BACnet broadcast behavior. The allowlist needs to contain the
    in-range IPs and nothing else."""

    def test_allowlist_contains_in_range_devices(self):
        engine = ScanEngine(
            ScanOptions(networks=["10.0.0.2-10.0.0.21"]),
            callback=lambda _m: None,
        )
        allowed = engine._allowed_ips_for_targets()
        assert "10.0.0.19" in allowed  # SC-1
        assert "10.0.0.21" in allowed  # SC-2

    def test_allowlist_excludes_out_of_range_ips_seen_in_pcap(self):
        engine = ScanEngine(
            ScanOptions(networks=["10.0.0.2-10.0.0.21"]),
            callback=lambda _m: None,
        )
        allowed = engine._allowed_ips_for_targets()
        # Every one of these answered Who-Is in the OCC pcap but the user
        # never asked for them. Filter must reject them.
        out_of_range = [
            "10.0.0.22",   # just outside the range
            "10.0.0.107",  # Desigo CC
            "10.0.0.108",
            "10.0.0.123",
            "10.0.0.192",  # BASRT-B
            "10.0.0.207",
            "10.0.0.216",
            "10.0.0.230",
            "10.0.1.100",  # cross-subnet BBMD-forwarded I-Am
            "10.0.1.155",
        ]
        for ip in out_of_range:
            assert ip not in allowed, f"{ip} should be filtered out"


class TestBacnetScanPath:
    """Verify the BACnet scan code path actually uses the allowlist."""

    def test_filter_drops_out_of_range_simulated_iams(self, monkeypatch):
        """Simulate a mix of in-range and out-of-range I-Am responses and
        verify only in-range ones end up in results."""
        from hvac_scanner import engine as engine_mod

        # Fake BACnetClient that returns a preset I-Am list instead of
        # actually using the network.
        class FakeClient:
            def __init__(self, *_a, **_kw): pass
            def open(self): pass
            def close(self): pass
            def discover_who_is(self, *_a, **_kw):
                return [
                    # In-range
                    {'ip': '10.0.0.19', 'instance': 33333, 'vendor_id': 2},
                    {'ip': '10.0.0.21', 'instance': 22222, 'vendor_id': 2},
                    # Out-of-range — should be dropped
                    {'ip': '10.0.0.107', 'instance': 9997, 'vendor_id': 7},
                    {'ip': '10.0.0.230', 'instance': 104030, 'vendor_id': 7},
                    {'ip': '10.0.1.100', 'instance': 100, 'vendor_id': 7},
                ]

        monkeypatch.setattr(engine_mod, 'BACnetClient', FakeClient)

        eng = ScanEngine(
            ScanOptions(
                networks=["10.0.0.19, 10.0.0.21"],
                scan_bacnet=True,
                scan_mstp=False,
                scan_modbus=False,
                scan_services=False,
                scan_snmp=False,
                deep_scan=False,  # skip deep scan for simplicity
            ),
            callback=lambda _m: None,
        )
        eng.run()

        kept_ips = {d.get('ip') for d in eng.result.devices}
        assert kept_ips == {"10.0.0.19", "10.0.0.21"}, (
            f"Expected only in-range IPs in results, got {kept_ips}"
        )


class TestDeduplicationAcrossMultipleTargets:
    """Regression: v2.1.2 early build duplicated every device N times where
    N = number of comma-separated target tokens. Root cause: the engine
    broadcast a Who-Is once per network entry in opts.networks. When all
    targets were on the same /24, each broadcast returned the same I-Am
    responses, and each pass through the filter appended them to results.

    Found at OCC testing with target `10.0.0.245, 10.0.0.201, 10.0.0.230,
    10.0.0.176` — 4 devices returned 16 CSV rows.
    """

    def test_multiple_targets_same_subnet_no_duplicates(self, monkeypatch):
        from hvac_scanner import engine as engine_mod

        call_count = {'count': 0}

        class FakeClient:
            def __init__(self, *_a, **_kw): pass
            def open(self): pass
            def close(self): pass

            def discover_who_is(self, *_a, **_kw):
                # Every Who-Is broadcast returns the same I-Ams (realistic —
                # broadcast goes to the same /24 each time).
                call_count['count'] += 1
                return [
                    {'ip': '10.0.0.201', 'instance': 104002, 'vendor_id': 7},
                    {'ip': '10.0.0.230', 'instance': 104026, 'vendor_id': 7},
                    {'ip': '10.0.0.245', 'instance': 104046, 'vendor_id': 7},
                    {'ip': '10.0.0.176', 'instance': 101000, 'vendor_id': 7},
                ]

        monkeypatch.setattr(engine_mod, 'BACnetClient', FakeClient)

        # Simulate the GUI splitting the user's comma-separated input into
        # multiple network entries.
        eng = ScanEngine(
            ScanOptions(
                networks=['10.0.0.201', '10.0.0.230', '10.0.0.245', '10.0.0.176'],
                scan_bacnet=True,
                scan_mstp=False,
                scan_modbus=False,
                scan_services=False,
                scan_snmp=False,
                deep_scan=False,
            ),
            callback=lambda _m: None,
        )
        eng.run()

        # Must be exactly 4 distinct devices — no duplicates.
        assert len(eng.result.devices) == 4, (
            f"Expected 4 unique devices, got {len(eng.result.devices)} "
            f"(likely N× duplication bug)"
        )
        ips = [d['ip'] for d in eng.result.devices]
        assert sorted(ips) == sorted([
            '10.0.0.176', '10.0.0.201', '10.0.0.230', '10.0.0.245'
        ])

    def test_single_target_single_device_no_dedup_needed(self, monkeypatch):
        """Sanity check: the dedup logic must not drop legitimate devices
        when there's only one network iteration."""
        from hvac_scanner import engine as engine_mod

        class FakeClient:
            def __init__(self, *_a, **_kw): pass
            def open(self): pass
            def close(self): pass
            def discover_who_is(self, *_a, **_kw):
                return [
                    {'ip': '10.0.0.19', 'instance': 33333, 'vendor_id': 2},
                ]

        monkeypatch.setattr(engine_mod, 'BACnetClient', FakeClient)

        eng = ScanEngine(
            ScanOptions(networks=['10.0.0.19'], scan_bacnet=True,
                        scan_mstp=False, scan_modbus=False,
                        scan_services=False, scan_snmp=False, deep_scan=False),
            callback=lambda _m: None,
        )
        eng.run()

        assert len(eng.result.devices) == 1

    def test_broadcast_consolidation_fires_once_per_subnet(self, monkeypatch):
        """v2.1.2 optimization: when multiple targets resolve to the same
        broadcast, the engine should send Who-Is only once — not once per
        target token. This saves redundant packets on the wire and prevents
        the duplicate-row bug at its root cause."""
        from hvac_scanner import engine as engine_mod

        broadcasts_sent: list[str] = []

        class FakeClient:
            def __init__(self, *_a, **_kw): pass
            def open(self): pass
            def close(self): pass
            def discover_who_is(self, target_ip=None, *_a, **_kw):
                broadcasts_sent.append(target_ip)
                return [
                    {'ip': '10.0.0.176', 'instance': 101000, 'vendor_id': 7},
                    {'ip': '10.0.0.201', 'instance': 104002, 'vendor_id': 7},
                    {'ip': '10.0.0.230', 'instance': 104026, 'vendor_id': 7},
                    {'ip': '10.0.0.245', 'instance': 104046, 'vendor_id': 7},
                ]

        monkeypatch.setattr(engine_mod, 'BACnetClient', FakeClient)

        # 4 targets, all in same /24 — should consolidate to 1 broadcast.
        eng = ScanEngine(
            ScanOptions(
                networks=['10.0.0.176', '10.0.0.201', '10.0.0.230', '10.0.0.245'],
                scan_bacnet=True, scan_mstp=False, scan_modbus=False,
                scan_services=False, scan_snmp=False, deep_scan=False,
            ),
            callback=lambda _m: None,
        )
        eng.run()

        assert len(broadcasts_sent) == 1, (
            f"Expected 1 broadcast (consolidated), got {len(broadcasts_sent)}: "
            f"{broadcasts_sent}"
        )
        assert broadcasts_sent[0] == '10.0.0.255'
        assert len(eng.result.devices) == 4


class TestMstpScanPath:
    """MSTP discovery must respect the target-IP allowlist too.

    Pcap evidence: scanning 10.0.0.19-10.0.0.21 enumerated MSTP devices
    behind routers at 10.0.0.179 (Cimetrics PXC) and 10.0.0.192 (JCI
    BASRT-B). Those routers are NOT in the target range; their MSTP
    children must be dropped.
    """

    def test_mstp_drops_devices_behind_out_of_range_routers(self, monkeypatch):
        from hvac_scanner import engine as engine_mod

        class FakeClient:
            def __init__(self, *_a, **_kw): pass
            def open(self): pass
            def close(self): pass

            def discover_who_is(self, target_ip=None, low=None, high=None,
                                dnet=None, extra_wait=0.0):
                if dnet is None:
                    # BACnet/IP Who-Is — return just the Trane SCs
                    return [
                        {'ip': '10.0.0.19', 'instance': 33333, 'vendor_id': 2},
                        {'ip': '10.0.0.21', 'instance': 22222, 'vendor_id': 2},
                    ]
                # Routed Who-Is to a DNET — simulate responses based on DNET
                if dnet == 11:
                    # Behind SC-1 (10.0.0.19), in range — keep
                    return [
                        {'ip': '10.0.0.19', 'instance': 11001,
                         'source_network': 11, 'source_address': b'\x01'},
                    ]
                elif dnet == 102:
                    # Behind PXC (10.0.0.179), NOT in range — drop
                    return [
                        {'ip': '10.0.0.179', 'instance': 10201,
                         'source_network': 102, 'source_address': b'\x01'},
                        {'ip': '10.0.0.179', 'instance': 10202,
                         'source_network': 102, 'source_address': b'\x02'},
                    ]
                elif dnet == 103:
                    # Behind BASRT-B (10.0.0.192), NOT in range — drop
                    return [
                        {'ip': '10.0.0.192', 'instance': 103001,
                         'source_network': 103, 'source_address': b'\x01'},
                    ]
                return []

            def discover_routers(self, target_ip=None):
                # Three routers on the segment; scanner filter should
                # only consider ones within the target range.
                routers = [
                    {'ip': '10.0.0.19',  'networks': [11]},   # in range
                    {'ip': '10.0.0.179', 'networks': [102]},  # NOT in range
                    {'ip': '10.0.0.192', 'networks': [103]},  # NOT in range
                ]
                dnets = [11, 102, 103]
                return routers, dnets

        monkeypatch.setattr(engine_mod, 'BACnetClient', FakeClient)

        eng = ScanEngine(
            ScanOptions(
                networks=["10.0.0.19-10.0.0.21"],
                scan_bacnet=True,
                scan_mstp=True,
                scan_modbus=False,
                scan_services=False,
                scan_snmp=False,
                deep_scan=False,
            ),
            callback=lambda _m: None,
        )
        eng.run()

        kept_ips = {d.get('ip') for d in eng.result.devices}
        # Expect: SC-1, SC-2 (IP), and the one MSTP device behind SC-1.
        # Must NOT include 10.0.0.179 or 10.0.0.192 (out-of-range routers).
        assert kept_ips == {"10.0.0.19", "10.0.0.21"}, (
            f"Expected only devices at in-range router IPs, got {kept_ips}"
        )

        mstp_devs = [d for d in eng.result.devices
                     if d.get('protocol') == 'BACnet/MSTP']
        assert len(mstp_devs) == 1, (
            f"Expected exactly 1 MSTP device (behind SC-1), got {len(mstp_devs)}: "
            f"{[(d['ip'], d.get('device_id')) for d in mstp_devs]}"
        )
        assert mstp_devs[0]['ip'] == '10.0.0.19'
        assert mstp_devs[0]['instance'] == 11001
