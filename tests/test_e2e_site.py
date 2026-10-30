"""End to end against the simulated site in tools/sim_site.py.

Every other test exercises one layer against a hand-built packet or a mock on
127.0.0.1. These run the real engine against a small simulated building on
its own loopback /24 — real port 47808, a broadcast relay, an MS/TP router,
an RPM-rejecting workstation — and check what a user would see.

The site runs on 127.0.1.x so a simulator already running on 127.0.0.x (the
documented way to try the GUI) does not collide with it. Where loopback
aliases are unavailable (macOS) or port 47808 cannot be bound, the module
skips.
"""

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from hvac_scanner.engine import ScanEngine, ScanOptions  # noqa: E402

NET = "127.0.1"
TARGETS = f"{NET}.2-30"

IP_DEVICES = {1001, 2000, 2101, 3000, 1100, 3101}
MSTP_DEVICES = {500003, 500007, 500012}


@pytest.fixture(scope="module")
def site():
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind((f"{NET}.2", 47808))
        probe.close()
    except OSError as e:
        pytest.skip(f"cannot bind the simulated site on {NET}.x: {e}")
    import sim_site
    s = sim_site.Site(quiet=True, network=NET, bacnet_only=True).start()
    if len(s.endpoints) < 6:
        s.close()
        pytest.skip("simulated BACnet devices did not all start")
    yield s
    s.close()


def _scan(**kw):
    opts = dict(networks=[TARGETS], timeout=1.5, scan_modbus=False,
                scan_services=False, scan_snmp=False, scan_p2=False, scan_knx=False)
    opts.update(kw)
    logs = []
    result = ScanEngine(ScanOptions(**opts), callback=logs.append).run()
    return result, logs


@pytest.fixture(scope="module")
def full_scan(site):
    return _scan()


def _by_instance(result):
    return {d['instance']: d for d in result.devices if d.get('instance') is not None}


def test_every_device_is_found_once(full_scan):
    result, _ = full_scan
    found = _by_instance(result)
    assert set(found) == IP_DEVICES | MSTP_DEVICES
    assert len(result.devices) == len(found)


def test_relayed_iams_carry_the_device_address_not_the_relay(full_scan):
    """The relay delivers I-Ams as Forwarded-NPDUs, as a BBMD does. Before
    v2.7 every one of them was attributed to the relay's own address."""
    result, _ = full_scan
    found = _by_instance(result)
    assert found[1001]['ip'] == f"{NET}.2"
    assert found[2000]['ip'] == f"{NET}.3"
    assert all(d['ip'] != f"{NET}.255" for d in result.devices)


def test_mstp_devices_are_labelled_and_counted_as_mstp(full_scan):
    result, _ = full_scan
    found = _by_instance(result)
    for inst in MSTP_DEVICES:
        assert found[inst]['protocol'] == 'BACnet/MSTP'
        assert found[inst]['ip'] == f"{NET}.5"          # the router
    assert result.counts['mstp'] == 3
    assert result.counts['bacnet'] == 6


def test_points_are_read_with_correct_units(full_scan):
    result, _ = full_scan
    sc = _by_instance(result)[1001]
    assert len(sc['objects']) == 632
    by_name = {p['name']: p for p in sc['objects']}
    assert by_name['AHU-1:RA-H']['units'] == '%RH'       # was "W"
    assert by_name['AHU-1:SA-P']['units'] == 'inH2O'     # was "unit-58"
    assert by_name['AHU-1:RA-CO2']['units'] == 'ppm'     # was "kPa-alt"
    assert by_name['PLANT:CH1-KW']['units'] == 'kW'      # was "unit-48"
    assert by_name['PLANT:BLDG-KWH']['units'] == 'kWh'   # was "kPa"
    assert by_name['AHU-1:SA-T']['units'] == '°F'


def test_binary_points_read_active_or_inactive(full_scan):
    result, _ = full_scan
    sc = _by_instance(result)[1001]
    binaries = [p for p in sc['objects'] if p['type'].startswith('Binary')]
    assert binaries
    assert {p['present_value'] for p in binaries} <= {'active', 'inactive'}


def test_status_flags_are_read_and_summarised(full_scan):
    result, _ = full_scan
    sc = _by_instance(result)[1001]
    by_name = {p['name']: p for p in sc['objects']}
    assert by_name['AHU-2:FRZ-STAT']['status'] == 'in-alarm'
    assert by_name['AHU-3:SF-C']['status'] == 'overridden'
    assert by_name['VAV-07:ZN-T']['status'] == 'fault'
    assert by_name['AHU-4:RA-H']['status'] == 'out-of-service'
    assert by_name['AHU-1:SA-T']['status'] == ''
    assert sc['point_flags'] == {'in-alarm': 1, 'fault': 1, 'overridden': 2,
                                 'out-of-service': 1}
    pxc = _by_instance(result)[2000]
    assert {p['name']: p for p in pxc['objects']}['HHW:CH1-KW']['status'] == \
        'fault, out-of-service'


def test_multi_state_values_read_as_their_state_text(full_scan):
    result, _ = full_scan
    sc = _by_instance(result)[1001]
    modes = [p for p in sc['objects'] if p['name'].endswith('AHU-MODE')]
    assert modes
    for p in modes:
        assert p['present_value'] in ("Off", "Heating", "Cooling", "Economizer")
        assert 1 <= p['state_number'] <= 4


def test_mstp_points_are_read_through_the_router(full_scan):
    result, _ = full_scan
    fec = _by_instance(result)[500007]
    assert fec['properties']['model_name'] == 'FEC2611'
    assert len(fec['objects']) == 9


def test_a_device_that_rejects_rpm_is_still_identified(full_scan):
    result, _ = full_scan
    tes = _by_instance(result)[1100]
    assert tes['properties']['model_name'] == 'TES Workstation'


def test_result_order_is_discovery_order_not_finish_order(full_scan):
    """Parallel workers finish in any order; the result list should not."""
    import re
    result, logs = full_scan
    # First mention of each device is its discovery line; later ones head
    # its deep-scan detail.
    discovered = list(dict.fromkeys(int(m.group(1)) for line in logs
                                    if (m := re.match(r"\s+Device (\d+) at ", line))))
    assert [d['instance'] for d in result.devices] == discovered


def test_parallel_and_sequential_deep_scans_agree(site):
    def summary(result):
        return sorted((d['ip'], d['instance'], len(d.get('objects') or []))
                      for d in result.devices)
    parallel, _ = _scan(bacnet_workers=6, scan_mstp=False)
    sequential, _ = _scan(bacnet_workers=1, scan_mstp=False)
    assert summary(parallel) == summary(sequential)


def test_unicast_discovery_finds_what_broadcast_cannot(site):
    """Point the broadcast somewhere nothing listens — as on a routed VLAN —
    and the devices must still be found by asking each address directly."""
    result, logs = _scan(bacnet_broadcast=f"{NET}.254", unicast_discovery="always",
                         scan_mstp=False, deep_scan=False)
    found = _by_instance(result)
    assert IP_DEVICES <= set(found)
    assert all(found[i].get('discovered_via') == 'unicast' for i in IP_DEVICES)
    assert found[1001]['vendor_id'] == 2 and found[1001]['max_apdu'] == 1476
    assert any('Unicast discovery found' in line for line in logs)


def test_unicast_discovery_off_finds_nothing_without_a_broadcast(site):
    result, logs = _scan(bacnet_broadcast=f"{NET}.254", unicast_discovery="off",
                         scan_mstp=False, deep_scan=False)
    assert not result.devices
    assert any('No BACnet device answered' in line for line in logs)
