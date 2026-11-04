"""2.9: alarm routing (Notification Class) and router tables."""

import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from hvac_scanner import codec  # noqa: E402
from hvac_scanner.engine import ScanEngine, ScanOptions  # noqa: E402

NET = "127.0.1"
REMOTE = "127.0.3"
_MAC = socket.inet_aton("10.20.30.40") + struct.pack('!H', 47808)


# ---------------------------------------------------------------------------
# codec
# ---------------------------------------------------------------------------

def test_a_six_or_seven_octet_context_value_is_not_an_opening_or_closing_tag():
    """_read_tag reports opening/closing tags as length 6/7, which a context
    value of six or seven octets also reports. A B/IP MAC is six octets, so
    every routing-table entry lost its next hop, and a seven-octet value
    ended the construct around it."""
    entry = b'\x09\x09' + b'\x1d\x06' + _MAC + b'\x29\x00'
    assert codec.decode_routing_table(entry) == [
        {'network': 9, 'via': '10.20.30.40:47808', 'status': 'available'}]
    seven = b'\x0d\x07' + bytes(range(7))
    assert codec._value_end(seven + b'\x3f', 0) == 9
    assert codec._parse_app_value(seven, 0) == (bytes(range(7)).hex(), 9)


def test_recipient_list_decodes_devices_and_addresses():
    import sim_site
    raw = (sim_site.destination('1111100', (7, 0, 0, 0), (18, 0, 0, 0),
                                sim_site.to_device(9001), transitions='110',
                                confirmed=False, process=3)
           + sim_site.destination('1111111', *sim_site.ALL_DAY,
                                  sim_site.to_address(0, _MAC), process=7))
    first, second = codec.decode_recipient_list(raw)
    assert first == {'device': 9001, 'days': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
                     'from': '07:00', 'to': '18:00', 'process': 3, 'confirmed': False,
                     'transitions': ['to-offnormal', 'to-fault']}
    assert (second['network'], second['address'], second['confirmed']) == \
        (0, '10.20.30.40:47808', True)
    assert codec.decode_recipient_list(b'') == []


def test_bit_strings_and_ack_required():
    assert codec.decode_bits('05c0') == [True, True, False]
    assert codec.decode_ack_required('05a0') == ['to-offnormal', 'to-normal']
    assert codec.decode_bits('zz') == []


def test_an_empty_rpm_value_is_an_answer():
    """A Notification Class with no recipients reads as an empty list; it
    used to be dropped like a property the device never returned."""
    ack = (bytes([0x81, 0x0A, 0, 0, 0x01, 0x00, 0x30, 0x01, 0x0E])
           + b'\x0c' + struct.pack('!I', (15 << 22) | 2) + b'\x1e'
           + b'\x29\x66' + b'\x4e\x4f' + b'\x1f')
    (entry,) = codec.parse_read_property_multiple_ack_full(ack)
    assert (entry.prop_id, entry.value, entry.raw) == (102, [], b'')


def test_recipient_summary_leaves_out_what_is_always():
    from hvac_scanner.report import recipient_summary
    assert recipient_summary({'device': 1100, 'days': list('1234567'), 'from': '00:00',
                              'to': '23:59', 'transitions': ['a', 'b', 'c']}) == "device 1100"
    assert recipient_summary({'device': 9001, 'days': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
                              'from': '07:00', 'to': '18:00',
                              'transitions': ['to-offnormal', 'to-fault']}) == \
        "device 9001, Mon–Fri, 07:00–18:00, to-offnormal + to-fault"
    assert recipient_summary({'network': 5, 'address': '7'}).startswith("7 (network 5)")


# ---------------------------------------------------------------------------
# against the simulated site
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def site_scan():
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind((f"{NET}.2", 47808))
        probe.close()
    except OSError as e:
        pytest.skip(f"cannot bind the simulated site on {NET}.x: {e}")
    import sim_site
    site = sim_site.Site(quiet=True, network=NET, bacnet_only=True).start()
    try:
        logs = []
        result = ScanEngine(ScanOptions(
            networks=[f"{NET}.2-7"], timeout=1.5, scan_modbus=False, scan_services=False,
            scan_snmp=False, scan_p2=False, scan_knx=False), callback=logs.append).run()
    finally:
        site.close()
    return result, logs


def _by_instance(result):
    return {d['instance']: d for d in result.devices if d.get('instance') is not None}


def test_notification_classes_are_read(site_scan):
    result, logs = site_scan
    classes = {n['name']: n for n in _by_instance(result)[1001]['notification_classes']}
    critical = classes["Critical alarms"]
    assert critical['priority'] == {'to-offnormal': 64, 'to-fault': 64, 'to-normal': 200}
    assert critical['ack_required'] == ['to-offnormal', 'to-fault']
    assert [r.get('device') for r in critical['recipients']] == [1100, 9001, None]
    assert critical['recipients'][2]['address'] == "10.20.30.40:47808"
    assert classes["Maintenance"]['recipients'] == []
    assert any("2 notification class(es) (1 with no recipients)" in line for line in logs)


def test_alarm_routing_findings(site_scan):
    from hvac_scanner.report import build_findings, render_html
    result, _ = site_scan
    scan = result.to_dict()
    by_title = {f.title: f for f in build_findings(scan)}
    assert by_title["Notification classes with no recipients"].rows[0][3] == "Maintenance"
    missing = by_title["Alarm recipients this scan did not find"].rows
    assert [r[4] for r in missing] == ["device 9001"]       # 1100 answered the scan
    page = render_html(scan)
    assert "<h2>Alarm routing</h2>" in page and "device 9001, Mon–Fri, 07:00–18:00" in page


def test_router_routing_tables_are_read(site_scan):
    result, _ = site_scan
    ip_port = next(p for p in _by_instance(result)[3000]['network_ports'] if p['type'] == 'IPv4')
    assert ip_port['routes'] == [{'network': 9, 'via': '127.0.9.5:47808', 'status': 'available'}]


@pytest.fixture
def remote_building():
    import sim_site
    ip, dev, mstp, bbmd = sim_site.build_remote_building(REMOTE, f"{NET}.5")
    try:
        ep = sim_site.BACnetEndpoint(ip, dev, mstp, bbmd=bbmd, remote=True)
    except OSError as e:
        pytest.skip(f"cannot bind {ip}: {e}")
    yield ep
    ep.close()


def test_routing_table_networks_are_asked_through_the_router(remote_building):
    """Network 5 is in the remote router's routing table, not on its ports:
    it is behind another router. A Who-Is routed to this router reaches it
    too, so it is asked; not known to be MS/TP, it is not address-probed."""
    logs = []
    ScanEngine(ScanOptions(networks=[f"{REMOTE}.5"], timeout=1.5, unicast_discovery="always",
                           mstp_mac_probe=True, scan_modbus=False, scan_services=False,
                           scan_snmp=False, scan_p2=False, scan_knx=False),
               callback=logs.append).run()
    assert any(f"Router {REMOTE}.5: routed Who-Is to network(s) 5, 9" in line for line in logs)
    assert any("Network 5 via" in line and "not known to be MS/TP" in line for line in logs)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def test_gui_lists_alarm_routing(gui_app):
    dev = {'ip': '10.0.0.5', 'instance': 5, 'protocol': 'BACnet/IP', 'max_apdu': 1476,
           'objects': [{'type': 'Analog Input', 'instance': 1}],
           'notification_classes': [
               {'instance': 1, 'name': 'Critical', 'number': 1,
                'priority': {'to-offnormal': 64, 'to-fault': 64, 'to-normal': 200},
                'ack_required': ['to-offnormal'],
                'recipients': [{'device': 1100, 'days': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri',
                                                         'Sat', 'Sun'],
                                'from': '00:00', 'to': '23:59',
                                'transitions': ['to-offnormal', 'to-fault', 'to-normal']}]},
               {'instance': 2, 'name': 'Nobody', 'number': 2, 'recipients': []}],
           'network_ports': [{'instance': 1, 'name': 'BACnet/IP', 'type': 'IPv4', 'network': 1,
                              'routes': [{'network': 9, 'via': '10.0.4.5:47808',
                                          'status': 'available'}]}]}
    gui_app._add_meta_for(dev)
    rows = [gui_app.meta_tree.item(i, 'values') for i in gui_app._rows['meta']]
    assert [r[1] for r in rows] == ["Notification Class", "Notification Class"]
    assert rows[0][4] == "device 1100" and rows[0][5] == "priority 64 / 64 / 200"
    assert rows[1][7] == "no recipients"
    assert gui_app.notebook.tab(2, 'text') == "Trends, Schedules & Alarms"
    lines = {k: v for kind, k, v in gui_app._detail_lines(dev) if kind == 'kv'}
    assert lines['Alarm classes'] == "2 (1 with no recipients)"
    assert "routes to network 9 via 10.0.4.5:47808 (available)" in lines['BACnet/IP']
