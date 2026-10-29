"""Regression tests for the v2.7 review fixes and additions."""

import json
import socket
import struct
import threading
import time

import pytest

from hvac_scanner import codec
from hvac_scanner.constants import BACNET_OBJ_TYPES, BACNET_UNITS, POINT_PROPERTIES_BY_TYPE


# ---------------------------------------------------------------------------
# Reference tables
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("enum,label", [
    (29, "%RH"), (19, "kWh"), (48, "kW"), (47, "W"), (58, "inH2O"), (56, "psi"),
    (89, "gpm"), (96, "ppm"), (84, "CFM"), (62, "°C"), (64, "°F"), (98, "%"),
    (53, "Pa"), (54, "kPa"), (104, "RPM"), (27, "Hz"), (118, "cm"), (117, "BTU/lb"),
    (95, ""),
])
def test_engineering_units_match_the_standard(enum, label):
    """Most of the old table was wrong — humidity showed as W, kWh as kPa."""
    assert BACNET_UNITS[enum] == label


@pytest.mark.parametrize("enum,name", [
    (45, "Integer Value"), (46, "Large Analog Value"), (40, "CharacterString Value"),
    (48, "Positive Integer Value"), (54, "Lighting Output"),
    (55, "Binary Lighting Output"), (56, "Network Port"), (57, "Elevator Group"),
])
def test_object_types_match_the_standard(enum, name):
    assert BACNET_OBJ_TYPES[enum] == name


def test_every_per_type_property_list_names_a_real_object_type():
    assert set(POINT_PROPERTIES_BY_TYPE) <= set(BACNET_OBJ_TYPES.values())


# ---------------------------------------------------------------------------
# BBMD-relayed packets carry the originating device's address
# ---------------------------------------------------------------------------

def _forwarded(origin_ip: str, origin_port: int, npdu_apdu: bytes) -> bytes:
    body = socket.inet_aton(origin_ip) + struct.pack('!H', origin_port) + npdu_apdu
    return codec.build_bvlc(codec.BVLC_FORWARDED_NPDU, body)


_IAM_APDU = bytes([0x10, 0x00, 0xC4, 0x02, 0x00, 0x03, 0xE9,   # device 1001
                   0x22, 0x05, 0xC4, 0x91, 0x03, 0x21, 0x02])


def test_forwarded_iam_is_attributed_to_its_origin():
    pkt = _forwarded("10.20.30.40", 47808, b'\x01\x00' + _IAM_APDU)
    dev = codec.parse_iam(pkt, ("192.168.1.250", 47808))      # the BBMD
    assert dev is not None
    assert dev.ip == "10.20.30.40"
    assert dev.instance == 1001


def test_plain_iam_still_uses_the_datagram_source():
    pkt = codec.build_bvlc(0x0B, b'\x01\x00' + _IAM_APDU)
    assert codec.parse_iam(pkt, ("10.0.0.9", 47808)).ip == "10.0.0.9"


def test_forwarded_origin_and_router_announcement():
    pkt = _forwarded("10.20.30.5", 47808, bytes([0x01, 0x80, 0x01, 0x00, 0x05]))
    assert codec.forwarded_origin(pkt) == ("10.20.30.5", 47808)
    assert codec.parse_iam_router(pkt) == [5]
    assert codec.forwarded_origin(codec.build_whois()) is None


def test_unspecified_date_and_time_fields():
    assert codec._parse_app_value(bytes([0xA4, 255, 255, 1, 255]), 0)[0] == "*-*-01"
    assert codec._parse_app_value(bytes([0xB4, 255, 255, 255, 255]), 0)[0] == "*:*:*"


# ---------------------------------------------------------------------------
# BACnetClient: several requests in flight at once
# ---------------------------------------------------------------------------

def test_concurrent_requests_to_different_devices_each_get_their_own_reply():
    """Two devices behind the one socket, read from two threads at once.
    Every reply must land with the request that asked for it."""
    from hvac_scanner.bacnet import BACnetClient
    from .mock_device import MockBACnetDevice

    a = MockBACnetDevice(instance=111, n_objects=40, host='127.0.0.1')
    try:
        b = MockBACnetDevice(instance=222, n_objects=60, host='127.0.0.2', patch_port=False)
        b._sock.close()
        b._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b._sock.bind(('127.0.0.2', a.port))       # same port, different address
        b.port = a.port
    except OSError as e:
        pytest.skip(f"no second loopback address: {e}")

    with a, b:
        client = BACnetClient(timeout=2.0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("", 0))
        client._sock = s
        results: dict[str, list] = {'127.0.0.1': [], '127.0.0.2': []}

        def hammer(ip: str, n: int) -> None:
            for i in range(1, n + 1):
                results[ip].append(client.read_property(ip, 'Device', 4194303,
                                                        'objectList', array_index=i))
        threads = [threading.Thread(target=hammer, args=('127.0.0.1', 40)),
                   threading.Thread(target=hammer, args=('127.0.0.2', 60))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        client.close()

    assert results['127.0.0.1'] == [tuple(o) for o in a.objects]
    assert results['127.0.0.2'] == [tuple(o) for o in b.objects]


def test_invoke_ids_are_per_device():
    from hvac_scanner.bacnet import BACnetClient
    c = BACnetClient()
    assert [c._next_invoke_id('10.0.0.1') for _ in range(3)] == [1, 2, 3]
    assert c._next_invoke_id('10.0.0.2') == 1


# ---------------------------------------------------------------------------
# Modbus
# ---------------------------------------------------------------------------

class _ModbusServer:
    """Answers FC43 / FC3 per unit, counting connections."""

    def __init__(self, units: dict, any_unit: bool = False):
        self.units, self.any_unit = units, any_unit
        self.connections = 0
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(('127.0.0.1', 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        with conn:
            while True:
                hdr = conn.recv(7)
                if len(hdr) < 7:
                    return
                pdu = conn.recv(struct.unpack('!H', hdr[4:6])[0] - 1)
                uid, fc = hdr[6], pdu[0]
                unit = self.units.get(uid) or (next(iter(self.units.values()))
                                               if self.any_unit else None)
                if unit is None:
                    reply = bytes([fc | 0x80, 0x0B])      # gateway: no device
                elif fc == 0x2B:
                    v = unit.encode()
                    reply = bytes([0x2B, 0x0E, 1, 1, 0, 0, 1, 0, len(v)]) + v
                else:
                    reply = bytes([fc, 2, 0, 42])
                conn.sendall(hdr[:4] + struct.pack('!H', len(reply) + 1) + bytes([uid]) + reply)

    def close(self):
        self.srv.close()


def test_gateway_no_device_exception_is_not_a_device():
    from hvac_scanner.modbus import ModbusScanner
    srv = _ModbusServer({1: "Meter"})
    try:
        found = ModbusScanner(timeout=1.0).scan_host('127.0.0.1', srv.port)
    finally:
        srv.close()
    assert [d['unit_id'] for d in found] == [1]


def test_a_device_answering_every_unit_id_is_reported_once():
    from hvac_scanner.modbus import ModbusScanner
    srv = _ModbusServer({1: "Meter"}, any_unit=True)
    try:
        found = ModbusScanner(timeout=1.0).scan_host('127.0.0.1', srv.port)
    finally:
        srv.close()
    assert len(found) == 1
    assert found[0]['answers_any_unit'] is True
    assert found[0]['vendor'] == "Meter"


def test_unit_probes_share_one_connection():
    from hvac_scanner.modbus import ModbusScanner
    srv = _ModbusServer({1: "A", 2: "B"})
    try:
        ModbusScanner(timeout=1.0).scan_host('127.0.0.1', srv.port)
    finally:
        srv.close()
    assert srv.connections == 1


# ---------------------------------------------------------------------------
# TCP sweep and SNMP fan-out
# ---------------------------------------------------------------------------

def test_tcp_sweep_reports_only_open_ports():
    from hvac_scanner.netsweep import tcp_sweep
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    open_port = srv.getsockname()[1]
    closed = socket.socket()
    closed.bind(('127.0.0.1', 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        found = tcp_sweep([('127.0.0.1', open_port), ('127.0.0.1', closed_port)],
                          timeout=3.0, concurrency=4)
    finally:
        srv.close()
    assert found == [('127.0.0.1', open_port)]


def test_tcp_sweep_honours_stop():
    from hvac_scanner.netsweep import tcp_sweep
    stop = threading.Event()
    stop.set()
    assert tcp_sweep((('127.0.0.1', p) for p in range(1, 1000)),
                     timeout=1.0, stop_event=stop) == []


def test_snmp_fan_out_tries_communities_in_turn(monkeypatch):
    from hvac_scanner.snmp import SNMPScanner
    agent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    agent.bind(('127.0.0.1', 0))
    port = agent.getsockname()[1]
    seen = []

    def serve():
        agent.settimeout(5)
        try:
            while True:
                data, addr = agent.recvfrom(4096)
                seen.append(data)
                if b'secret' not in data:
                    continue          # wrong community: agents stay silent
                descr = b"Test controller"
                vb = (bytes([0x30, 10 + len(descr) + 2, 0x06, 0x08, 0x2B, 6, 1, 2, 1, 1, 1, 0,
                             0x04, len(descr)]) + descr)
                agent.sendto(bytes([0x30, len(vb) + 2]) + bytes([0x30, len(vb)]) + vb, addr)
        except OSError:
            return
    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(SNMPScanner, "PORT", port)
    try:
        found = SNMPScanner(timeout=1.0).scan_network(
            "127.0.0.1", communities=["public", "secret"])
    finally:
        agent.close()
    assert len(seen) == 2
    assert found and found[0]['sys_descr'] == "Test controller"
    assert found[0]['community'] == "secret"


# ---------------------------------------------------------------------------
# Engine and exports
# ---------------------------------------------------------------------------

def test_engine_messages_are_not_logged_at_info(caplog):
    """The CLI prints the callback and configures logging at INFO; logging
    engine messages at INFO as well printed every line twice."""
    from hvac_scanner.engine import ScanEngine, ScanOptions
    caplog.set_level("INFO", logger="hvac_scanner")
    ScanEngine(ScanOptions(networks=["127.0.0.1"], scan_bacnet=False, scan_mstp=False,
                           scan_modbus=False, scan_services=False, scan_snmp=False,
                           scan_p2=False),
               callback=lambda m: None).run()
    assert not [r for r in caplog.records if r.name == "hvac_scanner.engine"]


def test_points_csv_lists_every_point_and_register(tmp_path):
    import csv
    from hvac_scanner.engine import ScanResult
    r = ScanResult()
    r.devices = [
        {'ip': '10.0.0.2', 'instance': 1, 'protocol': 'BACnet/IP',
         'properties': {'object_name': 'AHU-1'},
         'objects': [{'type': 'Analog Input', 'instance': 1, 'name': 'SA-T',
                      'present_value': '55', 'units': '°F', 'description': 'Supply'}]},
        {'ip': '10.0.0.9', 'unit_id': 1, 'protocol': 'Modbus TCP', 'port': 502,
         'holding_registers': [{'register': 0, 'value': 7, 'hex': '0x0007'}],
         'input_registers': [], 'coils': [{'coil': 0, 'value': 1, 'state': 'ON'}]},
    ]
    out = tmp_path / "points.csv"
    r.write_points_csv(str(out))
    rows = list(csv.reader(out.open(encoding='utf-8-sig')))
    assert rows[0][0] == 'Device IP'
    assert rows[1][2] == 'AHU-1' and rows[1][7] == 'SA-T' and rows[1][9] == '°F'
    assert [row[5] for row in rows[2:]] == ['Holding Register', 'Coil']


def test_unicast_auto_skips_subnets_the_broadcast_reached():
    from hvac_scanner.engine import ScanEngine, ScanOptions

    class Client:
        probed = None

        def discover_unicast(self, ips, stop_fn=None):
            Client.probed = list(ips)
            return []

    eng = ScanEngine(ScanOptions(networks=["10.9.8.1-3", "10.9.9.1-2"]),
                     callback=lambda m: None)
    eng._is_local = lambda ip: False                 # every target is routed
    eng._discover_unicast(Client(), set(eng._target_ips_in_order()),
                          {("10.9.8.1", 5)})
    assert Client.probed == ["10.9.9.1", "10.9.9.2"]


def test_cli_rejects_a_bad_target_with_exit_1(capsys):
    from hvac_scanner import cli
    assert cli.main(["10.0.0.0/33"]) == 1
    assert "invalid target" in capsys.readouterr().err


def test_cli_version(capsys):
    from hvac_scanner import __version__, cli
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert __version__ in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Settings and icon
# ---------------------------------------------------------------------------

def test_settings_round_trip_and_tolerate_damage(tmp_path):
    from hvac_scanner import settings
    path = tmp_path / "sub" / "settings.json"
    settings.save(path, {'targets': '10.0.0.0/24'})
    assert settings.load(path) == {'targets': '10.0.0.0/24'}
    path.write_text("{not json", encoding='utf-8')
    assert settings.load(path) == {}
    assert settings.load(tmp_path / "missing.json") == {}
    assert settings.load(None) == {}


def test_icon_renders_as_png_and_ico():
    from hvac_scanner import icon
    png = icon.png_bytes(16)
    assert png.startswith(b'\x89PNG\r\n\x1a\n')
    ico = icon.ico_bytes((16, 32))
    assert ico[:4] == b'\x00\x00\x01\x00' and struct.unpack('<H', ico[4:6])[0] == 2


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def _dev(ip, inst, name, points=2, protocol='BACnet/IP'):
    return {'ip': ip, 'instance': inst, 'protocol': protocol, 'vendor_name': 'V',
            'properties': {'object_name': name},
            'objects': [{'type': 'Analog Input', 'instance': i, 'name': f'{name}-P{i}',
                         'present_value': '1', 'units': '°F', 'description': ''}
                        for i in range(points)],
            '_fingerprint': {'default_creds': 'admin / admin'}}


def test_filter_hides_and_restores_rows(gui_app):
    gui_app._stream_device(_dev('10.0.0.2', 1, 'AHU-1'))
    gui_app._stream_device(_dev('10.0.0.3', 2, 'VAV-7', points=3))
    gui_app.filter_var.set('vav-7')
    gui_app._apply_filter()
    assert len(gui_app.device_tree.get_children()) == 1
    assert len(gui_app.points_tree.get_children()) == 3
    gui_app.filter_var.set('')
    gui_app._apply_filter()
    assert len(gui_app.device_tree.get_children()) == 2
    assert len(gui_app.points_tree.get_children()) == 5


def test_rows_streamed_while_filtered_respect_the_filter(gui_app):
    gui_app.filter_var.set('ahu')
    gui_app._apply_filter()
    gui_app._stream_device(_dev('10.0.0.3', 2, 'VAV-7'))
    assert len(gui_app.device_tree.get_children()) == 0
    gui_app.filter_var.set('')
    gui_app._apply_filter()
    assert len(gui_app.device_tree.get_children()) == 1


def test_sorting_ip_column_is_numeric(gui_app):
    for ip in ('10.0.0.20', '10.0.0.3', '10.0.0.100'):
        gui_app._stream_device(_dev(ip, int(ip.split('.')[-1]), f'D{ip}'))
    gui_app._sort_treeview(gui_app.device_tree, 'ip')
    ips = [gui_app.device_tree.set(i, 'ip') for i in gui_app.device_tree.get_children()]
    assert ips == ['10.0.0.3', '10.0.0.20', '10.0.0.100']


def test_details_panel_shows_the_selected_device(gui_app):
    gui_app._stream_device(_dev('10.0.0.2', 1, 'AHU-1'))
    iid = gui_app.device_tree.get_children()[0]
    gui_app.device_tree.selection_set(iid)
    gui_app._show_selected_details()
    text = gui_app.details_text.get("1.0", "end")
    assert "AHU-1" in text and "admin / admin" in text


def test_modbus_rows_open_details_too(gui_app):
    """Details were looked up by the row's text, and a Modbus row's 'Unit 1'
    never matched, so double-clicking one did nothing."""
    dev = {'ip': '10.0.0.9', 'port': 502, 'unit_id': 1, 'protocol': 'Modbus TCP',
           'vendor': 'Acme', 'objects': [], 'properties': {}, '_fingerprint': {},
           'holding_registers': [], 'input_registers': [], 'coils': []}
    gui_app._stream_device(dev)
    gui_app.device_tree.selection_set(gui_app.device_tree.get_children()[0])
    assert gui_app._selected_device() is dev


def test_point_popup_opens(gui_app):
    """Double-clicking a point raised AttributeError (Colors.TEXT_PRIMARY)."""
    import tkinter as tk
    gui_app._stream_device(_dev('10.0.0.2', 1, 'AHU-1'))
    gui_app.points_tree.selection_set(gui_app.points_tree.get_children()[0])
    gui_app._on_point_double_click(None)
    tops = [w for w in gui_app.root.winfo_children() if isinstance(w, tk.Toplevel)]
    assert tops
    for t in tops:
        t.destroy()


def test_bad_bbmd_address_blocks_the_scan(gui_app):
    gui_app.network_entry.delete(0, 'end')
    gui_app.network_entry.insert(0, '10.0.0.0/24')
    gui_app.adv_vars['bbmd'].set('not-an-ip')
    assert gui_app._build_options() is None
    gui_app.adv_vars['bbmd'].set('10.0.0.1')
    opts = gui_app._build_options()
    assert opts is not None and opts.bbmd == '10.0.0.1'


def test_gui_settings_round_trip(gui_app):
    gui_app.network_entry.delete(0, 'end')
    gui_app.network_entry.insert(0, '172.16.5.0/24')
    gui_app.scan_services.set(True)
    gui_app.adv_vars['rate_limit'].set('75')
    data = json.loads(json.dumps(gui_app._collect_settings()))
    gui_app.network_entry.delete(0, 'end')
    gui_app.scan_services.set(False)
    gui_app.adv_vars['rate_limit'].set('0')
    gui_app._apply_settings(data)
    assert gui_app.network_entry.get() == '172.16.5.0/24'
    assert gui_app.scan_services.get() is True
    assert gui_app.rate_limit_entry.get() == '75'


def test_scan_runs_through_the_queue_to_completion(gui_app):
    """Press Scan with nothing selected and let the worker finish: the result
    must arrive through the queue and re-enable the buttons."""
    gui_app.network_entry.delete(0, 'end')
    gui_app.network_entry.insert(0, '127.0.0.1')
    for var in (gui_app.scan_bacnet, gui_app.scan_mstp, gui_app.scan_modbus,
                gui_app.scan_services, gui_app.scan_snmp, gui_app.scan_p2):
        var.set(False)
    gui_app.scan_btn.invoke()
    deadline = time.time() + 20
    while gui_app.scan_running and time.time() < deadline:
        gui_app.root.update()
        time.sleep(0.02)
    assert not gui_app.scan_running
    assert gui_app.result is not None
    assert str(gui_app.scan_btn['state']) == 'normal'
    assert 'complete' in gui_app.status_var.get().lower()


# ---------------------------------------------------------------------------
# Point status and multi-state text
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,flags", [
    ("0400", []),
    ("0480", ["in-alarm"]),
    ("0440", ["fault"]),
    ("0430", ["overridden", "out-of-service"]),
    ("04f0", ["in-alarm", "fault", "overridden", "out-of-service"]),
    ("04", []), ("zz", []), (None, []), (7, []),
])
def test_status_flags_decode(raw, flags):
    from hvac_scanner.engine import _status_flags
    assert _status_flags(raw) == flags


def test_state_text_validation():
    from hvac_scanner.bacnet import _validate_point_property as v
    assert v('stateText', ['Off', 'On']) == ['Off', 'On']
    assert v('stateText', 'Only') == ['Only']          # one-element array
    assert v('stateText', [1, 2]) is None
    assert v('stateText', []) is None


def test_flagged_points_are_highlighted_and_counted(gui_app):
    dev = _dev('10.0.0.2', 1, 'AHU-1', points=3)
    dev['objects'][0]['status'] = 'in-alarm'
    dev['objects'][1]['status'] = 'overridden'
    gui_app._stream_device(dev)
    rows = gui_app.points_tree.get_children()
    assert 'alarm' in gui_app.points_tree.item(rows[0], 'tags')
    assert 'flag' in gui_app.points_tree.item(rows[1], 'tags')
    assert gui_app.points_tree.set(rows[0], 'status') == 'in-alarm'
    assert gui_app.chips['flagged'].cget('text').endswith('2')
    # highlighting survives filtering
    gui_app.filter_var.set('ahu')
    gui_app._apply_filter()
    assert 'alarm' in gui_app.points_tree.item(rows[0], 'tags')


# ---------------------------------------------------------------------------
# HTML survey report
# ---------------------------------------------------------------------------

def _survey_scan():
    return {
        'scan_time': '2026-10-29T10:00:00', 'elapsed_seconds': 12.3,
        'scanner': 'HVAC Network Scanner v2.7.0', 'targets': ['10.0.0.0/24'],
        'counts': {'bacnet': 1, 'mstp': 0, 'modbus': 1, 'services': 4, 'snmp': 1, 'points': 2},
        'devices': [
            {'protocol': 'BACnet/IP', 'ip': '10.0.0.2', 'instance': 1001,
             'properties': {'object_name': 'SC-1 <script>alert(1)</script>',
                            'model_name': 'Tracer SC+'},
             'default_creds': 'admin / Tracer1$', 'web_url': 'https://10.0.0.2',
             'objects': [{'type': 'Binary Input', 'instance': 5, 'name': 'FRZ',
                          'present_value': 'active', 'units': '', 'status': 'in-alarm'},
                         {'type': 'Analog Output', 'instance': 3, 'name': 'VLV',
                          'present_value': '40', 'units': '%', 'status': 'overridden'}],
             'point_flags': {'in-alarm': 1, 'overridden': 1}},
            {'protocol': 'BACnet/IP', 'ip': '10.0.0.9', 'instance': 7,
             'default_creds': 'admin / (set at install)', 'web_url': 'http://10.0.0.9',
             'objects': []},
            {'protocol': 'Modbus TCP', 'ip': '10.0.0.20', 'unit_id': 1, 'vendor': 'Acme'},
            {'protocol': 'SNMP', 'ip': '10.0.0.30', 'sys_descr': 'JACE', 'community': 'public'},
            {'protocol': 'Service', 'ip': '10.0.0.2', 'port': 443, 'service': 'HTTPS',
             'tls': {'subject_cn': 'SC-1', 'not_after': '2020-01-01T00:00:00+00:00'}},
            {'protocol': 'Service', 'ip': '10.0.0.2', 'port': 80, 'service': 'HTTP'},
            {'protocol': 'Service', 'ip': '10.0.0.40', 'port': 23, 'service': 'Telnet'},
            {'protocol': 'Service', 'ip': '10.0.0.9', 'port': 80, 'service': 'HTTP'},
        ],
    }


def test_report_findings_cover_the_survey():
    from hvac_scanner.report import build_findings
    findings = {f.title: f for f in build_findings(_survey_scan())}
    creds = findings['Products with published default credentials and a reachable login']
    assert [r[0] for r in creds.rows] == ['10.0.0.2']        # "(set at install)" is not a password
    assert creds.severity == 'high'
    clear = findings['Management interfaces without encryption']
    assert ['10.0.0.9', 'HTTP only (TCP 80)'] == clear.rows[0][:2]
    assert any(r[0] == '10.0.0.40' and 'Telnet' in r[1] for r in clear.rows)
    assert not any(r[0] == '10.0.0.2' for r in clear.rows)     # has HTTPS too
    assert 'SNMP answering a default community string' in findings
    assert findings['Expired TLS certificates'].rows[0][0] == '10.0.0.2'
    assert findings['Points in alarm or fault'].rows[0][3] == 'FRZ'
    assert findings['Points overridden or out of service'].rows[0][3] == 'VLV'
    assert 'Modbus TCP devices' in findings
    severities = [f.severity for f in build_findings(_survey_scan())]
    assert severities == sorted(severities, key=['high', 'medium', 'low', 'info'].index)


def test_report_html_escapes_device_data():
    from hvac_scanner.report import render_html
    page = render_html(_survey_scan())
    assert '<script>alert(1)</script>' not in page
    assert '&lt;script&gt;' in page
    assert '<script' not in page.lower().replace('&lt;script', '')


def test_report_from_saved_json(tmp_path):
    from hvac_scanner import report
    src = tmp_path / 'scan.json'
    src.write_text(json.dumps(_survey_scan()), encoding='utf-8')
    assert report.main([str(src)]) == 0
    out = (tmp_path / 'scan.html').read_text(encoding='utf-8')
    assert 'Building automation network survey' in out and '10.0.0.0/24' in out
    bad = tmp_path / 'bad.json'
    bad.write_text('{"nope": 1}', encoding='utf-8')
    assert report.main([str(bad)]) == 1


def test_scan_result_records_its_targets():
    from hvac_scanner.engine import ScanEngine, ScanOptions
    r = ScanEngine(ScanOptions(networks=['127.0.0.1'], scan_bacnet=False, scan_mstp=False,
                               scan_modbus=False, scan_services=False, scan_snmp=False,
                               scan_p2=False),
                   callback=lambda m: None).run()
    assert r.to_dict()['targets'] == ['127.0.0.1']


# ---------------------------------------------------------------------------
# Siemens APOGEE P2 detection
# ---------------------------------------------------------------------------

def test_p2_probe_frame_follows_the_wire_rules():
    from hvac_scanner import p2
    frame = p2.build_probe(seq=7, now=0x6A000000)
    total, msg_type, seq = struct.unpack('>III', frame[:12])
    assert total == len(frame)                         # self-inclusive length
    assert seq == 7 and frame[12] == 0x00              # request direction
    slots = frame[13:].split(b'\x00')[:4]
    assert [s.decode() for s in slots] == [p2.PROBE_BLN, p2.PROBE_NODE,
                                          p2.PROBE_BLN, p2.PROBE_IDENTITY]
    slot_bytes = sum(len(s) + 1 for s in slots)
    assert msg_type == 13 + slot_bytes                 # a header length
    op_at = 13 + slot_bytes
    assert struct.unpack('>H', frame[op_at:op_at + 2])[0] == 0x4640
    body = frame[op_at + 2:]
    names = (p2.PROBE_IDENTITY, p2.PROBE_SITE, p2.PROBE_BLN)
    assert len(body) == 25 + sum(len(n) for n in names)   # 3 TLV headers + 16-byte tail
    assert body[-16:-11] == b'\x00\x01\x01\x00\x00'
    assert struct.unpack('>I', body[-7:-3])[0] == 0x6A000000


def test_p2_probe_name_is_a_legal_bln_name():
    from hvac_scanner import p2
    assert p2.PROBE_BLN.isalnum() and len(p2.PROBE_BLN) <= 30


@pytest.fixture
def p2_nodes():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import sim_site
    nodes = []
    try:
        nodes.append(sim_site.P2Node('127.0.1.43', 'SIMBLN', 'PXC43'))
        nodes.append(sim_site.P2Node('127.0.1.44', 'SIMBLN', 'INSIGHT', supervisor=True))
    except OSError as e:
        for n in nodes:
            n.close()
        pytest.skip(f"cannot bind simulated P2 nodes: {e}")
    yield nodes
    for n in nodes:
        n.close()


def test_p2_panel_and_supervisor_are_told_apart(p2_nodes):
    from hvac_scanner.p2 import P2Scanner
    found = P2Scanner(timeout=2.0).scan_network('127.0.1.42-45')
    roles = {d['ip']: d['p2_role'] for d in found}
    assert roles == {'127.0.1.43': 'field panel', '127.0.1.44': 'supervisor listener'}
    assert all(d['protocol'] == 'APOGEE P2' for d in found)


def test_p2_probe_is_one_attempt_with_one_fixed_name(p2_nodes):
    """Not enumeration: each node sees a single attempt, always the same name,
    and never its own BLN — so nothing is registered on it."""
    from hvac_scanner import p2
    from hvac_scanner.p2 import P2Scanner
    P2Scanner(timeout=2.0).scan_network('127.0.1.43-44')
    P2Scanner(timeout=2.0).scan_network('127.0.1.43-44')
    for node in p2_nodes:
        assert node.attempts == [p2.PROBE_BLN, p2.PROBE_BLN]


def test_an_open_port_that_is_not_p2_is_not_reported():
    from hvac_scanner.p2 import probe
    srv = socket.socket()
    try:
        srv.bind(('127.0.1.46', 0))
    except OSError as e:
        pytest.skip(str(e))
    srv.listen(1)
    port = srv.getsockname()[1]

    def answer():
        conn, _ = srv.accept()
        conn.recv(256)
        conn.sendall(b'HTTP/1.0 400 Bad Request\r\n\r\n')
        conn.close()
    threading.Thread(target=answer, daemon=True).start()
    try:
        assert probe('127.0.1.46', port, timeout=2.0) is None
    finally:
        srv.close()


def test_p2_devices_are_fingerprinted_and_reported():
    from hvac_scanner.fingerprint import fingerprint_device
    from hvac_scanner.report import build_findings
    dev = {'protocol': 'APOGEE P2', 'ip': '10.0.0.5', 'port': 5033,
           'p2_role': 'field panel', 'p2_evidence': 'reset'}
    fp = fingerprint_device(dev, [])
    assert fp['model'] == 'Siemens APOGEE field panel (P2)'
    assert 'BACnet/IP' in fp['description']
    titles = [f.title for f in build_findings({'devices': [dev]})]
    assert 'Siemens APOGEE P2 nodes' in titles
