"""2.16: fixes from the 2026-11-21 review. Loopback only."""
import json
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from hvac_scanner import bacnet, diff as D
from hvac_scanner.engine import ScanEngine, ScanOptions, ScanResult, write_json_atomic

from .mock_device import MockBACnetDevice


@pytest.fixture
def mock_client(monkeypatch):
    def _open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        s.bind(("127.0.0.1", 0))
        self._sock, self._bound_port = s, s.getsockname()[1]
        return self._bound_port
    monkeypatch.setattr(bacnet.BACnetClient, "open", _open)
    made = []

    def _make(timeout=0.3):
        c = bacnet.BACnetClient(timeout=timeout)
        c.open()
        made.append(c)
        return c
    yield _make
    for c in made:
        c.close()


# -- 1. the time limit keeps what was read ---------------------------------------

def test_points_read_before_the_time_limit_are_kept(mock_client):
    """A controller answering every request 80 ms late hits a 1.5 s limit
    part way through its points. Until 2.16 it was filed with none."""
    eng = ScanEngine(ScanOptions(networks=["127.0.0.1"], timeout=0.5, device_time_limit=1.5,
                                 read_metadata=False), callback=lambda _m: None)
    with MockBACnetDevice(n_objects=300, rpm_mode='full', delay=0.08) as dev:
        d = {'ip': '127.0.0.1', 'instance': dev.instance, 'protocol': 'BACnet/IP',
             'max_apdu': 1476}
        eng._deep_read(mock_client(timeout=0.5), d)
    assert "per-device time limit" in d.get('cut_short', '')
    points = d['objects']
    assert 0 < len(points) < 300, len(points)
    assert all(p['name'] for p in points)                   # read ones only
    assert 'object_list' not in d['properties']              # the duplicate is gone


# -- 2. a pass that did not run ------------------------------------------------------

def _bacnet(ip, inst):
    return {'ip': ip, 'instance': inst, 'protocol': 'BACnet/IP',
            'properties': {'object_name': f'D{inst}'}}


def test_devices_of_a_skipped_pass_are_not_compared_not_gone():
    base = {'devices': [_bacnet('192.0.2.5', 5), _bacnet('192.0.2.6', 6),
                        {'ip': '192.0.2.20', 'port': 502, 'unit_id': 1,
                         'protocol': 'Modbus TCP'}]}
    cur = {'devices': [], 'coverage': {'passes': {
        'bacnet': 'skipped: the BBMD did not answer', 'modbus': 'scanned'}}}
    d = D.diff_scans(base, cur)
    assert [x['ip'] for x in d.removed] == ['192.0.2.20']      # Modbus ran: it is gone
    assert list(d.not_compared) == ['BACnet skipped: the BBMD did not answer']
    assert len(d.not_compared['BACnet skipped: the BBMD did not answer']) == 2
    text = D.format_text(d)
    assert "NOT RESPONDING (1)" in text and "NOT COMPARED (2)" in text
    assert "2 not compared" in text
    assert d.to_dict()['summary']['not_compared'] == 2


def test_an_export_without_coverage_compares_everything():
    d = D.diff_scans({'devices': [_bacnet('192.0.2.5', 5)]}, {'devices': []})
    assert len(d.removed) == 1 and not d.not_compared


@pytest.fixture
def scanned(monkeypatch):
    from hvac_scanner import cli

    def use(passes, devices=()):
        class Engine:
            def __init__(self, opts, callback=None, stop_event=None):
                pass

            def run(self):
                r = ScanResult()
                r.passes = dict(passes)
                r.devices = [dict(x) for x in devices]
                return r
        monkeypatch.setattr(cli, "ScanEngine", Engine)
    return use


def test_a_partial_scan_exits_five_and_says_why_even_when_quiet(tmp_path, scanned, capsys):
    from hvac_scanner.cli import main
    base = tmp_path / 'b.json'
    base.write_text(json.dumps({'devices': [_bacnet('192.0.2.5', 5)]}), encoding='utf-8')
    scanned({'bacnet': 'skipped: the BBMD did not answer'})
    rc = main(['192.0.2.0/30', '--quiet', '--print', 'none', '--baseline', str(base),
               '--fail-on-change', '--diff-output', str(tmp_path / 'd.txt')])
    assert rc == 5
    err = capsys.readouterr().err
    assert "partial" in err and "BACnet skipped: the BBMD did not answer" in err
    out = (tmp_path / 'd.txt').read_text(encoding='utf-8')
    assert "NOT COMPARED (1)" in out and "NOT RESPONDING" not in out


def test_a_complete_scan_still_exits_zero(scanned):
    from hvac_scanner.cli import main
    scanned({'bacnet': 'scanned', 'modbus': 'off'})
    assert main(['192.0.2.0/30', '--quiet', '--print', 'none']) == 0


def test_the_window_says_a_pass_was_skipped(gui_app):
    r = ScanResult()
    r.passes = {'bacnet': 'skipped: the BBMD did not answer', 'modbus': 'scanned'}
    gui_app.stop_event.clear()
    gui_app._scan_finished(r, None)
    status = gui_app.status_var.get()
    assert status.startswith("Finished — BACnet skipped") and "Scan complete" not in status


# -- 3. sorting and filtering from Python ------------------------------------------

def test_sorting_and_filtering_use_the_kept_values(gui_app):
    tree = gui_app.points_tree
    cols = list(tree["columns"])
    rows = [("D (192.0.2.10)", "Analog Input", "3", "ZN-T", "71.5", "°F", "", "x"),
            ("D (192.0.2.2)", "Analog Input", "1", "DA-T", "55.0", "°F", "fault", "y"),
            ("D (192.0.2.9)", "Binary Output", "2", "FAN", "active", "", "", "z")]
    for r in rows:
        gui_app._insert(tree, r[:len(cols)])
    gui_app._sort_treeview(tree, cols[3])                       # by name
    names = [tree.item(i, "values")[3] for i in tree.get_children()]
    assert names == ["DA-T", "FAN", "ZN-T"]
    tags = [tree.item(i, "tags") for i in tree.get_children()]
    assert ["alt" in t for t in tags] == [False, True, False]
    gui_app._filters[tree._hvac_name] = "fault"
    gui_app._apply_filter_to(tree)
    assert [tree.item(i, "values")[3] for i in tree.get_children()] == ["DA-T"]
    gui_app._filters[tree._hvac_name] = ""
    gui_app._apply_filter_to(tree)
    assert len(tree.get_children()) == 3
    # A row changed in place sorts by its new value.
    first = gui_app._rows[tree._hvac_name][0]
    gui_app._set_values(tree, first, ("D", "Analog Input", "3", "AAA", "", "", "", "")[:len(cols)])
    gui_app._sort_treeview(tree, cols[3])
    gui_app._sort_treeview(tree, cols[3])                       # twice: reversed, then back
    gui_app._sort_treeview(tree, cols[3])
    assert tree.item(tree.get_children()[0], "values")[3] in ("AAA", "ZN-T")


# -- 5, 6. the window on small and changed screens ---------------------------------

def test_the_advanced_fields_go_fewer_to_a_row_when_narrow(gui_app, monkeypatch):
    frame = gui_app.adv_frame
    monkeypatch.setattr(frame, "winfo_width", lambda: 2000)
    gui_app._reflow_advanced()
    assert gui_app._adv_layout[0] == 3
    monkeypatch.setattr(frame, "winfo_width", lambda: 700)
    gui_app._reflow_advanced()
    assert gui_app._adv_layout[0] in (1, 2)
    assert len(gui_app._adv_layout[1]) >= 2                      # the boxes wrapped
    info = gui_app.timeout_entry.grid_info()
    assert int(info["row"]) == 0


@pytest.mark.parametrize("geo,screen,want", [
    ("1500x900+40+20", (0, 0, 1920, 1080), "1500x900+40+20"),
    ("1500x900+3920+300", (0, 0, 1920, 1080), "1500x900"),     # the monitor is gone
    ("1500x900+-1800+100", (-1920, 0, 3840, 1080), "1500x900+-1800+100"),  # a left monitor
    ("1500x900+-1800+100", (0, 0, 1920, 1080), "1500x900"),
    ("2400x1400+0+0", (0, 0, 1366, 768), "1366x768+0+0"),       # shrunk to fit
    ("1500x900", (0, 0, 1920, 1080), "1500x900"),
    ("nonsense", (0, 0, 1920, 1080), None),
])
def test_a_saved_position_is_used_only_on_a_screen(geo, screen, want):
    from hvac_scanner.gui import _onscreen_geometry
    assert _onscreen_geometry(geo, screen) == want


# -- 8. a host on 502 that is not Modbus ---------------------------------------------

class _Port502:
    """A TCP listener on loopback that answers every Modbus request with
    `reply` (a function of the request), or never."""

    def __init__(self, reply=None):
        self.requests, self.reply = [], reply
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.srv.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        conn.settimeout(0.2)
        while not self.stop:
            try:
                head = conn.recv(7)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(head) < 7:
                return
            txn, _p, length, unit = struct.unpack('!HHHB', head)
            pdu = conn.recv(length - 1)
            self.requests.append(unit)
            if self.reply:
                out = self.reply(unit, pdu)
                conn.sendall(struct.pack('!HHHB', txn, 0, len(out) + 1, unit) + out)

    def close(self):
        self.stop = True
        self.srv.close()


def test_a_silent_host_on_502_is_left_after_three_unit_ids():
    from hvac_scanner.modbus import ModbusScanner
    port = _Port502()
    try:
        began = time.monotonic()
        found = ModbusScanner(timeout=0.3).scan_host("127.0.0.1", port.port)
        took = time.monotonic() - began
    finally:
        port.close()
    assert found == []
    assert port.requests == [1, 255, 247]
    assert took < 2.0, took


def test_a_gateway_that_says_no_device_is_still_asked_every_unit():
    """Exception 0x0B ("target failed to respond") is an answer: the gateway
    is there, and its other units are asked."""
    from hvac_scanner.modbus import ModbusScanner
    port = _Port502(reply=lambda unit, pdu: bytes([pdu[0] | 0x80, 0x0B]))
    try:
        ModbusScanner(timeout=0.3).scan_host("127.0.0.1", port.port)
    finally:
        port.close()
    assert sorted(set(port.requests)) == sorted(ModbusScanner.COMMON_UNIT_IDS)


# -- 9. the router-discovery wait ------------------------------------------------------

def test_router_discovery_waits_only_the_time_left(mock_client):
    """An unrelated datagram just before the end used to restart the full wait."""
    client = mock_client(timeout=0.6)
    noise = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_late():
        time.sleep(0.5)
        noise.sendto(b"not bacnet", ("127.0.0.1", client._bound_port))
    threading.Thread(target=send_late, daemon=True).start()
    began = time.monotonic()
    client.discover_routers(target_ip="127.0.0.1")
    took = time.monotonic() - began
    noise.close()
    assert took < 0.9, took


def test_a_discovery_wait_logs_its_last_answer(mock_client):
    lines = []
    client = mock_client(timeout=1.0)
    client._log = lines.append
    client.discover_who_is(target_ip="127.0.0.1")
    assert any("Who-Is: no answer in the" in line for line in lines), lines


# -- 10. exports and small things -------------------------------------------------------

def test_exports_are_in_address_order(tmp_path):
    r = ScanResult()
    r.devices = [{'ip': '192.0.2.10', 'protocol': 'BACnet/IP', 'instance': 10},
                 {'ip': '192.0.2.2', 'protocol': 'Modbus TCP', 'port': 502, 'unit_id': 1},
                 {'ip': '192.0.2.9', 'protocol': 'BACnet/MSTP', 'instance': 900},
                 {'ip': '192.0.2.9', 'protocol': 'BACnet/IP', 'instance': 9}]
    assert [(d['ip'], d['protocol']) for d in r.to_dict()['devices']] == [
        ('192.0.2.2', 'Modbus TCP'), ('192.0.2.9', 'BACnet/IP'),
        ('192.0.2.9', 'BACnet/MSTP'), ('192.0.2.10', 'BACnet/IP')]
    r.write_csv(str(tmp_path / 'd.csv'))
    lines = (tmp_path / 'd.csv').read_text(encoding='utf-8-sig').splitlines()[1:]
    assert [line.split(',')[1] for line in lines] == ['192.0.2.2', '192.0.2.9', '192.0.2.9',
                                                       '192.0.2.10']


def test_an_export_into_a_missing_folder_names_the_file(tmp_path):
    target = tmp_path / "nope" / "x.json"
    with pytest.raises(OSError) as e:
        write_json_atomic(str(target), {})
    assert e.value.filename == str(target) and ".tmp-" not in str(e.value)


def test_scan_time_has_its_utc_offset():
    from datetime import datetime
    stamp = ScanResult().started_at
    assert datetime.fromisoformat(stamp).utcoffset() is not None


def test_importing_the_package_does_not_import_the_report_module():
    """Or `python -m hvac_scanner.report` warns on every run."""
    out = subprocess.run([sys.executable, "-c",
                          "import sys, hvac_scanner; print('hvac_scanner.report' in sys.modules)"],
                         capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "False", out.stderr


def test_report_tables_scroll_on_their_own():
    from hvac_scanner.report import render_html
    page = render_html({'devices': [{'ip': '192.0.2.5', 'protocol': 'Modbus TCP',
                                     'port': 502, 'unit_id': 1}]})
    assert '<div class="tw"><table>' in page and ".tw { overflow-x: auto; }" in page
