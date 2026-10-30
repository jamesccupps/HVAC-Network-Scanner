"""2.8: BBMD tables, MS/TP behind remote routers, trend log and schedule
metadata, BACnet/SC detection and saved site profiles."""

import json
import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from hvac_scanner import codec  # noqa: E402
from hvac_scanner.engine import ScanEngine, ScanOptions, ScanResult  # noqa: E402

NET = "127.0.1"          # the module site in test_e2e_site uses the same /24
REMOTE = "127.0.3"


# ---------------------------------------------------------------------------
# codec
# ---------------------------------------------------------------------------

def _bvll(function: int, body: bytes) -> bytes:
    return struct.pack('!BBH', 0x81, function, 4 + len(body)) + body


def test_bdt_and_fdt_acks_decode():
    bdt = _bvll(0x03, socket.inet_aton("10.1.0.5") + struct.pack('!H', 47808)
                + socket.inet_aton("255.255.255.255")
                + socket.inet_aton("10.2.0.5") + struct.pack('!H', 47809)
                + socket.inet_aton("255.255.255.0"))
    assert codec.parse_read_bdt_ack(bdt) == [
        {'address': '10.1.0.5:47808', 'mask': '255.255.255.255'},
        {'address': '10.2.0.5:47809', 'mask': '255.255.255.0'}]
    fdt = _bvll(0x07, socket.inet_aton("10.9.9.9") + struct.pack('!HHH', 47808, 300, 211))
    assert codec.parse_read_fdt_ack(fdt) == [
        {'address': '10.9.9.9:47808', 'ttl': 300, 'remaining': 211}]


def test_an_empty_bdt_is_an_answer_and_a_nak_is_not():
    assert codec.parse_read_bdt_ack(_bvll(0x03, b'')) == []
    nak = struct.pack('!BBHH', 0x81, 0x00, 6, 0x0020)
    assert codec.parse_read_bdt_ack(nak) is None
    assert codec.parse_bvlc_result(nak) == codec.BVLC_RESULT_READ_BDT_NAK


def test_bbmd_table_requests_are_bare_bvll_reads():
    assert codec.build_read_bdt() == bytes([0x81, 0x02, 0x00, 0x04])
    assert codec.build_read_fdt() == bytes([0x81, 0x06, 0x00, 0x04])


def test_unicast_who_is_is_not_wrapped_as_a_broadcast():
    """Sent to one router as Original-Broadcast-NPDU, a BBMD would forward the
    Who-Is to every peer subnet."""
    assert codec.build_whois(dnet=9)[1] == 0x0B
    assert codec.build_whois(dnet=9, unicast=True)[1] == 0x0A
    assert codec.build_whois_router_to_network(unicast=True)[1] == 0x0A


def _ctx(tag: int, data: bytes) -> bytes:
    return bytes([(tag << 4) | 0x08 | len(data)]) + data


def _oid(obj_type: int, inst: int) -> bytes:
    return struct.pack('!I', (obj_type << 22) | inst)


def test_property_references_decode_with_their_optional_parts():
    raw = (_ctx(0, _oid(0, 3)) + _ctx(1, b'\x55')
           + _ctx(0, _oid(5, 1)) + _ctx(1, b'\x55') + _ctx(2, b'\x02') + _ctx(3, _oid(8, 1001)))
    assert codec.decode_property_references(raw) == [
        {'object': ('Analog Input', 3), 'property': 85},
        {'object': ('Binary Value', 1), 'property': 85, 'index': 2, 'device': 1001}]


def test_weekly_schedule_decodes_day_by_day():
    day = (b'\x0e' + b'\xb4\x06\x00\x00\x00' + b'\x91\x01'
           + b'\xb4\x12\x00\x00\x00' + b'\x00' + b'\x0f')       # 06:00 -> 1, 18:00 -> Null
    raw = day + b'\x0e\x0f' * 6
    week = codec.decode_weekly_schedule(raw)
    assert len(week) == 7
    assert week[0] == [("06:00:00.00", 1), ("18:00:00.00", None)]
    assert week[1:] == [[]] * 6


def test_rpm_value_with_a_nested_tag_4_is_not_cut_short():
    """A constructed value may itself use context tag 4. The RPM parser used
    to stop at the first closing-tag-4 byte, losing the rest of the value
    and every property after it."""
    nested = b'\x4e' + b'\x21\x05' + b'\x4f'
    ack = (bytes([0x81, 0x0A, 0, 0, 0x01, 0x00, 0x30, 0x01, 0x0E])
           + _ctx(0, _oid(17, 1)) + b'\x1e'
           + b'\x29\x7b' + b'\x4e' + nested + b'\x21\x07' + b'\x4f'
           + b'\x29\x4d' + b'\x4e' + b'\x75\x04\x00Sch' + b'\x4f'
           + b'\x1f')
    entries = codec.parse_read_property_multiple_ack_full(ack)
    assert [e.prop_id for e in entries] == [123, 77]
    assert entries[0].raw == nested + b'\x21\x07'
    assert entries[1].value == "Sch"


def test_raw_read_property_ack_keeps_the_encoding():
    value = _ctx(0, _oid(0, 3)) + _ctx(1, b'\x55')
    ack = (bytes([0x81, 0x0A, 0, 0, 0x01, 0x00, 0x30, 0x01, 0x0C])
           + _ctx(0, _oid(20, 1)) + _ctx(1, b'\x84') + b'\x3e' + value + b'\x3f')
    assert codec.parse_read_property_ack_raw(ack) == value


# ---------------------------------------------------------------------------
# against the simulated site
# ---------------------------------------------------------------------------

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


def _scan(networks, **kw):
    opts = dict(networks=networks, timeout=1.5, scan_modbus=False,
                scan_services=False, scan_snmp=False, scan_p2=False, scan_knx=False)
    opts.update(kw)
    logs = []
    result = ScanEngine(ScanOptions(**opts), callback=logs.append).run()
    return result, logs


@pytest.fixture(scope="module")
def site_scan(site):
    return _scan([f"{NET}.2-7"])


def _by_instance(result):
    return {d['instance']: d for d in result.devices if d.get('instance') is not None}


def test_bbmd_tables_are_read_from_the_bbmd_only(site_scan):
    result, logs = site_scan
    found = _by_instance(result)
    router = found[3000]
    assert router['bbmd']['bdt'][0]['address'] == f"{NET}.5:47808"
    assert router['bbmd']['fdt'] == [
        {'address': '10.20.30.40:47808', 'ttl': 300, 'remaining': 211}]
    assert not any(found[i].get('bbmd') for i in found if i != 3000)
    assert any("Peer BBMD(s) outside the scanned targets: 127.0.9.5" in line for line in logs)


def test_trend_logs_are_read_as_metadata(site_scan):
    result, _ = site_scan
    trends = {t['name']: t for t in _by_instance(result)[1001]['trend_logs']}
    sat = trends["AHU-1 SA-T 15 min"]
    assert sat['logs'] == ["AHU-1:SA-T (Analog Input 1) presentValue"]
    assert sat['interval_s'] == 900 and sat['logging_type'] == 'polled'
    assert (sat['records'], sat['buffer_size'], sat['enabled']) == (412, 1000, True)
    assert trends["VAV-01 ZN-T COV"]['logging_type'] == 'COV'
    assert trends["Chiller 1 demand"]['enabled'] is False
    assert trends["VAV-07 airflow"]['stop_when_full'] is True
    multi = trends["Plant temperatures"]
    assert multi['type'] == 'Trend Log Multiple' and len(multi['logs']) == 3


def test_a_reference_into_another_device_names_that_device(site_scan):
    result, _ = site_scan
    trend = _by_instance(result)[2000]['trend_logs'][0]
    assert trend['logs'] == ["device 1001 Analog Input 1 presentValue"]


def test_schedules_and_calendars_are_read(site_scan):
    result, _ = site_scan
    by_type = {s['type']: s for s in _by_instance(result)[1001]['schedules']}
    sched = by_type['Schedule']
    assert sched['controls'] == ["AHU-1:OCC (Binary Value 1) presentValue"]
    assert sched['weekly']['Mon'] == "06:00 active, 18:00 inactive"
    assert sched['weekly']['Sat'] == "08:00 active, 12:00 inactive"
    assert 'Sun' not in sched['weekly']
    assert sched['default'] == 'inactive' and sched['present_value'] == 'active'
    assert sched['effective'] == "from 2026-01-01"
    assert by_type['Calendar']['present_value'] == 'false'


def test_metadata_objects_are_not_points(site_scan):
    result, _ = site_scan
    sc = _by_instance(result)[1001]
    assert len(sc['objects']) == 632
    assert not any(o['type'] in ('Trend Log', 'Schedule', 'Calendar', 'Network Port')
                   for o in sc['objects'])


def test_network_ports_describe_the_router(site_scan):
    result, _ = site_scan
    ports = {p['type']: p for p in _by_instance(result)[3000]['network_ports']}
    assert ports['IPv4']['network'] == 1
    assert ports['IPv4']['mac'] == f"{NET}.5:47808"
    assert ports['IPv4']['accepts_fd_registrations'] is True
    assert (ports['MS/TP']['network'], ports['MS/TP']['mac'],
            ports['MS/TP']['max_master']) == (5, '0', 127)


def test_metadata_and_bbmd_reads_can_be_turned_off(site):
    result, _ = _scan([f"{NET}.2-7"], read_metadata=False, read_bbmd_tables=False,
                      scan_mstp=False)
    assert not any(d.get('trend_logs') or d.get('schedules') or d.get('network_ports')
                   or d.get('bbmd') for d in result.devices)


@pytest.fixture(scope="module")
def remote_building():
    """Only the second building: a router on a /24 no broadcast reaches."""
    import sim_site
    ip, dev, mstp, bbmd = sim_site.build_remote_building(REMOTE, f"{NET}.5")
    try:
        ep = sim_site.BACnetEndpoint(ip, dev, mstp, bbmd=bbmd, remote=True)
    except OSError as e:
        pytest.skip(f"cannot bind {ip}: {e}")
    yield ep
    ep.close()


def test_mstp_behind_a_remote_router_without_a_bbmd(remote_building):
    """The router is found by unicast and its MS/TP network from its Network
    Port. A routed Who-Is finds the device that answers the requester; the one
    that only broadcasts stays hidden, and the log says how to find it."""
    result, logs = _scan([f"{REMOTE}.5"], unicast_discovery="always")
    found = _by_instance(result)
    assert set(found) == {4000, 900002}
    vav = found[900002]
    assert vav['protocol'] == 'BACnet/MSTP'
    assert (vav['ip'], vav['source_network'], vav['source_address']) == (f"{REMOTE}.5", 9, '2')
    assert vav['discovered_via'] == 'routed who-is'
    assert len(vav['objects']) == 9               # deep-scanned through the router
    assert any("--mstp-probe" in line and f"--bbmd {REMOTE}.5" in line for line in logs)


def test_mstp_address_probe_finds_devices_that_only_broadcast(remote_building):
    result, logs = _scan([f"{REMOTE}.5"], unicast_discovery="always", mstp_mac_probe=True)
    found = _by_instance(result)
    assert set(found) == {4000, 900002, 900006}
    assert found[900006]['discovered_via'] == 'mac-probe'
    assert found[900006]['source_address'] == '6'
    # Bounded by the port's max master (7), skipping the router's own MAC 0.
    assert any("asking MS/TP addresses 0–7" in line for line in logs)


def test_mstp_probe_skips_networks_of_unknown_type():
    """A network learned only from I-Am-Router-To-Network might not be MS/TP,
    and a one-byte MAC sweep would be meaningless there."""
    eng = ScanEngine(ScanOptions(networks=["10.0.0.5"], mstp_mac_probe=True),
                     callback=lambda _m: None)
    eng.result.devices = [{'ip': '10.0.0.5', 'instance': 1, 'protocol': 'BACnet/IP',
                           'discovered_via': 'unicast'}]
    logs = []
    eng.callback = logs.append

    class Client:
        probed = []

        def discover_routers_unicast(self, ips, **_kw):
            return [{'ip': '10.0.0.5', 'networks': [12]}]

        def discover_who_is_networks(self, **_kw):
            return []

        def probe_mstp_macs(self, *a, **kw):
            Client.probed.append(a)
            return []

    eng._scan_remote_mstp(Client())
    assert Client.probed == []
    assert any("not known to be MS/TP" in line for line in logs)


# ---------------------------------------------------------------------------
# BACnet/SC
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sc_hubs(tmp_path_factory):
    import sim_site
    cert = sim_site._self_signed_cert("bsc-hub", "Site CA", str(tmp_path_factory.mktemp("sc")))
    if not cert:
        pytest.skip("openssl is needed to make the hubs' certificates")
    hubs = []
    try:
        hubs.append(sim_site.SCHub(f"{NET}.25", 47808, cert))
        hubs.append(sim_site.SCHub(f"{NET}.26", 47820, cert, require_client_cert=False))
    except OSError as e:
        for h in hubs:
            h.close()
        pytest.skip(f"cannot bind the hubs: {e}")
    yield hubs
    for h in hubs:
        h.close()


def test_a_hub_that_requires_client_certificates(sc_hubs):
    from hvac_scanner.services import HVACServiceScanner
    info = HVACServiceScanner(timeout=2)._identify(f"{NET}.25", 47808, "BACnet/SC (TCP)")
    assert info['tls_client_cert_required'] is True
    assert info['product'] == "BACnet/SC (mutual TLS)"
    assert "CN=bsc-hub" in info['tls_summary']        # kept from the handshake
    assert sc_hubs[0].upgrades == 0


def test_a_hub_that_lets_anyone_in_is_reported(sc_hubs):
    from hvac_scanner.fingerprint import fingerprint_device
    from hvac_scanner.report import build_findings
    from hvac_scanner.services import HVACServiceScanner
    info = HVACServiceScanner(timeout=2)._identify(f"{NET}.26", 47820, "BACnet/SC")
    assert (info['sc_role'], info['tls_client_cert_required']) == ('hub', False)
    assert info['product'] == "BACnet/SC hub"
    assert fingerprint_device(info)['model'] == "BACnet/SC hub"
    findings = build_findings({'devices': [info]})
    assert findings[0].severity == 'high' and 'without a client certificate' in findings[0].title


def test_an_ordinary_web_server_is_not_bacnet_sc(tmp_path):
    import sim_site
    from hvac_scanner.services import HVACServiceScanner
    cert = sim_site._self_signed_cert("web", "Example", str(tmp_path))
    if not cert:
        pytest.skip("openssl is needed for the certificate")
    try:
        web = sim_site.WebUI(f"{NET}.27", 8443, "Login", "nginx", tls_cert=cert)
    except OSError as e:
        pytest.skip(f"cannot bind: {e}")
    try:
        info = HVACServiceScanner(timeout=2)._identify(f"{NET}.27", 8443, "HTTPS-Alt")
    finally:
        web.close()
    assert info['title'] == "Login"
    assert not info.get('sc_role') and not info.get('tls_client_cert_required')


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def _scan_dict():
    return {'devices': [
        {'protocol': 'BACnet/IP', 'ip': '10.0.0.5', 'instance': 5,
         'bbmd': {'bdt': [{'address': '10.0.0.5:47808'}, {'address': '10.9.0.5:47808'}],
                  'fdt': [{'address': '10.20.30.40:47808', 'ttl': 300, 'remaining': 211}]},
         'trend_logs': [
             {'name': 'Off <one>', 'logs': ['x'], 'enabled': False},
             {'name': 'Full', 'logs': ['y'], 'enabled': True, 'stop_when_full': True,
              'records': 10, 'buffer_size': 10},
             {'name': 'Fine', 'logs': ['z'], 'enabled': True, 'records': 1,
              'buffer_size': 10, 'interval_s': 900, 'logging_type': 'polled'}],
         'schedules': [{'type': 'Schedule', 'instance': 1, 'name': 'Occ',
                        'weekly': {'Mon': 'a', 'Tue': 'a', 'Wed': 'a', 'Sat': 'b'}}]},
        {'protocol': 'Service', 'ip': '10.0.0.9', 'port': 47808, 'sc_role': 'hub or node',
         'tls_client_cert_required': True, 'tls_summary': 'CN=hub'},
    ]}


def test_report_findings_for_bbmds_trends_and_sc():
    from hvac_scanner.report import build_findings
    by_title = {f.title: f for f in build_findings(_scan_dict())}
    fdt = by_title["Foreign devices registered with a BBMD"]
    assert fdt.severity == 'low' and fdt.rows == [['10.0.0.5', '10.20.30.40:47808', '300', '211']]
    idle = by_title["Trend logs not recording"]
    assert [r[2] for r in idle.rows] == ['Off <one>', 'Full']
    assert [r[4] for r in idle.rows] == ['disabled', 'full, stopped']
    assert by_title["BBMDs linking subnets into one BACnet network"].rows == [
        ['10.0.0.5', '10.9.0.5']]
    assert by_title["BACnet/SC endpoints requiring client certificates"].severity == 'info'


def test_report_lists_trends_and_schedules_escaped():
    from hvac_scanner.report import render_html
    page = render_html(_scan_dict())
    assert "<h2>Trend logs</h2>" in page and "<h2>Schedules and calendars</h2>" in page
    assert "Off &lt;one&gt;" in page and "Off <one>" not in page
    assert "Mon–Wed a; Sat b" in page
    assert "every 15 min" in page


@pytest.mark.parametrize("trend, text", [
    ({'logging_type': 'COV'}, 'on change (COV)'),
    ({'logging_type': 'polled', 'interval_s': 60}, 'every 1 min'),
    ({'logging_type': 'polled', 'interval_s': 7200}, 'every 2 h'),
    ({'logging_type': 'polled', 'interval_s': 2.5}, 'every 2.5 s'),
])
def test_trend_interval_wording(trend, text):
    from hvac_scanner.report import trend_interval
    assert trend_interval(trend) == text


def test_week_summary_runs_only_consecutive_days_together():
    from hvac_scanner.report import week_summary
    assert week_summary({'Mon': 'x', 'Wed': 'x', 'Thu': 'x', 'Sun': 'y'}) == \
        "Mon x; Wed–Thu x; Sun y"
    assert week_summary({}) == ""


# ---------------------------------------------------------------------------
# site profiles
# ---------------------------------------------------------------------------

_PROFILE = {
    'targets': "10.1.0.0/24, 10.1.1.5",
    'depth': 'quick',
    'advanced': {'timeout': "8", 'rate_limit': "20", 'workers': "2", 'unicast': "always",
                 'bbmd': "10.1.0.5", 'broadcast': "not an ip", 'max_objects': "",
                 'whois_chunk': "0", 'communities': "public, bms"},
    'toggles': {'scan_modbus': False, 'mstp_mac_probe': True, 'deep_scan': 'yes'},
}


def test_profile_options_parse_what_parses_and_skip_the_rest():
    from hvac_scanner.settings import profile_options
    kw = profile_options(_PROFILE)
    assert kw['networks'] == ["10.1.0.0/24", "10.1.1.5"]
    assert (kw['scan_depth'], kw['timeout'], kw['rate_limit_ms'], kw['bacnet_workers']) == \
        ('quick', 8.0, 20, 2)
    assert kw['unicast_discovery'] == 'always' and kw['bbmd'] == '10.1.0.5'
    assert kw['snmp_communities'] == ['public', 'bms']
    assert kw['scan_modbus'] is False and kw['mstp_mac_probe'] is True
    for skipped in ('bacnet_broadcast', 'max_objects_per_device', 'deep_scan'):
        assert skipped not in kw
    ScanOptions(**kw)                                    # every key is a real option


def _settings_file(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({'profiles': {'Building A': _PROFILE}}), encoding='utf-8')
    return path


def _run_cli(monkeypatch, argv):
    from hvac_scanner import cli
    seen = {}

    class Engine:
        def __init__(self, opts, **_kw):
            seen['opts'] = opts

        def run(self):
            return ScanResult()

    monkeypatch.setattr(cli, "ScanEngine", Engine)
    code = cli.main(argv + ["--quiet", "--print", "none"])
    return code, seen.get('opts')


def test_cli_scans_a_saved_profile(monkeypatch, tmp_path):
    code, opts = _run_cli(monkeypatch, ["--profile", "Building A",
                                        "--settings-file", str(_settings_file(tmp_path))])
    assert code == 0
    assert opts.networks == ["10.1.0.0/24", "10.1.1.5"]
    assert (opts.timeout, opts.scan_modbus, opts.mstp_mac_probe, opts.bbmd) == \
        (8.0, False, True, "10.1.0.5")


def test_cli_flags_and_targets_override_the_profile(monkeypatch, tmp_path):
    code, opts = _run_cli(monkeypatch, ["10.5.0.0/24", "--profile", "Building A",
                                        "--timeout", "3", "--bacnet-only",
                                        "--settings-file", str(_settings_file(tmp_path))])
    assert code == 0
    assert opts.networks == ["10.5.0.0/24"]
    assert opts.timeout == 3.0
    assert opts.scan_snmp is False
    assert opts.rate_limit_ms == 20                    # not given: still the profile's


def test_cli_unknown_profile_and_missing_targets(monkeypatch, tmp_path, capsys):
    code, _ = _run_cli(monkeypatch, ["--profile", "Nope",
                                     "--settings-file", str(_settings_file(tmp_path))])
    assert code == 1
    assert "Building A" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        _run_cli(monkeypatch, [])
    assert e.value.code == 2


def test_cli_lists_profiles(tmp_path, capsys):
    from hvac_scanner import cli
    assert cli.main(["--list-profiles", "--settings-file", str(_settings_file(tmp_path))]) == 0
    assert capsys.readouterr().out.strip() == "Building A\t10.1.0.0/24, 10.1.1.5"


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def test_gui_saves_and_restores_a_site_profile(gui_app):
    app = gui_app
    app.network_entry.delete(0, "end")
    app.network_entry.insert(0, "10.7.0.0/24")
    app.scan_depth_var.set("full")
    app.adv_vars['timeout'].set("9")
    app.mstp_mac_probe.set(True)
    app._store_profile("Plant")

    app.network_entry.delete(0, "end")
    app.network_entry.insert(0, "192.168.9.0/24")
    app.scan_depth_var.set("quick")
    app.adv_vars['timeout'].set("2")
    app.mstp_mac_probe.set(False)

    app._load_profile("Plant")
    assert app.network_entry.get() == "10.7.0.0/24"
    assert app.scan_depth_var.get() == "full"
    assert app.adv_vars['timeout'].get() == "9"
    assert app.mstp_mac_probe.get() is True
    assert list(app.profile_combo.cget('values')) == ["Plant"]

    saved = app._collect_settings()
    assert saved['profile'] == "Plant" and "Plant" in saved['profiles']
    app._remove_profile("Plant")
    assert app.profile_var.get() == "" and not app._profiles


def test_gui_profiles_survive_a_settings_round_trip(gui_app):
    gui_app._apply_settings({'profiles': {'A': _PROFILE, 'bad': 'nope'}, 'profile': 'A'})
    assert gui_app.profile_var.get() == "A"
    assert list(gui_app.profile_combo.cget('values')) == ["A"]


def test_gui_passes_the_new_options(gui_app):
    gui_app.network_entry.delete(0, "end")
    gui_app.network_entry.insert(0, "10.0.0.0/24")
    gui_app.read_metadata.set(False)
    gui_app.mstp_mac_probe.set(True)
    opts = gui_app._build_options()
    assert (opts.read_metadata, opts.mstp_mac_probe, opts.read_bbmd_tables) == \
        (False, True, True)


def test_gui_shows_trends_schedules_and_bbmd_details(gui_app):
    dev = _scan_dict()['devices'][0]
    dev['network_ports'] = [{'instance': 2, 'name': 'MS/TP trunk', 'type': 'MS/TP',
                             'network': 5, 'mac': '0', 'max_master': 127}]
    gui_app._add_meta_for(dev)
    rows = [gui_app.meta_tree.item(i, 'values') for i in gui_app._rows['meta']]
    assert len(rows) == 4
    assert rows[0][7] == 'disabled' and rows[2][5] == 'every 15 min'
    assert rows[3][5] == "Mon–Wed a; Sat b"
    lines = {k: v for kind, k, v in gui_app._detail_lines(dev) if kind == 'kv'}
    assert lines['Foreign devs'] == "10.20.30.40:47808 (211 s left)"
    assert lines['MS/TP trunk'] == "MS/TP, network 5, MAC 0, max master 127"


# ---------------------------------------------------------------------------
# from the prior-art review: 22-bit property IDs, BACnet/SC hub URIs,
# Niagara Fox identity, KNXnet/IP, Modbus Report Server ID
# ---------------------------------------------------------------------------

def test_property_ids_past_65535_use_three_octets():
    """The BACnet/SC Network Port properties start at 4194316. A two-octet
    encoding turned 4194325 (SC_Primary_Hub_URI) into property 21."""
    pkt = codec.build_read_property('Network Port', 1, 4194325)
    assert pkt.endswith(b'\x1b\x40\x00\x15')
    rpm = codec.build_read_property_multiple('Network Port', 1, [77, 4194325])
    assert b'\x09\x4d' in rpm and b'\x0b\x40\x00\x15' in rpm


def test_sc_hub_uris_are_read_from_network_ports(site_scan):
    result, _ = site_scan
    ports = _by_instance(result)[2101]['network_ports']
    sc = next(p for p in ports if p['type'] == 'BACnet/SC')
    assert sc['sc_primary_hub'] == f"wss://{NET}.25:47808"
    assert sc['sc_failover_hub'] == f"wss://{NET}.26:4443"
    assert sc['sc_hub_function'] is False


def test_a_hub_on_an_unswept_port_is_found_through_the_device_naming_it(tmp_path):
    import sim_site
    from hvac_scanner.services import HVACServiceScanner
    cert = sim_site._self_signed_cert("hub", "Site CA", str(tmp_path))
    if not cert:
        pytest.skip("openssl is needed for the certificate")
    try:
        hub = sim_site.SCHub(f"{NET}.31", 4443, cert, require_client_cert=False)
    except OSError as e:
        pytest.skip(f"cannot bind: {e}")
    try:
        eng = ScanEngine(ScanOptions(networks=[f"{NET}.31"]), callback=lambda _m: None)
        eng.result.devices = [{'ip': f"{NET}.9", 'protocol': 'BACnet/IP', 'network_ports': [
            {'type': 'BACnet/SC', 'sc_primary_hub': f"wss://{NET}.31:4443/hub"}]}]
        found = eng._probe_named_sc_hubs(HVACServiceScanner(timeout=2), [])
    finally:
        hub.close()
    assert [(d['ip'], d['port'], d['sc_role']) for d in found] == [(f"{NET}.31", 4443, 'hub')]
    assert found[0]['sc_named_by'] == f"wss://{NET}.31:4443/hub"


def test_fox_hello_is_parsed_into_station_identity():
    from hvac_scanner.services import parse_fox_hello
    import sim_site
    text = sim_site._fox_hello("JACE_B", "4.13.1.16", "QNX", "7.0.0", "Qnx-1").decode()
    fields = parse_fox_hello(text)
    assert fields['station.name'] == "JACE_B" and fields['app.version'] == "4.13.1.16"
    assert fields['timeZone'] == "America/Chicago"
    assert fields['brandId'] == "vykon" and fields['hostId'] == "Qnx-1"


@pytest.mark.parametrize("version, flagged", [("3.8.41", True), ("4.13.1.16", False)])
def test_fox_probe_and_niagara_ax_finding(version, flagged):
    import sim_site
    from hvac_scanner.report import build_findings
    from hvac_scanner.services import HVACServiceScanner
    try:
        srv = sim_site.BannerService(f"{NET}.32", 1911, sim_site._fox_hello(
            "ST1", version, "QNX", "7.0", "Qnx-2"), reply_to_input=True)
    except OSError as e:
        pytest.skip(f"cannot bind: {e}")
    try:
        info = HVACServiceScanner(timeout=2)._identify(f"{NET}.32", 1911, "Niagara Fox")
    finally:
        srv.close()
    assert info['product'] == f"Niagara Station {version}"
    assert info['fox']['station.name'] == "ST1"
    titles = [f.title for f in build_findings({'devices': [dict(info, ip=f"{NET}.32", port=1911)]})]
    assert ("Niagara AX stations past end of support" in titles) is flagged


def test_knx_description_response_round_trip():
    import sim_site
    from hvac_scanner.knx import KNXScanner
    try:
        gw = sim_site.KNXGateway(f"{NET}.33", "Lighting IP interface", 0x1101)
    except OSError as e:
        pytest.skip(f"cannot bind: {e}")
    try:
        found = KNXScanner(timeout=1.5).scan_network(f"{NET}.33-34")
    finally:
        gw.close()
    assert len(found) == 1
    knx = found[0]
    assert (knx['name'], knx['knx_address'], knx['medium']) == ("Lighting IP interface", "1.1.1", "TP1")
    assert knx['tunnelling'] and not knx['routing'] and not knx['secure']


def test_knx_findings_and_fingerprint():
    from hvac_scanner.fingerprint import fingerprint_device
    from hvac_scanner.report import build_findings
    gw = {'protocol': 'KNXnet/IP', 'ip': '10.0.0.40', 'name': 'GW', 'knx_address': '1.1.0',
          'medium': 'TP1', 'services': [{'family': 'Tunnelling'}, {'family': 'Routing'}],
          'tunnelling': True, 'routing': True, 'secure': False}
    secure = dict(gw, ip='10.0.0.41', secure=True)
    finding = next(f for f in build_findings({'devices': [gw, secure]})
                   if f.title == "KNXnet/IP gateways without KNX Secure")
    assert finding.rows == [['10.0.0.40', 'GW', '1.1.0', 'tunnelling, routing']]
    assert fingerprint_device(gw)['device_type'] == 'KNX IP Router'


def test_knx_can_be_turned_off_from_the_cli(monkeypatch):
    code, opts = _run_cli(monkeypatch, ["10.0.0.0/24", "--no-knx"])
    assert code == 0 and opts.scan_knx is False
    code, opts = _run_cli(monkeypatch, ["10.0.0.0/24", "--bacnet-only"])
    assert opts.scan_knx is False


def test_modbus_report_server_id_identifies_what_fc43_does_not():
    import sim_site
    from hvac_scanner.modbus import ModbusScanner
    try:
        srv = sim_site.ModbusServer(f"{NET}.34", {
            1: sim_site.ModbusUnit(device_id=False, server_id=b"\x0aVFD-480 drive v3.2"),
            2: sim_site.ModbusUnit(device_id=False)})
    except OSError as e:
        pytest.skip(f"cannot bind: {e}")
    try:
        found = {d['unit_id']: d for d in ModbusScanner(timeout=1.0).scan_host(f"{NET}.34", 502, [1, 2])}
    finally:
        srv.close()
    assert found[1]['detected_via'] == 'report_server_id'
    assert found[1]['product'] == "VFD-480 drive v3.2"
    assert found[2]['detected_via'] == 'holding_register_read'


def test_a_comma_list_given_as_one_target_entry_is_split():
    """One quoted CLI argument, "10.0.0.2-30, 10.0.4.5", reached the engine
    as a single entry: parse_targets rejected it as one spec, so unicast
    discovery silently had no targets, and the entry's two /24s fell back to
    a limited broadcast."""
    from hvac_scanner.netrange import parse_targets
    assert len(parse_targets(["10.0.0.2-30, 10.0.4.5"])) == 30
    eng = ScanEngine(ScanOptions(networks=["10.0.0.2-30, 10.0.4.5"]), callback=lambda _m: None)
    assert eng.opts.networks == ["10.0.0.2-30", "10.0.4.5"]
    assert len(eng._target_ips_in_order()) == 30


def test_every_module_is_bundled_into_the_windows_exe():
    """The PyInstaller spec lists the package's modules by hand; one left off
    is missing from the exe, and nothing else would notice until it ran."""
    root = Path(__file__).resolve().parent.parent
    spec = (root / "packaging" / "hvac_scanner.spec").read_text(encoding="utf-8")
    modules = {f"hvac_scanner.{p.stem}" for p in (root / "hvac_scanner").glob("*.py")
               if p.stem not in ("__init__", "__main__")}
    missing = sorted(m for m in modules if f"'{m}'" not in spec)
    assert not missing, f"add to hiddenimports in packaging/hvac_scanner.spec: {missing}"
