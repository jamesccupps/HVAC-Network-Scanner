"""2.11: more of what a building network holds. LonWorks/IP (IP-852)
routers and nodes; packet layouts from the IzoT LonTalk stack
(github.com/izot/lon-stack-ex, LonTalkStack/Source/ShareIp)."""
import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from hvac_scanner import lonworks  # noqa: E402
from hvac_scanner.engine import ScanEngine, ScanOptions  # noqa: E402

LON_IP = "127.0.6.27"


def _devconfig(name=b"AHU LON router\x00", neuron=bytes.fromhex("04A1B2C3D4E5"),
               node_type=1, flags=0, ext_words=0, lon_flags=0x02, digest=b""):
    """A Device Configuration packet built field by field from LtIpDevRegister."""
    body = struct.pack('!IBBBBBBHHHIIIIIIHHHH',
                       3_960_000_000, 1, 0, lon_flags, node_type, 0, 0, 150,
                       len(neuron), 1628, 0x0A000105, 0, 0, 0x0A0001C8, 0x0A000101, 0,
                       1629, 123, 0, 0)
    payload = body + neuron + bytes([len(name)]) + name
    size = 20 + 4 * ext_words + len(payload)
    header = struct.pack('!HBBBBHIII', size, 1, 0x71, ext_words, flags, 0, 7, 0, 0)
    return header + bytes(4 * ext_words) + payload + digest


def test_the_request_is_a_36_byte_device_configuration_request():
    pkt = lonworks.build_devconfig_request(session=0x01020304)
    assert len(pkt) == 36
    size, version, ptype, ext, flags, vendor, session, seq, _ts = struct.unpack('!HBBBBHIII', pkt[:20])
    assert (size, version, ptype, ext, flags, vendor, session, seq) == (36, 1, 0x63, 0, 0, 0, 0x01020304, 0)


def test_a_device_configuration_reply_is_read_field_by_field():
    info = lonworks.parse_devconfig(_devconfig())
    assert info['name'] == "AHU LON router"
    assert info['node_type'] == "LonTalk/IP router" and info['router_mode'] == "configured"
    assert info['neuron_ids'] == ["04A1B2C3D4E5"]
    assert info['unicast'] == "10.0.1.5:1628"
    assert info['config_server'] == "10.0.1.200:1629"
    assert info['time_servers'] == ["10.0.1.1:123"]
    assert info['auth_supported'] is True and info['authenticated'] is False


def test_an_extended_header_and_a_digest_are_stepped_over():
    info = lonworks.parse_devconfig(_devconfig(flags=0x20, ext_words=3, digest=bytes(16)))
    assert info['name'] == "AHU LON router" and info['authenticated'] is True


@pytest.mark.parametrize("data", [
    b"", b"\x00" * 19,
    _devconfig()[:3] + b"\x01" + _devconfig()[4:],          # a data packet, not a reply
    _devconfig()[:30],                                     # cut short in the fixed part
])
def test_anything_else_is_not_a_device(data):
    assert lonworks.parse_devconfig(data) is None


def test_a_name_running_past_the_packet_is_cut_at_its_end():
    pkt = bytearray(_devconfig())
    pkt[20 + 48 + 6] = 0xFF                    # the name's length byte claims 255
    assert lonworks.parse_devconfig(bytes(pkt))['name'] == "AHU LON router"


def test_the_scanner_finds_the_simulated_router():
    import sim_site
    router = sim_site.IP852Router(LON_IP, "Floor 3 LON router", "04A1B2C3D4E5", f"{LON_IP}:1629")
    try:
        lines = []
        devs = lonworks.LonWorksScanner(callback=lines.append, timeout=1.0).scan_network(
            f"{LON_IP}, 127.0.6.28")
    finally:
        router.close()
    assert [d['ip'] for d in devs] == [LON_IP]
    d = devs[0]
    assert d['protocol'] == 'LonWorks/IP' and d['name'] == "Floor 3 LON router"
    assert d['config_server'] == f"{LON_IP}:1629" and d['neuron_ids'] == ["04A1B2C3D4E5"]
    assert any("LonWorks/IP at 127.0.6.27: LonTalk/IP router 'Floor 3 LON router'" in l for l in lines)


def test_the_engine_reports_and_names_it():
    import sim_site
    from hvac_scanner.report import build_findings
    router = sim_site.IP852Router(LON_IP, "Floor 3 LON router", "04A1B2C3D4E5", f"{LON_IP}:1629")
    try:
        result = ScanEngine(ScanOptions(networks=[LON_IP], scan_bacnet=False, scan_mstp=False,
                                        scan_modbus=False, scan_services=False, scan_snmp=False,
                                        scan_p2=False, scan_knx=False, timeout=1.0),
                            callback=lambda m: None).run()
    finally:
        router.close()
    assert result.counts['lon'] == 1 and result.passes['lon'] == 'scanned'
    fp = result.devices[0]['_fingerprint']
    assert fp['device_type'] == 'LonWorks/IP Router'
    assert fp['model'] == ''                  # the reply names no product: none is guessed
    assert fp['description'] == f"IP-852 LonTalk/IP router, config server {LON_IP}:1629"
    f = next(f for f in build_findings(result.to_dict())
             if f.title == "LonWorks/IP (IP-852) devices without authentication")
    assert f.rows == [[LON_IP, "Floor 3 LON router", "LonTalk/IP router", "yes"]]


def test_lonworks_can_be_turned_off_from_the_cli(monkeypatch):
    from tests.test_v28 import _run_cli
    code, opts = _run_cli(monkeypatch, ["10.0.0.0/24", "--no-lon"])
    assert code == 0 and opts.scan_lon is False
    code, opts = _run_cli(monkeypatch, ["10.0.0.0/24", "--bacnet-only"])
    assert opts.scan_lon is False


# -- Moxa serial gateways -------------------------------------------------------

from hvac_scanner import moxa  # noqa: E402

MOXA_IP = "127.0.6.30"


def _moxa_reply(model_code=6250, mac="0090E8123456", ip="192.168.127.254"):
    """A 24-byte identify reply: 0x81, model code (little-endian) at 12,
    MAC at 14, IP at 20 (Metasploit moxa_discover, runZero oobscan)."""
    return (bytes([0x81, 0x00, 0x00, 0x18]) + bytes(8) + struct.pack('<H', model_code)
            + bytes.fromhex(mac) + socket.inet_aton(ip))


def test_the_identify_request_is_the_eight_byte_function_1():
    assert moxa.IDENTIFY == bytes.fromhex("0100000800000000")


def test_an_identify_reply_gives_model_code_mac_and_ip():
    info = moxa.parse_identify_reply(_moxa_reply())
    assert info == {'model_code': 6250, 'mac': "00:90:E8:12:34:56", 'moxa_oui': True,
                    'reported_ip': "192.168.127.254"}


@pytest.mark.parametrize("data", [
    b"", _moxa_reply()[:23], b"\x01" + _moxa_reply()[1:],
    _moxa_reply(mac="000000000000"), _moxa_reply(mac="FFFFFFFFFFFF"),
])
def test_other_replies_are_not_moxa_devices(data):
    assert moxa.parse_identify_reply(data) is None


def test_the_scanner_finds_the_simulated_nport_and_sends_only_identify():
    import sim_site
    dev = sim_site.MoxaDevice(MOXA_IP, model_code=5150, mac="0090E8ABCDEF")
    try:
        found = moxa.MoxaScanner(timeout=1.0).scan_network(f"{MOXA_IP}, 127.0.6.31")
    finally:
        dev.close()
    assert [(d['ip'], d['model_code'], d['mac']) for d in found] == \
        [(MOXA_IP, 5150, "00:90:E8:AB:CD:EF")]
    assert dev.requests == [moxa.IDENTIFY]          # never the "unlock" function


def test_the_engine_names_a_moxa_device_by_its_code_and_flags_it():
    import sim_site
    from hvac_scanner.report import build_findings
    dev = sim_site.MoxaDevice(MOXA_IP, model_code=5150, mac="0090E8ABCDEF")
    try:
        result = ScanEngine(ScanOptions(networks=[MOXA_IP], scan_bacnet=False, scan_mstp=False,
                                        scan_modbus=False, scan_services=False, scan_snmp=False,
                                        scan_p2=False, scan_knx=False, scan_lon=False, timeout=1.0),
                            callback=lambda m: None).run()
    finally:
        dev.close()
    assert result.counts['gateways'] == 1 and result.passes['gateways'] == 'scanned'
    fp = result.devices[0]['_fingerprint']
    assert fp['model'] == "Moxa (model code 5150)"      # not a guessed product name
    assert fp['device_type'] == 'Serial Gateway'
    f = next(f for f in build_findings(result.to_dict())
             if f.title == "Moxa gateways answering their management protocol")
    assert f.rows == [[MOXA_IP, "5150", "00:90:E8:AB:CD:EF"]] and "CVE-2016-9361" in f.why


def test_gateways_can_be_turned_off_from_the_cli(monkeypatch):
    from tests.test_v28 import _run_cli
    code, opts = _run_cli(monkeypatch, ["10.0.0.0/24", "--no-gateways"])
    assert code == 0 and opts.scan_gateways is False
    assert _run_cli(monkeypatch, ["10.0.0.0/24", "--bacnet-only"])[1].scan_gateways is False


# -- names that are accurate -----------------------------------------------------

@pytest.mark.parametrize("text,vendor", [
    ("Alerton Compass", "Alerton (Honeywell)"),     # was "Carrier / ALC"
    ("Vertiv Liebert iCOM", "Vertiv"),              # was "Emerson" (spun off 2016)
    ("Copeland E3 supervisor", "Copeland"),         # was "Emerson" (spun off 2023)
    ("Carrier i-Vu", "Carrier / ALC"),
    ("NPort Web Console", "Moxa"), ("MGate 5105-MB-EIP", "Moxa"),
    ("Lantronix XPort", "Lantronix"), ("i.LON SmartServer", "Echelon / EnOcean"),
    ("Honeywell WEBs-N4", "Honeywell / Tridium"),
])
def test_web_page_vendors_are_named_correctly(text, vendor):
    import re
    from hvac_scanner.constants import HTTP_FINGERPRINTS
    assert next(v for p, v in HTTP_FINGERPRINTS if re.search(p, text.lower())) == vendor


def test_the_niagara_platform_ports_are_probed():
    from hvac_scanner.constants import HVAC_TCP_PORTS
    assert {3011, 5011} <= set(HVAC_TCP_PORTS)


def test_a_moxa_device_is_named_by_its_own_web_page_and_only_then():
    from hvac_scanner.fingerprint import fingerprint_device
    dev = {'ip': '10.0.0.70', 'protocol': 'Moxa', 'model_code': 5150, 'mac': '00:90:E8:00:00:01'}
    web = {'ip': '10.0.0.70', 'protocol': 'Service', 'port': 80, 'title': 'NPort 5150 Web Console'}
    assert fingerprint_device(dev, [web])['model'] == "Moxa NPort 5150"
    assert fingerprint_device(dev, [])['model'] == "Moxa (model code 5150)"
    web['title'] = 'MGate 5105-mb-eip'
    assert fingerprint_device(dev, [web])['model'] == "Moxa MGate 5105-MB-EIP"


# -- OPC UA server identity --------------------------------------------------------

from hvac_scanner import opcua  # noqa: E402

UA_IP = "127.0.6.21"


@pytest.fixture
def ua_server():
    import sim_site
    srv = sim_site.OPCUAServer(UA_IP, "Plant OPC UA Server", port=4840)
    yield srv
    srv.close()


def test_get_endpoints_gives_the_servers_own_name_and_security(ua_server):
    info = opcua.probe(UA_IP, 4840, timeout=2.0)
    assert info['product'] == "Plant OPC UA Server"
    ua = info['opcua']
    assert ua['product_uri'] == "urn:sim:bms" and ua['application_uri'] == "urn:sim:bms:opcua"
    assert [(e['security_mode'], e['security_policy'], e['user_tokens']) for e in ua['endpoints']] == [
        ("None", "None", ["Anonymous", "UserName"]),
        ("SignAndEncrypt", "Basic256Sha256", ["UserName"])]
    assert ua['security_none'] is True and ua['anonymous'] is True


def test_the_probe_only_does_discovery():
    assert opcua.build_hello("opc.tcp://x:4840")[:4] == b'HELF'
    opn = opcua.build_open(3000)
    assert opn[:4] == b'OPNF' and opcua.POLICY_NONE.encode() in opn
    assert struct.pack('<BBH', 1, 0, 446) in opn                    # OpenSecureChannel
    msg = opcua.build_get_endpoints(7, 1, "opc.tcp://x:4840", 3000)
    assert struct.pack('<BBH', 1, 0, 428) in msg                    # GetEndpoints, nothing else


@pytest.mark.parametrize("reply", [
    b"HTTP/1.1 400 Bad Request\r\n\r\n",                           # a web server on 4840
    b"ACKF\xff\xff\xff\x7f",                                        # absurd size
    b"",
])
def test_anything_but_opc_ua_gives_nothing(reply):
    import threading
    srv = socket.socket()
    srv.bind(("127.0.6.22", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def answer():
        c, _ = srv.accept()
        with c:
            c.recv(4096)
            if reply:
                c.sendall(reply)
    t = threading.Thread(target=answer, daemon=True)
    t.start()
    try:
        assert opcua.probe("127.0.6.22", port, timeout=1.0) == {}
    finally:
        t.join(2)
        srv.close()


def test_a_hostile_endpoint_count_is_bounded():
    body = (struct.pack('<BBH', 1, 0, 431) + struct.pack('<qII', 0, 2, 0) + b'\x00'
            + struct.pack('<i', -1) + b'\x00\x00\x00' + struct.pack('<i', 2_000_000_000))
    with pytest.raises(opcua._Malformed):
        opcua.parse_get_endpoints(body)


def test_the_report_flags_unsecured_and_anonymous_opc_ua(ua_server):
    from hvac_scanner.report import build_findings
    from hvac_scanner.services import HVACServiceScanner
    svc = HVACServiceScanner(timeout=2.0)._identify(UA_IP, 4840, "OPC UA")
    titles = {f.title: f for f in build_findings({'devices': [svc]})}
    assert titles["OPC UA servers offering unsecured endpoints"].rows == \
        [[UA_IP, "4840", "Plant OPC UA Server", "None"]]
    assert titles["OPC UA servers allowing anonymous sessions"].rows == \
        [[UA_IP, "4840", "Plant OPC UA Server"]]


# -- adaptive timeout ------------------------------------------------------------------

from hvac_scanner import bacnet  # noqa: E402
from collections import deque  # noqa: E402
import time  # noqa: E402


def test_the_wait_adapts_to_how_fast_a_device_answers():
    c = bacnet.BACnetClient(timeout=5.0)
    assert c.timeout_for("10.0.0.5") == 5.0                      # nothing known yet
    c._reply_times["10.0.0.5"] = deque([0.02, 0.03], maxlen=16)
    assert c.timeout_for("10.0.0.5") == 5.0                      # not enough yet
    c._reply_times["10.0.0.5"].append(0.02)
    assert c.timeout_for("10.0.0.5") == 1.0                      # floor
    c._reply_times["10.0.0.5"].append(0.6)
    assert c.timeout_for("10.0.0.5") == pytest.approx(2.4)       # 4 x slowest
    c._reply_times["10.0.0.5"].append(2.0)
    assert c.timeout_for("10.0.0.5") == 5.0                      # never past the setting
    assert bacnet.BACnetClient(timeout=0.5).timeout_for("x") == 0.5


def test_a_lossy_controller_costs_a_second_per_drop_not_the_timeout(mock_client_v211):
    """Four controllers on one site lost ~45% of requests and hit the 3-minute
    limit at 5 s a loss."""
    n = 300
    with __import__("tests.mock_device", fromlist=["MockBACnetDevice"]).MockBACnetDevice(
            n_objects=n, rpm_mode='full', max_apdu=480, drop_rpm={5, 6}) as dev:
        client = mock_client_v211(timeout=4.0)
        began = time.monotonic()
        got = client.read_object_list_entries_indexed(
            '127.0.0.1', 1234, list(range(1, n + 1)), max_apdu=dev.max_apdu)
        took = time.monotonic() - began
    assert [i for i, _ in got] == list(range(1, n + 1))
    assert took < 4.0, took                  # two drops at 4 s each would be 8 s
    assert 1.5 < client.lost_wait('127.0.0.1') < 3.0


@pytest.fixture
def mock_client_v211(monkeypatch):
    def _open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        s.bind(("", 0))
        self._sock, self._bound_port = s, s.getsockname()[1]
        return self._bound_port
    monkeypatch.setattr(bacnet.BACnetClient, "open", _open)
    made = []

    def _make(timeout=1.0):
        c = bacnet.BACnetClient(timeout=timeout)
        c.open()
        made.append(c)
        return c
    yield _make
    for c in made:
        c.close()
