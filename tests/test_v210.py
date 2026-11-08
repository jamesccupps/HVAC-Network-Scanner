"""2.10: the in-app updater (signed manifest, verified download, swap) and
the signing tool. Network-free: every source is a local folder."""
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))

from hvac_scanner import __version__, ed25519, updater  # noqa: E402
import signing  # noqa: E402


@pytest.fixture(autouse=True)
def _own_settings_folder(tmp_path, monkeypatch):
    """The update log lives in the settings folder: keep it out of the real one."""
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

# RFC 8032, section 7.1, tests 1-3: (secret key, public key, message, signature).
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
     "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
     "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed,pub,msg,sig", RFC)
def test_rfc8032_vectors(seed, pub, msg, sig):
    s, m = bytes.fromhex(seed), bytes.fromhex(msg)
    assert ed25519.public_key(s).hex() == pub
    assert ed25519.sign(s, m).hex() == sig
    assert ed25519.verify(bytes.fromhex(pub), m, bytes.fromhex(sig))
    bad = bytearray(bytes.fromhex(sig))
    bad[0] ^= 1
    assert not ed25519.verify(bytes.fromhex(pub), m, bytes(bad))


def test_the_built_in_key_is_a_real_key():
    key = base64.b64decode(updater.UPDATE_PUBLIC_KEY, validate=True)
    assert len(key) == 32 and ed25519._decompress(key) is not None


# -- a throwaway signing key and a release folder ---------------------------

SEED = bytes(range(32))
PUB = base64.b64encode(ed25519.public_key(SEED)).decode()


def _release(folder: Path, version: str, exe: bytes = b"MZ new exe " * 100) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / updater.EXE_NAME).write_bytes(exe)
    (folder / updater.MANIFEST_NAME).write_text(
        signing.manifest(folder, version, SEED), encoding="utf-8")
    return folder


def _resign(folder: Path, payload: dict, seed: bytes = SEED) -> None:
    raw = json.dumps(payload).encode()
    (folder / updater.MANIFEST_NAME).write_text(json.dumps({
        "payload": base64.b64encode(raw).decode(),
        "signature": base64.b64encode(ed25519.sign(seed, raw)).decode()}), encoding="utf-8")


def test_signing_round_trip(tmp_path):
    rel = _release(tmp_path / "rel", "9.9.9")
    lines = signing.verify(rel, "9.9.9", public_key=PUB)
    assert lines[-1].startswith("ok  latest.json  version 9.9.9")


def test_pem_round_trip():
    assert signing.seed_from_pem(signing.pem_from_seed(SEED)) == SEED


def test_check_finds_a_newer_release(tmp_path):
    rel = _release(tmp_path / "rel", "99.0.0")
    up = updater.check(current=__version__, source=str(rel), public_key=PUB)
    assert up.version == "99.0.0" and up.kind == "source" and not up.can_install


def test_check_is_quiet_when_up_to_date(tmp_path):
    rel = _release(tmp_path / "rel", __version__)
    assert updater.check(current=__version__, source=str(rel), public_key=PUB) is None


def test_the_built_in_key_refuses_a_manifest_signed_with_another(tmp_path):
    rel = _release(tmp_path / "rel", "99.0.0")
    with pytest.raises(updater.UpdateError, match="isn't signed"):
        updater.check(current=__version__, source=str(rel))


@pytest.mark.parametrize("change,message", [
    ({"app": "pingerplot"}, "another app"),
    ({"version": "3.0"}, "bad version"),
    ({"exe": {"file": "../evil.exe", "size": 5, "sha256": "0" * 64}}, "bad file name"),
    ({"exe": {"file": "HVACNetworkScanner.exe", "size": 10 ** 12, "sha256": "0" * 64}}, "bad size"),
    ({"exe": {"file": "HVACNetworkScanner.exe", "size": 5, "sha256": "xyz"}}, "bad sha256"),
])
def test_malformed_manifests_are_refused(tmp_path, change, message):
    rel = _release(tmp_path / "rel", "99.0.0")
    payload = {"app": updater.APP_KEY, "version": "99.0.0",
               "exe": {"file": updater.EXE_NAME, "size": 5, "sha256": "0" * 64}}
    payload.update(change)
    _resign(rel, payload)
    with pytest.raises(updater.UpdateError, match=message):
        updater.check(current=__version__, source=str(rel), public_key=PUB)


def test_a_tampered_payload_is_refused(tmp_path):
    rel = _release(tmp_path / "rel", "99.0.0")
    outer = json.loads((rel / updater.MANIFEST_NAME).read_text(encoding="utf-8"))
    payload = json.loads(base64.b64decode(outer["payload"]))
    payload["version"] = "99.0.1"
    outer["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    (rel / updater.MANIFEST_NAME).write_text(json.dumps(outer), encoding="utf-8")
    with pytest.raises(updater.UpdateError, match="isn't signed"):
        updater.check(current=__version__, source=str(rel), public_key=PUB)


def _exe_update(rel: Path, version="99.0.0") -> updater.Update:
    m = updater.verify_manifest((rel / updater.MANIFEST_NAME).read_text(encoding="utf-8"), PUB)
    return updater.Update(version, m["published"], "exe", m["exe"], str(rel))


def test_download_checks_size_and_hash(tmp_path):
    rel = _release(tmp_path / "rel", "99.0.0", exe=b"x" * 5000)
    got = updater.download(_exe_update(rel), dest_dir=tmp_path / "dl")
    assert got.read_bytes() == b"x" * 5000


def test_a_swapped_file_is_deleted_not_kept(tmp_path):
    rel = _release(tmp_path / "rel", "99.0.0", exe=b"x" * 5000)
    up = _exe_update(rel)
    (rel / updater.EXE_NAME).write_bytes(b"y" * 5000)          # same size, other bytes
    with pytest.raises(updater.UpdateError, match="doesn't match"):
        updater.download(up, dest_dir=tmp_path / "dl")
    assert not any((tmp_path / "dl").iterdir())


def test_a_longer_file_is_cut_off(tmp_path):
    rel = _release(tmp_path / "rel", "99.0.0", exe=b"x" * 5000)
    up = _exe_update(rel)
    (rel / updater.EXE_NAME).write_bytes(b"x" * 9000)
    with pytest.raises(updater.UpdateError, match="bigger"):
        updater.download(up, dest_dir=tmp_path / "dl")


def test_asset_comes_from_the_manifests_own_tag():
    src = updater.DEFAULT_SOURCE
    assert updater.asset_location(src, "2.10.0", updater.EXE_NAME) == (
        f"https://github.com/{updater.REPO}/releases/download/v2.10.0/{updater.EXE_NAME}")


# -- the swap ------------------------------------------------------------------

def test_swap_puts_the_new_exe_in_place_and_keeps_the_old(tmp_path):
    target, new = tmp_path / "app" / updater.EXE_NAME, tmp_path / "new.exe"
    target.parent.mkdir()
    target.write_bytes(b"old")
    new.write_bytes(b"new")
    updater.swap_in(target, new)
    assert target.read_bytes() == b"new"
    assert updater.old_copy(target).read_bytes() == b"old"
    updater.cleanup_after_update(target)
    assert not updater.old_copy(target).exists()
    # The update test (packaging/test_update.ps1) waits for this line.
    assert f"update: {__version__} started" in updater.update_log().read_text(encoding="utf-8")


def test_a_failed_swap_puts_the_old_exe_back(tmp_path, monkeypatch):
    target, new = tmp_path / "app" / updater.EXE_NAME, tmp_path / "new.exe"
    target.parent.mkdir()
    target.write_bytes(b"old")
    new.write_bytes(b"new")

    def broken_copy(*_a, **_kw):
        target.write_bytes(b"ne")                  # half a file, then the failure
        raise OSError("disk full")
    monkeypatch.setattr(updater.shutil, "copy2", broken_copy)
    with pytest.raises(OSError):
        updater.swap_in(target, new)
    assert target.read_bytes() == b"old"
    assert not updater.old_copy(target).exists()


def test_finish_update_swaps_then_starts_the_new_one(tmp_path, monkeypatch):
    target, new = tmp_path / "app" / updater.EXE_NAME, tmp_path / "new.exe"
    target.parent.mkdir()
    target.write_bytes(b"old")
    new.write_bytes(b"new")
    started = []
    monkeypatch.setattr(updater, "_spawn", lambda args, cwd: started.append(args))
    monkeypatch.setattr(updater, "_ulog", lambda msg, path=None: None)
    gone = 2 ** 22 + 12345                          # no such process: already exited
    assert updater.finish_update(target, gone, new_exe=new) == 0
    assert target.read_bytes() == b"new"
    assert started == [[target, "--updated"]]


def test_finish_update_reports_failure_and_starts_the_old_one(tmp_path, monkeypatch):
    target, new = tmp_path / "app" / updater.EXE_NAME, tmp_path / "missing.exe"
    target.parent.mkdir()
    target.write_bytes(b"old")
    started = []
    monkeypatch.setattr(updater, "_spawn", lambda args, cwd: started.append(args))
    monkeypatch.setattr(updater, "_ulog", lambda msg, path=None: None)
    assert updater.finish_update(target, 2 ** 22 + 12345, new_exe=new) == 1
    assert target.read_bytes() == b"old"
    assert started == [[target, "--update-failed"]]


def test_gui_update_arguments(monkeypatch):
    from hvac_scanner import gui
    calls = []
    monkeypatch.setattr(updater, "finish_update",
                        lambda t, p, restart=True: calls.append((t, p, restart)) or 0)
    monkeypatch.setattr(updater, "cleanup_after_update", lambda: calls.append("clean"))
    assert gui._update_args(["x", "--finish-update", "C:/a.exe", "42"]) == (0, None)
    assert gui._update_args(["x", "--finish-update", "C:/a.exe", "42", "--no-restart"]) == (0, None)
    assert gui._update_args(["x", "--updated"])[1].startswith("Updated to")
    assert "could not be installed" in gui._update_args(["x", "--update-failed"])[1]
    assert gui._update_args(["x"]) == (None, None)
    assert calls == [("C:/a.exe", "42", True), ("C:/a.exe", "42", False), "clean"]


# -- what the user's first real scan asked for --------------------------------

def _dev(ip, model, points, protocol='BACnet/IP'):
    return {'protocol': protocol, 'ip': ip, 'instance': int(ip.split('.')[-1]),
            'properties': {'model_name': model, 'object_name': f"RM{ip.split('.')[-1]}"},
            'objects': points}


def test_repeated_faults_on_identical_controllers_are_one_row():
    from hvac_scanner.report import build_findings
    unused = {'type': 'Analog Value', 'instance': 50, 'name': 'RM DCV EVAL',
              'present_value': '0', 'units': 'ppm', 'status': 'fault'}
    real = {'type': 'Analog Input', 'instance': 1, 'name': 'ZN-T',
            'present_value': '-40', 'units': 'degF', 'status': 'fault'}
    devs = [_dev(f"10.0.0.{i}", "DXR2.E10PL-1", [dict(unused)]) for i in range(10, 20)]
    devs[0]['objects'].append(real)
    f = next(f for f in build_findings({'devices': devs}) if f.title == "Points in alarm or fault")
    assert len(f.rows) == 2
    assert "10 devices" in f.rows[0][1] and "and 7 more" in f.rows[0][0]
    assert f.rows[1][0] == "10.0.0.10" and f.rows[1][3] == "ZN-T"


def test_identical_knx_gateways_are_one_row():
    from hvac_scanner.report import build_findings
    devs = [{'protocol': 'KNXnet/IP', 'ip': f"10.0.0.{i}", 'name': 'KNX/IP Tunneling Desigo TRA',
             'knx_address': '0.2.251', 'tunnelling': True, 'secure': False} for i in range(5)]
    f = next(f for f in build_findings({'devices': devs}) if "KNX Secure" in f.title)
    assert len(f.rows) == 1 and "5 gateways" in f.rows[0][1]


def test_report_says_when_47808_was_taken_and_where_others_answered():
    from hvac_scanner.report import render_html
    scan = {'devices': [], 'coverage': {'stopped': False, 'passes': {'bacnet': 'scanned'},
                                        'options': {}, 'bacnet_port': 55789,
                                        'outside_targets': {'10.0.1.0/24': 110, '10.0.2.0/24': 3}}}
    page = render_html(scan)
    assert "ran on UDP port 55789" in page
    assert "113 device(s) answered from outside the targets" in page
    assert "10.0.1.0/24 (110)" in page


def test_engine_records_where_out_of_range_devices_answered(monkeypatch):
    from hvac_scanner import engine as engine_mod
    from hvac_scanner.engine import ScanEngine, ScanOptions

    class Client:
        _bound_port = 55789

        def __init__(self, *a, **kw):
            pass

        def open(self):
            pass

        def close(self):
            pass

        def discover_who_is(self, *a, **kw):
            return [{'ip': '10.0.1.7', 'instance': 1}, {'ip': '10.0.1.8', 'instance': 2},
                    {'ip': '10.0.0.5', 'instance': 3}]

        def read_bbmd_tables(self, *a, **kw):
            return {}

    lines = []
    monkeypatch.setattr(engine_mod, "BACnetClient", Client)
    eng = ScanEngine(ScanOptions(networks=['10.0.0.0/24'], scan_mstp=False, deep_scan=False,
                                 scan_modbus=False, scan_services=False, scan_snmp=False,
                                 scan_p2=False, scan_knx=False, scan_lon=False, scan_gateways=False, unicast_discovery='off'),
                     callback=lines.append)
    result = eng.run()
    cov = result.to_dict()['coverage']
    assert cov['bacnet_port'] == 55789
    assert cov['outside_targets'] == {'10.0.1.0/24': 2}
    assert any("Answered from outside the targets" in l and "10.0.1.0/24 (2)" in l
               for l in lines)


def test_gui_finds_and_offers_an_update(gui_app, tmp_path, monkeypatch):
    rel = _release(tmp_path / "rel", "99.0.0")
    monkeypatch.setenv(updater.SOURCE_ENV, str(rel))
    monkeypatch.setattr(updater, "UPDATE_PUBLIC_KEY", PUB)
    monkeypatch.setattr("hvac_scanner.updater.verify_manifest.__defaults__", (PUB,), raising=False)
    gui_app._update_event('update-found', (updater.check(public_key=PUB), False))
    assert gui_app.update_btn.cget('text') == "Update to 99.0.0"


def test_gui_update_click_downloads_installs_and_closes(gui_app, tmp_path, monkeypatch):
    """The path a click on "Update to …" takes in the packaged app, up to the
    hand-over to the new exe (packaging/test_update.ps1 covers the rest)."""
    from hvac_scanner import gui as gui_mod
    rel = _release(tmp_path / "rel", "99.0.0")
    monkeypatch.setattr(updater, "install_kind", lambda: "exe")
    up = updater.check(source=str(rel), public_key=PUB)
    gui_app.auto_update_var.set(False)          # 2.13 installs by itself; this is the click
    gui_app._update_event('update-found', (up, False))
    asked, applied, later = [], [], []
    monkeypatch.setattr(gui_mod.messagebox, "askyesno", lambda *a, **k: asked.append(a) or True)
    monkeypatch.setattr(updater, "staging_dir", lambda v: tmp_path / "staging")
    monkeypatch.setattr(updater, "apply", lambda u, p: applied.append((u.version, p)))
    monkeypatch.setattr(gui_app.root, "after", lambda ms, fn: later.append(fn))
    gui_app._update_clicked()
    kinds = []
    while 'update-ready' not in kinds:
        kind, payload = gui_app._events.get(timeout=10)
        kinds.append(kind)
        assert kind != 'update-error', payload
        gui_app._update_event(kind, payload)
    assert asked and "99.0.0" in asked[0][1]
    assert 'update-progress' in kinds
    assert applied == [("99.0.0", tmp_path / "staging" / updater.EXE_NAME)]
    assert (tmp_path / "staging" / updater.EXE_NAME).read_bytes() == \
        (rel / updater.EXE_NAME).read_bytes()
    assert gui_app.root.destroy in later


# -- from the user's second real-site scan ------------------------------------

import socket  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402

from hvac_scanner import bacnet, codec  # noqa: E402

from .mock_device import MockBACnetDevice  # noqa: E402

_IAM_APDU = bytes([0x10, 0x00, 0xC4, 0x02, 0x00, 0x03, 0xE9,   # device 1001
                   0x22, 0x05, 0xC4, 0x91, 0x03, 0x21, 0x02])


def _iam(origin=None):
    """An I-Am, direct or relayed by a BBMD from `origin`."""
    if origin is None:
        return codec.build_bvlc(0x0B, b'\x01\x00' + _IAM_APDU)
    body = socket.inet_aton(origin) + struct.pack('!H', 47808) + b'\x01\x00' + _IAM_APDU
    return codec.build_bvlc(codec.BVLC_FORWARDED_NPDU, body)


def test_an_iam_relayed_by_a_bbmd_is_marked_relayed():
    assert codec.parse_iam(_iam("10.0.1.83"), ("10.0.0.108", 47808)).relayed
    assert not codec.parse_iam(_iam(), ("10.0.1.83", 47808)).relayed


def test_a_device_heard_directly_as_well_counts_as_direct():
    class Sock:
        def __init__(self, packets):
            self.packets = packets

        def gettimeout(self):
            return 1.0

        def settimeout(self, t):
            pass

        def recvfrom(self, n):
            if not self.packets:
                raise socket.timeout()
            return self.packets.pop(0)

    c = bacnet.BACnetClient(timeout=0.2)
    c._sock = Sock([(_iam("10.0.1.83"), ("10.0.0.108", 47808)),
                    (_iam(), ("10.0.1.83", 47808))])
    devs = c._collect_iam(time.time() + 1)
    assert [(d['ip'], d['relayed']) for d in devs] == [("10.0.1.83", False)]


def test_silent_addresses_on_another_subnet_are_probed_whatever_answered():
    """Answers from another subnet do not show a broadcast covers it. The
    quick scan heard 83 of 112 controllers on 10.0.1.x through the BBMD and
    skipped the other 29; a later one heard only the BBMD itself, which
    answers directly, and skipped all 112."""
    from hvac_scanner.engine import ScanEngine, ScanOptions

    class Client:
        probed = None

        def discover_unicast(self, ips, stop_fn=None):
            Client.probed = list(ips)
            return []

    eng = ScanEngine(ScanOptions(networks=["10.0.1.198-202"]), callback=lambda m: None)
    eng._is_local = lambda ip: False
    seen = {("10.0.1.200", 112000)}                       # the BBMD, answering directly
    eng._discover_unicast(Client(), set(eng._target_ips_in_order()), seen)
    assert Client.probed == ["10.0.1.198", "10.0.1.199", "10.0.1.201", "10.0.1.202"]


@pytest.fixture
def mock_client(monkeypatch):
    def _open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        s.bind(("", 0))
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


def test_object_list_rides_out_a_burst_of_lost_batches(mock_client):
    """10.0.1.83, .84 and .89 dropped to one read per index after lost
    batches and took minutes each. Once batches have worked, silence is a
    lost packet: ask again, shrink only if that fails too, grow back."""
    n = 300
    with MockBACnetDevice(n_objects=n, rpm_mode='full', drop_rpm={2, 3, 4, 5, 6, 7}) as dev:
        got = mock_client().read_object_list_entries_indexed(
            '127.0.0.1', 1234, list(range(1, n + 1)), max_apdu=dev.max_apdu)
    assert [i for i, _ in got] == list(range(1, n + 1))
    assert dev.single_reads == 0
    assert dev.rpm_requests <= 14


def test_object_list_still_falls_back_when_batches_never_work(mock_client):
    n = 40
    with MockBACnetDevice(n_objects=n, rpm_mode='full', drop_rpm=range(1, 1000)) as dev:
        got = mock_client().read_object_list_entries_indexed(
            '127.0.0.1', 1234, list(range(1, n + 1)), max_apdu=dev.max_apdu)
    assert [i for i, _ in got] == list(range(1, n + 1))
    assert dev.rpm_requests <= 6            # halved down, no extra asks


def test_point_batches_stay_on_after_a_burst_of_lost_batches(mock_client):
    with MockBACnetDevice(n_objects=60, rpm_mode='full', drop_rpm={2, 3, 4, 5}) as dev:
        objs = [(t, i, ['objectName', 'presentValue']) for t, i in dev.objects]
        out = mock_client().read_points_batched('127.0.0.1', 1234, objs)
    assert all(props.get('objectName') for _t, _i, props in out)
    assert dev.single_reads == 0


def test_progress_names_the_devices_a_deep_scan_is_waiting_on():
    """The normal scan sat at 180 / 183 for minutes with nothing saying why."""
    import threading
    from hvac_scanner.engine import ScanEngine, ScanOptions
    release = threading.Event()
    phases, lines = [], []
    eng = ScanEngine(ScanOptions(networks=["10.0.0.0/24"], bacnet_workers=4),
                     callback=lines.append,
                     progress_callback=lambda p, d, t: phases.append((p, d, t)))

    def deep_read(client, dev, buffered=False):
        if dev['ip'] == "10.0.0.83":
            release.wait(10)

    eng._deep_read = deep_read
    devs = [{'ip': f"10.0.0.{i}", 'instance': i, 'protocol': 'BACnet/IP'} for i in range(80, 90)]
    t = threading.Thread(target=eng._deep_scan_devices, args=(None, devs))
    t.start()
    for _ in range(100):
        if any(d == 9 for _p, d, _t in phases):
            break
        time.sleep(0.05)
    release.set()
    t.join(10)
    assert ("BACnet deep scan · still reading 10.0.0.83", 9, 10) in phases
    assert any(l.startswith("  Still reading 10.0.0.83 (") for l in lines)
    assert phases[-1] == ("BACnet deep scan", 10, 10)


def test_a_router_heard_directly_and_through_a_bbmd_is_listed_once():
    msg = bytes([0x01, 0x80, 0x01, 0x00, 0x6A])            # I-Am-Router-To-Network 106
    direct = codec.build_bvlc(0x0B, msg)
    relayed = codec.build_bvlc(codec.BVLC_FORWARDED_NPDU,
                               socket.inet_aton("10.0.1.100") + struct.pack('!H', 47808) + msg)

    class Sock:
        packets = [(direct, ("10.0.1.100", 47808)), (relayed, ("10.0.0.108", 47808))]

        def sendto(self, *a):
            pass

        def gettimeout(self):
            return 1.0

        def settimeout(self, t):
            pass

        def recvfrom(self, n):
            if not self.packets:
                raise socket.timeout()
            return self.packets.pop(0)

    lines = []
    c = bacnet.BACnetClient(timeout=0.2, callback=lines.append)
    c._sock = Sock()
    routers, nets = c.discover_routers("10.0.0.255")
    assert [(r['ip'], r['networks']) for r in routers] == [("10.0.1.100", [106])]
    assert nets == [106]
    assert sum("Router at 10.0.1.100" in l for l in lines) == 1


@pytest.mark.parametrize("vendor_id,vendor,model,firmware,instance,apdu,kind,words", [
    (7, "Siemens Schweiz", "DXR2.E12P-1", "v01.21", 107003, 1476, "Field Controller", "pressure sensor"),
    (7, "Siemens Schweiz", "DXR2.E10PL-1", "v01.21", 102002, 1476, "Field Controller", "damper actuator"),
    (7, "Siemens Schweiz", "DXR2.E18-1", "v01.21", 104028, 1476, "Field Controller", "18 I/O"),
    (7, "Siemens Schweiz", "Siemens BACnet Field Panel", "PXME V3.5.5 BACnet 4.3g", 112000, 1476,
     "Automation Station", "PXC Modular"),
    (7, "Siemens Schweiz", "Insight", "", 9997, 1476, "Management Station", "Insight"),
    (7, "Siemens Schweiz", "PXC5.E24.A", "", 107100, 1476, "Automation Station", "Desigo PXC5"),
    (2, "The Trane Company", "TES Workstation", "", 125, 1476, "Management Station", "Tracer Ensemble"),
    (2, "The Trane Company", "TR200", "", 5, 480, "Variable Frequency Drive", "TR200"),
    (141, "Yaskawa America", "HV60U", "", 6, 480, "Variable Frequency Drive", "HV600"),
])
def test_devices_are_named_for_what_their_model_says(vendor_id, vendor, model, firmware,
                                                      instance, apdu, kind, words):
    """A second site showed the naming leaned on the first site's numbering:
    a Tracer Ensemble server was a "unitary controller", an Insight
    workstation a Desigo CC server, every DXR2 a "Desigo PXC" controller."""
    from hvac_scanner.device_profiles import classify_device
    from hvac_scanner.fingerprint import fingerprint_device
    fp = fingerprint_device({'ip': '10.0.0.5', 'vendor_id': vendor_id, 'vendor_name': vendor,
                             'instance': instance, 'max_apdu': apdu, 'protocol': 'BACnet/IP',
                             'properties': {'model_name': model, 'vendor_name': vendor,
                                            'firmware_revision': firmware}})
    assert fp['model'] == model
    assert fp['device_type'] == kind
    assert words in fp['description']
    assert 'PXC series' not in fp['description'] and 'unitary' not in fp['description']
    _profile, why = classify_device(vendor, model, 100)
    assert 'bath' not in why and 'heat pump' not in why


# -- faster scans and a log that says where the time went ----------------------

def test_devices_only_depth_reads_identity_and_nothing_else():
    from hvac_scanner.engine import ScanEngine, ScanOptions

    class Client:
        asked = []

        def read_device_info(self, ip, instance, **kw):
            Client.asked.append('info')
            return {'object_name': 'RM101', 'model_name': 'DXR2.E12P-1'}

        def __getattr__(self, name):            # anything else is a failure
            def nope(*a, **kw):
                Client.asked.append(name)
                raise AssertionError(f"devices-only scan called {name}")
            return nope

    eng = ScanEngine(ScanOptions(networks=["10.0.0.5"], scan_depth="devices"),
                     callback=lambda m: None)
    dev = {'ip': '10.0.0.5', 'instance': 5, 'protocol': 'BACnet/IP'}
    eng._deep_read_device(Client(), dev)
    assert Client.asked == ['info']
    assert dev['properties']['model_name'] == 'DXR2.E12P-1'
    assert not dev.get('objects')


def test_devices_only_is_offered_everywhere():
    from hvac_scanner import cli
    from hvac_scanner.device_profiles import SCAN_DEPTH_PRESETS, DeviceProfile, apply_scan_depth
    assert 'devices' in SCAN_DEPTH_PRESETS
    assert apply_scan_depth(DeviceProfile(object_cap=500, class_label="x"), "devices")[0].object_cap == 0
    args = cli._build_parser().parse_args(["10.0.0.5", "--scan-depth", "devices",
                                           "--device-time-limit", "60"])
    assert args.scan_depth == "devices" and args.device_time_limit == 60


def test_report_of_a_devices_only_scan_does_not_claim_zero_points():
    from hvac_scanner.report import render_html
    scan = {'devices': [], 'counts': {'points': 0},
            'coverage': {'stopped': False, 'passes': {'bacnet': 'scanned'},
                         'options': {'scan_depth': 'devices'}}}
    page = render_html(scan)
    assert "Devices-only scan" in page
    assert '<b>—</b><span>Points</span>' in page


def test_the_log_says_when_each_section_ran_and_where_the_time_went():
    from hvac_scanner.engine import ScanEngine, ScanOptions
    lines = []
    eng = ScanEngine(ScanOptions(networks=["10.0.0.5"]), callback=lines.append)
    title = eng._title("MODBUS TCP DISCOVERY")
    assert title.startswith("MODBUS TCP DISCOVERY  ·  ") and ", +" in title
    eng.result.seconds.update({'bacnet': 581.0, 'bacnet_deep': 552.0, 'mstp': 12.0,
                               'modbus': 4.2, 'snmp': 3.0})
    assert eng._timing_summary() == ("BACnet 9 min 41 s (deep scan 9 min 12 s, MS/TP 12 s), "
                                     "Modbus 4.2 s, SNMP 3.0 s")
    assert eng.result.to_dict()['coverage']['seconds']['modbus'] == 4.2


def test_a_device_that_drops_requests_is_named_and_cut_off_at_the_limit(mock_client):
    """10.0.1.81, .84 and .89 took minutes each and the log never said why."""
    from hvac_scanner.engine import ScanEngine, ScanOptions
    lines = []
    eng = ScanEngine(ScanOptions(networks=["127.0.0.1"], timeout=0.3, device_time_limit=1.5,
                                 read_metadata=False),
                     callback=lines.append)
    with MockBACnetDevice(n_objects=300, rpm_mode='full', drop_rpm=range(2, 10_000)) as dev:
        client = mock_client(timeout=0.3)
        d = {'ip': '127.0.0.1', 'instance': dev.instance, 'protocol': 'BACnet/IP',
             'max_apdu': 1476}
        began = time.monotonic()
        eng._deep_read(client, d)
        took = time.monotonic() - began
    assert took < 6, took
    assert d['requests']['unanswered'] >= 3
    assert "per-device time limit" in d['cut_short']
    footer = next(l for l in lines if l.startswith("    Took "))
    assert "requests went unanswered" in footer and "per-device time limit" in footer


def test_report_names_controllers_that_drop_requests_and_devices_cut_short():
    from hvac_scanner.report import build_findings, render_html
    devs = [{'ip': '10.0.1.84', 'instance': 1, 'protocol': 'BACnet/IP',
             'properties': {'object_name': 'RM7704'}, 'scan_seconds': 131.0,
             'requests': {'sent': 120, 'unanswered': 14}, 'cut_short': 'x'},
            {'ip': '10.0.1.85', 'instance': 2, 'protocol': 'BACnet/IP',
             'requests': {'sent': 120, 'unanswered': 1}}]
    f = next(f for f in build_findings({'devices': devs}) if f.title == "Controllers that drop requests")
    assert f.rows == [['10.0.1.84', f.rows[0][1], '14 of 120 (12%)', '2 min 11 s']]
    page = render_html({'devices': devs, 'coverage': {'stopped': False, 'passes': {}, 'options': {}}})
    assert "1 device(s) reached the per-device time limit" in page


def test_unicast_discovery_asks_silent_addresses_twice():
    """Each of two scans missed a different controller on a lossy link."""
    c = bacnet.BACnetClient(timeout=0.2)
    c._sock = object()
    calls = []

    def request_many(reqs, parser=None, stop_fn=None):
        ips = [ip for ip, _pkt, _inv in reqs]
        calls.append(ips)
        out = {'10.0.1.65': ('Device', 107025)}
        if len(calls) == 2:
            out['10.0.1.81'] = ('Device', 107001)        # answered only when asked again
        return {ip: v for ip, v in out.items() if ip in ips}

    c._request_many = request_many
    c._describe_found = lambda ip, inst, dnet=None: {'ip': ip, 'instance': inst}
    found = c.discover_unicast(['10.0.1.65', '10.0.1.81', '10.0.1.90'])
    assert sorted(d['instance'] for d in found) == [107001, 107025]
    assert calls[1] == ['10.0.1.81', '10.0.1.90']


def test_unicast_discovery_does_not_ask_again_when_nothing_answered():
    c = bacnet.BACnetClient(timeout=0.2)
    c._sock = object()
    calls = []
    c._request_many = lambda reqs, parser=None, stop_fn=None: calls.append(reqs) or {}
    assert c.discover_unicast(['10.0.9.1', '10.0.9.2']) == []
    assert len(calls) == 1
