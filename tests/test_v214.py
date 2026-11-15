"""2.14: fixes from the 2026-11-14 audit. Network-free."""
import hashlib
import os
import random
import stat
import struct

import pytest

from hvac_scanner import codec, limits
from hvac_scanner.engine import ScanEngine, ScanOptions, ScanResult

from .test_v291 import _cli


# -- a cut-off value from a device ------------------------------------------------

def test_a_cut_off_date_is_hex_not_an_error():
    # A Date tag declaring 4 octets, with only 1 in the packet.
    assert codec._parse_app_value(bytes.fromhex("a400"), 0)[0] == "00"
    for decoder in (codec.decode_weekly_schedule, codec.decode_routing_table,
                    codec.decode_recipient_list, codec.decode_property_references):
        assert decoder(bytes.fromhex("a400")) == []
    # Whole values still decode.
    assert codec._parse_app_value(bytes.fromhex("a47a0b0e02"), 0)[0] == "2022-11-14"
    assert codec._parse_app_value(bytes.fromhex("b40c1e00ff"), 0)[0] == "12:30:00"
    assert codec._parse_app_value(bytes.fromhex("c400800005"), 0)[0] == ("Analog Value", 5)


# Well-formed values to mutate: Date, Time, Object Identifier, Real, Double,
# a character string, a weekly schedule (Monday 06:00 on), a recipient and a
# property reference.
_SEEDS = [bytes.fromhex(h) for h in (
    "a47a0b0e02", "b40c1e00ff", "c402000005", "4442c80000", "55084059000000000000",
    "750500616263", "0eb4060000009101 0f".replace(" ", ""),
    "8201fe b400000000 b4173b3b63 0c02000001 21 01 1001 8201e0".replace(" ", ""),
    "0c00000001 1955 2902 3c02000064".replace(" ", ""),
)]


def _inputs(seed: int, n: int):
    rnd = random.Random(seed)
    for s in _SEEDS:
        for cut in range(len(s)):
            yield s[:cut]                                  # every truncation
    for _ in range(n):
        if rnd.random() < 0.5:
            yield bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 48)))
        else:
            b = bytearray(rnd.choice(_SEEDS))
            for _ in range(rnd.randrange(1, 4)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            yield bytes(b[:rnd.randrange(1, len(b) + 1)])


@pytest.mark.parametrize("name", ["decode_weekly_schedule", "decode_routing_table",
                                  "decode_recipient_list", "decode_property_references"])
def test_metadata_decoders_never_raise(name):
    decoder = getattr(codec, name)
    for data in _inputs(214, 3000):
        decoder(data)                                      # any exception fails the test


def test_value_parser_raises_only_its_own_errors():
    for data in _inputs(1114, 3000):
        if not data:
            continue
        try:
            codec._parse_app_value(data, 0)
        except (codec.BACnetParseError, IndexError, struct.error):
            pass                                           # the callers catch these


@pytest.mark.parametrize("parse", [
    codec.parse_read_property_ack, codec.parse_read_property_ack_raw,
    codec.parse_read_property_multiple_ack_full, codec.parse_iam_router,
    codec.parse_bvlc_result, codec.parse_read_bdt_ack, codec.parse_read_fdt_ack,
    lambda d: codec.parse_iam(d, ("192.0.2.10", 47808)),
    lambda d: codec.parse_read_property_multiple_ack(d, [85, 77]),
])
def test_reply_parsers_never_raise(parse):
    rnd = random.Random(47808)
    heads = [bytes.fromhex(h) for h in ("810a0000010030010c", "810a000001003001 0e".replace(" ", ""),
                                        "810b000c0120ffff00", "8100000c")]
    for data in _inputs(4780, 1500):
        head = rnd.choice(heads)
        parse(head + data)
        parse(data)


# -- one bad object costs only itself ---------------------------------------------

def test_one_bad_metadata_object_leaves_the_others():
    logs = []
    engine = ScanEngine(ScanOptions(networks=[]), callback=logs.append)
    dev = {'ip': '192.0.2.10', 'instance': 7, 'objects': []}
    meta = [
        ('Trend Log', 1, {'objectName': 'TL-1', 'logInterval': 'garbled'}),   # raises inside
        ('Notification Class', 2, {'objectName': 'NC-2', 'priority': [1, 2, 3]}),
        ('Schedule', 3, {'objectName': 'SCH-3', 'weeklySchedule': bytes.fromhex("a400")}),
    ]
    engine._apply_metadata(dev, meta)
    assert [a['name'] for a in dev['notification_classes']] == ['NC-2']
    assert [s['name'] for s in dev['schedules']] == ['SCH-3']
    assert 'trend_logs' not in dev
    assert any("Could not decode 1 trend log" in m and "device 7" in m for m in logs)


# -- number options: one table, finite, bounded ------------------------------------

@pytest.mark.parametrize("option,text", [
    ("timeout", "nan"), ("timeout", "inf"), ("timeout", "1e999"), ("timeout", "0.05"),
    ("timeout", "301"), ("bacnet_workers", "100000"), ("rate_limit_ms", "99999999999"),
    ("max_objects_per_device", "0"), ("device_time_limit", "-1"), ("whois_chunk_size", "abc"),
])
def test_limits_refuse_what_cannot_be_meant(option, text):
    with pytest.raises(ValueError):
        limits.parse(option, text, "x")


def test_limits_accept_the_usual_values():
    assert limits.parse("timeout", "5", "Timeout") == 5.0
    assert limits.parse("bacnet_workers", " 64 ", "Workers") == 64
    assert limits.parse("device_time_limit", "0", "Limit") == 0.0


@pytest.mark.parametrize("argv", [
    ["127.0.0.1", "--timeout", "nan"], ["127.0.0.1", "--timeout", "inf"],
    ["127.0.0.1", "--timeout", "1e308"], ["127.0.0.1", "--device-time-limit", "nan"],
    ["127.0.0.1", "--rate-limit", "99999999999"], ["127.0.0.1", "--whois-chunk", "-1"],
])
def test_cli_refuses_non_finite_and_huge_numbers(monkeypatch, argv):
    with pytest.raises(SystemExit) as e:
        _cli(monkeypatch, argv, ScanResult())
    assert e.value.code == 1


def test_profiles_take_the_same_bounds():
    from hvac_scanner.settings import profile_options
    got = profile_options({'targets': '127.0.0.1', 'advanced': {
        'timeout': 'inf', 'workers': '100000', 'rate_limit': '50', 'max_objects': '1e999'}})
    assert got['rate_limit_ms'] == 50
    assert not {'timeout', 'bacnet_workers', 'max_objects_per_device'} & got.keys()


@pytest.mark.parametrize("field,text", [
    ("timeout_entry", "nan"), ("timeout_entry", "1e999"), ("workers_entry", "99999999999"),
    ("rate_limit_entry", "99999999999"), ("device_limit_entry", "inf"),
])
def test_window_refuses_the_same_numbers(gui_app, field, text):
    gui_app.network_entry.delete(0, "end")
    gui_app.network_entry.insert(0, "127.0.0.1")
    entry = getattr(gui_app, field)
    entry.delete(0, "end")
    entry.insert(0, text)
    assert gui_app._build_options() is None
    assert str(entry.cget("style")) == "Error.TEntry"


def test_window_refuses_an_unknown_unicast_mode(gui_app):
    gui_app.network_entry.delete(0, "end")
    gui_app.network_entry.insert(0, "127.0.0.1")
    gui_app.adv_vars['unicast'].set("abc")                 # a damaged settings file
    assert gui_app._build_options() is None
    gui_app.adv_vars['unicast'].set("off")
    assert gui_app._build_options().unicast_discovery == "off"


def test_a_marked_field_is_cleared_once_it_checks_out(gui_app):
    gui_app.network_entry.delete(0, "end")
    gui_app.network_entry.insert(0, "not a network")
    assert gui_app._build_options() is None
    assert str(gui_app.network_entry.cget("style")) == "Error.TEntry"
    gui_app.network_entry.delete(0, "end")                 # no key press: a paste
    gui_app.network_entry.insert(0, "127.0.0.1")
    assert gui_app._build_options() is not None
    assert str(gui_app.network_entry.cget("style")) == "TEntry"


# -- public addresses ---------------------------------------------------------------

def test_public_targets_are_named():
    from hvac_scanner.netrange import public_targets
    assert public_targets("10.0.0.0/24, 192.168.1.5, 127.0.0.1, 172.16.0.2-20") == []
    assert public_targets("192.0.2.0/24 198.51.100.7 203.0.113.1-9 100.64.0.1") == []
    assert public_targets("10.0.0.0/24, 8.8.8.0/30, 1.1.1.1") == ["8.8.8.0/30", "1.1.1.1"]
    assert public_targets("not-a-target") == []


def test_cli_refuses_public_targets_without_the_flag(monkeypatch, capsys):
    code, made = _cli(monkeypatch, ["8.8.8.8"], ScanResult())
    assert code == 1 and not made
    assert "--allow-public" in capsys.readouterr().err
    code, made = _cli(monkeypatch, ["8.8.8.8", "--allow-public"], ScanResult())
    assert code == 0 and made[0].networks == ["8.8.8.8"]
    code, made = _cli(monkeypatch, ["127.0.0.1"], ScanResult())
    assert code == 0


def test_window_asks_once_before_public_targets(gui_app, monkeypatch):
    from tkinter import messagebox
    asked = []
    answer = [False]
    monkeypatch.setattr(messagebox, "askyesno",
                        lambda title, text, **kw: asked.append(text) or answer[0])
    assert gui_app._confirm_public(["127.0.0.1"]) and not asked
    assert not gui_app._confirm_public(["8.8.8.8"]) and "8.8.8.8" in asked[0]
    assert "public" in gui_app.status_var.get()
    answer[0] = True
    assert gui_app._confirm_public(["8.8.8.8"]) and len(asked) == 2
    assert gui_app._confirm_public(["8.8.8.8"]) and len(asked) == 2     # not asked again


# -- the window: Show points and the filters ------------------------------------------

def _bacnet(ip, inst, name, points=3):
    return {'ip': ip, 'instance': inst, 'protocol': 'BACnet/IP', 'vendor_name': 'V',
            'properties': {'object_name': name}, '_fingerprint': {},
            'objects': [{'type': 'Analog Input', 'instance': i, 'name': f'{name}-P{i}',
                         'present_value': '1', 'units': '', 'description': ''}
                        for i in range(points)]}


def _modbus(ip):
    return {'ip': ip, 'port': 502, 'unit_id': 1, 'protocol': 'Modbus TCP', 'vendor': 'Acme',
            'objects': [], 'properties': {}, '_fingerprint': {},
            'holding_registers': [{'register': 0, 'value': 1, 'hex': '0x0001'}],
            'input_registers': [],
            'coils': []}


def _select_device(app, ip):
    for iid in app.device_tree.get_children():
        if app.device_tree.set(iid, 'ip') == ip:
            app.device_tree.selection_set(iid)
            return
    raise AssertionError(f"no row for {ip}")


def test_show_points_opens_the_right_tab_and_leaves_devices_listed(gui_app):
    gui_app._stream_device(_bacnet('127.0.0.2', 1, 'SC-1'))
    gui_app._stream_device(_bacnet('127.0.0.3', 2, 'VAV-7'))
    gui_app._stream_device(_modbus('127.0.0.20'))
    gui_app.root.update()
    _select_device(gui_app, '127.0.0.20')
    gui_app._ctx_show_points()
    assert gui_app.notebook.select() == str(gui_app._registers_tab)
    _select_device(gui_app, '127.0.0.2')
    gui_app._ctx_show_points()
    gui_app.root.update()
    assert gui_app.notebook.select() == str(gui_app._points_tab)
    assert len(gui_app.points_tree.get_children()) == 3                  # SC-1's only
    # Back on Devices: every device, and the box holds that tab's (empty) filter.
    gui_app.notebook.select(0)
    gui_app.root.update()
    assert gui_app.filter_var.get() == ""
    assert len(gui_app.device_tree.get_children()) == 3
    # And the points keep theirs.
    gui_app.notebook.select(gui_app._points_tab)
    gui_app.root.update()
    assert "SC-1" in gui_app.filter_var.get()


def test_filter_clear_button_and_escape(gui_app):
    gui_app._stream_device(_bacnet('127.0.0.2', 1, 'SC-1'))
    gui_app.root.update()
    gui_app.filter_var.set("nothing-matches")
    gui_app._apply_filter()
    gui_app.root.update()
    assert gui_app.filter_clear.winfo_manager() == "pack"
    assert len(gui_app.device_tree.get_children()) == 0
    gui_app.filter_clear.invoke()
    gui_app._apply_filter()
    assert gui_app.filter_clear.winfo_manager() == ""
    assert len(gui_app.device_tree.get_children()) == 1
    gui_app.filter_var.set("x")
    assert gui_app._on_filter_escape() == "break" and gui_app.filter_var.get() == ""
    assert gui_app._on_filter_escape() is None                           # empty: Esc stops a scan


# -- settings file, staged update, version ----------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")
def test_settings_are_saved_for_the_owner_only(tmp_path):
    from hvac_scanner import settings
    path = tmp_path / "cfg" / "settings.json"
    settings.save(path, {'targets': '127.0.0.1'})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_settings_still_round_trip(tmp_path):
    from hvac_scanner import settings
    path = tmp_path / "cfg" / "settings.json"
    settings.save(path, {'targets': '127.0.0.1', 'note': 'caf\u00e9'})
    assert settings.load(path) == {'targets': '127.0.0.1', 'note': 'caf\u00e9'}
    assert b"\r\r" not in path.read_bytes()


def test_a_staged_update_changed_since_its_check_is_not_installed(tmp_path, monkeypatch):
    from hvac_scanner import updater
    spawned = []
    monkeypatch.setattr(updater, "_spawn", lambda args, cwd: spawned.append(args))
    monkeypatch.setattr(updater, "current_exe", lambda: tmp_path / "app" / updater.EXE_NAME)
    (tmp_path / "app").mkdir()
    new = tmp_path / "staging" / updater.EXE_NAME
    new.parent.mkdir()
    new.write_bytes(b"checked")
    asset = {"file": updater.EXE_NAME, "size": 7, "sha256": hashlib.sha256(b"checked").hexdigest()}
    up = updater.Update("99.0.0", None, "exe", asset, "x")
    new.write_bytes(b"swapped")                              # same size, other bytes
    with pytest.raises(updater.UpdateError):
        updater.apply(up, new, restart=False)
    new.unlink()
    with pytest.raises(updater.UpdateError):
        updater.apply(up, new, restart=False)
    assert spawned == []


def test_the_version_is_the_same_in_both_places():
    import re
    from pathlib import Path
    from hvac_scanner import __version__
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', text, re.M).group(1) == __version__
