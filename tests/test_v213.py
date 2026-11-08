"""2.13: the advisory list updates itself (signed download, CISA watcher)
and app updates install themselves when the window closes. Network-free:
CISA's data comes from tests/data/csaf, sources are local files."""
import base64
import json
import queue
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(ROOT / "tools"))

from hvac_scanner import advisories, ed25519, updater  # noqa: E402
from hvac_scanner.update_key import ADVISORY_PUBLIC_KEY, UPDATE_PUBLIC_KEY  # noqa: E402
import advisory_watch as watch  # noqa: E402
import signing  # noqa: E402

from .test_v210 import PUB, SEED, _release  # noqa: E402

CSAF = Path(__file__).parent / "data" / "csaf"
FIXTURE = Path(__file__).parent / "data" / "advisories-fixture.json"


@pytest.fixture(autouse=True)
def _own_settings_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


@pytest.fixture
def test_key(monkeypatch):
    """Lists signed with the tests' key count as genuine."""
    monkeypatch.setattr(advisories, "ADVISORY_PUBLIC_KEY", PUB)


def _list(serial=5, entries=None, as_of="2026-11-07") -> dict:
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    base.update(serial=serial, as_of=as_of)
    if entries is not None:
        base["advisories"] = entries
    return base


def _entry(**kw) -> dict:
    e = {"id": "ICSA-26-071-01", "published": "2026-03-12", "title": "Trane Tracer",
         "vendor": "trane", "model": r"^tracer sc\+$", "field": "application_software_version",
         "fixed": "6.30.2313", "cves": ["CVE-2026-28252"], "cvss": 8.1, "firmware": "",
         "note": "", "no_fix": False, "revision": "1", "auto": True}
    e.update(kw)
    return e


def _doc(name: str) -> dict:
    return json.loads((CSAF / name).read_text(encoding="utf-8"))


def _dev(model, vendor="Siemens Schweiz", **props):
    return {'ip': '10.0.0.9', 'protocol': 'BACnet/IP', 'vendor_name': vendor,
            'properties': {'model_name': model, 'vendor_name': vendor, **props}}


# -- the list built in, and the signed copy ---------------------------------------

def test_the_built_in_list_and_its_signed_copy_are_valid():
    t = advisories.bundled()
    assert t.serial >= 1 and t.advisories
    signed = advisories.verify_signed(
        (ROOT / "data" / "advisories.signed.json").read_text(encoding="utf-8"))
    # The workflow signs after a change merges, so the copy may trail by one.
    assert signed.serial <= t.serial


def test_the_advisory_key_is_its_own_and_never_the_update_key():
    key = base64.b64decode(ADVISORY_PUBLIC_KEY, validate=True)
    assert len(key) == 32 and ed25519._decompress(key) is not None
    assert ADVISORY_PUBLIC_KEY != UPDATE_PUBLIC_KEY
    # A release manifest signed with the advisory key is refused by the updater:
    # it checks against UPDATE_PUBLIC_KEY only.
    raw = json.dumps({"app": updater.APP_KEY, "version": "99.0.0"}).encode()
    fake = json.dumps({"payload": base64.b64encode(raw).decode(),
                       "signature": base64.b64encode(ed25519.sign(SEED, raw)).decode()})
    with pytest.raises(updater.UpdateError):
        updater.verify_manifest(fake)


def test_a_signed_list_is_used_only_with_the_right_key(test_key):
    text = advisories.signed_text(_list(), SEED)
    assert advisories.verify_signed(text).serial == 5
    with pytest.raises(advisories.AdvisoryDataError):
        advisories.verify_signed(text, public_key=ADVISORY_PUBLIC_KEY)
    outer = json.loads(text)
    obj = json.loads(base64.b64decode(outer["payload"]))
    obj["advisories"][0]["fixed"] = "1.0"                 # tampered
    outer["payload"] = base64.b64encode(advisories.canonical(obj)).decode()
    with pytest.raises(advisories.AdvisoryDataError):
        advisories.verify_signed(json.dumps(outer))


@pytest.mark.parametrize("change", [
    {"id": "ICSA-2026-1"}, {"model": "(unclosed"}, {"fixed": "6.30 beta"},
    {"cvss": 11}, {"cves": ["CVE-1"]}, {"field": "object_name"}, {"vendor": "Trane Inc"},
    {"no_fix": "yes"}, {"title": ""},
])
def test_entries_the_app_would_misread_are_refused(change):
    with pytest.raises(advisories.AdvisoryDataError):
        advisories.parse_table(_list(entries=[_entry(**change)]))


def test_lists_for_another_app_or_with_a_bad_serial_are_refused():
    for change in ({"app": "other"}, {"kind": "latest"}, {"serial": 0}, {"serial": True},
                   {"as_of": "yesterday"}):
        with pytest.raises(advisories.AdvisoryDataError):
            advisories.parse_table({**_list(), **change})


def test_the_downloaded_list_is_used_only_when_its_serial_is_higher(tmp_path, test_key):
    cache = tmp_path / "advisories.signed.json"
    base = advisories.bundled()
    cache.write_text(advisories.signed_text(_list(serial=base.serial + 3), SEED), encoding="utf-8")
    t = advisories.current(cache)
    assert t.serial == base.serial + 3 and t.origin == "downloaded"
    cache.write_text(advisories.signed_text(_list(serial=base.serial), SEED), encoding="utf-8")
    assert advisories.current(cache) is base
    cache.write_text("not signed", encoding="utf-8")
    assert advisories.current(cache) is base


def test_refresh_keeps_a_newer_list_and_nothing_else(tmp_path, test_key):
    cache = tmp_path / "cache" / "advisories.signed.json"
    src = tmp_path / "published.json"
    serial = advisories.bundled().serial + 1
    src.write_text(advisories.signed_text(_list(serial=serial), SEED), encoding="utf-8")
    t, changed = advisories.refresh(str(src), cache)
    assert changed and t.serial == serial and cache.read_text(encoding="utf-8") == \
        src.read_text(encoding="utf-8")
    assert advisories.refresh(str(src), cache)[1] is False
    src.write_text(advisories.signed_text(_list(serial=serial + 1), bytes(32)), encoding="utf-8")
    with pytest.raises(advisories.AdvisoryDataError):
        advisories.refresh(str(src), cache)
    assert advisories.current(cache).serial == serial          # kept


def test_an_advisory_listed_twice_for_a_device_counts_once_with_its_firmest_status():
    t = advisories.parse_table(_list(entries=[
        _entry(fixed=None, note="check by hand"), _entry(), _entry(id="ICSA-25-044-11",
                                                                   fixed=None, no_fix=True)]))
    got = {m['advisory'].id: m['status'] for m in advisories.for_device(
        _dev("Tracer SC+", "Trane", application_software_version="v5.70.1731"), t)}
    assert got == {"ICSA-26-071-01": "affected", "ICSA-25-044-11": "no fix"}


def test_the_report_says_which_list_it_used(monkeypatch):
    from hvac_scanner.report import build_findings
    t = advisories.parse_table(_list(serial=7))
    monkeypatch.setattr(advisories, "current", lambda cache=None: t)
    f = {f.title: f for f in build_findings({'devices': [
        _dev("Tracer SC+", "Trane", application_software_version="v5.70.1731")]})}
    assert "Advisory list as of 2026-11-07 (list 7, built in)." in \
        f["Firmware covered by published security advisories"].why


# -- the CISA watcher ---------------------------------------------------------------

@pytest.mark.parametrize("text,kind,version,suffix", [
    ("<v6.3.2310", "below", "6.3.2310", ""),
    ("vers:intdot/<01.21.233.16-7862", "below", "01.21.233.16", "-7862"),
    ("< 01.21.142.5-22", "below", "01.21.142.5", "-22"),
    ("vers:all/<V3.5.7", "below", "3.5.7", ""),
    ("vers:all/>=V2.3|<V6.30.37", "below", "6.30.37", ""),
    ("<v4.4_SP7", "below", None, ""),                    # a service pack: not a version
    ("vers:all/*", "all", None, ""),
    ("vers:intdot/>=2.3", "all", None, ""),
    ("<=4.2.1134", "other", None, ""),
])
def test_csaf_version_ranges(text, kind, version, suffix):
    r = watch.parse_range(text)
    assert (r["kind"], r["version"], r["suffix"]) == (kind, version, suffix)


def _by_model(entries):
    return {(e["model"], e["firmware"]): e for e in entries}


def test_tracer_sc_plus_takes_the_fix_trane_names_over_cisas_product_list():
    entries, uncovered = watch.map_advisory(_doc("icsa-26-071-01.json"))
    e = _by_model(entries)
    plus = e[(r"^tracer sc\+$", "")]
    assert plus["fixed"] == "6.30.2313" and "6.3.2310" in plus["note"] and plus["cvss"] == 8.1
    assert e[(r"^tracer sc$", "")]["fixed"] is None                  # before v4.4_SP7: by hand
    assert [p.name for p in uncovered] == ["Tracer Concierge"]       # its model name is unknown


def test_apogee_pxc_lines_by_firmware_and_p2_left_out():
    entries, uncovered = watch.map_advisory(_doc("icsa-22-349-16.json"))
    e = _by_model(entries)
    assert e[(r"^siemens bacnet field panel$", r"^EPXC\b")]["fixed"] == "3.5.5"
    assert e[(r"^siemens bacnet field panel$", r"^PXME\b")]["fixed"] == "3.5.5"
    assert {p.name for p in uncovered} == {"TALON TC Compact (BACnet)", "TALON TC Modular (BACnet)"}
    nofix, _ = watch.map_advisory(_doc("icsa-25-044-11.json"))
    assert [(x["firmware"], x["fixed"], x["no_fix"]) for x in nofix] == \
        [(r"^(PXME|EPXC)\b", None, True)]


def test_desigo_dxr2_and_pxc_with_their_own_fixes():
    e = _by_model(watch.map_advisory(_doc("icsa-26-225-08.json"))[0])
    assert e[("^dxr2", "")]["fixed"] == "01.21.233.16"
    assert e[("^dxr2", "")]["note"] == "fixed in 01.21.233.16-7862"
    for model in ("^pxc4", r"^pxc5\.e003", r"^pxc5\.e24", "^pxc7"):
        assert e[(model, "")]["fixed"] == "02.21.194.36"
    # CISA marks only the DXR2 affected in ICSA-22-132-10's data.
    assert [x["model"] for x in watch.map_advisory(_doc("icsa-22-132-10.json"))[0]] == ["^dxr2"]


def test_desigo_cc_is_split_by_release():
    entries, _ = watch.map_advisory(_doc("icsa-26-209-01.json"))
    t = advisories.parse_table(_list(entries=entries))
    v9 = advisories.for_device(_dev("Desigo CC", application_software_version="9.00"), t)
    assert [(m['status'], "V9: before 9.0.1" in m['advisory'].note) for m in v9] == [("check", True)]
    assert advisories.for_device(_dev("Desigo CC", application_software_version="10.00"), t) == []
    old, _ = watch.map_advisory(_doc("icsa-18-093-01.json"))      # versions nested in the file
    assert sorted(x["firmware"] for x in old) == [r"^\s*v?0*1\.", r"^\s*v?0*2\.", r"^\s*v?0*3\."]
    assert "MP3.0" in old[0]["note"]


def test_rebuild_keeps_hand_made_entries_and_replaces_its_own():
    manual = _entry(id="ICSA-20-001-01", auto=False, published="2020-01-01")
    stale = _entry(fixed="6.0")
    other = _entry(id="ICSA-19-001-01", published="2019-01-01")
    new = watch.rebuild([manual, stale, other], {"ICSA-26-071-01": [_entry()],
                                                  "ICSA-20-001-01": [_entry(id="ICSA-20-001-01")]})
    assert [(e["id"], e["fixed"], e["auto"]) for e in new] == [
        ("ICSA-19-001-01", "6.30.2313", True), ("ICSA-20-001-01", "6.30.2313", False),
        ("ICSA-26-071-01", "6.30.2313", True)]


def _feed(tmp_path, recent: str) -> Path:
    titles = {"icsa-26-071-01": "Trane Tracer SC, Tracer SC+, and Tracer Concierge",
              "icsa-22-349-16": "Siemens APOGEE and TALON",
              "icsa-26-225-08": "Siemens Desigo DXR and PXC Controllers",
              "icsa-25-044-11": "Siemens Apogee PXC100 Devices",
              "icsa-26-209-01": "Siemens Desigo CC"}
    entries = [{"id": k.upper(), "title": v,
                "updated": recent if k == "icsa-26-071-01" else "2026-01-01T00:00:00.000000Z",
                "content": {"src": f"{watch.CSAF_BASE}20{k[5:7]}/{k}.json"}}
               for k, v in titles.items()]
    entries.append({"id": "ICSA-26-001-01", "title": "Rockwell Automation PLC",
                    "updated": recent, "content": {"src": watch.CSAF_BASE + "2026/icsa-26-001-01.json"}})
    path = tmp_path / "feed.json"
    path.write_text(json.dumps({"feed": {"entry": entries}}), encoding="utf-8")
    return path


def test_the_daily_run_builds_signs_and_asks_for_review_once(tmp_path, monkeypatch, test_key):
    from datetime import datetime, timezone
    source = tmp_path / "advisories.json"
    source.write_text(json.dumps(_list(serial=3, entries=[])), encoding="utf-8")
    signed, message = tmp_path / "signed.json", tmp_path / "msg.txt"
    monkeypatch.setenv("ADVISORY_SIGNING_KEY", signing.pem_from_seed(SEED))
    monkeypatch.setenv("GITHUB_REPOSITORY", "someone/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    opened, existing = [], []

    class FakeGitHub:
        def __init__(self, repo, token):
            pass

        def issue_titles(self):
            return list(existing)

        def open_issue(self, title, body):
            opened.append((title, body))
            existing.append(title)
            return "https://example.invalid/1"
    monkeypatch.setattr(watch, "GitHub", FakeGitHub)
    now = datetime.now(timezone.utc).isoformat()
    args = ["--feed", str(_feed(tmp_path, now)), "--csaf-dir", str(CSAF), "--source", str(source),
            "--signed", str(signed), "--sign", "--issues", "--message", str(message),
            "--today", "2026-11-07"]
    assert watch.main(args) == 0
    t = advisories.verify_signed(signed.read_text(encoding="utf-8"))
    assert t.serial == 4 and t.as_of == "2026-11-07"
    assert advisories.canonical(advisories.table_to_dict(t)) == \
        advisories.canonical(json.loads(source.read_text(encoding="utf-8")))
    assert {a.id for a in t.advisories} == {"ICSA-26-071-01", "ICSA-22-349-16", "ICSA-26-225-08",
                                            "ICSA-25-044-11", "ICSA-26-209-01"}
    assert message.read_text(encoding="utf-8").startswith("Advisory list 4:")
    assert len(opened) == 1 and "ICSA-26-071-01" in opened[0][0] and "Tracer Concierge" in opened[0][1]
    # The next day: nothing new, nothing signed again, no second issue.
    before = signed.read_bytes()
    message.unlink()
    assert watch.main(args) == 0
    assert signed.read_bytes() == before and not message.exists() and len(opened) == 1


def test_a_hand_edit_without_a_new_serial_is_signed_with_one(tmp_path, monkeypatch, test_key):
    source, signed = tmp_path / "advisories.json", tmp_path / "signed.json"
    obj = _list(serial=3)
    signed.write_text(advisories.signed_text(obj, SEED), encoding="utf-8")
    obj["advisories"] = obj["advisories"][:2]                # edited, serial left at 3
    source.write_text(json.dumps(obj), encoding="utf-8")
    monkeypatch.setenv("ADVISORY_SIGNING_KEY", signing.pem_from_seed(SEED))
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"feed": {"entry": []}}), encoding="utf-8")
    assert watch.main(["--feed", str(feed), "--source", str(source), "--signed", str(signed),
                       "--sign", "--today", "2026-11-08"]) == 0
    t = advisories.verify_signed(signed.read_text(encoding="utf-8"))
    assert t.serial == 4 and len(t.advisories) == 2


def test_signing_tool_checks_the_signed_copy_matches_the_list(tmp_path):
    source, signed = tmp_path / "a.json", tmp_path / "s.json"
    source.write_text(json.dumps(_list()), encoding="utf-8")
    signing.sign_data(SEED, source, signed)
    assert signing.verify_data(signed, source, public_key=PUB)[0].startswith("ok")
    source.write_text(json.dumps(_list(serial=6)), encoding="utf-8")
    with pytest.raises(SystemExit):
        signing.verify_data(signed, source, public_key=PUB)


# -- installing updates as the window closes -----------------------------------------

def test_apply_without_restart_tells_the_new_exe(tmp_path, monkeypatch):
    spawned = []
    monkeypatch.setattr(updater, "_spawn", lambda args, cwd: spawned.append(args))
    monkeypatch.setattr(updater, "current_exe", lambda: tmp_path / "app" / updater.EXE_NAME)
    (tmp_path / "app").mkdir()
    new = tmp_path / "staging" / updater.EXE_NAME
    up = updater.Update("99.0.0", None, "exe", {}, "x")
    updater.apply(up, new, restart=False)
    updater.apply(up, new)
    assert spawned[0][-1] == "--no-restart" and spawned[1][-1] != "--no-restart"


def test_finish_without_restart_swaps_and_starts_nothing(tmp_path, monkeypatch):
    target, new = tmp_path / "app" / updater.EXE_NAME, tmp_path / "new.exe"
    target.parent.mkdir()
    target.write_bytes(b"old")
    new.write_bytes(b"new")
    spawned = []
    monkeypatch.setattr(updater, "_spawn", lambda args, cwd: spawned.append(args))
    monkeypatch.setattr(updater, "_wait_for_exit", lambda pid, timeout=60: True)
    assert updater.finish_update(target, 1, new, restart=False) == 0
    assert target.read_bytes() == b"new" and not updater.old_copy(target).exists()
    assert spawned == []
    assert "opens next time" in updater.update_log().read_text(encoding="utf-8")

    def broken(t, n):
        raise OSError("locked")
    monkeypatch.setattr(updater, "swap_in", broken)
    assert updater.finish_update(target, 1, new, restart=False) == 1 and spawned == []


def test_tidy_removes_what_an_update_left(tmp_path, monkeypatch):
    exe = tmp_path / "app" / updater.EXE_NAME
    exe.parent.mkdir()
    exe.write_bytes(b"x")
    updater.old_copy(exe).write_bytes(b"old")
    temp = tmp_path / "temp"
    for name in ("HVACNetworkScanner-update-1.0.0", "HVACNetworkScanner-update-999.0.0",
                 "HVACNetworkScanner-update-junk"):
        (temp / name).mkdir(parents=True)
    monkeypatch.setattr(updater.tempfile, "gettempdir", lambda: str(temp))
    updater.tidy(exe)
    assert not updater.old_copy(exe).exists() and exe.exists()
    assert sorted(p.name for p in temp.iterdir()) == ["HVACNetworkScanner-update-999.0.0",
                                                      "HVACNetworkScanner-update-junk"]


def test_self_test_argument():
    from hvac_scanner import gui
    assert gui._update_args(["x", "--self-test"]) == (0, None)


def _drain(app):
    out = []
    while True:
        try:
            out.append(app._events.get_nowait())
        except queue.Empty:
            return out


def _until_ready(app):
    kinds = []
    while 'update-ready' not in kinds:
        kind, payload = app._events.get(timeout=10)
        kinds.append(kind)
        assert kind != 'update-error', payload
        app._update_event(kind, payload)
    return kinds


def test_gui_downloads_by_itself_and_installs_on_close(gui_app, tmp_path, monkeypatch):
    from hvac_scanner import gui as gui_mod
    rel = _release(tmp_path / "rel", "99.0.0")
    monkeypatch.setattr(updater, "install_kind", lambda: "exe")
    monkeypatch.setattr(updater, "staging_dir", lambda v: tmp_path / "staging")
    asked = []
    monkeypatch.setattr(gui_mod.messagebox, "askyesno", lambda *a, **k: asked.append(a) or True)
    up = updater.check(source=str(rel), public_key=PUB)
    gui_app._update_event('update-found', (up, True))
    kinds = _until_ready(gui_app)
    assert not asked and 'update-progress' not in kinds        # quiet: no dialog, no progress bar
    path = tmp_path / "staging" / updater.EXE_NAME
    assert gui_app._ready_path == path and path.read_bytes() == (rel / updater.EXE_NAME).read_bytes()
    assert gui_app.update_btn.cget("text") == "Restart to update to 99.0.0"
    # The next daily check finds the same version: nothing is downloaded again.
    gui_app._update_event('update-found', (up, True))
    assert gui_app._ready_path == path and not gui_app._update_busy
    applied, closed = [], []
    monkeypatch.setattr(updater, "apply",
                        lambda u, p, restart=True: applied.append((u.version, p, restart)))
    monkeypatch.setattr(gui_app.root, "destroy", lambda: closed.append(1))
    gui_app._on_close()
    assert applied == [("99.0.0", path, False)] and closed


def test_gui_restart_now_installs_with_a_restart(gui_app, tmp_path, monkeypatch):
    from hvac_scanner import gui as gui_mod
    rel = _release(tmp_path / "rel", "99.0.0")
    monkeypatch.setattr(updater, "install_kind", lambda: "exe")
    monkeypatch.setattr(updater, "staging_dir", lambda v: tmp_path / "staging")
    monkeypatch.setattr(gui_mod.messagebox, "askyesno", lambda *a, **k: True)
    gui_app._update_event('update-found', (updater.check(source=str(rel), public_key=PUB), True))
    _until_ready(gui_app)
    applied, later = [], []
    monkeypatch.setattr(updater, "apply",
                        lambda u, p, restart=True: applied.append((u.version, restart)))
    monkeypatch.setattr(gui_app.root, "after", lambda ms, fn: later.append(fn))
    gui_app._update_clicked()
    assert applied == [("99.0.0", True)] and gui_app.root.destroy in later


def test_gui_with_automatic_installs_off_only_offers(gui_app, tmp_path, monkeypatch):
    rel = _release(tmp_path / "rel", "99.0.0")
    monkeypatch.setattr(updater, "install_kind", lambda: "exe")
    gui_app.auto_update_var.set(False)
    _drain(gui_app)
    gui_app._update_event('update-found', (updater.check(source=str(rel), public_key=PUB), True))
    assert gui_app.update_btn.cget("text") == "Update to 99.0.0" and not gui_app._update_busy
    assert all(k == 'log' for k, _ in _drain(gui_app))


def test_gui_notes_a_new_advisory_list_and_a_silent_update(gui_app):
    _drain(gui_app)
    t = advisories.parse_table(_list(serial=9))
    gui_app._update_event('update-advisories', (t, True))
    gui_app._update_event('update-advisories', (t, False))
    gui_app._note_silent_update({'last_version': '1.0.0'})
    gui_app._note_silent_update({'last_version': '99.0.0'})       # an older copy run later
    logs = [m for k, m in _drain(gui_app) if k == 'log']
    assert logs == ["Advisory list updated: 20 entries, as of 2026-11-07 (list 9, built in).",
                    f"Updated to {updater.__version__} (was 1.0.0)."]


def test_gui_remembers_the_setting_and_the_version(gui_app):
    data = gui_app._collect_settings()
    assert data['auto_update'] is True and data['last_version'] == updater.__version__
    gui_app._apply_settings({'auto_update': False})
    assert gui_app.auto_update_var.get() is False


# -- packaging and the command line ---------------------------------------------------

def test_the_list_ships_in_the_exe_and_the_wheel():
    spec = (ROOT / "packaging" / "hvac_scanner.spec").read_text(encoding="utf-8")
    assert "'hvac_scanner', 'advisories.json'), 'hvac_scanner')" in spec
    assert 'hvac_scanner = ["advisories.json"]' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_cli_update_advisories_on_its_own(monkeypatch, capsys):
    from hvac_scanner import cli
    t = advisories.parse_table(_list(serial=9))
    monkeypatch.setattr(advisories, "refresh", lambda: (t, True))
    assert cli.main(["--update-advisories"]) == 0
    assert "Advisory list: 20 entries, as of 2026-11-07 (list 9, built in) (updated)" in \
        capsys.readouterr().err

    def offline():
        raise OSError("no network")
    monkeypatch.setattr(advisories, "refresh", offline)
    assert cli.main(["--update-advisories"]) == 0
    assert "not updated" in capsys.readouterr().err
