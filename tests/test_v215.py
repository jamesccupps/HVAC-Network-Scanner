"""2.15: what a PyPI install is told about updates, BBMD tables that
disagree, and smaller fixes from the 2026-11-14 audit. Network-free."""
import json
import sys
from pathlib import Path

import pytest

from hvac_scanner import updater
from hvac_scanner.report import bbmd_problems, build_findings

PKG_PARENT = Path(updater.__file__).resolve().parent.parent


# -- what a copy installed from PyPI is told -------------------------------------

class _Dist:
    def __init__(self, location=PKG_PARENT, direct=None):
        self.location, self.direct = Path(location), direct

    def read_text(self, name):
        return json.dumps(self.direct) if name == "direct_url.json" and self.direct else None

    def locate_file(self, path):
        return self.location / path


@pytest.fixture
def installed(monkeypatch):
    import importlib.metadata as md

    def install(dist=None, prefix="/opt/venv"):
        def distribution(name):
            assert name == "hvac-network-scanner"
            if dist is None:
                raise md.PackageNotFoundError(name)
            return dist
        monkeypatch.setattr(md, "distribution", distribution)
        monkeypatch.setattr(sys, "prefix", prefix)
    monkeypatch.delattr(sys, "frozen", raising=False)
    return install


@pytest.mark.parametrize("prefix,command", [
    ("/home/u/.local/share/pipx/venvs/hvac-network-scanner", "pipx upgrade hvac-network-scanner"),
    (r"C:\Users\u\pipx\venvs\hvac-network-scanner", "pipx upgrade hvac-network-scanner"),
    ("/home/u/venv", "pip install --upgrade hvac-network-scanner"),
])
def test_a_pypi_install_is_told_its_upgrade_command(installed, prefix, command):
    installed(_Dist(), prefix)
    assert updater.upgrade_command() == command
    up = updater.Update("2.99.0", "2026-12-01", "source", None, "test")
    assert updater.how_to_update(up) == f"run: {command}"


@pytest.mark.parametrize("dist", [
    None,                                                          # run from a clone
    _Dist(direct={"url": "file:///src/hvac", "dir_info": {"editable": True}}),   # pip install -e
    _Dist(location="/elsewhere/site-packages"),                    # installed, but not this copy
])
def test_a_clone_is_sent_to_the_releases_page(installed, dist):
    installed(dist, "/home/u/.local/share/pipx/venvs/hvac-network-scanner")
    assert updater.upgrade_command() is None
    up = updater.Update("2.99.0", "2026-12-01", "source", None, "test")
    assert updater.how_to_update(up) == updater.RELEASES_URL


def test_the_executable_updates_itself(installed, monkeypatch):
    installed(_Dist())
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert updater.upgrade_command() is None
    up = updater.Update("2.99.0", "2026-12-01", "exe",
                        {"file": "HVACNetworkScanner.exe", "size": 1, "sha256": "0" * 64}, "test")
    assert updater.how_to_update(up) == "Update to install it"


# -- BBMD tables that disagree ------------------------------------------------------

def _bbmd(ip, peers, fdt=None):
    return {'ip': ip, 'protocol': 'BACnet/IP', 'instance': int(ip.split('.')[-1]),
            'bbmd': {'bdt': [{'address': f"{p}:47808", 'mask': '255.255.255.255'}
                             for p in [ip, *peers]], 'fdt': fdt}}


# One site's tables, in documentation addresses: two BBMDs on one subnet
# both listing the far BBMD, which lists only one of them back, and a third
# with a stale table pointing outside the scan.
SITE = [_bbmd('192.0.2.107', ['198.51.100.200']),
        _bbmd('192.0.2.108', ['198.51.100.200']),
        _bbmd('192.0.2.192', ['203.0.113.166', '203.0.113.20'], fdt=[]),
        _bbmd('198.51.100.200', ['192.0.2.108'], fdt=[])]
TARGETS = ['192.0.2.0/24', '198.51.100.0/24']


def test_bbmds_sharing_a_subnet_and_a_one_way_table_are_found():
    rows = bbmd_problems(SITE, TARGETS)
    assert [r[0] for r in rows] == ['192.0.2.107, 192.0.2.108, 192.0.2.192', '192.0.2.107']
    assert "3 BBMDs on 192.0.2.0/24" in rows[0][1]
    assert "198.51.100.200 gets each of them 2 times (listed by 192.0.2.107, 192.0.2.108)" in rows[0][1]
    assert "198.51.100.200's table doesn't list 192.0.2.107" in rows[1][1]


def test_a_peer_in_the_scanned_range_that_is_no_bbmd_is_found():
    rows = bbmd_problems([_bbmd('192.0.2.10', ['192.0.2.50', '203.0.113.9'])], ['192.0.2.1-100'])
    assert rows == [['192.0.2.10', "Lists 192.0.2.50 as a peer, which is in the scanned range "
                                   "but didn't answer as a BBMD: a stale entry, or a BBMD that "
                                   "is down or unreachable."]]


def test_tables_that_agree_raise_nothing():
    pair = [_bbmd('192.0.2.10', ['198.51.100.10']), _bbmd('198.51.100.10', ['192.0.2.10'])]
    assert bbmd_problems(pair, TARGETS) == []
    titles = [f.title for f in build_findings({'devices': pair, 'targets': TARGETS})]
    assert "BBMD tables that duplicate or drop broadcasts" not in titles
    assert "BBMDs linking subnets into one BACnet network" in titles


@pytest.mark.parametrize("scan,why", [
    ({'devices': "nope"}, "'devices' is not a list"),
    ({'devices': ["x"]}, "something other than objects"),
    ({'devices': [], 'counts': {'points': "12"}}, "'counts' is not a set of numbers"),
    ({'devices': [], 'coverage': {'outside_targets': {'192.0.2.0/24': "3"}}},
     "'coverage.outside_targets'"),
    ({'devices': [], 'elapsed_seconds': "90"}, "'elapsed_seconds' is not a number"),
    ({'devices': [], 'targets': "192.0.2.0/24"}, "'targets' is not a list of strings"),
])
def test_the_report_tool_names_what_is_wrong_with_a_scan_file(tmp_path, capsys, scan, why):
    """Audit 2026-11-14, finding 6: these four (and two more) were tracebacks."""
    from hvac_scanner import report
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(scan), encoding="utf-8")
    assert report.main([str(bad)]) == 1
    err = capsys.readouterr().err
    assert "is not a scan export" in err and why in err and "Traceback" not in err
    assert not (tmp_path / "bad.html").exists()


def test_a_real_export_still_passes_the_shape_check():
    from hvac_scanner.report import scan_shape_problem
    from hvac_scanner.engine import ScanResult
    assert scan_shape_problem(ScanResult().to_dict()) is None
    assert scan_shape_problem({'devices': SITE, 'targets': TARGETS}) is None


# -- the window on a narrow screen --------------------------------------------------

def test_the_end_of_a_row_moves_under_it_when_the_window_is_narrow(tk_root):
    import tkinter as tk
    from tkinter import ttk
    from hvac_scanner.gui import HVACNetworkScannerGUI
    top = tk.Toplevel(tk_root)
    try:
        top.geometry("1600x120+-3000+-3000")
        line = ttk.Frame(top)
        line.pack(fill=tk.X)
        head, tail = ttk.Frame(line, width=600, height=20), ttk.Frame(line, width=500, height=20)
        HVACNetworkScannerGUI._wrap_when_narrow(line, head, tail)
        top.update()
        assert tail.grid_info()['row'] == 0
        top.geometry("900x120")
        top.update()
        assert tail.grid_info()['row'] == 1
        top.geometry("1600x120")
        top.update()
        assert tail.grid_info()['row'] == 0
    finally:
        top.destroy()


def test_the_header_keeps_the_status_at_the_minimum_size(gui_app):
    """The protocol list is packed last, so it is what a narrow header cuts."""
    hdr = gui_app.status_label.master
    packed = hdr.pack_slaves()
    assert packed.index(gui_app.status_label) < packed.index(packed[-1])
    assert "BACnet/IP" in str(packed[-1].cget("text"))


def test_the_report_carries_the_bbmd_finding():
    found = {f.title: f for f in build_findings({'devices': SITE, 'targets': TARGETS})}
    f = found["BBMD tables that duplicate or drop broadcasts"]
    assert f.severity == "low" and f.columns == ["BBMD", "Problem"] and len(f.rows) == 2
