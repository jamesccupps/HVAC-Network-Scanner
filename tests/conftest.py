"""Shared pytest configuration."""

import sys
from pathlib import Path

import pytest

# Ensure the package is importable without install
sys.path.insert(0, str(Path(__file__).parent.parent))


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_routing: let the engine consult this machine's routing "
                   "table when deciding whether a target is on a local subnet")


@pytest.fixture(scope="session")
def tk_root():
    """One Tk interpreter for the whole run.

    Creating and destroying a Tk() per test eventually fails on Windows with
    "Can't find a usable tk.tcl", which showed up as GUI tests skipping at
    random in a full run while passing alone.
    """
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as e:            # no display (headless CI)
        pytest.skip(f"no Tk display available: {e}")
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def gui_app(tk_root):
    """A fresh GUI in its own window, without the user's saved settings."""
    import tkinter as tk
    from hvac_scanner.gui import HVACNetworkScannerGUI
    top = tk.Toplevel(tk_root)
    top.withdraw()
    try:
        yield HVACNetworkScannerGUI(top, settings_path=None)
    finally:
        top.destroy()


@pytest.fixture(autouse=True)
def _targets_are_on_link(monkeypatch, request):
    """Treat every target as on a directly attached subnet.

    Whether "auto" unicast discovery probes an address depends on how this
    machine routes to it, and a unit test must not pass on one machine and
    fail on the next because 10.0.0.0/24 happens to be someone's LAN. Tests
    about unicast discovery opt out with @pytest.mark.real_routing or patch
    `_is_local` themselves.
    """
    if request.node.get_closest_marker("real_routing"):
        return
    from hvac_scanner.engine import ScanEngine
    monkeypatch.setattr(ScanEngine, "_is_local", lambda self, ip: True)
