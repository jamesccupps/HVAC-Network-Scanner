"""GUI -> ScanOptions plumbing.

gui.py had no test coverage at all, which is how rate_limit_ms went missing
from the primary interface: the option existed on ScanOptions and on the CLI
from v2 onward, but the GUI never set it, so every GUI scan ran unthrottled
against field controllers — the exact load the README warns can lock them up.

These tests build the real widget tree, so they skip where there is no
display (headless CI on Linux).
"""

import pytest

tk = pytest.importorskip("tkinter")

from hvac_scanner.engine import ScanOptions


@pytest.fixture
def app():
    from hvac_scanner.gui import HVACNetworkScannerGUI
    try:
        root = tk.Tk()
    except tk.TclError as e:            # no display
        pytest.skip(f"no Tk display available: {e}")
    root.withdraw()
    try:
        yield HVACNetworkScannerGUI(root)
    finally:
        root.destroy()


def test_rate_limit_field_exists(app):
    assert hasattr(app, "rate_limit_entry")


def test_rate_limit_defaults_to_off(app):
    """Default must match the previous behavior so existing runs don't change."""
    assert app.rate_limit_entry.get() == "0"


def test_gui_can_set_every_scan_option_it_claims_to(app):
    """The controls on screen must reach ScanOptions."""
    app.rate_limit_entry.delete(0, tk.END)
    app.rate_limit_entry.insert(0, "50")
    assert app._read_number(app.rate_limit_entry, "Rate", 0, int, minimum=0) == 50


@pytest.mark.parametrize("raw,expected", [
    ("50", 50), ("0", 0), ("", 0),
    ("abc", 0),        # junk falls back instead of raising
    ("-5", 0),         # below minimum falls back
])
def test_read_number_tolerates_junk(app, raw, expected):
    app.rate_limit_entry.delete(0, tk.END)
    app.rate_limit_entry.insert(0, raw)
    assert app._read_number(app.rate_limit_entry, "Rate", 0, int, minimum=0) == expected


def test_bad_timeout_no_longer_aborts_the_scan(app):
    """A typo'd timeout used to raise out of _run_scan and dump a traceback."""
    app.timeout_entry.delete(0, tk.END)
    app.timeout_entry.insert(0, "five")
    assert app._read_number(app.timeout_entry, "Timeout", 5.0, float, minimum=0.1) == 5.0


def test_rate_limit_reaches_the_client():
    """A non-zero rate limit must actually throttle BACnetClient."""
    from hvac_scanner.bacnet import BACnetClient
    opts = ScanOptions(networks=["10.0.0.0/24"], rate_limit_ms=50)
    client = BACnetClient(rate_limit_ms=opts.rate_limit_ms)
    assert client.rate_limit_ms == 50
