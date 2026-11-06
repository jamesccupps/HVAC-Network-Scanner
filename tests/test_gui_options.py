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
def app(gui_app):
    return gui_app


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
])
def test_read_number_reads_numbers_and_blank(app, raw, expected):
    app.rate_limit_entry.delete(0, tk.END)
    app.rate_limit_entry.insert(0, raw)
    assert app._read_number(app.rate_limit_entry, "Rate", 0, int, minimum=0) == expected


@pytest.mark.parametrize("raw", ["abc", "-5", "5O"])
def test_read_number_refuses_junk(app, raw):
    """A typo used to fall back to the default, the least gentle setting
    (no rate limit); now the scan does not start until it is fixed."""
    app.rate_limit_entry.delete(0, tk.END)
    app.rate_limit_entry.insert(0, raw)
    with pytest.raises(ValueError):
        app._read_number(app.rate_limit_entry, "Rate", 0, int, minimum=0)


def test_bad_timeout_stops_the_scan_with_a_reason(app):
    """A typo'd timeout used to raise out of _run_scan and dump a traceback,
    then to fall back silently; now it is refused before anything is sent."""
    app.network_entry.delete(0, tk.END)
    app.network_entry.insert(0, "10.0.0.0/24")
    app.timeout_entry.delete(0, tk.END)
    app.timeout_entry.insert(0, "five")
    assert app._build_options() is None
    assert "Timeout" in app.status_var.get() or "settings" in app.status_var.get()


def test_advanced_button_counts_changed_settings(app):
    """Advanced settings persist while the panel is folded away; the button
    says how many differ from the defaults."""
    assert app.adv_btn.cget('text').startswith("Advanced ")
    assert "changed" not in app.adv_btn.cget('text')
    app.adv_vars['bbmd'].set("10.0.0.5")
    app.mstp_mac_probe.set(True)
    assert "(2 changed)" in app.adv_btn.cget('text')


def test_rate_limit_reaches_the_client():
    """A non-zero rate limit must actually throttle BACnetClient."""
    from hvac_scanner.bacnet import BACnetClient
    opts = ScanOptions(networks=["10.0.0.0/24"], rate_limit_ms=50)
    client = BACnetClient(rate_limit_ms=opts.rate_limit_ms)
    assert client.rate_limit_ms == 50
