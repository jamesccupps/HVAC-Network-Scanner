"""Results reaching the UI while the scan is still running.

engine.run() blocked and the GUI populated everything afterwards, so on a long
scan the Points tab stayed empty for the whole run and then inserted every row
at once. The engine now emits each device as it finishes and the GUI draws it.

The interesting properties are that emission happens *during* the scan rather
than at the end, and that the final pass does not draw anything twice.
"""

import socket

import pytest

import hvac_scanner.bacnet as bacnet
from hvac_scanner.engine import ScanEngine, ScanOptions

from .mock_device import MockBACnetDevice


@pytest.fixture
def loopback_engine(monkeypatch):
    """Engine wired to talk to a loopback mock instead of a real subnet."""
    def _open(self):
        if self._sock is not None:
            return self._bound_port or 0
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(self.timeout)
        s.bind(("", 0))
        self._sock, self._bound_port = s, s.getsockname()[1]
        return self._bound_port
    monkeypatch.setattr(bacnet.BACnetClient, "open", _open)

    def _make(**kw):
        opts = ScanOptions(networks=["127.0.0.1"], timeout=1.0,
                           scan_modbus=False, scan_services=False,
                           scan_snmp=False, scan_mstp=False,
                           bacnet_broadcast="127.0.0.1", **kw)
        return opts
    return _make


# -- engine -----------------------------------------------------------------

class TestEngineEmitsDevices:

    def test_device_callback_fires_for_each_device(self, loopback_engine):
        seen = []
        with MockBACnetDevice(n_objects=8):
            ScanEngine(loopback_engine(), callback=lambda m: None,
                       device_callback=seen.append).run()
        assert len(seen) == 1
        assert seen[0]['instance'] == 1234

    def test_emitted_device_is_already_complete(self, loopback_engine):
        """It must carry its points, or the UI draws an empty row and never
        revisits it."""
        seen = []
        with MockBACnetDevice(n_objects=8):
            ScanEngine(loopback_engine(), callback=lambda m: None,
                       device_callback=seen.append).run()
        assert len(seen[0]['objects']) == 8
        assert seen[0]['properties']['model_name'] == 'Tracer SC+'

    def test_emission_happens_during_the_scan_not_after(self, loopback_engine):
        """The whole point: a device is handed over before run() returns."""
        marker = {'emitted_before_return': False, 'returned': False}

        def on_device(dev):
            marker['emitted_before_return'] = not marker['returned']

        with MockBACnetDevice(n_objects=8):
            ScanEngine(loopback_engine(), callback=lambda m: None,
                       device_callback=on_device).run()
        marker['returned'] = True
        assert marker['emitted_before_return']

    def test_emitted_object_is_the_one_in_the_result(self, loopback_engine):
        seen = []
        with MockBACnetDevice(n_objects=4):
            result = ScanEngine(loopback_engine(), callback=lambda m: None,
                                device_callback=seen.append).run()
        assert seen[0] is result.devices[0]

    def test_a_failing_callback_does_not_break_the_scan(self, loopback_engine):
        """A UI error must not take the scan down with it."""
        def boom(dev):
            raise RuntimeError("UI exploded")

        with MockBACnetDevice(n_objects=4):
            result = ScanEngine(loopback_engine(), callback=lambda m: None,
                                device_callback=boom).run()
        assert len(result.devices) == 1
        assert len(result.devices[0]['objects']) == 4

    def test_no_callback_is_fine(self, loopback_engine):
        with MockBACnetDevice(n_objects=4):
            result = ScanEngine(loopback_engine(), callback=lambda m: None).run()
        assert len(result.devices) == 1


# -- gui --------------------------------------------------------------------

tk = pytest.importorskip("tkinter")


@pytest.fixture
def app():
    from hvac_scanner.gui import HVACNetworkScannerGUI
    try:
        root = tk.Tk()
    except tk.TclError as e:
        pytest.skip(f"no Tk display: {e}")
    root.withdraw()
    try:
        yield HVACNetworkScannerGUI(root)
    finally:
        root.destroy()


def _device(ip='10.0.0.19', instance=33333, points=3, protocol='BACnet/IP'):
    return {
        'ip': ip, 'instance': instance, 'protocol': protocol,
        'vendor_name': 'The Trane Company',
        'properties': {'object_name': 'AHU-1', 'model_name': 'Tracer SC+'},
        'objects': [{'type': 'Analog Input', 'instance': i, 'name': f'P{i}',
                     'present_value': '72.5', 'units': 'F', 'description': ''}
                    for i in range(points)],
        '_fingerprint': {},
    }


class TestGuiStreaming:

    def test_streaming_a_device_draws_its_rows(self, app):
        app._stream_device(_device(points=5))
        assert len(app.device_tree.get_children()) == 1
        assert len(app.points_tree.get_children()) == 5

    def test_streaming_updates_the_status_line(self, app):
        app._stream_device(_device(points=5))
        assert '1 device' in app.status_var.get()
        assert '5 point' in app.status_var.get()

    def test_the_same_device_is_not_drawn_twice(self, app):
        dev = _device(points=3)
        app._stream_device(dev)
        app._stream_device(dev)
        assert len(app.points_tree.get_children()) == 3

    def test_service_rows_are_left_to_the_final_pass(self, app):
        """Deduplicating services against primary rows needs the whole result
        set, so streaming them early would show a BACnet host four times."""
        app._stream_device({'ip': '10.0.0.5', 'protocol': 'Service',
                            'port': 80, 'objects': []})
        assert len(app.device_tree.get_children()) == 0

    def test_final_pass_does_not_duplicate_streamed_rows(self, app):
        from hvac_scanner.engine import ScanResult
        dev = _device(points=4)
        app._stream_device(dev)
        app.result = ScanResult()
        app.result.devices = [dev]
        app._populate_results()
        assert len(app.device_tree.get_children()) == 1
        assert len(app.points_tree.get_children()) == 4

    def test_final_pass_still_draws_devices_that_were_not_streamed(self, app):
        from hvac_scanner.engine import ScanResult
        streamed, late = _device(instance=1), _device(instance=2)
        app._stream_device(streamed)
        app.result = ScanResult()
        app.result.devices = [streamed, late]
        app._populate_results()
        assert len(app.device_tree.get_children()) == 2
        assert len(app.points_tree.get_children()) == 6

    def test_modbus_registers_stream_too(self, app):
        dev = {'ip': '10.0.0.90', 'port': 502, 'unit_id': 1,
               'protocol': 'Modbus TCP', 'objects': [], 'properties': {},
               'holding_registers': [{'register': 0, 'value': 42, 'hex': '0x002A'}],
               'input_registers': [], 'coils': [], '_fingerprint': {}}
        app._stream_device(dev)
        assert len(app.reg_tree.get_children()) == 1

    def test_device_label_prefers_the_reported_object_name(self, app):
        assert app._device_label(_device()) == 'AHU-1 (10.0.0.19)'

    def test_device_label_falls_back_to_ip_and_instance(self, app):
        dev = _device()
        dev['properties'] = {}
        assert app._device_label(dev) == '10.0.0.19 (33333)'

    def test_starting_a_scan_resets_the_stream_state(self, app):
        app._stream_device(_device(points=3))
        assert app._streamed
        app.network_entry.delete(0, tk.END)
        app.network_entry.insert(0, '')      # no targets: returns quickly
        app.start_scan()
        assert app._streamed == set()
        assert app._streamed_points == 0
        app.stop_event.set()


class TestGuiCompare:
    """The CLI has --baseline for scheduled runs; the GUI needs the same
    comparison for someone working interactively, or the feature is only
    reachable from a terminal."""

    def test_compare_button_exists_and_starts_disabled(self, app):
        assert hasattr(app, 'compare_btn')
        assert str(app.compare_btn['state']) == 'disabled'

    def test_diff_window_renders_the_report(self, app):
        from hvac_scanner import diff as D
        from hvac_scanner.engine import ScanResult
        app.result = ScanResult()
        app.result.devices = [_device()]
        base = {'scan_time': 'earlier', 'devices': [
            {**_device(), 'properties': {'object_name': 'AHU-1',
                                         'model_name': 'Tracer SC'}}]}
        d = D.diff_scans(base, app.result.to_dict())
        app._show_diff_window(d, 'baseline.json')
        app.root.update()
        tops = [w for w in app.root.winfo_children() if isinstance(w, tk.Toplevel)]
        assert len(tops) == 1
        body = [c for c in tops[0].winfo_children() if isinstance(c, tk.Text)][0]
        assert "'Tracer SC' -> 'Tracer SC+'" in body.get("1.0", tk.END)
        tops[0].destroy()

    def test_diff_text_is_read_only(self, app):
        from hvac_scanner import diff as D
        from hvac_scanner.engine import ScanResult
        app.result = ScanResult()
        app.result.devices = [_device()]
        app._show_diff_window(D.diff_scans({'devices': []}, app.result.to_dict()), 'b')
        app.root.update()
        top = [w for w in app.root.winfo_children() if isinstance(w, tk.Toplevel)][0]
        txt = [c for c in top.winfo_children() if isinstance(c, tk.Text)][0]
        assert str(txt['state']) == 'disabled'
        top.destroy()
