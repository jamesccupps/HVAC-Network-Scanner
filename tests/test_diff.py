"""Baseline comparison.

The scanner has written JSON since v2 and been schedulable since then, but
nothing read the output back. These tests cover the identity rules that make a
comparison useful rather than noisy — chiefly that a BACnet device keys on its
instance number, so a controller that moves address is one changed device
rather than one disappearance and one unrelated arrival.
"""

import json

import pytest

from hvac_scanner import diff as D


def bacnet_dev(ip, instance, model='Tracer SC+', fw='5.20', name='AHU-1',
               objects=0, vendor='The Trane Company'):
    return {
        'ip': ip, 'instance': instance, 'protocol': 'BACnet/IP',
        'vendor_name': vendor,
        'properties': {'model_name': model, 'firmware_revision': fw,
                       'object_name': name},
        'objects': [{'type': 'Analog Input', 'instance': i} for i in range(objects)],
    }


def modbus_dev(ip, unit=1, port=502):
    return {'ip': ip, 'port': port, 'unit_id': unit, 'protocol': 'Modbus TCP',
            'vendor_name': 'Acme', 'properties': {}, 'objects': []}


def scan(devices, when='2026-08-19T02:00:00'):
    return {'scan_time': when, 'devices': devices}


# -- identity ---------------------------------------------------------------

class TestDeviceKey:

    def test_bacnet_keys_on_instance_not_address(self):
        a = D.device_key(bacnet_dev('10.0.0.19', 33333))
        b = D.device_key(bacnet_dev('10.0.0.121', 33333))
        assert a == b

    def test_different_bacnet_instances_are_different_devices(self):
        assert D.device_key(bacnet_dev('10.0.0.19', 33333)) \
            != D.device_key(bacnet_dev('10.0.0.19', 22222))

    def test_modbus_keys_on_address_port_and_unit(self):
        assert D.device_key(modbus_dev('10.0.0.90', 1)) \
            != D.device_key(modbus_dev('10.0.0.90', 2))
        assert D.device_key(modbus_dev('10.0.0.90')) \
            != D.device_key(modbus_dev('10.0.0.91'))

    def test_bacnet_without_an_instance_falls_back_to_address(self):
        dev = {'ip': '10.0.0.5', 'protocol': 'BACnet/IP'}
        assert '10.0.0.5' in D.device_key(dev)


# -- the diff ---------------------------------------------------------------

class TestDiff:

    def test_identical_scans_report_no_changes(self):
        devs = [bacnet_dev('10.0.0.19', 33333, objects=10), modbus_dev('10.0.0.90')]
        d = D.diff_scans(scan(devs), scan(devs))
        assert not d.has_changes
        assert d.unchanged == 2

    def test_new_device_is_reported_as_added(self):
        d = D.diff_scans(scan([bacnet_dev('10.0.0.19', 33333)]),
                         scan([bacnet_dev('10.0.0.19', 33333),
                               bacnet_dev('10.0.0.77', 5002)]))
        assert len(d.added) == 1
        assert d.added[0]['instance'] == 5002
        assert not d.removed

    def test_missing_device_is_reported_as_removed(self):
        d = D.diff_scans(scan([bacnet_dev('10.0.0.19', 33333),
                               bacnet_dev('10.0.0.60', 5001)]),
                         scan([bacnet_dev('10.0.0.19', 33333)]))
        assert len(d.removed) == 1
        assert d.removed[0]['instance'] == 5001
        assert not d.added

    def test_a_controller_that_moved_address_is_a_change_not_a_swap(self):
        """The reason BACnet keys on instance: DHCP must not look like an outage."""
        d = D.diff_scans(scan([bacnet_dev('10.0.0.21', 22222)]),
                         scan([bacnet_dev('10.0.0.121', 22222)]))
        assert not d.added and not d.removed
        assert len(d.changed) == 1
        assert [c.field for c in d.changed[0].changes] == ['address']

    def test_firmware_change_is_reported(self):
        d = D.diff_scans(scan([bacnet_dev('10.0.0.45', 103000, fw='V3.5.2')]),
                         scan([bacnet_dev('10.0.0.45', 103000, fw='V3.5.4')]))
        assert len(d.changed) == 1
        c = d.changed[0].changes[0]
        assert (c.field, c.before, c.after) == ('firmware', 'V3.5.2', 'V3.5.4')

    def test_object_count_change_is_reported(self):
        d = D.diff_scans(scan([bacnet_dev('10.0.0.45', 1, objects=449)]),
                         scan([bacnet_dev('10.0.0.45', 1, objects=512)]))
        assert any(c.field == 'object count' for c in d.changed[0].changes)

    def test_model_and_vendor_changes_are_reported(self):
        d = D.diff_scans(
            scan([bacnet_dev('10.0.0.9', 1, model='UC400', vendor='The Trane Company')]),
            scan([bacnet_dev('10.0.0.9', 1, model='Symbio 400-500', vendor='Trane')]))
        fields = {c.field for c in d.changed[0].changes}
        assert {'model', 'vendor'} <= fields

    def test_several_changes_on_one_device_are_grouped(self):
        d = D.diff_scans(scan([bacnet_dev('10.0.0.9', 1, fw='1.0', objects=10)]),
                         scan([bacnet_dev('10.0.0.19', 1, fw='2.0', objects=20)]))
        assert len(d.changed) == 1
        assert len(d.changed[0].changes) == 3

    def test_present_values_are_not_treated_as_changes(self):
        """A temperature differs on every scan; reporting it would bury the signal."""
        a = bacnet_dev('10.0.0.9', 1, objects=2)
        b = bacnet_dev('10.0.0.9', 1, objects=2)
        a['objects'][0]['present_value'] = '72.5'
        b['objects'][0]['present_value'] = '68.1'
        d = D.diff_scans(scan([a]), scan([b]))
        assert not d.has_changes

    def test_a_field_missing_from_one_side_is_not_a_change(self):
        """An earlier run without --deep has no object count; that is not a drop."""
        shallow = bacnet_dev('10.0.0.9', 1, objects=0)
        deep = bacnet_dev('10.0.0.9', 1, objects=500)
        d = D.diff_scans(scan([shallow]), scan([deep]))
        assert not any(c.field == 'object count' for dd in d.changed for c in dd.changes)

    def test_empty_baseline_makes_everything_new(self):
        d = D.diff_scans(scan([]), scan([bacnet_dev('10.0.0.9', 1)]))
        assert len(d.added) == 1 and not d.removed and not d.changed

    def test_empty_current_makes_everything_missing(self):
        d = D.diff_scans(scan([bacnet_dev('10.0.0.9', 1)]), scan([]))
        assert len(d.removed) == 1 and not d.added

    def test_scan_times_are_carried_through(self):
        d = D.diff_scans(scan([], when='2026-01-01T00:00:00'),
                         scan([], when='2026-02-02T00:00:00'))
        assert d.baseline_time == '2026-01-01T00:00:00'
        assert d.current_time == '2026-02-02T00:00:00'


# -- reporting --------------------------------------------------------------

class TestReport:

    def _mixed(self):
        return D.diff_scans(
            scan([bacnet_dev('10.0.0.19', 33333, name='SC-1'),
                  bacnet_dev('10.0.0.60', 5001, name='AHU-4'),
                  bacnet_dev('10.0.0.45', 103000, fw='V3.5.2', name='PXC-3')]),
            scan([bacnet_dev('10.0.0.19', 33333, name='SC-1'),
                  bacnet_dev('10.0.0.77', 5002, name='AHU-7'),
                  bacnet_dev('10.0.0.45', 103000, fw='V3.5.4', name='PXC-3')]))

    def test_text_report_names_each_section(self):
        text = D.format_text(self._mixed())
        assert 'NEW (1)' in text
        assert 'NOT RESPONDING (1)' in text
        assert 'CHANGED (1)' in text

    def test_text_report_shows_the_before_and_after(self):
        text = D.format_text(self._mixed())
        assert "'V3.5.2' -> 'V3.5.4'" in text

    def test_unchanged_scan_says_so_plainly(self):
        devs = [bacnet_dev('10.0.0.19', 33333)]
        text = D.format_text(D.diff_scans(scan(devs), scan(devs)))
        assert 'No changes' in text

    def test_json_report_is_serializable_and_summarized(self):
        payload = self._mixed().to_dict()
        json.dumps(payload)
        assert payload['summary'] == {'added': 1, 'removed': 1,
                                      'changed': 1, 'unchanged': 1}

    def test_written_files_round_trip(self, tmp_path):
        d = self._mixed()
        t, j = tmp_path / 'r.txt', tmp_path / 'r.json'
        D.write_text(d, str(t))
        D.write_json(d, str(j))
        assert 'NEW (1)' in t.read_text(encoding='utf-8')
        assert json.loads(j.read_text(encoding='utf-8'))['summary']['added'] == 1


# -- loading ----------------------------------------------------------------

class TestLoad:

    def test_loads_a_real_scan_export(self, tmp_path):
        from hvac_scanner.engine import ScanResult
        r = ScanResult()
        r.devices = [bacnet_dev('10.0.0.19', 33333, objects=3)]
        p = tmp_path / 'scan.json'
        r.write_json(str(p))
        loaded = D.load_scan(str(p))
        assert loaded['devices'][0]['instance'] == 33333

    def test_round_trips_through_a_real_export(self, tmp_path):
        """A saved baseline must compare cleanly against itself."""
        from hvac_scanner.engine import ScanResult
        r = ScanResult()
        r.devices = [bacnet_dev('10.0.0.19', 33333, objects=3)]
        p = tmp_path / 'scan.json'
        r.write_json(str(p))
        loaded = D.load_scan(str(p))
        assert not D.diff_scans(loaded, loaded).has_changes

    def test_rejects_a_file_that_is_not_a_scan(self, tmp_path):
        p = tmp_path / 'nope.json'
        p.write_text('{"hello": 1}', encoding='utf-8')
        with pytest.raises(ValueError):
            D.load_scan(str(p))


# -- cli --------------------------------------------------------------------

class TestCliIntegration:

    def test_flags_parse(self):
        from hvac_scanner.cli import _build_parser
        a = _build_parser().parse_args([
            '10.0.0.0/24', '--baseline', 'b.json', '--save-baseline', 'n.json',
            '--diff-output', 'd.txt', '--fail-on-change'])
        assert a.baseline == 'b.json'
        assert a.save_baseline == 'n.json'
        assert a.diff_output == 'd.txt'
        assert a.fail_on_change is True

    def test_defaults_are_off(self):
        from hvac_scanner.cli import _build_parser
        a = _build_parser().parse_args(['10.0.0.0/24'])
        assert a.baseline is None and a.save_baseline is None
        assert a.fail_on_change is False

    def test_unchanged_scan_exits_zero_with_fail_on_change(self, tmp_path):
        from hvac_scanner.cli import main
        from hvac_scanner.engine import ScanResult
        base = tmp_path / 'b.json'
        r = ScanResult()
        r.write_json(str(base))
        rc = main(['10.0.0.0/30', '--no-bacnet', '--no-modbus', '--no-services',
                   '--no-snmp', '--no-mstp', '--quiet', '--print', 'none',
                   '--baseline', str(base), '--fail-on-change',
                   '--diff-output', str(tmp_path / 'd.txt')])
        assert rc == 0

    def test_changed_scan_exits_four_with_fail_on_change(self, tmp_path):
        from hvac_scanner.cli import main
        base = tmp_path / 'b.json'
        base.write_text(json.dumps(scan([bacnet_dev('10.0.0.9', 42)])), encoding='utf-8')
        rc = main(['10.0.0.0/30', '--no-bacnet', '--no-modbus', '--no-services',
                   '--no-snmp', '--no-mstp', '--quiet', '--print', 'none',
                   '--baseline', str(base), '--fail-on-change',
                   '--diff-output', str(tmp_path / 'd.txt')])
        assert rc == 4

    def test_changed_scan_exits_zero_without_the_flag(self, tmp_path):
        from hvac_scanner.cli import main
        base = tmp_path / 'b.json'
        base.write_text(json.dumps(scan([bacnet_dev('10.0.0.9', 42)])), encoding='utf-8')
        rc = main(['10.0.0.0/30', '--no-bacnet', '--no-modbus', '--no-services',
                   '--no-snmp', '--no-mstp', '--quiet', '--print', 'none',
                   '--baseline', str(base),
                   '--diff-output', str(tmp_path / 'd.txt')])
        assert rc == 0

    def test_baseline_is_saved_even_when_the_scan_changed(self, tmp_path):
        """An unattended schedule must roll its baseline forward, or it
        re-reports the same drift every night."""
        from hvac_scanner.cli import main
        base = tmp_path / 'b.json'
        base.write_text(json.dumps(scan([bacnet_dev('10.0.0.9', 42)])), encoding='utf-8')
        new = tmp_path / 'new.json'
        main(['10.0.0.0/30', '--no-bacnet', '--no-modbus', '--no-services',
              '--no-snmp', '--no-mstp', '--quiet', '--print', 'none',
              '--baseline', str(base), '--save-baseline', str(new),
              '--diff-output', str(tmp_path / 'd.txt')])
        assert new.exists()
        assert 'devices' in json.loads(new.read_text(encoding='utf-8'))

    def test_missing_baseline_file_is_an_error_not_a_crash(self, tmp_path):
        from hvac_scanner.cli import main
        rc = main(['10.0.0.0/30', '--no-bacnet', '--no-modbus', '--no-services',
                   '--no-snmp', '--no-mstp', '--quiet', '--print', 'none',
                   '--baseline', str(tmp_path / 'nope.json')])
        assert rc == 3
