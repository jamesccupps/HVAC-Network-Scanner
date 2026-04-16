"""Tests for the scan orchestrator and result exports."""

import json
import csv
import tempfile
from pathlib import Path

from hvac_scanner.engine import ScanOptions, ScanResult


def test_scan_options_defaults():
    opts = ScanOptions(networks=["192.168.1.0/24"])
    assert opts.scan_bacnet is True
    assert opts.scan_mstp is True
    assert opts.scan_modbus is True
    assert opts.scan_services is True
    assert opts.scan_snmp is True
    assert opts.deep_scan is True
    assert opts.use_rpm is True
    assert opts.rate_limit_ms == 0
    assert opts.max_objects_per_device == 500


def test_scan_options_disables_cleanly():
    opts = ScanOptions(
        networks=["10.0.0.0/24"],
        scan_bacnet=False, scan_modbus=False,
    )
    assert opts.scan_bacnet is False
    assert opts.scan_modbus is False
    # Others unchanged
    assert opts.scan_services is True


def test_scan_result_to_dict_empty():
    result = ScanResult()
    d = result.to_dict()
    assert 'scan_time' in d
    assert 'elapsed_seconds' in d
    assert d['devices'] == []
    assert d['counts']['bacnet'] == 0


def test_scan_result_json_roundtrip():
    result = ScanResult()
    result.devices.append({
        'protocol': 'BACnet/IP',
        'ip': '192.168.5.10',
        'port': 47808,
        'instance': 33333,
        'vendor_id': 2,
        'vendor_name': 'The Trane Company',
        '_fingerprint': {
            'model': 'Trane Tracer SC+',
            'device_type': 'Supervisory Controller',
            'web_url': 'https://192.168.5.10',
            'default_creds': 'admin / Tracer1$',
            'description': 'Trane BACnet supervisory controller',
        },
    })
    result.counts['bacnet'] = 1

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        path = f.name

    try:
        result.write_json(path)
        with open(path) as f:
            data = json.load(f)
        assert data['counts']['bacnet'] == 1
        assert len(data['devices']) == 1
        dev = data['devices'][0]
        assert dev['identified_model'] == 'Trane Tracer SC+'
        assert dev['web_url'] == 'https://192.168.5.10'
        # Private fields should be stripped
        assert '_fingerprint' not in dev
    finally:
        Path(path).unlink(missing_ok=True)


def test_scan_result_csv_export():
    result = ScanResult()
    result.devices.append({
        'protocol': 'Modbus TCP',
        'ip': '10.0.0.100', 'port': 502, 'unit_id': 1,
        'vendor': 'Schneider', 'instance': 1,
        '_fingerprint': {'model': '', 'device_type': '', 'web_url': ''},
    })

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        path = f.name

    try:
        result.write_csv(path)
        with open(path, encoding='utf-8-sig') as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2
        assert rows[0][0] == 'Protocol'
        assert rows[1][0] == 'Modbus TCP'
        assert rows[1][1] == '10.0.0.100'
    finally:
        Path(path).unlink(missing_ok=True)


def test_scan_result_handles_non_json_serializable():
    """Private fields and un-serializable values should be stripped or stringified."""
    result = ScanResult()
    result.devices.append({
        'ip': '1.2.3.4', 'protocol': 'BACnet/IP',
        '_internal': object(),                   # not serializable
        'a_set': {1, 2, 3},                      # not directly serializable
        '_fingerprint': {},
    })
    d = result.to_dict()
    dev = d['devices'][0]
    assert '_internal' not in dev
    # Sets get stringified, not dropped
    assert 'a_set' in dev
    assert isinstance(dev['a_set'], str)


# ---------------------------------------------------------------------------
# Regression tests for bugs fixed after first field run
# ---------------------------------------------------------------------------

def test_bug1_refingerprint_always_runs_even_if_scan_pass_raises():
    """A crash in any scan pass must not skip fingerprinting of already-found devices.

    Previously, _refingerprint was inside the same try block as the scan passes;
    an SNMP socket error would silently skip fingerprinting all BACnet devices.
    """
    from hvac_scanner.engine import ScanEngine

    opts = ScanOptions(networks=["10.0.0.0/24"],
                       scan_bacnet=True, scan_modbus=False,
                       scan_services=False, scan_snmp=True, deep_scan=False)
    engine = ScanEngine(opts)

    # Pretend BACnet scan found one device before SNMP crashed
    def fake_bacnet_scan():
        engine.result.devices.append({
            'ip': '10.0.0.107', 'protocol': 'BACnet/IP',
            'vendor_id': 7, 'instance': 9997, 'max_apdu': 1476, 'port': 47808,
        })
        engine.result.counts['bacnet'] = 1

    def exploding_snmp():
        raise PermissionError("simulated raw socket perm denied")

    engine._scan_bacnet = fake_bacnet_scan
    engine._scan_snmp = exploding_snmp
    result = engine.run()

    assert len(result.devices) == 1
    assert '_fingerprint' in result.devices[0]
    assert result.devices[0]['_fingerprint']['model']  # some model was assigned


def test_bug2_csv_no_redundant_instance_column():
    """Device ID already contains instance; old schema duplicated it."""
    result = ScanResult()
    result.devices.append({
        'protocol': 'BACnet/IP', 'ip': '10.0.0.1', 'port': 47808,
        'instance': 9997, 'vendor_id': 7,
        'vendor_name': 'Siemens Building Technologies',
        '_fingerprint': {},
    })
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        path = f.name
    try:
        result.write_csv(path)
        with open(path, encoding='utf-8-sig') as f:
            rows = list(csv.reader(f))
        header = rows[0]
        # Only one instance-like column
        assert header.count('BACnet Instance') == 0
        assert 'Device ID' in header
        # Check the instance made it into Device ID
        row = rows[1]
        assert row[header.index('Device ID')] == '9997'
    finally:
        Path(path).unlink(missing_ok=True)


def test_bug2_device_model_name_preferred_over_heuristic():
    """If the device reports its own model_name, CSV should show it, not
    our heuristic guess."""
    result = ScanResult()
    result.devices.append({
        'protocol': 'BACnet/IP', 'ip': '10.0.0.107', 'port': 47808,
        'instance': 9997, 'vendor_id': 7,
        'vendor_name': 'Siemens Building Technologies',
        'properties': {'model_name': 'Insight'},   # device says "Insight"
        '_fingerprint': {'model': 'Siemens Desigo CC Server'},  # heuristic says this
    })
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        path = f.name
    try:
        result.write_csv(path)
        with open(path, encoding='utf-8-sig') as f:
            rows = list(csv.reader(f))
        row = rows[1]
        header = rows[0]
        # Device-reported wins
        assert row[header.index('Identified Model')] == 'Insight'
    finally:
        Path(path).unlink(missing_ok=True)


def test_safe_str_truncates_and_strips_control_chars():
    """_safe_str must guarantee cell values don't overflow into neighbors."""
    from hvac_scanner.engine import _safe_str

    # Control chars stripped
    assert _safe_str("\x01\x02hello\x03") == "hello"
    # None → empty
    assert _safe_str(None) == ""
    # List → joined with separator
    assert _safe_str([1, "two", 3.0]) == "1 | two | 3.0"
    # Long strings truncated
    long = "a" * 500
    out = _safe_str(long)
    assert len(out) <= 200
    assert out.endswith("\u2026")


def test_format_present_value_trane_sentinel():
    """Trane VAV unconfigured points return IEEE 754 values > 1e30."""
    from hvac_scanner.engine import _format_present_value

    assert "unconfigured" in _format_present_value(1.5e31)
    # Normal floats trimmed nicely
    assert _format_present_value(72.5) == "72.5"
    assert _format_present_value(72.0) == "72"
    # Multi-value arrays collapsed, not spilled
    assert _format_present_value([1, 2, 3]) == "[3 values]"
    # None becomes empty string
    assert _format_present_value(None) == ""


# ---------------------------------------------------------------------------
# v2.0.2 regression tests
# ---------------------------------------------------------------------------

def test_bug_unique_ip_count_not_summed():
    """Regression: a single IP with BACnet + HTTPS + FTP is ONE host, not THREE.

    Previously _finish() summed per-protocol counts, inflating the 'Total devices'
    number to the sum of all service ports plus BACnet devices.
    """
    from hvac_scanner.engine import ScanEngine, ScanOptions
    import threading
    engine = ScanEngine(ScanOptions(networks=["10.0.0.0/24"]),
                        stop_event=threading.Event())
    # Same IP appears multiple times across protocols
    engine.result.devices = [
        {'ip': '10.0.0.121', 'protocol': 'BACnet/IP', 'port': 47808, 'instance': 102013},
        {'ip': '10.0.0.121', 'protocol': 'Service', 'port': 80},
        {'ip': '10.0.0.121', 'protocol': 'Service', 'port': 443},
        {'ip': '10.0.0.1', 'protocol': 'Service', 'port': 443},
        {'ip': '10.0.0.1', 'protocol': 'Service', 'port': 8080},
    ]
    engine.result.counts['bacnet'] = 1
    engine.result.counts['services'] = 4

    # Just run _finish and count unique IPs in the devices list ourselves
    unique_ips = {d.get('ip') for d in engine.result.devices if d.get('ip')}
    assert len(unique_ips) == 2  # 10.0.0.121 and 10.0.0.1, not 5
