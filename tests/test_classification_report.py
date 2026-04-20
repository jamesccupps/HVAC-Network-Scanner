"""Tests for the v2.2 classification report writer."""

import os
import tempfile

import pytest

from hvac_scanner.engine import ScanResult


def _make_device(ip, instance, classification=None, obj_name='', model='', vendor='',
                 points=0):
    """Build a device dict matching what the engine would produce."""
    dev = {
        'protocol': 'BACnet/IP',
        'ip': ip,
        'port': 47808,
        'instance': instance,
        'properties': {
            'object_name': obj_name,
            'model_name': model,
            'vendor_name': vendor,
        },
        'objects': [{'type': 'Analog Input', 'instance': i, 'name': f'pt{i}'}
                    for i in range(points)],
    }
    if classification:
        dev['_classification'] = classification
    return dev


class TestClassificationReportBasics:

    def test_writes_file(self):
        r = ScanResult()
        r.devices = [_make_device('10.0.0.19', 33333)]
        with tempfile.NamedTemporaryFile(mode='r', suffix='.txt',
                                          delete=False) as f:
            path = f.name
        try:
            r.write_classification_report(path)
            assert os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert 'HVAC Network Scanner' in content
            assert 'Classification Report' in content
        finally:
            os.unlink(path)

    def test_includes_device_metadata(self):
        r = ScanResult()
        r.devices = [_make_device(
            '10.0.0.19', 33333,
            obj_name='SC-1 + E22J04614',
            model='Tracer SC+',
            vendor='The Trane Company',
            points=5474,
            classification={
                'vendor_name': 'The Trane Company',
                'model_name': 'Tracer SC+',
                'object_count': 5517,
                'profile_class': 'Trane supervisory (SC+)',
                'profile_cap': 5000,
                'profile_verified_at': 'OCC Portland 2026-04-20',
                'explanation': 'known device [Trane supervisory (SC+)] — cap 5000',
                'depth_note': None,
            },
        )]
        with tempfile.NamedTemporaryFile(mode='r', suffix='.txt',
                                          delete=False) as f:
            path = f.name
        try:
            r.write_classification_report(path)
            with open(path) as f:
                content = f.read()
            # Key details should all be present
            assert '10.0.0.19' in content
            assert '33333' in content
            assert 'SC-1 + E22J04614' in content
            assert 'Tracer SC+' in content
            assert 'The Trane Company' in content
            assert '5517' in content  # object count
            assert '5000' in content  # cap
            assert 'known device' in content
        finally:
            os.unlink(path)

    def test_summary_counts_classification_paths(self):
        r = ScanResult()
        r.devices = [
            _make_device('10.0.0.1', 1, classification={
                'vendor_name': 'X', 'model_name': 'Y', 'object_count': 100,
                'profile_class': 'foo', 'profile_cap': 500,
                'profile_verified_at': None,
                'explanation': 'known device [foo] — cap 500',
                'depth_note': None,
            }),
            _make_device('10.0.0.2', 2, classification={
                'vendor_name': 'X', 'model_name': 'Z', 'object_count': 100,
                'profile_class': 'bar', 'profile_cap': 500,
                'profile_verified_at': None,
                'explanation': 'vendor-substring match [bar] — cap 500',
                'depth_note': None,
            }),
            _make_device('10.0.0.3', 3, classification={
                'vendor_name': '', 'model_name': '', 'object_count': 75,
                'profile_class': 'unknown', 'profile_cap': 175,
                'profile_verified_at': None,
                'explanation': 'heuristic [small, 75 objects] — cap 175',
                'depth_note': None,
            }),
        ]
        with tempfile.NamedTemporaryFile(mode='r', suffix='.txt',
                                          delete=False) as f:
            path = f.name
        try:
            r.write_classification_report(path)
            with open(path) as f:
                content = f.read()
            # Summary should break down by path
            assert 'Known device (exact profile):' in content
            assert 'Vendor-substring match:' in content
            assert 'Heuristic fallback' in content
            # With one heuristic device, the contribution call-to-action appears
            assert 'submitting a' in content and 'device profile' in content
            assert 'github.com' in content.lower()
        finally:
            os.unlink(path)

    def test_excludes_non_bacnet_devices(self):
        """Modbus / services / SNMP devices don't have classification —
        they shouldn't appear in the classification report."""
        r = ScanResult()
        r.devices = [
            _make_device('10.0.0.1', 1, classification={
                'vendor_name': 'X', 'model_name': 'Y', 'object_count': 10,
                'profile_class': 'foo', 'profile_cap': 100,
                'profile_verified_at': None,
                'explanation': 'known device',
                'depth_note': None,
            }),
            {
                'protocol': 'Modbus TCP', 'ip': '10.0.0.50',
                'port': 502, 'unit_id': 1,
            },
        ]
        with tempfile.NamedTemporaryFile(mode='r', suffix='.txt',
                                          delete=False) as f:
            path = f.name
        try:
            r.write_classification_report(path)
            with open(path) as f:
                content = f.read()
            assert '10.0.0.1' in content
            assert '10.0.0.50' not in content  # modbus excluded
        finally:
            os.unlink(path)

    def test_handles_empty_result(self):
        r = ScanResult()
        r.devices = []
        with tempfile.NamedTemporaryFile(mode='r', suffix='.txt',
                                          delete=False) as f:
            path = f.name
        try:
            r.write_classification_report(path)
            with open(path) as f:
                content = f.read()
            # Should still produce a valid report with zeros
            assert 'Total BACnet devices classified: 0' in content
        finally:
            os.unlink(path)

    def test_no_privacy_leaks(self):
        """Classification reports are designed to be safely shared on GitHub.
        They must NOT contain point names, present values, or other
        site-specific data that might expose operational information."""
        r = ScanResult()
        r.devices = [_make_device(
            '10.0.0.19', 33333,
            obj_name='SC-1',
            points=100,  # 100 points with names 'pt0', 'pt1', ...
            classification={
                'vendor_name': 'Trane', 'model_name': 'SC+',
                'object_count': 100, 'profile_class': 'x',
                'profile_cap': 500, 'profile_verified_at': None,
                'explanation': 'known', 'depth_note': None,
            },
        )]
        with tempfile.NamedTemporaryFile(mode='r', suffix='.txt',
                                          delete=False) as f:
            path = f.name
        try:
            r.write_classification_report(path)
            with open(path) as f:
                content = f.read()
            # Point names should NOT appear — only the count
            assert 'pt0' not in content
            assert 'pt50' not in content
            assert 'points_read:' in content
            assert '100' in content  # count, fine
        finally:
            os.unlink(path)
