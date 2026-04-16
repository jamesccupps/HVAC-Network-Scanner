"""Device fingerprinting tests."""

from hvac_scanner.fingerprint import fingerprint_device


def test_trane_tracer_sc_plus():
    dev = {
        'ip': '192.168.5.10', 'protocol': 'BACnet/IP',
        'vendor_id': 2, 'instance': 33333, 'max_apdu': 1024,
    }
    services = [{'ip': '192.168.5.10', 'port': 443, 'protocol': 'Service', 'server': 'nginx'}]
    fp = fingerprint_device(dev, services)
    assert 'Trane Tracer SC+' in fp['model']
    assert 'admin / Tracer1$' in fp['default_creds']
    assert fp['web_url'] == 'https://192.168.5.10'


def test_siemens_desigo_with_nucleus_ftp():
    dev = {
        'ip': '10.0.0.5', 'protocol': 'BACnet/IP',
        'vendor_id': 7, 'instance': 1000, 'max_apdu': 1476,
    }
    services = [
        {'ip': '10.0.0.5', 'port': 21, 'protocol': 'Service',
         'banner': 'Nucleus FTP Server', 'server': '', 'title': ''},
        {'ip': '10.0.0.5', 'port': 80, 'protocol': 'Service',
         'banner': '', 'server': '', 'title': ''},
    ]
    fp = fingerprint_device(dev, services)
    assert 'Desigo PXC' in fp['model']
    assert 'Automation Station' in fp['device_type']
    assert 'SBTAdmin' in fp['default_creds']


def test_jci_mstp_field_controller():
    dev = {
        'ip': '192.168.5.1', 'protocol': 'BACnet/MSTP',
        'vendor_id': 5, 'instance': 40005, 'max_apdu': 480,
        'source_network': 42, 'source_address': '5',
    }
    fp = fingerprint_device(dev, [])
    assert 'JCI' in fp['model']
    assert 'MSTP' in fp['device_type']


def test_contemporary_controls_router():
    dev = {
        'ip': '192.168.5.2', 'protocol': 'BACnet/IP',
        'vendor_id': 245, 'instance': 50001, 'max_apdu': 1476,
    }
    services = [{'ip': '192.168.5.2', 'port': 80, 'protocol': 'Service',
                 'banner': '', 'server': '', 'title': ''}]
    fp = fingerprint_device(dev, services)
    assert 'BASRT-B' in fp['model']
    assert 'Router' in fp['device_type']


def test_contemporary_controls_vendor_485_also_works():
    dev = {
        'ip': '192.168.5.3', 'protocol': 'BACnet/IP',
        'vendor_id': 485, 'instance': 50002, 'max_apdu': 1476,
    }
    fp = fingerprint_device(dev, [])
    assert 'BASRT-B' in fp['model']


def test_snmp_trane_fallback():
    dev = {
        'ip': '192.168.5.50', 'protocol': 'SNMP',
        'sys_descr': 'Trane Tracer Concierge v4.0',
    }
    fp = fingerprint_device(dev, [])
    assert 'Trane' in fp['model']


def test_unknown_vendor_fallback():
    dev = {
        'ip': '192.168.5.99', 'protocol': 'BACnet/IP',
        'vendor_id': 9999, 'instance': 1,
    }
    fp = fingerprint_device(dev, [])
    assert fp['model']  # something was assigned


def test_service_only_unifi():
    dev = {
        'ip': '192.168.5.1', 'protocol': 'Service',
        'port': 443, 'title': 'UniFi Network', 'banner': '',
    }
    fp = fingerprint_device(dev, [dev])
    assert 'UniFi' in fp['model']
