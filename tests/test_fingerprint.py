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


def test_vendor_485_is_scs_not_contemporary_controls():
    """485 is SCS in the ASHRAE registry, not Contemporary Controls.

    This test previously asserted the opposite, codifying the desync
    introduced when BACNET_VENDORS was regenerated in v2.1.1.
    """
    dev = {
        'ip': '192.168.5.3', 'protocol': 'BACnet/IP',
        'vendor_id': 485, 'instance': 50002, 'max_apdu': 1476,
    }
    fp = fingerprint_device(dev, [])
    assert 'BASRT-B' not in fp['model']
    assert 'SCS' in fp['model']


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


# ---------------------------------------------------------------------------
# Guard: the vendor IDs this module branches on must agree with the ASHRAE
# registry in constants.py.
#
# v2.1.1 regenerated BACNET_VENDORS from the official list (34 -> 593 entries)
# without re-checking the hardcoded IDs in fingerprint.py. Two branches
# silently desynced: 485 (SCS) was treated as Contemporary Controls, and
# 13/514 (Teletrol Systems / t-mac Technologies) as Cimetrics. The SCS case
# also attached another vendor's default credentials to the result. These
# tests fail loudly if a future registry update desyncs them again.
# ---------------------------------------------------------------------------

from hvac_scanner.constants import BACNET_VENDORS
from hvac_scanner import fingerprint as _fp


def test_vendor_id_constants_match_the_registry():
    expected = {
        _fp.VENDOR_TRANE:              'trane',
        _fp.VENDOR_JOHNSON_CONTROLS:   'johnson',
        _fp.VENDOR_CIMETRICS:          'cimetrics',
        _fp.VENDOR_CONTEMPORARY:       'contemporary',
    }
    for vid, substring in expected.items():
        assert vid in BACNET_VENDORS, f"vendor id {vid} missing from registry"
        assert substring in BACNET_VENDORS[vid].lower(), (
            f"vendor id {vid} is {BACNET_VENDORS[vid]!r}, expected a "
            f"{substring!r} vendor"
        )


def test_siemens_vendor_ids_match_the_registry():
    for vid in _fp.VENDORS_SIEMENS:
        assert vid in BACNET_VENDORS, f"vendor id {vid} missing from registry"
        assert 'siemens' in BACNET_VENDORS[vid].lower(), (
            f"vendor id {vid} is {BACNET_VENDORS[vid]!r}, expected Siemens"
        )


def test_scs_is_not_identified_as_a_contemporary_controls_router():
    """485 is SCS. It must not inherit Contemporary Controls' default creds."""
    assert 'contemporary' not in BACNET_VENDORS[485].lower()
    info = fingerprint_device({'ip': '10.0.0.5', 'vendor_id': 485,
                               'protocol': 'BACnet/IP'})
    assert 'BASRT' not in info['model']
    assert info['default_creds'] == ''


def test_teletrol_and_tmac_are_not_identified_as_cimetrics():
    for vid in (13, 514):
        assert 'cimetrics' not in BACNET_VENDORS[vid].lower()
        info = fingerprint_device({'ip': '10.0.0.6', 'vendor_id': vid,
                                   'protocol': 'BACnet/IP'})
        assert 'Cimetrics' not in info['model']


def test_cimetrics_is_identified_at_its_real_vendor_id():
    info = fingerprint_device({'ip': '10.0.0.7', 'vendor_id': 14,
                               'protocol': 'BACnet/IP'})
    assert 'Cimetrics' in info['model']


def test_contemporary_controls_still_identified_at_245():
    info = fingerprint_device({'ip': '10.0.0.8', 'vendor_id': 245,
                               'protocol': 'BACnet/IP'})
    assert 'BASRT-B' in info['model']
    assert info['default_creds'] == 'admin / admin'


def test_siemens_alternate_vendor_ids_are_fingerprinted():
    """A device reporting 9, 22, or 313 is still Siemens, not an unknown."""
    for vid in _fp.VENDORS_SIEMENS:
        info = fingerprint_device({'ip': '10.0.0.9', 'vendor_id': vid,
                                   'protocol': 'BACnet/IP'})
        assert 'Siemens' in info['model'], f"vendor {vid} -> {info['model']!r}"


# ---------------------------------------------------------------------------
# DEFAULT_CREDS was defined in constants.py and never read by anything: all
# emitted credentials came from literals inside the vendor branches, so only
# Trane / Siemens / JCI / Contemporary Controls ever produced a value while
# the README advertised coverage for 18 more vendors.
# ---------------------------------------------------------------------------

from hvac_scanner.constants import DEFAULT_CREDS


def test_default_creds_table_is_actually_reachable():
    """Every key in DEFAULT_CREDS must be reachable by at least one route."""
    from hvac_scanner.fingerprint import (
        _VENDOR_ID_TO_CREDS_KEY, _lookup_default_creds,
    )
    reachable = set(_VENDOR_ID_TO_CREDS_KEY.values())
    for key in DEFAULT_CREDS:
        # Either a vendor ID maps to it, or its own name matches it.
        if key in reachable:
            continue
        assert _lookup_default_creds(key, None) == DEFAULT_CREDS[key], (
            f"DEFAULT_CREDS key {key!r} is unreachable"
        )


def test_creds_vendor_id_map_agrees_with_the_registry():
    """Each mapped vendor ID must exist and its creds key must be a real key."""
    from hvac_scanner.fingerprint import _VENDOR_ID_TO_CREDS_KEY
    for vid, key in _VENDOR_ID_TO_CREDS_KEY.items():
        assert vid in BACNET_VENDORS, f"vendor id {vid} not in registry"
        assert key in DEFAULT_CREDS, f"{key!r} is not a DEFAULT_CREDS key"


def test_previously_uncovered_vendors_now_get_credentials():
    """The vendors the README promised but the code never delivered."""
    expected = {
        24:  'Automated Logic WebCTRL',
        36:  'Honeywell Tridium Niagara',
        28:  'KMC Controls',
        364: 'Distech Controls',
        35:  'Reliable Controls',
        8:   'Delta Controls',
        77:  'Carel pCO',
        284: 'Belimo',
        502: 'EasyIO',
        3:   'Daikin',
        16:  'Carrier i-Vu',
        10:  'Schneider EcoStruxure',
    }
    for vid, key in expected.items():
        info = fingerprint_device({'ip': '10.0.0.5', 'vendor_id': vid,
                                   'protocol': 'BACnet/IP'})
        assert info['default_creds'] == DEFAULT_CREDS[key], (
            f"vendor {vid} -> {info['default_creds']!r}"
        )


def test_model_specific_creds_still_win_over_the_table():
    """A branch that knows the exact model must not be overwritten."""
    info = fingerprint_device({
        'ip': '10.0.0.19', 'protocol': 'BACnet/IP',
        'vendor_id': 2, 'instance': 33333, 'max_apdu': 1024,
    }, [])
    assert info['model'] == 'Trane Tracer SC+'
    assert info['default_creds'] == 'admin / Tracer1$'


def test_longest_key_wins_the_substring_match():
    from hvac_scanner.fingerprint import _lookup_default_creds
    assert _lookup_default_creds('Trane Tracer SC+', 2) == DEFAULT_CREDS['Trane Tracer SC+']


def test_unknown_vendor_gets_no_credentials():
    """An empty column is honest; a guessed credential is not."""
    info = fingerprint_device({'ip': '10.0.0.5', 'vendor_id': 9999,
                               'protocol': 'BACnet/IP'})
    assert info['default_creds'] == ''
