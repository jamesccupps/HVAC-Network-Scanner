"""2.14.1: what a site's two scans, one from the controls subnet and one routed
in from the office network, showed. A P2 supervisor that closes just past 2 s
was dropped; a routed scan found no MS/TP devices and said nothing; a lost
modelName read named a DXR2 a PXC, with the PXC default password."""
import socket
import sys
from pathlib import Path

import pytest

from hvac_scanner import bacnet, p2
from hvac_scanner.engine import ScanEngine, ScanOptions, _foreign_device_bbmd
from hvac_scanner.fingerprint import fingerprint_device
from hvac_scanner.report import render_html

from .mock_device import MockBACnetDevice


# -- P2: a supervisor listener that takes its time --------------------------------

def test_a_supervisor_that_closes_after_two_seconds_is_still_found():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import sim_site
    try:
        node = sim_site.P2Node('127.0.1.48', 'SIMBLN', 'DCC', supervisor=True, close_after=2.3)
    except OSError as e:
        pytest.skip(f"cannot bind a simulated P2 node: {e}")
    try:
        found = p2.P2Scanner(timeout=2.0).scan_network('127.0.1.48')
    finally:
        node.close()
    assert [d['p2_role'] for d in found] == ['supervisor listener']
    assert p2.CLOSE_WAIT_S > 2.3


# -- MS/TP from another subnet -----------------------------------------------------

def _bbmd(bdt, fdt):
    return {'bdt': [{'address': f"{a}:47808", 'mask': '255.255.255.255'} for a in bdt],
            'fdt': fdt}


# The site's tables, in documentation addresses: two BBMDs on one subnet that
# answered no FDT read, one with a stale table, and the one that takes foreign
# devices and peers with the other subnet.
SITE_BBMDS = {
    '192.0.2.107': _bbmd(['192.0.2.107', '198.51.100.200'], None),
    '192.0.2.108': _bbmd(['192.0.2.108', '198.51.100.200'], None),
    '192.0.2.192': _bbmd(['203.0.113.166', '203.0.113.20', '192.0.2.192'], []),
    '198.51.100.200': _bbmd(['198.51.100.200', '192.0.2.108'], []),
}


def _unicast(ip, instance, **extra):
    return {'ip': ip, 'instance': instance, 'protocol': 'BACnet/IP',
            'discovered_via': 'unicast', **extra}


def test_the_suggested_bbmd_takes_foreign_devices_and_reaches_the_most():
    devices = [_unicast(ip, i, bbmd=t) for i, (ip, t) in enumerate(SITE_BBMDS.items())]
    assert _foreign_device_bbmd(devices) == '198.51.100.200'
    # Without it: a BBMD that keeps an FDT beats a better-connected one that didn't answer.
    assert _foreign_device_bbmd(devices[:3]) == '192.0.2.192'
    assert _foreign_device_bbmd(devices[:2]) == '192.0.2.107'
    assert _foreign_device_bbmd([_unicast('192.0.2.5', 1)]) is None


class _QuietRouters:
    """Routers on another subnet: none answers a direct Who-Is-Router-To-Network."""
    def discover_routers_unicast(self, ips, **_kw):
        return []

    def discover_who_is_networks(self, **_kw):
        return []


def _remote_engine(devices, **opts):
    logs = []
    eng = ScanEngine(ScanOptions(networks=["192.0.2.0/24", "198.51.100.0/24"], **opts),
                     callback=logs.append)
    eng.result.devices = devices
    return eng, logs


def test_a_routed_scan_says_mstp_devices_are_out_of_sight_and_how_to_see_them():
    devices = ([_unicast(ip, i, bbmd=t) for i, (ip, t) in enumerate(SITE_BBMDS.items())]
               + [_unicast('192.0.2.19', 33333), _unicast('198.51.100.81', 107001)])
    eng, logs = _remote_engine(devices)
    eng._scan_remote_mstp(_QuietRouters())
    hint = next(line for line in logs if "answered only when asked directly" in line)
    assert "192.0.2.0/24, 198.51.100.0/24" in hint
    assert "--bbmd 198.51.100.200" in hint
    assert eng.result.remote_mstp == {'bbmd': '198.51.100.200', 'networks': [],
                                      'subnets': ['192.0.2.0/24', '198.51.100.0/24']}
    assert eng.result.to_dict()['coverage']['remote_mstp'] == eng.result.remote_mstp


def test_no_mstp_hint_for_a_subnet_whose_broadcasts_arrive():
    """From the controls subnet itself, devices on the other one were partly
    found by unicast too, but its broadcasts arrived through the BBMDs."""
    devices = [_unicast('198.51.100.81', 107001),
               {'ip': '198.51.100.82', 'instance': 107002, 'protocol': 'BACnet/IP',
                'discovered_via': None}]
    eng, logs = _remote_engine(devices)
    eng._scan_remote_mstp(_QuietRouters())
    assert eng.result.remote_mstp is None
    assert not any("asked directly" in line for line in logs)


def test_no_mstp_hint_when_registered_with_a_bbmd():
    eng, logs = _remote_engine([_unicast('198.51.100.81', 107001)], bbmd='198.51.100.200')
    eng._scan_remote_mstp(_QuietRouters())
    assert eng.result.remote_mstp is None


def test_the_report_carries_the_mstp_note():
    def page(remote):
        return render_html({'devices': [], 'coverage': {
            'stopped': False, 'passes': {'bacnet': 'scanned'}, 'options': {},
            'remote_mstp': remote}})
    text = page({'bbmd': '198.51.100.200', 'networks': [],
                 'subnets': ['192.0.2.0/24', '198.51.100.0/24']})
    assert "BACnet devices on 192.0.2.0/24, 198.51.100.0/24 answered only when asked" in text
    assert "--bbmd 198.51.100.200" in text
    text = page({'bbmd': None, 'networks': [11, 114], 'subnets': ['192.0.2.0/24']})
    assert "MS/TP network(s) 11, 114 behind routers on 192.0.2.0/24 did not answer" in text
    assert "register with a BBMD on that subnet" in text
    text = page(None)
    assert "answered only when asked" not in text and "did not answer" not in text


# -- identity reads ---------------------------------------------------------------

@pytest.fixture
def mock_client(monkeypatch):
    def _open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        s.bind(("", 0))
        self._sock, self._bound_port = s, s.getsockname()[1]
        return self._bound_port
    monkeypatch.setattr(bacnet.BACnetClient, "open", _open)
    made = []

    def _make(timeout=0.3):
        c = bacnet.BACnetClient(timeout=timeout)
        c.open()
        made.append(c)
        return c
    yield _make
    for c in made:
        c.close()


def test_a_dropped_model_name_read_is_asked_again(mock_client):
    """The batched read went unanswered, then so did modelName on its own.
    It is asked once more; a property the device refuses is not."""
    with MockBACnetDevice(model='DXR2.E12P-1', drop_rpm={1}, drop_rp={70}) as dev:
        props = mock_client().read_device_info('127.0.0.1', dev.instance)
    assert props['model_name'] == 'DXR2.E12P-1'
    assert dev.rp_props.count(70) == 2
    assert dev.rp_props.count(58) == 1          # location: an Error, not asked again


def test_a_dropped_segmentation_read_is_asked_again(mock_client):
    """Unicast discovery fills in what an I-Am says; a lost read left one
    DXR2's segmentation blank."""
    with MockBACnetDevice(drop_rpm={1}, drop_rp={107}) as dev:
        dev.dev_props.update({120: bytes([0x21, 7]),            # vendorIdentifier
                              62: bytes([0x22, 0x05, 0xC4]),    # maxApduLengthAccepted
                              107: bytes([0x91, 0x00])})        # segmentationSupported: both
        c = mock_client()
        found = c._describe_found('127.0.0.1', dev.instance)
    assert found['segmentation'] == 'Both'
    assert dev.rp_props.count(107) == 2


def test_a_device_that_answers_nothing_is_not_asked_twice():
    c = bacnet.BACnetClient(timeout=0.1)
    asked = []

    def silent(ip, obj_type, instance, name, dnet=None, dadr=None):
        asked.append(name)
        c._local.unanswered = True
        return None
    c.read_property = silent
    assert c._read_each('192.0.2.9', 'Device', 1, ['object-name', 'model-name']) == {}
    assert asked == ['object-name', 'model-name']


def test_a_siemens_device_without_a_model_is_not_called_a_pxc():
    dev = {'ip': '198.51.100.81', 'protocol': 'BACnet/IP', 'vendor_id': 7,
           'instance': 107001, 'max_apdu': 1476, 'properties': {'object_name': 'VAV'}}
    fp = fingerprint_device(dev, [])
    assert fp['model'] == 'Siemens Controller' and fp['default_creds'] == ''
    dev['properties']['model_name'] = 'DXR2.E12P-1'
    fp = fingerprint_device(dev, [])
    assert fp['model'] == 'DXR2.E12P-1' and 'DXR2' in fp['description']
