"""X.509 parsing for the HTTPS service probe.

The services scan already established TLS to every 443/8443 it found and then
discarded the certificate. BAS controllers put the product line and often the
panel name in the subject CN, and the expiry date is operational information
the system owner wants regardless of fingerprinting.

DER is BER — the same tag-length-value encoding the BACnet codec and the SNMP
probe already decode — so this is hand-rolled rather than pulling in an ASN.1
dependency for four fields.

Fixtures are generated at import time with `openssl` where it is available and
skipped where it is not, so the certificates under test are real rather than
hand-assembled bytes that only prove the parser agrees with itself.
"""

import base64
import datetime
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path

import pytest

from hvac_scanner.certs import Certificate, parse_der_certificate

openssl = shutil.which('openssl')
needs_openssl = pytest.mark.skipif(not openssl, reason="openssl not available")


def _make_cert(subject, days=365, extra=()):
    """Generate a self-signed certificate and return its DER bytes.

    A fixture that will not build is an environment problem, not a defect in
    the parser, so this skips with openssl's own message rather than failing.
    openssl's CLI differs across distributions and major versions — notably in
    how `-subj` handles anything outside ASCII — and a parser test should not
    be reporting on that.
    """
    tmp = Path(tempfile.mkdtemp())
    key, crt = tmp / 'k.pem', tmp / 'c.pem'
    cmd = [openssl, 'req', '-x509', '-newkey', 'rsa:2048',
           '-keyout', str(key), '-out', str(crt), '-days', str(days),
           '-nodes', '-subj', subject, *extra]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0 or not crt.exists():
        pytest.skip("openssl could not generate a fixture for %r: %s"
                    % (subject, proc.stderr.decode('utf-8', 'replace')[-300:]))
    return ssl.PEM_cert_to_DER_cert(crt.read_text())


# -- structure --------------------------------------------------------------

@needs_openssl
class TestRealCertificates:

    def test_subject_common_name(self):
        c = parse_der_certificate(_make_cert('/CN=PXC-Compact'))
        assert c.subject_cn == 'PXC-Compact'

    def test_subject_organisation(self):
        c = parse_der_certificate(
            _make_cert('/CN=AHU-1/O=Siemens Building Technologies'))
        assert c.subject_cn == 'AHU-1'
        assert c.subject_o == 'Siemens Building Technologies'

    def test_self_signed_is_detected(self):
        """Near-universal on BAS gear, and it tells the reader the CN is
        self-asserted rather than vouched for."""
        c = parse_der_certificate(_make_cert('/CN=Tracer-SC'))
        assert c.issuer_cn == 'Tracer-SC'
        assert c.self_signed is True

    def test_validity_window_is_parsed(self):
        c = parse_der_certificate(_make_cert('/CN=Panel', days=30))
        assert c.not_before is not None and c.not_after is not None
        assert c.not_after > c.not_before
        assert 28 <= c.days_until_expiry() <= 30

    def test_not_expired_when_still_valid(self):
        assert parse_der_certificate(_make_cert('/CN=Panel', days=90)).expired is False

    def test_serial_is_captured(self):
        c = parse_der_certificate(_make_cert('/CN=Panel'))
        assert c.serial and all(ch in '0123456789ABCDEF' for ch in c.serial)

    def test_summary_reads_like_a_sentence(self):
        c = parse_der_certificate(_make_cert('/CN=PXC-Compact/O=Siemens', days=45))
        text = c.summary()
        assert 'CN=PXC-Compact' in text
        assert 'self-signed' in text
        assert 'expires in' in text

    def test_hyphenated_and_spaced_subjects_survive(self):
        c = parse_der_certificate(_make_cert('/CN=AHU-1 Supply Fan/O=Test BAS Ltd'))
        assert c.subject_cn == 'AHU-1 Supply Fan'
        assert c.subject_o == 'Test BAS Ltd'

    def test_to_dict_is_json_safe(self):
        import json
        json.dumps(parse_der_certificate(_make_cert('/CN=Panel')).to_dict())


# -- string encodings -------------------------------------------------------

def _der(tag, content):
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    n = (len(content).bit_length() + 7) // 8
    return bytes([tag, 0x80 | n]) + len(content).to_bytes(n, 'big') + content


def _name_with_cn(tag, encoded_cn):
    """Build an X.501 Name whose commonName uses the given string type."""
    atv = _der(0x30, _der(0x06, bytes([0x55, 0x04, 0x03])) + _der(tag, encoded_cn))
    return _der(0x30, _der(0x31, atv))


def _minimal_cert(subject_name, issuer_name=None):
    """A certificate with just enough structure to exercise Name parsing."""
    issuer_name = issuer_name if issuer_name is not None else subject_name
    validity = _der(0x30,
                    _der(0x17, b'260101000000Z') + _der(0x17, b'270101000000Z'))
    tbs = _der(0x30,
               _der(0xA0, _der(0x02, b'\x02'))       # version v3
               + _der(0x02, b'\x01\x23')            # serial
               + _der(0x30, _der(0x06, bytes([0x2A])))  # sig alg
               + issuer_name + validity + subject_name)
    return _der(0x30, tbs + _der(0x30, b'') + _der(0x03, b'\x00'))


class TestStringEncodings:
    """Certificates in the field use several ASN.1 string types for the same
    field. These build the DER directly so the encoding under test is the one
    intended, rather than whatever the local openssl chose."""

    def test_printable_string(self):
        cert = parse_der_certificate(
            _minimal_cert(_name_with_cn(0x13, b'PXC-Compact')))
        assert cert.subject_cn == 'PXC-Compact'

    def test_utf8_string(self):
        cert = parse_der_certificate(
            _minimal_cert(_name_with_cn(0x0C, 'Gebäude-Nord'.encode('utf-8'))))
        assert cert.subject_cn == 'Gebäude-Nord'

    def test_bmp_string(self):
        cert = parse_der_certificate(
            _minimal_cert(_name_with_cn(0x1E, 'Panel-1'.encode('utf-16-be'))))
        assert cert.subject_cn == 'Panel-1'

    def test_ia5_string(self):
        cert = parse_der_certificate(
            _minimal_cert(_name_with_cn(0x16, b'panel.example')))
        assert cert.subject_cn == 'panel.example'

    def test_issuer_and_subject_are_distinguished(self):
        cert = parse_der_certificate(_minimal_cert(
            subject_name=_name_with_cn(0x13, b'Panel'),
            issuer_name=_name_with_cn(0x13, b'Site CA')))
        assert cert.subject_cn == 'Panel'
        assert cert.issuer_cn == 'Site CA'
        assert cert.self_signed is False

    def test_validity_from_utctime(self):
        cert = parse_der_certificate(_minimal_cert(_name_with_cn(0x13, b'P')))
        assert cert.not_before.year == 2026
        assert cert.not_after.year == 2027


# -- agreement with the standard library ------------------------------------

@needs_openssl
def test_agrees_with_the_stdlib_decoder():
    """The parser has to match Python's own decoder, not merely be
    self-consistent."""
    if not hasattr(ssl, '_ssl') or not hasattr(ssl._ssl, '_test_decode_cert'):
        pytest.skip("ssl._ssl._test_decode_cert is not available on this build")
    der = _make_cert('/CN=Reference/O=TestOrg')
    tmp = Path(tempfile.mkdtemp()) / 'c.pem'
    tmp.write_text(ssl.DER_cert_to_PEM_cert(der))
    ref = ssl._ssl._test_decode_cert(str(tmp))
    ours = parse_der_certificate(der)
    ref_subject = dict(x[0] for x in ref['subject'])
    assert ours.subject_cn == ref_subject.get('commonName')
    assert ours.subject_o == ref_subject.get('organizationName')
    ref_after = datetime.datetime.strptime(ref['notAfter'], '%b %d %H:%M:%S %Y %Z')
    assert ours.not_after.replace(tzinfo=None) == ref_after


# -- robustness -------------------------------------------------------------

class TestMalformedInput:
    """A scanner must not fall over because one device presents a broken
    certificate, and building-automation gear presents plenty."""

    @pytest.mark.parametrize("data", [
        b'', b'\x00', b'\x30', b'\x30\x82', b'\x30\x82\xff\xff',
        b'\x30\x05\x02\x03\x01\x02\x03',
        b'not der at all',
        bytes(range(256)),
    ])
    def test_garbage_returns_none_without_raising(self, data):
        assert parse_der_certificate(data) is None

    @needs_openssl
    def test_truncated_certificate_returns_none(self):
        der = _make_cert('/CN=Panel')
        for cut in (10, len(der) // 3, len(der) // 2, len(der) - 1):
            assert parse_der_certificate(der[:cut]) is None

    @needs_openssl
    def test_trailing_garbage_is_ignored(self):
        der = _make_cert('/CN=Panel')
        assert parse_der_certificate(der + b'\xff' * 32).subject_cn == 'Panel'


# -- expiry arithmetic ------------------------------------------------------

class TestExpiry:

    def _cert(self, days_offset):
        when = (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=days_offset))
        return Certificate(subject_cn='X', issuer_cn='X', not_after=when)

    def test_future_expiry_is_positive(self):
        assert self._cert(45).days_until_expiry() in (44, 45)
        assert self._cert(45).expired is False

    def test_past_expiry_is_negative(self):
        assert self._cert(-10).days_until_expiry() in (-10, -11)
        assert self._cert(-10).expired is True

    def test_unknown_expiry_is_none_not_a_guess(self):
        c = Certificate(subject_cn='X')
        assert c.days_until_expiry() is None
        assert c.expired is None

    def test_expired_summary_says_how_long_ago(self):
        assert 'expired' in self._cert(-5).summary()


# -- integration with the service probe -------------------------------------

@needs_openssl
class TestServiceProbeIntegration:

    def test_probe_attaches_the_certificate(self, tmp_path):
        """Serve HTTPS with a known certificate and confirm the probe reports
        it, including the expiry warning for a short-lived one."""
        import http.server
        import socket
        import ssl as _ssl
        import threading

        from hvac_scanner.services import HVACServiceScanner

        key, crt = tmp_path / 'k.pem', tmp_path / 'c.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048',
                        '-keyout', str(key), '-out', str(crt), '-days', '10',
                        '-nodes', '-subj', '/CN=AHU-Panel/O=TestBAS'],
                       capture_output=True, check=True)

        class Quiet(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<html><title>Panel Login</title></html>"
                self.send_response(200)
                self.send_header('Server', 'TestPanel/1.0')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(('127.0.0.1', 0), Quiet)
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.handle_request, daemon=True)
        t.start()

        logs = []
        scanner = HVACServiceScanner(timeout=6, callback=logs.append)
        try:
            info = scanner._http_banner('127.0.0.1', port, use_ssl=True)
        finally:
            srv.server_close()

        assert info['tls']['subject_cn'] == 'AHU-Panel'
        assert info['tls']['subject_o'] == 'TestBAS'
        assert info['tls']['self_signed'] is True
        assert 'AHU-Panel' in info['tls_summary']
        # 10-day certificate is inside the 30-day warning window
        assert any('expires in' in line for line in logs)

    def test_plain_http_has_no_tls_fields(self):
        from hvac_scanner.services import HVACServiceScanner
        info = HVACServiceScanner(timeout=0.2)._http_banner('127.0.0.1', 1)
        assert 'tls' not in info
