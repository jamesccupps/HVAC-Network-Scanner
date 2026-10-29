"""
HVAC service port scanner.

Probes 25+ TCP ports used by building automation systems and extracts
vendor/product info via banner grabs and protocol-specific handshakes.
"""

from __future__ import annotations

import http.client
import logging
import re
import socket
import ssl
import struct
import warnings
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any, Callable, Optional

from . import __version__
from .certs import parse_der_certificate
from .constants import HTTP_FINGERPRINTS, HVAC_TCP_PORTS, PORT_TO_SERVICE
from .netsweep import tcp_sweep

log = logging.getLogger(__name__)

# Ports we explicitly skip here - handled by their own scanners
_SKIP_PORTS = {47808, 502}

# Hosts identified concurrently after the sweep. Each host's own ports are
# probed one after another: an embedded web server often serves a single
# connection at a time.
_IDENTIFY_WORKERS = 16


def _tls_context() -> ssl.SSLContext:
    """A client context that will talk to old building-automation gear.

    Python's default context refuses TLS 1.0/1.1 and the ciphers that go with
    them, and a lot of installed BAS hardware — older JACEs, supervisory
    controllers on original firmware — offers nothing newer, so the probe
    failed the handshake and reported an HTTPS port with no banner and no
    certificate. This probe reads a public banner and certificate and sends
    nothing secret, so accepting a weak handshake costs nothing; it is never
    used for anything else.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    try:
        ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    except ssl.SSLError:
        pass
    return ctx


class HVACServiceScanner:
    """Scan for HVAC-related TCP services: Niagara Fox, OPC UA, CIP, HTTP, etc."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 1.5):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.services: list[dict[str, Any]] = []

    def _log(self, msg: str) -> None:
        log.debug(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    def scan_network(self, network_cidr: str, ports: Optional[list[int]] = None,
                     max_workers: int = 256, stop_event=None,
                     progress: Optional[Callable[[int, int], None]] = None
                     ) -> list[dict[str, Any]]:
        self.services = []
        ports = [p for p in (ports or HVAC_TCP_PORTS) if p not in _SKIP_PORTS]
        if not ports:
            return []

        # v2.1.2: accept CIDR, single IPs, shorthand ranges, full-IP ranges, lists.
        from .netrange import parse_targets, InvalidTargetSyntaxError
        try:
            hosts = parse_targets(network_cidr)
        except InvalidTargetSyntaxError as e:
            self._log(f"Invalid target: {e}")
            return []
        if not hosts:
            self._log(f"No hosts parsed from target {network_cidr!r}")
            return []

        self._log(f"Scanning {len(hosts)} hosts x {len(ports)} HVAC service ports...")

        def on_open(ip: str, port: int) -> None:
            svc_name = PORT_TO_SERVICE.get((port, "tcp"), f"TCP/{port}")
            self._log(f"  {ip}:{port} - {svc_name}")

        # Port-major: each host sees one connection attempt at a time.
        found = tcp_sweep(((ip, p) for p in ports for ip in hosts),
                          total=len(hosts) * len(ports),
                          # A LAN answers a SYN in milliseconds; the full probe
                          # timeout is for the banner exchange afterwards.
                          timeout=min(self.timeout, 1.0),
                          concurrency=max_workers, stop_event=stop_event,
                          on_open=on_open, progress=progress)
        self._log(f"  Found {len(found)} open HVAC service port(s)")
        if stop_event and stop_event.is_set():
            return []

        # Identify in host order, ports ascending, so results read naturally.
        rank = {ip: i for i, ip in enumerate(hosts)}
        by_host: "OrderedDict[str, list[int]]" = OrderedDict()
        for ip, port in sorted(found, key=lambda t: (rank.get(t[0], 0), t[1])):
            by_host.setdefault(ip, []).append(port)

        def identify_host(item: tuple[str, list[int]]) -> list[dict[str, Any]]:
            ip, host_ports = item
            out = []
            for port in host_ports:
                if stop_event and stop_event.is_set():
                    break
                svc_name = PORT_TO_SERVICE.get((port, "tcp"), f"TCP/{port}")
                try:
                    out.append(self._identify(ip, port, svc_name))
                except Exception:
                    log.exception("identifying %s:%d failed", ip, port)
            return out

        if by_host:
            with ThreadPoolExecutor(max_workers=min(_IDENTIFY_WORKERS, len(by_host)),
                                    thread_name_prefix="svc-id") as pool:
                for infos in pool.map(identify_host, by_host.items()):
                    self.services.extend(infos)

        self._log(f"Identified {len(self.services)} HVAC service(s)")
        return self.services

    def _identify(self, ip: str, port: int, svc_name: str) -> dict[str, Any]:
        info: dict[str, Any] = {
            'ip': ip, 'port': port, 'service': svc_name,
            'protocol': 'Service', 'vendor': '', 'product': '',
            'version': '', 'banner': '', 'title': '',
        }

        if port in (80, 8080, 8000, 8888, 9090):
            info.update(self._http_banner(ip, port, use_ssl=False))
        elif port in (443, 8443):
            info.update(self._http_banner(ip, port, use_ssl=True))
        elif port in (1911, 4911):
            info.update(self._probe_niagara_fox(ip, port))
        elif port == 4840:
            info['product'] = 'OPC UA Server'
        elif port == 102:
            info.update(self._probe_s7(ip, port))
        elif port == 44818:
            info.update(self._probe_ethernet_ip(ip, port))
        elif port in (22, 23, 21):
            info['banner'] = self._tcp_banner(ip, port)
        elif port in (1883, 8883):
            info['product'] = 'MQTT Broker'

        # Regex-match fingerprints over combined text
        all_text = ' '.join(str(info.get(k, '')) for k in
                            ('banner', 'title', 'server', 'product',
                             'tls_summary')).lower()
        for pattern, vendor in HTTP_FINGERPRINTS:
            if re.search(pattern, all_text):
                info['vendor'] = vendor
                break

        return info

    # -- protocol probes --------------------------------------------------

    def _http_banner(self, ip: str, port: int, use_ssl: bool = False) -> dict:
        info: dict[str, Any] = {'server': '', 'title': '', 'banner': ''}
        cert = None
        conn = None
        try:
            if use_ssl:
                conn = http.client.HTTPSConnection(ip, port, timeout=self.timeout,
                                                   context=_tls_context())
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=self.timeout)
            conn.request("GET", "/", headers={"User-Agent": f"HVAC-Scanner/{__version__}"})

            # Capture the certificate before reading the response. The probe
            # already establishes TLS and threw this away; BAS controllers put
            # the product line and often the panel name in the subject CN, and
            # the expiry date is operational information the owner wants.
            # Verification is off (self-signed is the norm on this gear), so
            # the DER has to be decoded directly rather than via getpeercert().
            if use_ssl and getattr(conn, 'sock', None) is not None:
                try:
                    der = conn.sock.getpeercert(binary_form=True)
                    cert = parse_der_certificate(der)
                except (AttributeError, ValueError, OSError) as e:
                    log.debug("cert read %s:%d: %s", ip, port, e)

            resp = conn.getresponse()
            info['server'] = resp.getheader('Server', '')
            info['banner'] = f"HTTP/{resp.status} {resp.reason} | Server: {info['server']}"
            body = resp.read(4096).decode('utf-8', errors='replace')

            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
            if title_match:
                info['title'] = title_match.group(1).strip()
            if not info['title']:
                login_match = re.search(
                    r'(login|sign.?in|webctrl|niagara|metasys|desigo)',
                    body, re.IGNORECASE
                )
                if login_match:
                    info['title'] = f"[Login Page: {login_match.group(1)}]"
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            log.debug("HTTP probe %s:%d: %s", ip, port, e)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        if cert is not None:
            info['tls'] = cert.to_dict()
            info['tls_summary'] = cert.summary()
            days = cert.days_until_expiry()
            if days is not None and days < 0:
                self._log(f"  [!] {ip}:{port} TLS certificate expired "
                          f"{-days} day(s) ago ({cert.subject_cn or 'no CN'})")
            elif days is not None and days < 30:
                self._log(f"  [!] {ip}:{port} TLS certificate expires in "
                          f"{days} day(s) ({cert.subject_cn or 'no CN'})")
        return info

    def _probe_niagara_fox(self, ip: str, port: int) -> dict:
        info: dict[str, Any] = {'product': 'Niagara Fox', 'vendor': 'Honeywell / Tridium'}
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.sendall(b'fox a 1 -1 fox hello\n')
                resp = sock.recv(2048).decode('ascii', errors='replace')
            if 'fox' in resp.lower():
                info['banner'] = resp.strip()[:200]
                for line in resp.split('\n'):
                    if 'version' in line.lower():
                        info['version'] = line.strip()
                    elif 'host' in line.lower():
                        info['product'] = f"Niagara ({line.strip()})"
        except OSError as e:
            log.debug("Fox probe %s:%d: %s", ip, port, e)
        return info

    def _probe_s7(self, ip: str, port: int) -> dict:
        info: dict[str, Any] = {'vendor': 'Siemens', 'product': 'S7 Controller'}
        cotp_cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
                         0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02,
                         0x01, 0x00, 0xC2, 0x02, 0x01, 0x02])
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.sendall(cotp_cr)
                resp = sock.recv(1024)
            if resp and len(resp) >= 4 and resp[0] == 0x03:
                info['banner'] = f"S7 ISO-TSAP response ({len(resp)} bytes)"
        except OSError as e:
            log.debug("S7 probe %s:%d: %s", ip, port, e)
        return info

    def _probe_ethernet_ip(self, ip: str, port: int) -> dict:
        info: dict[str, Any] = {'product': 'EtherNet/IP Device'}
        # EtherNet/IP encapsulation header (ODVA spec, 24 bytes):
        #   command uint16 | length uint16 | session uint32 | status uint32
        #   | sender_context 8 bytes | options uint32
        #
        # Was '<HHIHIQ', which is 22 bytes and misaligns every field after
        # `length`. All of them are zero so the bytes looked innocuous, but a
        # conforming device sees a truncated header and does not reply — so
        # this probe only ever reported the generic 'EtherNet/IP Device'
        # inferred from the open port, never an actual identity.
        list_id = struct.pack('<HHII8sI', 0x0063, 0x0000, 0x00000000,
                              0x00000000, bytes(8), 0x00000000)
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.sendall(list_id)
                resp = sock.recv(4096)
            if resp and len(resp) >= 26:
                cmd = struct.unpack('<H', resp[0:2])[0]
                if cmd == 0x0063:
                    info['banner'] = f"CIP List Identity ({len(resp)} bytes)"
                    ascii_parts = re.findall(rb'[\x20-\x7E]{4,}', resp)
                    if ascii_parts:
                        info['product'] = ascii_parts[0].decode('ascii', errors='replace')[:64]
        except OSError as e:
            log.debug("CIP probe %s:%d: %s", ip, port, e)
        return info

    def _tcp_banner(self, ip: str, port: int) -> str:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                return sock.recv(1024).decode('ascii', errors='replace').strip()[:200]
        except OSError as e:
            log.debug("TCP banner %s:%d: %s", ip, port, e)
            return ""
