"""
HVAC service port scanner.

Probes 25+ TCP ports used by building automation systems and extracts
vendor/product info via banner grabs and protocol-specific handshakes.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import re
import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from typing import Any, Callable, Optional

from .constants import HTTP_FINGERPRINTS, HVAC_TCP_PORTS, PORT_TO_SERVICE

log = logging.getLogger(__name__)

# Ports we explicitly skip here - handled by their own scanners
_SKIP_PORTS = {47808, 502}


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
                     max_workers: int = 80, stop_event=None) -> list[dict[str, Any]]:
        self.services = []
        ports = [p for p in (ports or HVAC_TCP_PORTS) if p not in _SKIP_PORTS]
        if not ports:
            return []

        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError as e:
            self._log(f"Invalid network: {e}")
            return []

        hosts = [str(h) for h in network.hosts()]
        self._log(f"Scanning {len(hosts)} hosts x {len(ports)} HVAC service ports...")
        targets = [(ip, p) for ip in hosts for p in ports]

        def probe(target):
            if stop_event and stop_event.is_set():
                return None
            ip, port = target
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return (ip, port)
            except OSError:
                pass
            return None

        open_services: list[tuple[str, int, str]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(probe, t) for t in targets]
            for f in as_completed(futures):
                if stop_event and stop_event.is_set():
                    break
                result = f.result()
                if result:
                    ip, port = result
                    svc_name = PORT_TO_SERVICE.get((port, "tcp"), f"TCP/{port}")
                    open_services.append((ip, port, svc_name))
                    self._log(f"  {ip}:{port} - {svc_name}")

        self._log(f"  Found {len(open_services)} open HVAC service port(s)")

        for ip, port, svc_name in open_services:
            if stop_event and stop_event.is_set():
                break
            info = self._identify(ip, port, svc_name)
            self.services.append(info)

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
                            ('banner', 'title', 'server', 'product')).lower()
        for pattern, vendor in HTTP_FINGERPRINTS:
            if re.search(pattern, all_text):
                info['vendor'] = vendor
                break

        return info

    # -- protocol probes --------------------------------------------------

    def _http_banner(self, ip: str, port: int, use_ssl: bool = False) -> dict:
        info: dict[str, Any] = {'server': '', 'title': '', 'banner': ''}
        conn = None
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=self.timeout)
            conn.request("GET", "/", headers={"User-Agent": "HVAC-Scanner/2.0"})
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
        return info

    def _probe_niagara_fox(self, ip: str, port: int) -> dict:
        info: dict[str, Any] = {'product': 'Niagara Fox', 'vendor': 'Honeywell / Tridium'}
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(b'fox a 1 -1 fox hello\n')
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
                sock.send(cotp_cr)
                resp = sock.recv(1024)
            if resp and len(resp) >= 4 and resp[0] == 0x03:
                info['banner'] = f"S7 ISO-TSAP response ({len(resp)} bytes)"
        except OSError as e:
            log.debug("S7 probe %s:%d: %s", ip, port, e)
        return info

    def _probe_ethernet_ip(self, ip: str, port: int) -> dict:
        info: dict[str, Any] = {'product': 'EtherNet/IP Device'}
        list_id = struct.pack('<HHIHIQ', 0x0063, 0x0000, 0x00000000, 0x00000000, 0x00000000, 0)
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(list_id)
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
