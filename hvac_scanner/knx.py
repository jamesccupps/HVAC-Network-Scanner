"""
KNXnet/IP gateway detection.

KNX runs lighting, blinds, and often room HVAC in European buildings, and
reaches the IP network through KNXnet/IP interfaces and routers on UDP 3671.
Each one answers a DESCRIPTION_REQUEST (KNXnet/IP Core, 0x0203) with a
DESCRIPTION_RESPONSE: its friendly name, KNX individual address, serial
number, MAC, and the service families it offers. The same request nmap's
knx-gateway-info sends; nothing is connected or written.

What matters for an audit is the service families: Tunnelling lets any host
that can reach the gateway open a connection and put telegrams on the KNX
bus (switch lights, move blinds, change setpoints), Routing does the same by
multicast, and only the Security family (KNX IP Secure) protects either.

One UDP socket sends to every host and collects the replies in one window,
as the SNMP pass does.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

KNX_PORT = 3671
_DESCRIPTION_REQUEST = 0x0203
_DESCRIPTION_RESPONSE = 0x0204

# DIB_DEVICE_INFO medium codes
_MEDIA = {0x02: "TP1", 0x04: "PL110", 0x10: "RF", 0x20: "KNX IP"}

# Service family IDs (DIB_SUPP_SVC_FAMILIES)
SERVICE_FAMILIES = {
    0x02: "Core", 0x03: "Device Management", 0x04: "Tunnelling",
    0x05: "Routing", 0x06: "Remote Logging", 0x07: "Remote Configuration",
    0x08: "Object Server", 0x09: "Security",
}


def build_description_request(local_ip: str, local_port: int) -> bytes:
    """DESCRIPTION_REQUEST carrying the control endpoint (HPAI) to answer."""
    hpai = struct.pack('!BB4sH', 8, 0x01, socket.inet_aton(local_ip), local_port)
    return struct.pack('!BBHH', 0x06, 0x10, _DESCRIPTION_REQUEST, 6 + len(hpai)) + hpai


def parse_description_response(data: bytes) -> Optional[dict[str, Any]]:
    """The device information in a DESCRIPTION_RESPONSE, or None."""
    if len(data) < 8 or data[0] != 0x06 or data[1] != 0x10:
        return None
    service, total = struct.unpack('!HH', data[2:6])
    if service != _DESCRIPTION_RESPONSE:
        return None
    out: dict[str, Any] = {}
    pos = 6
    end = min(total, len(data))
    while pos + 2 <= end:
        length, kind = data[pos], data[pos + 1]
        if length < 2:
            break
        body = data[pos + 2:pos + length]
        if kind == 0x01 and len(body) >= 52:            # DEVICE_INFO
            addr = struct.unpack('!H', body[2:4])[0]
            out.update({
                'medium': _MEDIA.get(body[0], f"0x{body[0]:02X}"),
                'programming_mode': bool(body[1] & 0x01),
                'knx_address': f"{addr >> 12}.{(addr >> 8) & 0x0F}.{addr & 0xFF}",
                'serial': body[6:12].hex(),
                'multicast': socket.inet_ntoa(body[12:16]),
                'mac': ':'.join(f"{b:02X}" for b in body[16:22]),
                'name': body[22:52].split(b'\x00', 1)[0].decode('latin-1').strip(),
            })
        elif kind == 0x02:                               # SUPP_SVC_FAMILIES
            out['services'] = [
                {'family': SERVICE_FAMILIES.get(body[i], f"0x{body[i]:02X}"),
                 'version': body[i + 1]}
                for i in range(0, len(body) - 1, 2)]
        pos += length
    return out or None


class KNXScanner:
    """Find KNXnet/IP interfaces and routers among the targets."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 2.0, port: int = KNX_PORT):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.port = port

    def _log(self, msg: str) -> None:
        log.debug(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    def scan_network(self, targets: str, stop_event=None,
                     progress: Optional[Callable[[int, int], None]] = None,
                     pace_s: float = 0.001) -> list[dict[str, Any]]:
        from .netrange import parse_targets, InvalidTargetSyntaxError
        try:
            hosts = parse_targets(targets)
        except InvalidTargetSyntaxError as e:
            self._log(f"Invalid target: {e}")
            return []
        if not hosts:
            return []
        self._log(f"KNXnet/IP description request to {len(hosts)} host(s) on UDP {self.port}")

        found: dict[str, dict[str, Any]] = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('', 0))
            local_port = sock.getsockname()[1]
            local_ip: dict[str, str] = {}        # per /24: the address the reply goes to
            for i, ip in enumerate(hosts):
                if stop_event is not None and stop_event.is_set():
                    return []
                net = ip.rsplit('.', 1)[0]
                if net not in local_ip:
                    local_ip[net] = _local_address_for(ip)
                try:
                    sock.sendto(build_description_request(local_ip[net], local_port),
                                (ip, self.port))
                except OSError as e:
                    log.debug("KNX request to %s: %s", ip, e)
                if progress and (i % 64 == 0 or i == len(hosts) - 1):
                    progress(i + 1, len(hosts))
                if pace_s:
                    time.sleep(pace_s)

            wanted = set(hosts)
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline and len(found) < len(wanted):
                if stop_event is not None and stop_event.is_set():
                    break
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError as e:
                    log.debug("KNX recvfrom: %s", e)   # Windows: ICMP unreachable
                    continue
                if addr[0] not in wanted or addr[0] in found:
                    continue
                info = parse_description_response(data)
                if info:
                    found[addr[0]] = info

        out = []
        for ip in hosts:
            info = found.get(ip)
            if not info:
                continue
            families = [s['family'] for s in info.get('services', [])]
            dev = {
                'ip': ip, 'port': self.port, 'protocol': 'KNXnet/IP',
                'vendor': '', 'product': info.get('name') or 'KNXnet/IP device',
                **info,
                'tunnelling': 'Tunnelling' in families,
                'routing': 'Routing' in families,
                'secure': 'Security' in families,
            }
            self._log(f"  KNXnet/IP at {ip}: {dev['product']} "
                      f"(KNX {info.get('knx_address', '?')}, {', '.join(families) or 'no services listed'})")
            out.append(dev)
        self._log(f"  Found {len(out)} KNXnet/IP device(s)")
        return out


def _local_address_for(ip: str) -> str:
    """This host's address on the route to `ip` (a UDP connect sends nothing)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((ip, KNX_PORT))
            return s.getsockname()[0]
    except OSError:
        return '0.0.0.0'
