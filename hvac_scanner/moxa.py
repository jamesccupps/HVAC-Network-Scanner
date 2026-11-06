"""
Moxa serial gateway detection.

Serial field buses (Siemens P1/FLN, Johnson Controls N2, BACnet MS/TP,
Modbus RTU, LonTalk) never appear on IP themselves. Where a site has put one
on the network, it is often through a Moxa NPort serial device server or an
MGate protocol gateway, and finding those shows where the hidden buses are.

Moxa devices answer an identify request on UDP 4800, part of Moxa's
management protocol (its "DeviceSearch"), used by the NPort, MGate and
OnCell lines. The request is 8 bytes, function 0x01; a reply is 24 bytes,
starts with 0x81 (the function code with the top bit set) and carries:

    bytes 12-13  model code, little-endian
    bytes 14-19  MAC address (Moxa's OUI is 00:90:E8)
    bytes 20-23  IPv4 address

Sources: Metasploit's moxa_discover module and its documentation (Cisco
Talos, tested on an NPort 6250), and runZero's oobscan decoder. The model
code is reported as a number: the protocol is shared by several product
lines, so the scanner does not turn it into a product name.

Only that identify request is ever sent. The same protocol has an "unlock"
function that older firmware answers with the admin password and SNMP
community (CVE-2016-9361, ICS-CERT ICSA-16-336-02); the scanner never sends
it, and only reports that the device should be checked.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

MOXA_PORT = 4800
IDENTIFY = bytes([0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
MOXA_OUI = bytes([0x00, 0x90, 0xE8])


def parse_identify_reply(data: bytes) -> Optional[dict[str, Any]]:
    """Model code, MAC and IP from an identify reply, or None."""
    if len(data) < 24 or data[0] != 0x81:
        return None
    mac = data[14:20]
    if mac in (bytes(6), b'\xff' * 6):
        return None
    model_code = struct.unpack('<H', data[12:14])[0]
    return {
        'model_code': model_code,
        'mac': ':'.join(f"{b:02X}" for b in mac),
        'moxa_oui': mac[:3] == MOXA_OUI,
        'reported_ip': socket.inet_ntoa(data[20:24]),
    }


class MoxaScanner:
    """Find Moxa devices (NPort, MGate, OnCell) among the targets."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 2.0, port: int = MOXA_PORT):
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
        self._log(f"Moxa identify request to {len(hosts)} host(s) on UDP {self.port}")

        found: dict[str, dict[str, Any]] = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('', 0))
            for i, ip in enumerate(hosts):
                if stop_event is not None and stop_event.is_set():
                    return []
                try:
                    sock.sendto(IDENTIFY, (ip, self.port))
                except OSError as e:
                    log.debug("Moxa identify to %s: %s", ip, e)
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
                    log.debug("Moxa recvfrom: %s", e)     # Windows: ICMP unreachable
                    continue
                if addr[0] not in wanted or addr[0] in found:
                    continue
                info = parse_identify_reply(data)
                if info:
                    found[addr[0]] = info

        out = []
        for ip in hosts:
            info = found.get(ip)
            if not info:
                continue
            dev = {'ip': ip, 'port': self.port, 'protocol': 'Moxa', 'vendor': 'Moxa', **info}
            self._log(f"  Moxa device at {ip}: model code {info['model_code']}, MAC {info['mac']}"
                      + ("" if info['moxa_oui'] else " (not a Moxa MAC prefix)"))
            out.append(dev)
        self._log(f"  Found {len(out)} Moxa device(s)")
        return out
