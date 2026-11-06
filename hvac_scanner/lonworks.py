"""
LonWorks/IP (IP-852) device detection.

LonWorks field devices sit on LonTalk twisted pair and are not on IP at all.
They reach the network through IP-852 routers (i.LON and SmartServer,
LOYTEC L-IP and others) and through controllers with an IP-852 channel of
their own, which listen on UDP 1628. IP-852 is also published as CEA-852
(formerly EIA-852) and ISO/IEC 14908-4, and Wireshark calls it CN/IP.

Each IP-852 device answers a Device Configuration Request (packet type 0x63)
with a Device Configuration packet (0x71): the name it was given, what kind
of IP-852 node it is, its Neuron IDs, its unicast address, and the
configuration and time servers it uses. The reference stack answers that
request "from any node", even on a channel whose authentication rejected the
packet. Nothing is configured, joined or sent onto the LonTalk side.

Packet layouts follow the IzoT LonTalk stack (github.com/izot/lon-stack-ex,
LonTalkStack/Source/ShareIp: LtIpPackets.h, LtIpPackets.cpp, LtIpMaster.cpp).

One UDP socket sends to every host and collects the replies in one window,
as the KNX and SNMP passes do.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import time
from typing import Any, Callable, Optional

from .text import clean_text

log = logging.getLogger(__name__)

IP852_PORT = 1628                 # normal priority; 1629 carries urgent traffic

_VERSION = 1                      # VERSION_ONE, the standard version
_REQ_DEVCONFIG = 0x63             # PKTTYPE_REQDEVCONFIG
_DEVCONFIGURE = 0x71              # PKTTYPE_DEVCONFIGURE
_SECURITY_FLAG = 0x20             # PROTFLAG_SECURITY: an MD5 digest follows
_HEADER = struct.Struct('!HBBBBHIII')          # 20-byte CN/IP header
_REQUEST = struct.Struct('!IBHBII')            # LtIpRequest fields, 16 bytes
_DEVCONFIG = struct.Struct('!IBBBBBBHHHIIIIIIHHHH')   # LtIpDevRegister fixed part, 48 bytes
_ADDPORT = 8                      # LtIpAddPort: IP, port, 2 bytes MBZ
_NEURON_ID = 6
_NTP_EPOCH = 2208988800           # seconds from 1900 to 1970

# ipNodeType (LTNODE_*)
NODE_TYPES = {1: "LonTalk/IP router", 2: "IP-852 node", 3: "IP-852 proxy",
              4: "IP-852 to IP-852 router"}
# routerType (LTROUTER_*), meaningful for routers
ROUTER_MODES = {0: "configured", 1: "learning", 2: "bridge", 3: "repeater"}
_SUPPORTS_AUTH = 0x02             # lonTalkFlags: SUPPORTS_EIA_AUTH


def build_devconfig_request(session: Optional[int] = None) -> bytes:
    """A Device Configuration Request: the 20-byte header and the 16 bytes
    of LtIpRequest, no digest."""
    now = time.time()
    session = session if session is not None else int.from_bytes(os.urandom(4), 'big')
    header = _HEADER.pack(_HEADER.size + _REQUEST.size, _VERSION, _REQ_DEVCONFIG, 0, 0, 0,
                          session, 0, int(now * 1000) & 0xFFFFFFFF)
    body = _REQUEST.pack((int(now) + _NTP_EPOCH) & 0xFFFFFFFF, 0, 1, 0, 0, 0)
    return header + body


def _ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack('!I', value))


def _addr(ip: int, port: int) -> str:
    return f"{_ip(ip)}:{port}" if ip else ""


def parse_devconfig(data: bytes) -> Optional[dict[str, Any]]:
    """The device information in a Device Configuration packet, or None."""
    if len(data) < _HEADER.size:
        return None
    size, version, ptype, ext_words, flags, vendor, _session, _seq, _ts = \
        _HEADER.unpack_from(data)
    if ptype != _DEVCONFIGURE or (version & 0x1F) > 1:
        return None
    end = min(size, len(data))
    pos = _HEADER.size + 4 * ext_words
    if end < pos + _DEVCONFIG.size:
        return None
    (_dt, ip_flags, router_type, lon_flags, node_type, mc_count, _mbz, channel_timeout,
     nid_bytes, uc_port, uc_addr, _chan_dt, _send_dt, cs_addr, ts_addr, ts2_addr,
     cs_port, ts_port, ts2_port, _mbz2) = _DEVCONFIG.unpack_from(data, pos)
    pos += _DEVCONFIG.size
    out: dict[str, Any] = {
        'node_type': NODE_TYPES.get(node_type, f"node type {node_type}"),
        'unicast': _addr(uc_addr, uc_port),
        'config_server': _addr(cs_addr, cs_port),
        'time_servers': [a for a in (_addr(ts_addr, ts_port), _addr(ts2_addr, ts2_port)) if a],
        'channel_timeout_ms': channel_timeout,
        'auth_supported': bool(lon_flags & _SUPPORTS_AUTH),
        'authenticated': bool(flags & _SECURITY_FLAG),
        'vendor_code': vendor,
    }
    if node_type in (1, 4):
        out['router_mode'] = ROUTER_MODES.get(router_type, f"mode {router_type}")
    pos += _ADDPORT * min(mc_count, 64)
    nid_bytes = min(nid_bytes, 64 * _NEURON_ID)
    if pos + nid_bytes > end:
        return out
    out['neuron_ids'] = [data[i:i + _NEURON_ID].hex().upper()
                         for i in range(pos, pos + nid_bytes - _NEURON_ID + 1, _NEURON_ID)]
    pos += nid_bytes
    if pos < end:
        name_len = data[pos]
        raw = data[pos + 1:min(end, pos + 1 + name_len)]
        out['name'] = clean_text(raw.split(b'\x00', 1)[0].decode('latin-1')).strip()
    return out


class LonWorksScanner:
    """Find IP-852 (LonWorks/IP) routers and nodes among the targets."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 2.0, port: int = IP852_PORT):
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
        self._log(f"IP-852 device configuration request to {len(hosts)} host(s) on UDP {self.port}")

        found: dict[str, dict[str, Any]] = {}
        request = build_devconfig_request()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('', 0))
            for i, ip in enumerate(hosts):
                if stop_event is not None and stop_event.is_set():
                    return []
                try:
                    sock.sendto(request, (ip, self.port))
                except OSError as e:
                    log.debug("IP-852 request to %s: %s", ip, e)
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
                    log.debug("IP-852 recvfrom: %s", e)   # Windows: ICMP unreachable
                    continue
                if addr[0] not in wanted or addr[0] in found:
                    continue
                info = parse_devconfig(data)
                if info:
                    found[addr[0]] = info

        out = []
        for ip in hosts:
            info = found.get(ip)
            if not info:
                continue
            dev = {'ip': ip, 'port': self.port, 'protocol': 'LonWorks/IP',
                   'name': '', 'neuron_ids': [], **info}
            auth = ("authenticated" if dev['authenticated'] else
                    "no authentication" + (" (supported)" if dev['auth_supported'] else ""))
            self._log(f"  LonWorks/IP at {ip}: {dev['node_type']}"
                      + (f" '{dev['name']}'" if dev['name'] else "")
                      + (f", Neuron ID {', '.join(dev['neuron_ids'][:2])}" if dev['neuron_ids'] else "")
                      + (f", config server {dev['config_server']}" if dev['config_server'] else "")
                      + f", {auth}")
            out.append(dev)
        self._log(f"  Found {len(out)} LonWorks/IP device(s)")
        return out
