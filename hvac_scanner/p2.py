"""
Siemens APOGEE P2 panel detection — read-only, and leaves no trace on the panel.

APOGEE panels on firmware 2.x speak Siemens' P2 protocol over TCP/5033 rather
than BACnet/IP. They have IP addresses and may be fully managed by Desigo CC
or Insight, yet a BACnet scan sees nothing, so an APOGEE building looked empty.

How a panel is recognised
-------------------------
P2 has no authentication. Its only admission check is the BLN (network) name
carried in every frame, and a field panel answers a frame with the wrong BLN
name by resetting the TCP connection, before any other processing and without
writing anything to its node table; a supervisor's listener closes gracefully
instead. So the probe is:

1. connect to TCP/5033;
2. send one well-formed identify frame (opcode 0x4640, EBLN_PING) whose BLN
   name is a fixed value no site uses;
3. read how the connection ends: RST — a field panel; FIN with no data — a
   P2 supervisor listener (Desigo CC, Insight); anything else is not P2.

It is deliberately *not* a handshake with the right BLN name. That would be
admitted and would write a permanent node-table entry for the scanner on the
panel, which an inventory tool has no business doing. It is also not BLN-name
guessing: the name is one constant, the same on every connection, and each
panel sees one attempt.

The protocol facts used here — the frame layout, the identify-block body, and
the wrong-BLN reset with no table side effect — are from the P2 technical
reference in the companion project
https://github.com/jamesccupps/P2_Wireshark_Dissector_And_P2_Scanner
(PROTOCOL.md sections 6.1, 6.2, 7.3.1 and 17.2), which is wire-verified.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

from .netsweep import tcp_sweep

log = logging.getLogger(__name__)

P2_PORT = 5033
OP_EBLN_PING = 0x4640

# Letters and digits only (what a BLN name may contain), and not a name any
# site would choose. It is sent once per panel, identically every time.
PROBE_BLN = "HVACSCANNERPROBE"
PROBE_NODE = "PROBE"
PROBE_IDENTITY = "HVACSCANNER"
PROBE_SITE = "SCAN"

ROLE_PANEL = "field panel"
ROLE_SUPERVISOR = "supervisor listener"


def _tlv(text: str) -> bytes:
    raw = text.encode('ascii')
    return b'\x01' + struct.pack('>H', len(raw)) + raw


def build_probe(seq: int = 1, now: Optional[float] = None) -> bytes:
    """The identify frame the probe sends, with the deliberately wrong BLN.

    Layout (big-endian): u32 total length (self-inclusive), u32 msg_type,
    u32 sequence, u8 direction (0 = request), four NUL-terminated routing
    slots [BLN, destination node, BLN, own identity], u16 opcode, body.
    msg_type is 13 plus the bytes of the four slots — a header length; a
    frame whose msg_type does not match its slots is silently dropped.
    The body is the eBLN_Node block: three name TLVs (node, site, BLN) and
    a 16-byte tail of flags, spare, timestamp, timezone and DST.
    """
    slots = b''.join(s.encode('ascii') + b'\x00'
                     for s in (PROBE_BLN, PROBE_NODE, PROBE_BLN, PROBE_IDENTITY))
    tail = (b'\x00\x01\x01\x00\x00'                       # five boolean flags
            + struct.pack('>I', 0)                        # spare
            + struct.pack('>I', int(now if now is not None else time.time()))
            + struct.pack('>H', 0) + b'\x00')             # timezone, DST
    body = _tlv(PROBE_IDENTITY) + _tlv(PROBE_SITE) + _tlv(PROBE_BLN) + tail
    payload = b'\x00' + slots + struct.pack('>H', OP_EBLN_PING) + body
    msg_type = 13 + len(slots)
    return struct.pack('>III', 12 + len(payload), msg_type, seq) + payload


def probe(ip: str, port: int = P2_PORT, timeout: float = 2.0) -> Optional[dict[str, Any]]:
    """Probe one address. Returns a device dict for a P2 node, else None."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    started = time.monotonic()
    outcome = "silent"
    try:
        sock.settimeout(timeout)
        try:
            sock.sendall(build_probe())
            data = sock.recv(256)
            outcome = "fin" if not data else "data"
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            outcome = "rst"
        except socket.timeout:
            outcome = "silent"
        except OSError as e:
            log.debug("p2 probe %s:%d: %s", ip, port, e)
            outcome = "rst" if getattr(e, 'winerror', None) in (10053, 10054) else "error"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    ms = int((time.monotonic() - started) * 1000)

    if outcome == "rst":
        role, evidence = ROLE_PANEL, (
            f"reset the connection {ms} ms after a P2 identify frame with a "
            f"foreign BLN name — the APOGEE field-panel access gate")
    elif outcome == "fin":
        role, evidence = ROLE_SUPERVISOR, (
            f"closed the connection without replying {ms} ms after a P2 "
            f"identify frame with a foreign BLN name — how a P2 supervisor "
            f"listener refuses one")
    else:
        log.debug("%s:%d open but not P2 (%s)", ip, port, outcome)
        return None

    return {
        'ip': ip, 'port': port, 'protocol': 'APOGEE P2',
        'vendor': 'Siemens',
        'product': ('APOGEE field panel (P2)' if role == ROLE_PANEL
                    else 'P2 supervisor (Desigo CC / Insight)'),
        'p2_role': role,
        'p2_evidence': evidence,
    }


class P2Scanner:
    """Find APOGEE P2 nodes: a TCP/5033 sweep, then one probe per open port."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 2.0):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout

    def _log(self, msg: str) -> None:
        log.debug(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    def scan_network(self, network_cidr: str, port: int = P2_PORT,
                     max_workers: int = 256, stop_event=None,
                     progress: Optional[Callable[[int, int], None]] = None
                     ) -> list[dict[str, Any]]:
        from .netrange import parse_targets, InvalidTargetSyntaxError
        try:
            hosts = parse_targets(network_cidr)
        except InvalidTargetSyntaxError as e:
            self._log(f"Invalid target: {e}")
            return []
        if not hosts:
            return []
        self._log(f"Scanning {len(hosts)} hosts for APOGEE P2 on TCP {port}...")
        open_hosts = [ip for ip, _p in tcp_sweep(
            ((h, port) for h in hosts), total=len(hosts),
            timeout=min(self.timeout, 1.0), concurrency=max_workers,
            stop_event=stop_event, progress=progress)]
        self._log(f"  Found {len(open_hosts)} host(s) with TCP {port} open")
        if not open_hosts or (stop_event and stop_event.is_set()):
            return []

        rank = {ip: i for i, ip in enumerate(hosts)}
        found: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(16, len(open_hosts)),
                                thread_name_prefix="p2") as pool:
            for ip, dev in zip(open_hosts, pool.map(
                    lambda ip: probe(ip, port, self.timeout), open_hosts)):
                if dev:
                    found.append(dev)
                    self._log(f"  APOGEE P2 {dev['p2_role']} at {ip}")
                else:
                    self._log(f"  {ip}:{port} is open but did not behave like P2")
        found.sort(key=lambda d: rank.get(d['ip'], 0))
        self._log(f"Found {len(found)} APOGEE P2 node(s)")
        return found
