"""
Minimal SNMPv1 sysDescr scanner — raw UDP, no pysnmp dependency.

v2.7: one socket sends a GET to every host and gathers whatever answers within
one timeout, instead of a thread per host each waiting out its own timeout.
A /24 now costs about one timeout, and several community strings can be tried
in turn against the hosts that stayed silent.
"""

from __future__ import annotations

import logging
import socket
import time
from contextlib import closing
from typing import Any, Callable, Iterable, Optional

log = logging.getLogger(__name__)

# Spacing between GETs. A sweep of a /24 goes out in about a quarter second;
# nothing on the far side sees a burst.
_SEND_SPACING_S = 0.001


class SNMPScanner:
    """Raw UDP SNMP v1/v2c scanner for sysDescr (OID 1.3.6.1.2.1.1.1.0)."""

    PORT = 161

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 1.5):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.devices: list[dict[str, Any]] = []

    def _log(self, msg: str) -> None:
        log.debug(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    def scan_network(self, network_cidr: str, community: bytes = b'public',
                     max_workers: int = 50, stop_event=None,
                     communities: Optional[Iterable["str | bytes"]] = None,
                     progress: Optional[Callable[[int, int], None]] = None
                     ) -> list[dict[str, Any]]:
        """GET sysDescr.0 from every host. `max_workers` is accepted for
        compatibility and unused: there are no workers any more."""
        self.devices = []
        # v2.1.2: accept CIDR, single IPs, shorthand ranges, full-IP ranges, lists.
        from .netrange import parse_targets, InvalidTargetSyntaxError
        try:
            hosts = parse_targets(network_cidr)
        except InvalidTargetSyntaxError as e:
            self._log(f"Invalid target: {e}")
            return []
        if not hosts:
            return []
        comms = [c.encode() if isinstance(c, str) else bytes(c)
                 for c in (communities or [community])]
        self._log(f"Scanning {len(hosts)} hosts for SNMP...")

        found: dict[str, dict[str, Any]] = {}
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
                sock.bind(('', 0))
                for i, comm in enumerate(comms):
                    if stop_event and stop_event.is_set():
                        break
                    pending = [h for h in hosts if h not in found]
                    if not pending:
                        break
                    self._sweep(sock, pending, comm, found, stop_event, progress,
                                round_no=i, rounds=len(comms))
        except OSError as e:
            self._log(f"  SNMP socket error: {e}")

        rank = {ip: i for i, ip in enumerate(hosts)}
        self.devices = sorted(found.values(), key=lambda d: rank.get(d['ip'], 0))
        self._log(f"Found {len(self.devices)} SNMP device(s)")
        return self.devices

    def _sweep(self, sock: socket.socket, hosts: list[str], community: bytes,
               found: dict[str, dict[str, Any]], stop_event, progress,
               round_no: int = 0, rounds: int = 1) -> None:
        pkt = self._build_snmp_get(community)
        wanted = set(hosts)
        total = len(hosts) * rounds
        base = len(hosts) * round_no
        for n, ip in enumerate(hosts, 1):
            if stop_event and stop_event.is_set():
                return
            try:
                sock.sendto(pkt, (ip, self.PORT))
            except OSError as e:
                log.debug("snmp send %s: %s", ip, e)
            if _SEND_SPACING_S:
                time.sleep(_SEND_SPACING_S)
            if progress and n % 32 == 0:
                progress(base + n // 2, total)
            self._drain(sock, wanted, found, community, wait=0.0)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline and wanted - found.keys():
            if stop_event and stop_event.is_set():
                return
            self._drain(sock, wanted, found, community,
                        wait=min(0.2, max(0.0, deadline - time.monotonic())))
        if progress:
            progress(base + len(hosts), total)

    def _drain(self, sock: socket.socket, wanted: set[str],
               found: dict[str, dict[str, Any]], community: bytes, wait: float) -> None:
        """Read every reply already queued, waiting up to `wait` for the first."""
        sock.settimeout(wait if wait > 0 else 0.0)
        while True:
            try:
                resp, addr = sock.recvfrom(4096)
            except (socket.timeout, BlockingIOError):
                return
            except OSError as e:
                # Windows surfaces an ICMP port-unreachable from an earlier
                # send as an error here. One closed port says nothing about
                # the rest of the sweep.
                log.debug("snmp recv: %s", e)
                continue
            finally:
                sock.settimeout(0.0)
            ip = addr[0]
            if ip not in wanted or ip in found:
                continue
            descr = self._parse_snmp_response(resp)
            if descr is None:
                continue
            found[ip] = {'ip': ip, 'port': 161, 'sys_descr': descr,
                         'community': community.decode('latin-1')}
            self._log(f"  SNMP at {ip}: {descr[:80]}")

    # -- wire format ------------------------------------------------------

    @staticmethod
    def _ber_len(n: int) -> bytes:
        """Encode a BER length. Short form below 128, long form above.

        The original code emitted a bare length byte everywhere, which is only
        valid for n < 128. A community string long enough to push any enclosing
        SEQUENCE past 127 bytes produced a malformed packet that agents dropped.
        """
        if n < 0x80:
            return bytes([n])
        raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(raw)]) + raw

    @classmethod
    def _build_snmp_get(cls, community: bytes) -> bytes:
        L = cls._ber_len
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        null_val = bytes([0x05, 0x00])
        varbind = oid + null_val
        varbind_seq = bytes([0x30]) + L(len(varbind)) + varbind
        varbind_list = bytes([0x30]) + L(len(varbind_seq)) + varbind_seq
        request_id = bytes([0x02, 0x01, 0x01])
        error_status = bytes([0x02, 0x01, 0x00])
        error_index = bytes([0x02, 0x01, 0x00])
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = bytes([0xA0]) + L(len(pdu_content)) + pdu_content
        version = bytes([0x02, 0x01, 0x00])
        comm = bytes([0x04]) + L(len(community)) + community
        msg_content = version + comm + pdu
        return bytes([0x30]) + L(len(msg_content)) + msg_content

    @staticmethod
    def _read_ber_len(data: bytes, idx: int) -> tuple[int, int]:
        """Read a BER length starting at idx. Returns (length, next_idx).

        Handles both the short form (one byte, < 128) and the long form
        (0x8N followed by N length bytes). sysDescr routinely exceeds 127
        bytes on enterprise gear — Cisco IOS descriptors run well past 200 —
        so the long form is the common case, not an edge case. Reading it as
        a short length yielded a garbage leading character and a truncated
        string, which then broke the vendor regexes in engine._scan_snmp.
        """
        if idx >= len(data):
            raise IndexError("BER length past end of buffer")
        first = data[idx]
        if first < 0x80:
            return first, idx + 1
        n = first & 0x7F
        if n == 0 or idx + 1 + n > len(data):
            raise IndexError("malformed BER long-form length")
        return int.from_bytes(data[idx + 1:idx + 1 + n], 'big'), idx + 1 + n

    @classmethod
    def _parse_snmp_response(cls, data: bytes) -> Optional[str]:
        try:
            oid_marker = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            pos = data.find(oid_marker)
            if pos < 1:
                return None
            # Step back over the OID's tag+length to find the varbind, then
            # walk forward past the OID to the value that follows it.
            oid_len, idx = cls._read_ber_len(data, pos - 1)
            idx = idx + oid_len
            if idx >= len(data):
                return None
            val_tag = data[idx]
            val_len, idx = cls._read_ber_len(data, idx + 1)
            if idx + val_len > len(data):
                return None
            if val_tag == 0x04:
                return data[idx:idx + val_len].decode('utf-8', errors='replace')
            if val_tag == 0x02:
                return str(int.from_bytes(data[idx:idx + val_len], 'big'))
        except (IndexError, UnicodeDecodeError) as e:
            log.debug("snmp parse: %s", e)
        return None
