"""
Minimal SNMPv1 sysDescr scanner — raw UDP, no pysnmp dependency.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


class SNMPScanner:
    """Raw UDP SNMP v1/v2c scanner for sysDescr (OID 1.3.6.1.2.1.1.1.0)."""

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
                     max_workers: int = 50, stop_event=None) -> list[dict[str, Any]]:
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
        self._log(f"Scanning {len(hosts)} hosts for SNMP...")

        def probe(ip: str) -> Optional[dict[str, Any]]:
            if stop_event and stop_event.is_set():
                return None
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
                    sock.settimeout(self.timeout)
                    pkt = self._build_snmp_get(community)
                    sock.sendto(pkt, (ip, 161))
                    resp, _ = sock.recvfrom(4096)
                descr = self._parse_snmp_response(resp)
                if descr is not None:
                    return {'ip': ip, 'port': 161, 'sys_descr': descr}
            except OSError:
                pass
            except Exception as e:
                log.debug("snmp probe %s: %s", ip, e)
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(probe, h) for h in hosts]
            for f in as_completed(futures):
                if stop_event and stop_event.is_set():
                    break
                result = f.result()
                if result:
                    self.devices.append(result)
                    self._log(f"  SNMP at {result['ip']}: {result['sys_descr'][:80]}")

        self._log(f"Found {len(self.devices)} SNMP device(s)")
        return self.devices

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
