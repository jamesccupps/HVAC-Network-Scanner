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
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            return []
        hosts = [str(h) for h in network.hosts()]
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
    def _build_snmp_get(community: bytes) -> bytes:
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        null_val = bytes([0x05, 0x00])
        varbind = oid + null_val
        varbind_seq = bytes([0x30, len(varbind)]) + varbind
        varbind_list = bytes([0x30, len(varbind_seq)]) + varbind_seq
        request_id = bytes([0x02, 0x01, 0x01])
        error_status = bytes([0x02, 0x01, 0x00])
        error_index = bytes([0x02, 0x01, 0x00])
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
        version = bytes([0x02, 0x01, 0x00])
        comm = bytes([0x04, len(community)]) + community
        msg_content = version + comm + pdu
        return bytes([0x30, len(msg_content)]) + msg_content

    @staticmethod
    def _parse_snmp_response(data: bytes) -> Optional[str]:
        try:
            oid_marker = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            pos = data.find(oid_marker)
            if pos < 0:
                return None
            idx = pos - 2
            oid_len = data[idx + 1]
            idx = idx + 2 + oid_len
            if idx >= len(data):
                return None
            val_tag = data[idx]
            val_len = data[idx + 1]
            idx += 2
            if val_tag == 0x04:
                return data[idx:idx + val_len].decode('ascii', errors='replace')
            if val_tag == 0x02:
                return str(int.from_bytes(data[idx:idx + val_len], 'big'))
        except (IndexError, UnicodeDecodeError) as e:
            log.debug("snmp parse: %s", e)
        return None
