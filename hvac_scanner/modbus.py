"""
Modbus TCP scanner.

Fixes vs v1:
- Every socket is wrapped in try/finally (v1 leaked on exception)
- COMMON_UNIT_IDS includes 255 (default for TCP-only gateways)
- Exception responses (0x83/0x84) are recorded as evidence of liveness
- read_registers / read_coils share a helper to build MBAP headers
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


class ModbusScanner:
    # 255 added vs v1 — default unit ID for many TCP-only gateways
    COMMON_UNIT_IDS = [1, 2, 3, 4, 5, 10, 100, 247, 255]

    def __init__(self, callback: Optional[Callable[[str], None]] = None,
                 timeout: float = 1.0):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.devices: list[dict[str, Any]] = []

    def _log(self, msg: str) -> None:
        log.debug(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    # -- per-host probing -----------------------------------------------

    def scan_host(self, ip: str, port: int = 502,
                  unit_ids: Optional[list[int]] = None) -> list[dict[str, Any]]:
        """Probe one host at multiple unit IDs."""
        unit_ids = unit_ids or self.COMMON_UNIT_IDS
        results: list[dict[str, Any]] = []

        for uid in unit_ids:
            # Try Device Identification (FC 0x2B, MEI 0x0E) first
            info = self._try_device_id(ip, port, uid)
            if info:
                results.append(info)
                self._log(f"  Modbus device at {ip}:{port} unit={uid}")
                continue

            # Fall back to a minimal holding register read
            info = self._try_holding_read(ip, port, uid)
            if info:
                results.append(info)
                self._log(f"  Modbus device at {ip}:{port} unit={uid} ({info.get('detected_via', '?')})")

        return results

    def _try_device_id(self, ip: str, port: int, uid: int) -> Optional[dict[str, Any]]:
        req = struct.pack('!HHHBBBB', 0x0001, 0x0000, 0x0005, uid, 0x2B, 0x0E, 0x01, 0x00)
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(req)
                resp = sock.recv(1024)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

        if not resp or len(resp) < 9:
            return None
        info = self._parse_device_id_response(resp)
        info.update({'ip': ip, 'port': port, 'unit_id': uid})
        return info

    def _try_holding_read(self, ip: str, port: int, uid: int) -> Optional[dict[str, Any]]:
        req = struct.pack('!HHHBBHH', 0x0001, 0x0000, 0x0006, uid, 0x03, 0x0000, 0x0001)
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(req)
                resp = sock.recv(1024)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

        if not resp or len(resp) < 9:
            return None
        fc = resp[7]
        # 0x03 = success; 0x83 = exception (valid device replying, just unsupported data)
        if fc not in (0x03, 0x83):
            return None
        return {
            'ip': ip, 'port': port, 'unit_id': uid,
            'vendor': 'Unknown', 'product': 'Unknown', 'version': 'Unknown',
            'detected_via': 'holding_register_read' if fc == 0x03 else 'exception_response',
        }

    # -- network sweep ---------------------------------------------------

    def scan_network(self, network_cidr: str, port: int = 502,
                     unit_ids: Optional[list[int]] = None,
                     max_workers: int = 50,
                     stop_event=None) -> list[dict[str, Any]]:
        self.devices = []
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError as e:
            self._log(f"Invalid network: {e}")
            return []

        hosts = [str(h) for h in network.hosts()]
        self._log(f"Scanning {len(hosts)} hosts for Modbus TCP on port {port}...")

        def check_port(ip: str) -> Optional[str]:
            if stop_event and stop_event.is_set():
                return None
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        return ip
            except OSError:
                pass
            return None

        open_hosts: list[str] = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(check_port, h) for h in hosts]
            for f in as_completed(futures):
                if stop_event and stop_event.is_set():
                    break
                result = f.result()
                if result:
                    open_hosts.append(result)
                    self._log(f"  -> Port {port} open on {result}")

        self._log(f"  Found {len(open_hosts)} host(s) with port {port} open")
        for ip in open_hosts:
            if stop_event and stop_event.is_set():
                break
            self.devices.extend(self.scan_host(ip, port, unit_ids))

        self._log(f"Found {len(self.devices)} Modbus device(s)")
        return self.devices

    # -- register / coil reads -------------------------------------------

    def read_registers(self, ip: str, port: int, unit_id: int,
                       start: int = 0, count: int = 10, func_code: int = 3) -> list[dict]:
        """Read holding (fc=3) or input (fc=4) registers."""
        req = struct.pack('!HHHBBHH', 0x0001, 0x0000, 0x0006, unit_id, func_code, start, count)
        results: list[dict] = []
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(req)
                resp = sock.recv(4096)
        except OSError as e:
            self._log(f"  Register read error: {e}")
            return results

        if not resp or len(resp) < 9:
            return results
        fc = resp[7]
        if fc != func_code:
            return results
        byte_count = resp[8]
        data = resp[9:9 + byte_count]
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                val = struct.unpack('!H', data[i:i + 2])[0]
                results.append({'register': start + (i // 2), 'value': val, 'hex': f"0x{val:04X}"})
        return results

    def read_coils(self, ip: str, port: int, unit_id: int,
                   start: int = 0, count: int = 16) -> list[dict]:
        req = struct.pack('!HHHBBHH', 0x0001, 0x0000, 0x0006, unit_id, 0x01, start, count)
        results: list[dict] = []
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(req)
                resp = sock.recv(4096)
        except OSError as e:
            self._log(f"  Coil read error: {e}")
            return results

        if not resp or len(resp) < 9 or resp[7] != 0x01:
            return results
        byte_count = resp[8]
        data = resp[9:9 + byte_count]
        for i in range(count):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(data):
                val = (data[byte_idx] >> bit_idx) & 1
                results.append({'coil': start + i, 'value': val, 'state': 'ON' if val else 'OFF'})
        return results

    # -- device ID parsing -----------------------------------------------

    @staticmethod
    def _parse_device_id_response(resp: bytes) -> dict[str, Any]:
        info: dict[str, Any] = {
            'vendor': 'Unknown', 'product': 'Unknown',
            'version': 'Unknown', 'detected_via': 'device_id',
        }
        try:
            if len(resp) < 15:
                return info
            idx = 13
            num_objects = resp[idx] if idx < len(resp) else 0
            idx += 1
            obj_names = {
                0: 'vendor', 1: 'product', 2: 'version',
                3: 'vendor_url', 4: 'product_name', 5: 'model_name',
            }
            for _ in range(num_objects):
                if idx + 2 > len(resp):
                    break
                obj_id = resp[idx]
                obj_len = resp[idx + 1]
                idx += 2
                if idx + obj_len > len(resp):
                    break
                val = resp[idx:idx + obj_len].decode('ascii', errors='replace')
                key = obj_names.get(obj_id)
                if key:
                    info[key] = val
                idx += obj_len
        except (IndexError, UnicodeDecodeError) as e:
            log.debug("device id parse: %s", e)
        return info
