"""
Modbus TCP scanner.

Fixes vs v1:
- Every socket is wrapped in try/finally (v1 leaked on exception)
- COMMON_UNIT_IDS includes 255 (default for TCP-only gateways)
- Exception responses (0x83/0x84) are recorded as evidence of liveness
- read_registers / read_coils share a helper to build MBAP headers

v2.7:
- One TCP connection per host carries every unit-ID probe, instead of a fresh
  connection per request (up to 18 per host)
- Gateway exceptions 0x0A/0x0B ("path unavailable", "target failed to
  respond") mean there is no device at that unit ID, and are no longer
  reported as one
- A device that answers every unit ID identically — most direct-attached
  meters and drives ignore the field — is reported once, not nine times
- Hosts are probed in parallel
"""

from __future__ import annotations

import logging
import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

from .netsweep import tcp_sweep

log = logging.getLogger(__name__)

# Exception codes a TCP-to-serial gateway returns for a unit ID with nothing
# behind it. Anything else in an exception response is a real device saying it
# does not support the request.
_GATEWAY_NO_DEVICE = {0x0A, 0x0B}

# Hosts probed concurrently once the port sweep has found them. Each host still
# sees one request at a time.
_HOST_WORKERS = 16


class _ModbusSession:
    """One TCP connection to a Modbus server, reused across requests.

    Reconnects once if the server closes the connection between requests,
    which plenty of small devices do after every reply. Once a request on
    the connection has timed out, replies must carry the transaction ID just
    sent, so the late answer to that request is not taken for the answer to
    the next one. Until then any reply is accepted: the spec says a server
    echoes the ID, and not every device does.
    """

    def __init__(self, ip: str, port: int, timeout: float):
        self.ip, self.port, self.timeout = ip, port, timeout
        self.sock: Optional[socket.socket] = None
        self.txn = 0
        self._stale_possible = False

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            self._stale_possible = False

    def __enter__(self) -> "_ModbusSession":
        return self

    def __exit__(self, *_a) -> None:
        self.close()

    def request(self, unit_id: int, pdu: bytes) -> Optional[bytes]:
        """Send one PDU and return the full response frame, or None."""
        for attempt in (0, 1):
            try:
                if self.sock is None:
                    self.sock = socket.create_connection((self.ip, self.port),
                                                         timeout=self.timeout)
                self.txn = (self.txn + 1) & 0xFFFF
                self.sock.sendall(struct.pack('!HHHB', self.txn, 0, len(pdu) + 1, unit_id)
                                  + pdu)
                while True:
                    resp = ModbusScanner._recv_frame(self.sock)
                    if len(resp) < 8:
                        raise ConnectionError("connection closed")
                    got = struct.unpack('!H', resp[0:2])[0]
                    if got == self.txn or not self._stale_possible:
                        return resp
                    log.debug("%s:%d stale Modbus reply (txn %d)", self.ip, self.port, got)
            except socket.timeout:
                # The device is up but silent for this unit. Do not retry: the
                # next request would just wait out the same timeout again.
                self._stale_possible = True
                return None
            except OSError:
                self.close()
                if attempt:
                    return None
        return None


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

    # -- framing ----------------------------------------------------------

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        """Read exactly n bytes, or return what arrived before the stream ended."""
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return bytes(buf)

    @classmethod
    def _recv_frame(cls, sock: socket.socket) -> bytes:
        """Read one complete Modbus TCP frame.

        Every probe here used a single recv() and treated whatever came back
        as the whole response. TCP does not promise that: a response split
        across segments was parsed short, and a byte_count larger than the
        first segment silently truncated the register list. The MBAP header
        declares the length, so read the header then exactly that many bytes.
        """
        header = cls._recv_exact(sock, 7)          # txn(2) proto(2) len(2) unit(1)
        if len(header) < 7:
            return header
        length = struct.unpack('!H', header[4:6])[0]
        if not 1 <= length <= 253:                 # per the Modbus TCP spec
            return header
        return header + cls._recv_exact(sock, length - 1)

    # -- request PDUs -----------------------------------------------------

    # FC 43 / MEI 14 Read Device Identification, basic objects from 0.
    _DEVICE_ID_PDU = bytes([0x2B, 0x0E, 0x01, 0x00])

    @staticmethod
    def _read_pdu(func_code: int, start: int, count: int) -> bytes:
        return struct.pack('!BHH', func_code, start, count)

    # -- per-host probing -----------------------------------------------

    def scan_host(self, ip: str, port: int = 502,
                  unit_ids: Optional[list[int]] = None) -> list[dict[str, Any]]:
        """Probe one host at multiple unit IDs over one connection."""
        unit_ids = unit_ids or self.COMMON_UNIT_IDS
        results: list[dict[str, Any]] = []

        with _ModbusSession(ip, port, self.timeout) as session:
            for uid in unit_ids:
                # Try Device Identification (FC 0x2B, MEI 0x0E) first, then
                # Report Server ID (FC 0x11), which older devices answer
                # instead.
                info = self._device_id_via(session, uid)
                if info is None:
                    info = self._server_id_via(session, uid)
                if info is None:
                    # Fall back to a minimal holding register read
                    info = self._holding_read_via(session, uid)
                if info:
                    info.update({'ip': ip, 'port': port, 'unit_id': uid})
                    results.append(info)

        results = self._collapse_any_unit(results, unit_ids)
        for info in results:
            note = " (answers any unit ID)" if info.get('answers_any_unit') else ""
            via = info.get('detected_via', '?')
            self._log(f"  Modbus device at {ip}:{port} unit={info['unit_id']} ({via}){note}")
        return results

    @staticmethod
    def _collapse_any_unit(results: list[dict[str, Any]],
                           unit_ids: list[int]) -> list[dict[str, Any]]:
        """Report a device that ignores the unit ID once.

        A Modbus TCP device that is not a gateway usually answers whatever
        unit ID it is sent, so probing nine IDs listed one meter nine times.
        A gateway answers per slave, and its slaves differ (or go silent). If
        every probed ID answered with the same identity, it is one device.
        """
        if len(unit_ids) < 3 or len(results) != len(unit_ids):
            return results

        def identity(r):
            return (r.get('vendor'), r.get('product'), r.get('version'),
                    r.get('detected_via'))
        if len({identity(r) for r in results}) != 1:
            return results
        first = dict(results[0])
        first['answers_any_unit'] = True
        return [first]

    def _device_id_via(self, session: _ModbusSession, uid: int) -> Optional[dict[str, Any]]:
        resp = session.request(uid, self._DEVICE_ID_PDU)
        if not resp or len(resp) < 9:
            return None
        # 0x2B echoed = the device answered the request. 0xAB (0x2B | 0x80) is
        # an exception response: FC 43 / MEI 14 is optional and plenty of
        # devices reject it. Fall through to the register read so the caller
        # labels how the device was really detected.
        if resp[7] != 0x2B:
            return None
        return self._parse_device_id_response(resp)

    def _server_id_via(self, session: _ModbusSession, uid: int) -> Optional[dict[str, Any]]:
        """Report Server ID (FC 0x11), as nmap's modbus-discover asks.

        Its contents are the vendor's own: usually a product string, a run
        indicator, sometimes a version. Printable text in it is kept as the
        product; the rest is reported as hex.
        """
        resp = session.request(uid, bytes([0x11]))
        if not resp or len(resp) < 10 or resp[7] != 0x11:
            return None
        data = resp[9:9 + resp[8]]
        text = " ".join(t.decode('ascii') for t in re.findall(rb'[\x20-\x7E]{3,}', data)).strip()
        return {
            'vendor': 'Unknown', 'product': text[:80] or 'Unknown', 'version': 'Unknown',
            'server_id': data.hex(), 'detected_via': 'report_server_id',
        }

    def _holding_read_via(self, session: _ModbusSession, uid: int) -> Optional[dict[str, Any]]:
        resp = session.request(uid, self._read_pdu(0x03, 0, 1))
        if not resp or len(resp) < 9:
            return None
        fc = resp[7]
        # 0x03 = success; 0x83 = exception (valid device replying, just
        # unsupported data) — unless it is a gateway saying nobody is there.
        if fc == 0x83 and resp[8] in _GATEWAY_NO_DEVICE:
            return None
        if fc not in (0x03, 0x83):
            return None
        return {
            'vendor': 'Unknown', 'product': 'Unknown', 'version': 'Unknown',
            'detected_via': 'holding_register_read' if fc == 0x03 else 'exception_response',
        }

    # Single-request forms, kept for callers that probe one unit directly.

    def _try_device_id(self, ip: str, port: int, uid: int) -> Optional[dict[str, Any]]:
        with _ModbusSession(ip, port, self.timeout) as session:
            info = self._device_id_via(session, uid)
        if info:
            info.update({'ip': ip, 'port': port, 'unit_id': uid})
        return info

    def _try_holding_read(self, ip: str, port: int, uid: int) -> Optional[dict[str, Any]]:
        with _ModbusSession(ip, port, self.timeout) as session:
            info = self._holding_read_via(session, uid)
        if info:
            info.update({'ip': ip, 'port': port, 'unit_id': uid})
        return info

    # -- network sweep ---------------------------------------------------

    def scan_network(self, network_cidr: str, port: int = 502,
                     unit_ids: Optional[list[int]] = None,
                     max_workers: int = 256,
                     stop_event=None,
                     progress: Optional[Callable[[int, int], None]] = None
                     ) -> list[dict[str, Any]]:
        self.devices = []
        # v2.1.2: accept CIDR, single IPs, shorthand ranges (10.0.0.2-100),
        # full-IP ranges (10.0.0.2-10.0.0.100), or comma-separated lists.
        from .netrange import parse_targets, InvalidTargetSyntaxError
        try:
            hosts = parse_targets(network_cidr)
        except InvalidTargetSyntaxError as e:
            self._log(f"Invalid target: {e}")
            return []
        if not hosts:
            self._log(f"No hosts parsed from target {network_cidr!r}")
            return []

        self._log(f"Scanning {len(hosts)} hosts for Modbus TCP on port {port}...")

        def on_open(ip: str, _port: int) -> None:
            self._log(f"  -> Port {port} open on {ip}")

        open_hosts = [ip for ip, _p in tcp_sweep(
            ((h, port) for h in hosts), total=len(hosts),
            timeout=min(self.timeout, 1.0), concurrency=max_workers,
            stop_event=stop_event, on_open=on_open, progress=progress)]
        self._log(f"  Found {len(open_hosts)} host(s) with port {port} open")
        if not open_hosts or (stop_event and stop_event.is_set()):
            return []

        def probe(ip: str) -> list[dict[str, Any]]:
            if stop_event and stop_event.is_set():
                return []
            try:
                return self.scan_host(ip, port, unit_ids)
            except Exception:
                log.exception("Modbus probe of %s failed", ip)
                return []

        with ThreadPoolExecutor(max_workers=min(_HOST_WORKERS, len(open_hosts)),
                                thread_name_prefix="modbus") as pool:
            for found in pool.map(probe, open_hosts):
                self.devices.extend(found)

        self._log(f"Found {len(self.devices)} Modbus device(s)")
        return self.devices

    # -- register / coil reads -------------------------------------------

    def read_points(self, ip: str, port: int, unit_id: int) -> dict[str, list[dict]]:
        """Holding registers 0-49, input registers 0-49 and coils 0-15, on
        one connection."""
        with _ModbusSession(ip, port, self.timeout) as session:
            return {
                'holding_registers': self._registers_from(
                    session.request(unit_id, self._read_pdu(3, 0, 50)), 0, 3),
                'input_registers': self._registers_from(
                    session.request(unit_id, self._read_pdu(4, 0, 50)), 0, 4),
                'coils': self._coils_from(
                    session.request(unit_id, self._read_pdu(1, 0, 16)), 0, 16),
            }

    def read_registers(self, ip: str, port: int, unit_id: int,
                       start: int = 0, count: int = 10, func_code: int = 3) -> list[dict]:
        """Read holding (fc=3) or input (fc=4) registers."""
        with _ModbusSession(ip, port, self.timeout) as session:
            resp = session.request(unit_id, self._read_pdu(func_code, start, count))
        return self._registers_from(resp, start, func_code)

    def read_coils(self, ip: str, port: int, unit_id: int,
                   start: int = 0, count: int = 16) -> list[dict]:
        with _ModbusSession(ip, port, self.timeout) as session:
            resp = session.request(unit_id, self._read_pdu(0x01, start, count))
        return self._coils_from(resp, start, count)

    @staticmethod
    def _registers_from(resp: Optional[bytes], start: int, func_code: int) -> list[dict]:
        results: list[dict] = []
        if not resp or len(resp) < 9 or resp[7] != func_code:
            return results
        byte_count = resp[8]
        data = resp[9:9 + byte_count]
        for i in range(0, len(data) - 1, 2):
            val = struct.unpack('!H', data[i:i + 2])[0]
            results.append({'register': start + (i // 2), 'value': val, 'hex': f"0x{val:04X}"})
        return results

    @staticmethod
    def _coils_from(resp: Optional[bytes], start: int, count: int) -> list[dict]:
        results: list[dict] = []
        if not resp or len(resp) < 9 or resp[7] != 0x01:
            return results
        byte_count = resp[8]
        data = resp[9:9 + byte_count]
        for i in range(count):
            byte_idx = i // 8
            if byte_idx < len(data):
                val = (data[byte_idx] >> (i % 8)) & 1
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
