"""A simulated building-automation site on loopback addresses.

Stands up a small but realistic BAS network on 127.0.0.x so the scanner can be
exercised end to end — real sockets, the real BACnet port 47808, broadcast
discovery, MS/TP routing, Modbus, SNMP and web UIs — without going anywhere
near a live building. It is what the end-to-end tests run against, and what
the README screenshots were taken from.

    python tools/sim_site.py             # run until Ctrl-C
    hvac-scanner 127.0.0.2-30            # in another terminal

The whole of 127.0.0.0/8 is loopback on Windows and Linux, so every simulated
device gets an address of its own. (macOS only answers on 127.0.0.1 unless
you add aliases: `sudo ifconfig lo0 alias 127.0.0.2` and so on.) Loopback has
no broadcast, so a listener on the /24 broadcast address, 127.0.0.255, relays
each Who-Is to every device — the job the switch does on a real segment.

Replies to a broadcast come back through that relay as Forwarded-NPDUs
carrying each device's own address, exactly as a BBMD delivers them. They
cannot come straight from the devices: Windows Firewall filters UDP
statefully and drops a datagram from 127.0.0.3 to a socket that only ever
sent to 127.0.0.255, the same way it drops real broadcast replies for a
program that has no inbound rule.

Ports below 1024 (Modbus 502, SNMP 161, HTTP 80, FTP 21) need root on Linux.

Nothing here is used by the scanner itself. It depends only on the standard
library and the scanner's own codec for object-identifier encoding.
"""

from __future__ import annotations

import argparse
import http.server
import math
import os
import random
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hvac_scanner.codec import BACnetParseError, _read_tag  # noqa: E402

BACNET_PORT = 47808
DEFAULT_NETWORK = "127.0.0"


# ---------------------------------------------------------------------------
# BACnet value encoding
# ---------------------------------------------------------------------------

def _tag(num: int, data: bytes, context: bool = False) -> bytes:
    """One tag header plus its contents, extended length where needed."""
    cls = 0x08 if context else 0x00
    n = len(data)
    if n <= 4:
        return bytes([(num << 4) | cls | n]) + data
    if n < 254:
        return bytes([(num << 4) | cls | 5, n]) + data
    return bytes([(num << 4) | cls | 5, 254]) + struct.pack('!H', n) + data


def _uint_bytes(v: int) -> bytes:
    return v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')


def app_unsigned(v: int) -> bytes:
    return _tag(2, _uint_bytes(v))


def app_enum(v: int) -> bytes:
    return _tag(9, _uint_bytes(v))


def app_real(v: float) -> bytes:
    return _tag(4, struct.pack('!f', v))


def app_string(s: str) -> bytes:
    return _tag(7, b'\x00' + s.encode('utf-8'))


def app_oid(obj_type: int, instance: int) -> bytes:
    return _tag(12, struct.pack('!I', (obj_type << 22) | instance))


def ctx_unsigned(num: int, v: int) -> bytes:
    return _tag(num, _uint_bytes(v), context=True)


def bvlc(fn: int, npdu_apdu: bytes) -> bytes:
    return struct.pack('!BBH', 0x81, fn, 4 + len(npdu_apdu)) + npdu_apdu


# ---------------------------------------------------------------------------
# Site model
# ---------------------------------------------------------------------------

UNITS_F, UNITS_PCT, UNITS_RH, UNITS_INWC, UNITS_CFM, UNITS_KW, UNITS_PPM = 64, 98, 29, 58, 84, 48, 96
UNITS_HZ, UNITS_KWH, UNITS_GPM, UNITS_PSI = 27, 19, 89, 56

# (object type, base name, units, description, value range)
_AHU_POINTS = [
    (0, "SA-T", UNITS_F, "Supply air temperature", (52, 58)),
    (0, "RA-T", UNITS_F, "Return air temperature", (70, 75)),
    (0, "MA-T", UNITS_F, "Mixed air temperature", (58, 66)),
    (0, "OA-T", UNITS_F, "Outside air temperature", (35, 60)),
    (0, "SA-P", UNITS_INWC, "Duct static pressure", (1.2, 1.6)),
    (0, "RA-H", UNITS_RH, "Return air humidity", (35, 50)),
    (0, "RA-CO2", UNITS_PPM, "Return air CO2", (450, 900)),
    (0, "SA-CFM", UNITS_CFM, "Supply airflow", (9000, 14000)),
    (1, "CHW-V", UNITS_PCT, "Chilled water valve", (0, 100)),
    (1, "HW-V", UNITS_PCT, "Hot water valve", (0, 40)),
    (1, "OA-D", UNITS_PCT, "Outside air damper", (15, 100)),
    (1, "SF-VFD", UNITS_PCT, "Supply fan speed", (40, 85)),
    (2, "SA-T-SP", UNITS_F, "Supply air temperature setpoint", (55, 55)),
    (2, "SA-P-SP", UNITS_INWC, "Duct static pressure setpoint", (1.4, 1.4)),
    (3, "SF-S", None, "Supply fan status", (0, 1)),
    (3, "FRZ-STAT", None, "Freeze stat", (0, 0)),
    (3, "FLTR-DP", None, "Filter differential pressure switch", (0, 0)),
    (4, "SF-C", None, "Supply fan command", (1, 1)),
    (5, "OCC", None, "Occupied", (1, 1)),
    (19, "AHU-MODE", None, "Unit mode", (1, 4)),
]

_VAV_POINTS = [
    (0, "ZN-T", UNITS_F, "Zone temperature", (69, 75)),
    (0, "DA-T", UNITS_F, "Discharge air temperature", (55, 85)),
    (0, "AIR-FLOW", UNITS_CFM, "Box airflow", (150, 900)),
    (1, "DMPR-POS", UNITS_PCT, "Damper position", (10, 100)),
    (1, "HTG-VLV", UNITS_PCT, "Reheat valve", (0, 60)),
    (2, "ZN-SP", UNITS_F, "Zone setpoint", (72, 72)),
    (2, "FLOW-SP", UNITS_CFM, "Airflow setpoint", (200, 800)),
    (3, "OCC-SENS", None, "Occupancy sensor", (0, 1)),
    (19, "OCC-MODE", None, "Occupancy mode", (1, 3)),
]

_PLANT_POINTS = [
    (0, "CHWS-T", UNITS_F, "Chilled water supply temperature", (43, 46)),
    (0, "CHWR-T", UNITS_F, "Chilled water return temperature", (52, 57)),
    (0, "CHW-DP", UNITS_PSI, "Chilled water differential pressure", (10, 14)),
    (0, "CHW-FLOW", UNITS_GPM, "Chilled water flow", (400, 900)),
    (0, "CH1-KW", UNITS_KW, "Chiller 1 demand", (120, 260)),
    (0, "BLDG-KWH", UNITS_KWH, "Building energy", (812000, 812500)),
    (1, "CHWP1-VFD", UNITS_PCT, "Chilled water pump 1 speed", (55, 80)),
    (2, "CHWS-SP", UNITS_F, "Chilled water supply setpoint", (44, 44)),
    (3, "CH1-S", None, "Chiller 1 status", (1, 1)),
    (3, "CHWP1-S", None, "Chilled water pump 1 status", (1, 1)),
    (4, "CH1-C", None, "Chiller 1 enable", (1, 1)),
    (19, "PLANT-MODE", None, "Plant mode", (2, 2)),
]


@dataclass
class SimPoint:
    obj_type: int
    instance: int
    name: str
    units: Optional[int]
    description: str
    value: float
    flags: int = 0                     # statusFlags bits: 0x80 alarm .. 0x10 OOS
    states: Optional[list[str]] = None # stateText, multi-state objects only


# stateText for the multi-state points in the templates above.
_STATE_TEXT = {
    "AHU-MODE": ["Off", "Heating", "Cooling", "Economizer"],
    "OCC-MODE": ["Occupied", "Unoccupied", "Standby"],
    "PLANT-MODE": ["Off", "Normal", "Free cooling"],
}
STATUS_IN_ALARM, STATUS_FAULT, STATUS_OVERRIDDEN, STATUS_OUT_OF_SERVICE = 0x80, 0x40, 0x20, 0x10


@dataclass
class SimDevice:
    """One BACnet device: an IP controller, or an MS/TP device behind a router."""
    instance: int
    name: str
    vendor_id: int
    vendor_name: str
    model: str
    firmware: str = "1.0"
    app_version: str = "1.0"
    description: str = ""
    location: str = ""
    max_apdu: int = 1476
    segmentation: int = 3              # 3 = no segmentation
    rpm: bool = True                   # False: reject ReadPropertyMultiple
    latency: float = 0.002             # per-request processing time
    points: list[SimPoint] = field(default_factory=list)

    def add_equipment(self, prefix: str, template, start: dict[int, int]) -> None:
        """Append one piece of equipment's points, numbering per object type."""
        for obj_type, base, units, desc, (lo, hi) in template:
            inst = start.setdefault(obj_type, 1)
            start[obj_type] = inst + 1
            if obj_type in (3, 4, 5):
                value = float(random.choice([lo, hi]))
            elif obj_type == 19:
                value = float(random.randint(int(lo), int(hi)))
            else:
                value = round(random.uniform(lo, hi), 1)
            self.points.append(SimPoint(obj_type, inst, f"{prefix}:{base}" if prefix else base,
                                        units, desc, value,
                                        states=_STATE_TEXT.get(base) if obj_type == 19 else None))

    def flag(self, name: str, flags: int) -> None:
        """Set statusFlags on the point called `name`."""
        for p in self.points:
            if p.name == name:
                p.flags |= flags
                return
        raise KeyError(name)

    # -- property access ---------------------------------------------------

    def object_list(self) -> list[tuple[int, int]]:
        return [(8, self.instance)] + [(p.obj_type, p.instance) for p in self.points]

    def _point(self, obj_type: int, instance: int) -> Optional[SimPoint]:
        for p in self.points:
            if p.obj_type == obj_type and p.instance == instance:
                return p
        return None

    def read(self, obj_type: int, instance: int, prop: int,
             index: Optional[int]) -> "bytes | tuple[int, int]":
        """Encoded value, or (error class, error code)."""
        if obj_type == 8 and instance in (self.instance, 4194303):
            return self._read_device(prop, index)
        p = self._point(obj_type, instance)
        if p is None:
            return (1, 31)                       # object / unknown-object
        if prop == 75:
            return app_oid(obj_type, instance)
        if prop == 77:
            return app_string(p.name)
        if prop == 79:
            return app_enum(obj_type)
        if prop == 28:
            return app_string(p.description)
        if prop == 85:
            if obj_type in (3, 4, 5):
                return app_enum(int(p.value))
            if obj_type == 19:
                return app_unsigned(int(p.value))
            drift = p.value * 0.01 * math.sin(time.time() / 7 + instance)
            return app_real(round(p.value + drift, 2))
        if prop == 117 and p.units is not None:
            return app_enum(p.units)
        if prop == 111:                          # statusFlags: 4 bits used
            return _tag(8, bytes([4, p.flags]))
        if prop == 81:                           # outOfService
            return bytes([0x11 if p.flags & STATUS_OUT_OF_SERVICE else 0x10])
        if prop == 110 and p.states:             # stateText
            if index is None:
                return b''.join(app_string(s) for s in p.states)
            if index == 0:
                return app_unsigned(len(p.states))
            if 1 <= index <= len(p.states):
                return app_string(p.states[index - 1])
            return (2, 42)
        return (2, 32)                           # property / unknown-property

    def _read_device(self, prop: int, index: Optional[int]) -> "bytes | tuple[int, int]":
        if prop == 76:
            objs = self.object_list()
            if index is None:
                return b''.join(app_oid(t, i) for t, i in objs)
            if index == 0:
                return app_unsigned(len(objs))
            if 1 <= index <= len(objs):
                return app_oid(*objs[index - 1])
            return (2, 42)                       # property / invalid-array-index
        simple = {
            75: lambda: app_oid(8, self.instance),
            77: lambda: app_string(self.name),
            79: lambda: app_enum(8),
            112: lambda: app_enum(0),
            121: lambda: app_string(self.vendor_name),
            120: lambda: app_unsigned(self.vendor_id),
            70: lambda: app_string(self.model),
            44: lambda: app_string(self.firmware),
            12: lambda: app_string(self.app_version),
            28: lambda: app_string(self.description),
            58: lambda: app_string(self.location),
            62: lambda: app_unsigned(self.max_apdu),
            107: lambda: app_enum(self.segmentation),
            98: lambda: app_unsigned(1),
            139: lambda: app_unsigned(14),
        }
        if prop in simple:
            if prop in (28, 58) and not (self.description if prop == 28 else self.location):
                return (2, 32)
            return simple[prop]()
        return (2, 32)

    def iam_apdu(self) -> bytes:
        return (bytes([0x10, 0x00]) + app_oid(8, self.instance)
                + app_unsigned(self.max_apdu) + app_enum(self.segmentation)
                + app_unsigned(self.vendor_id))


# ---------------------------------------------------------------------------
# BACnet/IP endpoint
# ---------------------------------------------------------------------------

def _parse_npdu(data: bytes, idx: int) -> Optional[dict]:
    """Decode an NPDU header. Returns its fields and where the APDU starts."""
    if idx + 2 > len(data) or data[idx] != 0x01:
        return None
    ctrl = data[idx + 1]
    idx += 2
    out = {'ctrl': ctrl, 'dnet': None, 'dadr': None}
    if ctrl & 0x20:
        out['dnet'] = struct.unpack('!H', data[idx:idx + 2])[0]
        dlen = data[idx + 2]
        out['dadr'] = data[idx + 3:idx + 3 + dlen]
        idx += 3 + dlen
    if ctrl & 0x08:
        slen = data[idx + 2]
        idx += 3 + slen
    if ctrl & 0x20:
        idx += 1                                  # hop count
    out['network_msg'] = bool(ctrl & 0x80)
    out['apdu'] = idx
    return out


def _who_is_range(data: bytes, idx: int) -> tuple[int, int]:
    if idx >= len(data):
        return 0, 4194303
    try:
        _, _, _, vs, ve = _read_tag(data, idx)
        low = int.from_bytes(data[vs:ve], 'big')
        _, _, _, vs2, ve2 = _read_tag(data, ve)
        return low, int.from_bytes(data[vs2:ve2], 'big')
    except (BACnetParseError, IndexError):
        return 0, 4194303


class BACnetEndpoint:
    """One BACnet/IP address: a controller, optionally routing to MS/TP."""

    def __init__(self, ip: str, device: SimDevice,
                 mstp: Optional[dict[int, dict[int, SimDevice]]] = None):
        self.ip = ip
        self.device = device
        self.mstp = mstp or {}                    # dnet -> {mac: device}
        self.requests = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, BACNET_PORT))
        self._lock = threading.Lock()             # one request at a time, like the real thing
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._stop = True
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                self.handle(data, addr)
            except Exception as e:                 # a broken request must not kill the device
                print(f"[sim {self.ip}] error handling packet: {e!r}", file=sys.stderr)

    def _send(self, apdu: bytes, addr, broadcast: bool = False,
              snet: Optional[int] = None, sadr: bytes = b'', via=None) -> None:
        if snet is None:
            npdu = b'\x01\x00'
        else:
            npdu = bytes([0x01, 0x08]) + struct.pack('!H', snet) + bytes([len(sadr)]) + sadr
        if via is not None:
            via(self.ip, npdu + apdu)
        else:
            self.sock.sendto(bvlc(0x0B if broadcast else 0x0A, npdu + apdu), addr)

    def handle(self, data: bytes, addr, via=None) -> None:
        """Answer one packet. `via`, when given, is how a broadcast's replies
        travel back: through the relay, as Forwarded-NPDUs."""
        if len(data) < 6 or data[0] != 0x81:
            return
        idx = 4 + (6 if data[1] == 0x04 else 0)   # Forwarded-NPDU carries an origin address
        npdu = _parse_npdu(data, idx)
        if npdu is None:
            return
        if npdu['network_msg']:
            msg_type = data[npdu['apdu']]
            if msg_type == 0x00 and self.mstp:     # Who-Is-Router-To-Network
                nets = b''.join(struct.pack('!H', n) for n in sorted(self.mstp))
                payload = bytes([0x01, 0x80, 0x01]) + nets
                if via is not None:
                    via(self.ip, payload)
                else:
                    self.sock.sendto(bvlc(0x0B, payload), addr)
            return

        a = npdu['apdu']
        dnet, dadr = npdu['dnet'], npdu['dadr']
        if a + 2 > len(data):
            return

        # Who-Is: unconfirmed request, service 8
        if data[a] == 0x10 and data[a + 1] == 0x08:
            low, high = _who_is_range(data, a + 2)
            if dnet in (None, 0xFFFF) and low <= self.device.instance <= high:
                time.sleep(random.uniform(0, 0.05))
                self._send(self.device.iam_apdu(), addr, broadcast=True, via=via)
            for net, devices in self.mstp.items():
                if dnet not in (0xFFFF, net):
                    continue
                for mac, dev in devices.items():
                    if low <= dev.instance <= high:
                        time.sleep(dev.latency)
                        self._send(dev.iam_apdu(), addr, broadcast=True,
                                   snet=net, sadr=bytes([mac]), via=via)
            return

        if (data[a] >> 4) != 0 or a + 4 > len(data):
            return                                 # only confirmed requests from here
        invoke, service = data[a + 2], data[a + 3]
        target, snet, sadr = self.device, None, b''
        if dnet is not None and dnet != 0xFFFF:
            devices = self.mstp.get(dnet)
            if not devices or not dadr or dadr[0] not in devices:
                return                             # unreachable: real routers stay silent too
            target, snet, sadr = devices[dadr[0]], dnet, dadr

        with self._lock:
            self.requests += 1
            time.sleep(target.latency)
            if service == 0x0C:
                apdu = self._read_property(target, data, a + 4, invoke)
            elif service == 0x0E:
                apdu = (self._read_property_multiple(target, data, a + 4, invoke)
                        if target.rpm else _error(invoke, 0x0E, 5, 9))
            else:
                apdu = bytes([0x60, invoke, 0x08])    # Reject: unrecognized-service
            self._send(apdu, addr, snet=snet, sadr=sadr)

    @staticmethod
    def _read_property(dev: SimDevice, data: bytes, idx: int, invoke: int) -> bytes:
        try:
            _, _, _, vs, ve = _read_tag(data, idx)
            oid = struct.unpack('!I', data[vs:ve])[0]
            _, _, _, ps, pe = _read_tag(data, ve)
            prop = int.from_bytes(data[ps:pe], 'big')
            index = None
            if pe < len(data):
                _, _, _, is_, ie = _read_tag(data, pe)
                index = int.from_bytes(data[is_:ie], 'big')
        except (BACnetParseError, IndexError, struct.error):
            return bytes([0x60, invoke, 0x02])     # Reject: invalid-tag
        obj_type, inst = oid >> 22, oid & 0x3FFFFF
        val = dev.read(obj_type, inst, prop, index)
        if isinstance(val, tuple):
            return _error(invoke, 0x0C, *val)
        if obj_type == 8 and inst == 4194303:
            inst = dev.instance                    # wildcard answered as ourselves
        body = (bytes([0x0C]) + struct.pack('!I', (obj_type << 22) | inst)
                + ctx_unsigned(1, prop)
                + (ctx_unsigned(2, index) if index is not None else b'')
                + b'\x3E' + val + b'\x3F')
        return bytes([0x30, invoke, 0x0C]) + body

    @staticmethod
    def _read_property_multiple(dev: SimDevice, data: bytes, idx: int, invoke: int) -> bytes:
        out = bytearray()
        try:
            while idx < len(data):
                if data[idx] != 0x0C:
                    break
                oid = struct.unpack('!I', data[idx + 1:idx + 5])[0]
                idx += 5
                if data[idx] != 0x1E:
                    break
                idx += 1
                obj_type, inst = oid >> 22, oid & 0x3FFFFF
                reply_inst = dev.instance if (obj_type == 8 and inst == 4194303) else inst
                out += bytes([0x0C]) + struct.pack('!I', (obj_type << 22) | reply_inst) + b'\x1E'
                while data[idx] != 0x1F:
                    _, _, _, ps, pe = _read_tag(data, idx)
                    prop = int.from_bytes(data[ps:pe], 'big')
                    idx = pe
                    index = None
                    if (data[idx] & 0xF8) == 0x18 and (data[idx] & 0x07) not in (6, 7):
                        _, _, _, is_, ie = _read_tag(data, idx)
                        index = int.from_bytes(data[is_:ie], 'big')
                        idx = ie
                    val = dev.read(obj_type, inst, prop, index)
                    out += ctx_unsigned(2, prop)
                    if index is not None:
                        out += ctx_unsigned(3, index)
                    if isinstance(val, tuple):
                        out += b'\x5E' + app_enum(val[0]) + app_enum(val[1]) + b'\x5F'
                    else:
                        out += b'\x4E' + val + b'\x4F'
                idx += 1
                out += b'\x1F'
        except (BACnetParseError, IndexError, struct.error):
            return bytes([0x60, invoke, 0x02])
        if len(out) > dev.max_apdu - 8:
            return bytes([0x70, invoke, 0x04])     # Abort: segmentation-not-supported
        return bytes([0x30, invoke, 0x0E]) + bytes(out)


def _error(invoke: int, service: int, err_class: int, err_code: int) -> bytes:
    return bytes([0x50, invoke, service]) + app_enum(err_class) + app_enum(err_code)


class BroadcastRelay:
    """Stands in for the switch: hands each broadcast to every device."""

    def __init__(self, endpoints: list[BACnetEndpoint], address: str):
        self.endpoints = endpoints
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, BACNET_PORT))
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return

            def forward(origin_ip: str, npdu_apdu: bytes, addr=addr) -> None:
                origin = socket.inet_aton(origin_ip) + struct.pack('!H', BACNET_PORT)
                try:
                    self.sock.sendto(bvlc(0x04, origin + npdu_apdu), addr)
                except OSError:
                    pass

            for ep in self.endpoints:
                threading.Thread(target=ep.handle, args=(data, addr, forward),
                                 daemon=True).start()

    def close(self) -> None:
        self.sock.close()


# ---------------------------------------------------------------------------
# Modbus TCP
# ---------------------------------------------------------------------------

class ModbusUnit:
    def __init__(self, vendor: str = "", product: str = "", version: str = "",
                 holding: Optional[list[int]] = None, device_id: bool = True):
        self.vendor, self.product, self.version = vendor, product, version
        self.device_id = device_id
        self.holding = holding or [random.randint(0, 3000) for _ in range(60)]
        self.inputs = [random.randint(0, 1000) for _ in range(60)]
        self.coils = [random.randint(0, 1) for _ in range(32)]


class ModbusServer:
    """`units` maps unit id -> unit. `any_unit` answers every unit id (most
    direct-attached devices do); otherwise unknown ids get gateway exception
    0x0B, the way a TCP-to-RTU gateway reports a slave that did not answer."""

    def __init__(self, ip: str, units: dict[int, ModbusUnit], any_unit: bool = False):
        self.units, self.any_unit = units, any_unit
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(5)
                while True:
                    try:
                        hdr = _recv_exact(sock, 7)
                        if len(hdr) < 7:
                            return
                        length = struct.unpack('!H', hdr[4:6])[0]
                        pdu = _recv_exact(sock, length - 1)
                    except OSError:
                        return
                    reply = outer.respond(hdr[6], pdu)
                    if reply is None:
                        continue
                    sock.sendall(hdr[0:4] + struct.pack('!H', len(reply) + 1)
                                 + bytes([hdr[6]]) + reply)

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer((ip, 502), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def respond(self, uid: int, pdu: bytes) -> Optional[bytes]:
        if not pdu:
            return None
        fc = pdu[0]
        unit = self.units.get(uid)
        if unit is None and self.any_unit:
            unit = next(iter(self.units.values()))
        if unit is None:
            return bytes([fc | 0x80, 0x0B])      # gateway target failed to respond
        time.sleep(0.003)
        if fc == 0x2B:
            if not unit.device_id:
                return bytes([0xAB, 0x01])        # illegal function
            objs = [unit.vendor, unit.product, unit.version]
            body = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objs)])
            for i, s in enumerate(objs):
                b = s.encode()
                body += bytes([i, len(b)]) + b
            return body
        if fc in (3, 4) and len(pdu) >= 5:
            start, count = struct.unpack('!HH', pdu[1:5])
            regs = unit.holding if fc == 3 else unit.inputs
            vals = regs[start:start + count]
            if len(vals) < count:
                return bytes([fc | 0x80, 0x02])
            return bytes([fc, 2 * count]) + b''.join(struct.pack('!H', v) for v in vals)
        if fc == 1 and len(pdu) >= 5:
            start, count = struct.unpack('!HH', pdu[1:5])
            bits = unit.coils[start:start + count]
            out = bytearray((count + 7) // 8)
            for i, b in enumerate(bits):
                if b:
                    out[i // 8] |= 1 << (i % 8)
            return bytes([1, len(out)]) + bytes(out)
        return bytes([fc | 0x80, 0x01])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# SNMP, HTTP(S), banners
# ---------------------------------------------------------------------------

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = _uint_bytes(n)
    return bytes([0x80 | len(raw)]) + raw


def _ber(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


class SNMPAgent:
    """Answers a v1/v2c GET for sysDescr.0 with community 'public'."""

    SYS_DESCR_OID = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])

    def __init__(self, ip: str, sys_descr: str):
        self.sys_descr = sys_descr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, 161))
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                reply = self._reply(data)
            except (IndexError, ValueError):
                continue
            if reply:
                self.sock.sendto(reply, addr)

    def _reply(self, data: bytes) -> Optional[bytes]:
        # SEQUENCE { version, community, PDU { request-id, ... } }
        idx = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
        version = data[idx + 2]
        idx += 3
        clen = data[idx + 1]
        community = data[idx + 2:idx + 2 + clen]
        idx += 2 + clen
        if community != b'public' or self.SYS_DESCR_OID not in data:
            return None
        pdu_hdr = 2 if data[idx + 1] < 0x80 else 2 + (data[idx + 1] & 0x7F)
        rid_start = idx + pdu_hdr
        rid = data[rid_start:rid_start + 2 + data[rid_start + 1]]
        varbind = _ber(0x30, _ber(0x06, self.SYS_DESCR_OID)
                       + _ber(0x04, self.sys_descr.encode()))
        pdu = _ber(0xA2, rid + _ber(0x02, b'\x00') + _ber(0x02, b'\x00')
                   + _ber(0x30, varbind))
        return _ber(0x30, _ber(0x02, bytes([version])) + _ber(0x04, community) + pdu)

    def close(self) -> None:
        self.sock.close()


class WebUI:
    def __init__(self, ip: str, port: int, title: str, server: str,
                 tls_cert: Optional[tuple[str, str]] = None):
        body = (f"<html><head><title>{title}</title></head>"
                f"<body><form>Username <input name=u> Password <input type=password name=p>"
                f"</form></body></html>").encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = server
            sys_version = ""

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_a):
                pass

        self.httpd = http.server.ThreadingHTTPServer((ip, port), Handler)
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class BannerService:
    """A TCP port that sends a fixed greeting, e.g. an embedded FTP server."""

    def __init__(self, ip: str, port: int, banner: bytes, reply_to_input: bool = False):
        self.banner, self.reply_to_input = banner, reply_to_input
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(16)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn) -> None:
        with conn:
            try:
                conn.settimeout(3)
                if self.reply_to_input:
                    conn.recv(1024)
                conn.sendall(self.banner)
                time.sleep(0.2)
            except OSError:
                pass

    def close(self) -> None:
        self.sock.close()


class P2Node:
    """A Siemens APOGEE P2 listener on TCP/5033 that knows its BLN name.

    It answers the way the P2 reference documents a real node answering a
    frame from outside its network: a field panel resets the connection, a
    supervisor listener closes it gracefully, both before any processing.
    A frame carrying the right BLN name is acknowledged with a bare success
    response (not that the scanner ever sends one).
    """

    def __init__(self, ip: str, bln: str, node_name: str, supervisor: bool = False):
        self.bln, self.node_name, self.supervisor = bln, node_name, supervisor
        self.attempts: list[str] = []          # BLN names presented, for tests
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, 5033))
        self.sock.listen(16)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            hdr = _recv_exact(conn, 4)
            if len(hdr) < 4:
                return
            frame = hdr + _recv_exact(conn, struct.unpack('!I', hdr)[0] - 4)
            slots = frame[13:].split(b'\x00', 4)
            presented = slots[0].decode('ascii', 'replace') if slots else ''
            self.attempts.append(presented)
            if presented != self.bln:
                time.sleep(0.05)
                if not self.supervisor:          # panel: RST
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                    struct.pack('ii', 1, 0))
                return                           # supervisor: FIN on close
            src = slots[3] if len(slots) > 3 else b''
            reply_slots = (self.bln.encode() + b'\x00' + self.node_name.encode() + b'\x00'
                           + self.bln.encode() + b'\x00' + src + b'\x00')
            payload = b'\x01' + reply_slots
            conn.sendall(struct.pack('!III', 12 + len(payload), 13 + len(reply_slots),
                                     struct.unpack('!I', frame[8:12])[0]) + payload)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self.sock.close()


def _self_signed_cert(cn: str, org: str, workdir: str) -> Optional[tuple[str, str]]:
    """Make a throwaway certificate with openssl, if it is installed."""
    openssl = shutil.which('openssl')
    if not openssl:
        return None
    key, crt = os.path.join(workdir, f'{cn}.key'), os.path.join(workdir, f'{cn}.crt')
    try:
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key,
                        '-out', crt, '-days', '20', '-nodes', '-subj', f'/CN={cn}/O={org}'],
                       capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return crt, key                               # load_cert_chain(certfile, keyfile)


# ---------------------------------------------------------------------------
# The site
# ---------------------------------------------------------------------------

def build_bacnet_devices(network: str = DEFAULT_NETWORK,
                         seed: int = 7) -> list[tuple[str, SimDevice, dict]]:
    """The BACnet side of the site: (ip, device, mstp routes)."""
    random.seed(seed)

    sc = SimDevice(1001, "SC-1", 2, "Trane", "Tracer SC+", firmware="6.10.2154",
                   app_version="6.10", description="Building supervisory controller",
                   location="Mechanical room 2", max_apdu=1476)
    nums: dict[int, int] = {}
    for n in range(1, 5):
        sc.add_equipment(f"AHU-{n}", _AHU_POINTS, nums)
    for n in range(1, 61):
        sc.add_equipment(f"VAV-{n:02d}", _VAV_POINTS, nums)
    sc.add_equipment("PLANT", _PLANT_POINTS, nums)

    pxc = SimDevice(2000, "PXC-AS-2000", 7, "Siemens Building Technologies",
                    "Siemens BACnet Field Panel", firmware="EPXC V3.5.2",
                    description="Heating plant automation station", max_apdu=1476)
    nums = {}
    pxc.add_equipment("HHW", _PLANT_POINTS, nums)
    for n in range(5, 9):
        pxc.add_equipment(f"AHU-{n}", _AHU_POINTS, nums)

    dxr = SimDevice(2101, "RM-201", 7, "Siemens Building Technologies", "DXR2.E10PL-1",
                    firmware="01.21", max_apdu=480)
    dxr.add_equipment("", _VAV_POINTS, {})

    ens = SimDevice(1100, "Ensemble", 2, "Trane", "TES Workstation", rpm=False)

    distech = SimDevice(3101, "ECY-303", 364, "Distech Controls", "ECY-303",
                        firmware="2.4", description="Rooftop unit controller", latency=0.004)
    distech.add_equipment("RTU-1", _AHU_POINTS, {})

    router = SimDevice(3000, "BASRT-B", 245, "Contemporary Controls", "BASRT-B",
                       firmware="4.11", max_apdu=1476)
    mstp: dict[int, dict[int, SimDevice]] = {5: {}}
    for mac in (3, 7, 12):
        d = SimDevice(500000 + mac, f"FEC-{mac}", 5, "Johnson Controls", "FEC2611",
                      firmware="10.1", max_apdu=480, latency=0.025)
        d.add_equipment("", _VAV_POINTS, {})
        mstp[5][mac] = d

    sc.flag("AHU-2:FRZ-STAT", STATUS_IN_ALARM)
    sc.flag("AHU-3:SF-C", STATUS_OVERRIDDEN)
    sc.flag("VAV-07:ZN-T", STATUS_FAULT)
    sc.flag("VAV-12:DMPR-POS", STATUS_OVERRIDDEN)
    sc.flag("AHU-4:RA-H", STATUS_OUT_OF_SERVICE)
    pxc.flag("HHW:CH1-KW", STATUS_FAULT | STATUS_OUT_OF_SERVICE)

    return [
        (f"{network}.2", sc, {}),
        (f"{network}.3", pxc, {}),
        (f"{network}.4", dxr, {}),
        (f"{network}.5", router, mstp),
        (f"{network}.6", ens, {}),
        (f"{network}.7", distech, {}),
    ]


class Site:
    """`network` is the first three octets of the loopback /24 to use, so a
    test can run its own site beside one that is already up."""

    def __init__(self, quiet: bool = False, network: str = DEFAULT_NETWORK,
                 bacnet_only: bool = False):
        self.quiet = quiet
        self.network = network
        self.bacnet_only = bacnet_only
        self._closers: list = []
        self.endpoints: list[BACnetEndpoint] = []
        self._tmp = tempfile.mkdtemp(prefix="hvac-sim-")

    def _try(self, label: str, fn):
        try:
            obj = fn()
        except OSError as e:
            print(f"  [skip] {label}: {e}", file=sys.stderr)
            return None
        self._closers.append(obj)
        if not self.quiet:
            print(f"  {label}")
        return obj

    def start(self) -> "Site":
        net = self.network
        for ip, dev, mstp in build_bacnet_devices(net):
            ep = self._try(f"{ip:<11} BACnet  {dev.model} (device {dev.instance}, "
                           f"{len(dev.points)} points)"
                           + (f", routing MS/TP net {list(mstp)} ({sum(len(v) for v in mstp.values())} devices)"
                              if mstp else ""),
                           lambda ip=ip, dev=dev, mstp=mstp: BACnetEndpoint(ip, dev, mstp))
            if ep:
                self.endpoints.append(ep)
        self._try(f"{net + '.255':<11} BACnet  broadcast relay",
                  lambda: BroadcastRelay(self.endpoints, f"{net}.255"))
        if self.bacnet_only:
            return self

        meter = ModbusUnit("Schneider Electric", "PM5560", "v2.6.1",
                           holding=[2301, 2299, 2304, 412, 398, 405, 600, 0, 98] + [0] * 51)
        self._try(f"{net}.20  Modbus  power meter (answers any unit id)",
                  lambda: ModbusServer(f"{net}.20", {1: meter}, any_unit=True))
        self._try(f"{net}.21  Modbus  RTU gateway (units 1 and 2)",
                  lambda: ModbusServer(f"{net}.21", {
                      1: ModbusUnit(device_id=False),
                      2: ModbusUnit("Carrier", "30XA Chiller", "4.2"),
                  }))

        self._try(f"{net}.23  P2      APOGEE field panel (firmware 2.x, no BACnet)",
                  lambda: P2Node(f"{net}.23", "SIMBLN", "PXC23"))
        self._try(f"{net}.24  P2      Insight / Desigo CC P2 listener",
                  lambda: P2Node(f"{net}.24", "SIMBLN", "INSIGHT", supervisor=True))
        self._try(f"{net}.22  SNMP    Niagara JACE",
                  lambda: SNMPAgent(f"{net}.22", "Tridium JACE-8000 Niagara 4.13.1.16 "
                                                  "QNX 7.0 (supervisor for building B)"))
        self._try(f"{net}.22  Fox     Niagara JACE (1911)",
                  lambda: BannerService(f"{net}.22", 1911,
                                        b"fox a 0 -1 fox hello\n{\nfox.version=s:1.0.1\n"
                                        b"hostName=s:JACE-B\n};;\n", reply_to_input=True))
        self._try(f"{net}.22  HTTP    Niagara web UI",
                  lambda: WebUI(f"{net}.22", 80, "Niagara Web Server", "Niagara Web Server/4.13"))
        self._try(f"{net}.2   HTTP    Tracer SC+ web UI",
                  lambda: WebUI(f"{net}.2", 80, "Tracer SC+ - Log In", "Trane"))
        cert = _self_signed_cert("SC-1", "Trane", self._tmp)
        if cert:
            self._try(f"{net}.2   HTTPS   Tracer SC+ web UI (self-signed)",
                      lambda: WebUI(f"{net}.2", 443, "Tracer SC+ - Log In", "Trane",
                                    tls_cert=cert))
        self._try(f"{net}.3   HTTP    PXC web UI",
                  lambda: WebUI(f"{net}.3", 80, "Desigo PXC", "nginx"))
        self._try(f"{net}.3   FTP     PXC (Nucleus)",
                  lambda: BannerService(f"{net}.3", 21, b"220 Nucleus FTP Server ready\r\n"))
        return self

    def close(self) -> None:
        for obj in reversed(self._closers):
            try:
                obj.close()
            except Exception:
                pass
        shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self) -> "Site":
        return self.start()

    def __exit__(self, *_a) -> None:
        self.close()


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--network", default=DEFAULT_NETWORK, metavar="A.B.C",
                   help="loopback /24 to use (default: 127.0.0)")
    args = p.parse_args(argv)
    print("Simulated BAS site on loopback:")
    site = Site(quiet=args.quiet, network=args.network).start()
    print(f"\nScan it with:  hvac-scanner {args.network}.2-30   (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        site.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
