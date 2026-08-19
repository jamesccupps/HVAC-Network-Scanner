"""Mock BACnet device for end-to-end testing.

Answers Who-Is, ReadProperty, and ReadPropertyMultiple (including
propertyArrayIndex batches), and counts the round trips it served so tests can
assert on exchange cost rather than only on correctness.

`rpm_mode` controls how the device handles ReadPropertyMultiple:
    "full"        answer everything, including array-index batches
    "reject"      reply Error to every RPM (the Tracer Ensemble behavior)
    "no_arrays"   answer plain RPM but reject requests carrying array indices
                  (a stack that implements RPM but not propertyArrayIndex)
"""
import socket
import struct
import threading

from hvac_scanner import codec
from hvac_scanner.constants import BACNET_OBJ_TYPES


def _bvlc(payload, fn=0x0A):
    return struct.pack('!BBH', 0x81, fn, 4 + len(payload)) + payload


def _cs(text):
    b = b'\x00' + text.encode()
    return bytes([0x75, len(b)]) + b


class MockBACnetDevice:
    def __init__(self, instance=1234, n_objects=200, vendor_id=2,
                 model='Tracer SC+', max_apdu=1476, rpm_mode='full',
                 host='127.0.0.1'):
        self.instance = instance
        self.vendor_id = vendor_id
        self.model = model
        self.max_apdu = max_apdu
        self.rpm_mode = rpm_mode
        self.exchanges = 0            # request packets served
        self.rpm_batches = 0          # array-index RPM requests served
        self.single_reads = 0         # plain ReadProperty requests served

        # Contiguous type blocks, the way real controllers enumerate
        self.objects = []
        blocks = [('Analog Input', 0.58), ('Analog Output', 0.08),
                  ('Analog Value', 0.16), ('Binary Input', 0.09),
                  ('Binary Output', 0.05), ('Multi-State Value', 0.04)]
        for name, share in blocks:
            for i in range(max(1, round(n_objects * share))):
                self.objects.append((name, i))
        # Rounding can land just under the target; pad so the device really
        # holds n_objects and a test asserting full coverage means something.
        while len(self.objects) < n_objects:
            self.objects.append(('Analog Value', len(self.objects)))
        self.objects = self.objects[:n_objects]

        self.dev_props = {
            77: _cs('Mock Controller'), 121: _cs('The Trane Company'),
            70: _cs(model), 44: _cs('5.20'), 12: _cs('5.20'),
            28: _cs('mock device'), 98: bytes([0x21, 0x01]),
            139: bytes([0x21, 0x0F]),
        }
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, 47808))
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *a):
        self._stop = True
        self._sock.close()

    # -- encoding helpers --------------------------------------------------

    def _obj_id_value(self, idx):
        """Application-tagged object identifier for objectList[idx] (1-based)."""
        if not 1 <= idx <= len(self.objects):
            return None
        t, i = self.objects[idx - 1]
        return bytes([0xC4]) + codec.encode_object_id(t, i)

    def _point_prop(self, otype, oinst, prop):
        name = BACNET_OBJ_TYPES.get(otype, '?')
        if prop == 85:
            if name.startswith('Binary'):
                return bytes([0x91, 0x01])
            if name.startswith('Multi'):
                return bytes([0x21, 0x02])
            return bytes([0x44]) + struct.pack('!f', 72.5)
        if prop == 77:
            return _cs('%s-%d' % (name, oinst))
        if prop == 117:
            return bytes([0x91, 64])
        if prop == 28:
            return _cs('mock point')
        return None

    def _prop_value(self, otype, oinst, prop, array_index):
        if otype == 8:
            if prop == 76:
                if array_index == 0:
                    return bytes([0x21, len(self.objects)]) if len(self.objects) < 256 \
                        else bytes([0x22, (len(self.objects) >> 8) & 0xFF,
                                    len(self.objects) & 0xFF])
                if array_index is not None:
                    return self._obj_id_value(array_index)
                return None
            return self.dev_props.get(prop)
        return self._point_prop(otype, oinst, prop)

    # -- server ------------------------------------------------------------

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                return
            self.exchanges += 1
            try:
                self._handle(data, addr)
            except Exception:
                pass

    def _handle(self, data, addr):
        if len(data) >= 12 and data[10:12] == b'\x10\x08':
            oid = struct.pack('!I', (8 << 22) | self.instance)
            apdu_code = {50: 0, 128: 1, 206: 2, 480: 3, 1024: 4}.get(self.max_apdu, 5)
            iam = (bytes([0x10, 0x00, 0xC4]) + oid
                   + bytes([0x22, (self.max_apdu >> 8) & 0xFF, self.max_apdu & 0xFF])
                   + bytes([0x91, 0x03])
                   + bytes([0x21, self.vendor_id]))
            self._sock.sendto(_bvlc(b'\x01\x00' + iam, 0x0B), addr)
            return

        inv = codec._extract_invoke_id(data)
        if inv is None or len(data) < 11:
            return
        svc = data[9]

        if svc == 0x0C:
            self.single_reads += 1
            self._handle_rp(data, inv, addr)
        elif svc == 0x0E:
            self._handle_rpm(data, inv, addr)

    def _handle_rp(self, data, inv, addr):
        raw = struct.unpack('!I', data[11:15])[0]
        otype, oinst = (raw >> 22) & 0x3FF, raw & 0x3FFFFF
        prop = data[16]
        ai = data[18] if len(data) > 18 and data[17] == 0x29 else None
        if ai is None and len(data) > 19 and data[17] == 0x2A:
            ai = struct.unpack('!H', data[18:20])[0]
        val = self._prop_value(otype, oinst, prop, ai)
        if val is None:
            return
        ack = (bytes([0x30, inv, 0x0C, 0x0C])
               + codec.encode_object_id(otype, oinst)
               + bytes([0x19, prop])
               + (codec.encode_context_unsigned(2, ai) if ai is not None else b'')
               + bytes([0x3E]) + val + bytes([0x3F]))
        self._sock.sendto(_bvlc(b'\x01\x00' + ack), addr)

    def _error(self, inv, service, addr):
        self._sock.sendto(_bvlc(b'\x01\x00' + bytes([0x50, inv, service, 0x09])), addr)

    def _handle_rpm(self, data, inv, addr):
        if self.rpm_mode == 'reject':
            self._error(inv, 0x0E, addr)
            return
        raw = struct.unpack('!I', data[11:15])[0]
        otype, oinst = (raw >> 22) & 0x3FF, raw & 0x3FFFFF
        idx = 15
        if idx >= len(data) or data[idx] != 0x1E:
            self._error(inv, 0x0E, addr)
            return
        idx += 1
        refs = []
        while idx < len(data) and data[idx] != 0x1F:
            tag = data[idx]
            if (tag & 0xF8) == 0x08:                       # ctx0 propertyIdentifier
                n = tag & 0x07
                prop = int.from_bytes(data[idx + 1:idx + 1 + n], 'big')
                idx += 1 + n
                ai = None
                if idx < len(data) and (data[idx] & 0xF8) == 0x18:   # ctx1 arrayIndex
                    m = data[idx] & 0x07
                    ai = int.from_bytes(data[idx + 1:idx + 1 + m], 'big')
                    idx += 1 + m
                refs.append((prop, ai))
            else:
                break
        if self.rpm_mode == 'no_arrays' and any(ai is not None for _p, ai in refs):
            self._error(inv, 0x0E, addr)
            return
        if any(ai is not None for _p, ai in refs):
            self.rpm_batches += 1

        body = bytearray()
        body += bytes([0x0C]) + codec.encode_object_id(otype, oinst)
        body += bytes([0x1E])
        for prop, ai in refs:
            val = self._prop_value(otype, oinst, prop, ai)
            body += codec.encode_context_unsigned(2, prop)
            if ai is not None:
                body += codec.encode_context_unsigned(3, ai)
            if val is None:
                body += bytes([0x5E, 0x91, 0x02, 0x91, 0x20, 0x5F])   # access error
            else:
                body += bytes([0x4E]) + val + bytes([0x4F])
        body += bytes([0x1F])
        ack = bytes([0x30, inv, 0x0E]) + bytes(body)
        self._sock.sendto(_bvlc(b'\x01\x00' + ack), addr)
