"""
Pure-function BACnet packet codec — no socket I/O.

Separating encode/decode from transport makes the parser testable against
captured packet bytes. The original scanner mixed the two, which is why
parser bugs were hard to notice.

Covers:
- BVLC header (Original-Unicast-NPDU, Original-Broadcast-NPDU)
- NPDU with optional DNET/DADR/SNET/SADR
- APDU: Who-Is, I-Am, ReadProperty, ReadProperty-ACK,
  ReadPropertyMultiple, ReadPropertyMultiple-ACK
- Application-tagged value decoding (all common types)
- Context-tagged value skipping (extended-length aware)

References:
- ASHRAE 135 Clauses 20-21 for APDU/property encoding
- ASHRAE 135 Annex J for BVLL/BVLC
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from .constants import BACNET_OBJ_TYPES, BACNET_PORT, BACNET_BVLC_TYPE, PROP_IDS


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IAmDevice:
    """Result of parsing an I-Am response."""
    ip: str
    port: int
    instance: int
    max_apdu: Optional[int] = None
    segmentation: Optional[str] = None
    vendor_id: Optional[int] = None
    source_network: Optional[int] = None
    source_address: Optional[str] = None


@dataclass
class ReadPropertyResult:
    """Decoded ReadProperty ACK."""
    obj_type: int
    obj_instance: int
    prop_id: int
    array_index: Optional[int]
    value: Any


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class BACnetParseError(ValueError):
    """Raised when a packet cannot be parsed. Wraps the underlying cause."""


# ---------------------------------------------------------------------------
# Tag helpers
# ---------------------------------------------------------------------------

def _read_tag(data: bytes, idx: int) -> tuple[int, int, int, int, int]:
    """Decode one BACnet tag header.

    Returns (tag_number, tag_class, length_or_value_type, value_start, next_tag_start).

    Handles:
      - tag numbers >= 15 (extended tag: second byte holds real number)
      - length >= 5 (extended length: additional bytes encode real length)
      - length == 6/7 (opening/closing tags — callers should special-case these)
    """
    if idx >= len(data):
        raise BACnetParseError(f"tag read past EOF at {idx}")

    tag_byte = data[idx]
    tag_class = (tag_byte >> 3) & 0x01  # 0=application, 1=context
    tag_num = (tag_byte >> 4) & 0x0F
    length = tag_byte & 0x07
    idx += 1

    # Extended tag number (tag field == 0xF)
    if tag_num == 0x0F:
        if idx >= len(data):
            raise BACnetParseError("extended tag num past EOF")
        tag_num = data[idx]
        idx += 1

    # Opening/closing tag — no value, caller decides what to do
    if length in (6, 7):
        return tag_num, tag_class, length, idx, idx

    # Extended length
    if length == 5:
        if idx >= len(data):
            raise BACnetParseError("extended length byte past EOF")
        ext = data[idx]
        idx += 1
        if ext < 254:
            length = ext
        elif ext == 254:
            if idx + 2 > len(data):
                raise BACnetParseError("extended length u16 past EOF")
            length = struct.unpack('!H', data[idx:idx + 2])[0]
            idx += 2
        else:  # 255
            if idx + 4 > len(data):
                raise BACnetParseError("extended length u32 past EOF")
            length = struct.unpack('!I', data[idx:idx + 4])[0]
            idx += 4

    return tag_num, tag_class, length, idx, idx + length


def _skip_tag(data: bytes, idx: int) -> int:
    """Advance past one tag+value. Handles opening/closing tags as zero-length."""
    _, _, length, _, next_idx = _read_tag(data, idx)
    if length in (6, 7):
        return next_idx  # opening/closing: no value bytes
    return next_idx


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def encode_context_unsigned(tag: int, value: int) -> bytes:
    """Encode an unsigned integer as a context-tagged value."""
    if value < 0x100:
        return bytes([0x08 | (tag << 4) | 1, value & 0xFF])
    elif value < 0x10000:
        return bytes([0x08 | (tag << 4) | 2,
                      (value >> 8) & 0xFF, value & 0xFF])
    elif value < 0x1000000:
        return bytes([0x08 | (tag << 4) | 3,
                      (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
    else:
        return bytes([0x08 | (tag << 4) | 4,
                      (value >> 24) & 0xFF, (value >> 16) & 0xFF,
                      (value >> 8) & 0xFF, value & 0xFF])


def encode_object_id(obj_type: int | str, obj_instance: int) -> bytes:
    """Encode an Object Identifier as 4 bytes (10 bits type, 22 bits instance)."""
    if isinstance(obj_type, str):
        obj_type = resolve_object_type(obj_type)
    oid = ((obj_type & 0x3FF) << 22) | (obj_instance & 0x3FFFFF)
    return struct.pack('!I', oid)


def resolve_object_type(name: str) -> int:
    """Convert an object type name to its numeric ID. Accepts display names
    ('Analog Input'), camelCase ('analogInput'), lowercase, or 'type-N' syntax."""
    # Reverse map from display names
    for num, display in BACNET_OBJ_TYPES.items():
        if display == name or display.lower() == name.lower():
            return num
    # Common camelCase forms
    camel = {
        'analogInput': 0, 'analogOutput': 1, 'analogValue': 2,
        'binaryInput': 3, 'binaryOutput': 4, 'binaryValue': 5,
        'device': 8, 'multiStateInput': 13, 'multiStateOutput': 14,
        'multiStateValue': 19, 'schedule': 17, 'trendLog': 20,
        'notificationClass': 15, 'loop': 12, 'program': 16,
    }
    if name in camel:
        return camel[name]
    if name.lower() in {k.lower(): v for k, v in camel.items()}:
        return {k.lower(): v for k, v in camel.items()}[name.lower()]
    # type-N fallback
    if name.startswith('type-'):
        try:
            return int(name[5:])
        except ValueError:
            pass
    return 8  # default to device


def resolve_property_id(prop: int | str) -> int:
    """Convert a property name or number to a numeric property ID."""
    if isinstance(prop, int):
        return prop
    if prop in PROP_IDS:
        return PROP_IDS[prop]
    # last-ditch: try numeric
    try:
        return int(prop)
    except (TypeError, ValueError):
        return 85  # presentValue


def build_bvlc(function: int, payload: bytes) -> bytes:
    """Wrap an NPDU payload in a BVLC header."""
    total_len = 4 + len(payload)
    return struct.pack('!BBH', BACNET_BVLC_TYPE, function, total_len) + payload


# ---------------------------------------------------------------------------
# Who-Is / I-Am / Who-Is-Router
# ---------------------------------------------------------------------------

def build_whois(low: Optional[int] = None, high: Optional[int] = None,
                dnet: Optional[int] = None) -> bytes:
    """Build a Who-Is BVLC packet (Original-Broadcast-NPDU).

    If dnet is supplied, targets a specific BACnet network (for MSTP probing).
    If low/high supplied, filters by device instance range.
    """
    if dnet is not None:
        # NPDU: version, control(has-dest=1, expects-reply=0, priority=0),
        # DNET, DLEN=0 (broadcast), hop count
        npdu = bytearray([0x01, 0x20])
        npdu += struct.pack('!H', dnet)
        npdu += bytes([0x00, 0xFF])
    else:
        # Global broadcast: DNET=0xFFFF, DLEN=0
        npdu = bytearray([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])

    apdu = bytearray([0x10, 0x08])  # Unconfirmed-Request, service 8 = Who-Is
    if low is not None and high is not None:
        apdu += encode_context_unsigned(0, low)
        apdu += encode_context_unsigned(1, high)

    return build_bvlc(0x0B, bytes(npdu + apdu))  # 0x0B = Original-Broadcast-NPDU


def build_whois_router_to_network(dnet: Optional[int] = None) -> bytes:
    """Who-Is-Router-To-Network (NPDU network message type 0x00)."""
    if dnet is None:
        npdu = b'\x01\x80\x00'  # ver, control(network-msg=1), msg type 0
    else:
        npdu = b'\x01\x80\x00' + struct.pack('!H', dnet)
    return build_bvlc(0x0B, npdu)


def parse_iam(data: bytes, src_addr: tuple[str, int]) -> Optional[IAmDevice]:
    """Parse a received I-Am packet. Returns None if it isn't one."""
    try:
        if len(data) < 4 or data[0] != BACNET_BVLC_TYPE:
            return None
        idx = 4  # skip BVLC header

        # NPDU
        if idx + 2 > len(data) or data[idx] != 0x01:
            return None
        npdu_ctrl = data[idx + 1]
        idx += 2

        source_network = None
        source_address = None

        # Destination present
        if npdu_ctrl & 0x20:
            if idx + 3 > len(data):
                return None
            idx += 2  # DNET
            dlen = data[idx]
            idx += 1 + dlen

        # Source present
        if npdu_ctrl & 0x08:
            if idx + 3 > len(data):
                return None
            source_network = struct.unpack('!H', data[idx:idx + 2])[0]
            idx += 2
            slen = data[idx]
            idx += 1
            if slen > 0:
                if idx + slen > len(data):
                    return None
                sadr_bytes = data[idx:idx + slen]
                if slen == 1:
                    source_address = str(sadr_bytes[0])
                else:
                    source_address = ':'.join(f'{b:02X}' for b in sadr_bytes)
                idx += slen

        # Hop count byte if destination was present
        if npdu_ctrl & 0x20:
            if idx >= len(data):
                return None
            idx += 1

        # APDU must be Unconfirmed-Request (0x10) I-Am (service 0x00)
        if idx + 2 > len(data) or data[idx] != 0x10 or data[idx + 1] != 0x00:
            return None
        idx += 2

        # I-Am payload: object ID, max-APDU, segmentation, vendor-id
        # all application-tagged (tag class 0). We iterate rather than
        # assuming tag-byte sequences.
        device = IAmDevice(
            ip=src_addr[0],
            port=src_addr[1],
            instance=-1,
            source_network=source_network,
            source_address=source_address,
        )

        # Tag 12 = Object Identifier, application-class
        tag_num, tag_class, length, vstart, vend = _read_tag(data, idx)
        if tag_class != 0 or tag_num != 12 or length != 4:
            return None
        oid = struct.unpack('!I', data[vstart:vstart + 4])[0]
        device.instance = oid & 0x3FFFFF
        idx = vend

        # Tag 2 = Unsigned (max-APDU)
        tag_num, tag_class, length, vstart, vend = _read_tag(data, idx)
        if tag_class == 0 and tag_num == 2:
            device.max_apdu = int.from_bytes(data[vstart:vend], 'big')
            idx = vend
        else:
            return device  # truncated, still return what we have

        # Tag 9 = Enumerated (segmentation)
        tag_num, tag_class, length, vstart, vend = _read_tag(data, idx)
        if tag_class == 0 and tag_num == 9:
            seg_val = int.from_bytes(data[vstart:vend], 'big')
            seg_map = {0: "Both", 1: "Transmit", 2: "Receive", 3: "None"}
            device.segmentation = seg_map.get(seg_val, str(seg_val))
            idx = vend
        else:
            return device

        # Tag 2 = Unsigned (vendor-id)
        tag_num, tag_class, length, vstart, vend = _read_tag(data, idx)
        if tag_class == 0 and tag_num == 2:
            device.vendor_id = int.from_bytes(data[vstart:vend], 'big')

        return device if device.instance >= 0 else None

    except BACnetParseError:
        return None
    except (IndexError, struct.error):
        return None


def _extract_invoke_id(data: bytes) -> Optional[int]:
    """Extract the invoke-id byte from a Confirmed-ACK / Error / Reject packet.

    Returns None for packets that don't carry an invoke-id (I-Am broadcasts,
    COV notifications, Who-Is requests, etc.). Those are the packets we want
    to discard when waiting for a specific request's response on a shared socket.

    This is a lightweight prefix-walk — it doesn't fully parse the APDU, just
    skips past BVLC + NPDU to find the APDU header byte and extracts the
    invoke-id from the expected offset for each PDU type.
    """
    try:
        if len(data) < 4 or data[0] != BACNET_BVLC_TYPE:
            return None
        idx = 4  # skip BVLC

        # NPDU
        if idx + 2 > len(data) or data[idx] != 0x01:
            return None
        npdu_ctrl = data[idx + 1]
        idx += 2

        # Network-layer message (no APDU, no invoke-id)
        if npdu_ctrl & 0x80:
            return None

        # Skip optional destination
        if npdu_ctrl & 0x20:
            if idx + 3 > len(data):
                return None
            idx += 2
            dlen = data[idx]
            idx += 1 + dlen
        # Skip optional source
        if npdu_ctrl & 0x08:
            if idx + 3 > len(data):
                return None
            idx += 2
            slen = data[idx]
            idx += 1 + slen
        # Hop count if dest was present
        if npdu_ctrl & 0x20:
            idx += 1

        if idx >= len(data):
            return None

        pdu_type = (data[idx] >> 4) & 0x0F
        # PDU types that carry invoke-id: Confirmed-Request(0), Simple-ACK(2),
        # Complex-ACK(3), Segment-ACK(4), Error(5), Reject(6), Abort(7).
        # Unconfirmed-Request(1) doesn't — that's I-Am, Who-Is, UnconfirmedCOV, etc.
        if pdu_type == 1:
            return None

        # Invoke ID location depends on PDU type:
        # - Confirmed-Request: byte[2] (after pdu-type+flags, max-segs/apdu, then invoke)
        # - Simple-ACK / Complex-ACK / Error / Reject / Abort: byte[1] (pdu-type, then invoke)
        # - Segment-ACK: byte[1]
        if pdu_type == 0:  # Confirmed-Request
            if idx + 2 >= len(data):
                return None
            return data[idx + 2]
        # All ACK/Error/Reject/Abort types have invoke-id at idx+1
        if idx + 1 >= len(data):
            return None
        return data[idx + 1]
    except (IndexError, struct.error):
        return None


def parse_iam_router(data: bytes) -> Optional[list[int]]:
    """Parse I-Am-Router-To-Network. Returns list of reachable DNETs, or None."""
    try:
        if len(data) < 4 or data[0] != BACNET_BVLC_TYPE:
            return None
        idx = 4
        if idx + 2 > len(data) or data[idx] != 0x01:
            return None
        npdu_ctrl = data[idx + 1]
        idx += 2

        # Must be a network-layer message
        if not (npdu_ctrl & 0x80):
            return None

        # Skip SNET/SADR if source is present
        if npdu_ctrl & 0x08:
            if idx + 3 > len(data):
                return None
            idx += 2
            slen = data[idx]
            idx += 1 + slen

        if idx >= len(data):
            return None
        msg_type = data[idx]
        idx += 1

        # Message type 0x01 = I-Am-Router-To-Network
        if msg_type != 0x01:
            return None

        networks = []
        while idx + 1 < len(data):
            networks.append(struct.unpack('!H', data[idx:idx + 2])[0])
            idx += 2

        return networks or None
    except (BACnetParseError, IndexError, struct.error):
        return None


# ---------------------------------------------------------------------------
# ReadProperty
# ---------------------------------------------------------------------------

def build_read_property(obj_type: int | str, obj_instance: int,
                        prop_id: int | str,
                        array_index: Optional[int] = None,
                        invoke_id: int = 0,
                        max_apdu: int = 1476) -> bytes:
    """Build a complete Confirmed-Request ReadProperty BVLC packet.

    max_apdu encoded per ASHRAE 135-5.2.1.4: 0=50, 1=128, 2=206, 3=480, 4=1024, 5=1476.
    """
    max_apdu_code = {50: 0, 128: 1, 206: 2, 480: 3, 1024: 4}.get(max_apdu, 5)

    npdu = b'\x01\x04'  # version + expecting-reply

    # Confirmed-Request APDU header: PDU type 0, flags=0, max segments/APDU, invoke-id
    apdu = bytearray([
        0x00,                       # PDU type 0, SEG/MOR/SA flags=0
        max_apdu_code & 0x0F,       # max-segs=0 (none), max-apdu=code
        invoke_id & 0xFF,
        0x0C,                       # Service choice 12 = ReadProperty
    ])

    # Context tag 0: Object Identifier
    apdu += bytes([0x0C]) + encode_object_id(obj_type, obj_instance)

    # Context tag 1: Property Identifier (1 or 2 bytes)
    prop_val = resolve_property_id(prop_id)
    if prop_val < 0x100:
        apdu += bytes([0x19, prop_val])
    else:
        apdu += bytes([0x1A, (prop_val >> 8) & 0xFF, prop_val & 0xFF])

    # Context tag 2: Array Index (optional)
    if array_index is not None:
        if array_index < 0x100:
            apdu += bytes([0x29, array_index])
        elif array_index < 0x10000:
            apdu += bytes([0x2A, (array_index >> 8) & 0xFF, array_index & 0xFF])
        else:
            apdu += bytes([0x2C,
                           (array_index >> 24) & 0xFF,
                           (array_index >> 16) & 0xFF,
                           (array_index >> 8) & 0xFF,
                           array_index & 0xFF])

    return build_bvlc(0x0A, npdu + bytes(apdu))  # 0x0A = Original-Unicast-NPDU


def parse_read_property_ack(data: bytes) -> Any:
    """Parse a ReadProperty-ACK and return the decoded value.

    Returns None if the packet is an error response or can't be parsed.
    For lists (e.g. objectList without array_index) returns a Python list.
    """
    try:
        if len(data) < 4 or data[0] != BACNET_BVLC_TYPE:
            return None
        idx = 4  # skip BVLC

        # NPDU
        if idx + 2 > len(data) or data[idx] != 0x01:
            return None
        npdu_ctrl = data[idx + 1]
        idx += 2

        # Skip optional destination
        if npdu_ctrl & 0x20:
            idx += 2
            dlen = data[idx]
            idx += 1 + dlen
        # Skip optional source
        if npdu_ctrl & 0x08:
            idx += 2
            slen = data[idx]
            idx += 1 + slen
        # Hop count if dest was present
        if npdu_ctrl & 0x20:
            idx += 1

        if idx >= len(data):
            return None

        pdu_type = (data[idx] >> 4) & 0x0F

        # Simple-ACK (type 2) carries no value
        if pdu_type == 2:
            return None

        # Error / Reject / Abort (types 5, 6, 7)
        if pdu_type in (5, 6, 7):
            return None

        # Complex-ACK (type 3)
        if pdu_type != 3:
            return None

        idx += 1  # PDU type byte
        idx += 1  # invoke ID
        if idx >= len(data):
            return None
        service = data[idx]
        idx += 1
        if service != 0x0C:  # 12 = ReadProperty
            return None

        # Skip context tag 0 (Object Identifier)
        if idx < len(data) and (data[idx] & 0xF8) == 0x08:  # context class, tag 0
            idx = _skip_tag(data, idx)

        # Skip context tag 1 (Property Identifier)
        if idx < len(data) and (data[idx] & 0xF8) == 0x18:  # context class, tag 1
            idx = _skip_tag(data, idx)

        # Skip optional context tag 2 (Array Index)
        if idx < len(data) and (data[idx] & 0xF8) == 0x28:  # context class, tag 2
            idx = _skip_tag(data, idx)

        # Opening tag 3
        if idx >= len(data) or data[idx] != 0x3E:
            return None
        idx += 1

        # Collect application-tagged values until closing tag 3 (0x3F)
        values: list[Any] = []
        while idx < len(data) and data[idx] != 0x3F:
            val, idx = _parse_app_value(data, idx)
            values.append(val)

        if not values:
            return None
        return values[0] if len(values) == 1 else values

    except BACnetParseError:
        return None
    except (IndexError, struct.error):
        return None


def _parse_app_value(data: bytes, idx: int) -> tuple[Any, int]:
    """Parse a single application-tagged value. Returns (value, next_idx)."""
    tag_num, tag_class, length, vstart, vend = _read_tag(data, idx)

    if tag_class != 0:
        # Context tag inside opening/closing — unusual here, just skip
        if length in (6, 7):
            return None, vstart
        return data[vstart:vend].hex(), vend

    value_bytes = data[vstart:vend]

    if tag_num == 0:  # Null
        return None, vend
    if tag_num == 1:  # Boolean (value in length field for app-tagged)
        return bool(length), vend
    if tag_num == 2:  # Unsigned
        return int.from_bytes(value_bytes, 'big'), vend
    if tag_num == 3:  # Signed
        return int.from_bytes(value_bytes, 'big', signed=True), vend
    if tag_num == 4:  # Real
        if length == 4:
            return struct.unpack('!f', value_bytes)[0], vend
        return None, vend
    if tag_num == 5:  # Double
        if length == 8:
            return struct.unpack('!d', value_bytes)[0], vend
        return None, vend
    if tag_num == 6:  # Octet String
        return value_bytes.hex(), vend
    if tag_num == 7:  # Character String
        if length == 0:
            return "", vend
        encoding = value_bytes[0]
        text = value_bytes[1:]
        if encoding == 0:  # UTF-8
            return text.decode('utf-8', errors='replace'), vend
        if encoding == 4:  # UCS-2
            try:
                return text.decode('utf-16-be', errors='replace'), vend
            except Exception:
                return text.decode('latin-1', errors='replace'), vend
        return text.decode('latin-1', errors='replace'), vend
    if tag_num == 8:  # Bit String
        return value_bytes.hex(), vend
    if tag_num == 9:  # Enumerated
        return int.from_bytes(value_bytes, 'big'), vend
    if tag_num == 10:  # Date
        if length == 4:
            y, m, d, dow = value_bytes
            return f"{1900+y}-{m:02d}-{d:02d}", vend
        return value_bytes.hex(), vend
    if tag_num == 11:  # Time
        if length == 4:
            h, mm, s, hs = value_bytes
            return f"{h:02d}:{mm:02d}:{s:02d}.{hs:02d}", vend
        return value_bytes.hex(), vend
    if tag_num == 12:  # Object Identifier
        if length == 4:
            oid = struct.unpack('!I', value_bytes)[0]
            obj_type = (oid >> 22) & 0x3FF
            obj_inst = oid & 0x3FFFFF
            type_name = BACNET_OBJ_TYPES.get(obj_type, f"type-{obj_type}")
            return (type_name, obj_inst), vend

    return value_bytes.hex(), vend


# ---------------------------------------------------------------------------
# ReadPropertyMultiple
# ---------------------------------------------------------------------------

def build_read_property_multiple(obj_type: int | str, obj_instance: int,
                                 prop_ids: list[int | str],
                                 invoke_id: int = 0,
                                 max_apdu: int = 1476) -> bytes:
    """Build a ReadPropertyMultiple request for one object, multiple properties.

    This is a huge speedup vs ReadProperty: one round trip reads N properties.
    """
    max_apdu_code = {50: 0, 128: 1, 206: 2, 480: 3, 1024: 4}.get(max_apdu, 5)

    npdu = b'\x01\x04'
    apdu = bytearray([
        0x00,
        max_apdu_code & 0x0F,
        invoke_id & 0xFF,
        0x0E,  # Service choice 14 = ReadPropertyMultiple
    ])

    # Opening tag 0 (object identifier group)
    # Context tag 0 = object identifier (same as ReadProperty)
    apdu += bytes([0x0C]) + encode_object_id(obj_type, obj_instance)

    # Opening tag 1 (list of property references)
    apdu += bytes([0x1E])

    for prop_id in prop_ids:
        pval = resolve_property_id(prop_id)
        # Context tag 0 = property identifier (within listOfPropertyReferences)
        if pval < 0x100:
            apdu += bytes([0x09, pval])
        else:
            apdu += bytes([0x0A, (pval >> 8) & 0xFF, pval & 0xFF])

    # Closing tag 1
    apdu += bytes([0x1F])

    return build_bvlc(0x0A, npdu + bytes(apdu))


def parse_read_property_multiple_ack(data: bytes,
                                     prop_ids: list[int | str]) -> dict[int, Any]:
    """Parse a ReadPropertyMultiple-ACK. Returns {prop_id: value}.

    Missing or error-returned properties are omitted from the dict.
    prop_ids is the request order — used to correlate when the ACK omits
    property identifiers that match the request.
    """
    try:
        if len(data) < 4 or data[0] != BACNET_BVLC_TYPE:
            return {}
        idx = 4

        if idx + 2 > len(data) or data[idx] != 0x01:
            return {}
        npdu_ctrl = data[idx + 1]
        idx += 2

        if npdu_ctrl & 0x20:
            idx += 2
            dlen = data[idx]
            idx += 1 + dlen
        if npdu_ctrl & 0x08:
            idx += 2
            slen = data[idx]
            idx += 1 + slen
        if npdu_ctrl & 0x20:
            idx += 1

        if idx >= len(data):
            return {}

        if (data[idx] >> 4) != 3:  # not complex-ack
            return {}

        idx += 1  # pdu type
        idx += 1  # invoke id
        service = data[idx]
        idx += 1
        if service != 0x0E:
            return {}

        results: dict[int, Any] = {}

        # listOfReadAccessResults: repeating [object-id, opening-tag-1, results, closing-tag-1]
        while idx < len(data):
            # Context tag 0 = object identifier
            if (data[idx] & 0xF8) != 0x08:
                break
            idx = _skip_tag(data, idx)

            # Opening tag 1
            if idx >= len(data) or data[idx] != 0x1E:
                break
            idx += 1

            # Repeating property results until closing tag 1
            while idx < len(data) and data[idx] != 0x1F:
                # Context tag 2 = property identifier
                if (data[idx] & 0xF8) != 0x28:
                    break
                _, _, plen, pvstart, pvend = _read_tag(data, idx)
                prop_id = int.from_bytes(data[pvstart:pvend], 'big')
                idx = pvend

                # Optional context tag 3 = array index
                if idx < len(data) and (data[idx] & 0xF8) == 0x38:
                    idx = _skip_tag(data, idx)

                # Either opening tag 4 (propertyValue) or opening tag 5 (propertyAccessError)
                if idx >= len(data):
                    break

                if data[idx] == 0x4E:  # Opening tag 4
                    idx += 1
                    values: list[Any] = []
                    while idx < len(data) and data[idx] != 0x4F:
                        val, idx = _parse_app_value(data, idx)
                        values.append(val)
                    if idx < len(data) and data[idx] == 0x4F:
                        idx += 1  # closing tag 4
                    if values:
                        results[prop_id] = values[0] if len(values) == 1 else values
                elif data[idx] == 0x5E:  # Opening tag 5 (access error)
                    # Skip error class + error code then closing
                    idx += 1
                    while idx < len(data) and data[idx] != 0x5F:
                        idx = _skip_tag(data, idx)
                    if idx < len(data) and data[idx] == 0x5F:
                        idx += 1
                else:
                    # Unknown marker, bail out of this property
                    break

            # Closing tag 1
            if idx < len(data) and data[idx] == 0x1F:
                idx += 1
            else:
                break

        return results
    except BACnetParseError:
        return {}
    except (IndexError, struct.error):
        return {}
