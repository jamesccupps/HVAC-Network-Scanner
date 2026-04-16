"""
BACnet codec tests.

Each test constructs a byte-accurate BACnet packet and runs it through the
parser/builder. These are the regression tests for the three parser bugs
identified in the v1 audit:

  Bug 1: ReadProperty ACK parser hardcoded context-tag skipping — broke on
         property IDs encoded with extended length.
  Bug 2: I-Am parser assumed positional tag order — broke on vendors that
         reorder application tags.
  Bug 3: No ReadPropertyMultiple support — now present and tested.

The packet bytes are constructed using the library's own builder where
possible, plus hand-constructed edge cases.
"""

import struct

import pytest

from hvac_scanner import codec


# ---------------------------------------------------------------------------
# Tag reader
# ---------------------------------------------------------------------------

class TestReadTag:
    def test_simple_application_tag(self):
        # Application tag 2 (unsigned), length 1, value 0x05
        data = bytes([0x21, 0x05])
        tag_num, tag_class, length, vstart, vend = codec._read_tag(data, 0)
        assert tag_num == 2
        assert tag_class == 0
        assert length == 1
        assert data[vstart:vend] == b"\x05"

    def test_context_tag(self):
        # Context tag 1 (class=1), length 2, value 0x01 0x2C (300)
        data = bytes([0x1A, 0x01, 0x2C])
        tag_num, tag_class, length, vstart, vend = codec._read_tag(data, 0)
        assert tag_num == 1
        assert tag_class == 1
        assert length == 2
        assert int.from_bytes(data[vstart:vend], "big") == 300

    def test_extended_tag_number(self):
        # Tag number 0xF means extended; next byte = real tag number
        # Context tag 200, length 1, value 0x01
        data = bytes([0xF9, 200, 0x01])
        tag_num, tag_class, length, _, _ = codec._read_tag(data, 0)
        assert tag_num == 200
        assert tag_class == 1
        assert length == 1

    def test_extended_length_u8(self):
        # Application tag 7 (char string), length=5 means extended,
        # next byte = real length (10)
        data = bytes([0x75, 10]) + b"0helloeeee"
        _, _, length, vstart, vend = codec._read_tag(data, 0)
        assert length == 10
        assert (vend - vstart) == 10

    def test_extended_length_u16(self):
        # length=5, ext=254 means u16 follows
        payload = b"A" * 300
        data = bytes([0x75, 254]) + struct.pack("!H", 300) + payload
        _, _, length, vstart, vend = codec._read_tag(data, 0)
        assert length == 300
        assert (vend - vstart) == 300

    def test_extended_length_u32(self):
        payload = b"B" * 100000
        data = bytes([0x75, 255]) + struct.pack("!I", 100000) + payload
        _, _, length, _, _ = codec._read_tag(data, 0)
        assert length == 100000

    def test_opening_tag(self):
        # Context tag 3, length=6 means opening tag
        data = bytes([0x3E, 0x21, 0x05])
        tag_num, tag_class, length, vstart, vend = codec._read_tag(data, 0)
        assert tag_num == 3
        assert tag_class == 1
        assert length == 6
        assert vstart == vend  # opening tags carry no value

    def test_read_past_eof_raises(self):
        with pytest.raises(codec.BACnetParseError):
            codec._read_tag(b"", 0)


# ---------------------------------------------------------------------------
# Object type / property ID resolution
# ---------------------------------------------------------------------------

class TestResolveObjectType:
    def test_display_name(self):
        assert codec.resolve_object_type("Analog Input") == 0
        assert codec.resolve_object_type("Device") == 8

    def test_camel_case(self):
        assert codec.resolve_object_type("analogInput") == 0
        assert codec.resolve_object_type("multiStateValue") == 19

    def test_type_n_fallback(self):
        assert codec.resolve_object_type("type-42") == 42

    def test_unknown_defaults_to_device(self):
        assert codec.resolve_object_type("nonexistent-type") == 8


class TestResolvePropertyId:
    def test_by_name(self):
        assert codec.resolve_property_id("presentValue") == 85
        assert codec.resolve_property_id("present-value") == 85
        assert codec.resolve_property_id("objectName") == 77

    def test_passthrough_int(self):
        assert codec.resolve_property_id(42) == 42


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

class TestEncodeContextUnsigned:
    def test_one_byte(self):
        assert codec.encode_context_unsigned(0, 5) == bytes([0x09, 0x05])

    def test_two_bytes(self):
        # 300 = 0x012C
        assert codec.encode_context_unsigned(1, 300) == bytes([0x1A, 0x01, 0x2C])

    def test_three_bytes(self):
        # 100000 = 0x0186A0
        assert codec.encode_context_unsigned(2, 100_000) == bytes([0x2B, 0x01, 0x86, 0xA0])


class TestEncodeObjectId:
    def test_device_object(self):
        # Device (type 8), instance 33333
        encoded = codec.encode_object_id(8, 33333)
        oid = struct.unpack("!I", encoded)[0]
        assert ((oid >> 22) & 0x3FF) == 8
        assert (oid & 0x3FFFFF) == 33333

    def test_analog_input(self):
        encoded = codec.encode_object_id("Analog Input", 1)
        oid = struct.unpack("!I", encoded)[0]
        assert ((oid >> 22) & 0x3FF) == 0
        assert (oid & 0x3FFFFF) == 1


# ---------------------------------------------------------------------------
# Who-Is / I-Am
# ---------------------------------------------------------------------------

class TestBuildWhois:
    def test_global_broadcast(self):
        pkt = codec.build_whois()
        assert pkt[0] == 0x81           # BVLC type
        assert pkt[1] == 0x0B           # original-broadcast-NPDU
        assert pkt[2:4] == b"\x00\x0c"  # total length
        # NPDU: ver, ctrl(0x20), DNET=0xFFFF, DLEN=0, hop
        assert pkt[4:10] == b"\x01\x20\xff\xff\x00\xff"
        # APDU: unconfirmed-request, Who-Is
        assert pkt[10:12] == b"\x10\x08"

    def test_range_filter(self):
        pkt = codec.build_whois(low=1000, high=2000)
        # Should include two context-tagged integers
        assert len(pkt) > 12
        # Tail should encode low=1000 as context tag 0 (0x0A 03 E8)
        # and high=2000 as context tag 1 (0x1A 07 D0) — 2 bytes each
        assert pkt[-6:] == bytes([0x0A, 0x03, 0xE8, 0x1A, 0x07, 0xD0])

    def test_dnet_broadcast(self):
        pkt = codec.build_whois(dnet=42)
        # NPDU control byte should have has-dest bit set
        assert pkt[5] & 0x20
        # DNET should be at offset 6-7
        assert struct.unpack("!H", pkt[6:8])[0] == 42


class TestParseIAm:
    def _build_iam(self, instance: int, max_apdu: int, seg: int, vendor: int,
                   source_network=None, source_address=None) -> bytes:
        """Build an I-Am packet the same way a real device would."""
        # NPDU: version 1, control=0 (no special fields)
        npdu_ctrl = 0
        npdu = bytearray([0x01])
        sadr_bytes = b""
        if source_network is not None:
            npdu_ctrl |= 0x08
            if isinstance(source_address, int):
                sadr_bytes = bytes([source_address])
            elif source_address is None:
                sadr_bytes = b""
        npdu.append(npdu_ctrl)
        if source_network is not None:
            npdu += struct.pack("!H", source_network)
            npdu += bytes([len(sadr_bytes)])
            npdu += sadr_bytes

        # APDU: unconfirmed-request, I-Am (service 0)
        apdu = bytearray([0x10, 0x00])
        # Object identifier (app tag 12, length 4)
        apdu.append(0xC4)
        apdu += codec.encode_object_id(8, instance)
        # Max APDU (app tag 2)
        if max_apdu < 256:
            apdu += bytes([0x21, max_apdu])
        else:
            apdu += bytes([0x22, (max_apdu >> 8) & 0xFF, max_apdu & 0xFF])
        # Segmentation (app tag 9, enumerated)
        apdu += bytes([0x91, seg])
        # Vendor ID (app tag 2, unsigned)
        if vendor < 256:
            apdu += bytes([0x21, vendor])
        else:
            apdu += bytes([0x22, (vendor >> 8) & 0xFF, vendor & 0xFF])

        payload = bytes(npdu) + bytes(apdu)
        return codec.build_bvlc(0x0A, payload)

    def test_parse_trane_tracer_iam(self):
        """Trane Tracer SC+: vendor 2, instance 33333, max_apdu 1024"""
        pkt = self._build_iam(instance=33333, max_apdu=1024, seg=3, vendor=2)
        device = codec.parse_iam(pkt, ("192.168.5.10", 47808))
        assert device is not None
        assert device.instance == 33333
        assert device.max_apdu == 1024
        assert device.segmentation == "None"
        assert device.vendor_id == 2

    def test_parse_siemens_desigo_iam(self):
        """Siemens Desigo PXC: vendor 7, instance 1000"""
        pkt = self._build_iam(instance=1000, max_apdu=1476, seg=0, vendor=7)
        device = codec.parse_iam(pkt, ("10.0.0.5", 47808))
        assert device.instance == 1000
        assert device.max_apdu == 1476
        assert device.segmentation == "Both"
        assert device.vendor_id == 7

    def test_parse_mstp_device_with_source(self):
        """JCI FEC behind an MSTP router: SNET=42, SADR=5"""
        pkt = self._build_iam(instance=40005, max_apdu=480, seg=3, vendor=5,
                              source_network=42, source_address=5)
        device = codec.parse_iam(pkt, ("192.168.5.1", 47808))
        assert device.source_network == 42
        assert device.source_address == "5"
        assert device.vendor_id == 5
        assert device.instance == 40005

    def test_parse_unsolicited_iam_not_a_valid_packet(self):
        assert codec.parse_iam(b"\x81\x0a\x00\x04", ("1.2.3.4", 47808)) is None
        assert codec.parse_iam(b"garbage", ("1.2.3.4", 47808)) is None


# ---------------------------------------------------------------------------
# ReadProperty
# ---------------------------------------------------------------------------

class TestBuildReadProperty:
    def test_simple_present_value(self):
        pkt = codec.build_read_property("Analog Input", 1, "presentValue")
        assert pkt[0] == 0x81
        assert pkt[1] == 0x0A  # original-unicast
        # APDU should contain service 0x0C (ReadProperty)
        assert 0x0C in pkt

    def test_with_array_index(self):
        pkt = codec.build_read_property("Device", 100, "objectList", array_index=0)
        # Array index 0 encoded as context tag 2, length 1, value 0
        assert bytes([0x29, 0x00]) in pkt

    def test_extended_property_id(self):
        # Property ID > 255 uses 2-byte form (context tag 1, length 2)
        pkt = codec.build_read_property("Device", 1, 500)
        # 500 = 0x01F4
        assert bytes([0x1A, 0x01, 0xF4]) in pkt


class TestParseReadPropertyAck:
    def _build_rp_ack(self, obj_type, obj_inst, prop_id, value_bytes: bytes) -> bytes:
        """Build a ReadProperty ACK with given value payload."""
        npdu = b"\x01\x00"
        apdu = bytearray([
            0x30, 0x00, 0x0C,  # complex-ack, invoke_id, service
        ])
        # Context tag 0 - Object Identifier
        apdu.append(0x0C)
        apdu += codec.encode_object_id(obj_type, obj_inst)
        # Context tag 1 - Property Identifier
        if prop_id < 256:
            apdu += bytes([0x19, prop_id])
        else:
            apdu += bytes([0x1A, (prop_id >> 8) & 0xFF, prop_id & 0xFF])
        # Opening tag 3
        apdu.append(0x3E)
        apdu += value_bytes
        # Closing tag 3
        apdu.append(0x3F)
        return codec.build_bvlc(0x0A, npdu + bytes(apdu))

    def test_parse_real_value(self):
        """Present value = 72.5 as IEEE 754 float"""
        value = bytes([0x44]) + struct.pack("!f", 72.5)  # app tag 4 (real), length 4
        pkt = self._build_rp_ack(0, 1, 85, value)
        result = codec.parse_read_property_ack(pkt)
        assert isinstance(result, float)
        assert abs(result - 72.5) < 0.001

    def test_parse_char_string_utf8(self):
        """Object name = 'ZN-T' in UTF-8"""
        text = b"ZN-T"
        # Tag 7 char string: length byte = 1 (encoding) + len(text)
        payload = bytes([0x75, 1 + len(text), 0x00]) + text
        pkt = self._build_rp_ack(0, 1, 77, payload)
        result = codec.parse_read_property_ack(pkt)
        assert result == "ZN-T"

    def test_parse_char_string_ucs2(self):
        text = "Zone".encode("utf-16-be")
        payload = bytes([0x75, 1 + len(text), 0x04]) + text
        pkt = self._build_rp_ack(0, 1, 77, payload)
        result = codec.parse_read_property_ack(pkt)
        assert result == "Zone"

    def test_parse_unsigned(self):
        value = bytes([0x21, 0x05])  # app tag 2, length 1, value 5
        pkt = self._build_rp_ack(8, 1000, 112, value)
        result = codec.parse_read_property_ack(pkt)
        assert result == 5

    def test_parse_object_identifier(self):
        """objectList element - returns (type_name, instance)"""
        oid = codec.encode_object_id("Analog Input", 42)
        value = bytes([0xC4]) + oid  # app tag 12, length 4
        pkt = self._build_rp_ack(8, 1, 76, value)
        result = codec.parse_read_property_ack(pkt)
        assert result == ("Analog Input", 42)

    def test_parse_extended_length_property_id(self):
        """Regression test for bug #1: parser broke on 2-byte property IDs."""
        value = bytes([0x21, 0x01])  # unsigned 1
        pkt = self._build_rp_ack(8, 1, 1500, value)  # prop ID > 255
        result = codec.parse_read_property_ack(pkt)
        assert result == 1

    def test_parse_with_array_index(self):
        """Optional context tag 2 (array index) should be skipped cleanly."""
        # Build the ACK with an array index tag between prop-id and opening-tag-3
        npdu = b"\x01\x00"
        apdu = bytearray([0x30, 0x00, 0x0C])
        apdu.append(0x0C)
        apdu += codec.encode_object_id(8, 1)
        apdu += bytes([0x19, 76])  # prop-id = objectList
        apdu += bytes([0x29, 5])   # array index = 5
        apdu.append(0x3E)
        apdu += bytes([0x21, 0x2A])  # unsigned 42
        apdu.append(0x3F)
        pkt = codec.build_bvlc(0x0A, npdu + bytes(apdu))
        result = codec.parse_read_property_ack(pkt)
        assert result == 42

    def test_parse_error_response_returns_none(self):
        """PDU type 5 (error) should parse as None."""
        npdu = b"\x01\x00"
        apdu = bytes([0x50, 0x00, 0x0C, 0x91, 0x00, 0x91, 0x00])  # error
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec.parse_read_property_ack(pkt) is None

    def test_parse_garbage_returns_none(self):
        assert codec.parse_read_property_ack(b"") is None
        assert codec.parse_read_property_ack(b"\x00\x00\x00\x00") is None
        assert codec.parse_read_property_ack(b"\x81\x0a") is None


# ---------------------------------------------------------------------------
# ReadPropertyMultiple (new in v2)
# ---------------------------------------------------------------------------

class TestReadPropertyMultiple:
    def test_build_request_structure(self):
        pkt = codec.build_read_property_multiple(
            "Device", 1000, ["objectName", "vendorName", "modelName"]
        )
        assert pkt[0] == 0x81
        # Service 0x0E = ReadPropertyMultiple
        assert 0x0E in pkt
        # Should have opening tag 1 (0x1E) and closing tag 1 (0x1F)
        assert 0x1E in pkt
        assert 0x1F in pkt

    def test_parse_rpm_ack(self):
        """Build and parse a round-trip RPM ACK with two properties."""
        npdu = b"\x01\x00"
        apdu = bytearray([0x30, 0x00, 0x0E])  # complex-ack, invoke, service 14

        # Context tag 0: object identifier
        apdu.append(0x0C)
        apdu += codec.encode_object_id(8, 1000)

        # Opening tag 1: listOfResults
        apdu.append(0x1E)

        # Prop 1: objectName = "DEV-1000"
        apdu += bytes([0x29, 77])  # context tag 2 (prop id) = 77
        apdu.append(0x4E)          # opening tag 4 (propertyValue)
        name = b"DEV-1000"
        apdu += bytes([0x75, 1 + len(name), 0x00]) + name
        apdu.append(0x4F)          # closing tag 4

        # Prop 2: vendorName = "Trane"
        apdu += bytes([0x29, 121])  # context tag 2, value 121
        apdu.append(0x4E)
        vendor = b"Trane"
        apdu += bytes([0x75, 1 + len(vendor), 0x00]) + vendor
        apdu.append(0x4F)

        # Closing tag 1
        apdu.append(0x1F)

        pkt = codec.build_bvlc(0x0A, npdu + bytes(apdu))
        result = codec.parse_read_property_multiple_ack(pkt, ["objectName", "vendorName"])
        assert 77 in result
        assert 121 in result
        assert result[77] == "DEV-1000"
        assert result[121] == "Trane"

    def test_parse_rpm_with_access_error(self):
        """If a property errors, it should be omitted from the result dict."""
        npdu = b"\x01\x00"
        apdu = bytearray([0x30, 0x00, 0x0E])
        apdu.append(0x0C)
        apdu += codec.encode_object_id(8, 1000)
        apdu.append(0x1E)  # opening tag 1

        # Good prop: objectName = "OK"
        apdu += bytes([0x29, 77])                         # ctx tag 2, prop id
        apdu.append(0x4E)                                 # opening tag 4
        apdu += bytes([0x75, 3, 0x00]) + b"OK"            # char string "OK"
        apdu.append(0x4F)                                 # closing tag 4

        # Errored prop: opening tag 5
        apdu += bytes([0x29, 121])
        apdu.append(0x5E)                                 # opening tag 5
        apdu += bytes([0x91, 0x02])                       # error class 2
        apdu += bytes([0x91, 0x20])                       # error code 32
        apdu.append(0x5F)                                 # closing tag 5

        apdu.append(0x1F)  # closing tag 1

        pkt = codec.build_bvlc(0x0A, npdu + bytes(apdu))
        result = codec.parse_read_property_multiple_ack(pkt, ["objectName", "vendorName"])
        assert 77 in result
        assert result[77] == "OK"
        assert 121 not in result

    def test_parse_rpm_empty_on_garbage(self):
        assert codec.parse_read_property_multiple_ack(b"", [77]) == {}
        assert codec.parse_read_property_multiple_ack(b"\x00" * 20, [77]) == {}


# ---------------------------------------------------------------------------
# Invoke ID extraction (v2.0.2 cross-request contamination fix)
# ---------------------------------------------------------------------------

class TestExtractInvokeId:
    def test_complex_ack_invoke_id(self):
        """Complex-ACK: invoke_id is byte[1] of APDU."""
        # Build a minimal Complex-ACK ReadProperty response
        npdu = b"\x01\x00"
        # APDU: 0x30 (complex-ack), invoke=0x42, service=0x0C, then padding
        apdu = bytes([0x30, 0x42, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x08])
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec._extract_invoke_id(pkt) == 0x42

    def test_simple_ack_invoke_id(self):
        """Simple-ACK: invoke_id is byte[1] of APDU."""
        npdu = b"\x01\x00"
        apdu = bytes([0x20, 0x7F, 0x0F])  # simple-ack, invoke 0x7F, service 15
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec._extract_invoke_id(pkt) == 0x7F

    def test_error_invoke_id(self):
        """Error (PDU type 5): invoke_id is byte[1] of APDU."""
        npdu = b"\x01\x00"
        apdu = bytes([0x50, 0x03, 0x0C, 0x91, 0x00, 0x91, 0x00])
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec._extract_invoke_id(pkt) == 0x03

    def test_reject_invoke_id(self):
        """Reject (PDU type 6): invoke_id is byte[1]."""
        npdu = b"\x01\x00"
        apdu = bytes([0x60, 0x09, 0x00])
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec._extract_invoke_id(pkt) == 0x09

    def test_confirmed_request_invoke_id(self):
        """Confirmed-Request: invoke_id is byte[2] (after max-segs/apdu byte)."""
        npdu = b"\x01\x04"
        apdu = bytes([0x00, 0x05, 0x55, 0x0C, 0x0C, 0x00, 0x00, 0x00, 0x08])
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec._extract_invoke_id(pkt) == 0x55

    def test_iam_broadcast_has_no_invoke_id(self):
        """I-Am is an Unconfirmed-Request (type 1) — no invoke id."""
        # Fake I-Am: global broadcast NPDU, unconfirmed-request, service 0
        npdu = b"\x01\x20\xff\xff\x00\xff"
        apdu = bytes([0x10, 0x00, 0xC4, 0x02, 0x00, 0x00, 0x05])
        pkt = codec.build_bvlc(0x0B, npdu + apdu)
        assert codec._extract_invoke_id(pkt) is None

    def test_whois_has_no_invoke_id(self):
        """Who-Is broadcast — no invoke id."""
        pkt = codec.build_whois()
        assert codec._extract_invoke_id(pkt) is None

    def test_network_layer_message_has_no_invoke_id(self):
        """Who-Is-Router-To-Network — network layer, no APDU."""
        pkt = codec.build_whois_router_to_network()
        assert codec._extract_invoke_id(pkt) is None

    def test_garbage_returns_none(self):
        assert codec._extract_invoke_id(b"") is None
        assert codec._extract_invoke_id(b"\x00") is None
        assert codec._extract_invoke_id(b"garbage") is None

    def test_with_source_address_in_npdu(self):
        """When NPDU has source info, invoke_id extraction must still land correctly."""
        # NPDU with source network + address present (control byte 0x08)
        npdu = b"\x01\x08" + b"\x00\x2A\x01\x05"  # SNET=42, SLEN=1, SADR=5
        apdu = bytes([0x30, 0x77, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x08])
        pkt = codec.build_bvlc(0x0A, npdu + apdu)
        assert codec._extract_invoke_id(pkt) == 0x77
