"""Tests for v2.1.0 MSTP routing fix and chunked Who-Is.

The v2.0.x `build_read_property` hardcoded NPDU `0x01 0x04` — version plus
expecting-reply flag, no destination specifier. This worked for IP devices
but caused every MSTP device behind a router to respond with "Object not
found" because the router processed the packet as addressed to itself.

Fix in v2.1.0: accept `dnet` and `dadr` arguments that emit a properly
routed NPDU: `0x01 0x24 <DNET-H> <DLEN> <DADR> 0xFF`. Credit to
OldAutomator on r/BuildingAutomation for the Yabe-vs-ours sniff analysis
that located the bug.
"""

import struct
from unittest.mock import MagicMock

import pytest

from hvac_scanner import bacnet, codec


# ---------------------------------------------------------------------------
# DADR encoding
# ---------------------------------------------------------------------------

class TestEncodeDadr:
    """Cover all shapes `parse_iam` produces for `source_address`."""

    def test_int_becomes_single_byte(self):
        assert codec._encode_dadr(5) == bytes([5])
        assert codec._encode_dadr(255) == bytes([255])
        # Masked to a byte — higher ints are silently truncated
        assert codec._encode_dadr(0x1FF) == bytes([0xFF])

    def test_decimal_string_mstp_mac(self):
        """parse_iam stores MSTP MACs as decimal strings like "5"."""
        assert codec._encode_dadr("5") == bytes([5])
        assert codec._encode_dadr("42") == bytes([42])
        assert codec._encode_dadr("255") == bytes([255])

    def test_hex_colon_bacnet_ip_address(self):
        """parse_iam stores longer SADRs as "AA:BB:CC:DD:EE:FF"."""
        result = codec._encode_dadr("C0:A8:01:0A:BA:C0")
        assert result == bytes([0xC0, 0xA8, 0x01, 0x0A, 0xBA, 0xC0])
        assert len(result) == 6  # IP (4) + port (2)

    def test_passes_through_bytes(self):
        assert codec._encode_dadr(b"\x01\x02\x03") == b"\x01\x02\x03"

    def test_none_returns_empty(self):
        assert codec._encode_dadr(None) == b""

    def test_empty_string_returns_empty(self):
        assert codec._encode_dadr("") == b""
        assert codec._encode_dadr("   ") == b""

    def test_invalid_string_returns_empty(self):
        # Garbage that's neither decimal nor hex-colon
        assert codec._encode_dadr("not-a-mac") == b""


# ---------------------------------------------------------------------------
# NPDU builder
# ---------------------------------------------------------------------------

class TestBuildNpdu:
    def test_unrouted_expecting_reply(self):
        """Default local NPDU: just version + control=0x04."""
        assert codec.build_npdu(expecting_reply=True) == bytes([0x01, 0x04])

    def test_unrouted_no_reply(self):
        assert codec.build_npdu(expecting_reply=False) == bytes([0x01, 0x00])

    def test_routed_to_mstp_device(self):
        """The v2.1.0 payoff — DNET + DLEN + DADR + hop-count."""
        npdu = codec.build_npdu(expecting_reply=True, dnet=42, dadr="5")
        # Layout: 0x01 | 0x24 | DNET-H(2) | DLEN(1) | DADR(DLEN) | hop(1)
        assert npdu == bytes([0x01, 0x24, 0x00, 42, 0x01, 5, 0xFF])
        # Control byte has BOTH destination-specifier AND expecting-reply
        assert npdu[1] & 0x20, "dest-specifier bit not set"
        assert npdu[1] & 0x04, "expecting-reply bit not set"

    def test_routed_broadcast_on_remote_network(self):
        """DNET set, DADR None: broadcast on that remote network (DLEN=0)."""
        npdu = codec.build_npdu(expecting_reply=False, dnet=42)
        assert npdu == bytes([0x01, 0x20, 0x00, 42, 0x00, 0xFF])
        # Control has dest-specifier but NOT expecting-reply
        assert npdu[1] & 0x20
        assert not (npdu[1] & 0x04)

    def test_routed_global_broadcast(self):
        """DNET=0xFFFF = broadcast to all networks. Used by Who-Is."""
        npdu = codec.build_npdu(expecting_reply=False, dnet=0xFFFF)
        assert npdu == bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])

    def test_multi_byte_dadr(self):
        """Routed IP over IP (unusual but legal): 6-byte DADR."""
        npdu = codec.build_npdu(dnet=100, dadr="C0:A8:01:0A:BA:C0")
        # Layout: 0x01 | 0x24 | 00 64 | 06 | C0 A8 01 0A BA C0 | FF
        assert npdu[0] == 0x01
        assert npdu[1] == 0x24
        assert npdu[2:4] == b"\x00\x64"
        assert npdu[4] == 0x06
        assert npdu[5:11] == bytes([0xC0, 0xA8, 0x01, 0x0A, 0xBA, 0xC0])
        assert npdu[11] == 0xFF


# ---------------------------------------------------------------------------
# build_read_property with routing
# ---------------------------------------------------------------------------

class TestReadPropertyRouted:
    def test_unrouted_matches_v2_0_behavior(self):
        """Backwards compatible: no dnet/dadr → no routing overhead."""
        pkt = codec.build_read_property("Analog Input", 1, "presentValue")
        # NPDU starts at offset 4 (after BVLC)
        assert pkt[4:6] == b"\x01\x04"

    def test_mstp_routed_emits_expected_npdu(self):
        """The exact fix: control byte 0x24 + DNET + DLEN=1 + DADR + hop."""
        pkt = codec.build_read_property(
            "Analog Input", 42, "presentValue",
            dnet=103, dadr="1",  # matches OCC: JCI FEC at MSTP net 103, MAC 1
        )
        # NPDU layout after BVLC (4 bytes)
        # 0x01 0x24 00 67 01 01 FF  (DNET=103=0x67, DLEN=1, DADR=1, hop=255)
        assert pkt[4] == 0x01         # version
        assert pkt[5] == 0x24         # dest + expecting-reply
        assert pkt[6:8] == b"\x00\x67"  # DNET = 103
        assert pkt[8] == 0x01         # DLEN
        assert pkt[9] == 0x01         # DADR
        assert pkt[10] == 0xFF        # hop count

    def test_extended_property_id_still_works_when_routed(self):
        """Regression: property IDs > 255 must still encode correctly
        after the NPDU change."""
        pkt = codec.build_read_property(
            "Device", 1, 1500,  # prop id > 255
            dnet=42, dadr="5",
        )
        # 2-byte property ID encoded as context tag 1 length 2
        assert bytes([0x1A, 0x05, 0xDC]) in pkt  # 1500 = 0x05DC


class TestReadPropertyMultipleRouted:
    def test_unrouted_matches_existing_behavior(self):
        pkt = codec.build_read_property_multiple(
            "Device", 1, ["objectName", "vendorName"]
        )
        assert pkt[4:6] == b"\x01\x04"

    def test_routed_rpm_has_destination_specifier(self):
        pkt = codec.build_read_property_multiple(
            "Device", 42, ["objectName"], dnet=103, dadr="1",
        )
        assert pkt[5] & 0x20  # dest-specifier
        assert pkt[5] & 0x04  # expecting-reply
        assert pkt[6:8] == b"\x00\x67"  # DNET = 103
        # Service 14 (RPM) still in the packet
        assert 0x0E in pkt


# ---------------------------------------------------------------------------
# Who-Is refactor backwards compatibility
# ---------------------------------------------------------------------------

class TestWhoisStillWorks:
    """The Who-Is builder was refactored to use build_npdu. Make sure the
    wire output is unchanged from v2.0.x."""

    def test_global_whois_unchanged(self):
        pkt = codec.build_whois()
        # BVLC header + NPDU + APDU = same bytes as v2.0.x
        assert pkt[0] == 0x81
        assert pkt[1] == 0x0B  # original-broadcast-NPDU
        # NPDU: 01 20 FF FF 00 FF
        assert pkt[4:10] == b"\x01\x20\xff\xff\x00\xff"
        # APDU: 10 08 (Unconfirmed-Request Who-Is)
        assert pkt[10:12] == b"\x10\x08"

    def test_dnet_whois_unchanged(self):
        pkt = codec.build_whois(dnet=42)
        # NPDU: 01 20 00 2A 00 FF
        assert pkt[4:10] == b"\x01\x20\x00\x2a\x00\xff"

    def test_range_filter_unchanged(self):
        pkt = codec.build_whois(low=1000, high=2000)
        # Tail still has context-tagged instance range
        assert pkt[-6:] == bytes([0x0A, 0x03, 0xE8, 0x1A, 0x07, 0xD0])


# ---------------------------------------------------------------------------
# End-to-end: BACnetClient read_property with MSTP routing
# ---------------------------------------------------------------------------

def _make_rp_ack_with_source(invoke_id: int, value_float: float,
                             snet: int, sadr_mac: int) -> bytes:
    """Build a ReadProperty-ACK that carries source-routing info back —
    what a real router emits when it forwards a response from an MSTP
    device back to the IP requester.

    NPDU control = 0x08 (source-present), then SNET (2) + SLEN (1) + SADR.
    """
    npdu = bytearray([0x01, 0x08])
    npdu += struct.pack("!H", snet)
    npdu += bytes([0x01, sadr_mac])  # SLEN=1, SADR=mac

    apdu = bytearray([
        0x30, invoke_id, 0x0C,       # complex-ack, invoke, ReadProperty
        0x0C, 0x00, 0x00, 0x00, 0x08,  # object id
        0x19, 0x55,                   # prop id 85 (presentValue)
        0x3E,                         # opening tag 3
        0x44, *struct.pack("!f", value_float),  # real value
        0x3F,                         # closing tag 3
    ])
    return codec.build_bvlc(0x0A, bytes(npdu) + bytes(apdu))


def _mock_client_with_sends(packet_queue):
    client = bacnet.BACnetClient(timeout=0.5)
    client._sock = MagicMock()
    client._sock.gettimeout.return_value = 0.5
    client._sock.recvfrom = MagicMock(side_effect=packet_queue)
    client._invoke_id = 0  # pin so first call produces invoke_id=1
    return client


def test_read_property_sends_routed_packet_to_mstp_device():
    """Sanity check the whole stack: read_property with dnet/dadr should
    emit a packet whose NPDU carries the destination specifier."""
    client = _mock_client_with_sends([
        (_make_rp_ack_with_source(1, 72.5, snet=103, sadr_mac=1),
         ('10.0.0.192', 47808)),
    ])
    result = client.read_property(
        '10.0.0.192', 'Analog Input', 29, 'presentValue',
        dnet=103, dadr='1',
    )
    assert result == 72.5

    # Verify the packet we sent had the routed NPDU
    sendto_args = client._sock.sendto.call_args_list
    assert len(sendto_args) == 1
    sent_pkt = sendto_args[0].args[0]
    # Check NPDU control byte (offset 5 in the full packet)
    assert sent_pkt[5] == 0x24, "NPDU should have dest-specifier + expecting-reply"
    # DNET should be 103 (0x67)
    assert sent_pkt[6:8] == b"\x00\x67"


def test_read_property_without_routing_emits_local_npdu():
    """No dnet/dadr = no routing overhead, same packet shape as v2.0.x."""
    # Build a response that doesn't have source routing (IP device direct)
    response = codec.build_bvlc(0x0A, b"\x01\x00" + bytes([
        0x30, 0x01, 0x0C,
        0x0C, 0x00, 0x00, 0x00, 0x08,
        0x19, 0x55,
        0x3E, 0x44, *struct.pack("!f", 72.5), 0x3F,
    ]))
    client = _mock_client_with_sends([(response, ('10.0.0.19', 47808))])
    result = client.read_property('10.0.0.19', 'Analog Input', 29, 'presentValue')
    assert result == 72.5
    sent_pkt = client._sock.sendto.call_args_list[0].args[0]
    # NPDU is just version + 0x04, no routing fields
    assert sent_pkt[4:6] == b"\x01\x04"


def test_engine_threads_source_network_to_deep_read():
    """engine._deep_read must pull source_network/source_address off the dev
    dict and pass them to the client. Regression against v2.0.2 which called
    read_device_info/read_object_list/read_point_properties without routing
    args even for MSTP devices."""
    from hvac_scanner.engine import ScanEngine, ScanOptions

    engine = ScanEngine(ScanOptions(networks=["10.0.0.0/24"]))
    mock_client = MagicMock()
    mock_client.read_device_info.return_value = {'model_name': 'FEC'}
    mock_client.read_object_list.return_value = []

    # Simulate an MSTP device discovered behind the BASRT-B router
    dev = {
        'ip': '10.0.0.192',         # router's IP
        'instance': 103001,
        'source_network': 103,
        'source_address': '1',
        'protocol': 'BACnet/MSTP',
    }

    engine._deep_read(mock_client, dev)

    # Verify every client call got the routing info
    assert mock_client.read_device_info.called
    dev_kwargs = mock_client.read_device_info.call_args.kwargs
    assert dev_kwargs.get('dnet') == 103
    assert dev_kwargs.get('dadr') == '1'

    ol_kwargs = mock_client.read_object_list.call_args.kwargs
    assert ol_kwargs.get('dnet') == 103
    assert ol_kwargs.get('dadr') == '1'


def test_engine_omits_routing_for_ip_direct_device():
    """IP-direct devices shouldn't get DNET/DADR — that would make the
    NPDU larger for no reason and could confuse some controllers."""
    from hvac_scanner.engine import ScanEngine, ScanOptions

    engine = ScanEngine(ScanOptions(networks=["10.0.0.0/24"]))
    mock_client = MagicMock()
    mock_client.read_device_info.return_value = {}
    mock_client.read_object_list.return_value = []

    dev = {
        'ip': '10.0.0.19',
        'instance': 33333,
        'protocol': 'BACnet/IP',
        # no source_network, no source_address
    }

    engine._deep_read(mock_client, dev)

    dev_kwargs = mock_client.read_device_info.call_args.kwargs
    assert dev_kwargs.get('dnet') is None
    assert dev_kwargs.get('dadr') is None


# ---------------------------------------------------------------------------
# Chunked Who-Is
# ---------------------------------------------------------------------------

class TestChunkedWhois:
    def test_default_mode_single_broadcast(self):
        """chunk=0 means one Who-Is, no range filter — v2.0.x behavior."""
        from hvac_scanner.engine import ScanEngine, ScanOptions

        engine = ScanEngine(ScanOptions(networks=["10.0.0.0/24"]))
        mock_client = MagicMock()
        mock_client.discover_who_is.return_value = [{'ip': '10.0.0.19', 'instance': 33333}]

        result = engine._discover_whois_on(mock_client, "10.0.0.255")

        assert len(result) == 1
        # One call, no low/high
        assert mock_client.discover_who_is.call_count == 1
        kwargs = mock_client.discover_who_is.call_args.kwargs
        assert 'low' not in kwargs
        assert 'high' not in kwargs

    def test_chunked_splits_instance_range(self):
        """chunk=1000 with max=5000 covers 0-999, 1000-1999, ... 5000-5000.
        That's 6 chunks, and the upper bound is hit before the 10-empty
        early-stop triggers."""
        from hvac_scanner.engine import ScanEngine, ScanOptions

        opts = ScanOptions(
            networks=["10.0.0.0/24"],
            whois_chunk_size=1000,
            whois_max_instance=5000,
            whois_chunk_delay_ms=0,  # no sleep in tests
        )
        engine = ScanEngine(opts)
        mock_client = MagicMock()
        mock_client.discover_who_is.return_value = []

        engine._discover_whois_on(mock_client, "10.0.0.255")

        # 0-999, 1000-1999, 2000-2999, 3000-3999, 4000-4999, 5000-5000 = 6
        assert mock_client.discover_who_is.call_count == 6

    def test_chunked_early_stop_after_empty_streak(self):
        """If 10 chunks return zero new devices, bail out to avoid scanning
        the whole 4M instance space on a small site."""
        from hvac_scanner.engine import ScanEngine, ScanOptions

        opts = ScanOptions(
            networks=["10.0.0.0/24"],
            whois_chunk_size=1000,
            whois_max_instance=4_194_303,  # full BACnet range
            whois_chunk_delay_ms=0,
        )
        engine = ScanEngine(opts)
        mock_client = MagicMock()
        mock_client.discover_who_is.return_value = []

        engine._discover_whois_on(mock_client, "10.0.0.255")

        # Should stop at 10 consecutive empties, not scan all 4195 chunks
        assert mock_client.discover_who_is.call_count == 10

    def test_chunked_resets_streak_on_new_device(self):
        """A hit in chunk N resets the empty streak counter so we don't
        stop in a sparse instance range."""
        from hvac_scanner.engine import ScanEngine, ScanOptions

        opts = ScanOptions(
            networks=["10.0.0.0/24"],
            whois_chunk_size=1000,
            whois_max_instance=20_000,
            whois_chunk_delay_ms=0,
        )
        engine = ScanEngine(opts)
        mock_client = MagicMock()

        # Respond with one device on every 5th chunk. That's 4 empty, 1 hit,
        # 4 empty, 1 hit — streak never reaches 10.
        responses = []
        for chunk_num in range(21):  # 20000 / 1000 = 20 chunks
            if chunk_num % 5 == 0:
                responses.append([{'ip': f'10.0.0.{chunk_num+1}',
                                  'instance': chunk_num * 1000}])
            else:
                responses.append([])
        mock_client.discover_who_is.side_effect = responses

        result = engine._discover_whois_on(mock_client, "10.0.0.255")

        # Should have scanned the full range — no 10-empty run
        assert mock_client.discover_who_is.call_count >= 20
        # And accumulated the devices from every 5th chunk
        assert len(result) >= 4

    def test_chunked_deduplicates_across_chunks(self):
        """A device responding to multiple chunks (shouldn't happen with the
        instance filter, but some misbehaved devices respond to any Who-Is)
        is de-duplicated by (ip, instance)."""
        from hvac_scanner.engine import ScanEngine, ScanOptions

        opts = ScanOptions(
            networks=["10.0.0.0/24"],
            whois_chunk_size=1000,
            whois_max_instance=3000,
            whois_chunk_delay_ms=0,
        )
        engine = ScanEngine(opts)
        mock_client = MagicMock()
        # Same device replies to every chunk
        mock_client.discover_who_is.return_value = [
            {'ip': '10.0.0.5', 'instance': 500},
        ]

        result = engine._discover_whois_on(mock_client, "10.0.0.255")

        assert len(result) == 1
