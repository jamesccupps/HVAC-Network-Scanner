"""Tests for v2.1.2 target range parser.

Previously the scanner only accepted CIDR. Users asked for "scan hosts 2-100"
without computing CIDR in their head, and the OCC test revealed that a /26
CIDR gets broadcast_address=10.0.0.63 which is NOT a real Ethernet broadcast
on a physical /24 subnet (silent Who-Is failure). This parser decouples
"which hosts to probe" from "which broadcast address to use."
"""
from __future__ import annotations

import pytest

from hvac_scanner.netrange import parse_targets, InvalidTargetSyntaxError


class TestCIDR:
    def test_slash_24(self):
        hosts = parse_targets("10.0.0.0/24")
        assert len(hosts) == 254  # excludes .0 and .255
        assert hosts[0] == "10.0.0.1"
        assert hosts[-1] == "10.0.0.254"

    def test_slash_26(self):
        hosts = parse_targets("10.0.0.0/26")
        assert len(hosts) == 62   # excludes .0 and .63
        assert hosts[0] == "10.0.0.1"
        assert hosts[-1] == "10.0.0.62"

    def test_slash_32_single_host(self):
        """/32 hosts() returns empty per RFC; we treat it as 'just this host'."""
        hosts = parse_targets("10.0.0.5/32")
        assert hosts == ["10.0.0.5"]

    def test_slash_30(self):
        """/30 has 2 usable hosts"""
        hosts = parse_targets("10.0.0.0/30")
        assert hosts == ["10.0.0.1", "10.0.0.2"]


class TestSingleHost:
    def test_single_ip(self):
        assert parse_targets("10.0.0.5") == ["10.0.0.5"]

    def test_single_ip_with_whitespace(self):
        assert parse_targets("  10.0.0.5  ") == ["10.0.0.5"]


class TestShortRange:
    """Short range: 10.0.0.2-100 means last octet varies."""

    def test_basic_short_range(self):
        hosts = parse_targets("10.0.0.2-10")
        assert hosts == [f"10.0.0.{i}" for i in range(2, 11)]

    def test_short_range_spans_99(self):
        hosts = parse_targets("10.0.0.2-100")
        assert len(hosts) == 99
        assert hosts[0] == "10.0.0.2"
        assert hosts[-1] == "10.0.0.100"

    def test_short_range_single(self):
        """X-X should produce [X]"""
        hosts = parse_targets("10.0.0.50-50")
        assert hosts == ["10.0.0.50"]

    def test_short_range_whole_octet(self):
        hosts = parse_targets("10.0.0.0-255")
        assert len(hosts) == 256
        assert hosts[0] == "10.0.0.0"
        assert hosts[-1] == "10.0.0.255"


class TestFullRange:
    """Full range: 10.0.0.2-10.0.0.100"""

    def test_basic_full_range(self):
        hosts = parse_targets("10.0.0.2-10.0.0.10")
        assert hosts == [f"10.0.0.{i}" for i in range(2, 11)]

    def test_full_range_crosses_octet(self):
        """10.0.0.250-10.0.1.5 spans octet boundary"""
        hosts = parse_targets("10.0.0.250-10.0.1.5")
        assert hosts[0] == "10.0.0.250"
        assert "10.0.0.255" in hosts
        assert "10.0.1.0" in hosts
        assert hosts[-1] == "10.0.1.5"
        assert len(hosts) == 6 + 6  # .250-.255 + .0-.5


class TestList:
    def test_comma_separated(self):
        hosts = parse_targets("10.0.0.5, 10.0.1.5, 10.0.2.5")
        assert hosts == ["10.0.0.5", "10.0.1.5", "10.0.2.5"]

    def test_whitespace_separated(self):
        hosts = parse_targets("10.0.0.5 10.0.1.5 10.0.2.5")
        assert hosts == ["10.0.0.5", "10.0.1.5", "10.0.2.5"]

    def test_mixed_cidr_single_range(self):
        hosts = parse_targets("10.0.0.0/30, 10.0.1.5, 10.0.2.10-12")
        # /30 → .1, .2 ; single → .1.5 ; range → .2.10, .2.11, .2.12
        assert hosts == [
            "10.0.0.1", "10.0.0.2",
            "10.0.1.5",
            "10.0.2.10", "10.0.2.11", "10.0.2.12",
        ]


class TestDeduplication:
    def test_overlapping_cidr_and_range_dedupe(self):
        """If two tokens cover the same IP, output only once."""
        hosts = parse_targets("10.0.0.0/30, 10.0.0.1-2")
        # /30 → .1, .2 ; range → .1, .2 → deduped
        assert hosts == ["10.0.0.1", "10.0.0.2"]

    def test_duplicate_single_ips_dedupe(self):
        assert parse_targets("10.0.0.5, 10.0.0.5, 10.0.0.5") == ["10.0.0.5"]


class TestErrors:
    def test_reversed_short_range(self):
        with pytest.raises(InvalidTargetSyntaxError, match="less than"):
            parse_targets("10.0.0.100-10")

    def test_reversed_full_range(self):
        with pytest.raises(InvalidTargetSyntaxError, match="less than"):
            parse_targets("10.0.0.100-10.0.0.10")

    def test_octet_out_of_range(self):
        with pytest.raises(InvalidTargetSyntaxError):
            parse_targets("10.0.0.5-300")

    def test_bad_cidr(self):
        with pytest.raises(InvalidTargetSyntaxError, match="bad CIDR"):
            parse_targets("10.0.0.0/99")

    def test_nonsense(self):
        with pytest.raises(InvalidTargetSyntaxError, match="unrecognized"):
            parse_targets("not an ip")

    def test_oversized_range_rejected(self):
        """A 17-bit span (>65536 hosts) is refused to avoid typo OOM."""
        with pytest.raises(InvalidTargetSyntaxError, match="spans more than"):
            parse_targets("10.0.0.0-10.2.0.0")


class TestIterableInput:
    def test_list_input(self):
        hosts = parse_targets(["10.0.0.5", "10.0.1.5"])
        assert hosts == ["10.0.0.5", "10.0.1.5"]

    def test_empty_input(self):
        assert parse_targets("") == []
        assert parse_targets([]) == []
        assert parse_targets("   ") == []


class TestOCCRegression:
    """The scenario that actually broke on OCC: user typed 10.0.0.0/26
    expecting to scan the first 64 IPs of their /24 network. Result: zero
    BACnet devices because broadcast_address=10.0.0.63 isn't a real
    Ethernet broadcast on /24. In v2.1.2 the user can instead type a
    range and the parser produces the list directly."""

    def test_first_half_by_range(self):
        hosts = parse_targets("10.0.0.1-63")
        assert len(hosts) == 63
        assert "10.0.0.1" in hosts
        assert "10.0.0.63" in hosts
        assert "10.0.0.64" not in hosts

    def test_specific_devices_only(self):
        """User wants SC-1, SC-2, and the BASRT-B — nothing else."""
        hosts = parse_targets("10.0.0.19, 10.0.0.21, 10.0.0.192")
        assert hosts == ["10.0.0.19", "10.0.0.21", "10.0.0.192"]
