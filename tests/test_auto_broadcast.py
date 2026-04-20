"""v2.1.2: test the auto-broadcast heuristic.

User enters a target; engine figures out the right Who-Is broadcast address
without ever asking the user. The rule:

  /24 or wider CIDR      → its own broadcast_address
  /25–/31 CIDR           → enclosing /24 broadcast
  /32 single host        → enclosing /24 broadcast
  range in one /24       → that /24 broadcast
  range spanning /24s    → 255.255.255.255 limited broadcast
  non-parseable target   → 255.255.255.255 limited broadcast

Regression tests guard against future edits that reintroduce the silent
'scan found nothing because broadcast went to unicast' failure mode.
"""
from __future__ import annotations

import pytest

from hvac_scanner.engine import ScanEngine, ScanOptions


@pytest.fixture
def engine():
    """Engine with no stop event and a no-op log callback for silent tests."""
    opts = ScanOptions(networks=[], timeout=1.0)
    return ScanEngine(opts, callback=lambda _m: None)


class TestWiderThan24:
    def test_slash_24(self, engine):
        assert engine._bcast_for("10.0.0.0/24") == "10.0.0.255"

    def test_slash_22(self, engine):
        # /22 covers 10.0.0.0-10.0.3.255, broadcast = 10.0.3.255
        assert engine._bcast_for("10.0.0.0/22") == "10.0.3.255"

    def test_slash_16(self, engine):
        assert engine._bcast_for("10.0.0.0/16") == "10.0.255.255"


class TestNarrowerThan24:
    """The bug case: narrow CIDR on a physical /24 produces unicast-to-nobody
    if you use the narrow CIDR's own broadcast. Heuristic routes to the
    enclosing /24 instead."""

    def test_slash_26(self, engine):
        # /26 covers 10.0.0.0-10.0.0.63. Own broadcast is 10.0.0.63 (bad).
        # Enclosing /24 broadcast is 10.0.0.255.
        assert engine._bcast_for("10.0.0.0/26") == "10.0.0.255"

    def test_slash_26_not_aligned_to_24(self, engine):
        # /26 at 10.0.0.64 — also lives inside 10.0.0.0/24
        assert engine._bcast_for("10.0.0.64/26") == "10.0.0.255"

    def test_slash_28(self, engine):
        assert engine._bcast_for("10.0.0.0/28") == "10.0.0.255"

    def test_slash_25_upper_half(self, engine):
        # 10.0.0.128/25 still in 10.0.0.0/24
        assert engine._bcast_for("10.0.0.128/25") == "10.0.0.255"


class TestSingleHost:
    def test_slash_32(self, engine):
        assert engine._bcast_for("10.0.0.5/32") == "10.0.0.255"

    def test_bare_ip(self, engine):
        # Bare IP isn't a CIDR but netrange parses it
        assert engine._bcast_for("10.0.0.5") == "10.0.0.255"


class TestRangeInOneSubnet:
    def test_short_range(self, engine):
        assert engine._bcast_for("10.0.0.2-100") == "10.0.0.255"

    def test_full_range_same_subnet(self, engine):
        assert engine._bcast_for("10.0.0.2-10.0.0.12") == "10.0.0.255"

    def test_list_of_hosts_same_subnet(self, engine):
        assert engine._bcast_for("10.0.0.19, 10.0.0.21, 10.0.0.192") == "10.0.0.255"


class TestRangeAcrossSubnets:
    def test_range_crosses_24(self, engine):
        # 10.0.0.250-10.0.1.5 spans two /24s → limited broadcast
        assert engine._bcast_for("10.0.0.250-10.0.1.5") == "255.255.255.255"

    def test_list_from_different_subnets(self, engine):
        assert engine._bcast_for("10.0.0.5, 10.0.1.5") == "255.255.255.255"


class TestExplicitOverride:
    def test_override_wins(self):
        opts = ScanOptions(networks=[], bacnet_broadcast="192.168.1.255")
        engine = ScanEngine(opts, callback=lambda _m: None)
        # Override beats everything, including the auto-heuristic.
        assert engine._bcast_for("10.0.0.0/24") == "192.168.1.255"
        assert engine._bcast_for("10.0.0.0/26") == "192.168.1.255"
        assert engine._bcast_for("10.0.0.5") == "192.168.1.255"


class TestOCCRegression:
    """The specific scan that failed silently in v2.1.1: 10.0.0.0/26 on a
    physical 10.0.0.0/24. Scanner sent Who-Is to 10.0.0.63 (unicast to
    nobody), zero I-Ams, zero devices reported. In v2.1.2 the same target
    auto-broadcasts to 10.0.0.255 and works."""

    def test_occ_narrow_cidr_now_broadcasts_correctly(self, engine):
        assert engine._bcast_for("10.0.0.0/26") == "10.0.0.255"

    def test_occ_specific_device_list(self, engine):
        # User wants SC-1, SC-2, BASRT-B only; all in 10.0.0.0/24
        assert engine._bcast_for("10.0.0.19, 10.0.0.21, 10.0.0.192") == "10.0.0.255"


class TestBadInput:
    def test_garbage_falls_back_to_limited_broadcast(self, engine):
        assert engine._bcast_for("not an ip") == "255.255.255.255"
