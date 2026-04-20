"""v2.1.1: verify POINT_PROPERTIES_BY_TYPE doesn't ask garbage questions.

The v2.0.x / v2.1.0 scanner asked every property of every object, flooding
logs with 'unknown property' errors for binary points (no units), calendars
(no present value), and similar type-mismatched reads. This test is a
regression guard: it asserts binary/multi-state types don't request units,
and that every listed property actually exists in PROP_IDS.
"""
from __future__ import annotations

import pytest

from hvac_scanner.constants import (
    POINT_PROPERTIES_BY_TYPE,
    PROP_IDS,
    DEFAULT_POINT_PROPERTIES,
)


class TestPropertyMapSanity:
    def test_every_property_exists(self):
        """Every property name listed must resolve to a PROP_IDS entry."""
        for obj_type, props in POINT_PROPERTIES_BY_TYPE.items():
            for prop in props:
                assert prop in PROP_IDS, (
                    f"{obj_type}: '{prop}' not in PROP_IDS — typo or missing entry"
                )

    def test_default_properties_also_valid(self):
        """Fallback default must also resolve against PROP_IDS."""
        for prop in DEFAULT_POINT_PROPERTIES:
            assert prop in PROP_IDS


class TestBinaryPointsDontAskUnits:
    """Binary objects have no 'units' property. Asking for it yields
    'unknown property' errors and wastes a round-trip."""

    @pytest.mark.parametrize("obj_type", [
        "Binary Input", "Binary Output", "Binary Value",
        "Binary Lighting Output",
    ])
    def test_binary_no_units(self, obj_type):
        props = POINT_PROPERTIES_BY_TYPE[obj_type]
        assert "units" not in props


class TestMultiStatePointsDontAskUnits:
    @pytest.mark.parametrize("obj_type", [
        "Multi-State Input", "Multi-State Output", "Multi-State Value",
    ])
    def test_multistate_no_units(self, obj_type):
        props = POINT_PROPERTIES_BY_TYPE[obj_type]
        assert "units" not in props


class TestAnalogPointsAskUnits:
    """Analog-family objects DO have units — they should be asked."""

    @pytest.mark.parametrize("obj_type", [
        "Analog Input", "Analog Output", "Analog Value",
        "Loop", "Accumulator", "Pulse Converter", "Averaging",
    ])
    def test_analog_asks_units(self, obj_type):
        props = POINT_PROPERTIES_BY_TYPE[obj_type]
        assert "units" in props


class TestNavigationalObjectsDontAskPresentValue:
    """Objects that have no presentValue (Group, NetworkPort, etc.)
    should not request one."""

    @pytest.mark.parametrize("obj_type", [
        "Group", "Global Group", "Network Port", "Elevator Group",
        "Escalator", "Event Enrollment", "Channel", "Command",
    ])
    def test_no_present_value_request(self, obj_type):
        props = POINT_PROPERTIES_BY_TYPE[obj_type]
        assert "presentValue" not in props, (
            f"{obj_type} has no presentValue — shouldn't ask for it"
        )


class TestVendorRegistryGrew:
    """v2.1.1 regenerated BACNET_VENDORS from the official registry.
    Previous table stopped around vendor 800. Current table covers many
    more — this guards against anyone regressing the table by trimming it."""

    def test_has_meaningful_size(self):
        from hvac_scanner.constants import BACNET_VENDORS
        assert len(BACNET_VENDORS) >= 500, (
            "BACNET_VENDORS looks truncated — did someone trim the registry?"
        )

    def test_common_vendors_resolved(self):
        """Sample check: common BAS vendors must resolve to non-numeric names."""
        from hvac_scanner.constants import BACNET_VENDORS
        # IDs that OldAutomator's '>100 shows as number' complaint was about
        critical_ids = {
            245: "Contemporary",  # Contemporary Control Systems (BASRT-B)
            332: "Distech",       # Distech Controls (OCC)
            389: "Chipkin",       # CAS gateways (widely deployed)
            423: "BELIMO",        # Belimo Automation
            502: "EasyIO",        # EasyIO (popular on Niagara)
            545: "AAON",          # AAON rooftop units
        }
        for vid, must_contain in critical_ids.items():
            got = BACNET_VENDORS.get(vid, "")
            assert must_contain.lower() in got.lower(), (
                f"Vendor {vid}: got {got!r}, expected something with "
                f"{must_contain!r}"
            )
