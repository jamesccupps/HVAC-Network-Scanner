"""v2.1.2: test the device profile classifier.

Devices should be classified based on vendor+model; unknown devices fall
back to a size-based heuristic; the Quick/Normal/Full dropdown adjusts the
cap on top of the profile's base cap.
"""
from __future__ import annotations

from hvac_scanner.device_profiles import (
    DeviceProfile,
    DEVICE_PROFILES,
    classify_device,
    apply_scan_depth,
)


class TestExactMatch:
    def test_trane_tracer_sc_plus(self):
        prof, explanation = classify_device("The Trane Company", "Tracer SC+", 3000)
        assert prof.object_cap >= 3000  # Must not truncate observed real device
        assert "Trane supervisory" in prof.class_label
        assert "known device" in explanation.lower()

    def test_trane_symbio(self):
        prof, explanation = classify_device("The Trane Company", "Symbio 400-500", 90)
        assert prof.object_cap >= 100
        assert prof.object_cap <= 1000  # Field controller — don't over-cap
        assert "Trane field" in prof.class_label

    def test_case_insensitive(self):
        # Vendor names come back in whatever case the device uses; our
        # lookup must not care.
        a, _ = classify_device("the trane company", "tracer sc+", 3000)
        b, _ = classify_device("THE TRANE COMPANY", "TRACER SC+", 3000)
        c, _ = classify_device("The Trane Company", "Tracer SC+", 3000)
        assert a.object_cap == b.object_cap == c.object_cap


class TestVendorSubstringMatch:
    """Regression: OCC field test showed a Trane SC+ reports its own
    vendor_name property as 'Trane' (short form) via ReadProperty, while
    the ASHRAE vendor registry records it as 'The Trane Company'. Our
    classifier must match either one to the same profile."""

    def test_short_vendor_name_still_matches(self):
        prof_short, explanation_short = classify_device("Trane", "Tracer SC+", 5000)
        prof_full, _ = classify_device("The Trane Company", "Tracer SC+", 5000)
        assert prof_short.object_cap == prof_full.object_cap, (
            f"'Trane' gave cap {prof_short.object_cap} but "
            f"'The Trane Company' gave cap {prof_full.object_cap}"
        )
        # The log message should indicate it was a substring match
        assert ("substring" in explanation_short.lower()
                or "known device" in explanation_short.lower())

    def test_uppercase_short_vendor(self):
        prof, _ = classify_device("TRANE", "Tracer SC+", 5000)
        assert prof.object_cap >= 5000

    def test_trane_inc(self):
        # Some older firmware may report 'Trane Inc.'
        prof, _ = classify_device("Trane Inc.", "Tracer SC+", 5000)
        assert prof.object_cap >= 5000


class TestPrefixRule:
    def test_symbio_family_match(self):
        """Models like 'Symbio 700' should match the Symbio prefix rule
        even if there's no exact entry."""
        prof, explanation = classify_device(
            "The Trane Company", "Symbio 800 Plus Something", 150
        )
        assert prof.object_cap >= 100
        # Exact match exists for 'Symbio 700-800' but not 'Symbio 800 Plus' —
        # so should land on a rule or heuristic and still be sensible.
        assert prof.object_cap <= 2000


class TestHeuristicFallback:
    def test_unknown_supervisory(self):
        """Device with 3000 objects, unknown vendor → treat as supervisory."""
        prof, explanation = classify_device("Unknown Vendor", "Model-X", 3000)
        assert prof.object_cap >= 3000
        assert "heuristic" in explanation.lower()

    def test_unknown_mid_controller(self):
        prof, explanation = classify_device("Unknown Vendor", "Model-Y", 700)
        assert prof.object_cap >= 700
        assert prof.object_cap <= 2000

    def test_unknown_field_controller(self):
        prof, explanation = classify_device("Unknown Vendor", "Model-Z", 50)
        assert prof.object_cap >= 50
        assert prof.object_cap <= 200

    def test_no_info_at_all(self):
        prof, explanation = classify_device(None, None, None)
        assert prof.object_cap > 0
        assert "default" in explanation.lower() or "no classification" in explanation.lower()


class TestScanDepth:
    def test_normal_is_unchanged(self):
        base = DeviceProfile(object_cap=5000, class_label="test")
        adjusted, _note = apply_scan_depth(base, "normal")
        assert adjusted.object_cap == 5000

    def test_quick_shrinks_cap(self):
        base = DeviceProfile(object_cap=5000, class_label="test")
        adjusted, note = apply_scan_depth(base, "quick")
        assert adjusted.object_cap < 5000
        assert adjusted.object_cap >= 50  # floor
        assert "Quick" in note

    def test_quick_floor_protects_small_devices(self):
        # 5% of 500 is 25, but floor is 50
        base = DeviceProfile(object_cap=500, class_label="test")
        adjusted, _ = apply_scan_depth(base, "quick")
        assert adjusted.object_cap >= 50

    def test_full_removes_cap(self):
        base = DeviceProfile(object_cap=500, class_label="test")
        adjusted, note = apply_scan_depth(base, "full")
        assert adjusted.object_cap >= 1_000_000  # effectively unlimited
        assert "Full" in note or "no cap" in note.lower()

    def test_unknown_depth_returns_unchanged(self):
        base = DeviceProfile(object_cap=500, class_label="test")
        adjusted, note = apply_scan_depth(base, "nonsense")
        assert adjusted.object_cap == 500


class TestOCCRegression:
    """Verify the specific Trane SC+ scenario that triggered this feature."""

    def test_sc_plus_with_3000_objects_doesnt_truncate(self):
        """Real SC+ at OCC has ~3000 objects. Cap must accommodate."""
        prof, _ = classify_device("The Trane Company", "Tracer SC+", 3000)
        assert prof.object_cap >= 3000, (
            f"SC+ cap {prof.object_cap} is below observed 3000 objects"
        )

    def test_symbio_with_90_objects_reads_all(self):
        """Symbio 400-500 at OCC has ~90 objects. Cap should be >= 100."""
        prof, _ = classify_device("The Trane Company", "Symbio 400-500", 90)
        assert prof.object_cap >= 100


class TestSiemensOCCRegression:
    """Verify Siemens profiles match the objects observed at OCC."""

    def test_dxr2_e10pl_1(self):
        """OCC DXR2.E10PL-1 (OCC_RM1007): 164 objects observed."""
        prof, explanation = classify_device("Siemens Schweiz", "DXR2.E10PL-1", 164)
        assert prof.object_cap >= 164, f"DXR2 cap {prof.object_cap} < observed 164"
        assert prof.object_cap <= 1000, "DXR2 should not be supervisory-class"
        assert "siemens" in prof.class_label.lower() or "dxr2" in prof.class_label.lower()

    def test_dxr2_e18_1(self):
        """OCC DXR2.E18-1 (OCC_RM1014_HP): 135 objects observed."""
        prof, _ = classify_device("Siemens Schweiz", "DXR2.E18-1", 135)
        assert prof.object_cap >= 135
        assert prof.object_cap <= 1000

    def test_dxr2_e12p_1(self):
        """OCC DXR2.E12P-1 (OCC_BATH_RM1054): 181 objects observed."""
        prof, _ = classify_device("Siemens Schweiz", "DXR2.E12P-1", 181)
        assert prof.object_cap >= 181
        assert prof.object_cap <= 1000

    def test_dxr2_family_prefix_for_unknown_variant(self):
        """An unknown DXR2 variant (e.g. 'DXR2.X99-42') should still
        match the DXR2 family prefix rule, not fall to heuristic."""
        prof, explanation = classify_device("Siemens Schweiz", "DXR2.X99-42", 150)
        assert prof.object_cap >= 150
        # Should have matched a rule/family, not fallen to heuristic
        assert "heuristic" not in explanation.lower() or prof.object_cap >= 500

    def test_pxc_field_panel(self):
        """OCC PXCC101000: Siemens BACnet Field Panel, 449 objects observed."""
        prof, _ = classify_device("Siemens Schweiz", "Siemens BACnet Field Panel", 449)
        assert prof.object_cap >= 449

    def test_pxme_modular_panel(self):
        """OCC OCCPXCM103000 (HV-1 PXME Modular): 1960 objects observed.
        Regression: ensure cap handles real PXME Modular sizes without
        silent truncation. If this fails because cap dropped below 2000,
        a silent truncation bug was reintroduced."""
        prof, _ = classify_device("Siemens Schweiz", "Siemens BACnet Field Panel", 1960)
        assert prof.object_cap >= 1960, (
            f"PXME Modular cap {prof.object_cap} below observed 1960 -- "
            f"silent truncation risk"
        )

    def test_siemens_vendor_substring_tolerance(self):
        """Some firmware may report 'Siemens' alone or 'Siemens Schweiz AG'
        (Swiss legal entity name with AG suffix). Must still classify."""
        # Short form
        prof_short, _ = classify_device("Siemens", "DXR2.E10PL-1", 164)
        assert prof_short.object_cap >= 164, "short-form Siemens should still classify"
        # Full legal name
        prof_full, _ = classify_device("Siemens Schweiz AG", "DXR2.E10PL-1", 164)
        assert prof_full.object_cap >= 164


class TestSupervisorDevices:
    """Verified at OCC 2026-04-20: supervisors present BACnet/IP but
    don't expose aggregated points via objectList. Cap is small on
    purpose — reflects what the device actually returns."""

    def test_desigo_cc_supervisor(self):
        prof, _ = classify_device("Siemens Schweiz", "Desigo CC", 2)
        assert prof.object_cap >= 2
        assert "desigo cc" in prof.class_label.lower()

    def test_desigo_cc_insight(self):
        prof, _ = classify_device("Siemens Schweiz", "Insight", 1)
        assert prof.object_cap >= 1
        assert "insight" in prof.class_label.lower() or "desigo" in prof.class_label.lower()

    def test_tracer_ensemble(self):
        prof, _ = classify_device("The Trane Company", "TES Workstation", 1)
        assert prof.object_cap >= 1
        assert "tracer ensemble" in prof.class_label.lower() or "trane" in prof.class_label.lower()


class TestTable:
    """Sanity checks on the DEVICE_PROFILES table itself."""

    def test_every_entry_has_verified_at(self):
        """Every explicit entry must declare where it was verified."""
        for key, prof in DEVICE_PROFILES.items():
            assert prof.verified_at, (
                f"Entry {key} has no verified_at — must not be "
                f"added without real hardware testing."
            )

    def test_every_entry_has_class_label(self):
        for key, prof in DEVICE_PROFILES.items():
            assert prof.class_label and prof.class_label != "unknown", (
                f"Entry {key} must have a class_label"
            )

    def test_every_cap_is_positive(self):
        for key, prof in DEVICE_PROFILES.items():
            assert prof.object_cap > 0, f"Entry {key} has invalid cap"
