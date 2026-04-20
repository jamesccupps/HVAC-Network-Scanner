"""
Device profiles — per-vendor/model tuning for BACnet object enumeration.

v2.1.2: The original scanner hardcoded a 500-object cap per device. That's
fine for small field controllers (Symbio, UC400, DXR2 room controllers —
they typically have 50-300 objects) but silently truncates on supervisory
controllers like the Trane Tracer SC+ (~3000-5000 mapped objects from
aggregated LonTalk / MSTP downstream devices).

Truncation is particularly bad on devices that enumerate by-type in array
order, because the user ends up with 500 Analog Inputs and no Binaries /
Multi-states / Analog Values. Found at OCC testing against a Tracer SC+.

This module provides:
- DeviceProfile dataclass describing per-device-class tuning.
- DEVICE_PROFILES lookup table seeded with verified entries.
- classify_device() which looks up the profile by (vendor_name, model_name)
  with heuristic fallback when we don't have an explicit entry.

Policy for adding entries to DEVICE_PROFILES:
- Only add entries that have been verified against real hardware. The
  heuristic fallback is the default for everything else. Guessing at caps
  across vendors we haven't tested would create silent mis-scans with
  false confidence, which is worse than the transparent fallback.
- Every entry includes a 'verified_at' note naming where/when it was
  validated, so future maintainers know which entries are solid.
- When promoting a device from heuristic to explicit profile, verify the
  cap is high enough that a real-world scan never hits it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class DeviceProfile:
    """Per-device-class tuning for BACnet enumeration.

    Currently just an object cap. Future fields (as testing surfaces the
    need) will cover RPM support quirks, response-reorder tolerance,
    segmented-ack handling, point-type skip lists, etc.
    """

    # Hard cap on object enumeration for this device class. Set high enough
    # that real-world scans of this device class never hit it; the whole
    # point is to avoid silent truncation.
    object_cap: int = 500

    # Label describing what this device is. Used in logs so users can see
    # why the scanner picked a particular cap.
    class_label: str = "unknown"

    # Short note on where/when this profile was verified, for maintenance.
    verified_at: str = ""


# --- Scan depth presets (maps to the Quick/Normal/Full dropdown) -----------

SCAN_DEPTH_PRESETS = {
    "quick":  {"multiplier": 0.05, "floor":   50, "label": "Quick (sample)"},
    "normal": {"multiplier": 1.00, "floor":  500, "label": "Normal (vendor-aware)"},
    "full":   {"multiplier": None, "floor":    0, "label": "Full (no cap)"},
}


# --- DEVICE_PROFILES: verified entries only --------------------------------
#
# Key: (vendor_name_exact, model_name_exact)
# Values: DeviceProfile
#
# Match is case-insensitive on both fields. Leave empty strings to be
# ignored by the lookup; partial matches handled separately in the
# classifier function below.

DEVICE_PROFILES: dict[tuple[str, str], DeviceProfile] = {
    # ------------------------------------------------------------------
    # Trane — verified against OCC Portland, 2026-04-20
    # ------------------------------------------------------------------
    # Tracer SC+ is a supervisory controller that aggregates LonTalk
    # downstream devices (~100 VAVs + AHUs in OCC's case) and exposes
    # them as mapped BACnet objects. Observed ~3000+ objects in practice.
    # Cap of 5000 gives meaningful headroom for larger sites.
    ("the trane company", "tracer sc+"): DeviceProfile(
        object_cap=5000,
        class_label="Trane supervisory (SC+)",
        verified_at="OCC Portland 2026-04-20",
    ),
    ("the trane company", "tracer sc"): DeviceProfile(
        object_cap=5000,
        class_label="Trane supervisory (SC)",
        verified_at="OCC Portland 2026-04-20",
    ),
    # Symbio 400/500/700/800 series — MSTP field controllers, not supervisory.
    # AC-4 at OCC enumerated ~90 objects across AI/AO/AV/BI/BO/BV/MSV.
    # Cap 500 is safe.
    ("the trane company", "symbio 400-500"): DeviceProfile(
        object_cap=500,
        class_label="Trane field (Symbio)",
        verified_at="OCC Portland 2026-04-20",
    ),
    ("the trane company", "symbio 700-800"): DeviceProfile(
        object_cap=500,
        class_label="Trane field (Symbio)",
        verified_at="OCC Portland 2026-04-20",
    ),
    # UC400, UC600 — older Trane controllers. Similar profile to Symbio.
    ("the trane company", "uc400"): DeviceProfile(
        object_cap=500,
        class_label="Trane field (UC400)",
        verified_at="OCC Portland 2026-04-20",
    ),
    ("the trane company", "uc600"): DeviceProfile(
        object_cap=500,
        class_label="Trane field (UC600)",
        verified_at="OCC Portland 2026-04-20",
    ),

    # ------------------------------------------------------------------
    # Siemens — verified against OCC Portland, 2026-04-20
    # ------------------------------------------------------------------
    # Vendor string per ASHRAE registry: "Siemens Schweiz AG" (Switzerland)
    # Real-world devices report it as "Siemens Schweiz" (short form) via
    # I-Am vendor_id=7. Field devices in BACnet/IP space report vendor_name
    # as "Siemens Building Technologies" in ReadProperty responses. The
    # vendor-substring match in classify_device() handles both.
    #
    # PXC Compact (EPXC firmware) / PXC Modular (PXME firmware) — field
    # panels. Both report modelName="Siemens BACnet Field Panel" on
    # BACnet/IP regardless of internal hardware class. Verified at OCC:
    #   - PXCC101000 (EPXC V3.5.2, Compact): 449 objects
    #   - OCCPXCM103000 (PXME V3.5.2, Modular, HV-1): 1,960 objects
    # Modular panels host substantially larger programs than Compact.
    # Cap 5000 accommodates real-world PXME panels with headroom for
    # larger installations; heuristic fallback applies for outliers.
    ("siemens schweiz", "siemens bacnet field panel"): DeviceProfile(
        object_cap=5000,
        class_label="Siemens field panel (PXC)",
        verified_at="OCC Portland 2026-04-20 (EPXC Compact 449 obj, PXME Modular 1960 obj verified; cap 5000 handles both with room)",
    ),
    # DXR2 room controllers (BACnet/IP). Small (100-200 objects). All
    # OCC-verified at firmware v01.21 / protocol revision 15. Observed:
    #   DXR2.E10PL-1: 164 objects   (standard room controller)
    #   DXR2.E12P-1:  181 objects   (P-series variant)
    #   DXR2.E18-1:   135 objects   (heat pump variant)
    ("siemens schweiz", "dxr2.e10pl-1"): DeviceProfile(
        object_cap=500,
        class_label="Siemens DXR2 room controller",
        verified_at="OCC Portland 2026-04-20",
    ),
    ("siemens schweiz", "dxr2.e18-1"): DeviceProfile(
        object_cap=500,
        class_label="Siemens DXR2 heat pump controller",
        verified_at="OCC Portland 2026-04-20",
    ),
    ("siemens schweiz", "dxr2.e12p-1"): DeviceProfile(
        object_cap=500,
        class_label="Siemens DXR2 bath controller",
        verified_at="OCC Portland 2026-04-20",
    ),
    # ------------------------------------------------------------------
    # Supervisor workstations — verified at OCC 2026-04-20
    # ------------------------------------------------------------------
    # These devices are BACnet supervisors/workstations that present
    # themselves on BACnet/IP but do NOT expose their aggregated point
    # database via objectList. Their BACnet objectList typically
    # contains only 1-2 objects (the Device object itself and possibly
    # a Notification Class). The real point data lives on downstream
    # field panels, which this scanner reaches directly on BACnet/IP or
    # via MSTP routing.
    #
    # For users scanning these IPs, the scanner correctly reports that
    # the supervisor exists without trying to enumerate points that
    # aren't there.

    # Desigo CC (Siemens supervisor) — OCC shows modelName="Desigo CC"
    # with 2-object objectList.
    ("siemens schweiz", "desigo cc"): DeviceProfile(
        object_cap=100,
        class_label="Siemens Desigo CC supervisor",
        verified_at="OCC Portland 2026-04-20 (2 objects in objectList)",
    ),
    # Desigo CC Insight (older branding / variant) — OCC shows
    # modelName="Insight" with 1-object objectList.
    ("siemens schweiz", "insight"): DeviceProfile(
        object_cap=100,
        class_label="Siemens Desigo CC supervisor (Insight)",
        verified_at="OCC Portland 2026-04-20 (1 object in objectList)",
    ),
    # Trane Tracer Ensemble (TES Workstation) — modelName="TES
    # Workstation", 1-object objectList. Notably rejects RPM and
    # requires per-property ReadProperty fallback, which the scanner
    # handles automatically.
    ("the trane company", "tes workstation"): DeviceProfile(
        object_cap=100,
        class_label="Trane Tracer Ensemble workstation",
        verified_at="OCC Portland 2026-04-20 (1 object in objectList; rejects RPM)",
    ),

    # ------------------------------------------------------------------
    # (Johnson Controls, Tridium, Honeywell, Schneider, etc.
    #  intentionally omitted — to be added after verification against
    #  real hardware. Unknown devices fall back to the heuristic below.)
    # ------------------------------------------------------------------
}


# --- Partial-match rules (for vendor/model variants) ------------------------
#
# Some vendors use consistent prefixes across many models (e.g. "Symbio" for
# a whole Trane field-controller family). Rather than enumerating every
# suffix, we check for these after exact match fails.

_VENDOR_MODEL_PREFIX_RULES = [
    # (vendor_substring, model_substring, profile)
    ("the trane company", "symbio",    DeviceProfile(
        object_cap=500,
        class_label="Trane field (Symbio family)",
        verified_at="OCC Portland 2026-04-20 (prefix rule)",
    )),
    ("the trane company", "tracer sc", DeviceProfile(
        object_cap=5000,
        class_label="Trane supervisory (Tracer family)",
        verified_at="OCC Portland 2026-04-20 (prefix rule)",
    )),
    # Siemens DXR2 family — any model starting with DXR2 is a room-level
    # field controller. Observed range at OCC: 135-181 objects across
    # E10PL-1, E12P-1, E18-1 variants. Cap 500 gives headroom for future
    # variants without opening the door to supervisory-class devices.
    ("siemens schweiz", "dxr2",        DeviceProfile(
        object_cap=500,
        class_label="Siemens DXR2 family (room controller)",
        verified_at="OCC Portland 2026-04-20 (prefix rule)",
    )),
    # Siemens PXC Compact / PXC Modular panels. The model string is
    # literally "Siemens BACnet Field Panel" regardless of whether the
    # underlying hardware is PXCC (Compact, EPXC firmware) or PXCM
    # (Modular, PXME firmware). Observed at OCC:
    #   - PXCC101000 (Compact): 449 objects
    #   - OCCPXCM103000 (Modular, HV-1): 1,960 objects
    ("siemens schweiz", "field panel", DeviceProfile(
        object_cap=5000,
        class_label="Siemens field panel (PXC)",
        verified_at="OCC Portland 2026-04-20 (prefix rule)",
    )),
]


# --- The public classifier function ----------------------------------------


def classify_device(
    vendor_name: Optional[str],
    model_name: Optional[str],
    object_list_count: Optional[int] = None,
) -> tuple[DeviceProfile, str]:
    """Return (profile, explanation) for a device.

    Lookup order:
      1. Exact (vendor, model) in DEVICE_PROFILES → verified profile
      2. Vendor-substring match against DEVICE_PROFILES (e.g. "Trane"
         matches "The Trane Company" entries)
      3. Partial-match rules (e.g. all Symbio variants)
      4. Heuristic based on object_list_count if provided
      5. Conservative default (cap 500, unknown class)

    Returns both the profile and a human-readable one-line explanation
    describing which rule matched. The explanation is logged to the scan
    log so users can see what classification the scanner applied.
    """
    v = (vendor_name or "").strip().lower()
    m = (model_name or "").strip().lower()

    # 1. Exact match
    if v and m and (v, m) in DEVICE_PROFILES:
        prof = DEVICE_PROFILES[(v, m)]
        return prof, (
            f"known device [{prof.class_label}] — cap {prof.object_cap}"
        )

    # 2. Vendor-substring match. Some devices report an abbreviated vendor
    #    name via ReadProperty (e.g. "Trane") while the ASHRAE registry
    #    records the full name ("The Trane Company"). Match either way.
    if v and m:
        for (pv, pm), prof in DEVICE_PROFILES.items():
            if m == pm and (pv in v or v in pv):
                return prof, (
                    f"vendor-substring match [{prof.class_label}] "
                    f"(device said '{vendor_name}') — cap {prof.object_cap}"
                )

    # 3. Prefix / substring rules
    for v_sub, m_sub, prof in _VENDOR_MODEL_PREFIX_RULES:
        if v_sub in v and m_sub in m:
            return prof, (
                f"matched rule [{prof.class_label}] — cap {prof.object_cap}"
            )

    # 4. Heuristic by object list size — no vendor knowledge needed.
    #    Picks a cap that guarantees we don't truncate, with round numbers
    #    to keep the log message readable.
    if object_list_count is not None:
        if object_list_count > 2000:
            cap = max(object_list_count + 100, 5000)
            return DeviceProfile(
                object_cap=cap,
                class_label=f"unknown supervisory ({vendor_name})",
                verified_at="heuristic by size",
            ), (
                f"heuristic [large, {object_list_count} objects] — cap {cap}"
            )
        if object_list_count > 500:
            cap = max(object_list_count + 50, 1500)
            return DeviceProfile(
                object_cap=cap,
                class_label=f"unknown mid-controller ({vendor_name})",
                verified_at="heuristic by size",
            ), (
                f"heuristic [mid, {object_list_count} objects] — cap {cap}"
            )
        # Small device: read all of it.
        cap = max(object_list_count + 10, 100)
        return DeviceProfile(
            object_cap=cap,
            class_label=f"unknown field ({vendor_name})",
            verified_at="heuristic by size",
        ), (
            f"heuristic [small, {object_list_count} objects] — cap {cap}"
        )

    # 5. No information at all — conservative default
    return DeviceProfile(
        object_cap=500,
        class_label="unknown",
        verified_at="default fallback",
    ), "no classification — conservative cap 500"


def apply_scan_depth(
    profile: DeviceProfile,
    scan_depth: str = "normal",
) -> tuple[DeviceProfile, str]:
    """Apply the Quick/Normal/Full dropdown to a classified profile.

    Quick: sample 5% of the cap (floor 50). Useful for fast inventory.
    Normal: honor the profile's verified cap.
    Full: no cap (reads everything).

    Returns the (possibly adjusted) profile and an explanation string.
    """
    preset = SCAN_DEPTH_PRESETS.get(scan_depth)
    if not preset:
        return profile, ""  # unknown depth → use profile as-is

    if preset["multiplier"] is None:
        # Full scan — effectively unlimited.
        return DeviceProfile(
            object_cap=10_000_000,
            class_label=profile.class_label,
            verified_at=profile.verified_at,
        ), "Full depth — no cap"

    mult = preset["multiplier"]
    floor = preset["floor"]
    if mult == 1.00:
        return profile, ""  # no adjustment needed for Normal

    adjusted_cap = max(floor, int(profile.object_cap * mult))
    return DeviceProfile(
        object_cap=adjusted_cap,
        class_label=profile.class_label,
        verified_at=profile.verified_at,
    ), f"{preset['label']} — cap {adjusted_cap} (from {profile.object_cap})"
