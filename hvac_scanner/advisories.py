"""
Published security advisories for the firmware devices report about
themselves.

Each entry comes from a CISA ICS advisory, read from CISA's own CSAF data
(github.com/cisagov/CSAF), and names: the products it covers (matched on
the vendor and model a device reports), which reported property holds the
version, and the version the advisory says to update to (None when the
advisory gives no fixed version). Nothing here is inferred.

A device is compared only when its reported version can be: one that is
older than the fix is "affected"; one whose version is too short to tell
(a DXR2 reports "v01.21" while the fix is 01.21.142.5-22) is "check"; an
advisory with no fixed version covers every version it lists. The scanner
does not test for the vulnerabilities themselves.

Data as of 2026-11-06. Add an advisory by adding an entry, with its source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

_VERSION = re.compile(r"(\d+(?:\.\d+)+)")


@dataclass(frozen=True)
class Advisory:
    id: str                       # CISA ICS advisory
    published: str
    title: str
    vendor: str                   # substring of the reported vendor name (lowercase)
    model: str                    # regex on the reported model name
    field: str                    # property holding the version
    fixed: Optional[str]          # the version the advisory says to update to; None: no fix
    cves: tuple[str, ...]
    cvss: float                   # highest CVSS v3 base score in the advisory
    firmware: str = ""            # regex the version property must also match (product line)
    note: str = ""

    @property
    def url(self) -> str:
        return f"https://www.cisa.gov/news-events/ics-advisories/{self.id.lower()}"


ADVISORIES: tuple[Advisory, ...] = (
    # Trane. ICSA-26-071-01 lists Tracer SC+ before v6.3.2310 as affected
    # and names v6.30.2313 as the version to upgrade to; the scanner uses
    # the named fix. CVE-2026-28255 and -28256 are mitigated by Trane, not
    # by a version.
    Advisory("ICSA-26-071-01", "2026-03-12", "Trane Tracer SC, Tracer SC+, and Tracer Concierge",
             "trane", r"^tracer sc\+$", "application_software_version", "6.30.2313",
             ("CVE-2026-28252", "CVE-2026-28253", "CVE-2026-28254", "CVE-2026-28255",
              "CVE-2026-28256"), 8.1,
             note="CVE-2026-28255 and CVE-2026-28256 are mitigated by Trane, not by a version"),
    Advisory("ICSA-26-071-01", "2026-03-12", "Trane Tracer SC, Tracer SC+, and Tracer Concierge",
             "trane", r"^tracer sc$", "application_software_version", None,
             ("CVE-2026-28252", "CVE-2026-28253", "CVE-2026-28254", "CVE-2026-28255",
              "CVE-2026-28256"), 8.1,
             note="affected before v4.4_SP7: compare the reported version by hand"),

    # Siemens APOGEE PXC Compact (EPXC) and Modular (PXME) on BACnet firmware.
    Advisory("ICSA-22-349-16", "2022-12-13", "Siemens APOGEE and TALON",
             "siemens", r"^siemens bacnet field panel$", "firmware_revision", "3.5.5",
             ("CVE-2020-15795", "CVE-2020-27009", "CVE-2020-27736", "CVE-2020-27737",
              "CVE-2020-27738", "CVE-2020-28388", "CVE-2021-25677", "CVE-2022-45937"), 8.8,
             firmware=r"^(PXME|EPXC)\b"),
    Advisory("ICSA-22-286-12", "2022-10-11", "Siemens APOGEE, TALON and Desigo PXC/PXM Products",
             "siemens", r"^siemens bacnet field panel$", "firmware_revision", "3.5.7",
             ("CVE-2022-38371",), 7.5, firmware=r"^(PXME|EPXC)\b"),
    Advisory("ICSA-26-295-08", "2026-10-13", "Siemens APOGEE, TALON and Desigo PXC/PXM Products",
             "siemens", r"^siemens bacnet field panel$", "firmware_revision", "3.5.7",
             ("CVE-2026-102073", "CVE-2026-102074", "CVE-2026-102075", "CVE-2026-102076"), 8.2,
             firmware=r"^(PXME|EPXC)\b"),
    Advisory("ICSA-25-044-11", "2025-02-11", "Siemens APOGEE PXC100 Devices",
             "siemens", r"^siemens bacnet field panel$", "firmware_revision", None,
             ("CVE-2024-54089", "CVE-2024-54090"), 7.5, firmware=r"^(PXME|EPXC)\b",
             note="all versions; no fixed version, mitigations in the advisory"),
    Advisory("ICSA-25-135-14", "2025-05-13", "Siemens APOGEE PXC and TALON TC Series",
             "siemens", r"^siemens bacnet field panel$", "firmware_revision", None,
             ("CVE-2025-40555",), 4.7, firmware=r"^(PXME|EPXC)\b",
             note="all versions; no fixed version, mitigations in the advisory"),
    Advisory("ICSA-25-254-05", "2025-09-09", "Siemens Apogee PXC and Talon TC Devices",
             "siemens", r"^siemens bacnet field panel$", "firmware_revision", None,
             ("CVE-2025-40757",), 5.3, firmware=r"^(PXME|EPXC)\b",
             note="all versions; no fixed version, mitigations in the advisory"),

    # Siemens Desigo DXR2 and PXC4 / PXC5 / PXC7.
    Advisory("ICSA-22-132-10", "2022-05-12", "Siemens Desigo PXC and DXR Devices",
             "siemens", r"^dxr2", "firmware_revision", "01.21.142.5",
             ("CVE-2021-41545", "CVE-2022-24039", "CVE-2022-24040", "CVE-2022-24041",
              "CVE-2022-24042", "CVE-2022-24043", "CVE-2022-24044", "CVE-2022-24045"), 9.0,
             note="fixed in 01.21.142.5-22"),
    Advisory("ICSA-26-225-08", "2026-08-11", "Siemens Desigo DXR and PXC Controllers",
             "siemens", r"^dxr2", "firmware_revision", "01.21.233.16",
             ("CVE-2026-59693",), 4.3, note="fixed in 01.21.233.16-7862"),
    Advisory("ICSA-26-225-08", "2026-08-11", "Siemens Desigo DXR and PXC Controllers",
             "siemens", r"^pxc(4|5\.e003|5\.e24|7)", "firmware_revision", "02.21.194.36",
             ("CVE-2026-59693",), 4.3, note="fixed in 02.21.194.36-2715"),

    # Siemens Desigo CC (V9). How the BACnet device's versions map to
    # Desigo CC releases is not documented, so these are left to check.
    Advisory("ICSA-26-209-01", "2026-07-14", "Siemens Desigo CC",
             "siemens", r"^desigo cc$", "application_software_version", None,
             ("CVE-2025-15467",), 9.8,
             note="Desigo CC V9 before V9.0 QU1 is affected: check the installed release"),
)


def _version(text: str) -> Optional[tuple[int, ...]]:
    m = _VERSION.search(text or "")
    return tuple(int(x) for x in m.group(1).split('.')) if m else None


def compare(reported: str, fixed: str) -> str:
    """'affected', 'fixed' or 'check' for a reported version against the
    version an advisory says to update to."""
    have, want = _version(reported), _version(fixed)
    if have is None or want is None:
        return "check"
    for a, b in zip(have, want):
        if a != b:
            return "affected" if a < b else "fixed"
    # Equal as far as both go: a shorter reported version cannot be placed.
    return "fixed" if len(have) >= len(want) else "check"


def for_device(dev: dict[str, Any]) -> list[dict[str, Any]]:
    """The advisories that cover this device's reported firmware, each with
    its status: 'affected', 'no fix' or 'check'. Fixed ones are left out."""
    props = dev.get('properties') or {}
    vendor = ' '.join(str(x or '') for x in (props.get('vendor_name'), dev.get('vendor_name'))).lower()
    model = str(props.get('model_name') or '').strip().lower()
    if not model:
        return []
    out = []
    for adv in ADVISORIES:
        if adv.vendor not in vendor or not re.search(adv.model, model):
            continue
        reported = str(props.get(adv.field) or '')
        if adv.firmware and not re.search(adv.firmware, reported):
            continue
        if adv.fixed is None:
            status = "no fix" if "all versions" in adv.note else "check"
        else:
            status = compare(reported, adv.fixed)
        if status == "fixed":
            continue
        out.append({'advisory': adv, 'status': status, 'reported': reported})
    return out
