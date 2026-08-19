"""Guard against site-identifying data reaching the public tree.

The repo shipped real asset identifiers from the installation it was developed
against: panel names (OCCPXCM103000, PXCC101000), room-controller names
(OCC_RM1007, OCC_BATH_RM1054), equipment tags (HV-1, AC-4), a controller
serial (in the README's objectName example), and ~30 references naming the
site itself — all alongside vendor, model, firmware revision and object
counts. Together that is a partial asset inventory of a named building.

Technical substance is fine and wanted: object counts, firmware revisions,
verification dates and behavioral notes all stay. What must not appear is a
string that names a site or a specific installed asset.

This test is deliberately source-scanning rather than reviewer-dependent —
the point is that the next contributor pasting field notes gets caught by CI.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SCANNED_SUFFIXES = {'.py', '.md', '.toml', '.yml', '.yaml', '.cfg', '.txt', '.bat'}
SKIP_DIRS = {'.git', '__pycache__', '.pytest_cache', 'build', 'dist', '.eggs'}

# Each pattern is (regex, why it is banned). Keep them specific enough that
# ordinary English does not trip them.
BANNED = [
    (r'\bOCC[_A-Z0-9]{3,}\b',       'site-prefixed device or room name'),
    (r'\bPXC[CM]\d{5,}\b',          'specific panel name'),
    (r'\bE\d{2}[A-Z]\d{5,}\b',      'controller serial number'),
    (r'\bOne City Center\b',        'site name'),
    (r'(?i)\bOCC Portland\b',       'site name'),
    (r'(?i)\b\d+ Gannett\b',        'site address'),
    (r'(?i)\bHaigis Parkway\b',     'site address'),
]

# This file necessarily contains the patterns it bans.
SELF = Path(__file__).name


def _scanned_files():
    for path in ROOT.rglob('*'):
        if not path.is_file() or path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name == SELF:
            continue
        yield path


@pytest.mark.parametrize("pattern,reason", BANNED)
def test_no_site_identifying_strings(pattern, reason):
    rx = re.compile(pattern)
    hits = []
    for path in _scanned_files():
        try:
            text = path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                rel = path.relative_to(ROOT).as_posix()
                hits.append(f"{rel}:{lineno}: {line.strip()[:100]}")
    assert not hits, (
        f"{reason} found in the public tree:\n  " + "\n  ".join(hits)
    )


def test_the_guard_actually_matches_what_it_claims_to():
    """Make sure the patterns are not silently inert."""
    samples = [
        ('OCCPXCM103000', r'\bOCC[_A-Z0-9]{3,}\b'),
        ('OCC_BATH_RM1054', r'\bOCC[_A-Z0-9]{3,}\b'),
        ('PXCC101000', r'\bPXC[CM]\d{5,}\b'),
        ('E22J04614', r'\bE\d{2}[A-Z]\d{5,}\b'),
        ('One City Center', r'\bOne City Center\b'),
    ]
    for sample, pattern in samples:
        assert re.search(pattern, sample), f"{pattern!r} no longer matches {sample!r}"


def test_guard_does_not_trip_on_ordinary_prose():
    innocuous = [
        "This occurs occasionally on some devices.",
        "The occupancy sensor reports presentValue.",
        "See docs/ARCHITECTURE.md for the occupied-mode sequence.",
    ]
    for pattern, _reason in BANNED:
        rx = re.compile(pattern)
        for line in innocuous:
            assert not rx.search(line), f"{pattern!r} false-positives on {line!r}"
