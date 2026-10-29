"""Guard against site-identifying data reaching the public tree.

The repo once shipped real asset identifiers from the installation it was
developed against: panel names, room-controller names, equipment tags, a
controller serial, and references naming the site itself — all alongside
vendor, model, firmware revision and object counts. Together that is a
partial asset inventory of a named building.

Technical substance is fine and wanted: object counts, firmware revisions,
verification dates and behavioral notes all stay. What must not appear is a
string that names a site or a specific installed asset.

This test is deliberately source-scanning rather than reviewer-dependent —
the point is that the next contributor pasting field notes gets caught by CI.

The site's name and address are checked by SHA-256 digest rather than spelled
out here. An earlier version listed them in plain text, which put them back
in the public tree in the very file meant to keep them out of it.
"""

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SCANNED_SUFFIXES = {'.py', '.md', '.toml', '.yml', '.yaml', '.cfg', '.txt', '.bat',
                    '.spec', '.json', '.ini'}
# Used only when git is unavailable (an sdist, say). With git, the scan covers
# exactly the files that would be published, so a virtualenv or build output
# inside the checkout can never trip it.
SKIP_DIRS = {'.git', '__pycache__', '.pytest_cache', 'build', 'dist', '.eggs',
             '.venv', 'venv', 'env', '.tox', 'node_modules', 'site-packages'}

# Shapes of asset names. Each is (regex, why it is banned); keep them specific
# enough that ordinary English does not trip them.
BANNED_SHAPES = [
    (r'\bOCC[_A-Z0-9]{3,}\b',       'site-prefixed device or room name'),
    (r'\bPXC[CM]\d{5,}\b',          'specific panel name'),
    (r'\bE\d{2}[A-Z]\d{5,}\b',      'controller serial number'),
]

# SHA-256 of lower-cased phrases (words joined by single spaces) that name the
# site or its address. Phrases of up to MAX_PHRASE_WORDS words are checked.
BANNED_PHRASE_DIGESTS = {
    'f5692c6b117e55786606c8f17d41846cfc94f5b76160c7c4f8f8b0f81f6cd7df': 'site name',
    'b905499ade9fcae9b0135d017212dacd2d6b970167b2634277ebe0ac4b41936e': 'site name',
    '9e227bce7fc27bb32f4abd09780d155eb651a4280e5e70babe710a2169468738': 'site address',
    '8f400ad379992d4f0deacd3577bf65e9bbef5a81c2806c95703e054ec048f736': 'site address',
}
MAX_PHRASE_WORDS = 3

# This file necessarily contains the patterns it bans.
SELF = Path(__file__).name


def _candidate_paths():
    try:
        out = subprocess.run(
            ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
            cwd=ROOT, capture_output=True, text=True, check=True, timeout=30,
        ).stdout
        return [ROOT / line for line in out.splitlines() if line]
    except (OSError, subprocess.SubprocessError):
        return [p for p in ROOT.rglob('*')
                if not any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts)]


def _scanned_files():
    for path in _candidate_paths():
        if not path.is_file() or path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        if path.name == SELF:
            continue
        yield path


def _lines():
    for path in _scanned_files():
        try:
            text = path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            yield rel, lineno, line


def _phrase_digests(line: str):
    words = re.findall(r'[a-z0-9]+', line.lower())
    for n in range(1, MAX_PHRASE_WORDS + 1):
        for i in range(len(words) - n + 1):
            yield hashlib.sha256(' '.join(words[i:i + n]).encode()).hexdigest()


@pytest.mark.parametrize("pattern,reason", BANNED_SHAPES)
def test_no_site_identifying_strings(pattern, reason):
    rx = re.compile(pattern)
    hits = [f"{rel}:{n}: {line.strip()[:100]}"
            for rel, n, line in _lines() if rx.search(line)]
    assert not hits, (
        f"{reason} found in the public tree:\n  " + "\n  ".join(hits)
    )


def test_no_site_name_or_address():
    hits = []
    for rel, n, line in _lines():
        for digest in _phrase_digests(line):
            if digest in BANNED_PHRASE_DIGESTS:
                hits.append(f"{rel}:{n}: ({BANNED_PHRASE_DIGESTS[digest]})")
                break
    # The offending text is deliberately not echoed back.
    assert not hits, "site-identifying text found in the public tree:\n  " + "\n  ".join(hits)


def test_the_guard_actually_matches_what_it_claims_to():
    """Make sure the patterns are not silently inert. Samples are synthetic."""
    samples = [
        ('OCC_TEST_ROOM', r'\bOCC[_A-Z0-9]{3,}\b'),
        ('OCCPXCM999999', r'\bOCC[_A-Z0-9]{3,}\b'),
        ('PXCM990000', r'\bPXC[CM]\d{5,}\b'),
        ('E99Z00000', r'\bE\d{2}[A-Z]\d{5,}\b'),
    ]
    for sample, pattern in samples:
        assert re.search(pattern, sample), f"{pattern!r} no longer matches {sample!r}"


def test_phrase_matching_is_word_based():
    digest = hashlib.sha256(b'example plaza').hexdigest()
    found = {d for d in _phrase_digests("Panels at  Example   PLAZA, level 2")}
    assert digest in found


def test_guard_does_not_trip_on_ordinary_prose():
    innocuous = [
        "This occurs occasionally on some devices.",
        "The occupancy sensor reports presentValue.",
        "See docs/ARCHITECTURE.md for the occupied-mode sequence.",
        "OCC-MODE and OCC-SENS are ordinary point names.",
    ]
    for pattern, _reason in BANNED_SHAPES:
        rx = re.compile(pattern)
        for line in innocuous:
            assert not rx.search(line), f"{pattern!r} false-positives on {line!r}"
    for line in innocuous:
        assert not any(d in BANNED_PHRASE_DIGESTS for d in _phrase_digests(line))
