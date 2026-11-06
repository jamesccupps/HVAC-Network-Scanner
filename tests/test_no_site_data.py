"""Guard against site-identifying data reaching the public tree.

The repo once shipped real asset identifiers from the installation it was
developed against: panel names, room-controller names, equipment tags, a
controller serial, and references naming the site itself — all alongside
vendor, model, firmware revision and object counts. Together that is a
partial asset inventory of a named building.

Technical substance is fine and wanted: object counts, firmware revisions,
verification dates and behavioral notes all stay. What must not appear is a
string that names a site or a specific installed asset.

Two layers:

- Generic shapes, below, that no public file should contain whatever the
  site: a panel name with its serial-style suffix, a controller serial.
  These run everywhere, CI included.
- A private deny-list naming particular sites, kept OUTSIDE the repository
  (a public list of what to keep out is a list of what to look for). Its
  path is $HVAC_SITE_DENYLIST, else ~/.hvac-scanner/site-denylist.txt; the
  tests using it skip when it is absent. A local pre-commit hook runs this
  file, so a commit carrying a listed name is refused before it exists.

Deny-list format, one entry per line ('#' starts a comment):
    re:<regex>          a pattern, searched case-sensitively
    sha256:<hex>        SHA-256 of a lower-cased phrase of up to three words
    <text>              a phrase, matched case-insensitively on word boundaries
"""

import codecs
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SCANNED_SUFFIXES = {'.py', '.md', '.toml', '.yml', '.yaml', '.cfg', '.txt', '.bat',
                    '.spec', '.json', '.ini', '.html', '.htm', '.csv', '.log', '.xml',
                    '.ps1', '.sh', '.js', '.css'}
# Used only when git is unavailable (an sdist, say). With git, the scan covers
# exactly the files that would be published, so a virtualenv or build output
# inside the checkout can never trip it.
SKIP_DIRS = {'.git', '__pycache__', '.pytest_cache', 'build', 'dist', '.eggs',
             '.venv', 'venv', 'env', '.tox', 'node_modules', 'site-packages'}

# Shapes of asset names that identify an installed device on any site. Each
# is (regex, why it is banned); specific enough that prose does not trip them.
BANNED_SHAPES = [
    (r'\bPXC[CM]\d{5,}\b',          'specific panel name'),
    (r'\bE\d{2}[A-Z]\d{5,}\b',      'controller serial number'),
]
MAX_PHRASE_WORDS = 3

# This file necessarily contains the patterns it bans.
SELF = Path(__file__).name


def denylist_path() -> Path:
    env = os.environ.get('HVAC_SITE_DENYLIST')
    return Path(env) if env else Path.home() / '.hvac-scanner' / 'site-denylist.txt'


def load_denylist(path: Path):
    """(regexes, digests) from a private deny-list; phrases become digests."""
    regexes, digests = [], set()
    for raw in path.read_text(encoding='utf-8').splitlines():
        entry = raw.split('#', 1)[0].strip()
        if not entry:
            continue
        if entry.startswith('re:'):
            regexes.append(re.compile(entry[3:].strip()))
        elif entry.startswith('sha256:'):
            digests.add(entry[7:].strip().lower())
        else:
            words = re.findall(r'[a-z0-9]+', entry.lower())
            digests.add(hashlib.sha256(' '.join(words).encode()).hexdigest())
    return regexes, digests


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


def _decode(data: bytes) -> str:
    """Text in whatever encoding it was saved in. Windows PowerShell 5's `>`
    writes UTF-16, which a UTF-8 read used to skip as undecodable."""
    for bom, enc in ((codecs.BOM_UTF8, 'utf-8-sig'), (codecs.BOM_UTF16_LE, 'utf-16'),
                     (codecs.BOM_UTF16_BE, 'utf-16')):
        if data.startswith(bom):
            return data.decode(enc, errors='replace')
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin-1')


def _lines():
    for path in _scanned_files():
        try:
            text = _decode(path.read_bytes())
        except OSError:
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
def test_no_asset_shaped_strings(pattern, reason):
    rx = re.compile(pattern)
    hits = [f"{rel}:{n}: {line.strip()[:100]}"
            for rel, n, line in _lines() if rx.search(line)]
    assert not hits, (
        f"{reason} found in the public tree:\n  " + "\n  ".join(hits)
    )


def test_nothing_on_the_private_denylist():
    path = denylist_path()
    if not path.is_file():
        pytest.skip(f"no private deny-list at {path}")
    regexes, digests = load_denylist(path)
    hits = []
    for rel, n, line in _lines():
        if any(rx.search(line) for rx in regexes) or any(
                d in digests for d in _phrase_digests(line)):
            hits.append(f"{rel}:{n}")
    # The offending text is deliberately not echoed back.
    assert not hits, "site-identifying text found in the public tree:\n  " + "\n  ".join(hits)


def test_the_guard_actually_matches_what_it_claims_to():
    """Make sure the patterns are not silently inert. Samples are synthetic."""
    samples = [
        ('PXCM990000', r'\bPXC[CM]\d{5,}\b'),
        ('E99Z00000', r'\bE\d{2}[A-Z]\d{5,}\b'),
    ]
    for sample, pattern in samples:
        assert re.search(pattern, sample), f"{pattern!r} no longer matches {sample!r}"


def test_denylist_format(tmp_path):
    deny = tmp_path / "deny.txt"
    deny.write_text("# comment\nre:\\bZZTOP_\\w+\nExample Plaza  # a phrase\n"
                    f"sha256:{hashlib.sha256(b'north annex').hexdigest()}\n",
                    encoding='utf-8')
    regexes, digests = load_denylist(deny)
    assert regexes[0].search("panel ZZTOP_AHU1")
    found = set(_phrase_digests("Panels at  Example   PLAZA, level 2"))
    assert hashlib.sha256(b'example plaza').hexdigest() in found & digests
    assert hashlib.sha256(b'north annex').hexdigest() in digests


def test_utf16_files_are_read():
    text = "PXCM990000 in a log"
    assert _decode(codecs.BOM_UTF16_LE + text.encode('utf-16-le')) == text


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
