"""
Published security advisories for the firmware devices report about
themselves.

The list lives in advisories.json, beside this file and built into the app.
Every entry comes from a CISA ICS advisory, read from CISA's own CSAF data
(github.com/cisagov/CSAF), and names: the products it covers (matched on
the vendor and model a device reports), which reported property holds the
version, and the version the advisory says to update to (None when it gives
none). tools/advisory_watch.py builds the entries from CSAF; nothing is
inferred beyond the product families it lists.

The list updates itself. A GitHub workflow (.github/workflows/advisories.yml)
runs that tool every day; when CISA publishes or revises an advisory for a
listed family, it commits the new list with a higher serial number and
publishes it signed (data/advisories.signed.json on the main branch). The app
downloads that file with its daily update check, verifies the signature with
ADVISORY_PUBLIC_KEY (update_key.py: a key of its own, which can sign this list
and nothing else) and keeps it in its settings folder; whichever of the
built-in and the downloaded list has the higher serial is used.

A device is compared only when its reported version can be: one older than
the fix is "affected"; one whose version is too short to tell (a DXR2 reports
"v01.21" while the fix is 01.21.142.5-22) is "check"; an advisory with no
fixed version covers every version it lists ("no fix"). The scanner does not
test for the vulnerabilities themselves.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from . import __version__, ed25519
from .update_key import ADVISORY_PUBLIC_KEY

log = logging.getLogger(__name__)

APP_KEY = "hvac-network-scanner"
KIND = "advisories"
BUNDLED = Path(__file__).with_name("advisories.json")
DATA_URL = ("https://raw.githubusercontent.com/jamesccupps/HVAC-Network-Scanner/"
            "main/data/advisories.signed.json")
SOURCE_ENV = "HVAC_ADVISORIES_URL"      # a URL or a file: tests, mirrors
CACHE_NAME = "advisories.signed.json"

MAX_SIGNED = 2 * 1024 * 1024
MAX_ENTRIES = 5000

FIELDS = ("firmware_revision", "application_software_version")
_ID = re.compile(r"^ICS(?:M)?A-\d{2}-\d{3}-\d{2}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FIXED = re.compile(r"^\d{1,6}(?:\.\d{1,9}){1,5}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,8}$")
_VENDOR = re.compile(r"^[a-z0-9][a-z0-9 .&/+-]{0,39}$")
_REVISION = re.compile(r"^\d{1,4}(?:\.\d{1,4}){0,3}$")
_VERSION = re.compile(r"(\d+(?:\.\d+)+)")


class AdvisoryDataError(Exception):
    """An advisory list that can't be used: unsigned, malformed, too big."""


@dataclass(frozen=True)
class Advisory:
    id: str                       # CISA ICS advisory
    published: str
    title: str
    vendor: str                   # substring of the reported vendor name (lowercase)
    model: str                    # regex on the reported model name (lowercase)
    field: str                    # property holding the version
    fixed: Optional[str]          # the version to update to; None: none given
    cves: tuple[str, ...]
    cvss: float                   # highest CVSS v3 base score for these products
    firmware: str = ""            # regex the version property must also match (product line)
    note: str = ""
    no_fix: bool = False          # every version listed is affected and no fix exists
    revision: str = ""            # the CSAF document's revision the entry was built from
    auto: bool = True             # built by tools/advisory_watch.py (False: by hand)

    @property
    def url(self) -> str:
        return f"https://www.cisa.gov/news-events/ics-advisories/{self.id.lower()}"


@dataclass(frozen=True)
class Table:
    serial: int
    as_of: str
    advisories: tuple[Advisory, ...]
    origin: str = "built in"      # or "downloaded"


# -- validation ----------------------------------------------------------------

def _text(v, name, limit, empty=True) -> str:
    if not isinstance(v, str) or len(v) > limit or (not empty and not v):
        raise AdvisoryDataError(f"{name}: bad value {v!r:.60}")
    return v


def _regex(v, name, empty=True) -> str:
    v = _text(v, name, 200, empty)
    try:
        re.compile(v)
    except re.error as e:
        raise AdvisoryDataError(f"{name}: bad pattern {v!r}: {e}") from e
    return v


def entry_from_dict(d: Any) -> Advisory:
    """One entry, checked field by field; raises AdvisoryDataError."""
    if not isinstance(d, dict):
        raise AdvisoryDataError("entry: not an object")
    aid = d.get("id")
    if not (isinstance(aid, str) and _ID.fullmatch(aid)):
        raise AdvisoryDataError(f"bad advisory id {aid!r:.40}")
    where = f"{aid}"
    published = d.get("published")
    if not (isinstance(published, str) and _DATE.fullmatch(published)):
        raise AdvisoryDataError(f"{where}: bad date {published!r:.20}")
    vendor = d.get("vendor")
    if not (isinstance(vendor, str) and _VENDOR.fullmatch(vendor)):
        raise AdvisoryDataError(f"{where}: bad vendor {vendor!r:.40}")
    field = d.get("field")
    if field not in FIELDS:
        raise AdvisoryDataError(f"{where}: bad field {field!r:.40}")
    fixed = d.get("fixed")
    if fixed is not None and not (isinstance(fixed, str) and _FIXED.fullmatch(fixed)):
        raise AdvisoryDataError(f"{where}: bad fixed version {fixed!r:.40}")
    cves = d.get("cves")
    if not (isinstance(cves, list) and len(cves) <= 200
            and all(isinstance(c, str) and _CVE.fullmatch(c) for c in cves)):
        raise AdvisoryDataError(f"{where}: bad CVE list")
    cvss = d.get("cvss")
    if isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10:
        raise AdvisoryDataError(f"{where}: bad CVSS {cvss!r:.20}")
    revision = d.get("revision", "")
    if revision and not (isinstance(revision, str) and _REVISION.fullmatch(revision)):
        raise AdvisoryDataError(f"{where}: bad revision {revision!r:.20}")
    for flag in ("no_fix", "auto"):
        if not isinstance(d.get(flag, False), bool):
            raise AdvisoryDataError(f"{where}: {flag} is not true or false")
    return Advisory(
        id=aid, published=published,
        title=_text(d.get("title"), f"{where} title", 300, empty=False),
        vendor=vendor, model=_regex(d.get("model"), f"{where} model", empty=False),
        field=field, fixed=fixed, cves=tuple(cves), cvss=float(cvss),
        firmware=_regex(d.get("firmware", ""), f"{where} firmware"),
        note=_text(d.get("note", ""), f"{where} note", 400),
        no_fix=d.get("no_fix", False), revision=revision or "",
        auto=d.get("auto", True))


def entry_to_dict(a: Advisory) -> dict[str, Any]:
    d = asdict(a)
    d["cves"] = list(a.cves)
    return d


def parse_table(obj: Any, origin: str = "built in") -> Table:
    """The list in `obj` (the JSON object), checked; raises AdvisoryDataError."""
    if not isinstance(obj, dict) or obj.get("app") != APP_KEY or obj.get("kind") != KIND:
        raise AdvisoryDataError("not this app's advisory list")
    serial = obj.get("serial")
    if isinstance(serial, bool) or not isinstance(serial, int) or not 0 < serial < 10**9:
        raise AdvisoryDataError(f"bad serial {serial!r:.20}")
    as_of = obj.get("as_of")
    if not (isinstance(as_of, str) and _DATE.fullmatch(as_of)):
        raise AdvisoryDataError(f"bad date {as_of!r:.20}")
    entries = obj.get("advisories")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise AdvisoryDataError("bad advisory list")
    return Table(serial, as_of, tuple(entry_from_dict(e) for e in entries), origin)


def table_to_dict(t: Table) -> dict[str, Any]:
    return {"app": APP_KEY, "kind": KIND, "serial": t.serial, "as_of": t.as_of,
            "advisories": [entry_to_dict(a) for a in t.advisories]}


def canonical(obj: Any) -> bytes:
    """The bytes that are signed: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signed_text(obj: dict, seed: bytes) -> str:
    """data/advisories.signed.json's text for the list `obj`, signed with
    `seed` (the Ed25519 private key)."""
    parse_table(obj)                     # never sign a list the app would refuse
    raw = canonical(obj)
    return json.dumps({"payload": base64.b64encode(raw).decode("ascii"),
                       "signature": base64.b64encode(ed25519.sign(seed, raw)).decode("ascii")},
                      indent=2) + "\n"


def verify_signed(text: str, public_key: Optional[str] = None,
                  origin: str = "downloaded") -> Table:
    """The list in a signed file, if and only if it is signed by
    `public_key` (base64; the one built into the app by default) and
    well-formed."""
    try:
        outer = json.loads(text)
        payload = base64.b64decode(outer["payload"], validate=True)
        signature = base64.b64decode(outer["signature"], validate=True)
        key = base64.b64decode(public_key or ADVISORY_PUBLIC_KEY, validate=True)
    except (ValueError, KeyError, TypeError) as e:
        raise AdvisoryDataError(f"the advisory list is malformed: {e}") from e
    if not ed25519.verify(key, payload, signature):
        raise AdvisoryDataError("the advisory list isn't signed with the key this app trusts")
    try:
        obj = json.loads(payload)
    except ValueError as e:
        raise AdvisoryDataError("the advisory list's payload isn't JSON") from e
    return parse_table(obj, origin)


# -- the list in use -------------------------------------------------------------

_lock = threading.Lock()
_bundled: Optional[Table] = None
_cached: dict[str, Any] = {"key": None, "table": None}


def bundled() -> Table:
    """The list built into this copy."""
    global _bundled
    if _bundled is None:
        _bundled = parse_table(json.loads(BUNDLED.read_text(encoding="utf-8")))
    return _bundled


def cache_path() -> Path:
    from .settings import default_path
    return default_path().parent / CACHE_NAME


def cached(path: Optional[Path] = None) -> Optional[Table]:
    """The downloaded list, checked again as it is read, or None."""
    path = Path(path or cache_path())
    try:
        st = path.stat()
    except OSError:
        return None
    key = (str(path), st.st_mtime_ns, st.st_size)
    with _lock:
        if _cached["key"] == key:
            return _cached["table"]
    table = None
    if st.st_size <= MAX_SIGNED:
        try:
            table = verify_signed(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, AdvisoryDataError) as e:
            log.warning("ignoring the downloaded advisory list %s: %s", path, e)
    with _lock:
        _cached.update(key=key, table=table)
    return table


def current(cache: Optional[Path] = None) -> Table:
    """The list to use: the downloaded one when its serial is higher than
    the built-in one's."""
    base = bundled()
    newer = cached(cache)
    return newer if newer is not None and newer.serial > base.serial else base


def source() -> str:
    return os.environ.get(SOURCE_ENV) or DATA_URL


def _read(src: str, timeout: float) -> str:
    if urlsplit(src).scheme in ("http", "https"):
        req = urllib.request.Request(src, headers={"User-Agent": f"HVAC-Scanner/{__version__}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(MAX_SIGNED + 1)
    else:
        with open(src, "rb") as fh:
            data = fh.read(MAX_SIGNED + 1)
    if len(data) > MAX_SIGNED:
        raise AdvisoryDataError("the advisory list is too big")
    return data.decode("utf-8")


def refresh(src: Optional[str] = None, cache: Optional[Path] = None,
            public_key: Optional[str] = None, timeout: float = 20) -> tuple[Table, bool]:
    """Download the signed list; keep it when its serial is higher than the
    list in use. Returns (the list now in use, whether it changed). Raises
    AdvisoryDataError, or OSError for the network."""
    text = _read(src or source(), timeout)
    new = verify_signed(text, public_key)
    now = current(cache)
    if new.serial <= now.serial:
        return now, False
    path = Path(cache or cache_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    part.write_bytes(text.encode("utf-8"))     # as published, byte for byte
    os.replace(part, path)
    log.info("advisory list %d (as of %s) downloaded", new.serial, new.as_of)
    return current(cache), True


def describe(t: Optional[Table] = None) -> str:
    t = t or current()
    return f"{len(t.advisories)} entries, as of {t.as_of} (list {t.serial}, {t.origin})"


def __getattr__(name: str):
    # ADVISORIES: the entries in use (kept for callers from 2.12).
    if name == "ADVISORIES":
        return current().advisories
    raise AttributeError(name)


# -- matching --------------------------------------------------------------------

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


_RANK = {"affected": 0, "no fix": 1, "check": 2}


def for_device(dev: dict[str, Any], table: Optional[Table] = None) -> list[dict[str, Any]]:
    """The advisories that cover this device's reported firmware, each with
    its status: 'affected', 'no fix' or 'check'. Fixed ones are left out; an
    advisory listed for several of the device's product names counts once,
    with its most definite status."""
    props = dev.get('properties') or {}
    vendor = ' '.join(str(x or '') for x in (props.get('vendor_name'), dev.get('vendor_name'))).lower()
    model = str(props.get('model_name') or '').strip().lower()
    if not model:
        return []
    best: dict[str, dict[str, Any]] = {}
    for adv in (table or current()).advisories:
        if adv.vendor not in vendor or not re.search(adv.model, model):
            continue
        reported = str(props.get(adv.field) or '')
        if adv.firmware and not re.search(adv.firmware, reported):
            continue
        if adv.fixed is None:
            status = "no fix" if adv.no_fix else "check"
        else:
            status = compare(reported, adv.fixed)
        if status == "fixed":
            continue
        had = best.get(adv.id)
        if had is None or _RANK[status] < _RANK[had['status']]:
            best[adv.id] = {'advisory': adv, 'status': status, 'reported': reported}
    return list(best.values())
