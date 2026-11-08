"""Keep hvac_scanner/advisories.json current with CISA's ICS advisories.

    python tools/advisory_watch.py [--days 30] [--sign] [--issues] [--dry-run]

Run every day by .github/workflows/advisories.yml. It reads CISA's CSAF feed
(github.com/cisagov/CSAF: every OT advisory, machine-readable), fetches the
advisories whose titles name a building-automation vendor, and:

  * builds the list's entries for every product in a FAMILY below: the model
    name the device reports, the property holding its version, and the
    version the advisory says to update to, all from the CSAF document;
  * replaces the entries it built before for those advisories (so a revised
    advisory revises its entries), leaves entries made by hand ("auto":
    false) alone, and bumps the list's serial when anything changed;
  * with --sign, writes data/advisories.signed.json, the copy installed apps
    download, signed with the advisory key (packaging/signing.py);
  * with --issues, opens a GitHub issue for an advisory updated in the last
    --days days that covers building-automation products no family maps:
    those need someone to find out what model name the devices report.

Only the families below are mapped, each with a model name checked against
real devices or the vendor's documentation. Adding one is the way to cover a
new product line: add it, run with --dry-run, and check the entries.

Exits non-zero, writing nothing, if any advisory can't be fetched: a list
built from part of the data would drop entries.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hvac_scanner import advisories  # noqa: E402

CSAF_BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
FEED_URL = CSAF_BASE + "cisa-csaf-ot-feed-tlp-white.json"
SOURCE = ROOT / "hvac_scanner" / "advisories.json"
SIGNED = ROOT / "data" / "advisories.signed.json"
_PATH = re.compile(r"^\d{4}/ics(?:m)?a-\d{2}-\d{3}-\d{2}\.json$")
MAX_FEED = 64 * 1024 * 1024
MAX_DOC = 8 * 1024 * 1024
ISSUE_PREFIX = "Advisory to review:"


# -- product families the list covers -------------------------------------------

@dataclass(frozen=True)
class Family:
    key: str
    csaf_vendor: str              # regex on the CSAF vendor branch (lowercase)
    csaf_product: str             # regex on the CSAF product name (lowercase, spaces collapsed)
    vendor: str                   # the entry's vendor (substring of what devices report)
    model: str                    # the entry's model regex (on what devices report)
    field: str
    firmware: str = ""
    check_only: bool = False      # versions can't be compared: always "check"
    check_note: str = ""
    by_release: bool = False      # one entry per release the advisory names (see releases())


# Model names are the ones devices report (BACnet modelName), as the
# scanner's fingerprint.py names them. Firmware lines tell APOGEE PXC
# Modular (PXME) and Compact (EPXC) apart on BACnet firmware.
FAMILIES: tuple[Family, ...] = (
    Family("tracer-sc+", r"^trane", r"^tracer sc\+$",
           "trane", r"^tracer sc\+$", "application_software_version"),
    Family("tracer-sc", r"^trane", r"^tracer sc$",
           "trane", r"^tracer sc$", "application_software_version"),
    Family("apogee-pxc-compact", r"^siemens", r"^apogee pxc compact \(bacnet\)$",
           "siemens", r"^siemens bacnet field panel$", "firmware_revision", firmware=r"^EPXC\b"),
    Family("apogee-pxc-modular", r"^siemens", r"^apogee pxc modular \(bacnet\)$",
           "siemens", r"^siemens bacnet field panel$", "firmware_revision", firmware=r"^PXME\b"),
    Family("apogee-pxc", r"^siemens", r"^apogee pxc(?: ?\+ ?talon tc)? series \(bacnet\)$",
           "siemens", r"^siemens bacnet field panel$", "firmware_revision",
           firmware=r"^(PXME|EPXC)\b"),
    Family("desigo-dxr2", r"^siemens", r"^desigo dxr2$",
           "siemens", r"^dxr2", "firmware_revision"),
    Family("desigo-pxc4", r"^siemens", r"^desigo pxc4$",
           "siemens", r"^pxc4", "firmware_revision"),
    Family("desigo-pxc5", r"^siemens", r"^desigo pxc5$",
           "siemens", r"^pxc5", "firmware_revision"),
    Family("desigo-pxc5.e003", r"^siemens", r"^desigo pxc5\.e003$",
           "siemens", r"^pxc5\.e003", "firmware_revision"),
    Family("desigo-pxc5.e24", r"^siemens", r"^desigo pxc5\.e24$",
           "siemens", r"^pxc5\.e24", "firmware_revision"),
    Family("desigo-pxc7", r"^siemens", r"^desigo pxc7$",
           "siemens", r"^pxc7", "firmware_revision"),
    Family("desigo-cc", r"^siemens", r"^desigo cc(?: compact| family)?(?: v\d+(?:\.\d+)?)?$",
           "siemens", r"^desigo cc$", "application_software_version", check_only=True,
           by_release=True,
           check_note="Desigo CC reports its release (9.00 is V9.0) but not its quality "
                      "update: check the installed one"),
)

# Advisory titles worth fetching: the families' vendors, and the vendors of
# building-automation products an issue should be opened for.
TITLE_WATCH = re.compile(
    r"\b(?:siemens\b.*\b(?:desigo|apogee|talon|building|bacnet|pxc|dxr|climatix|synco|knx)"
    r"|trane|johnson controls|honeywell|tridium|niagara|schneider electric|carrier"
    r"|automated logic|distech|delta controls|kmc|reliable controls|contemporary controls"
    r"|belimo|sauter|priva|optergy|loytec|echelon|enocean|daikin|lg electronics|carel"
    r"|abb\b.*\b(?:cylon|aspect|building|bacnet|knx)|moxa|lantronix|kieback|easyio"
    r"|lynxspring|viconics|sierra monitor|fieldserver|mitsubishi electric\b.*\b(?:air|hvac|bems)"
    r"|alerton|bacnet|lonworks|knx)\b", re.I)

# Products that are building automation, for the review issues:
# (vendor regex, product regex), both on lowercase names.
RELEVANT = (
    (r"siemens", r"desigo|apogee|talon|climatix|synco|dxr|pxc|pxm|bacnet|building|knx|gamma"),
    (r"trane", r"."),
    (r"johnson controls", r"metasys|facility explorer|\bfx|\bnae|\bnce|\bsnc|\bsne|\bads\b|\badx\b"
                          r"|verasys|easyio|bacnet|smart building"),
    (r"honeywell", r"webs|niagara|optimizer|alerton|spyder|ciper|excel|\bebi\b|\btrend\b|\biq"
                   r"|enterprise buildings|centraline|comfortpoint|bacnet|saia"),
    (r"tridium|niagara", r"."),
    (r"schneider", r"ecostruxure building|smartx|andover|continuum|\btac\b|i/a series"
                   r"|building operation|struxureware building|bacnet|spacelogic|knx"),
    (r"carrier", r"i-vu|webctrl|automated logic|bacnet|hvac|chiller"),
    (r"automated logic|distech|delta controls|kmc|reliable controls|contemporary control|belimo"
     r"|sauter|priva|optergy|loytec|easyio|lynxspring|viconics|kieback|alerton|daikin|carel"
     r"|lantronix", r"."),
    (r"echelon|enocean|dialog", r"i\.lon|smartserver|\blon"),
    (r"mitsubishi electric", r"air.?condition|centralized controller|ae-200|ae-50|ew-50|te-200"
                             r"|tw-50|ce-50|bems"),
    (r"lg", r"multi v|ac smart|ac manager|becon|hvac|air condition"),
    (r"danfoss", r"\bak-|alsmart|enviroguard|refrigerat"),
    (r"abb", r"cylon|aspect|fbxi|matrix|nexus|bacnet|knx|building"),
    (r"moxa", r"nport|mgate|oncell"),
    (r".", r"bacnet|niagara|\blon(?:works|talk)?\b|\bknx\b"),
)


# Products the scanner can't read a version from: APOGEE panels on P2
# firmware are detected, but P2 says nothing about firmware.
NOT_COVERABLE = r"\(p2 ethernet\)"


# -- reading CSAF ----------------------------------------------------------------

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip().lower()


@dataclass
class Product:
    pid: str
    vendor: str
    name: str                     # product_name (or the family's name)
    version: str                  # the version range text, '' when none is given


def products(doc: dict) -> list[Product]:
    """Every product in a CSAF product tree, with its vendor and range."""
    out: list[Product] = []

    versions = ("product_version_range", "product_version")

    def below(b):
        # Some older CISA files nest a product's versions one inside another.
        for c in b.get("branches") or []:
            if c.get("category") in versions:
                yield str(c.get("name", ""))
                yield from below(c)

    def walk(branches, vendor, name):
        for b in branches or []:
            cat, nm = b.get("category"), str(b.get("name", ""))
            v = nm if cat == "vendor" else vendor
            n = nm if cat in ("product_name", "product_family") else name
            if "product" in b:
                pid = b["product"].get("product_id", "")
                rng = " | ".join([nm, *below(b)]) if cat in versions else ""
                out.append(Product(pid, v, n, ("=" + rng) if cat == "product_version" else rng))
            walk(b.get("branches"), v, n)
    walk((doc.get("product_tree") or {}).get("branches"), "", "")
    return out


_CLEAN = re.compile(r"[vV]?\s*(\d+(?:\.\d+)+)(-\d+)?")
_IN_TEXT = re.compile(r"(?<![\w.])[vV]?(\d+(?:\.\d+)+)(-\d+)?(?![\w.])")


def parse_range(text: str) -> dict[str, Any]:
    """A CSAF version range as {'kind': 'all'|'below'|'other', 'bound': str,
    'version': str or None, 'suffix': str}. 'below' is "<X"; X's dotted
    version is 'version' (None when X is not one, like v4.4_SP7)."""
    t = text.strip()
    m = re.match(r"^vers:[a-z0-9]+/(.*)$", t, re.I)
    if m:
        t = m.group(1)
    below, kind = None, "all"
    for part in (p.strip() for p in t.split("|")):
        if part in ("", "*"):
            continue
        if part.startswith(">=") or (part.startswith(">") and not part.startswith(">=")):
            continue                           # a lower bound: older versions aren't listed
        if part.startswith("<") and not part.startswith("<="):
            below = part[1:].strip()
            kind = "below"
        else:
            kind = "other"
            below = " | ".join(x.strip().lstrip("=") for x in t.split("|") if x.strip())
            break
    if kind == "below":
        m = _CLEAN.fullmatch(below)
        return {"kind": kind, "bound": below, "version": m.group(1) if m else None,
                "suffix": (m.group(2) or "") if m else ""}
    return {"kind": kind, "bound": below or "", "version": None, "suffix": ""}


def _vt(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _rank_affected(v: dict, pid: str) -> bool:
    st = v.get("product_status") or {}
    return any(pid in (st.get(k) or []) for k in ("known_affected", "first_affected", "last_affected"))


def _score(v: dict, pid: str) -> float:
    best = 0.0
    for s in v.get("scores") or []:
        if pid in (s.get("products") or []) or not s.get("products"):
            base = (s.get("cvss_v3") or {}).get("baseScore")
            if isinstance(base, (int, float)):
                best = max(best, float(base))
    return best


def _remediations(doc: dict, pid: str) -> tuple[list[str], bool]:
    """(versions named by this product's vendor fixes, whether CISA says
    there is no fix for it)."""
    found, no_fix = [], False
    for v in doc.get("vulnerabilities") or []:
        if not _rank_affected(v, pid):
            continue
        for r in v.get("remediations") or []:
            if pid not in (r.get("product_ids") or []):
                continue
            if r.get("category") in ("none_available", "no_fix_planned"):
                no_fix = True
            elif r.get("category") == "vendor_fix":
                found += [m.group(1) for m in _IN_TEXT.finditer(str(r.get("details", "")))]
    return found, no_fix


def family_for(p: Product) -> Optional[Family]:
    vendor, name = _norm(p.vendor), _norm(p.name)
    for f in FAMILIES:
        if re.search(f.csaf_vendor, vendor) and re.search(f.csaf_product, name):
            return f
    return None


def relevant(p: Product) -> bool:
    vendor, name = _norm(p.vendor), _norm(p.name)
    if re.search(NOT_COVERABLE, name):
        return False
    return any(re.search(v, vendor) and re.search(n, name) for v, n in RELEVANT)


def _product_entry(doc: dict, p: Product, fam: Family) -> Optional[dict[str, Any]]:
    vulns = [v for v in doc.get("vulnerabilities") or [] if _rank_affected(v, p.pid)]
    if not vulns:
        return None
    cves = sorted({v["cve"] for v in vulns if isinstance(v.get("cve"), str)
                   and re.fullmatch(r"CVE-\d{4}-\d{4,8}", v["cve"])})
    cvss = max(_score(v, p.pid) for v in vulns)
    rng = parse_range(p.version) if p.version else {"kind": "all", "bound": "", "version": None,
                                                    "suffix": ""}
    fixed, no_fix, note = None, False, ""
    if fam.check_only:
        note = f"{_norm_title(p.name)}: {_range_text(rng)}"
    elif rng["kind"] == "below" and rng["version"]:
        fixed = rng["version"]
        named, _ = _remediations(doc, p.pid)
        later = [n for n in named if n.split(".")[0] == fixed.split(".")[0] and _vt(n) > _vt(fixed)]
        if later:
            fix = max(later, key=_vt)
            note = f"CISA's product list says before {rng['bound']}; the fix it names is {fix}"
            fixed = fix
        elif rng["suffix"]:
            note = f"fixed in {fixed}{rng['suffix']}"
    elif rng["kind"] == "below":
        note = f"affected before {rng['bound']}: compare the reported version by hand"
    elif rng["kind"] == "all":
        named, none = _remediations(doc, p.pid)
        if named:
            note = f"every version listed; the fix named is {max(named, key=_vt)}: check by hand"
        else:
            no_fix = True
            note = "all versions; no fixed version, mitigations in the advisory"
    else:
        note = f"affected: {rng['bound']}: compare the reported version by hand"
    track = doc["document"]["tracking"]
    rev = str(track.get("version", ""))
    return {"id": track["id"], "published": str(track.get("initial_release_date", ""))[:10],
            "title": _norm_title(doc["document"].get("title", "")), "vendor": fam.vendor,
            "model": fam.model, "field": fam.field, "fixed": fixed, "cves": cves,
            "cvss": cvss, "firmware": fam.firmware, "note": note, "no_fix": no_fix,
            "revision": rev if re.fullmatch(r"\d{1,4}(?:\.\d{1,4}){0,3}", rev) else "",
            "auto": True}


def _range_text(rng: dict) -> str:
    return {"all": "all versions", "below": f"before {rng['bound']}"}.get(
        rng["kind"], rng["bound"].lstrip("="))


def _norm_title(t: str) -> str:
    return re.sub(r"\s+", " ", str(t)).strip()[:300]


def _merge(entries: list[dict], fam: Family) -> dict:
    """One entry for a family from several products of one advisory."""
    first = dict(entries[0])
    first["cves"] = sorted({c for e in entries for c in e["cves"]})
    first["cvss"] = max(e["cvss"] for e in entries)
    if len({(e["fixed"], e["no_fix"]) for e in entries}) > 1:
        fixes = [e["fixed"] for e in entries if e["fixed"]]
        first["fixed"] = max(fixes, key=_vt) if fixes else None
        first["no_fix"] = all(e["no_fix"] for e in entries)
    notes = list(dict.fromkeys(e["note"] for e in entries if e["note"]))
    if fam.check_note:
        notes.append(fam.check_note)
    first["note"] = "; ".join(notes)[:400]
    return first


def releases(p: Product) -> list[int]:
    """The major releases a product line names: "Desigo CC family V8",
    "Desigo CC Compact V4.1", a version "V4.x", or the early "MP2.1"
    (Desigo CC V2.1). Empty when it names none (every release)."""
    m = re.search(r"\bv(\d+)(?:\.\d+)?\b", p.name, re.I)
    if m:
        return [int(m.group(1))]
    found = [int(x) for x in re.findall(r"(?:^|[|=\s])(?:v|mp)?(\d+)\.(?:x|\d+)\b",
                                        p.version, re.I)]
    return sorted(set(found)) if re.search(r"\.x\b|\bmp\d", p.version, re.I) else []


def map_advisory(doc: dict) -> tuple[list[dict], list[Product]]:
    """(the list's entries for this advisory, the building-automation
    products in it that no family covers)."""
    by_family: dict[str, list[dict]] = {}
    uncovered: list[Product] = []
    for p in products(doc):
        fam = family_for(p)
        if fam is None:
            if relevant(p):
                uncovered.append(p)
            continue
        e = _product_entry(doc, p, fam)
        if e is None:
            continue
        majors = releases(p) if fam.by_release else []
        if not majors:
            by_family.setdefault(fam.key, []).append(e)
        for major in majors:
            # Matched on the version the device reports: V9 says "9.00".
            by_family.setdefault(f"{fam.key}@{major}", []).append(
                {**e, "firmware": rf"^\s*v?0*{major}\."})
    fams = {f.key: f for f in FAMILIES}
    entries = [_merge(es, fams[k.split("@")[0]]) for k, es in by_family.items()]
    for e in entries:
        advisories.entry_from_dict(e)            # the app must accept what is written
    return entries, uncovered


# -- the list --------------------------------------------------------------------

def _sort_key(e: dict):
    return (e["published"], e["id"], e["vendor"], e["model"], e["firmware"])


def rebuild(old: list[dict], processed: dict[str, list[dict]]) -> list[dict]:
    """The list's entries after this run: hand-made entries kept; entries
    built for an advisory that was read again replaced by the new ones;
    entries for advisories not read this time kept."""
    manual = {e["id"] for e in old if not e.get("auto", True)}
    keep = [e for e in old if not e.get("auto", True) or e["id"] not in processed]
    new = [e for aid, es in processed.items() if aid not in manual for e in es]
    return sorted(keep + new, key=_sort_key)


def describe_change(old: list[dict], new: list[dict]) -> list[str]:
    o = {(e["id"], e["model"], e["firmware"]): e for e in old}
    n = {(e["id"], e["model"], e["firmware"]): e for e in new}
    lines = []
    for k in sorted(n.keys() - o.keys()):
        e = n[k]
        lines.append(f"added {e['id']} for {e['model']}: "
                     + (f"update to {e['fixed']}" if e["fixed"] else
                        "no fix" if e["no_fix"] else "check"))
    for k in sorted(o.keys() - n.keys()):
        lines.append(f"removed {k[0]} for {k[1]}")
    for k in sorted(o.keys() & n.keys()):
        if advisories.canonical(o[k]) != advisories.canonical(n[k]):
            lines.append(f"revised {k[0]} for {k[1]} (revision {n[k].get('revision') or '?'})")
    return lines


# -- network ---------------------------------------------------------------------

def _get(url: str, limit: int, headers: Optional[dict] = None, tries: int = 4) -> bytes:
    for attempt in range(1, tries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": "HVAC-Network-Scanner-advisory-watch",
                                                   **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read(limit + 1)
            if len(data) > limit:
                raise SystemExit(f"{url}: more than {limit} bytes")
            return data
        except urllib.error.HTTPError as e:
            if (e.code < 500 and e.code != 429) or attempt == tries:
                raise
        except urllib.error.URLError:
            if attempt == tries:
                raise
        time.sleep(5 * attempt)
    raise AssertionError("unreachable")


def watched(feed: dict) -> list[dict]:
    """The feed entries to read: titles naming a watched vendor, with a
    CSAF file in CISA's folder."""
    out = []
    for e in (feed.get("feed") or {}).get("entry") or []:
        src = ((e.get("content") or {}).get("src") or "")
        if not src.startswith(CSAF_BASE) or not _PATH.fullmatch(src[len(CSAF_BASE):]):
            continue
        if TITLE_WATCH.search(str(e.get("title", ""))):
            out.append({"id": e.get("id"), "title": e.get("title", ""), "path": src[len(CSAF_BASE):],
                        "updated": str(e.get("updated", ""))})
    return out


class GitHub:
    def __init__(self, repo: str, token: str):
        self.api = f"https://api.github.com/repos/{repo}"
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def issue_titles(self) -> list[str]:
        titles, page = [], 1
        while True:
            data = json.loads(_get(f"{self.api}/issues?state=all&per_page=100&page={page}",
                                   8 * 1024 * 1024, self.headers))
            titles += [i.get("title", "") for i in data]
            if len(data) < 100:
                return titles
            page += 1

    def open_issue(self, title: str, body: str) -> str:
        req = urllib.request.Request(f"{self.api}/issues", method="POST",
                                     data=json.dumps({"title": title, "body": body}).encode(),
                                     headers={**self.headers, "Content-Type": "application/json",
                                              "User-Agent": "HVAC-Network-Scanner-advisory-watch"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r).get("html_url", "")


def issue_body(doc: dict, uncovered: list[Product]) -> str:
    track = doc["document"]["tracking"]
    url = f"https://www.cisa.gov/news-events/ics-advisories/{track['id'].lower()}"
    rows = "\n".join(f"| {p.vendor} | {p.name} | {p.version or 'not given'} |" for p in uncovered)
    return (f"CISA published or revised [{track['id']}]({url}): "
            f"{_norm_title(doc['document'].get('title', ''))} (revision {track.get('version')}).\n\n"
            f"It covers building-automation products the advisory list can't match yet:\n\n"
            f"| Vendor | Product | Versions affected |\n|---|---|---|\n{rows}\n\n"
            f"To cover them, add a family to `tools/advisory_watch.py` with the model name "
            f"these devices report (from a real device or the vendor's documentation), then "
            f"run `python tools/advisory_watch.py --dry-run` and check the entries. Close this "
            f"issue if they don't apply.\n\nOpened by the advisories workflow.")


# -- main ------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days", type=int, default=30,
                    help="open issues for advisories updated in this many days (default 30)")
    ap.add_argument("--sign", action="store_true", help="write the signed copy as well")
    ap.add_argument("--issues", action="store_true",
                    help="open GitHub issues (GITHUB_TOKEN, GITHUB_REPOSITORY)")
    ap.add_argument("--dry-run", action="store_true", help="print what would change; write nothing")
    ap.add_argument("--feed", help="a local copy of CISA's feed (tests)")
    ap.add_argument("--csaf-dir", help="read CSAF files from this folder (tests)")
    ap.add_argument("--source", default=str(SOURCE))
    ap.add_argument("--signed", default=str(SIGNED))
    ap.add_argument("--today", default=None, help="the date to stamp (tests)")
    ap.add_argument("--message", help="write a commit message here when the list changes")
    a = ap.parse_args(argv)

    feed = json.loads(Path(a.feed).read_bytes() if a.feed else _get(FEED_URL, MAX_FEED))
    picks = watched(feed)
    print(f"{len(picks)} advisories from watched vendors in CISA's feed")

    processed: dict[str, list[dict]] = {}
    review: list[tuple[dict, list[Product]]] = []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=a.days)).isoformat()
    for pick in picks:
        if a.csaf_dir:
            raw = (Path(a.csaf_dir) / Path(pick["path"]).name).read_bytes()
        else:
            raw = _get(CSAF_BASE + pick["path"], MAX_DOC)
        doc = json.loads(raw)
        aid = doc["document"]["tracking"]["id"]
        if not advisories._ID.fullmatch(aid):
            print(f"  skipped {pick['path']}: id {aid!r}")
            continue
        entries, uncovered = map_advisory(doc)
        processed[aid] = entries
        if uncovered and pick["updated"] >= cutoff:
            review.append((doc, uncovered))

    source = Path(a.source)
    obj = json.loads(source.read_text(encoding="utf-8"))
    old = obj["advisories"]
    new = rebuild(old, processed)
    changes = describe_change(old, new)
    for line in changes:
        print("  " + line)
    if changes:
        obj["advisories"] = new
        obj["serial"] = int(obj["serial"]) + 1
        obj["as_of"] = a.today or date.today().isoformat()
        advisories.parse_table(obj)
        print(f"list {obj['serial']}: {len(new)} entries")
    else:
        print(f"no change: list {obj['serial']}, {len(new)} entries")

    if a.dry_run:
        for doc, unc in review:
            print(f"  would open an issue for {doc['document']['tracking']['id']}: "
                  + ", ".join(p.name for p in unc))
        return 0
    if changes:
        source.write_bytes((json.dumps(obj, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
        if a.message:
            Path(a.message).write_text(
                f"Advisory list {obj['serial']}: {len(changes)} change(s) from CISA\n\n"
                + "\n".join(changes) + "\n", encoding="utf-8")
    if a.sign:
        sys.path.insert(0, str(ROOT / "packaging"))
        import signing
        signed = Path(a.signed)
        current = None
        if signed.exists():
            try:
                current = advisories.verify_signed(signed.read_text(encoding="utf-8"))
            except advisories.AdvisoryDataError:
                current = None
        if current is None or advisories.canonical(advisories.table_to_dict(current)) \
                != advisories.canonical(obj):
            if current is not None and obj["serial"] <= current.serial:
                # Changed by hand without a new serial: installed copies take
                # a list only when its serial is higher than theirs.
                obj["serial"] = current.serial + 1
                obj["as_of"] = a.today or date.today().isoformat()
                source.write_bytes((json.dumps(obj, indent=1, ensure_ascii=False) + "\n")
                                   .encode("utf-8"))
            signing.sign_data(signing.data_key_seed(), source, signed)
            print(f"signed: {signed}")
            if a.message and not changes:
                Path(a.message).write_text(f"Advisory list {obj['serial']}: signed\n",
                                           encoding="utf-8")
    if a.issues and review:
        gh = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
        titles = gh.issue_titles()
        for doc, unc in review:
            aid = doc["document"]["tracking"]["id"]
            rev = doc["document"]["tracking"].get("version")
            title = f"{ISSUE_PREFIX} {aid} (revision {rev}) {_norm_title(doc['document'].get('title', ''))}"[:250]
            if any(f"{aid} (revision {rev})" in t for t in titles):
                continue
            print(f"  opened {gh.open_issue(title, issue_body(doc, unc))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
