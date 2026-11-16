"""Scan a release file with VirusTotal and report what the engines say.

    python packaging/virustotal.py FILE [--report report.json] [--summary PATH]
                                        [--rescan] [--wait SECONDS]

Uploads FILE, or uses the report VirusTotal already has for its SHA-256
(--rescan asks for a fresh analysis of a file it knows), waits for the
engines, prints the result and writes it as JSON (--report) and as Markdown
(--summary: the GitHub job summary). The key is the VT_API_KEY environment
variable, a repository secret in CI. Standard library only: the CI job that
runs this installs nothing.

Only release builds go through this: anything uploaded is shared with the
security vendors, which is fine for a file that is about to be public.

Exit codes:
  0  scanned, and no engine in BLOCKING flagged it. Others may have: a
     one-file PyInstaller executable draws machine-learning false positives
     (2.13.0 unsigned: 4 of 71; 2.13.1 signed: 1). They are reported, to be
     sent to the vendor as false positives, not fatal.
     Also 0, with a warning, when there is no key or VirusTotal couldn't
     finish: an outage shouldn't hold a release.
  1  an engine in BLOCKING flagged it: Microsoft (Defender), the one every
     Windows user runs. Don't publish until that is cleared.
  2  bad usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui/file/"
BLOCKING = ("Microsoft",)
POLL_S = 20.0                 # the free API allows 4 requests a minute
QUOTA_WAIT_S = 65.0           # after a 429, wait out the minute
DIRECT_UPLOAD_MAX = 32 * 1024 * 1024
FLAGGED = ("malicious", "suspicious")


class Unavailable(Exception):
    """VirusTotal couldn't be asked or didn't finish: not a verdict."""


def _request(method: str, path: str, key: str, data: Optional[bytes] = None,
             headers: Optional[dict] = None, url: Optional[str] = None,
             tries: int = 4) -> Optional[dict]:
    """JSON from the API; None for 404. Retries a 429 or a 5xx."""
    for attempt in range(1, tries + 1):
        req = urllib.request.Request(url or f"{API}{path}", data=data, method=method,
                                     headers={"x-apikey": key, "accept": "application/json",
                                              "User-Agent": "hvac-network-scanner-release",
                                              **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (401, 403):
                raise Unavailable(f"VirusTotal refused the key (HTTP {e.code})") from None
            if (e.code == 429 or e.code >= 500) and attempt < tries:
                time.sleep(QUOTA_WAIT_S if e.code == 429 else POLL_S)
                continue
            raise Unavailable(f"{method} {path or 'upload'}: HTTP {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            if attempt < tries:
                time.sleep(POLL_S)
                continue
            raise Unavailable(f"{method} {path or 'upload'}: {e}") from None
    raise AssertionError("unreachable")


def _multipart(name: str, content: bytes) -> tuple[bytes, str]:
    boundary = f"----hvac{uuid.uuid4().hex}"
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
    return head + content + f"\r\n--{boundary}--\r\n".encode(), \
        f"multipart/form-data; boundary={boundary}"


def _upload(path: Path, key: str) -> str:
    content = path.read_bytes()
    body, ctype = _multipart(path.name, content)
    url = None
    if len(content) > DIRECT_UPLOAD_MAX:
        url = (_request("GET", "/files/upload_url", key) or {}).get("data")
        if not url:
            raise Unavailable("no upload URL for a large file")
    resp = _request("POST", "/files", key, data=body, headers={"Content-Type": ctype}, url=url)
    analysis = ((resp or {}).get("data") or {}).get("id")
    if not analysis:
        raise Unavailable("the upload returned no analysis")
    return analysis


def _wait(analysis: str, key: str, wait_s: float) -> dict:
    deadline = time.monotonic() + wait_s
    while True:
        attrs = ((_request("GET", f"/analyses/{analysis}", key) or {}).get("data") or {}) \
            .get("attributes") or {}
        if attrs.get("status") == "completed":
            return attrs
        if time.monotonic() > deadline:
            raise Unavailable(f"no result after {wait_s:.0f} s (status {attrs.get('status')!r})")
        time.sleep(POLL_S)


def _verdict(sha256: str, stats: dict, results: dict, source: str) -> dict[str, Any]:
    flagged = sorted(({"engine": name, "category": r.get("category"), "result": r.get("result")}
                      for name, r in (results or {}).items() if r.get("category") in FLAGGED),
                     key=lambda f: f["engine"].lower())
    verdicts = sum(int(stats.get(k, 0) or 0)
                   for k in ("malicious", "suspicious", "undetected", "harmless"))
    return {"status": "scanned", "source": source, "sha256": sha256, "link": GUI + sha256,
            "stats": stats, "engines": verdicts, "flagged": flagged,
            "blocking": [f["engine"] for f in flagged if f["engine"] in BLOCKING],
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def scan(path: Path, key: str, rescan: bool = False, wait_s: float = 900.0) -> dict[str, Any]:
    """The verdict for `path`; raises Unavailable when there is none."""
    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    known = _request("GET", f"/files/{sha256}", key)
    attrs = ((known or {}).get("data") or {}).get("attributes") or {}
    if known and attrs.get("last_analysis_results") and not rescan:
        return _verdict(sha256, attrs.get("last_analysis_stats") or {},
                        attrs["last_analysis_results"], "existing report")
    if known:
        resp = _request("POST", f"/files/{sha256}/analyse", key, data=b"")
        analysis = ((resp or {}).get("data") or {}).get("id")
        if not analysis:
            raise Unavailable("the rescan request returned no analysis")
        source = "rescan"
    else:
        analysis = _upload(path, key)
        source = "upload"
    done = _wait(analysis, key, wait_s)
    return _verdict(sha256, done.get("stats") or {}, done.get("results") or {}, source)


def summary_markdown(name: str, v: dict[str, Any]) -> str:
    if v["status"] != "scanned":
        return f"### VirusTotal\n\n{name} was **not scanned**: {v['reason']}\n"
    n = len(v["flagged"])
    lines = ["### VirusTotal\n",
             f"**{n} of {v['engines']} engines** flagged {name} "
             f"([report]({v['link']}), {v['source']}).\n"]
    if v["blocking"]:
        lines.append(f"**{', '.join(v['blocking'])} flagged it: don't publish until that is "
                     f"cleared.**\n")
    if n:
        lines.append("| Engine | Says |\n|---|---|")
        lines += [f"| {f['engine']} | {f['category']}: `{f['result']}` |" for f in v["flagged"]]
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file")
    ap.add_argument("--report", help="write the verdict here as JSON")
    ap.add_argument("--summary", help="append the verdict here as Markdown")
    ap.add_argument("--rescan", action="store_true",
                    help="ask for a fresh analysis even if VirusTotal knows the file")
    ap.add_argument("--wait", type=float, default=900.0, help="most seconds to wait (900)")
    a = ap.parse_args(argv)
    path = Path(a.file)
    if not path.is_file():
        print(f"no such file: {path}", file=sys.stderr)
        return 2
    in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    key = os.environ.get("VT_API_KEY", "").strip()
    try:
        if not key:
            raise Unavailable("no VT_API_KEY")
        v = scan(path, key, rescan=a.rescan, wait_s=a.wait)
    except Unavailable as e:
        v = {"status": "not scanned", "reason": str(e),
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    if a.report:
        Path(a.report).write_text(json.dumps(v, indent=2) + "\n", encoding="utf-8")
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as f:
            f.write(summary_markdown(path.name, v))
    if v["status"] != "scanned":
        print(f"{'::warning::' if in_ci else 'WARNING: '}{path.name} not scanned by "
              f"VirusTotal: {v['reason']}")
        return 0
    print(f"VirusTotal: {len(v['flagged'])} of {v['engines']} engines flagged {path.name} "
          f"({v['source']}) {v['link']}")
    for f in v["flagged"]:
        print(f"  {f['engine']}: {f['category']} {f['result']}")
    if v["blocking"]:
        print(f"{'::error::' if in_ci else 'ERROR: '}{', '.join(v['blocking'])} flagged "
              f"{path.name}: don't publish it until that is cleared")
        return 1
    if v["flagged"] and in_ci:
        print(f"::warning::{len(v['flagged'])} engine(s) flagged {path.name}: "
              + ", ".join(f["engine"] for f in v["flagged"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
