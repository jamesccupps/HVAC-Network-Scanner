"""The Python half of packaging/test_update.ps1, which updates a copy of the
scanner to this build for real.

    python packaging/update_test_helper.py version
        This tree's version, X.Y.Z.

    python packaging/update_test_helper.py previous
        The newest published release older than this build that has an
        updater (a latest.json asset), as X.Y.Z, or nothing. GITHUB_TOKEN, if
        set, goes to the API.

    python packaging/update_test_helper.py sign RELEASE_DIR VERSION
        Write RELEASE_DIR/latest.json for VERSION, signed with a new
        throwaway key, and print the key's public half. Never the release
        key, so the folder is harmless if it's left behind.

    python packaging/update_test_helper.py drive OLD_SOURCE RELEASE_DIR APP_EXE OLD_PID PUBLIC_KEY [close]
        Run the old copy's own updater (its source, OLD_SOURCE: the previous
        release's, or this tree's when the build updates itself) the way its
        window does when "Update to ..." is clicked: check RELEASE_DIR,
        download, verify, apply. Then end OLD_PID, the old copy that is
        running from APP_EXE, as the window closes itself after apply.
        PUBLIC_KEY stands in for the one built into the old copy. With
        "close" (2.13 and later), install the way the window does when it is
        closed with an update downloaded: nothing is started after the swap.

Adapted from PingerPlot's packaging/update_test_helper.py.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "jamesccupps/HVAC-Network-Scanner"


def _version(text):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _tree_version(root: Path = ROOT) -> str:
    text = (root / "hvac_scanner" / "__init__.py").read_text(encoding="utf-8")
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def version():
    print(_tree_version())


def _get_json(req, tries=4, wait=10):
    """GitHub's answer as JSON, tried again (further apart each time) on no
    answer, a 5xx or a 429; anything else, or the last try, raises."""
    for attempt in range(1, tries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:      # before URLError, its base class
            if (e.code < 500 and e.code != 429) or attempt == tries:
                raise
            why = f"HTTP {e.code}"
        except urllib.error.URLError as e:
            if attempt == tries:
                raise
            why = str(e.reason)
        print(f"GitHub's API failed ({why}); trying again in {wait * attempt} s", file=sys.stderr)
        time.sleep(wait * attempt)


def previous():
    """Prints the version, or nothing when there's no older release with an
    updater. Fails (non-zero) if GitHub can't be asked: printing nothing then
    would quietly turn the cross-version test into the build updating itself."""
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases?per_page=50",
                                 headers={"Accept": "application/vnd.github+json",
                                          "User-Agent": "HVAC-Network-Scanner-update-test"})
    if os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    current = _version(_tree_version())
    older = [(_version(r["tag_name"]), r["tag_name"][1:]) for r in _get_json(req)
             if not r.get("draft") and not r.get("prerelease")
             and _version(r["tag_name"]) and _version(r["tag_name"]) < current
             # Releases before 2.10.0 have no in-app updater to test.
             and any(a.get("name") == "latest.json" for a in r.get("assets", []))]
    if older:
        print(max(older)[1])


def sign(release_dir, version):
    sys.path.insert(0, str(ROOT / "packaging"))
    import signing
    seed = os.urandom(32)
    signing.sign(Path(release_dir), version, seed)
    print(signing.public_key_b64(seed))


def _end_tree(pid: int) -> None:
    """End the process and its children: the one-file exe is a small loader
    that runs the app as a child of itself."""
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def drive(old_source, release_dir, app_exe, old_pid, public_key, mode="click"):
    # Only the old code is importable, never this build's (unless they are
    # the same tree). Its settings folder (APPDATA) is the test's.
    sys.path[0] = str(Path(old_source).resolve())
    from hvac_scanner import __version__, updater
    print(f"the {__version__} updater, as the exe {app_exe}")
    updater.install_kind = lambda: "exe"
    updater.current_exe = lambda: Path(app_exe)
    u = updater.check(current=__version__, source=release_dir, public_key=public_key)
    if u is None:
        raise SystemExit(f"the {__version__} updater found nothing newer in {release_dir}")
    print(f"found {u.version}: {u.asset['file']}, {u.asset['size']:,} bytes")
    path = updater.download(u)
    print(f"downloaded and verified: {path}")
    if mode == "close":
        updater.apply(u, path, restart=False)
    else:
        updater.apply(u, path)
    print(f"applied ({mode}); ending the old copy")
    _end_tree(int(old_pid))
    if not updater._wait_for_exit(int(old_pid), timeout=30):
        raise SystemExit(f"the old copy ({old_pid}) didn't exit")


if __name__ == "__main__":
    command, args = sys.argv[1], sys.argv[2:]
    {"version": version, "previous": previous, "sign": sign, "drive": drive}[command](*args)
