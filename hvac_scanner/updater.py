"""In-app updates: a signed release manifest, a verified download, a swap.

Each release carries ``latest.json``::

    {"payload": base64(JSON), "signature": base64(Ed25519 over the payload)}

    payload = {"app": "hvac-network-scanner", "version": "2.10.0",
               "published": "...",
               "exe": {"file": "HVACNetworkScanner.exe", "size": N, "sha256": "..."}}

The app checks the signature against the public key built into it
(update_key.py), and only then trusts the size and hash; a download that
doesn't match them is deleted. Nothing is downloaded without a click.

The executable is one file, so installing is a swap: the new exe is
downloaded to a temporary folder and started with ``--finish-update``; it
waits for this copy to exit, renames the old exe to ``<name>.old``, copies
itself into place and starts the updated app with ``--updated``, which
deletes the ``.old`` copy. If anything fails the old exe is put back and
started with ``--update-failed``. A copy run from source (or pip) is only
told that a new version exists.

The design is the one PingerPlot and UniFi Stock Watcher use (sibling
projects). What this reads from a release can never change, as every copy
out there reads it: the asset names, the manifest's shape, the tag vX.Y.Z.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit

from . import __version__, ed25519
from .update_key import UPDATE_PUBLIC_KEY

log = logging.getLogger(__name__)

REPO = "jamesccupps/HVAC-Network-Scanner"
APP_KEY = "hvac-network-scanner"
MANIFEST_NAME = "latest.json"
EXE_NAME = "HVACNetworkScanner.exe"
DEFAULT_SOURCE = f"https://github.com/{REPO}/releases/latest/download/{MANIFEST_NAME}"
RELEASES_URL = f"https://github.com/{REPO}/releases"
SOURCE_ENV = "HVAC_UPDATE_URL"           # a URL or a folder: tests, mirrors

MAX_MANIFEST = 64 * 1024
MAX_DOWNLOAD = 200 * 1024 * 1024

_VERSION_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,6})$")
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_GITHUB_LATEST = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/latest/download/latest\.json$")


class UpdateError(Exception):
    """Anything that stops an update: a bad signature, a short download..."""


def parse_version(v) -> Optional[tuple[int, int, int]]:
    m = _VERSION_RE.fullmatch(v) if isinstance(v, str) else None
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


def update_source() -> str:
    """Where latest.json comes from: HVAC_UPDATE_URL (a URL or a folder) or
    this repository's latest release."""
    return os.environ.get(SOURCE_ENV) or DEFAULT_SOURCE


def install_kind() -> str:
    """'exe' for the packaged executable, which can update itself; 'source'
    for a run from source or a pip install, which is only told."""
    return "exe" if getattr(sys, "frozen", False) else "source"


# -- manifest ------------------------------------------------------------------

def _check_asset(asset, name):
    if asset is None:
        return None
    if not isinstance(asset, dict):
        raise UpdateError(f"{name}: not an object")
    f, size, sha = asset.get("file"), asset.get("size"), asset.get("sha256")
    # A bare file name: the manifest says what to fetch, never from where.
    if not (isinstance(f, str) and _FILE_RE.fullmatch(f)):
        raise UpdateError(f"{name}: bad file name {f!r}")
    if not (isinstance(size, int) and not isinstance(size, bool) and 0 < size <= MAX_DOWNLOAD):
        raise UpdateError(f"{name}: bad size {size!r}")
    if not (isinstance(sha, str) and _SHA_RE.fullmatch(sha)):
        raise UpdateError(f"{name}: bad sha256")
    return {"file": f, "size": size, "sha256": sha}


def verify_manifest(text: str, public_key: Optional[str] = None) -> dict:
    """The manifest's payload, if and only if it is signed by `public_key`
    (base64 of the raw 32-byte key; the one built into the app by default)
    and well-formed."""
    public_key = public_key or UPDATE_PUBLIC_KEY
    try:
        outer = json.loads(text)
        payload = base64.b64decode(outer["payload"], validate=True)
        signature = base64.b64decode(outer["signature"], validate=True)
        key = base64.b64decode(public_key, validate=True)
    except (ValueError, KeyError, TypeError) as e:
        raise UpdateError(f"latest.json is malformed: {e}") from e
    if not ed25519.verify(key, payload, signature):
        raise UpdateError("latest.json isn't signed with the key this app trusts")
    try:
        m = json.loads(payload)
    except ValueError as e:
        raise UpdateError("latest.json's payload isn't JSON") from e
    if not isinstance(m, dict) or m.get("app") != APP_KEY:
        raise UpdateError("latest.json is for another app")
    if parse_version(m.get("version")) is None:
        raise UpdateError(f"latest.json has a bad version {m.get('version')!r}")
    return {
        "version": m["version"],
        "published": m.get("published") if isinstance(m.get("published"), str) else None,
        "exe": _check_asset(m.get("exe"), "exe"),
    }


# -- fetching ------------------------------------------------------------------

def _is_url(source: str) -> bool:
    return urlsplit(source).scheme in ("http", "https")


def asset_location(source: str, version: str, name: str) -> str:
    """Where a release file lives, next to its manifest. For GitHub's
    /releases/latest/ URL, from that version's own tag: a release published
    between reading the manifest and the download would otherwise hand over
    the next version's file (refused by its hash, but a failed update)."""
    m = _GITHUB_LATEST.match(source)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}/releases/download/v{version}/{name}"
    if _is_url(source):
        return urljoin(source, name)
    p = Path(source)
    return str((p.parent if p.suffix.lower() == ".json" else p) / name)


def _open(url: str, timeout: float):
    req = urllib.request.Request(url, headers={"User-Agent": f"HVAC-Scanner/{__version__}"})
    return urllib.request.urlopen(req, timeout=timeout)


def _read_manifest(source: str) -> Optional[str]:
    if _is_url(source):
        try:
            with _open(source, 20) as r:
                data = r.read(MAX_MANIFEST + 1)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # The latest release has no latest.json (one from before
                # 2.10, or made by hand): nothing to install.
                return None
            raise
    else:
        p = Path(source)
        if p.is_dir():
            p = p / MANIFEST_NAME
        with open(p, "rb") as fh:
            data = fh.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise UpdateError("latest.json is too big")
    return data.decode("utf-8")


@dataclass
class Update:
    version: str
    published: Optional[str]
    kind: str                 # install_kind() at check time
    asset: Optional[dict]     # what this copy would download; None for source runs
    source: str

    @property
    def can_install(self) -> bool:
        return self.asset is not None


def check(current: str = __version__, source: Optional[str] = None,
          public_key: Optional[str] = None) -> Optional[Update]:
    """The newer release, or None when this copy is up to date. Raises
    UpdateError (or OSError for the network) when it can't tell."""
    source = source or update_source()
    text = _read_manifest(source)
    if text is None:
        log.info("no latest.json at %s; nothing to install", source)
        return None
    m = verify_manifest(text, public_key)
    if parse_version(m["version"]) <= (parse_version(current) or (0, 0, 0)):
        return None
    kind = install_kind()
    return Update(m["version"], m["published"], kind,
                  m["exe"] if kind == "exe" else None, source)


def download(update: Update, dest_dir=None,
             progress: Optional[Callable[[int, int], None]] = None,
             cancel: Optional[Callable[[], bool]] = None) -> Path:
    """Fetch the update's exe, check its size and SHA-256, return its path.
    progress(done, total) is called as it arrives; cancel() returning True
    stops it."""
    if not update.can_install:
        raise UpdateError("nothing to download for this kind of copy")
    a = update.asset
    dest_dir = Path(dest_dir or staging_dir(update.version))
    dest_dir.mkdir(parents=True, exist_ok=True)
    final, part = dest_dir / a["file"], dest_dir / (a["file"] + ".part")
    where = asset_location(update.source, update.version, a["file"])
    digest, done = hashlib.sha256(), 0
    try:
        with open(part, "wb") as out:
            src = _open(where, 60) if _is_url(where) else open(where, "rb")
            with src:
                for chunk in iter(lambda: src.read(256 * 1024), b""):
                    if cancel and cancel():
                        raise UpdateError("download cancelled")
                    done += len(chunk)
                    if done > a["size"]:
                        raise UpdateError(f"{a['file']} is bigger than latest.json says")
                    digest.update(chunk)
                    out.write(chunk)
                    if progress:
                        progress(done, a["size"])
        if done != a["size"] or digest.hexdigest() != a["sha256"]:
            raise UpdateError(f"{a['file']} doesn't match latest.json "
                              f"({done} bytes, sha256 {digest.hexdigest()[:12]}…)")
        os.replace(part, final)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    log.info("%s %s downloaded and verified (%d bytes)", update.version, a["file"], done)
    return final


def staging_dir(version: str) -> Path:
    return Path(tempfile.gettempdir()) / f"HVACNetworkScanner-update-{version}"


# -- installing ----------------------------------------------------------------

_DETACHED = 0x00000008 | 0x00000200     # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP


def _spawn(args, cwd) -> subprocess.Popen:
    kwargs = {"cwd": str(cwd), "close_fds": True, "stdin": subprocess.DEVNULL,
              "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":
        kwargs["creationflags"] = _DETACHED
    return subprocess.Popen([str(a) for a in args], **kwargs)


def folder_is_writable(folder) -> bool:
    probe = Path(folder) / f".write-test-{os.getpid()}"
    try:
        probe.write_bytes(b"")
        probe.unlink()
        return True
    except OSError:
        return False


def current_exe() -> Path:
    return Path(sys.executable).resolve()


def apply(update: Update, path: Path) -> None:
    """Start installing the downloaded exe at `path`. The caller must exit
    straight away after: the new exe waits for this process to end."""
    target = current_exe()
    if not folder_is_writable(target.parent):
        raise UpdateError(f"{target.parent} can't be written to. Move the scanner to a "
                          f"folder of your own, or download the new version from "
                          f"{RELEASES_URL}.")
    log.info("starting the downloaded %s to swap it in", update.version)
    # Its working folder is the staging folder, never the program's.
    _spawn([path, "--finish-update", target, os.getpid()], cwd=path.parent)


def update_log() -> Path:
    from .settings import default_path
    return default_path().parent / "update.log"


def _ulog(msg: str, path: Optional[Path] = None) -> None:
    try:
        path = path or update_log()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


def _wait_for_exit(pid: int, timeout: float = 60) -> bool:
    if sys.platform != "win32":
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                os.kill(pid, 0)
            except OSError:
                return True
            time.sleep(0.2)
        return False
    import ctypes
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x00100000, False, pid)          # SYNCHRONIZE
    if not h:
        return True                                       # already gone
    try:
        return k32.WaitForSingleObject(h, int(timeout * 1000)) == 0
    finally:
        k32.CloseHandle(h)


def _retry(fn, tries: int = 40, delay: float = 0.25):
    for i in range(tries):
        try:
            return fn()
        except OSError:
            if i == tries - 1:
                raise
            time.sleep(delay)


def old_copy(target: Path) -> Path:
    return target.with_name(target.name + ".old")


def swap_in(target: Path, new_exe: Path) -> None:
    """Put `new_exe` at `target`: the old one renamed to <name>.old first,
    then the copy. On failure the copy is removed and the old one renamed
    back, so `target` is always one of the two whole files."""
    target, new_exe = Path(target), Path(new_exe)
    old = old_copy(target)
    if old.exists():
        _retry(lambda: old.unlink())
    renamed = False
    try:
        if target.exists():
            _retry(lambda: target.rename(old))
            renamed = True
        shutil.copy2(new_exe, target)
    except BaseException:
        try:
            _retry(lambda: target.unlink(missing_ok=True), tries=10)
        except OSError:
            pass
        if renamed:
            _retry(lambda: old.rename(target), tries=10)
        raise


def finish_update(target, pid, new_exe=None) -> int:
    """Run by the downloaded exe: swap it in at `target` once process `pid`
    has ended, then start it there. Returns the exit code."""
    target = Path(target)
    new_exe = Path(new_exe) if new_exe else current_exe()
    _ulog(f"update: {__version__} waiting for {pid} to exit")
    if not _wait_for_exit(int(pid)):
        _ulog("update: the old copy didn't exit; giving up")
        return 1
    try:
        swap_in(target, new_exe)
    except Exception as e:
        _ulog(f"update: failed, previous version kept: {e!r}")
        _spawn([target, "--update-failed"], cwd=target.parent)
        return 1
    _ulog(f"update: done, starting {__version__}")
    _spawn([target, "--updated"], cwd=target.parent)
    return 0


def cleanup_after_update(exe: Optional[Path] = None) -> None:
    """Run by the updated copy as it starts (``--updated``): note that it did
    in the update log, then remove what the swap left: the .old exe beside
    this one and the staging folders. Anything still locked is left for
    next time."""
    exe = exe or current_exe()
    _ulog(f"update: {__version__} started")
    try:
        old_copy(exe).unlink(missing_ok=True)
    except OSError:
        pass
    for p in Path(tempfile.gettempdir()).glob("HVACNetworkScanner-update-*"):
        shutil.rmtree(p, ignore_errors=True)
