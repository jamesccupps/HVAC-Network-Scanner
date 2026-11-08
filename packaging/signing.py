"""The release-signing key and latest.json, the manifest the updater trusts.

    python packaging/signing.py new-key
        One-time setup. Writes a new Ed25519 private key to KEY_FILE (below)
        and its public half into hvac_scanner/update_key.py, which ships in
        the app. Refuses to replace an existing key.

    python packaging/signing.py sign DIR [VERSION]
        Writes DIR/latest.json: the size and SHA-256 of DIR's
        HVACNetworkScanner.exe, signed with the private key.

    python packaging/signing.py verify DIR [VERSION]
        Checks DIR/latest.json the way the app will: its signature against
        the public key built into the app, then the exe it lists. Exits
        non-zero on any mismatch, so a release signed with the wrong key is
        stopped before it is published rather than by users' updaters.

    python packaging/signing.py new-data-key | sign-data | verify-data
        The advisory list's own key (ADVISORY_PUBLIC_KEY in update_key.py),
        and data/advisories.signed.json: hvac_scanner/advisories.json signed
        with it, and checked the way the app does. The advisories workflow
        signs with the key in its ADVISORY_SIGNING_KEY secret.

The private key is read from the file named by HVAC_SIGNING_KEY, or
~/.hvac-scanner/update-signing-key.pem. It never goes in the repository.
Releases are signed on the maintainer's PC when the draft is made, so no
repository secret holds it either.

Back the key up. Lose it and installed copies can no longer update in place:
they would need one manual download of a build carrying a new public key.

Standard library only: the key is a PKCS#8 PEM (what ``openssl genpkey
-algorithm ed25519`` writes), and hvac_scanner/ed25519.py signs. Adapted from
PingerPlot's packaging/signing.py.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hvac_scanner import __version__, advisories, ed25519, updater  # noqa: E402

KEY_ENV = "HVAC_SIGNING_KEY"
DEFAULT_KEY = Path.home() / ".hvac-scanner" / "update-signing-key.pem"
PUBLIC_FILE = ROOT / "hvac_scanner" / "update_key.py"

# The advisory list's key: a file (HVAC_ADVISORY_KEY, or the default below)
# on the maintainer's PC, or the PEM text itself in ADVISORY_SIGNING_KEY,
# which is how the advisories workflow passes its repository secret.
DATA_KEY_ENV = "HVAC_ADVISORY_KEY"
DATA_KEY_TEXT_ENV = "ADVISORY_SIGNING_KEY"
DEFAULT_DATA_KEY = Path.home() / ".hvac-scanner" / "advisory-signing-key.pem"
DATA_SOURCE = ROOT / "hvac_scanner" / "advisories.json"
DATA_SIGNED = ROOT / "data" / "advisories.signed.json"

# PKCS#8 for Ed25519 is a fixed 16-byte DER header and the 32-byte seed
# (RFC 8410, section 7).
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def key_file() -> Path:
    return Path(os.environ.get(KEY_ENV) or DEFAULT_KEY)


def pem_from_seed(seed: bytes) -> str:
    b64 = base64.b64encode(_PKCS8_PREFIX + seed).decode("ascii")
    return f"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n"


def seed_from_pem(text: str) -> bytes:
    lines = [ln.strip() for ln in text.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN PRIVATE KEY-----" \
            or lines[-1] != "-----END PRIVATE KEY-----":
        raise ValueError("not a PKCS#8 PEM private key")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(der) != 48 or not der.startswith(_PKCS8_PREFIX):
        raise ValueError("not an unencrypted Ed25519 private key")
    return der[16:]


def public_key_b64(seed: bytes) -> str:
    return base64.b64encode(ed25519.public_key(seed)).decode("ascii")


def write_public_key(public_b64: str, path: Path = PUBLIC_FILE,
                     name: str = "UPDATE_PUBLIC_KEY") -> None:
    """Set `name` in update_key.py, leaving the other key as it is."""
    text = path.read_text(encoding="utf-8")
    line = re.compile(rf'^{name} = "[^"]*"$', re.M)
    if not line.search(text):
        raise SystemExit(f"{path} has no {name} line")
    path.write_bytes(line.sub(f'{name} = "{public_b64}"', text).encode("utf-8"))


def new_key(path: Path) -> str:
    """Create the private key file (never replacing one); return the public
    key, base64."""
    seed = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
        fh.write(pem_from_seed(seed))
    return public_key_b64(seed)


def manifest(folder: Path, version: str, seed: bytes, published: str | None = None) -> str:
    """latest.json's text for the exe in `folder`."""
    exe = Path(folder) / updater.EXE_NAME
    if not exe.is_file():
        raise SystemExit(f"{exe} not found")
    data = exe.read_bytes()
    payload = {"app": updater.APP_KEY, "version": version,
               "published": published or datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "exe": {"file": exe.name, "size": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()}}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return json.dumps({"payload": base64.b64encode(raw).decode("ascii"),
                       "signature": base64.b64encode(ed25519.sign(seed, raw)).decode("ascii")},
                      indent=2) + "\n"


def sign(folder: Path, version: str, seed: bytes) -> Path:
    out = Path(folder) / updater.MANIFEST_NAME
    out.write_bytes(manifest(folder, version, seed).encode("utf-8"))
    return out


def verify(folder: Path, expected: str | None = None, public_key: str | None = None) -> list[str]:
    """What verify prints, line by line. Raises UpdateError or SystemExit."""
    folder = Path(folder)
    m = updater.verify_manifest((folder / updater.MANIFEST_NAME).read_text(encoding="utf-8"),
                                public_key)
    if expected and m["version"] != expected:
        raise SystemExit(f"latest.json says {m['version']}, expected {expected}")
    a = m["exe"]
    if a is None:
        raise SystemExit("latest.json lists no exe")
    data = (folder / a["file"]).read_bytes()
    if len(data) != a["size"] or hashlib.sha256(data).hexdigest() != a["sha256"]:
        raise SystemExit(f"{a['file']}: size or SHA-256 doesn't match latest.json")
    return [f"ok  {a['file']}  {len(data)} bytes  sha256 {a['sha256']}",
            f"ok  latest.json  version {m['version']}, signed by the key this app trusts"]


def data_key_seed() -> bytes:
    """The advisory list's private key: the PEM text in ADVISORY_SIGNING_KEY,
    else the file HVAC_ADVISORY_KEY names, else the default file."""
    text = os.environ.get(DATA_KEY_TEXT_ENV)
    if not text:
        text = Path(os.environ.get(DATA_KEY_ENV) or DEFAULT_DATA_KEY).read_text(encoding="ascii")
    return seed_from_pem(text)


def sign_data(seed: bytes, source: Path = DATA_SOURCE, out: Path = DATA_SIGNED) -> Path:
    """Write the signed copy of the advisory list `source` to `out`."""
    obj = json.loads(Path(source).read_text(encoding="utf-8"))
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(advisories.signed_text(obj, seed).encode("utf-8"))
    return out


def verify_data(signed: Path = DATA_SIGNED, source: Path | None = DATA_SOURCE,
                public_key: str | None = None) -> list[str]:
    """Check the signed list the way the app does, and that it holds the
    same list as `source`. Raises AdvisoryDataError or SystemExit."""
    t = advisories.verify_signed(Path(signed).read_text(encoding="utf-8"), public_key)
    if source is not None:
        want = advisories.canonical(json.loads(Path(source).read_text(encoding="utf-8")))
        if advisories.canonical(advisories.table_to_dict(t)) != want:
            raise SystemExit(f"{signed} doesn't hold the list in {source}: sign it again")
    return [f"ok  {Path(signed).name}  list {t.serial} as of {t.as_of}, "
            f"{len(t.advisories)} entries, signed by the key this app trusts"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("new-key")
    sub.add_parser("new-data-key")
    sub.add_parser("sign-data")
    sub.add_parser("verify-data")
    for name in ("sign", "verify"):
        p = sub.add_parser(name)
        p.add_argument("folder")
        p.add_argument("version", nargs="?", default=None)
    a = ap.parse_args(argv)

    if a.cmd == "new-key":
        path = key_file()
        if path.exists():
            raise SystemExit(f"{path} already exists; refusing to replace it. Releases signed "
                             "with a new key can't update copies that trust the old one.")
        write_public_key(new_key(path))
        print(f"private key: {path}  (back this up; keep it out of the repository)")
        print(f"public key:  {PUBLIC_FILE}")
        return 0
    if a.cmd == "new-data-key":
        path = Path(os.environ.get(DATA_KEY_ENV) or DEFAULT_DATA_KEY)
        if path.exists():
            raise SystemExit(f"{path} already exists; refusing to replace it.")
        write_public_key(new_key(path), name="ADVISORY_PUBLIC_KEY")
        print(f"private key: {path}  (store it as the ADVISORY_SIGNING_KEY repository "
              f"secret; keep it out of the repository)")
        print(f"public key:  {PUBLIC_FILE}")
        return 0
    if a.cmd == "sign-data":
        print("signed:", sign_data(data_key_seed()))
        return 0
    if a.cmd == "verify-data":
        try:
            for line in verify_data():
                print(line)
        except advisories.AdvisoryDataError as e:
            raise SystemExit(f"advisory list: {e}") from e
        return 0
    version = (a.version or __version__).lstrip("v")
    if a.cmd == "sign":
        seed = seed_from_pem(key_file().read_text(encoding="ascii"))
        print("signed:", sign(Path(a.folder), version, seed))
        return 0
    try:
        for line in verify(Path(a.folder), version if a.version else None):
            print(line)
    except updater.UpdateError as e:
        raise SystemExit(f"latest.json: {e}") from e
    return 0


if __name__ == "__main__":
    sys.exit(main())
