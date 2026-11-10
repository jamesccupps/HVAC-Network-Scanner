# HVAC Network Scanner

Notes for Claude Code working in this repository.

## Releases

Two things read this project's GitHub releases: the Scoop bucket
([jamesccupps/scoop-bucket](https://github.com/jamesccupps/scoop-bucket),
`bucket/hvac-network-scanner.json`, which updates itself from each release),
and the scanner's own updater. To keep both working:

- Tag releases `vX.Y.Z` and publish them as the latest release, not a
  pre-release.
- Keep the release file names unchanged: `HVACNetworkScanner.exe`,
  `HVACNetworkScanner.exe.sha256` and `latest.json`. Scoop downloads the exe
  and checks it against the `.sha256`; installed copies read `latest.json`.
- Keep publishing `HVACNetworkScanner.exe.sha256` alongside the exe.
- Sign files before publishing. CI Authenticode-signs the exe before it makes
  the `HVACNetworkScanner-windows-exe` artifact (see Code signing), so the
  release is made from that artifact as it is: its exe and `.sha256` are the
  signed file's. `latest.json` is signed from that same exe while the release
  is still a draft (`packaging/signing.py`). Never replace a file on a release
  that's already out: Scoop and winget have recorded its hash. Fix it with a
  new version.
- If a file name must change, update `bucket/hvac-network-scanner.json` in
  jamesccupps/scoop-bucket in the same change.

## Code signing

From 2.13.1 the exe is Authenticode-signed as James Cupps: Azure Artifact
Signing, the account and certificate Slate, NoteForge, PingerPlot, UniFi Stock
Watcher and Protect Panes use (account `SlateAccount`, profile `Slate`,
endpoint `https://eus.codesigning.azure.net/`). The app registration "Slate
signing" has a federated credential for
`repo:jamesccupps/HVAC-Network-Scanner:environment:release` (this repository
sends GitHub's classic subject format; checked 2026-11-10 with a throwaway
branch printing only the token's `sub`). The `release` environment admits `v*`
tags only, and the `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and
`AZURE_SUBSCRIPTION_ID` secrets name the app registration. No password or key
is stored. One signature a release.

ci.yml on a tag: `windows-exe` builds (PyPI tooling, no secrets) →
`authenticode` signs (only pinned actions, Microsoft's ArtifactSigning module
and `packaging/authenticode.ps1`; no PyPI, never the program) → `verify` tests
the signed file (`packaging/check_signatures.ps1`, smoke tests, the update
test), hashes it and uploads the artifact → `attest` (Sigstore) attests it.
`tests/test_release_signing.py` holds those rules. A dispatched run builds and
tests unsigned. A tag `vX.Y.Z-signtest.N` (the version in the source) runs it
all for trying a signing change; don't release from it, and delete the tag.

Authenticode sits beside the Ed25519 `latest.json`, not instead of it: the
updater checks only the manifest. Before signing, VirusTotal had the unsigned
2.13.0 exe at 4/71 (Bkav, SecureAge, SentinelOne Static ML, Skyhigh: generic
and ML heuristics, the usual pattern for a one-file PyInstaller exe); Microsoft
and the other major engines were clean.
