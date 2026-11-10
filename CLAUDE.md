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
- Sign files before publishing. `latest.json` is signed while the release is
  still a draft (`packaging/signing.py`); if the exe is ever code-signed, that
  happens before publishing too. Never replace a file on a release that's
  already out: Scoop and winget have recorded its hash. Fix it with a new
  version.
- If a file name must change, update `bucket/hvac-network-scanner.json` in
  jamesccupps/scoop-bucket in the same change.
