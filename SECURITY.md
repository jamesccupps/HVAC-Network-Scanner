# Security policy

HVAC Network Scanner runs on building-control networks and reads whatever the devices there send back, so security reports are taken seriously.

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private vulnerability reporting instead:
**Security → Report a vulnerability** on this repository
(<https://github.com/jamesccupps/HVAC-Network-Scanner/security/advisories/new>). Only the maintainer sees it.

Include:
- what an attacker could do with it;
- the steps to reproduce (a capture, or a device added to `tools/sim_site.py`, helps);
- the scanner version (the window title, or `--version`).

You should hear back within a week. Fixes are credited in the release notes unless you'd rather not be named.

## What counts

The scanner reads and never writes; [Safety and legal](README.md#safety-and-legal) lists exactly what it sends. Of particular interest:

- **Anything that makes it send a write** or another state-changing request beyond that list, or send anything to a host outside the targets you gave it.
- **A hostile device.** Anything on the network can answer a scan. A reply that crashes or hangs the scanner, runs code, puts script into the HTML survey report or a formula into a CSV export, or makes it write a file other than the export you asked for, is in scope.
- **The updater and the advisory list.** Installing an update, or loading an advisory list, that isn't signed with the project's key.
- **Site data in exports:** a site's own SNMP community in any export, or addresses and names in the classification report, which leaves them out.

## What doesn't

These are by design, and the README describes them:

- **The default-credentials list** shows the factory defaults each vendor publishes, so an owner can check they were changed. The scanner shows them and never tries them.
- **SNMP** asks with a community string (`public` unless you set others), in cleartext, as SNMP v1 and v2c do. Turn SNMP off where that matters.
- **BBMD registration** (`--bbmd`, off by default) is a write: a foreign-device entry that lasts at most 300 seconds (plus BACnet's 30-second grace) after the scan stops renewing it.
- **Vulnerabilities in the equipment the scanner finds** belong with that equipment's vendor (for Siemens, [ProductCERT](mailto:productcert@siemens.com)) or with CISA. A controller that crashes on one of the scanner's ordinary reads has a flaw of its own: report it to the vendor, and open an issue here as well so the scanner's profile for it can go easier.

## Supported versions

The latest release. The scanner updates itself; older versions don't get fixes.

## How releases are protected

- `HVACNetworkScanner.exe` is code-signed, comes with a SHA-256 hash and a build attestation, and is checked with VirusTotal before the release is published.
- The update manifest and the advisory list are signed with the project's Ed25519 key. Its public half is built into the app, and a download is checked again just before it installs.
