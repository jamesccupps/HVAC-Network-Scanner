# HVAC Network Scanner

A multi-protocol discovery and audit tool for HVAC and building automation networks. Zero third-party dependencies — everything runs on the Python 3.10+ standard library.

Looking for a Siemens APOGEE P2 scanner or BACnet bridge? See this project [P2Scanner](https://github.com/jamesccupps/P2_Wireshark_Dissector_And_P2_Scanner)

[![CI](https://github.com/jamesccupps/HVAC-Network-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jamesccupps/HVAC-Network-Scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

![HVAC Network Scanner](docs/screenshots/main-window.png)

## What it does

Scans a network and tells you what building-automation gear lives on it. For each device found it tries to identify the exact model, pull readable points or registers, and surface the factory-default credentials that ship with that product so you can confirm they've been changed.

Works against:

- **BACnet/IP** — raw UDP `Who-Is` / `I-Am`, `ReadProperty`, and `ReadPropertyMultiple`. No BAC0 dependency, works on newer python versions.
- **BACnet MSTP** — device enumeration behind BACnet routers via `Who-Is-Router-To-Network` and targeted `Who-Is` to remote DNETs.
- **Modbus TCP** — port sweep, device identification (FC 43 / MEI 14), holding/input register reads, and coil reads.
- **HVAC services** — Niagara Fox, OPC UA, Siemens S7, EtherNet/IP CIP, KNXnet/IP, LonWorks/IP, MQTT, WebCTRL, Metasys, plus HTTP/HTTPS banner grabs.
- **SNMP v1/v2c** — raw UDP `sysDescr` probe, no pysnmp dependency.

Model identification combines signals from multiple protocols:

- Trane Tracer SC / SC+ / UC600 / UC400
- Siemens Desigo PXC automation stations, Desigo CC, TX-I/O modules
- Johnson Controls FEC / Metasys NAE
- Honeywell / Tridium Niagara
- Schneider EcoStruxure / SmartX
- Contemporary Controls BASRT-B routers
- Carrier i-Vu, Automated Logic WebCTRL, Distech, Delta, KMC, Reliable, Carel, Belimo, Daikin, Mitsubishi, LG, and more

## Tested against (verified hardware)

The scanner has been verified against real hardware in live
installations. These devices have known-good classification profiles:

- **Trane Tracer SC+** — supervisory controller (5,000+ objects)
- **Trane Symbio 400-500** — field controller (MSTP)
- **Trane Tracer Ensemble (TES Workstation)** — supervisor
  (handles RPM rejection via fallback to single ReadProperty)
- **Siemens PXC Compact** (EPXC V3.5.x firmware) — field panel
- **Siemens PXC Modular** (PXME V3.5.x firmware) — field panel
  (verified with 1,960-object program)
- **Siemens DXR2.E10PL-1, .E12P-1, .E18-1** — room controllers
- **Siemens Desigo CC / Insight** — supervisors

Across these, the scanner has been tested with ~13,000 points read
and ~30,000 paired BACnet exchanges at zero wire-level errors.

**For hardware not on this list**, the scanner uses a size-based
heuristic that sets an appropriate object enumeration cap from the
device's own reported object count. This is expected to work
correctly for any BACnet-compliant device. If you scan a device that
isn't on this list, please consider [contributing a profile](CONTRIBUTING.md)
so future users can benefit from verified classification.

**Known out-of-scope:**

- Panels running proprietary firmware that doesn't include BACnet/IP.
  For example, Siemens APOGEE PXC panels running firmware revision 2.x
  speak Apogee P2 Ethernet rather than BACnet/IP. These panels may have
  IP addresses and be actively managed by Siemens Desigo CC, but they
  don't answer BACnet/IP. The same hardware upgraded to firmware
  revision 3.x or later would be scannable. If you're affected, check
  with your Siemens representative about a firmware upgrade path — or
  use commercial P2 gateways like PurpleSwift BACnetP2 for integration.
- Proprietary BMS protocols that are not BACnet or Modbus TCP
  (JCI N2, LonTalk, Honeywell C-Bus, various others).

## Install

```bash
git clone https://github.com/jamesccupps/HVAC-Network-Scanner.git
cd HVAC-Network-Scanner
pip install -e .
```

Or run straight from the source tree without installing:

```bash
python -m hvac_scanner           # launches the GUI
python -m hvac_scanner.cli --help
```

Requires Python 3.10 or newer. No extra packages.

### Standalone executable

For a Windows machine without Python — an engineering workstation you would
rather not install anything on — grab `HVACNetworkScanner.exe` from the
[latest release](https://github.com/jamesccupps/HVAC-Network-Scanner/releases).
One file, no installer, no runtime.

To build it yourself:

```bash
pip install -e ".[build]"
pyinstaller packaging/hvac_scanner.spec --noconfirm
# -> dist/HVACNetworkScanner.exe
```

PyInstaller is a build dependency only; the package itself stays
dependency-free at runtime. The executable ships the GUI — the CLI remains
available from a normal Python install.

## Using the GUI

```bash
python -m hvac_scanner
```

Enter one or more CIDR networks (comma-separated), pick which protocols to scan, click **SCAN**. Devices populate into tabs:

- **All Devices** — cross-protocol table with identified model, vendor, web UI URL, default credentials, and description. Right-click for open-web-UI, copy-IP, copy-creds, ping, and a full details popup.
- **BACnet Points** — per-device object lists with present values and units.
- **Modbus Registers** — holding / input / coil reads.
- **Services** — discovered TCP service ports with banners and page titles.
- **Raw JSON** — the full scan result, ready to copy or export.

Click column headers to sort. IP addresses sort numerically by octet, not lexicographically.

Export to CSV or JSON with the **EXPORT** button.

### Target syntax

The target field and CLI accept any mix of:

```
10.0.0.0/24                       # CIDR
10.0.0.5                          # single host
10.0.0.2-100                      # last-octet range
10.0.0.2-10.0.0.12                # full-IP range
10.0.0.0/30, 10.0.1.5, 10.0.2.1-20  # mixed list
```

The broadcast address for BACnet Who-Is is computed automatically from
whatever you type — narrow CIDRs (e.g. `/26`), ranges, and single hosts
all auto-broadcast to the enclosing `/24`. The scan log shows the chosen
broadcast target so it's never magic. Power users can override via the
`--broadcast` CLI flag or `ScanOptions.bacnet_broadcast`.

## What's new in v2.6

### v2.6.0 (2026-08-19)

- **TLS certificates are captured on HTTPS probes.** The scan already
  established TLS to every 443/8443 and discarded the certificate. BAS
  controllers put the product line and often the panel name in the subject CN,
  and the expiry date is worth knowing on its own. Reported in the JSON, as a
  CSV column, and as a scan-log warning when a certificate is expired or
  inside 30 days. Self-signed is flagged, since that is the norm here and it
  means the CN is self-asserted.
- **A Windows executable.** One ~14 MB `HVACNetworkScanner.exe`, no Python
  install required — see [Standalone executable](#standalone-executable).

See [CHANGELOG.md](CHANGELOG.md) for detail.

## What's new in v2.5

### v2.5.0 (2026-08-19)

Three features that change what the tool is for: it stops being something you
run when you suspect a problem and becomes something that tells you when one
appeared.

**Baseline comparison.** The scanner has written JSON since v2 and been
schedulable since then, but nothing read it back.

```bash
# nightly: compare, alert only on change, roll the baseline forward
python -m hvac_scanner.cli 10.0.0.0/24 \
    --baseline last.json --save-baseline last.json \
    --diff-output changes.txt --fail-on-change --quiet
```

Exit code 4 means something moved. BACnet devices are keyed on their device
instance rather than their address, so a panel that changes IP is reported as
an address change, not as a disappearance plus an unrelated arrival. Present
values are excluded on purpose — a temperature differs on every scan and would
bury the signal. A **COMPARE** button in the GUI runs the same comparison
interactively.

**Scan across subnets via a BBMD.** A Who-Is is a broadcast and broadcasts do
not cross a router, so discovery only ever saw the scanner's own subnet — one
run per building.

```bash
python -m hvac_scanner.cli 10.20.0.0/24 --bbmd 10.20.0.1
```

`--bbmd` registers as a Foreign Device and sends Who-Is as
Distribute-Broadcast-To-Network, so one host discovers every subnet that BBMD
and its peers serve. The lease renews automatically during long scans.

**Live results in the GUI.** Device rows, points and registers now appear as
each device finishes rather than all at once at the end. On a controller with
thousands of points the old behaviour was a blank window for the whole scan
followed by a freeze.

See [CHANGELOG.md](CHANGELOG.md) for detail.

## What's new in v2.4

### v2.4.0 (2026-08-19)

Performance release. Deep scans were round-trip bound and strictly
serialized — a 1,000-object controller cost 5,836 exchanges, a 5,476-object
supervisory controller close to 11,000, each one waiting on the last. Both
halves are now batched, and a full deep scan of that 1,000-object controller
takes **61 exchanges instead of 5,836**.

- **objectList enumeration batches by array index.** `BACnetPropertyReference`
  carries an optional `propertyArrayIndex`, so one request asks for
  `objectList[1..N]` rather than one request per index. 1,002 exchanges to 10.
- **Point properties batch across objects.** ReadPropertyMultiple takes a list
  of objects; the scanner was sending one request each. Now a single exchange
  reads four properties from a dozen points, with each object keeping its own
  property list so binary points still are not asked for units.
- **Adaptive batch sizing.** Response size cannot be predicted from the
  request — names and descriptions are free-form — so the window starts at 8,
  grows on success, halves on failure, and floors at the old per-object
  behaviour. Tracked per device.
- **Fallbacks verified identical.** A controller that rejects RPM, or supports
  RPM but not array indices, still returns exactly the same data; it just
  costs more exchanges. `--no-rpm` forces the serial path.
- **A real mock BACnet device in the test suite** (`tests/mock_device.py`),
  which is what caught a key-naming bug in this work before release.

See [CHANGELOG.md](CHANGELOG.md) for detail.

## What's new in v2.3

### v2.3.0 (2026-08-19)

Audit release: a read-through of the whole codebase against the wire formats
it implements, plus the first real test coverage of the socket-facing
modules. Two findings meant a protocol scan had never worked.

**Scans that were broken**

- **Modbus TCP scanning never worked in v2.2.0.** The device-ID request had
  a malformed `struct.pack` format that raised on every call; because
  `struct.error` is not an `OSError` it escaped the local handler and aborted
  the entire Modbus pass. Any host with port 502 open killed Modbus scanning.
- **BACnet point reads were dropped by ordinary broadcast traffic.** An I-Am
  or unconfirmed COV notification from the device being polled ended the read
  early with most of the timeout unspent — so on a busy segment with COV
  subscriptions, points went silently missing.
- **The EtherNet/IP identity probe could never get a reply** — its CIP
  encapsulation header was 22 bytes instead of the 24 the ODVA spec requires.
- **SNMP `sysDescr` over 127 bytes came back corrupted and truncated.** BER
  long-form lengths were read as short-form. Cisco IOS descriptors run past
  200 characters.

**Wrong results**

- Two vendor-ID branches disagreed with the ASHRAE registry after the v2.1.1
  regeneration: an SCS device was identified as a Contemporary Controls
  router and handed that vendor's default credentials, and Cimetrics gear
  never matched its own branch.
- The 22-entry default-credentials table was never actually read — only four
  vendors ever produced a credential despite the README advertising many more.
- Model identification ignored the device's own `modelName` in favour of
  heuristics keyed on device-instance numbers, which are a site convention,
  not a protocol fact. A supervisory controller numbered outside the expected
  range was reported as a unitary controller.

**Faster and safer**

- **Quick depth is actually quick.** It capped at 5% but still enumerated the
  full objectList first — 5,726 reads to sample 250 points from a
  5,476-object controller. Now 400 reads, with every object type represented
  in proportion.
- **Rate limiting is reachable from the GUI.** It had been CLI-only since v2,
  so every GUI scan ran unthrottled at field controllers.
- **Target lists are bounded.** `10.0.0.0/8` used to expand to 16.7M host
  strings; CIDR now shares the 65,536-host limit the range syntax always had,
  and an unparseable target aborts the scan instead of silently scanning
  everything that answered.

**Tests: 249 → 357, coverage 42% → 60%**, concentrated in the modules that
had none — `snmp.py` and `services.py` previously had no tests at all, which
is how two protocol scans stayed broken without anything failing.

See [CHANGELOG.md](CHANGELOG.md) for the full list.

## What's new in v2.2

### v2.2.0 (2026-04-20)

- **Classification report export.** New CLI flag
  `--export-classification PATH` and a GUI export option (save as
  `.txt`). Produces a plain-text report of every BACnet device the
  scanner classified, the path it took (known profile vs. vendor
  substring match vs. heuristic vs. default), the cap applied, and
  the observed object count. Designed so users can submit device
  profile contributions on GitHub without the maintainer needing
  physical access to the hardware.
- **Community contribution flow.** CONTRIBUTING.md now documents
  how to submit device profiles. New GitHub issue templates for
  device profile submissions and bug reports. The philosophy is
  explicit: profiles are only added with real hardware verification,
  because a wrong profile is worse than no profile (the heuristic
  fallback handles unknown gear correctly).
- **Banner version fix.** The scan log banner now reflects the
  actual installed version instead of hardcoded "v2.0".
- **"Tested against" section** in the README listing the hardware
  this scanner has been verified against. Devices not on that list
  use the heuristic fallback and are expected to work — please
  contribute a profile if you find something that doesn't.

## What's new in v2.1

### v2.1.2 (2026-04-20)

- **Silent-failure fix for narrow CIDR scans.** Previously `10.0.0.0/26`
  on a physical `/24` broadcast Who-Is to `10.0.0.63` (unicast to
  nobody, dropped). Engine now auto-computes the right broadcast for
  every target syntax — no new UI field, just works.
- **IP-range and host-list syntax** in the target field. No more need
  to compute CIDR in your head — type `10.0.0.2-100` or
  `10.0.0.19, 10.0.0.21` directly.
- **Target-range filter.** A Who-Is broadcast reaches every device on
  the subnet regardless of your target specification (that's how
  BACnet works). Previously the scanner would deep-scan every I-Am it
  received, even ones outside your specified target range. Now it
  filters I-Ams against the target spec on both BACnet/IP and MSTP
  paths — so `10.0.0.19-21` really does scan only those three IPs.
- **Broadcast consolidation.** Multiple targets on the same subnet
  (e.g. `10.0.0.19, 10.0.0.21, 10.0.0.22`) now produce ONE Who-Is
  broadcast, not N. Reduces redundant traffic on the wire.
- **Device deduplication.** Belt-and-suspenders safety net: no device
  ever appears more than once in results even under edge cases.
- **Vendor-aware object enumeration caps.** The previous 500-object
  cap silently truncated large supervisory controllers. A Trane
  Tracer SC+ with 3000+ mapped objects was returning 500 Analog
  Inputs and no other types at all. New `device_profiles.py` module
  with verified per-vendor/model caps, plus size-based heuristic
  fallback for unknown devices. When a cap would truncate, the
  scanner uses type-interleaved sampling so you get a representative
  mix across AI/AO/AV/BI/BO/BV/MSI/MSO rather than all-one-type.
- **Scan depth dropdown** (Quick / Normal / Full) in the GUI, and
  `--scan-depth` CLI flag. Quick samples ~5% per device for rapid
  site recon; Full overrides all caps when you really do want
  everything.
- **Device name in Points tab.** The Device column now shows the
  device's BACnet `objectName` (e.g. `"SC-1 + SN00000000 (10.0.0.19)"`)
  instead of a bare `"10.0.0.19 (33333)"`. CSV export adds an Object
  Name column.
- **Double-click any point row** for a detail popup with wrapped,
  selectable text for full name/value/units/description.
- **Better diagnostics.** If your target IP doesn't respond, the log
  now tells you why it might have failed (offline, firewalled, not
  BACnet/IP, wrong protocol, or older Siemens APOGEE/BLN hardware
  that isn't reachable via BACnet/IP at all).
- **Tested against real hardware in a live installation:**
  - Trane Tracer SC+ (5,476 and 4,403 object scans, 0 errors)
  - Trane Symbio 400-500 (MSTP, 90 objects, 0 errors)
  - Trane Tracer Ensemble workstation (RPM-reject fallback verified)
  - Siemens PXC Compact EPXC V3.5.x (449 objects, 0 errors)
  - Siemens PXC Modular PXME V3.5.x (1,960 objects, 0 errors)
  - Siemens DXR2.E10PL-1, .E12P-1, .E18-1 room controllers
  - Siemens Desigo CC / Insight supervisors
  - ~13,000 points read across 11 devices, ~30,000 paired BACnet
    exchanges, 0 wire-level errors.
- **Known limitation:** Older Siemens APOGEE generation (PME1252
  panels with PXME V2.8.x firmware) communicates via proprietary
  BLN over IP, not BACnet/IP. These panels are not reachable with
  this tool regardless of IP connectivity — only Siemens Desigo CC
  can talk to them.
- **+72 tests** (346 total): range parser, auto-broadcast heuristic,
  target filtering, vendor profiles, broadcast consolidation,
  deduplication.

### v2.1.1 (2026-04-18)

- **UX cleanup** following field testing:
  - Double-click on a device row now opens the Details popup (not the router's web UI, which for MSTP devices was never the right target).
  - "Include MSTP" checkbox greys out when BACnet is unchecked; engine auto-enables BACnet if MSTP-only was requested.
  - "Services" scan defaults OFF. No more TVs / printers / cameras polluting the device list unless explicitly opted in.
- **Per-object-type BACnet property querying.** Binary points don't get asked for units anymore; calendars don't get asked for presentValue. Cuts "unknown property" log noise and wastes fewer round-trips.
- **BACNET_VENDORS registry regenerated from the official ASHRAE list.** 34 entries → 593. Vendor IDs above ~100 now resolve to names instead of bare numbers.
- **+26 tests** (154 total).

### v2.1.0 (2026-04-17)

- **MSTP routing fix.** ReadProperty now correctly routes across BACnet routers to MSTP devices. v2.0.x hardcoded an unrouted NPDU, which caused every MSTP device behind a router to respond with "Object not found" — the router processed the request as addressed to itself instead of forwarding. Now when a device was discovered via routed Who-Is and has a `source_network` in its I-Am response, deep-scan packets carry the correct DNET/DLEN/DADR/hop-count so the router forwards them across the MSTP trunk. Credit: OldAutomator on r/BuildingAutomation for the packet-sniff analysis.
- **Chunked Who-Is for large sites** (`--whois-chunk SIZE`). A single global Who-Is on a busy multi-building network causes every BACnet device to I-Am simultaneously. With chunked mode, the scanner issues Who-Is requests with instance-range filters (e.g. `low=0 high=999`, `low=1000 high=1999`, ...), so each device only responds in the chunk its instance falls into. Spreads return traffic over time, much gentler on small field controllers. Auto-stops after 10 consecutive empty chunks.
- **CLI summary consistency.** The `hvac-scanner` summary now prints "Unique hosts: N" matching the engine log and GUI stats bar, instead of summing protocol counts (which triple-counted any IP that answered on BACnet + HTTPS + FTP).

## What's new in v2

- **Parser rewrite.** The BACnet codec is now a pure-function module with proper extended-tag-number and extended-length handling. Fixes silent failures on vendors that reorder I-Am tags, and on devices with property IDs above 255.
- **ReadPropertyMultiple support.** Deep scans on controllers that support RPM finish roughly 4× faster. Falls back to `ReadProperty` automatically where RPM isn't supported.
- **Socket reuse.** One long-lived UDP socket per scanner instance instead of a fresh socket per property read (~800 socket create/close cycles eliminated on a 200-point Trane Tracer).
- **Rate limiting.** Optional per-IP inter-packet delay so dense deep scans don't DoS small field controllers.
- **Headless CLI.** `python -m hvac_scanner.cli` runs end-to-end without the GUI, for Task Scheduler automation.
- **Package structure.** The monolithic v1 script is now a proper package: `codec`, `bacnet`, `modbus`, `services`, `snmp`, `fingerprint`, `engine`, `cli`, `gui`. Every module is testable in isolation.
- **Test suite.** 128 tests covering packet encode/decode correctness, cross-request socket contamination, MSTP routing, engine behavior, fingerprinting, and per-property type validation. CI runs them on Python 3.10 / 3.11 / 3.12 / 3.13 on Ubuntu and Windows.
- **Bug fixes.** 17 bare-except blocks replaced with targeted handling; MSTP devices at the same router IP disambiguated by instance; BACnet engineering unit 118 correctly mapped to `gal/s` (v1 had it as `L/min`, which is 81); Modbus unit ID 255 now scanned (default for many TCP-only gateways).

See [CHANGELOG.md](CHANGELOG.md) for the full history.

## Using the CLI

New in v2. Runs headless — no display, no Tk. Intended for Task Scheduler, cron, and CI pipelines.

```bash
# Basic scan of a /24
python -m hvac_scanner.cli 192.168.1.0/24

# Multiple networks, export to JSON and CSV
python -m hvac_scanner.cli 10.0.0.0/24 10.0.1.0/24 \
    --json scan.json --csv scan.csv

# BACnet only, with conservative rate limiting for small JACEs / UC400s
python -m hvac_scanner.cli 192.168.5.0/24 --bacnet-only --rate-limit 50

# Large-campus friendly: chunk Who-Is by 1000-instance ranges instead of
# one global broadcast. Avoids I-Am storms on big sites.
python -m hvac_scanner.cli 10.0.0.0/24 --whois-chunk 1000 --rate-limit 50

# Scan a narrow range of hosts — broadcast is auto-computed:
python -m hvac_scanner.cli 10.0.0.2-100

# Target specific devices only (no scan sweep at all):
python -m hvac_scanner.cli 10.0.0.19,10.0.0.21,10.0.0.192

# Power-user: override the auto-computed broadcast
python -m hvac_scanner.cli 10.0.0.0/24 --broadcast 255.255.255.255

# Quiet mode for scheduled runs
python -m hvac_scanner.cli 192.168.5.0/24 --json /var/log/bas-scan.json --quiet

# Generate a classification report — handy when you've scanned gear
# that fell back to the heuristic and you want to submit a profile:
python -m hvac_scanner.cli 10.0.0.0/24 --export-classification report.txt
```

See [docs/CLI_USAGE.md](docs/CLI_USAGE.md) for the full flag reference and a Windows Task Scheduler XML example.

Exit codes:

- `0` — scan completed
- `1` — bad arguments
- `2` — interrupted (SIGINT)
- `3` — internal error

## Safety and legal

This tool is intended for scanning networks you own or are authorized to audit. Running BACnet or Modbus sweeps against unfamiliar networks is at best rude and at worst unlawful in many jurisdictions. Building automation systems can also behave unpredictably when they see unexpected traffic — small field controllers have been known to lock up under probe load, and some equipment will fail-safe into unsafe mechanical states. Don't point it at anything you haven't been explicitly asked to assess.

The default-credentials database reflects the factory defaults published in each vendor's own documentation. It's here so the legitimate owner or operator of a system can quickly confirm whether defaults were ever changed, not as a remote-access toolkit.

## Project layout

```
hvac_scanner/
├── constants.py       # Vendor DB, BACnet units, object types, HVAC ports
├── codec.py           # Pure-function BACnet packet encode/decode
├── bacnet.py          # UDP transport, socket reuse, RPM, deep-scan
├── modbus.py          # Modbus TCP sweep + register reads
├── services.py        # TCP port scan + protocol-specific probes
├── snmp.py            # Raw UDP SNMP sysDescr probe
├── fingerprint.py     # Cross-protocol model identification
├── device_profiles.py # Per-vendor enumeration caps + scan-depth presets
├── netrange.py        # Target syntax: CIDR, ranges, host lists
├── engine.py          # ScanEngine orchestrator + result/export
├── certs.py           # Minimal X.509 parsing for HTTPS probes
├── diff.py            # Baseline comparison (what changed since last scan)
├── cli.py             # Headless command-line interface
├── gui.py             # Tk GUI (thin wrapper over ScanEngine)
├── __main__.py        # `python -m hvac_scanner` → GUI
└── __init__.py        # Public API

tests/                               # 502 tests
├── test_codec.py                    # BACnet packet encode/decode + parser regressions
├── test_bacnet_client.py            # Socket / invoke-id filtering, RPM gap filling
├── test_modbus.py                   # Modbus framing, MBAP reassembly, device ID
├── test_snmp.py                     # SNMP BER encode/decode
├── test_rpm_batching.py             # Array-index RPM enumeration
├── test_point_batching.py           # Multi-object RPM point reads
├── test_bbmd.py                     # Foreign Device registration
├── test_certs.py                    # X.509 parsing, expiry, malformed input
├── test_diff.py                     # Baseline comparison
├── test_streaming.py                # Live results during a scan
├── mock_device.py                   # UDP BACnet device for the tests
├── mock_bbmd.py                     # UDP BBMD for the tests
├── test_services_probes.py          # CIP and S7 request wire formats
├── test_engine.py                   # Orchestration, sampling strategy, result shaping
├── test_device_profiles.py          # Vendor caps, scan depth, --max-objects override
├── test_fingerprint.py              # Model ID, vendor registry agreement, credentials
├── test_netrange.py                 # Target syntax, host limits, lazy iteration
├── test_target_filtering.py         # I-Am filtering and deduplication
├── test_mstp_routing.py             # DNET/DADR routing across BACnet routers
├── test_auto_broadcast.py           # Broadcast address heuristic
├── test_property_per_type.py        # Per-object-type property selection
├── test_validate_point_property.py  # Per-property type validation
├── test_classification_report.py    # Classification report export
├── test_gui_options.py              # GUI controls reach ScanOptions (skips headless)
├── test_no_site_data.py             # Guard: no site-identifying data in the tree
└── conftest.py
```

## Development

```bash
git clone https://github.com/jamesccupps/HVAC-Network-Scanner.git
cd HVAC-Network-Scanner
pip install -e ".[dev]"
pytest
```

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

Open an [issue](https://github.com/jamesccupps/HVAC-Network-Scanner/issues) for bugs and feature requests. For security reports or general questions, email <jamesccupps@proton.me>.

## License

MIT — see [LICENSE](LICENSE).

## Author

James Cupps — <https://github.com/jamesccupps>
