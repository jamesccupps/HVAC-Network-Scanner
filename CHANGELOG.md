# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.2.0] — 2026-04-20

### Added

- **Classification report export** (`--export-classification PATH` on
  the CLI, or save as `.txt` in the GUI Export dialog). Produces a
  plain-text report of every BACnet device the scan classified, including
  vendor, model, observed object count, which classification path hit
  (known profile / vendor substring match / family rule / heuristic /
  default), cap applied, and points read. Designed for users who
  encounter unknown gear and want to submit a device profile to the
  project without requiring the maintainer to physically access their
  hardware.

- **Contribution workflow.** `CONTRIBUTING.md` documents how to submit
  device profiles, bug reports, and pull requests. GitHub issue
  templates added at `.github/ISSUE_TEMPLATE/` for:
  - Device profile submission (includes the classification report
    attachment instructions)
  - Bug report (with scanner version, environment, and wireshark
    capture request)

- **`Tested against`** section in the README listing the verified
  hardware (Trane Tracer SC+, Symbio, TES; Siemens PXC Compact,
  PXC Modular, DXR2 variants, Desigo CC). Devices not on the list
  use the heuristic fallback, which is correctness-complete.

- **Explicit out-of-scope documentation.** README now names Siemens
  APOGEE P2-over-Ethernet (PME1252, PXME V2.8.x firmware) as
  unreachable, directing users to commercial gateways like
  PurpleSwift BACnetP2 for that generation.

### Changed

- Scan log banner now reflects the actual installed version instead
  of hardcoded "v2.0". It reads `__version__` from the package.

### Internal

- Deep-scan pipeline now stashes classification metadata on each
  device dict at `dev['_classification']`. Used by the new report
  writer and available to any downstream code consuming `ScanResult`.

## [2.1.2] — 2026-04-20

### Fixed

- **Silent failure when scanning a CIDR narrower than the physical subnet.**
  Typing `10.0.0.0/26` on a physical `10.0.0.0/24` network made the engine
  compute broadcast address `10.0.0.63`. That's a valid /26 broadcast
  mathematically but NOT a real Ethernet broadcast on the host's /24 — the
  OS sends it as unicast to whoever owns .63 (usually nobody), it gets
  dropped, and zero I-Am responses come back. The scan reported
  "Scan complete, 0 devices" with no hint that no packets ever went out.
  **Fix: the engine now auto-computes the right broadcast address for every
  supported target syntax.** No UI field, no decision required from the user.

  - `/24` or wider CIDR → use its own broadcast
  - `/25`–`/31` CIDR → use the enclosing `/24` broadcast
  - `/32` single host → enclosing `/24` broadcast
  - IP range / host list in one `/24` → that `/24` broadcast
  - Range spanning multiple `/24`s → limited broadcast `255.255.255.255`
  - Every choice is logged to the scan log so it's never magic

- **User-intent violation: narrow BACnet targets deep-scanned every device
  on the subnet.** A Who-Is broadcast reaches every BACnet device on the
  physical /24, not just the ones in the user's target range. v2.1.1 and
  earlier took every I-Am that came back and deep-scanned it, so typing
  `10.0.0.2-10.0.0.21` could result in ReadProperty storms against devices
  at 10.0.0.230, 10.0.1.x (via BBMD-bridged subnets), etc. — things the
  user never asked for, with no obvious way to stop it without hitting STOP.
  Fix: I-Am responses are now filtered against the user's target spec
  before deep-scan on both BACnet/IP and MSTP paths. Scan log shows
  "Discovered N device(s); kept M in target range (dropped K out-of-range)."
  Found during v2.1.2 verification testing at OCC; confirmed at the wire
  level (13,071 packets, 11,067 of them to out-of-range IPs).

- **Silent truncation on supervisory controllers.** The fixed 500-object
  cap on BACnet deep-scan silently truncated Trane Tracer SC+ controllers
  (which aggregate ~3000+ mapped objects from downstream LonTalk/MSTP
  devices). Because the SC+ enumerates objects type-by-type in array
  order, hitting the cap meant the user got 500 Analog Inputs and *no*
  Analog Values, Binaries, or Multi-State objects — silently wrong.
  **Fix: per-vendor/model device profiles.** When the scanner reads
  `vendorName` and `modelName`, it classifies the device against a
  verified profile table:

  - **Trane Tracer SC+ / SC:** cap 5000 (supervisory)
  - **Trane Symbio 400-500 / 700-800 / UC400 / UC600:** cap 500 (field)
  - **Unknown devices:** size-based heuristic (large / mid / field classes
    get progressively tighter caps)

  When a cap would still truncate (e.g. a 10,000-point Niagara supervisory),
  the scanner reads the full object-type layout first, then enumerates a
  type-interleaved sample so users always see a representative mix of
  AI/AO/AV/BI/BO/BV/MSV/etc. instead of just the first type alphabetically.
  Every classification decision is logged so users can see exactly why a
  particular cap was picked.

- **SCAN / STOP / EXPORT buttons clipped off when window was narrow.**
  Config row split into two rows. Buttons now pack right-first so they
  can never be clipped by the checkboxes growing.
- **Window title said "v2.0"** despite being v2.1.x. Now unversioned.

### Added

- **IP range / host-list syntax in the target field.** Previously only CIDR
  was accepted, which forced users to compute prefix lengths in their
  heads. Now any of these work (and can be mixed in one field):
  ```
  10.0.0.0/24                       # CIDR (as before)
  10.0.0.5                          # single host
  10.0.0.2-100                      # last-octet range
  10.0.0.2-10.0.0.12                # full-IP range
  10.0.0.0/30, 10.0.1.5, 10.0.2.1-20  # mixed list
  ```
  The target field in the GUI shows a subtle hint line with these
  examples. Input is deduplicated, large ranges (>65 536 hosts) are
  rejected to guard against typo'd ranges exhausting memory.

- **Quick / Normal / Full scan depth dropdown.** New control next to the
  existing checkboxes (and `--scan-depth` CLI flag):

  - **Quick** — samples ~5% of each device's objects (minimum 50). Fast
    inventory pass for a "what's here" overview.
  - **Normal** (default) — honors vendor-aware caps from the device
    profile table.
  - **Full** — reads every object regardless of cap. Slow on big
    supervisory controllers but exhaustive when you need it.

- **Point detail popup.** Double-click any row in the BACnet Points tab
  to open a popup showing the full object name, value, units, and
  description in wrapped, selectable, copy-pasteable text. Useful for
  long BACnet names that get truncated in the table view (e.g.
  `"Auto Commissioning Discharge Air Temperature|vav-1"`).

- **Wider Name and Description columns** in the Points tab (360px each,
  up from 240/280). Users can still drag column headers to resize.

- **Device profile system.** New module `hvac_scanner/device_profiles.py`
  with verified per-vendor/model entries plus size-based heuristic fallback
  for unknown devices. Seeded with Trane entries verified against OCC
  Portland hardware. Siemens, JCI, Tridium, and others will be added as
  they're verified against real equipment. Every entry records where and
  when it was validated.

- **+72 regression tests** (27 range parser, 18 auto-broadcast, 10 target
  filtering, 18 device profiles). 227 total, all passing.

### Notes

- Existing users with scripts that pass CIDR strings need no changes; the
  parser is a strict superset of the old behavior.
- `max_objects_per_device` in `ScanOptions` is preserved as a global
  override, but the new per-device profile classification is the
  recommended path. If both are set, the profile classification wins
  (with scan-depth multiplier applied).

## [2.1.1] — 2026-04-18

Thanks again to OldAutomator on r/BuildingAutomation for a second round of
detailed field testing on v2.1.0. Every issue they reported was real — this
release fixes all of them.

### Fixed

- **Double-click on a device opens the Details popup, not a web browser.**
  For MSTP devices the table's "IP" column shows the router's IP, so
  double-clicking took the user to the router's login page instead of the
  device they were looking at. Web UI is still one right-click away.
- **MSTP checkbox gated on BACnet.** Previously, checking MSTP by itself
  did nothing — the MSTP scan runs inside the BACnet scan path — but
  there was no visible feedback. The MSTP checkbox is now disabled when
  BACnet is unchecked; if a user still passes `scan_mstp=True` without
  `scan_bacnet=True` via the CLI or a saved config, the engine turns
  BACnet on automatically and logs a warning.
- **Per-object-type property querying.** The scanner now only asks for
  `units` on analog objects (AI/AO/AV/Loop/Accumulator/etc.) and only
  asks `presentValue` on object types that have one. Binary, multi-state,
  and config objects no longer produce "unknown property" noise or waste
  round-trips. See `POINT_PROPERTIES_BY_TYPE` in `constants.py`.
- **Services scan now defaults OFF.** The 25+ port TCP sweep picked up
  TVs, printers, cameras, and NAS boxes and dumped them into the device
  list — overwhelming the BAS devices the user was actually looking for.
  Users who want the service sweep can still enable it explicitly.

### Updated

- **BACNET_VENDORS expanded from 34 entries to 593.** Previously, any
  vendor ID above ~100 showed as a bare number in the output. The vendor
  table is now regenerated from the official ASHRAE BACnet vendor
  registry (https://bacnet.org/assigned-vendor-ids/) and covers every
  vendor assigned through the current registry publication.

### Not a bug (clarification)

- "Scanner sends an I-Am globally every time it launches" — the scanner
  does not build or send I-Am packets. What was observed is a Who-Is
  global broadcast that fires when the user clicks SCAN (not at app
  launch). v2.1.0 already provides the `--whois-chunk SIZE` option for
  large sites that need to avoid the global-broadcast storm.

## [2.1.0] — 2026-04-17

Thanks to OldAutomator on r/BuildingAutomation for the field testing and the
Yabe-vs-ours packet-sniff analysis that located the MSTP routing bug. This
release is the fix plus follow-on work to make the tool friendlier on large
sites.

### Fixed

- **BACnet MSTP ReadProperty was not routed across the router.** The v2.0.x
  `build_read_property` / `build_read_property_multiple` hardcoded the NPDU
  as `0x01 0x04` — version plus the expecting-reply flag, but no destination
  specifier. This worked for IP-direct devices but caused every MSTP device
  behind a router to respond with "Object not found," because the router
  processed the unicast packet as if it were addressed to the router's own
  device object instead of forwarding it across the MSTP trunk.

  Field symptom: Who-Is discovery found MSTP devices fine (because
  `build_whois(dnet=N)` already included the destination specifier), but
  every subsequent property read failed silently. Reporters saw BACnet/IP
  controllers populate cleanly while every MSTP device — Trane UC400, JCI
  FEC, or any third-party behind a BASRT-B / PXC router — came back empty.

  Fix: `build_read_property` and `build_read_property_multiple` now accept
  `dnet` and `dadr` arguments. When set, the NPDU emits the correct routed
  form: `0x01 0x24 <DNET-H> <DLEN> <DADR-bytes> 0xFF`. New `build_npdu()`
  helper centralizes NPDU construction; `build_whois()` refactored to use it
  for consistency. New `_encode_dadr()` handles all three `source_address`
  shapes `parse_iam` produces (decimal MSTP MAC, hex-colon BACnet/IP addr,
  raw bytes, int).

  The `BACnetClient.read_property`, `read_property_multiple`,
  `read_device_info`, `read_object_list`, and `read_point_properties`
  methods thread `dnet`/`dadr` through. `ScanEngine._deep_read` now pulls
  `source_network` and `source_address` off the device dict and passes them
  to every client call, logging `(MSTP net=X mac=Y)` when routing is active.

- **CLI summary "Total devices" was summing protocol counts.** The engine's
  `_finish()` and the GUI's stats bar both correctly count unique IPs, but
  `cli._print_summary` still summed. Now also prints `Unique hosts:` and
  matches. (Flagged during v2.0.2 audit, landed now with the rest of 2.1.)

### Added

- **Chunked Who-Is for large sites** (`--whois-chunk SIZE`). Instead of one
  global Who-Is producing an I-Am storm on a busy site, issues Who-Is with
  `low`/`high` instance-range filters in steps of SIZE. Each device only
  I-Ams to the chunk its instance falls into, spreading return traffic over
  time. Early-stops after 10 consecutive empty chunks to avoid scanning the
  full 4M BACnet instance space on a small network.

  New `ScanOptions`: `whois_chunk_size` (0 = disabled, default),
  `whois_max_instance` (4,194,303 = 2^22-1), `whois_chunk_delay_ms` (50ms
  between chunks).

  New CLI flags: `--whois-chunk SIZE`, `--whois-max-instance N`,
  `--whois-chunk-delay MS`. New GUI field: "Chunk:" entry next to
  "Timeout:", defaults to 0.

- **MSTP routing end-to-end regression test.** `test_mstp_routing.py`
  exercises DADR encoding (all 3 formats), NPDU building, routed
  ReadProperty/RPM wire format, Who-Is backwards compatibility, engine-level
  threading of source_network through to the client, and the full chunked
  Who-Is state machine including dedup and early-stop. 30 new tests.

### Changed

- **`build_whois()` refactored** to use the new `build_npdu()` helper.
  Wire output is bytewise identical to v2.0.x — existing tests verify this.

### Test count
Went from 98 to 128 tests (+30).

---

## [2.0.2] — 2026-04-16

Second post-first-scan patch. Fixes the real root cause behind the "column
bleed" in the Points tab and the inflated device counts on the All Devices
tab.

### Fixed

- **Cross-request contamination on the shared BACnet socket.** This was the
  actual root cause of the Points tab showing floats in the Name column and
  object names in the Units column. The v1 and v2.0.0/v2.0.1
  `BACnetClient._request_response` did `sendto()` then `recvfrom()` and
  assumed the first packet back was the reply to the request just sent. On
  any busy BAS network — like OCC with 161 BACnet devices — the shared UDP
  socket bound to port 47808 is constantly receiving I-Am broadcasts, COV
  notifications, and stale replies from prior requests. Those stranger
  packets got parsed under the wrong request's context, so the property
  IDs in the response matched what we'd asked for, but the values came
  from a different object. Fix: every received packet is now validated
  against the expected invoke-id AND the expected source IP. Non-matching
  packets are discarded silently (with a DEBUG log) and we keep reading
  until the right one arrives or we time out. New `_extract_invoke_id()`
  helper in `codec.py` handles the invoke-id-location-by-PDU-type logic.
  Five new tests in `test_bacnet_client.py` exercise the exact
  contamination scenarios that were producing the field symptom.

- **Property-value type validation at the read layer.** As a belt-and-
  suspenders defense, `read_point_properties()` now type-checks each
  returned value against the expected type for its property name before
  passing it upstream. A float reported as `objectName` is dropped rather
  than str()'d into `"70.501953125"` in the Name column. A bool reported
  as `units` is dropped. An int reported as `description` is dropped.
  Named-type helper `_validate_point_property()` is covered by 14 new
  tests in `test_validate_point_property.py`.

- **Device count inflation.** `_finish()` previously reported
  "Total: N devices" by summing the per-protocol counts, so an IP with
  BACnet + HTTPS + FTP counted as 3 devices. Now reports
  "Total: N unique IP(s)" based on the distinct IPs in the result set.
  GUI status bar also shows `Hosts: N` up front.

- **All Devices tab deduplication.** An IP that responds on BACnet (or
  Modbus or SNMP) now shows as a single row. Its open HTTP/HTTPS/FTP ports
  no longer each get their own row in the primary device view. Those
  service details are still shown in the Services tab.

### Added

- `_extract_invoke_id()` helper in `codec.py` covering all 7 PDU types
  that carry invoke IDs.
- `_validate_point_property()` helper in `bacnet.py` with per-property
  type expectations.
- New test file `test_bacnet_client.py` with 5 cross-request
  contamination scenarios.
- New test file `test_validate_point_property.py` with 14 type-validator
  cases.
- Regression test for unique-IP counting in `test_engine.py`.

### Test count
Went from 64 to 98 tests (+34).

## [2.0.1] — 2026-04-16

Post-first-scan bug fixes discovered running against One City Center's
161-device BACnet network.

### Fixed
- **Fingerprinting was skipped whenever a scan pass raised.** The
  `_refingerprint()` call sat inside the same `try` block as the scan
  passes, so an SNMP permission error (or any other late-stage exception)
  silently bypassed fingerprinting for every device already discovered.
  Result in the field: 161 BACnet devices found but the Identified Model,
  Device Type, Default Credentials, Web UI URL, and Description columns
  were blank across the board. Now each scan pass has its own try block
  and `_refingerprint` runs in a `finally` so it always executes.
- **BACnet Points tab column-bleed on Structured View objects.** Siemens
  Desigo PXC controllers expose Structured View (object type 29) objects
  for UI grouping; they have `objectName` and `description` but no
  `presentValue` or `units`. The v2.0.0 engine passed raw property values
  straight through to the Treeview, so a description string would end up
  in the Present Value column and unit enum integers would end up in the
  Name column. The engine now skips navigational object types
  (Structured View, Device, File, Schedule, Calendar, Notification Class,
  Trend Log, Trend Log Multiple, Event Log, Program) during point
  enumeration, and a new `_safe_str` helper hard-caps cell values and
  strips control characters so no value can overflow into its neighbor.
- **Device-advertised model/description preferred over heuristic.** For
  devices that expose a `model_name` property (e.g. Siemens returning
  "Insight" or "Desigo CC"), the CSV and GUI now show that text rather
  than the heuristic guess from `fingerprint_device()`. Heuristic is the
  fallback, not the override.
- **CSV had redundant "Device ID" and "BACnet Instance" columns** with
  identical data. The "BACnet Instance" column has been removed.

### Added
- `_safe_str()` and `_format_present_value()` helpers in `engine.py`,
  both tested.
- 5 regression tests covering each of the above fixes.

## [2.0.0] — 2026-04-16

Major rewrite. Same feature set as v1 plus significant protocol correctness
fixes, new capabilities, and a proper test suite.

### Added
- **Headless CLI** — `python -m hvac_scanner.cli` (or `hvac-scanner` after
  install) runs scans without the GUI. Supports all scan options as flags,
  JSON/CSV export, custom rate limiting, and SIGINT-handled graceful abort.
  Exit codes distinguish clean completion (0), bad args (1), interrupt (2),
  and internal error (3).
- **ReadPropertyMultiple (BACnet service 14)** — dramatically faster deep
  scans on devices that support it. Automatically falls back to per-property
  `ReadProperty` on devices that don't. Toggleable via `--no-rpm` / GUI checkbox.
- **Rate limiting** — `--rate-limit MS` enforces a minimum interval between
  BACnet packets to the same IP, protecting small field controllers
  (UC400, FEC, BASRT) from deep-scan DoS.
- **Unit test suite** — 59 tests, all using hand-constructed packet bytes as
  fixtures to verify parser behavior against synthesized real-world responses.
- **CI pipeline** — GitHub Actions matrix on Python 3.10–3.13 across Ubuntu
  and Windows. Lints with `py_compile` and runs `pytest`.
- **Package structure** — Split the monolithic 2,350-line `hvac_scanner.py`
  into ten focused modules. Public API exposed via `hvac_scanner.__init__`.
- **Pyproject packaging** — `pip install -e .` installs the package and
  registers `hvac-scanner` and `hvac-scanner-gui` as console scripts.
- **Issue and PR templates** — under `.github/`.
- **CLI documentation** — `docs/CLI_USAGE.md` with a full flag reference
  and a Windows Task Scheduler XML example for scheduled audits.
- **Architecture documentation** — `docs/ARCHITECTURE.md` describes module
  boundaries and threading model.

### Fixed
- **BACnet ReadProperty ACK parser** — v1 hardcoded context-tag skipping,
  breaking on property IDs encoded with extended length (property number > 255).
  Rewrite uses a generic tag-class + length reader.
- **BACnet I-Am parser** — v1 relied on positional tag order and gave wrong
  vendor IDs for vendors emitting reordered application tags. Now iterates
  with tag-class awareness.
- **BACnet unit 118** — v1 mapped engineering-unit code 118 to `L/min`.
  Per ASHRAE 135, that code is `gal/s`; `L/min` is code 81.
- **Modbus unit ID 255** — v1 never tried 255, which is the default unit
  for many TCP-only gateways (most notably Schneider's). Now included.
- **MSTP device lookup by (ip, port, instance)** — v1's device-details
  popup looked up by `(ip, port)`, returning the wrong device for multiple
  MSTP devices behind a single router IP. Now disambiguated by instance.
- **Deep-scan cap consistency** — v1 had both 500 and 200 as cap values in
  different places. Unified as `max_objects_per_device`, defaulting to 500.
- **17 bare-except blocks** — replaced with targeted exception handling
  and DEBUG-level logging so real bugs surface instead of silently failing.
- **Socket leaks** — every socket in every scanner is now wrapped in either
  `with closing(...)` or a try/finally. No resource leaks on exception paths.
- **Vendor ID 13/514 collision** — both now correctly identify as Cimetrics.
- **Vendor ID 245/485 collision** — both now correctly identify as
  Contemporary Controls.

### Changed
- **Socket model for BACnet** — v1 created a fresh UDP socket for every
  `ReadProperty` call (~800 socket create/close cycles on a 200-point Trane
  Tracer). v2 uses one long-lived socket per scanner instance with
  thread-safe access, serialized request/response correlation, and
  invoke-ID tracking.
- **GUI is now a thin wrapper** over `ScanEngine`. Same UX and layout as v1,
  but identical scan logic to the CLI — guaranteed same output for same input.
- **README screenshot link** now points at a path in this repo (`docs/screenshots/`)
  rather than GitHub's `private-user-images.githubusercontent.com` CDN, which
  served expiring JWT-signed URLs that would break for other viewers.
- **Vendor DB expanded** — added Loytec, ABB, Mitsubishi Electric, LG,
  Daikin, and several others.
- **HTTP fingerprints expanded** — added Ubiquiti/UniFi, Beckhoff, WAGO,
  Emerson/Copeland/Vertiv, Danfoss, Samsung HVAC, Mitsubishi, LG.

### Removed
- Nothing removed from v1's feature set. Everything v1 could do, v2 can do.

---

## [1.0.0] — prior

Initial release. Monolithic `hvac_scanner.py` with BACnet/IP, BACnet MSTP,
Modbus TCP, HVAC service, and SNMP discovery behind a Tk GUI.
