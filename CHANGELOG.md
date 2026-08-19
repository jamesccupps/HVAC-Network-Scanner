# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.4.0] — 2026-08-19

Performance release. Deep scans were round-trip bound and strictly
serialized: a 1,000-object controller cost 5,836 exchanges, and a 5,476-object
supervisory controller close to 11,000, every one of them waiting on the
previous. Both halves of that are now batched.

### Changed — deep scans are roughly two orders of magnitude cheaper

Measured against a mock controller with 1,000 objects, full deep scan. All
four paths return byte-identical results (1,000 points, 1,000 names, 1,000
values, 820 units — units only on the types that have them):

| device behaviour | exchanges |
|---|---|
| rejects ReadPropertyMultiple | 5,836 |
| supports RPM, run with `--no-rpm` | 4,830 |
| RPM without `propertyArrayIndex` | 1,053 |
| full RPM support | **61** |

- **objectList enumeration is batched by array index.**
  `BACnetPropertyReference` is
  `{[0] propertyIdentifier, [1] propertyArrayIndex OPTIONAL}`, so one request
  can ask for `objectList[1..N]` instead of one request per index. Batch size
  is bounded at both ends — the request must fit the device's
  `maxAPDULengthAccepted` and the response must fit the APDU we advertise
  back — and capped at 100 so a single bad batch stays cheap. Enumerating
  1,000 objects goes from 1,002 exchanges to 10.

- **Per-point property reads are batched across objects.**
  ReadPropertyMultiple takes a list of ReadAccessSpecifications, but the
  scanner issued one request per object. Now a single exchange reads four
  properties from a dozen objects, each object still carrying its own
  property list so binary points are not asked for units alongside analog
  ones.

  Batch size here is adaptive rather than computed: response size cannot be
  derived from the request, because object names and descriptions are
  free-form strings, so a batch that fits one controller overflows the next
  and a device that cannot segment simply Aborts. Starts at 8, grows by one
  per success to a cap of 24, halves on failure, floors at 1 — which is the
  old per-object behaviour. Tracked per device.

- **Fallbacks are per device and bounded.** A controller that rejects RPM
  outright, or implements RPM but not `propertyArrayIndex`, drops to the
  serial path after two failed batches and is not re-probed. `--no-rpm` still
  forces the serial path outright. Every fallback path was verified to return
  results identical to the batched path.

The two mechanisms are independent: a device supporting RPM but not
`propertyArrayIndex` still gets the point-read speedup (5,836 to 1,053).

### Fixed

- **Batched property results came back under the wrong key names.** The
  number-to-name map was built by inverting `PROP_IDS`, which carries
  hyphenated aliases alongside the camelCase names — `object-name` and
  `objectName` both map to 77 — so the inversion returned whichever came
  last. Every property arrived under a key the engine does not recognise,
  silently blanking names and values. Names are now resolved from what the
  caller actually requested. Found by the new mock device before release.

### Added

- **`tests/mock_device.py`** — a real UDP BACnet device for the test suite.
  Answers Who-Is, ReadProperty and ReadPropertyMultiple including
  multi-object and array-index requests, counts the exchanges it served, and
  can emulate the three RPM behaviours seen in the field: full support, RPM
  without `propertyArrayIndex`, and outright rejection.

  This is the fixture the project was missing. Two protocol scans shipped
  broken in v2.2.0 because nothing exercised the wire; assertions on exchange
  count and end-to-end data are worth more here than stubbed clients. It
  binds an ephemeral port and retargets the client for its own lifetime, so
  the suite passes on machines already running a BACnet service on 47808.

### Tests

- 357 to 395 tests, line coverage 60% to 63%. `bacnet.py` 37% to 64%,
  `codec.py` 72% to 75%.

## [2.3.0] — 2026-08-19

Audit release. A full read-through of the codebase against the wire formats
it implements, plus the first real test coverage of the socket-facing
modules. Two of the findings meant a protocol scan had never worked at all.

### Fixed — scanning was broken

- **Modbus TCP scanning never worked in 2.2.0.** The device-identification
  request was built with `struct.pack('!HHHBBBB', ...)` — seven format
  characters for eight values — so it raised on every call. `struct.error` is
  not an `OSError`, so it escaped the local handler, propagated out of
  `scan_host` and `scan_network`, and hit the engine's catch-all as "Modbus
  scan pass failed". Any host with port 502 open aborted the entire Modbus
  pass before a single device was recorded.

- **BACnet reads were dropped by ordinary broadcast traffic.** Packets
  carrying no invoke-id — any Unconfirmed-Request, so I-Am, unconfirmed COV,
  unconfirmed event notification — passed the reply filter, reached the
  parser, and its `None` was returned as the read result. One unsolicited
  broadcast from the device being polled ended the read with most of the
  timeout unspent. On a segment with active COV subscriptions this silently
  lost points.

- **EtherNet/IP identity probe could never get a reply.** The CIP
  ListIdentity request was 22 bytes where the ODVA encapsulation header is
  24, misaligning every field after `length`. A conforming device sees a
  truncated header and does not answer, so the probe only ever reported the
  generic product string inferred from the open port.

- **SNMP sysDescr over 127 bytes was corrupted.** The value length was read
  as a single byte, which is only the BER short form. Long-form lengths were
  misread, producing a garbage leading character and truncation at 129 bytes
  — and starving the vendor-matching regexes. Cisco IOS descriptors run past
  200 characters. The request builder had the mirror problem with long
  community strings.

- **Application-tagged Boolean consumed a byte it does not have.** Per ASHRAE
  135 20.2.3 the value lives in the tag's Length/Value/Type field with zero
  contents octets. Inside a ReadPropertyMultiple ACK the stolen byte was the
  closing tag, so the boolean decoded wrong AND every subsequent property of
  that object vanished into its value list.

- **Modbus responses were parsed from a single `recv()`.** TCP makes no
  promise that a response arrives in one segment; a split reply was parsed
  short and a long register list silently truncated. Frames are now read by
  the length the MBAP header declares.

### Fixed — wrong results

- **Two vendor-ID branches disagreed with the ASHRAE registry.** The v2.1.1
  registry regeneration (34 entries to 593) desynced them: 485 is SCS, not
  Contemporary Controls — an SCS device was labelled a BACnet router and
  handed another vendor's default credentials — and neither 13 (Teletrol
  Systems) nor 514 (t-mac Technologies) is Cimetrics, which is 14, so real
  Cimetrics gear never matched its own branch. Siemens' other registered IDs
  (9, 22, 313) are now recognised alongside 7.

- **The default-credentials table was never read.** `DEFAULT_CREDS` held 22
  vendor entries and nothing imported it; every credential the scanner
  emitted came from a literal inside a vendor branch, so only Trane, Siemens,
  JCI and Contemporary Controls ever produced one. Carrier i-Vu, Automated
  Logic, Distech, Delta, KMC, Reliable, Carel, Belimo, Daikin, Schneider and
  the rest got an empty column despite being advertised.

- **Model identification ignored the device's own answer.** The fingerprinter
  inferred a model from vendor ID, max-APDU and device instance while
  `modelName` sat unused in the same dict, so the CSV export and the JSON/GUI
  could name one device two different things. The instance heuristics were
  also site conventions rather than protocol facts: a supervisory controller
  numbered outside the expected range was reported as a unitary controller.

- **Partial ReadPropertyMultiple results left blank columns.** Individual
  retries only happened when RPM returned nothing at all, so a device with an
  incomplete RPM path kept an empty Name column even though a single
  ReadProperty would have answered. Gaps are now filled individually with a
  per-device give-up after three consecutive refusals — nine wasted reads on
  a controller that genuinely lacks the property, versus recovering the data
  on one that does not.

- **Object-type sampling lost its alignment on flaky links.** Array indices
  were paired against entries by position, but failed reads are omitted, so
  one timeout shifted every later pairing and the rest of the device's
  indices were bucketed under the wrong object type.

### Changed

- **Quick scan depth is now quick.** It reduced the cap to 5% but still
  walked the entire objectList before sampling — 5,726 reads to sample 250
  points from a 5,476-object controller, roughly four and a half minutes at a
  50 ms rate limit. Deep sampling now strides across the array instead: 400
  reads for the same result, with all eight object types represented and
  every type's share within 0.2% of its share of the device.

- **Trane supervisory cap raised 5000 to 8000.** The module's own policy is
  that a real-world scan of a profiled device class must never hit the cap,
  but the largest documented scan of this device was 5,476 objects — so the
  flagship verified profile tripped the sampling path and dropped 476
  objects.

- **CIDR targets are bounded at 65,536 hosts**, matching the limit the range
  syntax always had. `10.0.0.1-10.5.0.1` was refused while the larger
  `10.0.0.0/8` was accepted and expanded to 16.7M host strings (~875 MB),
  which the engine copied into an allow-list and the service scanner
  multiplied by 25 ports. A /16 is still accepted.

- **Unparseable targets now abort the scan** instead of degrading into "no
  filter", which meant deep-scanning every device that answered — the
  opposite of the target list the user typed.

- **`--max-objects` does something.** It was parsed, stored and never read.
  It is now a ceiling over the vendor-aware profile cap and defaults to
  unset; wiring its old default of 500 straight through would have re-imposed
  the flat cap v2.1.2 removed.

- **`--networks` no longer discards the positional argument.** It shared
  `dest` with the positional, so `hvac-scanner A --networks B` silently
  scanned only B. The two are merged in order.

- **Modbus devices that reject FC 43 / MEI 14** are no longer recorded as
  `detected_via='device_id'` with every field "Unknown"; the probe falls
  through so the holding-register path labels them accurately.

### Added

- **Rate limiting is reachable from the GUI.** `rate_limit_ms` has been on
  `ScanOptions` and the CLI since v2 but the GUI never set it, so every GUI
  scan ran unthrottled at field controllers — the load the README warns can
  lock them up. Added as a "Rate (ms)" field, defaulting to 0.
- Numeric GUI fields fall back to their default with a log line instead of
  raising; a typo'd timeout used to dump a traceback instead of scanning.
- `iter_parse_targets` is genuinely lazy rather than materialising the whole
  list first.

### Security / hygiene

- **Site-identifying data removed from the tree.** Real panel names, room
  controller names, equipment tags, a controller serial, and site references
  appeared alongside vendor, model, firmware revision and object count for
  each device — together a partial asset inventory of a named building.
  Technical substance is unchanged; only the identifying strings are
  generalised. `tests/test_no_site_data.py` scans for them so the next set of
  pasted field notes is caught by CI.

### Tests

- **249 to 357 tests, line coverage 42% to 60%.** The new coverage is
  concentrated where the bugs were: snmp 17% to 54%, modbus 23% to 49%,
  services 13% to 32%, gui 0% to 49%, cli 0% to 34%. New suites for SNMP, the
  service probes, GUI options, and the site-data guard — `snmp.py` and
  `services.py` previously had none, which is why two protocol scans could be
  broken without anything failing.
- Four existing tests asserted buggy behaviour and now assert the correct
  behaviour: the 485 mis-identification, the `--max-objects` default, and two
  Trane cases keyed on site-specific device instances.

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
  Found during v2.1.2 field verification; confirmed at the wire
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
  for unknown devices. Seeded with Trane entries field-verified against real hardware. Siemens, JCI, Tridium, and others will be added as
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
  any busy BAS network — like a large site with ~160 BACnet devices — the shared UDP
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

Post-first-scan bug fixes discovered running against a live installation's
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
