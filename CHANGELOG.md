# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.12.0] — 2026-11-06

### Added

- **Firmware covered by published advisories.** The report compares the firmware
  each BACnet controller reports with CISA ICS advisories, taken from CISA's own
  CSAF data: Trane Tracer SC+ (ICSA-26-071-01), Siemens APOGEE PXC on BACnet
  firmware (ICSA-22-349-16, -22-286-12, -26-295-08, and three advisories with no
  fix yet), Desigo PXC4/5/7 and DXR2 (ICSA-22-132-10, -26-225-08), Desigo CC
  (ICSA-26-209-01). A device older than its advisory's fix is listed with the
  version to update to; one whose reported version is too short to place (a DXR2
  saying "v01.21" against a fix at 01.21.142.5) is listed to check by hand.
  Versions are compared only; nothing is tested.

## [2.11.0] — 2026-11-06

### Added

- **LonWorks/IP (IP-852).** A new pass (`--no-lon` to skip) asks every target for
  its IP-852 device configuration on UDP 1628, the request the IzoT LonTalk
  stack answers from any address. Routers and nodes (i.LON, SmartServer,
  LOYTEC L-IP, controllers with an IP-852 channel) report their node type,
  the name they were given, Neuron IDs, configuration and time servers, and
  whether authentication is on; the report lists those without it. The
  reply names no product, so none is guessed.
- **Serial gateways.** A new pass (`--no-gateways`) sends Moxa's identify
  request on UDP 4800 and reports NPort, MGate and OnCell devices by MAC and
  model code (by product name only when their own web page gives it). The
  report says to check them against ICSA-16-336-02: older firmware gives the
  admin password to the same protocol (CVE-2016-9361), which the scanner
  never asks for.
- **OPC UA identity.** OPC UA ports (4840, and KEPServerEX's 49320) get the
  standard discovery exchange: the server's own application name and product
  URI, and each endpoint's security and accepted logins. The report flags
  servers offering an unsecured endpoint or anonymous sessions. Checked
  against a real server (FreeOpcUa asyncua) as well as the simulator.
- The Niagara platform ports (3011, 5011) are probed.

### Changed

- **Adaptive timeout.** The timeout is now the longest wait: a BACnet device
  that has answered a few requests gets four times its slowest recent reply
  (at least 1 s). On one site four controllers dropped about half of all
  requests and each used up the 3-minute limit at 5 s a loss. The per-device
  log line reports the time actually spent waiting.

### Fixed

- Vendor names from web pages and SNMP: Alerton was reported as Carrier / ALC
  (it is Honeywell's), Vertiv and Copeland as Emerson (independent since 2016
  and 2023). Moxa, Lantronix and Echelon / EnOcean (i.LON, SmartServer) are
  recognised.

## [2.10.0] — 2026-11-06

### Added

- **Updates from inside the app.** The Windows executable checks for a new
  release once a day (Advanced → *Check for updates daily*; the header's
  **Check for updates** asks now) and, on a click, downloads and installs it:
  the download must match `latest.json`, a manifest each release now carries,
  signed with the project's Ed25519 key and checked against the public key
  built into the app. The new exe swaps itself in and reopens; if anything
  fails the previous one is put back. A copy run from Python is told about
  the new version instead. Copies older than this one update by hand once.
  The same design as PingerPlot and UniFi Stock Watcher.
- **Where the rest of the site answered from.** Devices that answer the
  Who-Is from outside the targets (often other subnets behind a BBMD) were
  dropped with only a count. The log and the report now name their subnets,
  and the export's `coverage` records them (`outside_targets`).
- The export records the UDP port BACnet ran on and the address it scanned
  from (`coverage.bacnet_port`, `coverage.local_address`); the report says
  when other BACnet software had 47808, which hides broadcasts (some I-Ams,
  routers' network announcements) from the scan.

- **Devices only** depth: each device's identity (name, model, vendor,
  firmware, description, location) and nothing else, for a fast inventory;
  tick Services as well for devices and their open ports. The report shows
  a dash, not 0, for the point counts it did not read. A quick scan still
  read up to 50 objects per controller and took minutes on a large site.
- **A per-device time limit** (Advanced, `--device-time-limit`, 180 s by
  default, 0 for none): a device that reaches it keeps what was read, is
  marked partial in the log, the export (`cut_short`) and the report, and
  the scan moves on.
- **Times in the log.** Each section heading carries the clock time and the
  time since the start, each device says how long it took and how many of
  its requests went unanswered, and the summary ends with where the time
  went (`Time: BACnet 9 min 41 s (deep scan 9 min 12 s, MS/TP 12 s), ...`).
  The export records the same (`coverage.seconds`, and `scan_seconds` and
  `requests` per device), and the report lists *Controllers that drop
  requests*: on one site four controllers dropped about one request in
  ten and took minutes each, a timeout per loss, with nothing saying why.

### Changed

- The report shows the same flagged point on three or more controllers of
  one model as one row (with the addresses and a count), and identical KNX
  gateways likewise: a site of 51 identical room controllers gave 1,224
  near-identical fault rows and 51 identical KNX rows.
- While a deep scan waits on slow controllers, the progress text names them
  (`still reading 10.0.1.83, …`) and the log says once how long each has
  run; a controller read one object at a time logs its progress every 100
  entries. A site's scan sat at 180 / 183 for minutes with nothing saying why.

### Fixed

- **A quick scan missed 29 controllers a normal scan found.** Unicast
  discovery (`auto`) skipped every subnet the broadcast had heard from, but
  answers from another subnet that arrive through a BBMD's relay prove
  little: on one site the relay passed on none of 112 controllers' replies
  in one scan and 83 in the next. Those 83 made the scanner treat the subnet
  as reached and never ask the other 29; in a later scan the BBMD's own
  direct answer did the same to all 112. Every silent target on another
  subnet is now probed, whatever answered the broadcast from there.
- **Lost packets no longer slow a controller to a crawl.** Once batched
  reads (objectList, point properties) have worked on a controller, an
  unanswered one is asked again at the same size before the batch is
  halved, the size grows back afterwards, and the controller is never
  switched to one read at a time for good. Before, a short burst of loss
  dropped three controllers to single reads, each lost reply costing a
  5 s timeout, and their deep scans ran for minutes.
- **Devices named for what they are.** The type and description leaned on
  the first site's numbering, and a device's own model name only replaced
  the model column. On a second site that made a Trane Tracer Ensemble
  server a "unitary controller", an Insight workstation a Desigo CC
  server, every DXR2 a "Desigo PXC series controller", and the DXR2.E12P a
  "bath controller" (E18: "heat pump controller", the program one site
  runs). Known models now set type and description from the makers'
  catalogues: DXR2 E10PL / E12P / E18, PXC Modular / Compact (told apart by
  firmware), Desigo PXC4 / PXC5 / PXC7, Insight, Desigo CC, Tracer Ensemble, Trane TR200 and Yaskawa
  HV600 drives, and the MelcoBEMS MINI gateway.
- The dark theme's scrollbars were dark grey on dark grey; the thumb is now
  a lighter grey that brightens under the pointer.
- Unicast discovery asks the addresses that stayed silent once more (where
  anything answered at all): each of two scans of one site missed a
  different controller on a lossy link.
- A router heard both directly and through a BBMD was listed twice, and
  each router query now names the broadcast it went to (a bare "Found 0
  router(s)" for the remote subnet's broadcast read like a failure).

### Tests

- About fifteen tests against the simulated site skipped on every Linux CI
  leg with "Address already in use". On Linux, closing a socket does not wake
  a thread waiting on it in `recvfrom()` or `accept()`, so each simulated
  device kept its address bound until the run ended and the next test on
  that address could not start. The simulator now shuts each socket down and
  waits for its thread, and the Modbus Report Server ID test takes a free
  port instead of 502 (root only on Linux).
- Every executable build now updates a copy of the previous release (until
  one has an updater, a copy of itself) to the new exe for real
  (`packaging/test_update.ps1`): the old copy's own updater checks a release
  signed with a throwaway key, downloads, verifies and applies, and the test
  confirms the swap, the restart and the clean-up.

## [2.9.1] — 2026-11-06

Fixes from an external review of 2.9.0 (2026-11-06): what a broken or hostile
device could do to a scan, where the scanner was less gentle than it should
be, and what the exports left unsaid.

### Security

- **One oversized integer ended the BACnet pass.** An I-Am whose vendor-ID,
  max-APDU or segmentation field ran to ~1,800 octets (from any host, inside
  the target range or not) made Python refuse to print it, and the exception
  emptied the whole pass; a wide max-APDU instead broke every export. I-Am
  fields wider than four octets are rejected, Unsigned/Signed/Enumerated
  values wider than eight stay hex, SNMP INTEGERs wider than eight are
  dropped, and the JSON export cannot fail on one.
- **Spreadsheet formulas in device names.** Object names, descriptions,
  banners and page titles went into both CSVs and the Ctrl+C copy as they
  were. BACnet names are writable by anyone on the network, so a point
  renamed `=HYPERLINK(...)` ran as a formula in the integrator's point list.
  A value starting `=`, `+`, `-`, `@` (or a tab, line break or full-width
  form) is now written as text; plain numbers such as `-12.5` are left alone.
- **Terminal escapes in the log.** Device text reached the log, and the CLI
  prints log lines to a terminal as they are. Control characters and escape
  sequences are stripped from every log line, and from banners, titles, KNX
  names and SNMP descriptions as they arrive.
- **The classification report**, meant for attaching to a public GitHub
  issue, held each device's address, instance and name (names often carry
  serial numbers). Devices are now numbered, with vendor, model, firmware and
  counts only.
- **A site's own SNMP community** that worked was kept in the JSON export and
  the Raw JSON tab. Communities other than `public` and `private` are now
  recorded as `(custom)`.

### Fixed

- **UDP 47808 was shared with other BACnet software on the PC.** With
  `SO_REUSEADDR` the scanner bound alongside a front-end, YABE or a vendor
  tool, and the two split each other's traffic: the front-end lost replies
  and alarm notifications for as long as the scan ran. The port is now taken
  exclusively (`SO_EXCLUSIVEADDRUSE` on Windows); if it is in use the scanner
  takes another and says what that means.
- **A device's object count was never capped.** A count of 4,294,967,295
  meant building a list that size; 65,535 from a buggy device meant days of
  reads. No device is enumerated past 20,000 objects unless max objects is
  set higher, indices are ranges rather than lists, and enumeration stops
  after 20 unreadable entries in a row.
- **The Modbus read loop had no deadline.** A server sending frames with the
  wrong transaction ID every so often kept a request, and the scan, going
  for ever. Every request now has one deadline for everything it reads,
  however slowly the bytes arrive.
- **ReadPropertyMultiple batches were sized against the scanner's buffer**,
  not the device's: a 480-byte MS/TP controller was asked for ~700 bytes of
  objectList, aborted, and was then read one index per request (about 30
  times the traffic on the trunk). Replies are sized to what the device can
  send, an aborted batch is halved and asked again, and point-read requests
  are trimmed to fit the device's maximum. A device that refuses even
  one-object batches is no longer sent one per object first.
- **A short target list got ~25 connections per host at once.** The TCP
  sweep now keeps at most two attempts open to any one address.
- **Every absent unit ID behind a Modbus gateway cost three serial
  transactions.** Probing a unit stops at the first timeout or gateway
  "no device" answer.
- **Chunked Who-Is gave up after ten empty chunks**, so a site numbered
  1–500 and 100,001 upward never had its second group asked about. The range
  now doubles across empty stretches and drops back at the first answer,
  covering all 4,194,303 instances; each chunk also listens for less time.
- **Broadcasts on subnets that are not a /24.** Scanning a /16 the PC sits on
  broadcast to x.x.255.255, which a /24 sends to the gateway as unicast; the
  limited broadcast is used instead. A local subnet whose broadcast got no
  answer at all (a /24 target on a /23, or a PC with several interfaces) is
  asked once more the other way.
- **Waits a hostile peer could stretch out:** service probes have a
  15-second limit once connected, the SNMP receive loop ends while a flood
  continues, and one address can contribute at most 1,000 devices to a
  Who-Is (20,000 in all).
- **Exports did not say what was not scanned.** Services off (the GUI
  default), a stopped scan and a failed BBMD registration all read as clean
  results. The JSON now carries a `coverage` block (options, stopped, and
  per pass `scanned`, `off`, `failed`, `skipped: why`, `stopped partway` or
  `stopped before it ran`); the report shows a coverage note, a dash on the
  cards for passes that did not run, and "Not scanned" instead of "None".
- **A failed pass was logged only to the module logger**, so the GUI showed
  an empty result with no reason. It is now in the scan log too.
- **The baseline rolled forward on partial scans**, so the next night
  reported everything missed as new, and a missing or damaged baseline made
  every run scan and exit 3 without ever writing a replacement. The baseline
  is read before scanning (missing or damaged: exit 1 at once; missing with
  `--save-baseline` on the same path: the first run), a partial scan does not
  replace it, and JSON is written to a temporary file and moved into place.
- **A damaged settings file was replaced by the next save**, erasing every
  site profile. It is now renamed `settings.json.bad-<time>` and the GUI
  says so; a file that cannot be read is left alone; and profiles are written
  only by profile actions, so two windows no longer drop each other's.
- **The diff keyed BACnet devices on instance alone**, so duplicate
  instances collapsed and the survivor's address and name flipped between
  runs. A duplicated instance is keyed with its address (and MS/TP network
  and MAC), and listed.
- **Vendor fingerprints matched inside words**: "webs" in GoAhead-Webs read
  as Tridium, "fec" in "perfect" and "nae" in "effect" as Johnson Controls.
  They now match whole words and model-number forms.
- **CLI flags equal to their default were taken as "not given"**, so
  `--profile X --unicast auto` ran the profile's `always`, and
  `--rate-limit 0` was ignored. Explicit flags now always win.
- **CLI argument errors exited 2**, which is "interrupted". They exit 1.
- **The GUI fell back to defaults on a mistyped number** — the least gentle
  settings (no rate limit, four devices at once). It now stops with the
  reason.
- `python -m hvac_scanner.report` wrote `C:\Users\j.html` for a scan in
  `C:\Users\j.smith\scans\site`.
- MS/TP gap-filling gave up per router address, so one device lacking a
  property stopped fills for every device on the trunk; it is per device.
- A Modbus reply of the maximum legal length (254) was rejected.
- A Confirmed-Request arriving on the scanner's port could be matched as a
  reply.
- A value of thousands of nested opening tags raised RecursionError.
- One unexpected error in the GUI's event pump stopped it for good, leaving
  the window on "Scanning…".
- Ping from the GUI ran whichever `ping` came first on the search path (on
  Windows, the exe's own folder first) and misread its output's code page.
- A scan that found nothing could not be exported or compared.
- Dark-mode severity badges in the HTML report had too little contrast.

### Changed

- **BBMD registration is described as the write it is**, and its lease is
  capped at 300 seconds (`--bbmd-ttl` 10–300).
- The report footer no longer says no credentials were tried: it names the
  SNMP community strings used and any BBMD registration.
- The device CSV's credentials column is "Factory Default Login (published,
  not tried)".
- The MS/TP address probe asks two addresses at a time, waits at least three
  seconds for each and keeps to the rate limit: a few minutes per network
  instead of about one.
- The GUI starts with no target rather than a guessed office LAN, asks before
  a scan of more than 1,024 addresses, shows on the Advanced button how many
  settings differ from the defaults, and the scan log lists them.
- New `--max-hosts` (default 65,536 in total); `--bbmd` and `--broadcast`
  must be IPv4 addresses and `--timeout` more than 0.
- Gateways listing KNX IP Secure get an info finding that offering it does
  not mean plain tunnelling is off.
- New finding: **Duplicate BACnet device instances**.
- `hvac-scanner-gui` is a GUI script (no console window on Windows).

### Build

- CI: least-privilege permissions, checkout without persisted credentials,
  actions pinned to commit SHAs, and Dependabot to keep them current.
- The Windows executable is built from `packaging/requirements-build.txt`,
  PyInstaller and its dependencies pinned by version and hash, with no pip
  cache. Its SHA-256 is in the build log and in
  `HVACNetworkScanner.exe.sha256`, and the build signs a provenance
  attestation (`gh attestation verify`).
- GUI tests run on Linux CI under a virtual display instead of skipping.
- The site-data guard's site-specific deny-list moved out of the public
  repository to a private file the test reads when present (and a local
  pre-commit hook runs); the guard also reads HTML, CSV, log and XML files
  and UTF-16 text.
- Tests can no longer send a real limited-broadcast Who-Is.

## [2.9.0] — 2026-11-04

### Added

- **Alarm routing inventory.** Notification Class objects are read as
  metadata: each class's recipients (a device, or a network address), the
  days and hours each receives alarms, which transitions, confirmed or not,
  the priorities and which transitions need acknowledging. Shown in the
  device details and in the renamed **Trends, Schedules & Alarms** tab, and
  in a new **Alarm routing** section of the survey report.
  - Finding: notification classes with no recipients — alarms routed
    through them reach no one.
  - Finding: alarm recipients the scan did not find — a workstation that no
    longer exists, or one outside the scanned addresses.
- **Router tables.** A Network Port's routing table (the networks reachable
  through other routers on that port) is read and shown with the port.
  For a router on another subnet, those networks are also asked with a
  routed Who-Is, so a network behind a chain of routers is found without a
  Who-Is-Router-To-Network answer.
- Simulator: two notification classes on SC-1 (one routed to the front end,
  a missing workstation and a remote address; one routed to no one), and
  routing tables on both routers.

### Fixed

- **A context-tagged value of six or seven octets was read as an opening or
  closing tag.** The tag reader reports those as lengths 6 and 7, which a
  six-octet value — a B/IP MAC address — also reports, so routing-table
  entries lost their next hop and a seven-octet value ended the construct
  around it. Opening and closing tags are now told apart by having no
  contents.
- A ReadPropertyMultiple property whose value is empty (a Notification Class
  with no recipients) was dropped as if the device had not returned it.

## [2.8.0] — 2026-10-29

The rest of the BACnet roadmap and saved sites. Everything new is read-only:
nothing registers with a BBMD, joins a BACnet/SC hub or writes to a device
unless asked.

### Added

- **MS/TP behind routers on other subnets, without a BBMD.** Unicast
  discovery (2.7) found the routers but not the trunks behind them, because
  routers and MS/TP devices answer by broadcast on their own subnet. The
  network numbers now come from the routers' Network Port objects (or from
  routers that answer Who-Is-Router-To-Network directly); each network gets
  a Who-Is routed through its router, which finds devices that answer the
  requester. `--mstp-probe` (GUI: Advanced) goes further and asks each MS/TP
  address with a confirmed read, whose reply always comes back: it finds
  every device, at the cost of about a minute per network, a few requests at
  a time, bounded by the port's max master. Without it, the log says which
  networks went unanswered and how to reach them.
- **BBMD tables.** Every BACnet/IP address is asked for its
  Broadcast Distribution Table; the BBMDs among them are also asked for their
  Foreign Device Table. Both are plain reads. The scan reports which subnets
  each BBMD links (and flags peers outside the targets: the rest of the
  site's BACnet network) and who is registered to hear the site's
  broadcasts. `--no-bbmd-tables` to skip.
- **Trend log and schedule inventory**, as metadata: what each trend log
  records, how often, how full it is and whether it is still recording;
  each schedule's weekly programme, default, effective period and the
  objects it writes; calendars. Never trend records. New
  **Trends & Schedules** tab, report section and findings. `--no-metadata`
  to skip.
- **Network Port objects** are read as metadata (type, network number, MAC,
  max master, whether a BBMD accepts foreign devices) instead of being
  listed as nameless points.
- **BACnet/SC detection.** BACnet Secure Connect is BACnet over a WebSocket
  over TLS 1.3 with mutual authentication, on no fixed port. TCP 47808 and
  47820, and any HTTPS port that refuses the probe or serves no web page,
  are checked: a hub that demands a client certificate is reported as
  BACnet/SC (mutual TLS), with its certificate; one that accepts the
  BACnet/SC WebSocket without a certificate is reported as a high-severity
  finding, because anyone on the network can then join. The connection is
  closed before any BACnet/SC message is sent.
- **Saved site profiles.** Name the current targets and options in the GUI
  (Site, Save…) and pick them again later. The CLI runs them:
  `hvac-scanner --profile "Building A"`, with any targets or flags given on
  the command line taking precedence. `--list-profiles` lists them.
- **BACnet/SC hubs named by devices.** A device with both a BACnet/IP and a
  BACnet/SC port names its primary and failover hubs in its Network Port
  (and a hub names the URIs it accepts nodes on). Those addresses are probed
  too, so a hub on a port no sweep covers is still found.
- **KNXnet/IP gateways** (UDP 3671): one description request per target, as
  nmap's knx-gateway-info sends. Reports the gateway's name, KNX address,
  medium, serial and MAC, and which services it offers. A gateway offering
  tunnelling or routing without KNX IP Secure is a medium finding: anything
  that reaches it can switch whatever is on the bus. `--no-knx` to skip.
- **Niagara Fox identity.** The probe now sends a complete Fox hello (the
  form nmap's fox-info and zgrab2 use, naming this scanner rather than
  posing as Workbench) and keeps the whole reply: station name, Niagara
  version, host OS, Java VM, host ID and OEM brand. Fox over TLS on 4911 is
  spoken as TLS, with its certificate kept. Niagara AX (3.x) stations are a
  medium finding: Tridium's fixes for them have ended.
- **Modbus Report Server ID** (FC 17) identifies devices that reject Read
  Device Identification (FC 43), before falling back to a register read.
- Report findings: BACnet/SC without client certificates (high), KNX
  gateways without KNX Secure (medium), Niagara AX stations (medium),
  foreign devices registered with a BBMD (low), trend logs not recording
  (low), BBMDs linking subnets (info), BACnet/SC endpoints (info).
- Simulator: a second building on another /24 behind a router and BBMD
  (`--remote 127.0.4`), Network Port objects (one naming BACnet/SC hubs),
  trend logs, schedules and a calendar, BBMD tables, two BACnet/SC hubs (one
  on a port only a device names), a KNXnet/IP interface, a Niagara AX
  station alongside the Niagara 4 JACE, and a drive that answers only
  Report Server ID.
- Tests: the UDP passes (SNMP, KNX) are held to loopback like the TCP
  sweeps.

### Fixed

- **Property identifiers above 65535 were encoded in two octets**, so a
  request for one (all the BACnet/SC Network Port properties are above
  4194303) asked for a different property. Found while checking the
  constants against bacnet-stack.
- **Any page or banner mentioning "BACnet" was attributed to KMC
  Controls.** The KMC pattern matched the word itself; it now matches KMC's
  model numbers (BAC-5051 and so on).
- The Niagara Fox probe sent only the first line of a hello, which a
  station need not answer, and spoke plaintext to the TLS port 4911.
- **A comma list given as one CLI argument** (`"10.0.0.2-30, 10.0.4.5"`)
  failed to parse inside the engine, so unicast discovery silently had no
  targets, and the list's subnets shared one limited broadcast instead of a
  directed broadcast each. Each spec is now its own target, as in the GUI.
- A ReadPropertyMultiple value that itself contained context tag 4 ended at
  its first closing-tag byte, losing the rest of the value and every
  property after it in the reply.
- TCP 47808 was excluded from the service scan as if it were BACnet/IP,
  which is UDP.

## [2.7.0] — 2026-10-29

A full review of the code and the program in use, run against a new simulated
site (`tools/sim_site.py`) as well as the unit tests. Measured end to end on
that site with services enabled: 28.0 s before, 14.7 s after, with correct
results where before there were 15 phantom Modbus devices and mislabelled
units.

### Fixed

- **Engineering units.** `BACNET_UNITS` had been filled in by guess rather
  than from the enumeration, and most of it was wrong: 29 (%RH) showed "W",
  96 (ppm) "kPa-alt", 19 (kWh) "kPa", 30 (mm) "kW", 100 (per minute) "%RH",
  118 (cm) "gal/s" under a comment calling that a correction; 48 (kW),
  56 (psi), 58 (inH2O) and 89 (gpm) were missing and printed as `unit-48`
  and so on. Replaced with the complete BACnetEngineeringUnits table.
- **Object types.** The table stopped at 31 apart from three entries that
  were off by one (Network Port is 56, not 57). Integer Value, Large Analog
  Value, CharacterString Value and the rest came back as `type-45`, which
  also meant the per-type property lists written for them never matched.
- **BBMD-relayed I-Ams were attributed to the BBMD.** A Forwarded-NPDU comes
  from the BBMD's address and names the real device in its header; the
  parser skipped that header but kept the datagram's source, so every
  device a BBMD relayed was recorded at the BBMD's IP and deep-scanned
  there. Router announcements had the same problem. Both now use the
  originating address.
- **Phantom Modbus devices.** Exception codes 0x0A/0x0B are a gateway saying
  there is no device at that unit ID; they were counted as devices, so a
  gateway with two slaves reported nine. A device that ignores the unit ID —
  most direct-attached meters and drives — was reported once per probed ID.
  Both are now reported as what they are.
- **MS/TP devices found by the global Who-Is** were labelled BACnet/IP and
  counted as IP devices; the MS/TP pass only labelled devices it found
  itself.
- **Every CLI log line was printed twice** when not `--quiet`: once by the
  progress callback and once by the INFO-level logger.
- **An invalid target exited 0** after "scanning" nothing; it now exits 1,
  as documented, before anything is sent.
- **Double-clicking a point crashed the GUI** (`Colors.TEXT_PRIMARY` does
  not exist). Device details did nothing for Modbus and service rows, which
  were matched back to their device by display text that never matched.
- **Older HTTPS gear returned nothing.** Python's default TLS context refuses
  TLS 1.0/1.1, which is all a lot of installed BAS hardware offers.
- **Windows: ICMP port-unreachable aborted discovery.** Windows reports one
  as an error on the next receive; the discovery loops only expected a
  timeout.
- Binary present values read `active`/`inactive` instead of `1`/`0`. Dates
  and times with unspecified fields read `*` instead of year 2155. UCS-4
  strings decode. CLI output is written as UTF-8 so unit symbols survive
  redirection on Windows.
- **The site-data guard test published what it guarded.** It listed the
  site's name and street address in plain text, and used the real panel
  names and controller serial as samples. It now checks SHA-256 digests and
  synthetic samples, and only scans files git would publish — it used to
  fail on any checkout with a virtualenv inside it.
- GUI tests created a Tk interpreter per test, which on Windows eventually
  fails ("Can't find a usable tk.tcl"), so they skipped at random in a full
  run. They share one now.

### Changed

- **BACnet deep scans run in parallel** (`--bacnet-workers`, default 4).
  `BACnetClient` no longer serializes every request behind one lock: waiting
  threads take turns reading the shared socket and hand each reply to the
  request it answers, matched on source address and invoke ID (now allocated
  per device). Work is grouped by IP address, so no controller — and no
  router fronting an MS/TP trunk — ever has two requests outstanding.
  Results are kept in discovery order and each device's log is written as
  one block.
- **TCP sweeps use asyncio** (`netsweep.py`): a few hundred connection
  attempts in flight for the cost of a few hundred sockets, targets taken
  lazily, port-major so each host sees one attempt at a time. The connect
  phase uses at most a 1 s timeout; banner probes keep the full one. Service
  identification runs per host in parallel.
- **Modbus** probes all unit IDs over one connection per host, and probes
  hosts in parallel.
- **SNMP** sends to every host from one socket and waits once, instead of a
  thread per host each waiting out its own timeout.
- **MS/TP discovery** skips networks that already answered the global
  Who-Is, and sends the remaining directed Who-Is together with one
  collection window instead of one timeout each.
- The Modbus, service and SNMP passes sweep every target at once rather than
  once per comma-separated target.
- Fingerprinting indexes services by IP once instead of scanning the whole
  result for every device.

### Added

- **Unicast discovery** (`--unicast auto|always|off`): a ReadProperty of the
  wildcard device instance to each target address finds controllers on other
  subnets and VLANs, where a broadcast never arrives. `auto` (the default)
  probes only targets that are not on a local /24 and did not answer the
  broadcast.
- **A rebuilt GUI.** Summary counts and a progress bar while scanning; a
  filter across every tab; a device details panel; double-click a device for
  its points; copy rows as TSV; point-list export; an Advanced panel exposing
  every engine option (parallel devices, unicast, BBMD, broadcast, max
  objects, SNMP communities); settings remembered between runs; keyboard
  shortcuts; an application icon. The worker thread now reports through a
  queue the Tk thread drains, instead of calling into Tk.
- **Siemens APOGEE P2 detection** (`p2.py`, `--no-p2` to skip). Firmware
  2.x APOGEE panels speak P2 on TCP/5033, not BACnet/IP, so an APOGEE
  building used to look empty. Each open 5033 gets one well-formed P2
  identify frame (opcode 0x4640) carrying a fixed BLN name no site uses: a
  field panel resets the connection, a supervisor listener closes it
  gracefully, and anything else is not reported. Deliberately not a
  handshake with the right BLN name, which would write a permanent
  node-table entry for the scanner on the panel; and not BLN guessing —
  one constant name, one attempt per panel. Protocol facts are from the
  wire-verified reference in the companion P2 project. Panels found this
  way are flagged in the log when they did not answer BACnet, shown in the
  GUI and the report (with a finding: P2 has no authentication), and
  simulated in `tools/sim_site.py`.
- **Point status.** statusFlags is read wherever a point has a present
  value, in the same RPM batches: points carry `status` (in-alarm, fault,
  overridden, out-of-service) and devices `point_flags` counts. The GUI
  shows a Status column with alarm/fault rows in red and overrides in
  amber, plus a Flagged count.
- **Multi-state text.** stateText is read for multi-state objects, so a
  value reads "Occupied" rather than "2" (the number is kept as
  `state_number`).
- **HTML survey report** (`--html`, GUI Export, or
  `python -m hvac_scanner.report scan.json`): one self-contained file with
  findings ranked by severity — published default credentials on a
  reachable login, cleartext management (Telnet, FTP, HTTP-only), SNMP
  default communities, expired or expiring certificates, points in alarm
  or overridden, Modbus exposure, BACnet routed across subnets — plus the
  device inventory and open services. No scripts, prints cleanly. Built
  from the JSON form, so it works on a saved export too.
- **Point-list CSV** (`--points-csv`, `ScanResult.write_points_csv`): one
  row per BACnet point and Modbus register, with status.
- Exports record the scan `targets`.
- **Hints when nothing answers** — Windows Firewall, VLAN boundaries.
- `--snmp-community` (repeatable), `--version`, `location` read from the
  Device object, the scanner version in exports and the HTTP User-Agent.
- **`tools/sim_site.py`**, a simulated site on loopback; **`tools/gui_demo.py`**
  drives the GUI through a scan of it and takes a screenshot.
- The Windows executable carries an icon and version information.
- [ROADMAP.md](ROADMAP.md), starting with Siemens APOGEE (P2) panel
  detection.

### Tests

- 502 to 590, none skipped on Windows. New end-to-end tests run the engine
  against the simulated site (relay, router, RPM-rejecting device, unicast
  discovery, parallel vs sequential agreement); new unit tests cover the
  unit and object tables, Forwarded-NPDU origin, concurrent requests to two
  devices through one socket, Modbus gateway and any-unit handling, the TCP
  sweep, SNMP communities, settings, and the GUI's filter, sort, details and
  scan round trip. Unit tests no longer depend on the test machine's
  routing table, and a guard fails any test whose TCP sweep would reach a
  non-loopback address.

## [2.6.0] — 2026-08-19

### Added

- **TLS certificate capture on HTTPS probes.** The services scan already
  opened a TLS connection to every 443/8443 it found and threw the
  certificate away. BAS controllers put the product line, and often the panel
  name, in the subject CN, and the expiry date is operational information the
  system owner wants regardless of fingerprinting.

  New `hvac_scanner/certs.py` parses subject and issuer CN and organisation,
  the validity window and the serial straight from the DER. Hand-rolled on
  purpose: DER is BER, the same encoding the BACnet codec and SNMP probe
  already decode, and an ASN.1 dependency would cost the zero-dependency
  property for four fields. Certificate verification stays off — self-signed
  is the norm on this gear — which is why `getpeercert()` cannot be used and
  the DER is decoded directly.

  Surfaced as a `tls` object in the JSON, a **TLS Certificate** column in the
  CSV, and a scan-log warning when a certificate is expired or inside 30 days.
  Self-signed is called out explicitly so the reader knows the CN is
  self-asserted. The summary also feeds the vendor fingerprint regexes.

  Malformed certificates yield nothing rather than raising. A scanner must not
  fall over because one device presents a broken certificate, and this gear
  presents plenty.

- **Windows GUI executable.** `packaging/hvac_scanner.spec` builds a single
  ~14 MB `HVACNetworkScanner.exe` with PyInstaller. The package is stdlib-only
  precisely so it can run on a Windows box without a Python install; this is
  what makes that true for a field tech who is not going to install Python on
  a client's engineering workstation.

  ```bash
  pip install -e ".[build]"
  pyinstaller packaging/hvac_scanner.spec --noconfirm
  ```

  CI builds it on tags and on demand and uploads it as an artifact, after
  starting it to confirm the bundle resolves its imports — which is the
  failure mode a spec file actually has. PyInstaller is a build dependency
  only and never appears at runtime.

### Tests

- 470 to 502. The parser is checked against Python's own decoder, which it
  matches on subject, issuer and expiry, and against certificates generated
  with `openssl` where it is available.

- String-type coverage builds the DER directly rather than going through
  `openssl req -subj`: PrintableString, UTF8String, BMPString and IA5String,
  plus issuer/subject separation and UTCTime. openssl's handling of a
  non-ASCII `-subj` differs by distribution — Ubuntu's reads the bytes as
  Latin-1 and writes mojibake into the certificate — so a test asserting a
  round trip through it was measuring the local CLI rather than the parser.
  Building the DER puts the encoding under test under our control, and those
  cases now run on every platform instead of only where openssl exists.

- Fixture generation skips with openssl's own message rather than raising, so
  an environment difference reports what went wrong instead of surfacing as an
  unrelated-looking assertion.

## [2.5.0] — 2026-08-19

Three features that between them change what the tool is for: it stops being
something you run when you suspect a problem and becomes something that tells
you when one appeared.

### Added

- **Baseline comparison.** The scanner has written JSON since v2 and been
  schedulable since then, but nothing read the output back. A nightly scan
  nobody reads is disk usage. New `hvac_scanner/diff.py` plus:

  ```
  --baseline PATH        compare against a previous export
  --save-baseline PATH   write this scan for next time
  --diff-output PATH     .json for JSON, anything else for text
  --fail-on-change       exit 4 when the scan differs
  ```

  Exit 4 is the point for scheduled runs: the job alerts only when something
  moved. The baseline is written even when changes were found, so an
  unattended schedule rolls forward and reports each night's delta rather than
  re-reporting the same drift forever.

  BACnet devices are keyed on their device instance, not their address. The
  instance is configured in the controller and survives a DHCP lease change,
  so a panel that moves is reported as an address change rather than as a
  disappearance plus an unrelated arrival. Reported fields are limited to ones
  that mean something — name, model, vendor, firmware, application software,
  address, object count. Present values are excluded deliberately: a
  temperature differs on every scan and would bury the signal.

  A **COMPARE** button in the GUI runs the same comparison interactively and
  offers to save the report or promote the current scan to the new baseline.

- **BBMD / Foreign Device registration.** A Who-Is is a broadcast and
  broadcasts do not cross a router, so discovery only ever saw the subnet the
  scanner sat on — one run per building. `--bbmd IP` registers as a Foreign
  Device, sends Who-Is as Distribute-Broadcast-To-Network, and discovers every
  subnet that BBMD and its peers serve from a single host. `--bbmd-ttl`
  controls the lease, which is renewed automatically at two thirds elapsed:
  a large site can take longer to scan than the TTL, and once it lapses the
  BBMD stops forwarding and the scan would simply stop finding devices with
  nothing to say why.

  Registration failure aborts the BACnet pass rather than falling back to a
  local broadcast, and a BBMD that stays silent counts as failure. Both for
  the same reason: the user named a BBMD because the devices are not on this
  subnet, so a quiet fallback would report an empty network and read as a
  clean result.

- **Live results in the GUI.** Device rows, points and Modbus registers are
  drawn as each device finishes instead of all at once at the end, with a
  status line counting what has landed. On a controller with thousands of
  points the old behaviour was a blank window for the whole scan followed by a
  freeze while every row inserted at once.

### Fixed

- `parse_iam` now skips the 6-byte originating address in a Forwarded-NPDU.
  A BBMD relays broadcasts in that form, so without it every I-Am arriving
  through a BBMD failed the NPDU version check and was silently dropped —
  foreign-device registration would have appeared to work and found nothing.
- Four em dashes removed from CLI help text. `--help` writes to a console
  that is cp1252 on Windows, where a non-encodable character can raise
  UnicodeEncodeError.

### Tests

- 395 to 470. New `tests/mock_bbmd.py` relays to mock devices as
  Forwarded-NPDU so the skip above is exercised rather than assumed, and the
  mock device gained a `patch_port` flag so a device sitting behind a BBMD
  does not retarget the scanner at itself and bypass the thing under test.

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
