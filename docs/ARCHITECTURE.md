# Architecture

## Module layout

```
hvac_scanner/
├── constants.py      Vendor DB, BACnet unit/object tables, HVAC service ports
├── codec.py          Pure-function BACnet packet encode/decode (no I/O)
├── bacnet.py         BACnet/IP transport — shared socket, concurrent requests, RPM, unicast discovery
├── modbus.py         Modbus TCP — per-host sessions, unit-ID probing, register/coil reads
├── services.py       TCP service probes: HTTP(S) banners and certificates, Fox, S7, CIP, ...
├── snmp.py           Raw UDP SNMP sysDescr, one socket fanned out to every host
├── netsweep.py       asyncio TCP connect sweep used by modbus.py, p2.py and services.py
├── p2.py             Siemens APOGEE P2 detection: TCP/5033 sweep + one foreign-BLN identify frame
├── certs.py          Minimal X.509 (DER) parsing for the HTTPS probe
├── fingerprint.py    Cross-protocol model identification (pure function)
├── device_profiles.py Vendor-aware object caps and scan-depth presets
├── netrange.py       Target syntax: CIDR, ranges, host lists
├── diff.py           Baseline comparison
├── engine.py         ScanEngine orchestrator + ScanResult export
├── cli.py            Headless command-line entry point
├── gui.py            Tk GUI, thin wrapper over ScanEngine
├── settings.py       Remembered GUI settings (JSON in the user's config dir)
├── icon.py           The application icon, drawn in code (PNG and ICO writers)
├── __main__.py       `python -m hvac_scanner` → GUI
└── __init__.py       Public API, version

tools/sim_site.py     Simulated BAS site on loopback — used by tests/test_e2e_site.py
tools/gui_demo.py     Drives the GUI through a scan of the simulator, takes a screenshot
```

## Layering

```
┌─────────────────────────────────────────────────┐
│                   UI Layer                      │
│   gui.py                  cli.py                │
│   (Tk, windows, buttons)  (argparse, stdout)    │
└───────────────┬────────────────┬────────────────┘
                │                │
                └────┬───────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│                 Orchestration                   │
│   engine.py — ScanEngine, ScanOptions, Result   │
│   fingerprint.py — identify models              │
└───────────────┬─────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────┐
│                  Transport                      │
│   bacnet.py  modbus.py  services.py  snmp.py    │
│   netsweep.py                                   │
│   (sockets, threads/asyncio, rate limiting)     │
└───────────────┬─────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────┐
│                 Pure codec                      │
│   codec.py — encode/decode BACnet packets       │
│   constants.py — reference tables               │
└─────────────────────────────────────────────────┘
```

**Strict rule:** nothing in `codec.py` or `constants.py` imports sockets,
threads, or anything from higher layers. This is what makes the parser
testable against captured byte fixtures with no mocking.

## Threading model

### BACnet/IP (bacnet.py)

One long-lived UDP socket per `BACnetClient`, bound to port 47808 where
possible (some devices reply to 47808 whatever port asked) and an ephemeral
port otherwise. Every packet goes out and comes back through it.

Confirmed requests may be in flight from several threads at once, each to a
different device. There is no background receive thread. A request
registers `(destination IP, invoke ID)` in a pending table and sends; then
one waiting thread at a time takes the *reader* role, reads a datagram and
files it under the pending entry it answers, waking its owner. The other
waiters sleep on a condition variable until their reply is filed or the
reader role is free. Anything that matches no pending request — an I-Am, an
unconfirmed COV notification, a reply to a request that already timed out —
is discarded. Invoke IDs are allocated per destination, so a straggling reply
cannot be mistaken for the answer to a later request to the same device for
another 255 requests.

Discovery (Who-Is, Who-Is-Router-To-Network, BBMD registration, unicast
probing) reads the socket directly and runs as its own phase, never
overlapping confirmed requests.

### Deep scans (engine.py)

`_deep_scan_devices` groups discovered devices by IP address and runs the
groups on a thread pool (`ScanOptions.bacnet_workers`, default 4). Within a
group, devices are scanned one after another. A router and every MS/TP
device behind it share the router's IP, so they share a worker: the MS/TP
trunk is the slowest link on the site and never carries two conversations.
The load any single device sees is exactly what it was when the whole scan
was sequential; only the number of devices being talked to at once changed.

Each device's log lines are buffered and written as one block when it
finishes, and the result list is put back into discovery order at the end.

### Modbus, services (netsweep.py)

The port sweep is an asyncio coroutine pool on its own event loop
(`asyncio.run` in the calling thread): up to a few hundred connection
attempts pending at once, targets pulled lazily from an iterator so a /16 is
never materialised. Targets are ordered port-major — every host on one port,
then the next port — so a given host sees about one attempt at a time.

After the sweep, hosts are identified on a small thread pool (16), one host
per worker, each host's ports in sequence: Modbus unit-ID probing over one
TCP session, or the service banner probes.

### SNMP

One UDP socket sends a GET to every host (1 ms apart), then collects replies
for one timeout period. Further community strings are tried only against
hosts that stayed silent.

### ScanEngine

`run()` executes on one thread (the GUI's worker or the CLI's main thread).
Protocol passes are sequential: BACnet (discovery, unicast discovery, deep
scans, MS/TP), Modbus, APOGEE P2, services, SNMP, then fingerprinting. A
`threading.Event` (`stop_event`) is checked between passes, between devices
and between batches for cooperative abort; partial results are always
fingerprinted and returned.

The engine reports through three callbacks: `callback(msg)` for log lines,
`device_callback(dev)` as each device finishes, and
`progress_callback(phase, done, total)`.

### GUI

Tk is single-threaded and the worker thread never touches it. All three
engine callbacks put events on a `queue.Queue`; the Tk thread drains it every
100 ms (`_pump`), writing log lines in batches, drawing devices as they
arrive, and updating the progress bar. The final result arrives as a `done`
event.

## Data flow

```
ScanOptions
    │
    ▼
ScanEngine.run()
    │
    ├── _scan_bacnet()
    │     ├── Who-Is per broadcast domain   → codec.parse_iam() (Forwarded-NPDU aware)
    │     ├── _discover_unicast()           → BACnetClient.discover_unicast()
    │     ├── _deep_scan_devices()          → _deep_read() per device, grouped by IP
    │     └── _scan_mstp()                  → routers, directed Who-Is, deep scans
    │
    ├── _scan_modbus()      → ModbusScanner (netsweep + per-host sessions)
    ├── _scan_p2()          → P2Scanner (netsweep + one probe per open TCP/5033)
    ├── _scan_services()    → HVACServiceScanner (netsweep + per-host probes)
    ├── _scan_snmp()        → SNMPScanner (one-socket fan-out)
    └── _refingerprint()    → fingerprint_device() with same-IP services
    │
    ▼
ScanResult
    ├── .to_dict()                   → JSON-safe dict
    ├── .write_json(path)            → JSON file
    ├── .write_csv(path)             → device CSV
    ├── .write_points_csv(path)      → point list CSV
    └── .write_classification_report(path)
```

## Adding a new vendor fingerprint

1. Extend `BACNET_VENDORS` in `constants.py` if the vendor ID isn't there.
2. Add a new branch in `fingerprint_device()` in `fingerprint.py` that
   uses the combination of `vendor_id`, `max_apdu`, `instance`, service
   banners, and MSTP routing to identify the model.
3. Add a test in `tests/test_fingerprint.py`.

## Adding a new protocol

1. Create a new scanner module following the pattern of `modbus.py` or
   `snmp.py`: class with a `scan_network()` method taking `stop_event` and
   `progress`, callback for logging, all sockets closed on every path. Use
   `netsweep.tcp_sweep` for a TCP port sweep.
2. Add a scan pass in `ScanEngine` that calls it with every target at once,
   tags results with `protocol`, and accumulates them into `result.devices`.
3. Add a protocol toggle to `ScanOptions`.
4. Add the corresponding flag to `cli.py` and the checkbox to `gui.py`.
5. Add tests for anything parser-like in a new `tests/test_<proto>.py`, and
   a simulated device to `tools/sim_site.py` if it can be exercised end to
   end.
