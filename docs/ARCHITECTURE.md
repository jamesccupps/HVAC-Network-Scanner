# Architecture

## Module layout

```
hvac_scanner/
├── constants.py      Vendor DB, BACnet unit/object tables, HVAC service ports
├── codec.py          Pure-function BACnet packet encode/decode (no I/O)
├── bacnet.py         BACnet/IP transport layer — sockets, invoke IDs, RPM
├── modbus.py         Modbus TCP sweep + register/coil reads
├── services.py       TCP port scan + protocol-specific probes
├── snmp.py           Raw UDP SNMP sysDescr probe
├── fingerprint.py    Cross-protocol model identification (pure function)
├── engine.py         ScanEngine orchestrator + ScanResult export
├── cli.py            Headless command-line entry point
├── gui.py            Tk GUI, thin wrapper over ScanEngine
├── __main__.py       `python -m hvac_scanner` → GUI
└── __init__.py       Public API, version
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
│   (sockets, threading, rate limiting)           │
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

One long-lived UDP socket per `BACnetClient` instance, bound to port
47808 where possible and an ephemeral port otherwise. All packet sends
and receives go through this socket.

Concurrent requests are serialized by `BACnetClient._lock`. This is
intentional: BACnet/IP is a request/response protocol with an
invoke-ID byte, but the response for a specific invoke-ID arrives on
the shared port and there is no reliable way to demultiplex concurrent
in-flight requests without complex state tracking. Serializing is
simpler and fast enough — the bottleneck on a real scan is network
latency, not code.

### Modbus, services, SNMP

Each of these uses a `ThreadPoolExecutor` for the initial TCP port sweep,
then walks discovered hosts sequentially for their deep-scan reads. Each
worker gets its own short-lived socket wrapped in `contextlib.closing`.

### ScanEngine

Runs in a single thread (from either the GUI's scan-worker thread or the
CLI's main thread). Protocol passes are sequential: BACnet, Modbus,
services, SNMP, then a final re-fingerprinting pass. A
`threading.Event` (`stop_event`) is checked between passes and between
per-device iterations for cooperative abort.

### GUI

Tk is single-threaded. The GUI spawns one daemon thread to run
`ScanEngine.run()` and marshals log callbacks back onto the Tk event
loop via `root.after(0, ...)`. No direct Tk calls happen from the
worker thread.

## Data flow

```
ScanOptions
    │
    ▼
ScanEngine.run()
    │
    ├── _scan_bacnet()      → BACnetClient  → codec.parse_iam() / parse_read_property_ack()
    │                          + _deep_read per device
    │
    ├── _scan_mstp()        → reuses BACnetClient with dnet parameter
    │
    ├── _scan_modbus()      → ModbusScanner (own sockets, own thread pool)
    │
    ├── _scan_services()    → HVACServiceScanner
    │
    ├── _scan_snmp()        → SNMPScanner
    │
    └── _refingerprint()    → fingerprint_device() correlates across all results
    │
    ▼
ScanResult
    │
    ├── .to_dict()         → JSON-safe dict
    ├── .write_json(path)  → JSON file
    └── .write_csv(path)   → CSV file
```

## Adding a new vendor fingerprint

1. Extend `BACNET_VENDORS` in `constants.py` if the vendor ID isn't there.
2. Add a new branch in `fingerprint_device()` in `fingerprint.py` that
   uses the combination of `vendor_id`, `max_apdu`, `instance`, service
   banners, and MSTP routing to identify the model.
3. Add a test in `tests/test_fingerprint.py`.

## Adding a new protocol

1. Create a new scanner module following the pattern of `modbus.py` or
   `snmp.py`: class with a `scan_network()` method, callback for logging,
   all sockets wrapped in `contextlib.closing` or try/finally.
2. Add a scan pass in `ScanEngine` that calls it, tags results with
   `protocol`, and accumulates them into `result.devices`.
3. Add a protocol toggle to `ScanOptions`.
4. Add the corresponding flag to `cli.py` and the GUI checkbox to `gui.py`.
5. Add tests for anything parser-like in a new `tests/test_<proto>.py`.
