# HVAC Network Scanner

A multi-protocol discovery and audit tool for HVAC and building automation networks. Zero third-party dependencies — everything runs on the Python 3.10+ standard library.

[![CI](https://github.com/jamesccupps/HVAC-Network-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jamesccupps/HVAC-Network-Scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## What it does

Finds and fingerprints controllers, gateways, and workstations on a BAS network. Works against:

- **BACnet/IP** — raw UDP `Who-Is` / `I-Am`, `ReadProperty`, and `ReadPropertyMultiple`. No BAC0 dependency (works on Python 3.12+).
- **BACnet MSTP** — device enumeration behind BACnet routers via `Who-Is-Router-To-Network` + targeted `Who-Is` to remote DNETs.
- **Modbus TCP** — port sweep, device-identification (FC 43/MEI 14), holding/input register and coil reads.
- **HVAC services** — Niagara Fox, OPC UA, Siemens S7, EtherNet/IP CIP, KNXnet/IP, LonWorks/IP, MQTT, WebCTRL, Metasys, plus HTTP/HTTPS banner grabs.
- **SNMP v1/v2c** — raw UDP `sysDescr` probe (no pysnmp dependency).

Correlates results across protocols to identify specific models:

- Trane Tracer SC / SC+ / UC600 / UC400
- Siemens Desigo PXC automation stations, Desigo CC, TX-I/O modules
- Johnson Controls FEC / Metasys NAE
- Honeywell / Tridium Niagara
- Schneider EcoStruxure / SmartX
- Contemporary Controls BASRT-B routers
- Carrier i-Vu, Automated Logic WebCTRL, Distech, Delta, KMC, Reliable, Carel, Belimo, Daikin, Mitsubishi, LG, and more

## Install

```bash
git clone https://github.com/jamesccupps/HVAC-Network-Scanner.git
cd HVAC-Network-Scanner
pip install -e .
```

Or run directly from the source tree with no install:

```bash
python -m hvac_scanner           # launches the GUI
python -m hvac_scanner.cli --help
```

Requires Python 3.10 or newer. No extra packages.

## Using the GUI

```bash
python -m hvac_scanner
```

Enter one or more CIDR networks (comma-separated), pick which protocols to scan, click **SCAN**. Devices populate into tabs:

- **All Devices** — cross-protocol table with identified model, vendor, web UI URL, default credentials, and description. Right-click for open-web-UI, copy-IP, copy-creds, ping, and a full details popup.
- **BACnet Points** — per-device object lists with present values and units
- **Modbus Registers** — holding / input / coil reads
- **Services** — discovered TCP service ports with banners and titles
- **Raw JSON** — the full scan result, ready to copy/export

Columns are sortable (click the headers). IP addresses sort numerically by octet.

Export to CSV or JSON with the **EXPORT** button.

## Using the CLI

New in v2. Runs headless — no display, no Tk. Intended for Task Scheduler, cron, and CI pipelines.

```bash
# Basic scan of a /24
python -m hvac_scanner.cli 192.168.1.0/24

# Multiple networks, export to JSON and CSV
python -m hvac_scanner.cli 10.0.0.0/24 10.0.1.0/24 \
    --json scan.json --csv scan.csv

# BACnet only, with conservative rate limiting for small JACEs/UC400s
python -m hvac_scanner.cli 192.168.5.0/24 --bacnet-only --rate-limit 50

# Quiet mode for scheduled runs
python -m hvac_scanner.cli 192.168.5.0/24 --json /var/log/bas-scan.json --quiet
```

See [docs/CLI_USAGE.md](docs/CLI_USAGE.md) for the full flag reference and a Windows Task Scheduler XML example.

Exit codes:

- `0` — scan completed
- `1` — bad arguments
- `2` — interrupted (SIGINT)
- `3` — internal error

## What's new in v2

- **Parser rewrite.** The BACnet codec is split out as a pure-function module with proper extended-tag-number and extended-length handling. Fixes silent failures on vendors with reordered I-Am tags, and on devices with property IDs above 255.
- **ReadPropertyMultiple support.** Deep scans on controllers that support RPM now finish roughly 4× faster. Falls back to `ReadProperty` automatically where RPM isn't supported.
- **Socket reuse.** One long-lived UDP socket per scanner instance instead of creating a fresh socket per property read (~800 socket create/close cycles eliminated on a 200-point Trane Tracer).
- **Rate limiting.** Optional per-IP inter-packet delay protects small field controllers from DoS during dense deep scans.
- **Headless CLI.** `python -m hvac_scanner.cli` runs end-to-end without the GUI, for Task Scheduler automation.
- **Package structure.** Split the monolithic v1 script into a proper package: `codec`, `bacnet`, `modbus`, `services`, `snmp`, `fingerprint`, `engine`, `cli`, `gui`. Every module is testable in isolation.
- **Unit tests.** 59 tests covering packet-builder and parser correctness against hand-constructed byte fixtures. CI runs them on Python 3.10/3.11/3.12/3.13 on Ubuntu + Windows.
- **Bug fixes:** 17 bare-except blocks eliminated; MSTP devices at the same router IP now disambiguated by instance; correct unit mapping for BACnet engineering-unit code 118 (`gal/s`, was wrongly `L/min`); Modbus unit ID 255 now scanned.

See [CHANGELOG.md](CHANGELOG.md) for details.

## Safety and legal

This tool is intended for **scanning networks you own or are authorized to audit.** Running BACnet/Modbus sweeps against unfamiliar networks is at best rude and at worst unlawful in many jurisdictions — modern building automation systems can malfunction or fail-safe into unsafe states when they receive unexpected traffic. Don't point it at anything you haven't been explicitly asked to assess.

The default-credentials database reflects the factory defaults published in each vendor's documentation. It's here so the legitimate owner/operator of a system can quickly confirm whether defaults were ever changed — not as a remote-access toolkit.

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
├── engine.py          # ScanEngine orchestrator + result/export
├── cli.py             # Headless command-line interface
├── gui.py             # Tk GUI (thin wrapper over ScanEngine)
├── __main__.py        # `python -m hvac_scanner` → GUI
└── __init__.py        # Public API
tests/
├── test_codec.py      # Packet encode/decode + parser-bug regressions
├── test_fingerprint.py
├── test_modbus.py
└── test_engine.py
```

## Development

```bash
git clone https://github.com/jamesccupps/HVAC-Network-Scanner.git
cd HVAC-Network-Scanner
pip install -e ".[dev]"
pytest
```

Pull requests welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Author

James Cupps — <https://github.com/jamesccupps>
