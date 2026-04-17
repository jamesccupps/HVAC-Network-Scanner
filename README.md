# HVAC Network Scanner

A multi-protocol discovery and audit tool for HVAC and building automation networks. Zero third-party dependencies — everything runs on the Python 3.10+ standard library.

[![CI](https://github.com/jamesccupps/HVAC-Network-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jamesccupps/HVAC-Network-Scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

![HVAC Network Scanner](docs/screenshots/main-window.png)

## What it does

Walks a network and tells you what building-automation gear lives on it. For each device found it tries to identify the exact model, pull readable points or registers, and surface the factory-default credentials that ship with that product so you can confirm they've been changed.

Works against:

- **BACnet/IP** — raw UDP `Who-Is` / `I-Am`, `ReadProperty`, and `ReadPropertyMultiple`. No BAC0 dependency (works on Python 3.12+).
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

- **Parser rewrite.** The BACnet codec is now a pure-function module with proper extended-tag-number and extended-length handling. Fixes silent failures on vendors that reorder I-Am tags, and on devices with property IDs above 255.
- **ReadPropertyMultiple support.** Deep scans on controllers that support RPM finish roughly 4× faster. Falls back to `ReadProperty` automatically where RPM isn't supported.
- **Socket reuse.** One long-lived UDP socket per scanner instance instead of a fresh socket per property read (~800 socket create/close cycles eliminated on a 200-point Trane Tracer).
- **Rate limiting.** Optional per-IP inter-packet delay so dense deep scans don't DoS small field controllers.
- **Headless CLI.** `python -m hvac_scanner.cli` runs end-to-end without the GUI, for Task Scheduler automation.
- **Package structure.** The monolithic v1 script is now a proper package: `codec`, `bacnet`, `modbus`, `services`, `snmp`, `fingerprint`, `engine`, `cli`, `gui`. Every module is testable in isolation.
- **Test suite.** 98 tests covering packet encode/decode correctness, cross-request socket contamination, engine behavior, fingerprinting, and per-property type validation. CI runs them on Python 3.10 / 3.11 / 3.12 / 3.13 on Ubuntu and Windows.
- **Bug fixes.** 17 bare-except blocks replaced with targeted handling; MSTP devices at the same router IP disambiguated by instance; BACnet engineering unit 118 correctly mapped to `gal/s` (v1 had it as `L/min`, which is 81); Modbus unit ID 255 now scanned (default for many TCP-only gateways).

See [CHANGELOG.md](CHANGELOG.md) for the full history.

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
├── engine.py          # ScanEngine orchestrator + result/export
├── cli.py             # Headless command-line interface
├── gui.py             # Tk GUI (thin wrapper over ScanEngine)
├── __main__.py        # `python -m hvac_scanner` → GUI
└── __init__.py        # Public API

tests/
├── test_codec.py                    # Packet encode/decode + parser-bug regressions
├── test_bacnet_client.py            # Socket / invoke-id contamination scenarios
├── test_validate_point_property.py  # Per-property type validation
├── test_engine.py                   # Orchestration and result shaping
├── test_fingerprint.py              # Model identification
├── test_modbus.py                   # Modbus framing and parsing
└── conftest.py
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
